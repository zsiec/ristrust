//! The DTLS 1.2 connection: the public [`Conn`]/[`Config`]/[`Transport`] API and
//! the client/server handshake state machines (ristgo `conn.go` +
//! `handshake_*.go`).
//!
//! The connection drives a caller-supplied datagram [`Transport`] synchronously:
//! [`Conn::handshake`] runs the full flight exchange (with RFC 6347 §4.2.4
//! retransmission on read timeout), then [`Conn::write`]/[`Conn::read`] carry
//! record-protected application data. Cipher-suite selection is table-driven (see
//! [`super::suiteinfo`]): the PSK suite needs no flight-4 certificate messages, the
//! ECDHE suites add a Certificate + signed ServerKeyExchange, and the RSA
//! key-transport suite adds a Certificate the client encrypts the pre-master to.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use super::cert::{self, Identity, PeerKey};
use super::cipher::{ConnKeys, derive_keys};
use super::handshake::{FragmentHeader, HANDSHAKE_HEADER_LEN, Reassembler, full_message_bytes};
use super::keyexchange::{
    decrypt_rsa_premaster, ecdhe_premaster, encrypt_rsa_premaster, generate_ecdhe,
    new_rsa_premaster,
};
use super::messages::{
    CertificateMsg, CertificateVerify, ClientHello, HandshakeType, HelloVerifyRequest, ServerHello,
    ServerKeyExchange, certificate_request_body, client_key_exchange_ecdhe,
    client_key_exchange_psk, client_key_exchange_rsa, parse_client_key_exchange_ecdhe,
    parse_client_key_exchange_psk, parse_client_key_exchange_rsa,
};
use super::prf::{
    LABEL_CLIENT_FINISHED, LABEL_SERVER_FINISHED, PrfHash, extended_master_secret,
    finished_verify_data, master_secret,
};
use super::record::{ContentType, Record, VERSION_DTLS_1_0, VERSION_DTLS_1_2, split_records};
use super::replay::ReplayWindow;
use super::suiteinfo::{AuthMethod, KeyExchange, SUITE_TABLE, SuiteInfo, lookup_suite};
use super::suites::{
    NAMED_GROUP_SECP256R1, OFFERED_SIGNATURE_ALGORITHMS, RANDOM_LEN,
    TLS_PSK_WITH_AES_128_GCM_SHA256,
};

/// The cookie length the server issues (RFC 6347 §4.2.1 recommends ≤ 32).
const COOKIE_LEN: usize = 20;
/// The largest datagram the connection will receive.
const RECV_BUF: usize = 1 << 16;
/// The retransmission backoff ceiling (RFC 6347 §4.2.4.1).
const MAX_RETRANSMIT: Duration = Duration::from_secs(60);

/// A datagram transport the DTLS connection drives. Mirrors the subset of
/// `std::net::UdpSocket` the handshake needs: send a datagram, receive one
/// (honouring the read timeout), and set that timeout.
pub trait Transport {
    /// Sends one datagram.
    ///
    /// # Errors
    /// Propagates the transport's I/O error.
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize>;

    /// Receives one datagram into `buf`, returning its length. Must return an
    /// error of kind [`io::ErrorKind::TimedOut`] or [`io::ErrorKind::WouldBlock`]
    /// when the read timeout elapses.
    ///
    /// # Errors
    /// Propagates the transport's I/O error (including the timeout).
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Sets the receive timeout (`None` blocks indefinitely).
    ///
    /// # Errors
    /// Propagates the transport's I/O error.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

/// DTLS connection configuration. At least one authentication method (a PSK, or a
/// certificate for the ECDHE / RSA-transport suites) must be set.
// Each boolean is an orthogonal, independently-toggled policy knob on a public config;
// folding them into an enum or bitflags would obscure the per-field documentation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Config {
    /// The pre-shared key enabling `TLS_PSK_WITH_AES_128_GCM_SHA256`.
    pub psk: Option<Vec<u8>>,
    /// The PSK identity (sent by the client, expected by the server).
    pub psk_identity: Vec<u8>,
    /// The local certificate/key for the certificate suites: a server presents it
    /// (its key type — ECDSA P-256 or RSA — selects which `ECDHE_*` / RSA-transport
    /// suites it can serve); a client offers the certificate suites when it can
    /// verify the peer (via `insecure_skip_verify` or `peer_cert_fingerprint`).
    pub certificate: Option<Arc<Identity>>,
    /// Accept any peer certificate (test/insecure). When set, the client offers the
    /// certificate suites.
    pub insecure_skip_verify: bool,
    /// Accept only a peer leaf whose SHA-256 fingerprint matches this pin. When set,
    /// the client offers the certificate suites. On a server with
    /// [`require_client_cert`](Config::require_client_cert) it additionally pins the
    /// accepted client leaf.
    pub peer_cert_fingerprint: Option<[u8; 32]>,
    /// Mutual authentication: when set, a certificate-suite **server** sends a
    /// CertificateRequest and rejects a client that does not present a certificate
    /// proven by a valid CertificateVerify (RFC 5246 §7.4.4/§7.4.8). A **client**
    /// presents its [`certificate`](Config::certificate) whenever the server asks,
    /// regardless of this flag. The presented client leaf is verified with the same
    /// [`insecure_skip_verify`](Config::insecure_skip_verify) /
    /// [`peer_cert_fingerprint`](Config::peer_cert_fingerprint) policy as a server leaf.
    pub require_client_cert: bool,
    /// Require the peer to confirm `extended_master_secret` (RFC 7627). When
    /// `false` (the default) EMS is offered and used when the peer agrees, but its
    /// omission is tolerated for interop.
    pub require_extended_master_secret: bool,
    /// Cipher-suite ids the user has disabled (the TR-06-2 §6.2 per-suite disable
    /// knob). A disabled suite is neither offered (client) nor selected (server).
    pub disabled_suites: Vec<u16>,
    /// Allow the integrity-only `TLS_RSA_WITH_NULL_SHA256` suite, which provides NO
    /// confidentiality. OFF by default: an RSA certificate configured for the
    /// encrypted suites cannot silently enable a cleartext session — the NULL suite
    /// is reachable only when this is explicitly set.
    pub allow_null_cipher: bool,
    /// The overall handshake deadline.
    pub handshake_timeout: Duration,
    /// The initial retransmission timer (doubles per timeout, capped at 60 s).
    pub retransmit_timeout: Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            psk: None,
            psk_identity: Vec::new(),
            certificate: None,
            insecure_skip_verify: false,
            peer_cert_fingerprint: None,
            require_client_cert: false,
            require_extended_master_secret: false,
            disabled_suites: Vec::new(),
            allow_null_cipher: false,
            handshake_timeout: Duration::from_secs(30),
            retransmit_timeout: Duration::from_secs(1),
        }
    }
}

impl Config {
    /// A PSK client/server config with the given identity and key.
    #[must_use]
    pub fn psk(identity: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Config {
        Config {
            psk: Some(key.into()),
            psk_identity: identity.into(),
            ..Config::default()
        }
    }

    /// A certificate server config presenting `identity`. The identity's key type
    /// selects the suites served: an ECDSA P-256 leaf serves the `ECDHE_ECDSA_*`
    /// suites, an RSA leaf the `ECDHE_RSA_*` suites (and, with
    /// [`allow_null_cipher`](Config::allow_null_cipher), `RSA_WITH_NULL_SHA256`).
    #[must_use]
    pub fn ecdhe_server(identity: Identity) -> Config {
        Config {
            certificate: Some(Arc::new(identity)),
            ..Config::default()
        }
    }

    /// A certificate client config that accepts only a peer leaf matching `pin` (its
    /// SHA-256 fingerprint). It offers the certificate suites; the server's leaf key
    /// type decides which one is negotiated.
    #[must_use]
    pub fn ecdhe_client_pinned(pin: [u8; 32]) -> Config {
        Config {
            peer_cert_fingerprint: Some(pin),
            ..Config::default()
        }
    }

    /// A certificate client config that accepts any peer certificate (insecure; for
    /// tests / fingerprint-out-of-band deployments).
    #[must_use]
    pub fn ecdhe_client_insecure() -> Config {
        Config {
            insecure_skip_verify: true,
            ..Config::default()
        }
    }

    /// Whether this config can verify a peer certificate (and so may offer the
    /// certificate suites).
    fn can_verify_cert(&self) -> bool {
        self.insecure_skip_verify || self.peer_cert_fingerprint.is_some()
    }

    /// Whether the client may OFFER `suite`: it can perform the key exchange and
    /// authenticate the result, and the user has not disabled it. A certificate
    /// suite needs a verification policy; the NULL suite additionally needs the
    /// cleartext opt-in.
    fn client_can_offer(&self, suite: SuiteInfo) -> bool {
        if self.disabled_suites.contains(&suite.id) {
            return false;
        }
        if suite.kx == KeyExchange::Psk {
            return self.psk.is_some();
        }
        self.can_verify_cert() && (suite.aead || self.allow_null_cipher)
    }

    /// Whether the server may SELECT `suite` with its configured credentials, and the
    /// user has not disabled it. A certificate suite needs a leaf whose key type
    /// matches the suite's auth method; the NULL suite additionally needs the
    /// cleartext opt-in.
    fn server_can_serve(&self, suite: SuiteInfo) -> bool {
        if self.disabled_suites.contains(&suite.id) {
            return false;
        }
        if suite.kx == KeyExchange::Psk {
            return self.psk.is_some();
        }
        let Some(identity) = &self.certificate else {
            return false;
        };
        identity.auth_method() == suite.auth && (suite.aead || self.allow_null_cipher)
    }
}

/// One record to transmit: its content type, epoch (0 = plaintext, 1 = AEAD), and
/// the plaintext payload (encrypted at send time for epoch 1).
#[derive(Debug, Clone)]
struct RecordSpec {
    typ: ContentType,
    epoch: u16,
    payload: Vec<u8>,
}

/// One reassembled inbound handshake message.
#[derive(Debug)]
struct Incoming {
    typ: HandshakeType,
    message_seq: u16,
    body: Vec<u8>,
    epoch: u16,
}

/// A live DTLS 1.2 connection over a datagram [`Transport`].
#[derive(Debug)]
pub struct Conn<T: Transport> {
    transport: T,
    cfg: Config,
    is_client: bool,

    // Record-layer send/recv state (per epoch 0/1).
    send_seq: [u64; 2],
    replay: [ReplayWindow; 2],

    // Cipher state once keys are derived.
    keys: Option<ConnKeys>,
    cipher_suite: u16,
    /// The negotiated suite descriptor (its hash drives the PRF / transcript /
    /// Finished / key schedule). Defaults to a SHA-256 suite until negotiated.
    suite: SuiteInfo,

    // Handshake state.
    transcript: Vec<u8>,
    reasm: Reassembler,
    send_msg_seq: u16,
    handshake_done: bool,

    // Buffered application data decrypted while reading.
    app_buf: std::collections::VecDeque<Vec<u8>>,

    // Epoch-1 records that arrived before the keys were derived (e.g. the peer's
    // Finished packed into the same flight as the ClientKeyExchange that keys it).
    // Reprocessed by `drain_pending` once the keys are ready.
    pending_records: Vec<Record>,
}

impl<T: Transport> Conn<T> {
    /// Creates a DTLS client over `transport`.
    pub fn client(transport: T, cfg: Config) -> Conn<T> {
        Conn::new(transport, cfg, true)
    }

    /// Creates a DTLS server over `transport`.
    pub fn server(transport: T, cfg: Config) -> Conn<T> {
        Conn::new(transport, cfg, false)
    }

    fn new(transport: T, cfg: Config, is_client: bool) -> Conn<T> {
        Conn {
            transport,
            cfg,
            is_client,
            send_seq: [0, 0],
            replay: [ReplayWindow::new(), ReplayWindow::new()],
            keys: None,
            cipher_suite: 0,
            suite: lookup_suite(TLS_PSK_WITH_AES_128_GCM_SHA256).expect("PSK suite in table"),
            transcript: Vec::new(),
            reasm: Reassembler::new(),
            send_msg_seq: 0,
            handshake_done: false,
            app_buf: std::collections::VecDeque::new(),
            pending_records: Vec::new(),
        }
    }

    /// The negotiated cipher suite (valid after a successful handshake).
    #[must_use]
    pub fn cipher_suite(&self) -> u16 {
        self.cipher_suite
    }

    /// Runs the DTLS handshake to completion.
    ///
    /// # Errors
    /// An [`io::Error`] on transport failure, handshake timeout, or a protocol
    /// violation (bad cookie, Finished mismatch, no common suite, peer alert).
    pub fn handshake(&mut self) -> io::Result<()> {
        if self.handshake_done {
            return Ok(());
        }
        if self.is_client {
            self.client_handshake()
        } else {
            self.server_handshake()
        }
    }

    /// Sends one application-data record.
    ///
    /// # Errors
    /// An [`io::Error`] if the handshake has not completed or the transport fails.
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if !self.handshake_done {
            return Err(proto("write before handshake"));
        }
        self.send_flight(&[RecordSpec {
            typ: ContentType::ApplicationData,
            epoch: 1,
            payload: data.to_vec(),
        }])?;
        Ok(data.len())
    }

    /// Receives one application-data record into `buf`, returning its length.
    ///
    /// # Errors
    /// An [`io::Error`] if the handshake has not completed or the transport fails.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.handshake_done {
            return Err(proto("read before handshake"));
        }
        loop {
            if let Some(data) = self.app_buf.pop_front() {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Ok(n);
            }
            self.transport.set_read_timeout(None)?;
            let mut scratch = vec![0u8; RECV_BUF];
            let n = self.transport.recv(&mut scratch)?;
            self.process_datagram(&scratch[..n])?;
        }
    }

    // --- client handshake ---

    // The six DTLS flights are one linear sequence whose ordering (and the transcript
    // hashing interleaved with it) is the logic; splitting it across helpers would hide
    // the flow rather than clarify it. The server counterpart is structured the same way.
    #[allow(clippy::too_many_lines)]
    fn client_handshake(&mut self) -> io::Result<()> {
        let client_random = random32()?;

        // Flight 1: ClientHello without a cookie (not hashed).
        let ch1 = self.build_client_hello(&client_random, &[]);
        let f1 = vec![self.emit_handshake(HandshakeType::ClientHello, &ch1, 0, false)];
        self.send_flight(&f1)?;

        // Flight 2: HelloVerifyRequest.
        let hvr_msgs = self.read_flight(HandshakeType::HelloVerifyRequest, &f1)?;
        let hvr =
            HelloVerifyRequest::parse(&last_of(&hvr_msgs, HandshakeType::HelloVerifyRequest)?)
                .map_err(dtls_err)?;

        // Flight 3: ClientHello with the cookie (hashed — the first transcript msg).
        let ch3 = self.build_client_hello(&client_random, &hvr.cookie);
        let f3 = vec![self.emit_handshake(HandshakeType::ClientHello, &ch3, 0, true)];
        self.send_flight(&f3)?;

        // Flight 4: ServerHello … ServerHelloDone (hash every message).
        let f4 = self.read_flight(HandshakeType::ServerHelloDone, &f3)?;
        for m in &f4 {
            self.hash_incoming(m);
        }
        let sh =
            ServerHello::parse(&body_of(&f4, HandshakeType::ServerHello)?).map_err(dtls_err)?;
        self.cipher_suite = sh.cipher_suite;
        self.suite = lookup_suite(sh.cipher_suite)
            .ok_or_else(|| proto("server selected an unsupported suite"))?;
        // The server must not select a suite the client did not offer: a malicious
        // server could otherwise force a downgrade (e.g. to the cleartext
        // RSA_WITH_NULL_SHA256, or any suite the user disabled) that the client never
        // put on the wire. `client_can_offer` is exactly the predicate that built the
        // ClientHello suite list, so re-checking it rejects an off-list selection.
        if !self.cfg.client_can_offer(self.suite) {
            return Err(proto("server selected a suite we did not offer"));
        }
        let server_random = sh.random;
        let ems = sh.ext_master_secret;
        if self.cfg.require_extended_master_secret && !ems {
            return Err(proto("server omitted extended_master_secret"));
        }

        // A CertificateRequest asks the client to authenticate. It is meaningful only
        // in a certificate handshake; in a PSK handshake honoring it would emit a
        // certificate over the cleartext epoch-0 channel, so reject it there.
        let cert_requested = f4
            .iter()
            .any(|m| m.typ == HandshakeType::CertificateRequest);
        if cert_requested && self.suite.kx == KeyExchange::Psk {
            return Err(proto("unexpected CertificateRequest in PSK handshake"));
        }

        // Flight 5: [Certificate,] ClientKeyExchange, [CertificateVerify,] CCS,
        // Finished. Derive the premaster and the ClientKeyExchange body per the
        // negotiated suite's key exchange.
        let (pre_master, cke) = match self.suite.kx {
            KeyExchange::Psk => {
                let psk = self
                    .cfg
                    .psk
                    .clone()
                    .ok_or_else(|| proto("PSK not configured"))?;
                (
                    psk_premaster(&psk),
                    client_key_exchange_psk(&self.cfg.psk_identity),
                )
            }
            KeyExchange::Ecdhe => self.client_ecdhe(&f4, &client_random, &server_random)?,
            KeyExchange::Rsa => self.client_rsa(&f4)?,
        };

        let mut f5 = Vec::new();
        // When asked, present our certificate — an empty chain if none is configured,
        // which the server's `require_client_cert` then rejects. The same identity
        // signs the CertificateVerify below.
        let client_identity = if cert_requested {
            self.cfg.certificate.clone()
        } else {
            None
        };
        if cert_requested {
            let chain = client_identity
                .as_ref()
                .map(|id| vec![id.der().to_vec()])
                .unwrap_or_default();
            let cert_body = CertificateMsg { chain }.marshal_body();
            f5.push(self.emit_handshake(HandshakeType::Certificate, &cert_body, 0, true));
        }

        f5.push(self.emit_handshake(HandshakeType::ClientKeyExchange, &cke, 0, true));
        // The transcript now runs through ClientKeyExchange: the seed for the EMS
        // master secret, and the region a CertificateVerify signs.
        let session_hash = self.transcript_hash();
        let master = derive_master(
            self.suite.hash,
            ems,
            &pre_master,
            &session_hash,
            &client_random,
            &server_random,
        );
        self.keys = Some(derive_keys(
            self.suite,
            &master,
            &client_random,
            &server_random,
        ));
        self.drain_pending()?;

        // Prove possession of the certificate's private key by signing the transcript
        // through ClientKeyExchange (RFC 5246 §7.4.8); sent only when we presented a
        // certificate.
        if cert_requested && let Some(id) = client_identity.as_ref() {
            let (sig_scheme, signature) =
                cert::sign_handshake(id, &self.transcript).map_err(dtls_err)?;
            let cv_body = CertificateVerify {
                sig_scheme,
                signature,
            }
            .marshal_body();
            f5.push(self.emit_handshake(HandshakeType::CertificateVerify, &cv_body, 0, true));
        }

        // The client Finished covers the transcript through CertificateVerify, so its
        // verify_data is taken after the CV is hashed (with no CV this equals the
        // through-ClientKeyExchange hash, so the non-mutual path is unchanged).
        let client_fin = finished_verify_data(
            self.suite.hash,
            &master,
            LABEL_CLIENT_FINISHED,
            &self.transcript_hash(),
        );
        f5.push(RecordSpec {
            typ: ContentType::ChangeCipherSpec,
            epoch: 0,
            payload: vec![1],
        });
        f5.push(self.emit_handshake(HandshakeType::Finished, &client_fin, 1, true));
        self.send_flight(&f5)?;

        // Flight 6: ChangeCipherSpec, Finished (server).
        let f6 = self.read_flight(HandshakeType::Finished, &f5)?;
        self.verify_peer_finished(&f6, &master, LABEL_SERVER_FINISHED)?;
        self.handshake_done = true;
        Ok(())
    }

    fn build_client_hello(&self, random: &[u8; RANDOM_LEN], cookie: &[u8]) -> Vec<u8> {
        // The offered suites are the table entries this config can offer, in
        // server-preference (strongest-first) order.
        let cipher_suites: Vec<u16> = SUITE_TABLE
            .iter()
            .filter(|s| self.cfg.client_can_offer(**s))
            .map(|s| s.id)
            .collect();
        let any_ecdhe = SUITE_TABLE
            .iter()
            .any(|s| s.kx == KeyExchange::Ecdhe && cipher_suites.contains(&s.id));
        let any_cert = SUITE_TABLE
            .iter()
            .any(|s| s.auth != AuthMethod::None && cipher_suites.contains(&s.id));
        ClientHello {
            version: VERSION_DTLS_1_2,
            random: *random,
            session_id: Vec::new(),
            cookie: cookie.to_vec(),
            cipher_suites,
            ext_master_secret: true,
            // Offer the EC parameters only when offering an ECDHE suite.
            supported_groups: if any_ecdhe {
                vec![NAMED_GROUP_SECP256R1]
            } else {
                Vec::new()
            },
            point_formats: if any_ecdhe { vec![0] } else { Vec::new() },
            point_formats_offered: any_ecdhe,
            // Offer signature_algorithms (ECDSA + RSA, SHA-256/384) when offering any
            // certificate suite, so the server may authenticate with either key type.
            signature_algorithms: if any_cert {
                OFFERED_SIGNATURE_ALGORITHMS.to_vec()
            } else {
                Vec::new()
            },
            secure_renegotiation: true,
        }
        .marshal_body()
    }

    /// The client's ECDHE key agreement (ECDSA- or RSA-authenticated): verify the
    /// server's certificate and ServerKeyExchange signature (from flight 4), generate
    /// the client ephemeral, and return the premaster secret and ClientKeyExchange
    /// body. Rejecting a ServerKeyExchange whose Certificate is absent falls out of
    /// `body_of` (it errors), so the signature is never checked without a leaf key.
    fn client_ecdhe(
        &self,
        flight4: &[Incoming],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let cert_msg = CertificateMsg::parse(&body_of(flight4, HandshakeType::Certificate)?)
            .map_err(dtls_err)?;
        let ske = ServerKeyExchange::parse(&body_of(flight4, HandshakeType::ServerKeyExchange)?)
            .map_err(dtls_err)?;
        let leaf_key = cert::verify_peer(
            &cert_msg.chain,
            self.cfg.insecure_skip_verify,
            self.cfg.peer_cert_fingerprint,
        )
        .map_err(dtls_err)?;
        // The presented leaf's key type must match the negotiated suite's auth method.
        if leaf_key.auth_method() != self.suite.auth {
            return Err(proto(
                "server leaf key type does not match the negotiated suite",
            ));
        }
        // The signature covers client_random || server_random || signed ECDHE params.
        let mut signed = Vec::with_capacity(64 + ske.public_key.len());
        signed.extend_from_slice(client_random);
        signed.extend_from_slice(server_random);
        signed.extend_from_slice(&ske.signed_params());
        if !cert::verify_handshake_signature(&leaf_key, ske.sig_scheme, &signed, &ske.signature) {
            return Err(proto("bad ServerKeyExchange signature"));
        }
        let (client_secret, client_point) = generate_ecdhe();
        let pre_master = ecdhe_premaster(&client_secret, &ske.public_key).map_err(dtls_err)?;
        Ok((pre_master, client_key_exchange_ecdhe(&client_point)))
    }

    /// The client's RSA key transport (`RSA_WITH_NULL_SHA256`): verify the server's
    /// RSA certificate, then encrypt a fresh pre-master under its public key. No
    /// ServerKeyExchange is sent for RSA key transport — one arriving is a protocol
    /// violation.
    fn client_rsa(&self, flight4: &[Incoming]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        if flight4
            .iter()
            .any(|m| m.typ == HandshakeType::ServerKeyExchange)
        {
            return Err(proto("unexpected ServerKeyExchange for RSA key transport"));
        }
        let cert_msg = CertificateMsg::parse(&body_of(flight4, HandshakeType::Certificate)?)
            .map_err(dtls_err)?;
        let leaf_key = cert::verify_peer(
            &cert_msg.chain,
            self.cfg.insecure_skip_verify,
            self.cfg.peer_cert_fingerprint,
        )
        .map_err(dtls_err)?;
        let pub_key = match &leaf_key {
            PeerKey::Rsa(_) if leaf_key.auth_method() == self.suite.auth => leaf_key
                .rsa_public_key()
                .ok_or_else(|| proto("missing RSA public key"))?,
            _ => {
                return Err(proto(
                    "RSA key transport requires an RSA server certificate",
                ));
            }
        };
        let pms = new_rsa_premaster().map_err(dtls_err)?;
        let ct = encrypt_rsa_premaster(pub_key, &pms).map_err(dtls_err)?;
        Ok((pms, client_key_exchange_rsa(&ct)))
    }

    /// Selects the server's cipher suite: the first table entry (strongest first)
    /// the client offered that this config can serve and the user has not disabled.
    fn select_server_suite(&self, ch: &ClientHello) -> Option<u16> {
        SUITE_TABLE
            .iter()
            .find(|s| ch.cipher_suites.contains(&s.id) && self.cfg.server_can_serve(**s))
            .map(|s| s.id)
    }

    // --- server handshake ---

    #[allow(clippy::too_many_lines)] // a six-flight state machine reads best whole
    fn server_handshake(&mut self) -> io::Result<()> {
        let server_random = random32()?;

        // Flight 1: ClientHello (cookieless, not hashed).
        let f1 = self.read_flight(HandshakeType::ClientHello, &[])?;
        let ch1 =
            ClientHello::parse(&body_of(&f1, HandshakeType::ClientHello)?).map_err(dtls_err)?;
        if self.select_server_suite(&ch1).is_none() {
            return Err(proto("no common cipher suite"));
        }

        // Flight 2: HelloVerifyRequest with a fresh cookie (not hashed).
        let cookie = random_cookie()?;
        let hvr = HelloVerifyRequest {
            version: VERSION_DTLS_1_0,
            cookie: cookie.clone(),
        }
        .marshal_body();
        let f2 = vec![self.emit_handshake(HandshakeType::HelloVerifyRequest, &hvr, 0, false)];
        self.send_flight(&f2)?;

        // Flight 3: ClientHello echoing the cookie (the first transcript message).
        let f3 = self.read_flight(HandshakeType::ClientHello, &f2)?;
        let ch3_in = single(&f3, HandshakeType::ClientHello)?;
        let ch3 = ClientHello::parse(&ch3_in.body).map_err(dtls_err)?;
        if ch3.cookie.ct_eq(&cookie).unwrap_u8() != 1 {
            return Err(proto("bad cookie"));
        }
        self.hash_incoming(ch3_in);
        let suite = self
            .select_server_suite(&ch3)
            .ok_or_else(|| proto("no common cipher suite"))?;
        self.cipher_suite = suite;
        self.suite = lookup_suite(suite).expect("selected suite is in the table");
        let is_ecdhe = self.suite.kx == KeyExchange::Ecdhe;
        let cert_suite = self.suite.auth != AuthMethod::None;
        let client_random = ch3.random;
        let ems = ch3.ext_master_secret;

        // Flight 4: ServerHello [, Certificate, ServerKeyExchange], ServerHelloDone.
        let sh = ServerHello {
            version: VERSION_DTLS_1_2,
            random: server_random,
            session_id: Vec::new(),
            cipher_suite: suite,
            ext_master_secret: ems,
            point_formats: is_ecdhe && ch3.point_formats_offered,
            secure_renegotiation: ch3.secure_renegotiation,
        }
        .marshal_body();
        let mut f4 = vec![self.emit_handshake(HandshakeType::ServerHello, &sh, 0, true)];
        let mut server_secret = None;
        if cert_suite {
            let identity = self
                .cfg
                .certificate
                .clone()
                .ok_or_else(|| proto("no certificate configured"))?;
            let cert_msg = CertificateMsg {
                chain: vec![identity.der().to_vec()],
            };
            f4.push(self.emit_handshake(
                HandshakeType::Certificate,
                &cert_msg.marshal_body(),
                0,
                true,
            ));
            // ECDHE sends a signed ServerKeyExchange; RSA key transport sends none
            // (the client encrypts the pre-master to the certificate's public key).
            if is_ecdhe {
                let (secret, point) = generate_ecdhe();
                let mut ske = ServerKeyExchange {
                    curve: NAMED_GROUP_SECP256R1,
                    public_key: point,
                    sig_scheme: 0,
                    signature: Vec::new(),
                };
                let mut signed = Vec::with_capacity(64 + ske.public_key.len());
                signed.extend_from_slice(&client_random);
                signed.extend_from_slice(&server_random);
                signed.extend_from_slice(&ske.signed_params());
                // Sign with the certificate's key type (ECDSA or RSA), SHA-256.
                let (sig_scheme, signature) =
                    cert::sign_handshake(&identity, &signed).map_err(dtls_err)?;
                ske.sig_scheme = sig_scheme;
                ske.signature = signature;
                f4.push(self.emit_handshake(
                    HandshakeType::ServerKeyExchange,
                    &ske.marshal_body(),
                    0,
                    true,
                ));
                server_secret = Some(secret);
            }
        }
        // Mutual auth: a certificate-suite server asks the client to authenticate.
        // (A CertificateRequest is meaningless without a server certificate, so it is
        // gated on `cert_suite`.)
        if cert_suite && self.cfg.require_client_cert {
            f4.push(self.emit_handshake(
                HandshakeType::CertificateRequest,
                &certificate_request_body(),
                0,
                true,
            ));
        }
        f4.push(self.emit_handshake(HandshakeType::ServerHelloDone, &[], 0, true));
        self.send_flight(&f4)?;

        // Flight 5a: read through ClientKeyExchange. The ChangeCipherSpec and the
        // (encrypted) Finished may share this datagram; the Finished is buffered
        // until the keys derived from this ClientKeyExchange exist.
        let f5 = self.read_flight(HandshakeType::ClientKeyExchange, &f4)?;
        let cke_in = single(&f5, HandshakeType::ClientKeyExchange)?;

        // Mutual auth: a client Certificate precedes the ClientKeyExchange. Hash it
        // into the transcript first (preserving wire order), then parse and verify the
        // leaf against our peer policy. The leaf is held aside, NOT authenticated: a
        // CertificateVerify must prove possession of its private key before it counts
        // (RFC 5246 §7.4.8) — otherwise an attacker holding only the victim's public
        // certificate could impersonate the owner, defeating the fingerprint pin.
        let mut client_leaf: Option<PeerKey> = None;
        if let Some(cert_in) = f5.iter().find(|m| m.typ == HandshakeType::Certificate) {
            self.hash_incoming(cert_in);
            let cm = CertificateMsg::parse(&cert_in.body).map_err(dtls_err)?;
            if cm.chain.is_empty() {
                if self.cfg.require_client_cert {
                    return Err(proto("client certificate required but none sent"));
                }
            } else {
                client_leaf = Some(
                    cert::verify_peer(
                        &cm.chain,
                        self.cfg.insecure_skip_verify,
                        self.cfg.peer_cert_fingerprint,
                    )
                    .map_err(dtls_err)?,
                );
            }
        } else if self.cfg.require_client_cert {
            return Err(proto("client certificate required but none sent"));
        }

        let pre_master = match self.suite.kx {
            KeyExchange::Ecdhe => {
                let point = parse_client_key_exchange_ecdhe(&cke_in.body).map_err(dtls_err)?;
                let secret = server_secret.ok_or_else(|| proto("missing ECDHE secret"))?;
                ecdhe_premaster(&secret, &point).map_err(dtls_err)?
            }
            KeyExchange::Rsa => {
                let ct = parse_client_key_exchange_rsa(&cke_in.body).map_err(dtls_err)?;
                let identity = self
                    .cfg
                    .certificate
                    .clone()
                    .ok_or_else(|| proto("no certificate configured"))?;
                let rsa_key = identity
                    .rsa_private_key()
                    .ok_or_else(|| proto("RSA key transport requires an RSA certificate"))?;
                // The Bleichenbacher countermeasure yields a random pre-master on any
                // failure, so the handshake fails uniformly at Finished.
                decrypt_rsa_premaster(rsa_key, &ct).map_err(dtls_err)?
            }
            KeyExchange::Psk => {
                let identity = parse_client_key_exchange_psk(&cke_in.body).map_err(dtls_err)?;
                if identity != self.cfg.psk_identity {
                    return Err(proto("unknown PSK identity"));
                }
                let psk = self
                    .cfg
                    .psk
                    .clone()
                    .ok_or_else(|| proto("PSK not configured"))?;
                psk_premaster(&psk)
            }
        };
        self.hash_incoming(cke_in);
        let session_hash = self.transcript_hash();
        let master = derive_master(
            self.suite.hash,
            ems,
            &pre_master,
            &session_hash,
            &client_random,
            &server_random,
        );
        self.keys = Some(derive_keys(
            self.suite,
            &master,
            &client_random,
            &server_random,
        ));
        self.drain_pending()?; // decrypt the buffered Finished now that keys exist

        // Flight 5b: the client's [CertificateVerify,] Finished (the CV is epoch 0,
        // the Finished epoch 1).
        let fin_flight = self.read_flight(HandshakeType::Finished, &f4)?;

        // A CertificateVerify proves the client holds its certificate's private key.
        // Verify its signature over the transcript through ClientKeyExchange (the CV is
        // not yet hashed), then fold the CV into the transcript so the Finished MAC —
        // which the client computed over the transcript including the CV — matches.
        let mut saw_valid_cv = false;
        if let Some(cv_in) = fin_flight
            .iter()
            .find(|m| m.typ == HandshakeType::CertificateVerify)
        {
            let cv = CertificateVerify::parse(&cv_in.body).map_err(dtls_err)?;
            let leaf = client_leaf
                .as_ref()
                .ok_or_else(|| proto("CertificateVerify without a client certificate"))?;
            let signed = self.transcript.clone();
            if !cert::verify_handshake_signature(leaf, cv.sig_scheme, &signed, &cv.signature) {
                return Err(proto("client CertificateVerify signature mismatch"));
            }
            self.hash_incoming(cv_in);
            saw_valid_cv = true;
        }
        // Proof-of-possession gate (RFC 5246 §7.4.8): a presented client certificate —
        // or a mandated mutual auth — requires a verified CertificateVerify. The
        // Finished MAC alone proves nothing about the certificate's private key.
        if (client_leaf.is_some() || self.cfg.require_client_cert) && !saw_valid_cv {
            return Err(proto(
                "client did not authenticate (missing CertificateVerify)",
            ));
        }

        self.verify_peer_finished(&fin_flight, &master, LABEL_CLIENT_FINISHED)?;

        // Flight 6: ChangeCipherSpec, Finished (server).
        let server_fin = finished_verify_data(
            self.suite.hash,
            &master,
            LABEL_SERVER_FINISHED,
            &self.transcript_hash(),
        );
        let ccs = RecordSpec {
            typ: ContentType::ChangeCipherSpec,
            epoch: 0,
            payload: vec![1],
        };
        let fin_spec = self.emit_handshake(HandshakeType::Finished, &server_fin, 1, true);
        self.send_flight(&[ccs, fin_spec])?;
        self.handshake_done = true;
        Ok(())
    }

    /// Verifies the peer's Finished message (which must arrive under epoch 1) and,
    /// on success, hashes it into the transcript.
    fn verify_peer_finished(
        &mut self,
        flight: &[Incoming],
        master: &[u8; 48],
        label: &str,
    ) -> io::Result<()> {
        let fin = single(flight, HandshakeType::Finished)?;
        if fin.epoch != 1 {
            return Err(proto("Finished not under epoch 1"));
        }
        let expect = finished_verify_data(self.suite.hash, master, label, &self.transcript_hash());
        if fin.body.ct_eq(&expect).unwrap_u8() != 1 {
            return Err(proto("Finished verify_data mismatch"));
        }
        // Hashing the verified peer Finished closes the transcript for our own
        // Finished / the session.
        let m = Incoming {
            typ: fin.typ,
            message_seq: fin.message_seq,
            body: fin.body.clone(),
            epoch: fin.epoch,
        };
        self.hash_incoming(&m);
        Ok(())
    }

    // --- record + flight I/O ---

    /// Appends one handshake message to a flight: allocates its `message_seq`,
    /// optionally hashes it into the transcript, and returns its record spec.
    fn emit_handshake(
        &mut self,
        typ: HandshakeType,
        body: &[u8],
        epoch: u16,
        hash: bool,
    ) -> RecordSpec {
        let seq = self.send_msg_seq;
        self.send_msg_seq = self.send_msg_seq.wrapping_add(1);
        let payload = full_message_bytes(typ, seq, body);
        if hash {
            self.transcript.extend_from_slice(&payload);
        }
        RecordSpec {
            typ: ContentType::Handshake,
            epoch,
            payload,
        }
    }

    /// Marshals and transmits a flight as one datagram, allocating fresh record
    /// sequence numbers (so retransmits never reuse a GCM nonce).
    fn send_flight(&mut self, specs: &[RecordSpec]) -> io::Result<()> {
        let mut datagram = Vec::new();
        for spec in specs {
            let idx = usize::from(spec.epoch & 1);
            let seq = self.send_seq[idx];
            self.send_seq[idx] += 1;
            let fragment = if spec.epoch == 1 {
                let keys = self
                    .keys
                    .as_ref()
                    .ok_or_else(|| proto("epoch-1 send before keys"))?;
                let sealer = if self.is_client {
                    &keys.client_write
                } else {
                    &keys.server_write
                };
                sealer.seal(spec.epoch, seq, spec.typ, VERSION_DTLS_1_2, &spec.payload)
            } else {
                spec.payload.clone()
            };
            Record {
                typ: spec.typ,
                version: VERSION_DTLS_1_2,
                epoch: spec.epoch,
                seq,
                fragment,
            }
            .marshal(&mut datagram);
        }
        self.transport.send(&datagram)?;
        Ok(())
    }

    /// Reads inbound datagrams (retransmitting `last_flight` on timeout) until a
    /// handshake message of type `until` has been reassembled, returning the whole
    /// flight up to and including it.
    fn read_flight(
        &mut self,
        until: HandshakeType,
        last_flight: &[RecordSpec],
    ) -> io::Result<Vec<Incoming>> {
        let overall = Instant::now() + self.cfg.handshake_timeout;
        let mut retransmit = self.cfg.retransmit_timeout;
        let mut collected: Vec<Incoming> = Vec::new();
        loop {
            while let Some((typ, body, message_seq, epoch)) = self.reasm.next_message() {
                let done = typ == until;
                collected.push(Incoming {
                    typ,
                    message_seq,
                    body,
                    epoch,
                });
                if done {
                    return Ok(collected);
                }
            }
            let now = Instant::now();
            if now >= overall {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "rist: dtls: handshake timeout",
                ));
            }
            let deadline = (now + retransmit).min(overall);
            if let Some(dg) = self.read_datagram(deadline)? {
                self.process_datagram(&dg)?;
            } else {
                // Timed out: retransmit the last flight (fresh record seqs) and back
                // off (RFC 6347 §4.2.4.1).
                if !last_flight.is_empty() {
                    self.send_flight(last_flight)?;
                }
                retransmit = (retransmit * 2).min(MAX_RETRANSMIT);
            }
        }
    }

    /// Reads one datagram subject to `deadline`, returning `None` on timeout.
    fn read_datagram(&mut self, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        self.transport.set_read_timeout(Some(deadline - now))?;
        let mut scratch = vec![0u8; RECV_BUF];
        match self.transport.recv(&mut scratch) {
            Ok(n) => Ok(Some(scratch[..n].to_vec())),
            Err(e) if is_timeout(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Splits one datagram into records and processes each.
    fn process_datagram(&mut self, datagram: &[u8]) -> io::Result<()> {
        for rec in split_records(datagram).map_err(dtls_err)? {
            self.process_record(rec)?;
        }
        Ok(())
    }

    /// Processes one record: decrypts an epoch-1 record (buffering it if keys are
    /// not yet derived), applies the anti-replay filter, and routes it —
    /// ChangeCipherSpec is a no-op (the epoch is carried per-record), Handshake
    /// fragments feed the reassembler, ApplicationData buffers, an Alert aborts.
    fn process_record(&mut self, rec: Record) -> io::Result<()> {
        let idx = usize::from(rec.epoch & 1);
        if rec.epoch == 1 && self.keys.is_none() {
            // The peer's Finished can share a flight with the ClientKeyExchange that
            // derives the keys; stash it and reprocess once they exist.
            self.pending_records.push(rec);
            return Ok(());
        }
        if !self.replay[idx].check(rec.seq) {
            return Ok(()); // replay or too-old: drop
        }
        let fragment = if rec.epoch == 1 {
            let keys = self.keys.as_ref().expect("keys present (checked above)");
            let opener = if self.is_client {
                &keys.server_write
            } else {
                &keys.client_write
            };
            match opener.open(rec.epoch, rec.seq, rec.typ, rec.version, &rec.fragment) {
                Ok(pt) => pt,
                Err(_) => return Ok(()), // undecryptable: drop without marking
            }
        } else {
            rec.fragment.clone()
        };
        self.replay[idx].mark(rec.seq);

        match rec.typ {
            ContentType::ChangeCipherSpec => {}
            ContentType::Handshake => self.feed_handshake(&fragment, rec.epoch)?,
            ContentType::ApplicationData => self.app_buf.push_back(fragment),
            ContentType::Alert => return Err(proto("peer alert")),
        }
        Ok(())
    }

    /// Reprocesses records that were buffered before the keys existed (called right
    /// after the keys are derived).
    fn drain_pending(&mut self) -> io::Result<()> {
        for rec in std::mem::take(&mut self.pending_records) {
            self.process_record(rec)?;
        }
        Ok(())
    }

    /// Feeds the handshake fragments packed in one record to the reassembler.
    fn feed_handshake(&mut self, mut body: &[u8], epoch: u16) -> io::Result<()> {
        while !body.is_empty() {
            let (hdr, payload) = FragmentHeader::parse(body).map_err(dtls_err)?;
            let consumed = HANDSHAKE_HEADER_LEN + payload.len();
            self.reasm.accept(hdr, payload, epoch).map_err(dtls_err)?;
            body = &body[consumed..];
        }
        Ok(())
    }

    fn hash_incoming(&mut self, m: &Incoming) {
        self.transcript
            .extend_from_slice(&full_message_bytes(m.typ, m.message_seq, &m.body));
    }

    /// The handshake transcript hash under the negotiated suite's hash (32 bytes for
    /// SHA-256, 48 for SHA-384). Before negotiation it uses the SHA-256 default, but
    /// it is only consulted after the suite is fixed.
    fn transcript_hash(&self) -> Vec<u8> {
        self.suite.hash.digest(&self.transcript)
    }
}

/// Derives the master secret under the suite `hash`, using the extended scheme (RFC
/// 7627) when both peers agreed, else the classic randoms-based scheme (RFC 5246).
fn derive_master(
    hash: PrfHash,
    ems: bool,
    pre_master: &[u8],
    session_hash: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    if ems {
        extended_master_secret(hash, pre_master, session_hash)
    } else {
        master_secret(hash, pre_master, client_random, server_random)
    }
}

/// The PSK premaster secret (RFC 4279 §2): `uint16(n) || zeros(n) || uint16(n) ||
/// psk`.
fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let n = u16::try_from(psk.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(4 + 2 * psk.len());
    out.extend_from_slice(&n.to_be_bytes());
    out.resize(out.len() + psk.len(), 0);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(psk);
    out
}

/// A 32-byte random (handshake `random`).
fn random32() -> io::Result<[u8; RANDOM_LEN]> {
    let mut r = [0u8; RANDOM_LEN];
    getrandom::fill(&mut r).map_err(|_| io::Error::other("rist: dtls: CSPRNG unavailable"))?;
    Ok(r)
}

/// A fresh stateless cookie.
fn random_cookie() -> io::Result<Vec<u8>> {
    let mut c = vec![0u8; COOKIE_LEN];
    getrandom::fill(&mut c).map_err(|_| io::Error::other("rist: dtls: CSPRNG unavailable"))?;
    Ok(c)
}

/// Whether an I/O error is a (non-fatal) read timeout.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Wraps a [`super::DtlsError`] as an `io::Error`. Taken by value so it composes
/// with `Result::map_err`, which yields the error owned.
#[allow(clippy::needless_pass_by_value)]
fn dtls_err(e: super::DtlsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// A protocol-violation `io::Error`.
fn proto(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("rist: dtls: {msg}"))
}

/// The body of the (single expected) message of type `typ` in `flight`.
fn body_of(flight: &[Incoming], typ: HandshakeType) -> io::Result<Vec<u8>> {
    flight
        .iter()
        .find(|m| m.typ == typ)
        .map(|m| m.body.clone())
        .ok_or_else(|| proto("missing expected handshake message"))
}

/// Like [`body_of`], for the last message (used for HelloVerifyRequest).
fn last_of(flight: &[Incoming], typ: HandshakeType) -> io::Result<Vec<u8>> {
    body_of(flight, typ)
}

/// The single message of type `typ` in `flight` (by reference).
fn single(flight: &[Incoming], typ: HandshakeType) -> io::Result<&Incoming> {
    flight
        .iter()
        .find(|m| m.typ == typ)
        .ok_or_else(|| proto("missing expected handshake message"))
}

#[cfg(test)]
mod tests {
    use super::super::suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    use super::*;
    use std::sync::mpsc::{Receiver, Sender, channel};

    /// An in-memory datagram pipe transport for the self-interop test.
    struct Pipe {
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
        timeout: Option<Duration>,
    }

    impl Transport for Pipe {
        fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
            let _ = self.tx.send(datagram.to_vec());
            Ok(datagram.len())
        }
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let dg = match self.timeout {
                Some(t) => self
                    .rx
                    .recv_timeout(t)
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timeout"))?,
                None => self
                    .rx
                    .recv()
                    .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "closed"))?,
            };
            let n = dg.len().min(buf.len());
            buf[..n].copy_from_slice(&dg[..n]);
            Ok(n)
        }
        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.timeout = timeout;
            Ok(())
        }
    }

    /// Rewrites the cipher suite of the first ServerHello in a flight to `forced`,
    /// re-marshaling that record and passing the rest through. Returns `None` if no
    /// ServerHello is present (e.g. the HelloVerifyRequest flight).
    fn force_serverhello_suite(datagram: &[u8], forced: u16) -> Option<Vec<u8>> {
        let recs = split_records(datagram).ok()?;
        let mut out = Vec::new();
        let mut changed = false;
        for rec in recs {
            if !changed
                && rec.typ == ContentType::Handshake
                && let Ok((hdr, payload)) = FragmentHeader::parse(&rec.fragment)
                && hdr.typ == HandshakeType::ServerHello
                && hdr.fragment_offset == 0
                && let Ok(mut sh) = ServerHello::parse(payload)
            {
                sh.cipher_suite = forced;
                let fragment = full_message_bytes(
                    HandshakeType::ServerHello,
                    hdr.message_seq,
                    &sh.marshal_body(),
                );
                Record {
                    typ: rec.typ,
                    version: rec.version,
                    epoch: rec.epoch,
                    seq: rec.seq,
                    fragment,
                }
                .marshal(&mut out);
                changed = true;
                continue;
            }
            rec.marshal(&mut out);
        }
        changed.then_some(out)
    }

    /// A man-in-the-middle transport that rewrites the server's selected suite to
    /// `forced` on the first ServerHello it relays toward the client.
    struct ForceSuite {
        inner: Pipe,
        forced: u16,
        done: bool,
    }

    impl Transport for ForceSuite {
        fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
            self.inner.send(datagram)
        }
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut tmp = vec![0u8; buf.len()];
            let n = self.inner.recv(&mut tmp)?;
            let dg = &tmp[..n];
            let out = if self.done {
                dg.to_vec()
            } else if let Some(rw) = force_serverhello_suite(dg, self.forced) {
                self.done = true;
                rw
            } else {
                dg.to_vec()
            };
            let m = out.len().min(buf.len());
            buf[..m].copy_from_slice(&out[..m]);
            Ok(m)
        }
        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_read_timeout(timeout)
        }
    }

    fn pipe() -> (Pipe, Pipe) {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        (
            Pipe {
                tx: a_tx,
                rx: b_rx,
                timeout: None,
            },
            Pipe {
                tx: b_tx,
                rx: a_rx,
                timeout: None,
            },
        )
    }

    /// Overlays short timeouts on a config so a failed handshake fails fast.
    fn short(base: Config) -> Config {
        Config {
            handshake_timeout: Duration::from_secs(3),
            retransmit_timeout: Duration::from_millis(100),
            ..base
        }
    }

    /// A PSK config with short timeouts.
    fn test_cfg(key: &[u8]) -> Config {
        short(Config::psk(b"id".to_vec(), key.to_vec()))
    }

    #[test]
    fn ecdhe_handshake_self_interop() {
        let identity = crate::dtls::cert::Identity::generate("ristrust-test-server").unwrap();
        let pin = crate::dtls::cert::fingerprint(identity.der());
        let (cp, sp) = pipe();
        let server = std::thread::spawn(move || {
            let mut s = Conn::server(sp, short(Config::ecdhe_server(identity)));
            s.handshake().expect("server handshake");
            let mut buf = vec![0u8; 1500];
            let n = s.read(&mut buf).expect("server read");
            s.write(&buf[..n]).expect("server write");
            s.cipher_suite()
        });

        let mut c = Conn::client(cp, short(Config::ecdhe_client_pinned(pin)));
        c.handshake().expect("client handshake");
        // An ECDSA certificate negotiates the strongest ECDSA suite the table offers.
        assert_eq!(c.cipher_suite(), TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        c.write(b"ecdhe app data").expect("client write");
        let mut buf = vec![0u8; 1500];
        let n = c.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"ecdhe app data");
        assert_eq!(
            server.join().expect("server thread"),
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
    }

    #[test]
    fn ecdhe_fingerprint_mismatch_fails() {
        let identity = crate::dtls::cert::Identity::generate("server").unwrap();
        let (cp, sp) = pipe();
        let server = std::thread::spawn(move || {
            let mut s = Conn::server(sp, short(Config::ecdhe_server(identity)));
            s.handshake().is_err()
        });
        // The client pins a different fingerprint: certificate verification must fail.
        let mut c = Conn::client(cp, short(Config::ecdhe_client_pinned([0xAB; 32])));
        let client_failed = c.handshake().is_err();
        let server_failed = server.join().expect("server thread");
        assert!(
            client_failed || server_failed,
            "a fingerprint mismatch must fail the handshake"
        );
    }

    #[test]
    fn ecdhe_mutual_auth_self_interop() {
        // Both ends present an ECDSA certificate and pin the other's fingerprint.
        let server_id = crate::dtls::cert::Identity::generate("mutual-server").unwrap();
        let client_id = crate::dtls::cert::Identity::generate("mutual-client").unwrap();
        let server_pin = crate::dtls::cert::fingerprint(server_id.der());
        let client_pin = crate::dtls::cert::fingerprint(client_id.der());
        let (cp, sp) = pipe();

        let server = std::thread::spawn(move || {
            let mut s = Conn::server(sp, {
                short(Config {
                    require_client_cert: true,
                    peer_cert_fingerprint: Some(client_pin),
                    ..Config::ecdhe_server(server_id)
                })
            });
            s.handshake().expect("server handshake");
            let mut buf = vec![0u8; 1500];
            let n = s.read(&mut buf).expect("server read");
            s.write(&buf[..n]).expect("server write");
            s.cipher_suite()
        });

        let mut c = Conn::client(
            cp,
            short(Config {
                certificate: Some(Arc::new(client_id)),
                ..Config::ecdhe_client_pinned(server_pin)
            }),
        );
        c.handshake().expect("client handshake");
        assert_eq!(c.cipher_suite(), TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        c.write(b"mutual app data").expect("client write");
        let mut buf = vec![0u8; 1500];
        let n = c.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"mutual app data");
        assert_eq!(
            server.join().expect("server thread"),
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
    }

    #[test]
    fn mutual_auth_missing_client_cert_fails() {
        // The server requires a client certificate; the client offers none. The
        // server must reject (empty client Certificate, no CertificateVerify).
        let server_id = crate::dtls::cert::Identity::generate("server").unwrap();
        let server_pin = crate::dtls::cert::fingerprint(server_id.der());
        let (cp, sp) = pipe();

        let server = std::thread::spawn(move || {
            let mut s = Conn::server(
                sp,
                short(Config {
                    require_client_cert: true,
                    insecure_skip_verify: true,
                    ..Config::ecdhe_server(server_id)
                }),
            );
            s.handshake().is_err()
        });

        // A pinned client with no certificate of its own.
        let mut c = Conn::client(cp, short(Config::ecdhe_client_pinned(server_pin)));
        let client_failed = c.handshake().is_err();
        assert!(
            server.join().expect("server thread"),
            "server must reject a client that sent no certificate"
        );
        let _ = client_failed;
    }

    #[test]
    fn mutual_auth_wrong_client_pin_fails() {
        // The server pins a client fingerprint the client's leaf does not match.
        let server_id = crate::dtls::cert::Identity::generate("server").unwrap();
        let client_id = crate::dtls::cert::Identity::generate("client").unwrap();
        let server_pin = crate::dtls::cert::fingerprint(server_id.der());
        let (cp, sp) = pipe();

        let server = std::thread::spawn(move || {
            let mut s = Conn::server(
                sp,
                short(Config {
                    require_client_cert: true,
                    peer_cert_fingerprint: Some([0x11; 32]),
                    ..Config::ecdhe_server(server_id)
                }),
            );
            s.handshake().is_err()
        });

        let mut c = Conn::client(
            cp,
            short(Config {
                certificate: Some(Arc::new(client_id)),
                ..Config::ecdhe_client_pinned(server_pin)
            }),
        );
        let client_failed = c.handshake().is_err();
        let server_failed = server.join().expect("server thread");
        assert!(
            client_failed || server_failed,
            "a client-fingerprint mismatch must fail the handshake"
        );
    }

    #[test]
    fn psk_handshake_self_interop() {
        let (cp, sp) = pipe();
        let server = std::thread::spawn(move || {
            let mut s = Conn::server(sp, test_cfg(b"sekret"));
            s.handshake().expect("server handshake");
            // Echo one app-data record.
            let mut buf = vec![0u8; 1500];
            let n = s.read(&mut buf).expect("server read");
            s.write(&buf[..n]).expect("server write");
            s.cipher_suite()
        });

        let mut c = Conn::client(cp, test_cfg(b"sekret"));
        c.handshake().expect("client handshake");
        assert_eq!(c.cipher_suite(), TLS_PSK_WITH_AES_128_GCM_SHA256);
        c.write(b"hello dtls").expect("client write");
        let mut buf = vec![0u8; 1500];
        let n = c.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"hello dtls", "app data did not round-trip");

        let suite = server.join().expect("server thread");
        assert_eq!(suite, TLS_PSK_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn psk_handshake_wrong_key_fails() {
        let (cp, sp) = pipe();
        let server = std::thread::spawn(move || {
            let mut s = Conn::server(sp, test_cfg(b"right"));
            // A mismatched PSK yields a Finished mismatch; the handshake must fail.
            s.handshake().is_err()
        });
        let mut c = Conn::client(cp, test_cfg(b"wrong"));
        let client_failed = c.handshake().is_err();
        let server_failed = server.join().expect("server thread");
        assert!(
            client_failed || server_failed,
            "a key mismatch must fail the handshake"
        );
    }

    /// Runs a full handshake + one app-data echo over the in-memory pipe, asserting
    /// both ends agree on the negotiated suite, and returns it.
    fn run_suite_handshake(client_cfg: Config, server_cfg: Config) -> u16 {
        let (cp, sp) = pipe();
        let server = std::thread::spawn(move || {
            let mut s = Conn::server(sp, short(server_cfg));
            s.handshake().expect("server handshake");
            let mut buf = vec![0u8; 1500];
            let n = s.read(&mut buf).expect("server read");
            s.write(&buf[..n]).expect("server write");
            s.cipher_suite()
        });
        let mut c = Conn::client(cp, short(client_cfg));
        c.handshake().expect("client handshake");
        c.write(b"all-suites app data").expect("client write");
        let mut buf = vec![0u8; 1500];
        let n = c.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"all-suites app data", "app data round-trips");
        let server_suite = server.join().expect("server thread");
        assert_eq!(
            c.cipher_suite(),
            server_suite,
            "both sides agree on the suite"
        );
        c.cipher_suite()
    }

    /// Every TR-06-2 §6.2 mandatory suite (plus PSK) negotiates end to end. Each is
    /// pinned by disabling the stronger same-credential suites, exercising the
    /// table-driven selection, both AES key sizes, both PRF hashes, the ECDSA and RSA
    /// certificate paths, RSA key transport, and the NULL-cipher record layer.
    #[test]
    fn all_mandatory_suites_handshake() {
        use super::super::suites::{
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_NULL_SHA256,
        };

        let ecdsa = Identity::generate("ecdsa-leaf").unwrap();
        let ecdsa_pin = cert::fingerprint(ecdsa.der());
        let rsa = Identity::generate_rsa("rsa-leaf").unwrap();
        let rsa_pin = cert::fingerprint(rsa.der());

        let cert_client = |pin: [u8; 32], disabled: Vec<u16>, allow_null: bool| Config {
            peer_cert_fingerprint: Some(pin),
            disabled_suites: disabled,
            allow_null_cipher: allow_null,
            ..Config::default()
        };
        let cert_server = |id: Identity, disabled: Vec<u16>, allow_null: bool| Config {
            certificate: Some(Arc::new(id)),
            disabled_suites: disabled,
            allow_null_cipher: allow_null,
            ..Config::default()
        };

        // ECDHE_ECDSA: AES-256-GCM-SHA384 (table default) and AES-128-GCM-SHA256.
        assert_eq!(
            run_suite_handshake(
                cert_client(ecdsa_pin, vec![], false),
                cert_server(ecdsa.clone(), vec![], false)
            ),
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
        assert_eq!(
            run_suite_handshake(
                cert_client(ecdsa_pin, vec![], false),
                cert_server(
                    ecdsa.clone(),
                    vec![TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384],
                    false
                )
            ),
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        );

        // ECDHE_RSA: AES-256-GCM-SHA384 and AES-128-GCM-SHA256.
        assert_eq!(
            run_suite_handshake(
                cert_client(rsa_pin, vec![], false),
                cert_server(rsa.clone(), vec![], false)
            ),
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        );
        assert_eq!(
            run_suite_handshake(
                cert_client(rsa_pin, vec![], false),
                cert_server(
                    rsa.clone(),
                    vec![TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384],
                    false
                )
            ),
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );

        // RSA_WITH_NULL_SHA256 (integrity only) — both ends opt into the NULL cipher
        // and the ECDHE_RSA suites are disabled so it is the only RSA option.
        assert_eq!(
            run_suite_handshake(
                cert_client(rsa_pin, vec![], true),
                cert_server(
                    rsa.clone(),
                    vec![
                        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    ],
                    true
                )
            ),
            TLS_RSA_WITH_NULL_SHA256
        );

        // PSK.
        assert_eq!(
            run_suite_handshake(
                Config::psk(b"id".to_vec(), b"key".to_vec()),
                Config::psk(b"id".to_vec(), b"key".to_vec())
            ),
            TLS_PSK_WITH_AES_128_GCM_SHA256
        );
    }

    /// The NULL cipher is OFF by default: a server with an RSA certificate but no
    /// `allow_null_cipher` must NOT fall back to the cleartext suite even when it is
    /// the only suite the client offers — it has no common suite and fails.
    #[test]
    fn null_cipher_refused_without_optin() {
        let rsa = Identity::generate_rsa("rsa-leaf").unwrap();
        let rsa_pin = cert::fingerprint(rsa.der());
        // The client offers ONLY the NULL suite (every other RSA suite disabled).
        let client = Config {
            peer_cert_fingerprint: Some(rsa_pin),
            allow_null_cipher: true,
            disabled_suites: vec![
                super::super::suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                super::super::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            ..Config::default()
        };
        // The server has the RSA cert but did NOT opt into the NULL cipher.
        let server = Config {
            certificate: Some(Arc::new(rsa)),
            allow_null_cipher: false,
            ..Config::default()
        };
        let (cp, sp) = pipe();
        let srv = std::thread::spawn(move || Conn::server(sp, short(server)).handshake().is_err());
        let client_failed = Conn::client(cp, short(client)).handshake().is_err();
        assert!(
            client_failed || srv.join().expect("server thread"),
            "the NULL cipher must not be selectable without the opt-in"
        );
    }

    /// A malicious server (here a man-in-the-middle) that answers with a suite the
    /// client never offered must be rejected, not silently accepted: a PSK client is
    /// forced a ServerHello selecting the cleartext RSA_WITH_NULL_SHA256 it never put
    /// on the wire, and must abort with the downgrade guard rather than run in clear.
    #[test]
    fn client_rejects_unoffered_serverhello_suite() {
        use super::super::suites::TLS_RSA_WITH_NULL_SHA256;
        let (cp, sp) = pipe();
        let server = std::thread::spawn(move || {
            // Fails once the client aborts (its pipe drops) — result ignored.
            let _ = Conn::server(sp, test_cfg(b"sekret")).handshake();
        });
        let transport = ForceSuite {
            inner: cp,
            forced: TLS_RSA_WITH_NULL_SHA256,
            done: false,
        };
        let mut c = Conn::client(transport, test_cfg(b"sekret"));
        let err = c
            .handshake()
            .expect_err("client must reject a suite it did not offer");
        assert!(
            err.to_string().contains("did not offer"),
            "expected the offered-suite downgrade guard, got: {err}"
        );
        drop(c); // close the pipe so the server's handshake errors out promptly
        let _ = server.join();
    }
}
