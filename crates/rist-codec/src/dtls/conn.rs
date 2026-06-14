//! The DTLS 1.2 connection: the public [`Conn`]/[`Config`]/[`Transport`] API and
//! the client/server handshake state machines (ristgo `conn.go` +
//! `handshake_*.go`).
//!
//! The connection drives a caller-supplied datagram [`Transport`] synchronously:
//! [`Conn::handshake`] runs the full flight exchange (with RFC 6347 §4.2.4
//! retransmission on read timeout), then [`Conn::write`]/[`Conn::read`] carry
//! AES-128-GCM-protected application data. This module wires the PSK suite
//! end-to-end; the ECDHE-ECDSA suite layers its extra flight-4/5 messages on the
//! same machinery.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::cert::{self, Identity};
use super::cipher::{ConnKeys, derive_keys};
use super::handshake::{FragmentHeader, HANDSHAKE_HEADER_LEN, Reassembler, full_message_bytes};
use super::keyexchange::{ecdhe_premaster, generate_ecdhe};
use super::messages::{
    CertificateMsg, ClientHello, HandshakeType, HelloVerifyRequest, ServerHello, ServerKeyExchange,
    client_key_exchange_ecdhe, client_key_exchange_psk, parse_client_key_exchange_ecdhe,
    parse_client_key_exchange_psk,
};
use super::prf::{
    LABEL_CLIENT_FINISHED, LABEL_SERVER_FINISHED, extended_master_secret, finished_verify_data,
    master_secret,
};
use super::record::{ContentType, Record, VERSION_DTLS_1_0, VERSION_DTLS_1_2, split_records};
use super::replay::ReplayWindow;
use super::suites::{
    NAMED_GROUP_SECP256R1, RANDOM_LEN, SIG_SCHEME_ECDSA_P256_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_128_GCM_SHA256,
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

/// DTLS connection configuration. At least one authentication method (a PSK, or —
/// for ECDHE-ECDSA — a certificate) must be set.
#[derive(Debug, Clone)]
pub struct Config {
    /// The pre-shared key enabling `TLS_PSK_WITH_AES_128_GCM_SHA256`.
    pub psk: Option<Vec<u8>>,
    /// The PSK identity (sent by the client, expected by the server).
    pub psk_identity: Vec<u8>,
    /// The local certificate/key for `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`: a
    /// server presents it; a client offers the suite when it can verify the peer
    /// (via `insecure_skip_verify` or `peer_cert_fingerprint`).
    pub certificate: Option<Arc<Identity>>,
    /// Accept any peer certificate (test/insecure). When set, the client offers the
    /// ECDHE suite.
    pub insecure_skip_verify: bool,
    /// Accept only a peer leaf whose SHA-256 fingerprint matches this pin. When set,
    /// the client offers the ECDHE suite.
    pub peer_cert_fingerprint: Option<[u8; 32]>,
    /// Require the peer to confirm `extended_master_secret` (RFC 7627). When
    /// `false` (the default) EMS is offered and used when the peer agrees, but its
    /// omission is tolerated for interop.
    pub require_extended_master_secret: bool,
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
            require_extended_master_secret: false,
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

    /// An ECDHE-ECDSA server config presenting `identity`.
    #[must_use]
    pub fn ecdhe_server(identity: Identity) -> Config {
        Config {
            certificate: Some(Arc::new(identity)),
            ..Config::default()
        }
    }

    /// An ECDHE-ECDSA client config that accepts only a peer leaf matching `pin`
    /// (its SHA-256 fingerprint).
    #[must_use]
    pub fn ecdhe_client_pinned(pin: [u8; 32]) -> Config {
        Config {
            peer_cert_fingerprint: Some(pin),
            ..Config::default()
        }
    }

    /// An ECDHE-ECDSA client config that accepts any peer certificate (insecure;
    /// for tests / fingerprint-out-of-band deployments).
    #[must_use]
    pub fn ecdhe_client_insecure() -> Config {
        Config {
            insecure_skip_verify: true,
            ..Config::default()
        }
    }

    /// Whether this config can verify a peer certificate (and so may offer ECDHE).
    fn can_verify_cert(&self) -> bool {
        self.insecure_skip_verify || self.peer_cert_fingerprint.is_some()
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
        let server_random = sh.random;
        let ems = sh.ext_master_secret;
        if self.cfg.require_extended_master_secret && !ems {
            return Err(proto("server omitted extended_master_secret"));
        }

        // Flight 5: derive the premaster and the ClientKeyExchange body per the
        // selected suite (PSK identity, or verified ECDHE key agreement).
        let (pre_master, cke) = match sh.cipher_suite {
            TLS_PSK_WITH_AES_128_GCM_SHA256 => {
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
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                self.client_ecdhe(&f4, &client_random, &server_random)?
            }
            _ => return Err(proto("server selected an unsupported suite")),
        };
        let cke_spec = self.emit_handshake(HandshakeType::ClientKeyExchange, &cke, 0, true);
        let session_hash = self.transcript_hash();
        let master = derive_master(
            ems,
            &pre_master,
            &session_hash,
            &client_random,
            &server_random,
        );
        self.keys = Some(derive_keys(&master, &client_random, &server_random));
        self.drain_pending()?;

        let client_fin = finished_verify_data(&master, LABEL_CLIENT_FINISHED, &session_hash);
        let ccs = RecordSpec {
            typ: ContentType::ChangeCipherSpec,
            epoch: 0,
            payload: vec![1],
        };
        let fin_spec = self.emit_handshake(HandshakeType::Finished, &client_fin, 1, true);
        let f5 = vec![cke_spec, ccs, fin_spec];
        self.send_flight(&f5)?;

        // Flight 6: ChangeCipherSpec, Finished (server).
        let f6 = self.read_flight(HandshakeType::Finished, &f5)?;
        self.verify_peer_finished(&f6, &master, LABEL_SERVER_FINISHED)?;
        self.handshake_done = true;
        Ok(())
    }

    fn build_client_hello(&self, random: &[u8; RANDOM_LEN], cookie: &[u8]) -> Vec<u8> {
        let ecdhe = self.cfg.can_verify_cert();
        let psk = self.cfg.psk.is_some();
        let mut cipher_suites = Vec::new();
        if ecdhe {
            cipher_suites.push(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256); // preferred
        }
        if psk {
            cipher_suites.push(TLS_PSK_WITH_AES_128_GCM_SHA256);
        }
        ClientHello {
            version: VERSION_DTLS_1_2,
            random: *random,
            session_id: Vec::new(),
            cookie: cookie.to_vec(),
            cipher_suites,
            ext_master_secret: true,
            // Offer the EC parameters only when offering the ECDHE suite.
            supported_groups: if ecdhe {
                vec![NAMED_GROUP_SECP256R1]
            } else {
                Vec::new()
            },
            point_formats: if ecdhe { vec![0] } else { Vec::new() },
            point_formats_offered: ecdhe,
            signature_algorithms: if ecdhe {
                vec![SIG_SCHEME_ECDSA_P256_SHA256]
            } else {
                Vec::new()
            },
            secure_renegotiation: true,
        }
        .marshal_body()
    }

    /// The client's ECDHE-ECDSA key agreement: verify the server's certificate and
    /// ServerKeyExchange signature (from flight 4), generate the client ephemeral,
    /// and return the premaster secret and ClientKeyExchange body.
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
        // The signature covers client_random || server_random || signed ECDHE params.
        let mut signed = Vec::with_capacity(64 + ske.public_key.len());
        signed.extend_from_slice(client_random);
        signed.extend_from_slice(server_random);
        signed.extend_from_slice(&ske.signed_params());
        if !cert::verify(&leaf_key, &signed, &ske.signature) {
            return Err(proto("bad ServerKeyExchange signature"));
        }
        let (client_secret, client_point) = generate_ecdhe();
        let pre_master = ecdhe_premaster(&client_secret, &ske.public_key).map_err(dtls_err)?;
        Ok((pre_master, client_key_exchange_ecdhe(&client_point)))
    }

    /// Selects the server's cipher suite from the client's offer: ECDHE-ECDSA is
    /// preferred when a certificate is configured and offered, else PSK.
    fn select_server_suite(&self, ch: &ClientHello) -> Option<u16> {
        if self.cfg.certificate.is_some()
            && ch
                .cipher_suites
                .contains(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        {
            Some(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        } else if self.cfg.psk.is_some()
            && ch.cipher_suites.contains(&TLS_PSK_WITH_AES_128_GCM_SHA256)
        {
            Some(TLS_PSK_WITH_AES_128_GCM_SHA256)
        } else {
            None
        }
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
        let ecdhe = suite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let client_random = ch3.random;
        let ems = ch3.ext_master_secret;

        // Flight 4: ServerHello [, Certificate, ServerKeyExchange], ServerHelloDone.
        let sh = ServerHello {
            version: VERSION_DTLS_1_2,
            random: server_random,
            session_id: Vec::new(),
            cipher_suite: suite,
            ext_master_secret: ems,
            point_formats: ecdhe && ch3.point_formats_offered,
            secure_renegotiation: ch3.secure_renegotiation,
        }
        .marshal_body();
        let mut f4 = vec![self.emit_handshake(HandshakeType::ServerHello, &sh, 0, true)];
        let mut server_secret = None;
        if ecdhe {
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
            let (secret, point) = generate_ecdhe();
            let mut ske = ServerKeyExchange {
                curve: NAMED_GROUP_SECP256R1,
                public_key: point,
                sig_scheme: SIG_SCHEME_ECDSA_P256_SHA256,
                signature: Vec::new(),
            };
            let mut signed = Vec::with_capacity(64 + ske.public_key.len());
            signed.extend_from_slice(&client_random);
            signed.extend_from_slice(&server_random);
            signed.extend_from_slice(&ske.signed_params());
            ske.signature = cert::sign(identity.signing_key(), &signed);
            f4.push(self.emit_handshake(
                HandshakeType::ServerKeyExchange,
                &ske.marshal_body(),
                0,
                true,
            ));
            server_secret = Some(secret);
        }
        f4.push(self.emit_handshake(HandshakeType::ServerHelloDone, &[], 0, true));
        self.send_flight(&f4)?;

        // Flight 5a: read through ClientKeyExchange. The ChangeCipherSpec and the
        // (encrypted) Finished may share this datagram; the Finished is buffered
        // until the keys derived from this ClientKeyExchange exist.
        let f5 = self.read_flight(HandshakeType::ClientKeyExchange, &f4)?;
        let cke_in = single(&f5, HandshakeType::ClientKeyExchange)?;
        let pre_master = if ecdhe {
            let point = parse_client_key_exchange_ecdhe(&cke_in.body).map_err(dtls_err)?;
            let secret = server_secret.ok_or_else(|| proto("missing ECDHE secret"))?;
            ecdhe_premaster(&secret, &point).map_err(dtls_err)?
        } else {
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
        };
        self.hash_incoming(cke_in);
        let session_hash = self.transcript_hash();
        let master = derive_master(
            ems,
            &pre_master,
            &session_hash,
            &client_random,
            &server_random,
        );
        self.keys = Some(derive_keys(&master, &client_random, &server_random));
        self.drain_pending()?; // decrypt the buffered Finished now that keys exist

        // Flight 5b: the client's Finished (epoch 1).
        let fin_flight = self.read_flight(HandshakeType::Finished, &f4)?;
        self.verify_peer_finished(&fin_flight, &master, LABEL_CLIENT_FINISHED)?;

        // Flight 6: ChangeCipherSpec, Finished (server).
        let server_fin =
            finished_verify_data(&master, LABEL_SERVER_FINISHED, &self.transcript_hash());
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
        let expect = finished_verify_data(master, label, &self.transcript_hash());
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

    fn transcript_hash(&self) -> [u8; 32] {
        let digest = Sha256::digest(&self.transcript);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

/// Derives the master secret, using the extended scheme (RFC 7627) when both peers
/// agreed, else the classic randoms-based scheme (RFC 5246).
fn derive_master(
    ems: bool,
    pre_master: &[u8],
    session_hash: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    if ems {
        extended_master_secret(pre_master, session_hash)
    } else {
        master_secret(pre_master, client_random, server_random)
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
        assert_eq!(c.cipher_suite(), TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        c.write(b"ecdhe app data").expect("client write");
        let mut buf = vec![0u8; 1500];
        let n = c.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], b"ecdhe app data");
        assert_eq!(
            server.join().expect("server thread"),
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
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
}
