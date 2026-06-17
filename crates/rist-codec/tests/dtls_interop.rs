//! DTLS 1.2 interop against the OpenSSL reference (`s_server -dtls1_2`). libRIST
//! has no DTLS, so OpenSSL is the interop bar. Behind `--features dtls`; each test
//! gracefully skips (prints a notice and returns) when `openssl` is absent or lacks
//! DTLS, so the suite is safe to run anywhere:
//!
//! ```text
//! cargo test -p rist-codec --features dtls --test dtls_interop -- --nocapture
//! ```
#![cfg(feature = "dtls")]

use std::io;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rist_codec::dtls::conn::Conn;
use rist_codec::dtls::{Config, Transport};

/// A blocking UDP transport for the DTLS connection, connected to one peer.
struct UdpTransport {
    sock: UdpSocket,
}

impl Transport for UdpTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
        self.sock.send(datagram)
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.recv(buf)
    }
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

/// Locates the `openssl` binary, or returns `None` (the caller skips).
fn openssl() -> Option<String> {
    if let Ok(path) = std::env::var("OPENSSL") {
        return Some(path);
    }
    for cand in [
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
    ] {
        if std::path::Path::new(cand).is_file() {
            return Some(cand.to_string());
        }
    }
    // Fall back to PATH.
    if Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        return Some("openssl".to_string());
    }
    None
}

/// A process-unique token, so parallel tests that generate certificates do not
/// share (and race to delete) the same temp-file paths.
fn unique_token() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    (u64::from(std::process::id()) << 20) | N.fetch_add(1, Ordering::Relaxed)
}

/// A free loopback UDP port.
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Kills the child on drop.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawns a tool, mirroring its stderr to a file when `RIST_TOOL_LOG` is set.
fn spawn(cmd: &mut Command) -> ChildGuard {
    cmd.stdin(Stdio::piped()).stdout(Stdio::null());
    if let Ok(path) = std::env::var("RIST_TOOL_LOG") {
        let f = std::fs::File::create(path).expect("tool log");
        cmd.stderr(Stdio::from(f));
    } else {
        cmd.stderr(Stdio::null());
    }
    ChildGuard(cmd.spawn().expect("spawn openssl"))
}

/// A short-timeout overlay on `base` so a stuck handshake fails fast.
fn short(base: Config) -> Config {
    Config {
        handshake_timeout: Duration::from_secs(8),
        retransmit_timeout: Duration::from_millis(400),
        ..base
    }
}

/// Connects a ristrust DTLS client by UDP to `port`.
fn client(port: u16, cfg: Config) -> Conn<UdpTransport> {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    sock.connect(("127.0.0.1", port)).expect("connect");
    Conn::client(UdpTransport { sock }, short(cfg))
}

const PSK_HEX: &str = "0123456789abcdef0123456789abcdef";
const PSK_IDENTITY: &str = "Client_identity";

fn psk_bytes() -> Vec<u8> {
    (0..PSK_HEX.len() / 2)
        .map(|i| u8::from_str_radix(&PSK_HEX[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// ristrust DTLS client → OpenSSL `s_server -dtls1_2` (PSK). A completed handshake
/// proves the full PSK wire exchange — ClientHello/cookie/ServerHello/key
/// exchange/Finished — interoperates.
#[test]
fn interop_psk_client_to_openssl_server() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    let port = free_udp_port();
    let _server = spawn(Command::new(&openssl).args([
        "s_server",
        "-dtls1_2",
        "-listen",
        "-psk",
        PSK_HEX,
        "-psk_identity",
        PSK_IDENTITY,
        "-nocert",
        "-cipher",
        "PSK-AES128-GCM-SHA256",
        "-accept",
        &format!("127.0.0.1:{port}"),
        "-quiet",
    ]));
    std::thread::sleep(Duration::from_millis(600));

    let mut conn = client(
        port,
        Config::psk(PSK_IDENTITY.as_bytes().to_vec(), psk_bytes()),
    );
    conn.handshake()
        .expect("PSK handshake with openssl s_server");
    assert_eq!(
        conn.cipher_suite(),
        rist_codec::dtls::suites::TLS_PSK_WITH_AES_128_GCM_SHA256
    );
}

/// Deletes its paths on drop.
struct TempFiles(Vec<std::path::PathBuf>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Generates a self-signed cert + key with `openssl req -x509`, returning their
/// paths (kept alive by the guard), or `None` on failure. `key_args` selects the key
/// type; `tag` keeps the temp-file paths distinct.
fn gen_cert(
    openssl: &str,
    tag: &str,
    key_args: &[&str],
    subject: &str,
) -> Option<(std::path::PathBuf, std::path::PathBuf, TempFiles)> {
    let dir = std::env::temp_dir();
    let cert = dir.join(format!("ristrust-dtls-{tag}-{}-cert.pem", unique_token()));
    let key = dir.join(format!("ristrust-dtls-{tag}-{}-key.pem", unique_token()));
    let mut args = vec!["req", "-x509"];
    args.extend_from_slice(key_args);
    args.extend_from_slice(&[
        "-keyout",
        key.to_str()?,
        "-out",
        cert.to_str()?,
        "-days",
        "1",
        "-nodes",
        "-subj",
        subject,
    ]);
    let ok = Command::new(openssl)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        return None;
    }
    let guard = TempFiles(vec![cert.clone(), key.clone()]);
    Some((cert, key, guard))
}

/// A self-signed ECDSA P-256 cert + key.
fn gen_ecdsa_cert(openssl: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, TempFiles)> {
    gen_cert(
        openssl,
        "ec",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
        "/CN=ristrust-interop",
    )
}

/// ristrust DTLS client → OpenSSL `s_server -dtls1_2` (ECDHE-ECDSA). OpenSSL
/// presents a self-signed ECDSA P-256 certificate; ristrust verifies its
/// ServerKeyExchange signature and completes the ephemeral ECDH handshake.
#[test]
fn interop_ecdhe_client_to_openssl_server() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    let Some((cert, key, _files)) = gen_ecdsa_cert(&openssl) else {
        eprintln!("dtls interop: could not generate an ECDSA cert; skipping");
        return;
    };
    let port = free_udp_port();
    let _server = spawn(Command::new(&openssl).args([
        "s_server",
        "-dtls1_2",
        "-listen",
        "-cert",
        cert.to_str().unwrap(),
        "-key",
        key.to_str().unwrap(),
        "-cipher",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "-accept",
        &format!("127.0.0.1:{port}"),
        "-quiet",
    ]));
    std::thread::sleep(Duration::from_millis(600));

    // Accept any cert (the SKE signature is still verified against it).
    let mut conn = client(port, Config::ecdhe_client_insecure());
    conn.handshake()
        .expect("ECDHE handshake with openssl s_server");
    assert_eq!(
        conn.cipher_suite(),
        rist_codec::dtls::suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    );
}

/// A self-signed RSA-2048 cert + key.
fn gen_rsa_cert(openssl: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, TempFiles)> {
    gen_cert(
        openssl,
        "rsa",
        &["-newkey", "rsa:2048"],
        "/CN=ristrust-interop-rsa",
    )
}

/// Spawns `openssl s_server -dtls1_2` constrained to one `cipher`, presenting
/// `cert`/`key`, listening on `port`.
fn openssl_cert_server(
    openssl: &str,
    port: u16,
    cipher: &str,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> ChildGuard {
    let accept = format!("127.0.0.1:{port}");
    let mut cmd = Command::new(openssl);
    cmd.args([
        "s_server",
        "-dtls1_2",
        "-listen",
        "-cert",
        cert.to_str().unwrap(),
        "-key",
        key.to_str().unwrap(),
        "-cipher",
        cipher,
        "-accept",
        &accept,
        "-quiet",
    ]);
    spawn(&mut cmd)
}

/// Runs a ristrust DTLS client against an OpenSSL `s_server` pinned to one `cipher`
/// with the given `cert`/`key`, asserting the negotiated suite. Mirrors the existing
/// ECDHE-ECDSA-128 interop for the remaining TR-06-2 §6.2 suites.
fn run_client_interop(
    openssl: &str,
    cipher: &str,
    cert: &std::path::Path,
    key: &std::path::Path,
    cfg: Config,
    expect_suite: u16,
) {
    let port = free_udp_port();
    let _server = openssl_cert_server(openssl, port, cipher, cert, key);
    std::thread::sleep(Duration::from_millis(600));
    let mut conn = client(port, cfg);
    conn.handshake()
        .unwrap_or_else(|e| panic!("handshake with openssl ({cipher}): {e}"));
    assert_eq!(conn.cipher_suite(), expect_suite, "negotiated {cipher}");
}

/// ristrust client → OpenSSL server, ECDHE-ECDSA-AES256-GCM-SHA384 (AES-256 +
/// SHA-384 PRF over the ECDSA path).
#[test]
fn interop_ecdhe_ecdsa_aes256_client_to_openssl() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    let Some((cert, key, _files)) = gen_ecdsa_cert(&openssl) else {
        eprintln!("dtls interop: could not generate an ECDSA cert; skipping");
        return;
    };
    run_client_interop(
        &openssl,
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        &cert,
        &key,
        Config::ecdhe_client_insecure(),
        rist_codec::dtls::suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    );
}

/// ristrust client → OpenSSL server, ECDHE-RSA-AES128-GCM-SHA256 (the RSA
/// certificate / RSA-signed ServerKeyExchange path).
#[test]
fn interop_ecdhe_rsa_aes128_client_to_openssl() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    let Some((cert, key, _files)) = gen_rsa_cert(&openssl) else {
        eprintln!("dtls interop: could not generate an RSA cert; skipping");
        return;
    };
    run_client_interop(
        &openssl,
        "ECDHE-RSA-AES128-GCM-SHA256",
        &cert,
        &key,
        Config::ecdhe_client_insecure(),
        rist_codec::dtls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    );
}

/// ristrust client → OpenSSL server, ECDHE-RSA-AES256-GCM-SHA384 (RSA auth +
/// AES-256 + SHA-384 PRF together).
#[test]
fn interop_ecdhe_rsa_aes256_client_to_openssl() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    let Some((cert, key, _files)) = gen_rsa_cert(&openssl) else {
        eprintln!("dtls interop: could not generate an RSA cert; skipping");
        return;
    };
    run_client_interop(
        &openssl,
        "ECDHE-RSA-AES256-GCM-SHA384",
        &cert,
        &key,
        Config::ecdhe_client_insecure(),
        rist_codec::dtls::suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    );
}

/// ristrust client → OpenSSL server, RSA_WITH_NULL_SHA256 (RSA key transport + the
/// NULL-cipher-with-HMAC record layer). The client encrypts the pre-master to
/// OpenSSL's RSA key; integrity-only records carry the Finished. OpenSSL needs
/// `@SECLEVEL=0` to enable the NULL cipher at all.
#[test]
fn interop_rsa_null_client_to_openssl() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    let Some((cert, key, _files)) = gen_rsa_cert(&openssl) else {
        eprintln!("dtls interop: could not generate an RSA cert; skipping");
        return;
    };
    let cfg = Config {
        insecure_skip_verify: true,
        allow_null_cipher: true,
        ..Config::default()
    };
    run_client_interop(
        &openssl,
        "NULL-SHA256:@SECLEVEL=0",
        &cert,
        &key,
        cfg,
        rist_codec::dtls::suites::TLS_RSA_WITH_NULL_SHA256,
    );
}

/// A blocking UDP transport for a DTLS *server*: it learns the single client's
/// address from the first datagram and sends back to it.
struct UdpServerTransport {
    sock: UdpSocket,
    peer: Option<std::net::SocketAddr>,
}

impl Transport for UdpServerTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
        match self.peer {
            Some(p) => self.sock.send_to(datagram, p),
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "no peer yet")),
        }
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (n, addr) = self.sock.recv_from(buf)?;
        self.peer.get_or_insert(addr);
        Ok(n)
    }
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

/// OpenSSL `s_client -dtls1_2` → ristrust DTLS *server* (RSA_WITH_NULL_SHA256). This
/// is the server-role interop that validates the RSA key-transport DECRYPT path (the
/// Bleichenbacher countermeasure) against a real OpenSSL client — the one suite path
/// reachable only on the server side.
#[test]
fn interop_rsa_null_openssl_client_to_server() {
    let Some(openssl) = openssl() else {
        eprintln!("dtls interop: openssl not found; skipping");
        return;
    };
    // ristrust presents an RSA identity and opts into the NULL cipher.
    let Ok(identity) = rist_codec::dtls::cert::Identity::generate_rsa("ristrust-rsa-server") else {
        eprintln!("dtls interop: could not generate an RSA identity; skipping");
        return;
    };
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    let port = sock.local_addr().expect("addr").port();
    let cfg = short(Config {
        certificate: Some(std::sync::Arc::new(identity)),
        allow_null_cipher: true,
        // Force the NULL suite: disable the ECDHE_RSA suites this RSA cert could serve.
        disabled_suites: vec![
            rist_codec::dtls::suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rist_codec::dtls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        ..Config::default()
    });

    let server = std::thread::spawn(move || {
        let mut conn = Conn::server(UdpServerTransport { sock, peer: None }, cfg);
        conn.handshake().map(|()| conn.cipher_suite())
    });

    // Give the server a moment to start listening, then connect OpenSSL.
    std::thread::sleep(Duration::from_millis(200));
    let connect = format!("127.0.0.1:{port}");
    let mut client = spawn(Command::new(&openssl).args([
        "s_client",
        "-dtls1_2",
        "-connect",
        &connect,
        "-cipher",
        "NULL-SHA256:@SECLEVEL=0",
        "-quiet",
    ]));
    // The handshake completes on connect; feed a newline so s_client does not block
    // on stdin and the guard can reap it.
    if let Some(stdin) = client.0.stdin.take() {
        drop(stdin);
    }

    match server.join().expect("server thread") {
        Ok(suite) => assert_eq!(suite, rist_codec::dtls::suites::TLS_RSA_WITH_NULL_SHA256),
        Err(e) => panic!("ristrust server handshake with openssl s_client: {e}"),
    }
}
