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

/// Generates a self-signed ECDSA P-256 cert + key with `openssl`, returning their
/// paths (kept alive by the guard), or `None` on failure.
fn gen_ecdsa_cert(openssl: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, TempFiles)> {
    let dir = std::env::temp_dir();
    let cert = dir.join(format!("ristrust-dtls-{}-cert.pem", std::process::id()));
    let key = dir.join(format!("ristrust-dtls-{}-key.pem", std::process::id()));
    let ok = Command::new(openssl)
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
            key.to_str()?,
            "-out",
            cert.to_str()?,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=ristrust-interop",
        ])
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
