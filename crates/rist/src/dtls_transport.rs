//! DTLS 1.2 record-layer transport for the Main profile (feature `dtls`).
//!
//! The DTLS codec ([`rist_codec::dtls::Conn`]) is a **synchronous, blocking** state
//! machine: it owns its [`Transport`](rist_codec::dtls::Transport), runs a multi-flight
//! handshake with its own retransmission timers, and then encrypts/decrypts each
//! datagram through blocking `write`/`read`. The host, by contrast, is async. This
//! module bridges the two: a dedicated OS worker thread owns the `Conn` over a real
//! blocking UDP socket, and a [`DtlsAsyncSocket`] (an [`AsyncUdpSocket`]) shuttles
//! **plaintext** GRE datagrams to and from that worker over channels. Wrapped in a
//! [`MainSocket`](crate::socket::MainSocket), it is indistinguishable from a plain UDP
//! transport to the rest of the host — the [`MainDriver`](crate::driver_main) needs no
//! DTLS awareness.
//!
//! The RIST sender is the DTLS client (it dials a known remote); the RIST receiver is
//! the DTLS server (it learns its peer from the first datagram, as ristgo does). The
//! handshake runs on the worker before any media flows: outbound GRE frames queue in
//! the channel and are flushed once the tunnel is up; a handshake failure closes the
//! channels, which ends the session.
//!
//! The single worker interleaves reads and writes by capping the post-handshake recv
//! timeout: [`Conn::read`](rist_codec::dtls::Conn::read) blocks indefinitely by
//! design, so [`BridgeTransport`] caps its blocking recv to [`POLL_INTERVAL`] once the
//! handshake completes, making `read` return promptly so the worker can service queued
//! writes between reads. DTLS is Main-profile unicast only — not bonded, not
//! reversed-role — so one peer and one socket suffice.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use rist_codec::dtls::{self, Conn, Transport};

use crate::runtime::AsyncUdpSocket;
use crate::socket::MainSocket;

/// The post-handshake blocking-recv cap. [`Conn::read`] forces an infinite read
/// timeout each call; capping the underlying socket recv to this makes `read` return
/// [`io::ErrorKind::WouldBlock`] promptly (preserving its decrypt buffers), so the
/// worker can flush queued outbound writes between reads. It bounds the added latency
/// on the send path (a record decrypts and is delivered the instant it arrives, so the
/// receive path is unaffected).
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The server's pre-handshake accept poll: the worker waits this long for the first
/// client datagram per iteration, then re-checks the shutdown flag, so a receiver that
/// is closed before any client connects tears its worker down promptly.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// The depth of each plaintext bridge channel (outbound and inbound). A full queue
/// drops the datagram (as a UDP socket buffer overflow would); ARQ recovers media and
/// control traffic repeats.
const BRIDGE_CAPACITY: usize = 1024;

/// The largest datagram the worker will receive.
const RECV_BUF: usize = 65_536;

/// Builds a DTLS **client** transport: binds an ephemeral UDP socket, connects it to
/// `remote`, and spawns the worker that runs the DTLS handshake and record relay. The
/// returned [`MainSocket`] carries plaintext GRE to/from the worker.
///
/// # Errors
/// Returns an I/O error if the socket cannot be bound or connected.
pub(crate) fn dtls_client(remote: SocketAddr, cfg: dtls::Config) -> io::Result<MainSocket> {
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(remote)?;
    let local = sock.local_addr()?;
    let bridge = DtlsAsyncSocket::new(local);
    bridge.peer.set(remote).ok();
    spawn_worker(bridge.shared(), sock, cfg, true, remote);
    Ok(MainSocket::from_async(Arc::new(bridge)))
}

/// Builds a DTLS **server** transport: binds a UDP socket to `local` and spawns the
/// worker that learns its peer from the first inbound datagram, runs the DTLS
/// handshake as the server, and relays records. The returned [`MainSocket`] carries
/// plaintext GRE to/from the worker.
///
/// # Errors
/// Returns an I/O error if the socket cannot be bound.
pub(crate) fn dtls_server(local: SocketAddr, cfg: dtls::Config) -> io::Result<MainSocket> {
    let sock = UdpSocket::bind(local)?;
    let bound = sock.local_addr()?;
    let bridge = DtlsAsyncSocket::new(bound);
    spawn_worker(bridge.shared(), sock, cfg, false, bound);
    Ok(MainSocket::from_async(Arc::new(bridge)))
}

/// The half of the bridge state shared with the worker thread: the plaintext queues,
/// the learned peer, and the shutdown flag.
struct Shared {
    /// Plaintext GRE the host wants sent; the worker encrypts and transmits each.
    outbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    /// Plaintext GRE the worker decrypted; the host's reader drains it.
    inbound_tx: mpsc::Sender<Bytes>,
    /// The DTLS peer address, set by the worker once known (immediately for a client,
    /// after the first datagram for a server). Read back as the `recv` source.
    peer: Arc<OnceLock<SocketAddr>>,
    /// Set when the host side is dropped, so the worker's poll loops exit.
    shutdown: Arc<AtomicBool>,
}

/// An [`AsyncUdpSocket`] backed by a DTLS worker thread: `poll_send` queues a plaintext
/// GRE datagram for the worker to encrypt and transmit; `poll_recv` yields a datagram
/// the worker decrypted. The destination address is ignored (the worker's socket is
/// connected to the one DTLS peer), and the source returned is that peer.
#[derive(Debug)]
struct DtlsAsyncSocket {
    local: SocketAddr,
    /// Queues plaintext for the worker. Behind an `Arc` so clones share the one queue.
    outbound_tx: mpsc::Sender<Bytes>,
    /// The worker's decrypted output, polled by the host's reader.
    inbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    /// The learned DTLS peer (the `recv` source), shared with the worker.
    peer: Arc<OnceLock<SocketAddr>>,
    /// Signals the worker to stop (set on drop).
    shutdown: Arc<AtomicBool>,
    /// The worker's intake, handed off once via [`DtlsAsyncSocket::shared`].
    worker_intake: Mutex<Option<WorkerIntake>>,
}

/// The channel ends the worker takes ownership of (the inverse of the host's ends).
#[derive(Debug)]
struct WorkerIntake {
    outbound_rx: mpsc::Receiver<Bytes>,
    inbound_tx: mpsc::Sender<Bytes>,
}

impl DtlsAsyncSocket {
    fn new(local: SocketAddr) -> DtlsAsyncSocket {
        let (outbound_tx, outbound_rx) = mpsc::channel(BRIDGE_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(BRIDGE_CAPACITY);
        DtlsAsyncSocket {
            local,
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            peer: Arc::new(OnceLock::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            worker_intake: Mutex::new(Some(WorkerIntake {
                outbound_rx,
                inbound_tx,
            })),
        }
    }

    /// Takes the worker's [`Shared`] state, consuming the one-shot worker intake.
    fn shared(&self) -> Shared {
        let intake = self
            .worker_intake
            .lock()
            .expect("worker intake")
            .take()
            .expect("shared() called once");
        Shared {
            outbound_rx: Mutex::new(intake.outbound_rx),
            inbound_tx: intake.inbound_tx,
            peer: Arc::clone(&self.peer),
            shutdown: Arc::clone(&self.shutdown),
        }
    }

    /// The DTLS peer to report as the `recv` source (falls back to the local address
    /// until the server has learned its peer — harmless, as no inbound flows first).
    fn peer_addr(&self) -> SocketAddr {
        self.peer.get().copied().unwrap_or(self.local)
    }
}

impl Drop for DtlsAsyncSocket {
    fn drop(&mut self) {
        // Signal the worker to exit; its poll loops re-check this within one interval.
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl AsyncUdpSocket for DtlsAsyncSocket {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        _dest: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        // Queue the plaintext GRE frame for the worker. A full queue drops it (like a
        // UDP send-buffer overflow); a closed queue means the worker has ended.
        match self.outbound_tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "rist: dtls worker ended",
            ))),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut rx = self.inbound_rx.lock().expect("inbound rx");
        match rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Poll::Ready(Ok((n, self.peer_addr())))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "rist: dtls worker ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// Spawns the DTLS worker thread for one connection. The worker (for a server) learns
/// its peer, runs the handshake, then relays records until a channel closes or the
/// shutdown flag is set.
fn spawn_worker(
    shared: Shared,
    sock: UdpSocket,
    cfg: dtls::Config,
    is_client: bool,
    remote: SocketAddr,
) {
    std::thread::Builder::new()
        .name("rist-dtls".into())
        .spawn(move || worker(shared, sock, cfg, is_client, remote))
        .expect("spawn dtls worker thread");
}

/// The DTLS worker body: connect/accept, handshake, then relay loop. Takes `shared`
/// by value on purpose — when the worker returns (handshake failure, transport error,
/// or shutdown), dropping it closes the bridge channels, which ends the host session.
#[allow(clippy::needless_pass_by_value)]
fn worker(shared: Shared, sock: UdpSocket, cfg: dtls::Config, is_client: bool, remote: SocketAddr) {
    let done = Arc::new(AtomicBool::new(false));
    let Some(transport) = setup(&shared, sock, is_client, remote, Arc::clone(&done)) else {
        return; // shut down (or accept failed) before a peer appeared
    };
    let mut conn = if is_client {
        Conn::client(transport, cfg)
    } else {
        Conn::server(transport, cfg)
    };
    if let Err(e) = conn.handshake() {
        tracing::warn!(target: "rist::crypto", "rist: dtls handshake failed: {e}");
        return; // dropping `conn` closes the bridge channels → the session ends
    }
    // Past the handshake: cap the blocking recv so `read` returns between writes.
    done.store(true, Ordering::Relaxed);
    tracing::debug!(target: "rist::crypto", suite = conn.cipher_suite(), client = is_client, "rist: dtls handshake complete");
    relay(&mut conn, &shared);
}

/// Prepares the worker's [`BridgeTransport`]: a client connects to `remote`; a server
/// waits (polling the shutdown flag) for the first datagram, learns and connects to
/// that peer, and primes the transport with that datagram (the ClientHello). Returns
/// `None` if shutdown is requested before a peer appears.
fn setup(
    shared: &Shared,
    sock: UdpSocket,
    is_client: bool,
    remote: SocketAddr,
    done: Arc<AtomicBool>,
) -> Option<BridgeTransport> {
    if is_client {
        shared.peer.set(remote).ok();
        return Some(BridgeTransport::new(sock, None, done));
    }
    // Server: learn the peer from the first datagram, then connect to filter on it.
    sock.set_read_timeout(Some(ACCEPT_POLL)).ok();
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        if shared.shutdown.load(Ordering::Relaxed) {
            return None;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                sock.connect(peer).ok();
                shared.peer.set(peer).ok();
                return Some(BridgeTransport::new(sock, Some(buf[..n].to_vec()), done));
            }
            Err(e) if is_timeout(&e) => {}
            Err(_) => return None,
        }
    }
}

/// The post-handshake record relay: drain queued plaintext (encrypt + send), then read
/// one record (decrypt) and deliver it, looping until a channel closes or shutdown.
fn relay<T: Transport>(conn: &mut Conn<T>, shared: &Shared) {
    let mut buf = vec![0u8; RECV_BUF];
    let mut rx = shared.outbound_rx.lock().expect("outbound rx");
    loop {
        if shared.shutdown.load(Ordering::Relaxed) {
            return;
        }
        // Flush every queued outbound frame as a DTLS application record.
        loop {
            match rx.try_recv() {
                Ok(data) => {
                    if conn.write(&data).is_err() {
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return, // host dropped
            }
        }
        // Read one record (capped by POLL_INTERVAL); deliver application data.
        match conn.read(&mut buf) {
            Ok(n) => {
                if shared
                    .inbound_tx
                    .try_send(Bytes::copy_from_slice(&buf[..n]))
                    .is_err()
                    && shared.inbound_tx.is_closed()
                {
                    return; // host dropped (a Full error just drops the datagram)
                }
            }
            Err(e) if is_timeout(&e) => {}
            Err(_) => return, // transport or protocol error: tear the tunnel down
        }
    }
}

/// A [`Transport`] over a connected blocking UDP socket. Honours the DTLS codec's read
/// timeouts during the handshake; once `done` is set, it caps every blocking recv to
/// [`POLL_INTERVAL`] so the worker's relay loop stays responsive to queued writes. A
/// server's first inbound datagram (the ClientHello) is `primed` and returned first.
#[derive(Debug)]
struct BridgeTransport {
    sock: UdpSocket,
    primed: Option<Vec<u8>>,
    done: Arc<AtomicBool>,
}

impl BridgeTransport {
    fn new(sock: UdpSocket, primed: Option<Vec<u8>>, done: Arc<AtomicBool>) -> BridgeTransport {
        BridgeTransport { sock, primed, done }
    }
}

impl Transport for BridgeTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<usize> {
        self.sock.send(datagram)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(p) = self.primed.take() {
            let n = p.len().min(buf.len());
            buf[..n].copy_from_slice(&p[..n]);
            return Ok(n);
        }
        self.sock.recv(buf)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        // Post-handshake, `Conn::read` always requests an infinite timeout; cap it so
        // the relay loop can flush writes. Pre-handshake, honour the codec's request.
        let effective = if self.done.load(Ordering::Relaxed) {
            Some(POLL_INTERVAL)
        } else {
            timeout
        };
        self.sock.set_read_timeout(effective)
    }
}

/// Whether `e` is a blocking-socket read timeout (`WouldBlock` on Unix, `TimedOut` on
/// Windows), the signal the relay/accept loops poll on.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
