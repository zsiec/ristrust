//! The async-runtime abstraction.
//!
//! The host never names tokio directly outside this module: it talks to the
//! [`Runtime`] trait (clock, task spawning, timers, UDP sockets) and the
//! [`AsyncUdpSocket`] trait. The default implementation is [`TokioRuntime`];
//! keeping the boundary explicit means an alternative runtime can be swapped in
//! (and proven with a second-runtime test, as the SRT sibling does). Ported from
//! srtrust's `runtime.rs`, simplified — GSO/GRO batching (quinn-udp) is a WP2+
//! optimization layered behind the same trait.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

pub use crate::multicast::{Egress, Membership, ResolvedIface};

/// A pollable, runtime-agnostic UDP socket. `Debug` so host types holding one can
/// derive `Debug`.
pub trait AsyncUdpSocket: Send + Sync + std::fmt::Debug {
    /// Attempts to send `buf` to `dest`, returning the number of bytes sent.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// Attempts to receive a datagram into `buf`, returning its length and source.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// The socket's bound local address.
    ///
    /// # Errors
    /// Returns an I/O error if the local address cannot be determined.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Joins the multicast group described by `m` (a receiver operation). The
    /// default is a no-op, so non-OS runtimes used in tests need not implement it;
    /// the real [`TokioRuntime`] socket performs the group join.
    ///
    /// # Errors
    /// Returns an I/O error if the membership cannot be established.
    fn join_multicast(&self, m: &Membership) -> io::Result<()> {
        let _ = m;
        Ok(())
    }

    /// Applies multicast egress options — interface, hop limit, loopback — for a
    /// sender transmitting to a group. The default is a no-op (see
    /// [`join_multicast`](AsyncUdpSocket::join_multicast)).
    ///
    /// # Errors
    /// Returns an I/O error if an option cannot be set.
    fn set_multicast_egress(&self, e: &Egress) -> io::Result<()> {
        let _ = e;
        Ok(())
    }
}

/// The async services the host needs: a clock, task spawning, timers, and UDP
/// socket binding.
pub trait Runtime: Send + Sync + 'static {
    /// The current monotonic instant.
    fn now(&self) -> Instant;
    /// Spawns a detached task.
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
    /// A future that resolves at `deadline`.
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>>;
    /// Binds a UDP socket to `addr`.
    ///
    /// # Errors
    /// Returns an I/O error if the socket cannot be bound.
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>>;
}

/// The UDP send and receive buffer size [`TokioRuntime`] requests on every bound
/// socket (2 MiB), best-effort. Linux's small default UDP receive buffer (~208 KB)
/// drops a sender's opening burst before the driver drains it, forcing
/// retransmission and stalling startup; requesting the same 2 MiB as libRIST/ristgo
/// avoids it. The OS may clamp to its `rmem_max`/`wmem_max`, so failures are ignored.
const UDP_SOCKET_BUFFER_BYTES: usize = 1 << 21;

/// The default [`Runtime`], backed by tokio.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        let inner = tokio::net::UdpSocket::from_std(std_sock)?;
        // Enlarge the UDP buffers (best-effort) so a startup burst is not dropped
        // before the driver drains it — see UDP_SOCKET_BUFFER_BYTES.
        let sock = socket2::SockRef::from(&inner);
        let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES);
        let _ = sock.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES);
        Ok(Arc::new(TokioUdpSocket { inner }))
    }
}

#[derive(Debug)]
struct TokioUdpSocket {
    inner: tokio::net::UdpSocket,
}

impl AsyncUdpSocket for TokioUdpSocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_send_to(cx, buf, dest)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(addr)) => Poll::Ready(Ok((read_buf.filled().len(), addr))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn join_multicast(&self, m: &Membership) -> io::Result<()> {
        let sock = socket2::SockRef::from(&self.inner);
        let iface_v4 = m.iface.v4.unwrap_or(Ipv4Addr::UNSPECIFIED);
        match (m.group, m.source) {
            (IpAddr::V4(group), None) => sock.join_multicast_v4(&group, &iface_v4),
            (IpAddr::V4(group), Some(IpAddr::V4(source))) => {
                sock.join_ssm_v4(&source, &group, &iface_v4)
            }
            (IpAddr::V6(group), None) => sock.join_multicast_v6(&group, m.iface.index),
            (IpAddr::V6(_), Some(_)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 source-specific multicast is not supported",
            )),
            (IpAddr::V4(_), Some(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multicast group and source IP families differ",
            )),
        }
    }

    fn set_multicast_egress(&self, e: &Egress) -> io::Result<()> {
        let sock = socket2::SockRef::from(&self.inner);
        match e.group {
            IpAddr::V4(_) => {
                if let Some(iface) = e.iface.v4 {
                    sock.set_multicast_if_v4(&iface)?;
                }
                if e.ttl > 0 {
                    sock.set_multicast_ttl_v4(u32::from(e.ttl))?;
                }
                sock.set_multicast_loop_v4(e.loopback)?;
            }
            IpAddr::V6(_) => {
                if e.iface.index != 0 {
                    sock.set_multicast_if_v6(e.iface.index)?;
                }
                if e.ttl > 0 {
                    sock.set_multicast_hops_v6(u32::from(e.ttl))?;
                }
                sock.set_multicast_loop_v6(e.loopback)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tokio_runtime_binds_a_udp_socket() {
        let rt = TokioRuntime;
        let socket = rt
            .bind("127.0.0.1:0".parse().expect("valid addr"))
            .expect("bind loopback");
        let addr = socket.local_addr().expect("local_addr");
        assert_ne!(addr.port(), 0, "an ephemeral port should be assigned");
    }
}
