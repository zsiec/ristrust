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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

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
