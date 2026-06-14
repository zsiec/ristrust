//! The Simple-profile (VSF TR-06-1) UDP transport: a pair of unconnected UDP
//! sockets on adjacent even/odd ports — RTP media on the even port `P`, compound
//! RTCP on the odd port `P+1`.
//!
//! The sockets are deliberately *unconnected* and every send takes an explicit
//! destination, so one transport serves both roles: a receiver binds the
//! well-known port pair and learns the sender's source addresses from inbound
//! datagrams, while a sender binds an ephemeral pair and addresses the receiver's
//! well-known ports. The even/odd split and address learning mirror libRIST.
//!
//! This module only moves bytes; it never parses RTP/RTCP or touches the flow
//! core. It is built on the runtime-agnostic [`AsyncUdpSocket`] abstraction.

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::runtime::{AsyncUdpSocket, Runtime};

/// A RIST Simple-profile UDP transport: a media socket (even port) and an RTCP
/// socket (odd port). Clones share the underlying sockets (`Arc`), so the driver
/// can hold one handle for sends while awaiting receives on the same sockets.
#[derive(Debug, Clone)]
pub(crate) struct SimpleSocket {
    media: Arc<dyn AsyncUdpSocket>,
    rtcp: Arc<dyn AsyncUdpSocket>,
}

impl SimpleSocket {
    /// Binds the media socket to `addr` and the RTCP socket to the adjacent odd
    /// port (`addr.port() + 1`). The port must be a positive even number
    /// (TR-06-1 §4: the media port is even, RTCP is the next port). This is the
    /// receiver-side constructor.
    ///
    /// # Errors
    /// Returns an I/O error if the port is not a positive even number, or if
    /// either socket cannot be bound.
    pub(crate) fn listen(rt: &dyn Runtime, addr: SocketAddr) -> io::Result<SimpleSocket> {
        let port = addr.port();
        if port == 0 || !port.is_multiple_of(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("rist: socket: media port {port} must be a positive even number"),
            ));
        }
        let media = rt.bind(addr)?;
        let mut rtcp_addr = addr;
        rtcp_addr.set_port(port + 1);
        let rtcp = rt.bind(rtcp_addr)?;
        Ok(SimpleSocket { media, rtcp })
    }

    /// Binds both sockets to OS-chosen ports on the unspecified address of the
    /// given family. This is the sender-side constructor: the local ports are
    /// arbitrary; the receiver learns them from inbound datagrams.
    ///
    /// # Errors
    /// Returns an I/O error if either socket cannot be bound.
    pub(crate) fn dial_ephemeral(rt: &dyn Runtime, ipv6: bool) -> io::Result<SimpleSocket> {
        let unspecified = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let any = SocketAddr::new(unspecified, 0);
        let media = rt.bind(any)?;
        let rtcp = rt.bind(any)?;
        Ok(SimpleSocket { media, rtcp })
    }

    /// The local media (even) address the transport is bound to.
    ///
    /// # Errors
    /// Returns the underlying socket error if the address cannot be read.
    pub(crate) fn media_local(&self) -> io::Result<SocketAddr> {
        self.media.local_addr()
    }

    /// The local RTCP (odd) address the transport is bound to. (Used by tests and
    /// future diagnostics; the driver only needs the media address publicly.)
    ///
    /// # Errors
    /// Returns the underlying socket error if the address cannot be read.
    #[allow(dead_code)]
    pub(crate) fn rtcp_local(&self) -> io::Result<SocketAddr> {
        self.rtcp.local_addr()
    }

    /// Receives one media (RTP) datagram, returning its length and source.
    pub(crate) async fn recv_media(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.media.poll_recv(cx, buf)).await
    }

    /// Receives one RTCP datagram, returning its length and source.
    pub(crate) async fn recv_rtcp(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.rtcp.poll_recv(cx, buf)).await
    }

    /// Sends one media (RTP) datagram to `dst`.
    pub(crate) async fn send_media(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.media.poll_send(cx, buf, dst)).await
    }

    /// Sends one RTCP datagram to `dst`.
    pub(crate) async fn send_rtcp(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.rtcp.poll_send(cx, buf, dst)).await
    }
}

/// A RIST Main-profile (VSF TR-06-2) UDP transport: a single unconnected UDP
/// socket carrying both GRE-tunnelled media and compound RTCP on one port. Clones
/// share the underlying socket (`Arc`), so the driver can send while awaiting
/// receives on the same socket.
#[derive(Debug, Clone)]
pub(crate) struct MainSocket {
    sock: Arc<dyn AsyncUdpSocket>,
}

impl MainSocket {
    /// Binds the single socket to `addr` (the receiver-side constructor). Unlike the
    /// Simple profile, the Main profile multiplexes everything onto one port, so any
    /// positive port is accepted.
    ///
    /// # Errors
    /// Returns an I/O error if the port is zero or the socket cannot be bound.
    pub(crate) fn listen(rt: &dyn Runtime, addr: SocketAddr) -> io::Result<MainSocket> {
        if addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rist: socket: main-profile port must be non-zero",
            ));
        }
        Ok(MainSocket {
            sock: rt.bind(addr)?,
        })
    }

    /// Binds the socket to an OS-chosen port on the unspecified address of the given
    /// family (the sender-side constructor). The receiver learns the local port from
    /// inbound datagrams.
    ///
    /// # Errors
    /// Returns an I/O error if the socket cannot be bound.
    pub(crate) fn dial_ephemeral(rt: &dyn Runtime, ipv6: bool) -> io::Result<MainSocket> {
        let unspecified = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        Ok(MainSocket {
            sock: rt.bind(SocketAddr::new(unspecified, 0))?,
        })
    }

    /// The local address the transport is bound to.
    ///
    /// # Errors
    /// Returns the underlying socket error if the address cannot be read.
    pub(crate) fn local(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// Receives one datagram, returning its length and source.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.sock.poll_recv(cx, buf)).await
    }

    /// Sends one datagram to `dst`.
    pub(crate) async fn send(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.sock.poll_send(cx, buf, dst)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::TokioRuntime;

    #[tokio::test]
    async fn listen_rejects_odd_and_zero_ports() {
        let rt = TokioRuntime;
        for bad in [0u16, 5001] {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bad);
            assert!(SimpleSocket::listen(&rt, addr).is_err(), "port {bad}");
        }
    }

    #[tokio::test]
    async fn dial_ephemeral_binds_two_distinct_sockets() {
        let rt = TokioRuntime;
        let s = SimpleSocket::dial_ephemeral(&rt, false).unwrap();
        let media = s.media_local().unwrap();
        let rtcp = s.rtcp_local().unwrap();
        assert_ne!(media.port(), 0);
        assert_ne!(rtcp.port(), 0);
        assert_ne!(media.port(), rtcp.port());
    }

    #[tokio::test]
    async fn media_and_rtcp_round_trip_on_loopback() {
        let rt = TokioRuntime;
        let recv = SimpleSocket::dial_ephemeral(&rt, false).unwrap();
        let send = SimpleSocket::dial_ephemeral(&rt, false).unwrap();
        // The sockets bind the unspecified address (0.0.0.0); send to loopback.
        let loop_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let recv_media_addr = SocketAddr::new(loop_ip, recv.media_local().unwrap().port());
        let recv_rtcp_addr = SocketAddr::new(loop_ip, recv.rtcp_local().unwrap().port());

        send.send_media(b"media", recv_media_addr).await.unwrap();
        send.send_rtcp(b"rtcp!", recv_rtcp_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, _src) = recv.recv_media(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"media");
        let (n, _src) = recv.recv_rtcp(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"rtcp!");
    }

    #[tokio::test]
    async fn main_socket_rejects_zero_port_and_round_trips() {
        let rt = TokioRuntime;
        let zero = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert!(MainSocket::listen(&rt, zero).is_err());

        let recv = MainSocket::dial_ephemeral(&rt, false).unwrap();
        let send = MainSocket::dial_ephemeral(&rt, false).unwrap();
        let dst = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            recv.local().unwrap().port(),
        );
        send.send(b"gre-frame", dst).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _src) = recv.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"gre-frame");
    }
}
