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

use crate::multicast::{Egress, Membership};
use crate::runtime::{AsyncUdpSocket, Runtime};

/// A RIST Simple-profile UDP transport: a media socket (even port) and an RTCP
/// socket (odd port). Clones share the underlying sockets (`Arc`), so the driver
/// can hold one handle for sends while awaiting receives on the same sockets.
#[derive(Debug, Clone)]
pub(crate) struct SimpleSocket {
    media: Arc<dyn AsyncUdpSocket>,
    rtcp: Arc<dyn AsyncUdpSocket>,
    /// The separate-port column FEC socket (media port + 2), bound only on a receiver
    /// that has enabled the separate-port SMPTE ST 2022-1 / ST 2022-5 FEC carriage.
    fec_col: Option<Arc<dyn AsyncUdpSocket>>,
    /// The separate-port row FEC socket (media port + 4); bound only for 2-D FEC
    /// (column-only FEC binds the column socket alone).
    fec_row: Option<Arc<dyn AsyncUdpSocket>>,
}

impl SimpleSocket {
    /// Binds the media socket to `addr` and the RTCP socket to the adjacent odd
    /// port (`addr.port() + 1`). The port must be a positive even number
    /// (TR-06-1 §4: the media port is even, RTCP is the next port). This is the
    /// receiver-side constructor.
    ///
    /// When `membership` is set (the bind address is a multicast group), both the
    /// media and RTCP sockets join the group after binding.
    ///
    /// # Errors
    /// Returns an I/O error if the port is not a positive even number, if either
    /// socket cannot be bound, or if the multicast join fails.
    pub(crate) fn listen(
        rt: &dyn Runtime,
        addr: SocketAddr,
        membership: Option<&Membership>,
    ) -> io::Result<SimpleSocket> {
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
        if let Some(m) = membership {
            media.join_multicast(m)?;
            rtcp.join_multicast(m)?;
        }
        Ok(SimpleSocket {
            media,
            rtcp,
            fec_col: None,
            fec_row: None,
        })
    }

    /// Binds the separate-port FEC sockets for a receiver: the column FEC port (media
    /// port + 2) and, for 2-D FEC (`want_row`), the row FEC port (media port + 4).
    /// `addr` is the media bind address; `membership` is reapplied to the FEC sockets
    /// when the bind is a multicast group. Call after [`SimpleSocket::listen`], before
    /// the socket is handed to the driver.
    ///
    /// # Errors
    /// Returns an I/O error if a FEC socket cannot be bound or the multicast join
    /// fails.
    pub(crate) fn bind_fec(
        &mut self,
        rt: &dyn Runtime,
        addr: SocketAddr,
        membership: Option<&Membership>,
        want_row: bool,
    ) -> io::Result<()> {
        let mut col_addr = addr;
        col_addr.set_port(addr.port() + 2);
        let col = rt.bind(col_addr)?;
        if let Some(m) = membership {
            col.join_multicast(m)?;
        }
        self.fec_col = Some(col);
        if want_row {
            let mut row_addr = addr;
            row_addr.set_port(addr.port() + 4);
            let row = rt.bind(row_addr)?;
            if let Some(m) = membership {
                row.join_multicast(m)?;
            }
            self.fec_row = Some(row);
        }
        Ok(())
    }

    /// Receives one column FEC datagram, or never resolves when no column FEC socket
    /// is bound (so a `select!` arm is a no-op without FEC).
    pub(crate) async fn recv_fec_col(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.fec_col {
            Some(s) => poll_fn(|cx| s.poll_recv(cx, buf)).await,
            None => std::future::pending().await,
        }
    }

    /// Receives one row FEC datagram, or never resolves when no row FEC socket is
    /// bound (column-only FEC, or FEC disabled).
    pub(crate) async fn recv_fec_row(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.fec_row {
            Some(s) => poll_fn(|cx| s.poll_recv(cx, buf)).await,
            None => std::future::pending().await,
        }
    }

    /// Binds both sockets to OS-chosen ports on the unspecified address of the
    /// given family. This is the sender-side constructor: the local ports are
    /// arbitrary; the receiver learns them from inbound datagrams.
    ///
    /// When `egress` is set (the destination is a multicast group), both sockets
    /// receive the multicast egress options (interface, TTL, loopback).
    ///
    /// # Errors
    /// Returns an I/O error if either socket cannot be bound or the egress options
    /// cannot be applied.
    pub(crate) fn dial_ephemeral(
        rt: &dyn Runtime,
        ipv6: bool,
        egress: Option<&Egress>,
    ) -> io::Result<SimpleSocket> {
        let unspecified = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let any = SocketAddr::new(unspecified, 0);
        let media = rt.bind(any)?;
        let rtcp = rt.bind(any)?;
        if let Some(e) = egress {
            media.set_multicast_egress(e)?;
            rtcp.set_multicast_egress(e)?;
        }
        Ok(SimpleSocket {
            media,
            rtcp,
            fec_col: None,
            fec_row: None,
        })
    }

    /// Binds an ephemeral **consecutive** even/odd pair: a free even media port and its
    /// odd neighbor (`media + 1`) for RTCP. Used by the reversed-role caller-receiver so
    /// a listener-sender can derive the caller's media port as `rtcp_port - 1` (matching
    /// libRIST/ristgo). Probes for a free even port whose neighbor is also free.
    ///
    /// # Errors
    /// Returns an I/O error if no free even/odd pair can be bound, or the egress options
    /// cannot be applied.
    pub(crate) fn dial_ephemeral_paired(
        rt: &dyn Runtime,
        ipv6: bool,
        egress: Option<&Egress>,
    ) -> io::Result<SimpleSocket> {
        let unspecified = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        for _ in 0..64 {
            let media = rt.bind(SocketAddr::new(unspecified, 0))?;
            let port = media.local_addr()?.port();
            if !port.is_multiple_of(2) {
                continue; // odd media port: drop it and retry for an even one
            }
            let mut rtcp_addr = SocketAddr::new(unspecified, 0);
            rtcp_addr.set_port(port + 1);
            let Ok(rtcp) = rt.bind(rtcp_addr) else {
                continue; // the odd neighbor is taken: retry a fresh pair
            };
            if let Some(e) = egress {
                media.set_multicast_egress(e)?;
                rtcp.set_multicast_egress(e)?;
            }
            return Ok(SimpleSocket {
                media,
                rtcp,
                fec_col: None,
                fec_row: None,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "rist: socket: no free even/odd port pair for a reversed-role caller-receiver",
        ))
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
    /// The separate-port column FEC socket (GRE port + 2), bound only on a receiver
    /// with the SMPTE ST 2022-1 / ST 2022-5 separate-port FEC carriage enabled.
    fec_col: Option<Arc<dyn AsyncUdpSocket>>,
    /// The separate-port row FEC socket (GRE port + 4); bound only for 2-D FEC.
    fec_row: Option<Arc<dyn AsyncUdpSocket>>,
}

impl MainSocket {
    /// Binds the single socket to `addr` (the receiver-side constructor). Unlike the
    /// Simple profile, the Main profile multiplexes everything onto one port, so any
    /// positive port is accepted.
    ///
    /// When `membership` is set (the bind address is a multicast group), the socket
    /// joins the group after binding.
    ///
    /// # Errors
    /// Returns an I/O error if the port is zero, the socket cannot be bound, or the
    /// multicast join fails.
    pub(crate) fn listen(
        rt: &dyn Runtime,
        addr: SocketAddr,
        membership: Option<&Membership>,
    ) -> io::Result<MainSocket> {
        if addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rist: socket: main-profile port must be non-zero",
            ));
        }
        let sock = rt.bind(addr)?;
        if let Some(m) = membership {
            sock.join_multicast(m)?;
        }
        Ok(MainSocket {
            sock,
            fec_col: None,
            fec_row: None,
        })
    }

    /// Binds the separate-port FEC sockets for a Main-profile receiver: the column FEC
    /// port (GRE port + 2) and, for 2-D FEC (`want_row`), the row FEC port (+ 4). FEC
    /// is carried as standard ST 2022-1 RTP on these ports, not GRE-framed. Call after
    /// [`MainSocket::listen`], before the socket is handed to the driver.
    ///
    /// # Errors
    /// Returns an I/O error if a FEC socket cannot be bound or the multicast join
    /// fails.
    pub(crate) fn bind_fec(
        &mut self,
        rt: &dyn Runtime,
        addr: SocketAddr,
        membership: Option<&Membership>,
        want_row: bool,
    ) -> io::Result<()> {
        let mut col_addr = addr;
        col_addr.set_port(addr.port() + 2);
        let col = rt.bind(col_addr)?;
        if let Some(m) = membership {
            col.join_multicast(m)?;
        }
        self.fec_col = Some(col);
        if want_row {
            let mut row_addr = addr;
            row_addr.set_port(addr.port() + 4);
            let row = rt.bind(row_addr)?;
            if let Some(m) = membership {
                row.join_multicast(m)?;
            }
            self.fec_row = Some(row);
        }
        Ok(())
    }

    /// Receives one column FEC datagram, or never resolves when no column FEC socket
    /// is bound (so a `select!` arm is a no-op without FEC).
    pub(crate) async fn recv_fec_col(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.fec_col {
            Some(s) => poll_fn(|cx| s.poll_recv(cx, buf)).await,
            None => std::future::pending().await,
        }
    }

    /// Receives one row FEC datagram, or never resolves when no row FEC socket is
    /// bound (column-only FEC, or FEC disabled).
    pub(crate) async fn recv_fec_row(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.fec_row {
            Some(s) => poll_fn(|cx| s.poll_recv(cx, buf)).await,
            None => std::future::pending().await,
        }
    }

    /// Binds the socket to an OS-chosen port on the unspecified address of the given
    /// family (the sender-side constructor). The receiver learns the local port from
    /// inbound datagrams.
    ///
    /// When `egress` is set (the destination is a multicast group), the socket
    /// receives the multicast egress options (interface, TTL, loopback).
    ///
    /// # Errors
    /// Returns an I/O error if the socket cannot be bound or the egress options
    /// cannot be applied.
    pub(crate) fn dial_ephemeral(
        rt: &dyn Runtime,
        ipv6: bool,
        egress: Option<&Egress>,
    ) -> io::Result<MainSocket> {
        let unspecified = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let sock = rt.bind(SocketAddr::new(unspecified, 0))?;
        if let Some(e) = egress {
            sock.set_multicast_egress(e)?;
        }
        Ok(MainSocket {
            sock,
            fec_col: None,
            fec_row: None,
        })
    }

    /// Wraps an already-built [`AsyncUdpSocket`] as a Main transport (no FEC sockets).
    /// Used by the DTLS host-wiring, which presents its plaintext bridge as an
    /// `AsyncUdpSocket` so the driver is unchanged. (Feature `dtls`.)
    #[cfg(feature = "dtls")]
    pub(crate) fn from_async(sock: Arc<dyn AsyncUdpSocket>) -> MainSocket {
        MainSocket {
            sock,
            fec_col: None,
            fec_row: None,
        }
    }

    /// Recovers a caller-receiver NAT / dynamic-IP source-port change (libRIST
    /// `try_caller_socket_rebind`): binds a FRESH ephemeral socket on the same host
    /// family and returns it as a new [`MainSocket`] (no FEC sockets — caller-receiver
    /// reversed-role carries no separate-port FEC). The fresh local port makes the
    /// peer re-learn this side's source on the next outbound keepalive. The driver
    /// swaps `self` for the result and respawns its reader on it.
    ///
    /// # Errors
    /// Returns an I/O error if the current local address cannot be read or the fresh
    /// socket cannot be bound.
    pub(crate) fn rebind(&self) -> io::Result<MainSocket> {
        let ipv6 = self.local()?.is_ipv6();
        // A caller-rebind is a production NAT-recovery path; bind directly via the
        // default tokio runtime (matching ristgo's direct rebind), independent of any
        // injected runtime.
        MainSocket::dial_ephemeral(&crate::runtime::TokioRuntime, ipv6, None)
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
            assert!(SimpleSocket::listen(&rt, addr, None).is_err(), "port {bad}");
        }
    }

    #[tokio::test]
    async fn dial_ephemeral_binds_two_distinct_sockets() {
        let rt = TokioRuntime;
        let s = SimpleSocket::dial_ephemeral(&rt, false, None).unwrap();
        let media = s.media_local().unwrap();
        let rtcp = s.rtcp_local().unwrap();
        assert_ne!(media.port(), 0);
        assert_ne!(rtcp.port(), 0);
        assert_ne!(media.port(), rtcp.port());
    }

    #[tokio::test]
    async fn main_rebind_binds_a_fresh_distinct_port_same_family() {
        let rt = TokioRuntime;
        for ipv6 in [false, true] {
            let Ok(s) = MainSocket::dial_ephemeral(&rt, ipv6, None) else {
                continue; // host may lack IPv6
            };
            let old = s.local().unwrap();
            let fresh = s.rebind().expect("rebind");
            let new = fresh.local().unwrap();
            assert_eq!(old.is_ipv6(), new.is_ipv6(), "rebind must keep the family");
            assert_ne!(new.port(), 0);
            // The old socket is still open here (the driver closes it), so the OS must
            // pick a different port for the fresh one.
            assert_ne!(old.port(), new.port(), "rebind must pick a fresh port");
        }
    }

    #[tokio::test]
    async fn media_and_rtcp_round_trip_on_loopback() {
        let rt = TokioRuntime;
        let recv = SimpleSocket::dial_ephemeral(&rt, false, None).unwrap();
        let send = SimpleSocket::dial_ephemeral(&rt, false, None).unwrap();
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
        assert!(MainSocket::listen(&rt, zero, None).is_err());

        let recv = MainSocket::dial_ephemeral(&rt, false, None).unwrap();
        let send = MainSocket::dial_ephemeral(&rt, false, None).unwrap();
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
