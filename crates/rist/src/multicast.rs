//! Multicast group membership (receiver) and egress (sender) for the host
//! sockets — the libRIST `miface` / `ttl` / `source` options.
//!
//! Pure host I/O: when a receiver's bind address or a sender's destination is a
//! multicast group, the socket joins the group (any-source, or source-specific
//! when `multicast_source` is set) or stamps the egress interface / TTL /
//! loopback. A unicast address is left completely untouched. Ported from ristgo
//! `host.go` + `internal/socket/multicast.go`; the actual setsockopt calls live
//! in the [`AsyncUdpSocket`](crate::runtime::AsyncUdpSocket) implementation.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::Config;

/// A resolved network interface: the IPv4 membership/egress address (IPv4 groups
/// select the interface by address) and the interface index (IPv6 groups select
/// it by index). An empty `miface` yields `v4 = None`, `index = 0` — the OS
/// default interface.
#[derive(Debug, Clone, Default)]
pub struct ResolvedIface {
    /// The interface's IPv4 address, for IPv4 group membership/egress.
    pub v4: Option<Ipv4Addr>,
    /// The interface index, for IPv6 group membership/egress (`0` = default).
    pub index: u32,
}

/// A receiver's multicast membership: join `group` on `iface`, filtered to
/// `source` when source-specific multicast is requested.
#[derive(Debug, Clone)]
pub struct Membership {
    /// The multicast group to join.
    pub group: IpAddr,
    /// The SSM source filter, or `None` for any-source multicast.
    pub source: Option<IpAddr>,
    /// The membership interface.
    pub iface: ResolvedIface,
}

/// A sender's multicast egress options, applied when transmitting to `group`.
#[derive(Debug, Clone)]
pub struct Egress {
    /// The multicast destination group (selects the IP family of the options).
    pub group: IpAddr,
    /// The egress interface.
    pub iface: ResolvedIface,
    /// The multicast hop limit; `0` leaves the OS default (1, link-local).
    pub ttl: u8,
    /// Whether the sender receives its own datagrams on this host.
    pub loopback: bool,
}

/// The multicast group of `addr`, or `None` when it is a unicast address.
pub(crate) fn group_of(addr: SocketAddr) -> Option<IpAddr> {
    let ip = addr.ip();
    let multicast = match ip {
        IpAddr::V4(v4) => v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    };
    multicast.then_some(ip)
}

/// Resolves a `miface` interface name to its IPv4 address and index. An empty
/// name resolves to the OS default (`v4 = None`, `index = 0`).
///
/// # Errors
/// Returns [`io::ErrorKind::NotFound`] if a non-empty name matches no interface
/// on this host.
pub(crate) fn resolve_interface(name: &str) -> io::Result<ResolvedIface> {
    if name.is_empty() {
        return Ok(ResolvedIface::default());
    }
    let mut out = ResolvedIface::default();
    let mut found = false;
    for ifa in if_addrs::get_if_addrs()? {
        if ifa.name != name {
            continue;
        }
        found = true;
        if let Some(idx) = ifa.index {
            out.index = idx;
        }
        if let if_addrs::IfAddr::V4(v4) = &ifa.addr
            && out.v4.is_none()
        {
            out.v4 = Some(v4.ip);
        }
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name:?} not found"),
        ));
    }
    Ok(out)
}

/// Resolves the configured interface, or the OS default when none is set.
fn resolve_cfg_iface(cfg: &Config) -> io::Result<ResolvedIface> {
    match &cfg.interface {
        Some(name) => resolve_interface(name),
        None => Ok(ResolvedIface::default()),
    }
}

/// Builds the receiver membership for a bind to `bind`, or `None` for a unicast
/// bind (the plain receiver, unchanged).
///
/// # Errors
/// Errors if `multicast_source` is set on a unicast bind (a source filter is
/// meaningless without a group), if the configured interface does not resolve,
/// or if `multicast_source` is not a valid IP literal.
pub(crate) fn receiver_membership(
    cfg: &Config,
    bind: SocketAddr,
) -> io::Result<Option<Membership>> {
    let Some(group) = group_of(bind) else {
        if cfg.multicast_source.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multicast_source is set but the bind address is not a multicast group",
            ));
        }
        return Ok(None);
    };
    let source = match &cfg.multicast_source {
        Some(s) => Some(s.parse::<IpAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "multicast_source is not a valid IP",
            )
        })?),
        None => None,
    };
    Ok(Some(Membership {
        group,
        source,
        iface: resolve_cfg_iface(cfg)?,
    }))
}

/// Builds the sender egress for a destination `dst`, or `None` for a unicast
/// destination (the plain sender, unchanged).
///
/// # Errors
/// Errors if the configured interface does not resolve.
pub(crate) fn sender_egress(cfg: &Config, dst: SocketAddr) -> io::Result<Option<Egress>> {
    let Some(group) = group_of(dst) else {
        return Ok(None);
    };
    Ok(Some(Egress {
        group,
        iface: resolve_cfg_iface(cfg)?,
        ttl: cfg.multicast_ttl,
        loopback: cfg.multicast_loopback,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    #[test]
    fn group_detection_v4_and_v6() {
        assert_eq!(
            group_of(sa("239.1.2.3:5000")),
            Some("239.1.2.3".parse().unwrap())
        );
        assert_eq!(
            group_of(sa("[ff02::1]:5000")),
            Some("ff02::1".parse().unwrap())
        );
        assert_eq!(group_of(sa("127.0.0.1:5000")), None);
        assert_eq!(group_of(sa("[::1]:5000")), None);
    }

    #[test]
    fn empty_interface_resolves_to_default() {
        let r = resolve_interface("").expect("empty resolves");
        assert_eq!(r.v4, None);
        assert_eq!(r.index, 0);
    }

    #[test]
    fn unknown_interface_is_not_found() {
        let e = resolve_interface("nonexistent-iface-zzz").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn unicast_bind_yields_no_membership() {
        let cfg = Config::default();
        assert!(
            receiver_membership(&cfg, sa("127.0.0.1:5000"))
                .unwrap()
                .is_none()
        );
        assert!(sender_egress(&cfg, sa("127.0.0.1:5000")).unwrap().is_none());
    }

    #[test]
    fn source_on_unicast_bind_is_rejected() {
        let cfg = Config::default().with_multicast_source("10.0.0.1");
        assert!(receiver_membership(&cfg, sa("127.0.0.1:5000")).is_err());
    }

    #[test]
    fn multicast_bind_builds_membership_and_egress() {
        let cfg = Config::default()
            .with_multicast_ttl(16)
            .with_multicast_source("10.0.0.1");
        let m = receiver_membership(&cfg, sa("239.1.2.3:5000"))
            .unwrap()
            .expect("group");
        assert_eq!(m.group, "239.1.2.3".parse::<IpAddr>().unwrap());
        assert_eq!(m.source, Some("10.0.0.1".parse::<IpAddr>().unwrap()));
        let e = sender_egress(&cfg, sa("239.1.2.3:5000"))
            .unwrap()
            .expect("group");
        assert_eq!(e.ttl, 16);
    }
}
