//! Client IP extraction for network controls.
//!
//! Railway supplies the original client address in `X-Real-IP`. The service
//! trusts that header only when the socket peer belongs to a private network.
//! Direct public peers cannot select their rate-limit key with a header.
//!
//! The address returned stands for one client network. An IPv4 address stands
//! for itself. An IPv6 address is reduced to its /64, because one customer
//! usually holds the whole /64 and can send from any address in it. Every
//! per-client control keys on this value, so none of them can be reset by
//! moving to a neighbouring address.

use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

const REAL_IP_HEADER: &str = "x-real-ip";

/// Resolve the client network from request headers + optional peer address.
///
/// Use Railway's client header behind a private proxy. Otherwise, use the
/// socket peer. The result is an IPv4 address or an IPv6 /64 network address.
pub fn extract_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    let peer_ip = peer.map(|socket| canonicalize(socket.ip()));
    if peer_ip.is_some_and(is_private_proxy_peer) {
        if let Some(real_ip) = headers
            .get(REAL_IP_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return Some(client_network(real_ip));
        }
    }
    peer_ip.map(client_network)
}

/// The network that per-client controls treat as one client.
pub fn client_network(ip: IpAddr) -> IpAddr {
    match canonicalize(ip) {
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            segments[4..].fill(0);
            IpAddr::V6(Ipv6Addr::from(segments))
        }
        v4 => v4,
    }
}

/// The /48 that contains an IPv6 client network. One site can hold a whole /48,
/// which is 65,536 client networks.
pub fn ipv6_site(ip: IpAddr) -> Option<[u16; 3]> {
    match canonicalize(ip) {
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            Some([segments[0], segments[1], segments[2]])
        }
        IpAddr::V4(_) => None,
    }
}

fn is_private_proxy_peer(ip: IpAddr) -> bool {
    match canonicalize(ip) {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

/// Collapse IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4 so the
/// rate-limiter keys both representations to the same entry.
fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_real_ip(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(REAL_IP_HEADER, value.parse().unwrap());
        h
    }

    #[test]
    fn extracts_real_ip_behind_a_private_proxy() {
        let headers = headers_with_real_ip("203.0.113.7");
        let peer: SocketAddr = "10.0.0.8:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.7");
    }

    #[test]
    fn ignores_real_ip_from_a_public_peer() {
        let headers = headers_with_real_ip("203.0.113.7");
        let peer: SocketAddr = "198.51.100.8:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.8");
    }

    #[test]
    fn ignores_forwarded_for() {
        let mut headers = headers_with_real_ip("203.0.113.7");
        headers.insert("x-forwarded-for", "198.51.100.99".parse().unwrap());
        let peer: SocketAddr = "10.0.0.8:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.7");
    }

    #[test]
    fn falls_back_to_peer_when_header_absent() {
        let headers = HeaderMap::new();
        let peer: SocketAddr = "192.0.2.42:9000".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "192.0.2.42");
    }

    #[test]
    fn falls_back_to_peer_when_header_unparseable() {
        let headers = headers_with_real_ip("not-an-ip");
        let peer: SocketAddr = "192.0.2.42:9000".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "192.0.2.42");
    }

    #[test]
    fn returns_none_when_both_absent() {
        let headers = HeaderMap::new();
        assert!(extract_client_ip(&headers, None).is_none());
    }

    #[test]
    fn trims_whitespace_around_ip() {
        let headers = headers_with_real_ip("  203.0.113.99  ");
        let peer: SocketAddr = "10.0.0.8:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.99");
    }

    #[test]
    fn parses_ipv6_from_real_ip() {
        let headers = headers_with_real_ip("2001:db8:1:2:3:4:5:6");
        let peer: SocketAddr = "[fd00::8]:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "2001:db8:1:2::");
    }

    #[test]
    fn every_address_in_one_ipv6_64_is_one_client() {
        let peer: SocketAddr = "[fd00::8]:8080".parse().unwrap();
        let first = headers_with_real_ip("2001:db8:1:2::1");
        let second = headers_with_real_ip("2001:db8:1:2:ffff:ffff:ffff:ffff");
        let neighbour = headers_with_real_ip("2001:db8:1:3::1");
        assert_eq!(
            extract_client_ip(&first, Some(peer)).unwrap(),
            extract_client_ip(&second, Some(peer)).unwrap()
        );
        assert_ne!(
            extract_client_ip(&first, Some(peer)).unwrap(),
            extract_client_ip(&neighbour, Some(peer)).unwrap()
        );
    }

    #[test]
    fn a_direct_ipv6_peer_is_reduced_to_its_64() {
        let peer: SocketAddr = "[2001:db8:9:8:7:6:5:4]:8080".parse().unwrap();
        let ip = extract_client_ip(&HeaderMap::new(), Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "2001:db8:9:8::");
    }

    #[test]
    fn the_ipv6_site_is_the_48() {
        assert_eq!(
            ipv6_site("2001:db8:cafe:1::".parse().unwrap()),
            Some([0x2001, 0xdb8, 0xcafe])
        );
        assert_eq!(ipv6_site("203.0.113.7".parse().unwrap()), None);
        assert_eq!(ipv6_site("::ffff:203.0.113.7".parse().unwrap()), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_normalizes_to_ipv4() {
        // `::ffff:203.0.113.7` and `203.0.113.7` are the same host on
        // dual-stack networks. The rate limiter MUST key them identically
        // or an attacker can sustain double the configured rate.
        let mapped = headers_with_real_ip("::ffff:203.0.113.7");
        let plain = headers_with_real_ip("203.0.113.7");
        let peer: SocketAddr = "10.0.0.8:8080".parse().unwrap();
        assert_eq!(
            extract_client_ip(&mapped, Some(peer)).unwrap(),
            extract_client_ip(&plain, Some(peer)).unwrap()
        );
        let ip = extract_client_ip(&mapped, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.7");
    }

    #[test]
    fn pure_ipv6_is_not_collapsed() {
        // A non-mapped IPv6 must stay IPv6 — collapsing every IPv6 to
        // some IPv4 fallback would crash on legitimate IPv6-only clients.
        let headers = headers_with_real_ip("2001:db8::dead:beef");
        let peer: SocketAddr = "[fd00::8]:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(ip.to_string(), "2001:db8::");
    }
}
