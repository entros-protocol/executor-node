//! Client IP extraction for network controls.
//!
//! Railway supplies the original client address in `X-Real-IP`. The service
//! trusts that header only when the socket peer belongs to a private network.
//! Direct public peers cannot select their rate-limit key with a header.

use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

const REAL_IP_HEADER: &str = "x-real-ip";

/// Resolve the client IP from request headers + optional peer address.
///
/// Use Railway's client header behind a private proxy. Otherwise, use the
/// socket peer. Normalize IPv4-mapped IPv6 before returning the address.
pub fn extract_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    let peer_ip = peer.map(|socket| canonicalize(socket.ip()));
    if peer_ip.is_some_and(is_private_proxy_peer) {
        if let Some(real_ip) = headers
            .get(REAL_IP_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return Some(canonicalize(real_ip));
        }
    }
    peer_ip
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
        let headers = headers_with_real_ip("2001:db8::1");
        let peer: SocketAddr = "[fd00::8]:8080".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer)).unwrap();
        assert_eq!(ip.to_string(), "2001:db8::1");
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
        assert_eq!(ip.to_string(), "2001:db8::dead:beef");
    }
}
