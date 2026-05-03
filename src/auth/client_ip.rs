//! Client IP extraction for per-IP rate limiting (master-list #155).
//!
//! On Railway, the load balancer rewrites `X-Forwarded-For` on every
//! inbound request with the original client IP as the leftmost entry.
//! Trusting the header is safe ONLY because the edge layer overwrites
//! it before forwarding — outside Railway, `X-Forwarded-For` is
//! client-supplied and rotation-friendly. If this service is ever
//! deployed behind a different proxy or directly to the internet,
//! revisit this assumption.
//!
//! The peer address (`ConnectInfo<SocketAddr>` populated by axum) is
//! always Railway's internal proxy IP in production — useful only as a
//! local-dev fallback when the header is absent (direct curl, etc.).

use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";

/// Resolve the client IP from request headers + optional peer address.
///
/// Returns the leftmost parseable entry from `X-Forwarded-For`; otherwise
/// falls back to the peer address. Returns `None` only when both sources
/// are absent (unreachable in production — every Railway request has at
/// least the peer address).
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to their
/// IPv4 form so a dual-stack client cannot bypass the per-IP cap by
/// alternating between native IPv4 and the IPv4-mapped IPv6 representation
/// of the same underlying host.
pub fn extract_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    let raw = if let Some(value) = headers.get(FORWARDED_FOR_HEADER) {
        value
            .to_str()
            .ok()
            .and_then(|s| s.split(',').next())
            .and_then(|first| first.trim().parse::<IpAddr>().ok())
            .or_else(|| peer.map(|s| s.ip()))
    } else {
        peer.map(|s| s.ip())
    };
    raw.map(canonicalize)
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

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(FORWARDED_FOR_HEADER, value.parse().unwrap());
        h
    }

    #[test]
    fn extracts_leftmost_from_forwarded_for() {
        let headers = headers_with_xff("203.0.113.7, 10.0.0.1, 10.0.0.2");
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
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
        let headers = headers_with_xff("not-an-ip");
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
    fn handles_single_ip_in_forwarded_for() {
        let headers = headers_with_xff("198.51.100.5");
        let ip = extract_client_ip(&headers, None).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.5");
    }

    #[test]
    fn trims_whitespace_around_ip() {
        let headers = headers_with_xff("  203.0.113.99  , 10.0.0.1");
        let ip = extract_client_ip(&headers, None).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.99");
    }

    #[test]
    fn parses_ipv6_from_forwarded_for() {
        let headers = headers_with_xff("2001:db8::1, 10.0.0.1");
        let ip = extract_client_ip(&headers, None).unwrap();
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn ipv4_mapped_ipv6_normalizes_to_ipv4() {
        // `::ffff:203.0.113.7` and `203.0.113.7` are the same host on
        // dual-stack networks. The rate limiter MUST key them identically
        // or an attacker can sustain double the configured rate.
        let mapped = headers_with_xff("::ffff:203.0.113.7");
        let plain = headers_with_xff("203.0.113.7");
        assert_eq!(
            extract_client_ip(&mapped, None).unwrap(),
            extract_client_ip(&plain, None).unwrap()
        );
        // Confirm the canonical form is the IPv4.
        let ip = extract_client_ip(&mapped, None).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.7");
    }

    #[test]
    fn pure_ipv6_is_not_collapsed() {
        // A non-mapped IPv6 must stay IPv6 — collapsing every IPv6 to
        // some IPv4 fallback would crash on legitimate IPv6-only clients.
        let headers = headers_with_xff("2001:db8::dead:beef");
        let ip = extract_client_ip(&headers, None).unwrap();
        assert_eq!(ip.to_string(), "2001:db8::dead:beef");
    }
}
