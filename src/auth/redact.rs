//! Helper for redacting API keys and wallet IDs in log lines so operators
//! can correlate requests by prefix without exposing the full identifier
//! to anyone with log access (or a leaked log file).

use std::net::IpAddr;

const REDACT_PREFIX_LEN: usize = 6;

/// Returns a short, log-safe form of an API key.
///
/// `"gRAC5wF+6TPcQr25iCTgxSxj00fmmalXLXOlEn6yhFw="`
///   becomes
/// `"gRAC5w…"`
///
/// Six characters of base64-derived prefix is enough to differentiate keys
/// in a typical integrator pool while leaking minimal entropy. Empty input
/// returns `"<empty>"` for unambiguous logging.
pub fn redact_api_key(key: &str) -> String {
    if key.is_empty() {
        return "<empty>".into();
    }
    let take = REDACT_PREFIX_LEN.min(key.len());
    let mut s = String::with_capacity(take + 2);
    s.push_str(&key[..take]);
    s.push('…');
    s
}

/// Returns a short, log-safe form of a wallet pubkey.
///
/// Solana wallet pubkeys in base58 are 32–44 characters. The first 6
/// characters are sufficient to correlate log entries within an
/// integrator's traffic without retaining the full pubkey string in
/// operational logs. Wallet pubkeys are public on-chain data — every
/// transaction discloses the signer pubkey — so prefix redaction is a
/// privacy-by-architecture choice (keeping logs from becoming a secondary
/// surface for wallet-activity reconstruction) rather than a secrecy
/// primitive. Combined with structured logging plus the redacted API key,
/// operators can still triage incidents per integrator without retaining
/// per-wallet activity histories.
///
/// `"7xKxYBz2RdzBPyABxMfEHmgYPzqgxhCiW9TpRP4u9YCM"`
///   becomes
/// `"7xKxYB…"`
pub fn redact_wallet_id(wallet: &str) -> String {
    if wallet.is_empty() {
        return "<empty>".into();
    }
    let take = REDACT_PREFIX_LEN.min(wallet.len());
    let mut s = String::with_capacity(take + 2);
    s.push_str(&wallet[..take]);
    s.push('…');
    s
}

/// Returns a coarsened, log-safe form of a client IP address.
///
/// Mask the host portion so logs retain ISP-block-level granularity for
/// triage without storing exact client IPs. IPv4 → /24 (last octet
/// zeroed); IPv6 → /48 (only the first three groups kept). The trailing
/// `/24` or `/48` keeps the redaction shape unambiguous.
///
/// Used by the per-IP rate limiter middleware (master-list #155) so
/// `RATE_LIMIT: per-IP cap hit` log lines don't become a secondary
/// source of identifiable client data.
pub fn redact_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_long_keys_to_prefix() {
        let full = "gRAC5wF+6TPcQr25iCTgxSxj00fmmalXLXOlEn6yhFw=";
        let redacted = redact_api_key(full);
        assert_eq!(redacted, "gRAC5w…");
        assert!(!redacted.contains("yhFw"));
    }

    #[test]
    fn handles_short_keys() {
        assert_eq!(redact_api_key("ab"), "ab…");
    }

    #[test]
    fn handles_empty() {
        assert_eq!(redact_api_key(""), "<empty>");
    }

    #[test]
    fn handles_key_shorter_than_prefix_length() {
        // 5-char key < REDACT_PREFIX_LEN (6). Should take all 5 chars + ellipsis.
        assert_eq!(redact_api_key("abcde"), "abcde…");
    }

    #[test]
    fn handles_key_exactly_at_prefix_length() {
        // 6-char key == REDACT_PREFIX_LEN. Should take all 6 + ellipsis.
        assert_eq!(redact_api_key("abcdef"), "abcdef…");
    }

    #[test]
    fn redaction_is_deterministic() {
        let full = "gRAC5wF+6TPcQr25iCTgxSxj00fmmalXLXOlEn6yhFw=";
        assert_eq!(redact_api_key(full), redact_api_key(full));
    }

    #[test]
    fn redaction_does_not_leak_key_length() {
        // Two keys of very different lengths produce same-length redacted output.
        let short = redact_api_key("abcdefxxxxx");
        let long = redact_api_key("abcdefxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(short.chars().count(), long.chars().count());
    }

    #[test]
    fn redacts_wallet_pubkey_to_prefix() {
        let full = "7xKxYBz2RdzBPyABxMfEHmgYPzqgxhCiW9TpRP4u9YCM";
        let redacted = redact_wallet_id(full);
        assert_eq!(redacted, "7xKxYB…");
        assert!(!redacted.contains("9YCM"));
    }

    #[test]
    fn redact_wallet_handles_empty() {
        assert_eq!(redact_wallet_id(""), "<empty>");
    }

    #[test]
    fn redact_wallet_handles_short_input() {
        assert_eq!(redact_wallet_id("abc"), "abc…");
    }

    #[test]
    fn redacts_ipv4_last_octet() {
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        assert_eq!(redact_ip(ip), "203.0.113.0/24");
    }

    #[test]
    fn redacts_ipv6_to_first_three_groups() {
        let ip: IpAddr = "2001:db8:cafe::abcd".parse().unwrap();
        assert_eq!(redact_ip(ip), "2001:db8:cafe::/48");
    }

    #[test]
    fn redact_ipv4_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(redact_ip(ip), "127.0.0.0/24");
    }
}
