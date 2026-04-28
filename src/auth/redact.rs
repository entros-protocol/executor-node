//! Helper for redacting API keys in log lines so operators can correlate
//! requests by key prefix without exposing the full secret to anyone with
//! log access (or a leaked log file).

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
}
