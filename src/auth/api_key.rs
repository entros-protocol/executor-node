use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// Validate the X-API-Key header against the configured API keys.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub async fn api_key_auth(
    request: Request,
    next: Next,
    api_keys: &[String],
) -> Result<Response, AppError> {
    let key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let key_bytes = key.as_bytes();
    if !is_valid_api_key(key_bytes, api_keys) {
        return Err(AppError::Unauthorized);
    }

    Ok(next.run(request).await)
}

/// Check whether `provided` matches any of `api_keys` in constant time.
///
/// The naive pattern `k.len() == provided.len() && k.as_bytes().ct_eq(...)`
/// short-circuits on the length check before `ct_eq` runs, leaking the
/// expected key's length to a timing attacker (the wall-clock time differs
/// based on whether the lengths matched). Mitigation: ALWAYS run `ct_eq`
/// against a same-length subslice (or padded buffer), then `&` the result
/// with the length-equality bit so the length contribution is byte-wise
/// rather than control-flow-wise.
///
/// Mirrors the dummy-comparison pattern in entros-validation's auth
/// middleware so both Rust services have identical timing characteristics.
fn is_valid_api_key(provided: &[u8], api_keys: &[String]) -> bool {
    api_keys.iter().any(|k| {
        let expected = k.as_bytes();
        // Always run ct_eq against a slice of `expected.len()`. If lengths
        // differ, compare against a zero-buffer of the right length — the
        // result will be false anyway, but the wall-clock time matches.
        let comparison_target: Vec<u8> = if provided.len() == expected.len() {
            provided.to_vec()
        } else {
            vec![0u8; expected.len()]
        };
        let ct_match: bool = comparison_target.ct_eq(expected).into();
        let length_match = provided.len() == expected.len();
        // `&` (bitwise) rather than `&&` to avoid short-circuit timing.
        // Both bool ops are constant-time at the byte level.
        (ct_match as u8) & (length_match as u8) == 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_correct_key() {
        let keys = vec!["secret-abc-123".to_string()];
        assert!(is_valid_api_key(b"secret-abc-123", &keys));
    }

    #[test]
    fn rejects_wrong_key_same_length() {
        let keys = vec!["secret-abc-123".to_string()];
        assert!(!is_valid_api_key(b"secret-xyz-456", &keys));
    }

    #[test]
    fn rejects_wrong_length_short() {
        let keys = vec!["secret-abc-123".to_string()];
        assert!(!is_valid_api_key(b"short", &keys));
    }

    #[test]
    fn rejects_wrong_length_long() {
        let keys = vec!["secret-abc-123".to_string()];
        assert!(!is_valid_api_key(b"this-is-much-longer-than-expected", &keys));
    }

    #[test]
    fn rejects_empty_provided() {
        let keys = vec!["secret-abc-123".to_string()];
        assert!(!is_valid_api_key(b"", &keys));
    }

    #[test]
    fn matches_any_of_multiple_keys() {
        let keys = vec![
            "first-key-aaa".to_string(),
            "second-key-bbb".to_string(),
            "third-key-ccc".to_string(),
        ];
        assert!(is_valid_api_key(b"second-key-bbb", &keys));
    }

    #[test]
    fn empty_keys_list_rejects_everything() {
        let keys: Vec<String> = vec![];
        assert!(!is_valid_api_key(b"any-key", &keys));
    }
}
