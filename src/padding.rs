//! Response-size oracle closure for handler responses.
//!
//! Without padding, response byte length distinguishes outcome classes on
//! `/verify` and `/validate-features`: ~30 B for an opaque error, ~70 B
//! when the validator surfaces a soft-fail reason, ~150 B for a success
//! with a tx signature. An attacker watching only response sizes (e.g.,
//! over a TLS-terminating proxy or a passive network observer) can read
//! outcome class from byte count alone.
//!
//! `Padded<T>` adds a `_padding` field of ASCII `x` characters whose length
//! is computed so the final serialized JSON hits a fixed byte target. The
//! probe-then-fill pattern works for any flattenable JSON object — the
//! probe serializes with empty padding, measures, and assigns.
//!
//! Contract: `T` must serialize to a JSON object (not array, scalar, or
//! null) and must not contain a field named `_padding`. Both invariants
//! hold for every response type in this crate.

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Target serialized byte length for padded responses. 256 bytes is large
/// enough to absorb every observed response shape (largest is ~200 B for
/// re-verification success with tx signature) without leaving observable
/// margin between outcome classes. Responses that naturally exceed this
/// target ship with empty padding.
pub const RESPONSE_PADDING_TARGET: usize = 256;

/// JSON response wrapper that pads the serialized body to
/// `RESPONSE_PADDING_TARGET` bytes via a `_padding` field of ASCII `x`s.
/// Inner fields are flattened so consumers see them at the top level.
#[derive(Serialize)]
pub struct Padded<T: Serialize> {
    #[serde(flatten)]
    inner: T,
    _padding: String,
}

impl<T: Serialize> Padded<T> {
    /// Construct a `Padded<T>` whose serialized form (with the _padding
    /// field present and filled) hits `RESPONSE_PADDING_TARGET` bytes.
    /// Probes the empty-padding size, then assigns padding to fill the
    /// remainder. If the inner value naturally exceeds the target, the
    /// padding is empty and the response ships at its natural length.
    pub fn new(inner: T) -> Self {
        let mut padded = Self {
            inner,
            _padding: String::new(),
        };
        let probe_len = serde_json::to_string(&padded)
            .map(|s| s.len())
            .unwrap_or(RESPONSE_PADDING_TARGET);
        let padding_len = RESPONSE_PADDING_TARGET.saturating_sub(probe_len);
        padded._padding = "x".repeat(padding_len);
        padded
    }
}

/// Axum response type that wraps `T` and serializes it as JSON padded to
/// `RESPONSE_PADDING_TARGET` bytes. Drop-in replacement for `axum::Json`
/// at handler return sites where the response shouldn't leak outcome class
/// via byte length.
pub struct PaddedJson<T: Serialize>(pub T);

impl<T: Serialize> IntoResponse for PaddedJson<T> {
    fn into_response(self) -> Response {
        Json(Padded::new(self.0)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pads_short_inner_to_target_length() {
        let small = json!({ "ok": true });
        let padded = Padded::new(small);
        let serialized = serde_json::to_string(&padded).unwrap();
        assert_eq!(serialized.len(), RESPONSE_PADDING_TARGET);
        assert!(serialized.contains("\"_padding\":"));
    }

    #[test]
    fn empty_padding_when_inner_exceeds_target() {
        let big_string = "y".repeat(RESPONSE_PADDING_TARGET);
        let big = json!({ "data": big_string });
        let padded = Padded::new(big);
        let serialized = serde_json::to_string(&padded).unwrap();
        assert!(serialized.len() >= RESPONSE_PADDING_TARGET);
        // Padding is empty in this branch — confirm we still emit the field
        // for shape consistency (parsers don't see structural drift).
        assert!(serialized.contains("\"_padding\":\"\""));
    }

    #[test]
    fn preserves_inner_field_values() {
        #[derive(Serialize)]
        struct Inner {
            success: bool,
            tx: String,
        }
        let padded = Padded::new(Inner {
            success: true,
            tx: "abc123".into(),
        });
        let serialized = serde_json::to_string(&padded).unwrap();
        assert!(serialized.contains("\"success\":true"));
        assert!(serialized.contains("\"tx\":\"abc123\""));
        assert_eq!(serialized.len(), RESPONSE_PADDING_TARGET);
    }

    #[test]
    fn distinct_outcomes_serialize_to_identical_length() {
        // The whole point: a tiny error and a fat success must come out
        // the same size so an outside observer can't read outcome class
        // from byte count.
        let err = Padded::new(json!({ "error": "no" }));
        let ok = Padded::new(json!({
            "success": true,
            "tx_signature": "5ABC...",
            "verified": true,
            "remaining_quota": 999,
        }));
        let err_len = serde_json::to_string(&err).unwrap().len();
        let ok_len = serde_json::to_string(&ok).unwrap().len();
        assert_eq!(err_len, ok_len);
        assert_eq!(err_len, RESPONSE_PADDING_TARGET);
    }
}
