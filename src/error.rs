use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::padding::Padded;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Rate limited")]
    RateLimited,

    /// Per-IP rate-limit cap exceeded (master-list #155). The middleware
    /// short-circuits before auth/quota deduction so an attacker rotating
    /// wallets behind a single IP can't sustain throughput by burning the
    /// other limiters' state. Surfaces as `429 Too Many Requests` with a
    /// `Retry-After` header so well-behaved clients (SDK retry UX, ops
    /// scripts) back off correctly.
    #[error("IP rate limited")]
    IpRateLimited { retry_after_secs: u64 },

    /// Per-wallet validation-rejection cap exceeded (master-list #94 C4).
    /// `retry_after_secs` echoed in the response body so the client can
    /// surface a cooldown countdown instead of a blind retry.
    #[error("Too many attempts for this wallet")]
    WalletRateLimited { retry_after_secs: u64 },

    #[error("Insufficient quota")]
    InsufficientQuota,

    /// Solana RPC was unreachable or returned an error (connection
    /// refused, blockhash expiry, account read failure, etc.). Renders a
    /// generic user-facing body — `solana_client::ClientError` internals
    /// (RPC endpoints, retry counts, transport detail) never reach the
    /// wire. Full detail is preserved in call-site `tracing::error!` for
    /// ops. Note: the SDK still surfaces blockhash-retry signals via its
    /// own client-side `confirmAndCheck` wrapping for wallet-connected
    /// flows, so no user-actionable signal is lost here.
    #[error("Solana RPC temporarily unavailable")]
    SolanaRpcUnavailable,

    /// On-chain transaction submission failed after retry exhaustion.
    /// Renders a generic user-facing body — `solana_client::ClientError`
    /// internals (RPC URLs, transaction signatures, simulation traces)
    /// never reach the wire. Full detail is preserved in call-site
    /// `tracing::error!` for ops. Note: frontend `isPrevCommitmentMismatchError`
    /// / `isResetCooldownError` / `isProgramRevertError` matchers consume
    /// the SDK-side `JSON.stringify(confirmation.value.err)` wrapping from
    /// `pulse-sdk/src/submit/wallet.ts`, NOT the executor wire body, so no
    /// routing signal is lost here.
    #[error("Transaction submission failed")]
    TransactionSubmissionFailed,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Attestation processing failed (missing IdentityState, deserialization
    /// error, SAS issuance failure, system time error). Renders a generic
    /// user-facing body — closes the wallet-pubkey PII leak that the
    /// prior `AttestationFailed(format!("...wallet {user_wallet}"))` had.
    /// Full detail is preserved in call-site `tracing::error!` for ops.
    /// Attestation is best-effort post-verification — the SDK treats
    /// failure as nonfatal.
    #[error("Attestation processing failed")]
    AttestationServiceUnavailable,

    /// Validation rejected the submission. The validator surfaces a single
    /// whitelisted reason category over the wire (`phrase_content_mismatch`)
    /// because the user already knows whether they said the assigned phrase
    /// — that category exposes zero attacker-calibration value while
    /// enabling the soft-reject retry UX on entros.io. All other safe_reason
    /// categories (variance_floor, entropy_bounds, temporal_coupling_low,
    /// and attack-signal categories like TtsDetected, SybilMatch) carry
    /// directed-signal calibration value and stay opaque per the 2026-04-29
    /// strip — `reason` stays `None` for those.
    #[error("Validation failed")]
    ValidationFailed { reason: Option<String> },

    /// The upstream validation service was unreachable (connect refused,
    /// DNS failure, timeout, etc.). Renders a generic user-facing body
    /// — `reqwest::Error` internals (hostnames, ports, connect-error
    /// categories) never reach the wire. Full detail is preserved in
    /// the call-site `tracing::error!` for ops.
    #[error("Validation service temporarily unavailable")]
    ValidationServiceUnavailable,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // IpRateLimited needs a `Retry-After` header alongside the JSON body.
        // Handled before the standard match so we can attach the header
        // without restructuring the rest of the variant handling.
        //
        // The user-facing message starts with "Too many requests" so the
        // entros.io frontend's `isRateLimitedError` ("too many" substring
        // match) categorizes it as the friendly "rate-limited" UX surface
        // alongside the existing per-wallet rate-limit case, instead of
        // falling through to a generic "Verification failed" page.
        if let AppError::IpRateLimited { retry_after_secs } = &self {
            let body = json!({
                "error": "Too many requests from your network. Please wait before trying again.",
                "reason": "ip_rate_limited",
                "retry_after": retry_after_secs,
            });
            let mut resp =
                (StatusCode::TOO_MANY_REQUESTS, axum::Json(Padded::new(body))).into_response();
            // `u64::to_string` is always valid header bytes, so the parse
            // can't fail. unreachable! documents the invariant.
            let header = HeaderValue::from_str(&retry_after_secs.to_string())
                .unwrap_or_else(|_| unreachable!("u64 stringification is valid header bytes"));
            resp.headers_mut().insert("retry-after", header);
            return resp;
        }

        let (status, message) = match &self {
            AppError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".into()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limited".into()),
            AppError::IpRateLimited { .. } => unreachable!("handled above"),
            AppError::WalletRateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Please wait before trying again.".into(),
            ),
            AppError::InsufficientQuota => (
                StatusCode::PAYMENT_REQUIRED,
                "Insufficient verification quota".into(),
            ),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::SolanaRpcUnavailable => (
                StatusCode::BAD_GATEWAY,
                "Solana network temporarily unavailable. Please try again.".into(),
            ),
            AppError::TransactionSubmissionFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification could not be completed. Please try again.".into(),
            ),
            AppError::AttestationServiceUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attestation processing failed. Please try again.".into(),
            ),
            AppError::ValidationFailed { .. } => {
                (StatusCode::BAD_REQUEST, "Verification failed".into())
            }
            AppError::ValidationServiceUnavailable => (
                StatusCode::BAD_GATEWAY,
                "Validation service temporarily unavailable. Please try again.".into(),
            ),
        };

        // WalletRateLimited surfaces `reason + retry_after` so the client
        // can render a cooldown countdown; ValidationFailed surfaces a
        // whitelisted `reason` (currently only `phrase_content_mismatch`)
        // when the validator returned one — fuels the soft-reject retry UX
        // on entros.io without exposing attacker-calibration channels for
        // other check categories. Everything else returns `{error}` only.
        // Bodies are padded so an outside observer can't read outcome class
        // from the response byte length on timed endpoints.
        let body = match &self {
            AppError::WalletRateLimited { retry_after_secs } => {
                json!({
                    "error": message,
                    "reason": "rate_limited",
                    "retry_after": retry_after_secs,
                })
            }
            AppError::ValidationFailed { reason: Some(r) } => {
                json!({
                    "error": message,
                    "reason": r,
                })
            }
            _ => json!({ "error": message }),
        };
        (status, axum::Json(Padded::new(body))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// Shared assertion helper: asserts the response body carries the expected
    /// generic substring and contains none of the substrings that commonly
    /// appear in `reqwest::Error` / `solana_client::ClientError` rendering
    /// (which would indicate the sanitization boundary leaked).
    async fn assert_sanitized_body(resp: Response, expected_substring: &str) {
        let body_bytes = to_bytes(resp.into_body(), 64_000)
            .await
            .expect("body bytes");
        let body_str = std::str::from_utf8(&body_bytes).expect("utf8 body");

        assert!(
            body_str.to_lowercase().contains(expected_substring),
            "expected substring '{expected_substring}' in body, got: {body_str}"
        );

        for forbidden in [
            "tcp",
            "dns",
            "refused",
            "timeout",
            "ipv4",
            "ipv6",
            "rpc response error",
            "custom program error",
            "instruction",
            "wallet ",
            "pubkey",
        ] {
            assert!(
                !body_str.to_lowercase().contains(forbidden),
                "wire body must not leak '{forbidden}', got: {body_str}"
            );
        }
    }

    #[tokio::test]
    async fn validation_service_unavailable_renders_generic_body() {
        let resp = AppError::ValidationServiceUnavailable.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_sanitized_body(resp, "temporarily unavailable").await;
    }

    #[tokio::test]
    async fn solana_rpc_unavailable_renders_generic_body() {
        let resp = AppError::SolanaRpcUnavailable.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_sanitized_body(resp, "temporarily unavailable").await;
    }

    #[tokio::test]
    async fn transaction_submission_failed_renders_generic_body() {
        let resp = AppError::TransactionSubmissionFailed.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_sanitized_body(resp, "could not be completed").await;
    }

    #[tokio::test]
    async fn attestation_service_unavailable_renders_generic_body() {
        let resp = AppError::AttestationServiceUnavailable.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_sanitized_body(resp, "attestation processing failed").await;
    }
}
