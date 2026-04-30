use axum::http::StatusCode;
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

    /// Per-wallet validation-rejection cap exceeded (master-list #94 C4).
    /// `retry_after_secs` echoed in the response body so the client can
    /// surface a cooldown countdown instead of a blind retry.
    #[error("Too many attempts for this wallet")]
    WalletRateLimited { retry_after_secs: u64 },

    #[error("Insufficient quota")]
    InsufficientQuota,

    #[error("Solana RPC error: {0}")]
    SolanaRpc(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    /// Validation rejected the submission. The validator no longer surfaces
    /// a reason category over the wire (stripped 2026-04-29 to remove the
    /// directed-signal calibration channel for adversarial probing); this
    /// variant carries no payload. Server-side `safe_reason` still emits to
    /// `tracing::info!` for ops debugging.
    #[error("Validation failed")]
    ValidationFailed,

    #[error("Validation service error: {0}")]
    ValidationServiceError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".into()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limited".into()),
            AppError::WalletRateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Please wait before trying again.".into(),
            ),
            AppError::InsufficientQuota => {
                (StatusCode::PAYMENT_REQUIRED, "Insufficient verification quota".into())
            }
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::SolanaRpc(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            AppError::TransactionFailed(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
            }
            AppError::AttestationFailed(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
            }
            AppError::ValidationFailed => {
                (StatusCode::BAD_REQUEST, "Verification failed".into())
            }
            AppError::ValidationServiceError(msg) => {
                (StatusCode::BAD_GATEWAY, msg.clone())
            }
        };

        // WalletRateLimited surfaces `reason + retry_after` so the client
        // can render a cooldown countdown; everything else returns `{error}`
        // only. Bodies are padded so an outside observer can't read outcome
        // class from the response byte length on timed endpoints.
        let body = match &self {
            AppError::WalletRateLimited { retry_after_secs } => {
                json!({
                    "error": message,
                    "reason": "rate_limited",
                    "retry_after": retry_after_secs,
                })
            }
            _ => json!({ "error": message }),
        };
        (status, axum::Json(Padded::new(body))).into_response()
    }
}
