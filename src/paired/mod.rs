//! Paired sessions: three rounds of one word and one short path, then one finalize.
//!
//! The validator holds every round in Postgres, so the executor keeps no paired state. Opening
//! and committing are untimed forwards: a commit carries digests only, and a timing floor on each
//! round would add seconds inside the interaction. Finalize carries every segment and goes
//! through the same timed stack, quota and admission checks as `/validate-features`.

pub mod finalize;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRequest, Request, State};
use axum::http::{header::RETRY_AFTER, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use tokio::sync::OwnedSemaphorePermit;

use crate::error::AppError;
use crate::server::AppState;
use crate::validation::handler::{check_probing_block, request_origin};

/// Largest open body: a wallet and a tier.
pub const OPEN_BODY_BYTES: usize = 4 * 1_024;
/// Largest commit body: a wallet, a session id, hex digests and small integers.
pub const COMMIT_BODY_BYTES: usize = 8 * 1_024;
/// Largest finalize body: three twelve-second segments of 16-bit audio in base64, the features,
/// the contours and three coarse paths.
pub const SESSION_BODY_BYTES: usize = 2 * 1_048_576;

/// Open and commit touch one row under a lock, so they return in milliseconds.
const ROUND_TIMEOUT: Duration = Duration::from_secs(5);
/// Upstream responses to open and commit are small JSON objects.
const ROUND_RESPONSE_BYTES: usize = 16 * 1_024;

/// A JSON body whose parse failure answers in the shape every paired refusal uses. An oversize
/// body keeps its 413; anything else is 400 `invalid_request`.
pub struct PairedJson<T>(pub T);

impl<S, T> FromRequest<S> for PairedJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(error) if error.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(AppError::PayloadTooLarge)
            }
            Err(_) => Err(invalid_request()),
        }
    }
}

pub(crate) fn invalid_request() -> AppError {
    AppError::PairedRejected {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid_request".into(),
    }
}

/// One paired finalize slot. The gate takes it before the body is buffered, and the finalize
/// handler holds it until it returns, so the timing floor after the handler holds no slot.
#[derive(Clone)]
pub struct SessionSlot {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl SessionSlot {
    pub fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _permit: Arc::new(permit),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRequest {
    wallet: String,
    tier: String,
}

#[derive(Serialize)]
struct UpstreamOpen<'a> {
    wallet_id: &'a str,
    challenge_nonce: String,
    origin_ip: String,
}

/// Opens a paired session. The nonce is fresh randomness bound into the session's attempt
/// binding. It never passes through the single-capture challenge registry, whose current
/// nonce `/attest` still consumes.
pub async fn open_handler(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    PairedJson(request): PairedJson<OpenRequest>,
) -> Result<Response, AppError> {
    let wallet = Pubkey::from_str(&request.wallet).map_err(|_| invalid_request())?;
    if request.tier != "trace" {
        return Err(invalid_request());
    }
    let (ip, _) = request_origin(&headers, peer.map(|Extension(c)| c.0));
    check_probing_block(&state, ip)?;
    // A wallet out of attempts could not finalize, so it opens nothing. Opening records none.
    state
        .wallet_attempts
        .check(&wallet)
        .map_err(|retry_after_secs| AppError::WalletRateLimited { retry_after_secs })?;

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    relay(
        &state,
        "/paired/sessions",
        &UpstreamOpen {
            wallet_id: &request.wallet,
            challenge_nonce: nonce.iter().map(|byte| format!("{byte:02x}")).collect(),
            origin_ip: ip.to_string(),
        },
    )
    .await
}

/// One round's commitment, forwarded unchanged. The validator checks and recomputes every
/// field, so the executor checks only the wallet.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    wallet_id: String,
    session_id: String,
    round_index: u32,
    round_nonce: String,
    challenge_digest: String,
    previous_commitment: String,
    audio_format: String,
    audio_byte_length: u32,
    audio_digest: String,
    path_point_count: u32,
    path_digest: String,
    commitment: String,
    idempotency_key: String,
}

pub async fn commit_handler(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    PairedJson(request): PairedJson<CommitRequest>,
) -> Result<Response, AppError> {
    Pubkey::from_str(&request.wallet_id).map_err(|_| invalid_request())?;
    let (ip, _) = request_origin(&headers, peer.map(|Extension(c)| c.0));
    check_probing_block(&state, ip)?;
    relay(&state, "/paired/commit", &request).await
}

/// Forwards to the validator and passes its status, JSON body and any `Retry-After` through.
/// Every paired reason is a protocol rule the client acts on, so none is withheld. A reply that
/// is not the validator's JSON, or a validator fault, is unavailability.
async fn relay<B: Serialize>(state: &AppState, path: &str, body: &B) -> Result<Response, AppError> {
    let reply = crate::upstream::post_json(state, path, body, ROUND_TIMEOUT, ROUND_RESPONSE_BYTES)
        .await
        .map_err(|fault| {
            tracing::error!(error = %fault, path, "Paired upstream request failed");
            AppError::PairedUnavailable
        })?;
    let body = match reply.body {
        Some(body) if !reply.status.is_server_error() => body,
        _ => {
            tracing::error!(
                status = %reply.status,
                path,
                "Paired upstream returned a fault or a body that is not its JSON"
            );
            return Err(AppError::PairedUnavailable);
        }
    };
    let mut response = (reply.status, Json(body)).into_response();
    if let Some(retry_after) = reply.retry_after {
        response.headers_mut().insert(RETRY_AFTER, retry_after);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::mock_validator::{state_with_mock_validator, MockValidator};
    use axum::body::to_bytes;

    const WALLET: &str = "11111111111111111111111111111111";

    fn tracker() -> std::sync::Arc<crate::integrator::tracker::IntegratorTracker> {
        crate::server::tracker_with_quota("key", 10)
    }

    async fn json_of(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64_000).await.expect("body");
        (status, serde_json::from_slice(&bytes).expect("json body"))
    }

    fn open_request(wallet: &str, tier: &str) -> PairedJson<OpenRequest> {
        PairedJson(OpenRequest {
            wallet: wallet.into(),
            tier: tier.into(),
        })
    }

    fn commit_request() -> PairedJson<CommitRequest> {
        PairedJson(
            serde_json::from_value(serde_json::json!({
                "wallet_id": WALLET,
                "session_id": "00112233445566778899aabbccddeeff",
                "round_index": 1,
                "round_nonce": "aa".repeat(32),
                "challenge_digest": "bb".repeat(32),
                "previous_commitment": "cc".repeat(32),
                "audio_format": "pcm_s16le_16000_mono",
                "audio_byte_length": 32_000,
                "audio_digest": "dd".repeat(32),
                "path_point_count": 12,
                "path_digest": "ee".repeat(32),
                "commitment": "ff".repeat(32),
                "idempotency_key": "01".repeat(16),
            }))
            .expect("commit parses"),
        )
    }

    #[tokio::test]
    async fn opening_forwards_a_fresh_nonce_and_the_address_only() {
        let mock = MockValidator::spawn(
            StatusCode::OK,
            serde_json::json!({ "protocol": "paired", "session_id": "ab" }),
        )
        .await;
        let state = state_with_mock_validator(tracker(), &mock);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::USER_AGENT,
            "agent".parse().expect("header"),
        );
        let response = open_handler(State(state), None, headers, open_request(WALLET, "trace"))
            .await
            .expect("forwarded");
        let (status, body) = json_of(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["protocol"], "paired");

        let sent = mock.received();
        assert_eq!(sent.len(), 1);
        let mut keys: Vec<&str> = sent[0]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["challenge_nonce", "origin_ip", "wallet_id"]);
        assert_eq!(sent[0]["wallet_id"], WALLET);
        let nonce = sent[0]["challenge_nonce"].as_str().expect("nonce");
        assert_eq!(nonce.len(), 64);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn two_opens_never_share_a_nonce() {
        let mock = MockValidator::spawn(StatusCode::OK, serde_json::json!({})).await;
        let state = state_with_mock_validator(tracker(), &mock);
        for _ in 0..2 {
            open_handler(
                State(state.clone()),
                None,
                HeaderMap::new(),
                open_request(WALLET, "trace"),
            )
            .await
            .expect("forwarded");
        }
        let sent = mock.received();
        assert_ne!(sent[0]["challenge_nonce"], sent[1]["challenge_nonce"]);
    }

    #[tokio::test]
    async fn an_unsupported_tier_or_wallet_never_reaches_the_validator() {
        let mock = MockValidator::spawn(StatusCode::OK, serde_json::json!({})).await;
        let state = state_with_mock_validator(tracker(), &mock);
        for (wallet, tier) in [(WALLET, "speech_only"), ("not-a-wallet", "trace")] {
            let result = open_handler(
                State(state.clone()),
                None,
                HeaderMap::new(),
                open_request(wallet, tier),
            )
            .await;
            assert!(matches!(
                result,
                Err(AppError::PairedRejected { ref reason, .. }) if reason == "invalid_request"
            ));
        }
        assert_eq!(mock.request_count(), 0);
    }

    #[tokio::test]
    async fn a_wallet_out_of_attempts_opens_nothing_and_spends_nothing() {
        let mock = MockValidator::spawn(StatusCode::OK, serde_json::json!({})).await;
        let state = state_with_mock_validator(tracker(), &mock);
        let wallet = Pubkey::from_str(WALLET).expect("wallet");
        while state
            .wallet_attempts
            .check_and_record_attempt(&wallet)
            .is_ok()
        {}
        let result = open_handler(
            State(state),
            None,
            HeaderMap::new(),
            open_request(WALLET, "trace"),
        )
        .await;
        assert!(matches!(result, Err(AppError::WalletRateLimited { .. })));
        assert_eq!(mock.request_count(), 0);
    }

    #[tokio::test]
    async fn an_open_refusal_passes_its_wait_through() {
        let mock = MockValidator::spawn_retry_after(
            StatusCode::CONFLICT,
            serde_json::json!({ "reason": "session_active", "retry_after": 42 }),
            "42",
        )
        .await;
        let state = state_with_mock_validator(tracker(), &mock);
        let response = open_handler(
            State(state),
            None,
            HeaderMap::new(),
            open_request(WALLET, "trace"),
        )
        .await
        .expect("forwarded");
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .map(|value| value.as_bytes()),
            Some(&b"42"[..])
        );
        let (status, body) = json_of(response).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["reason"], "session_active");
        assert_eq!(body["retry_after"], 42);
    }

    #[tokio::test]
    async fn a_commit_rejection_passes_its_status_and_reason_through() {
        let mock = MockValidator::spawn(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": "refused", "reason": "round_expired" }),
        )
        .await;
        let state = state_with_mock_validator(tracker(), &mock);
        let response = commit_handler(State(state), None, HeaderMap::new(), commit_request())
            .await
            .expect("forwarded");
        let (status, body) = json_of(response).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["reason"], "round_expired");
        let sent = mock.received();
        assert_eq!(sent[0]["round_index"], 1);
        assert_eq!(sent[0]["idempotency_key"], "01".repeat(16));
    }

    #[test]
    fn a_commit_with_an_unknown_field_is_refused() {
        let mut value = serde_json::to_value(&commit_request().0).expect("value");
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<CommitRequest>(value).is_err());
    }

    #[tokio::test]
    async fn an_unreachable_or_faulting_validator_answers_unavailable() {
        let down = MockValidator::spawn(StatusCode::OK, serde_json::json!({})).await;
        let state = state_with_mock_validator(tracker(), &down);
        down.shutdown().await;
        let result = commit_handler(State(state), None, HeaderMap::new(), commit_request()).await;
        assert!(matches!(result, Err(AppError::PairedUnavailable)));

        let faulting = MockValidator::spawn(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({ "error": "down", "reason": "validation_unavailable" }),
        )
        .await;
        let state = state_with_mock_validator(tracker(), &faulting);
        let result = commit_handler(State(state), None, HeaderMap::new(), commit_request()).await;
        assert!(matches!(result, Err(AppError::PairedUnavailable)));

        let not_json = MockValidator::spawn_raw(StatusCode::NOT_FOUND, "not found").await;
        let state = state_with_mock_validator(tracker(), &not_json);
        let result = commit_handler(State(state), None, HeaderMap::new(), commit_request()).await;
        assert!(matches!(result, Err(AppError::PairedUnavailable)));
    }
}
