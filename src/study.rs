use std::sync::Arc;

use axum::extract::State;
use axum::http::{header::RETRY_AFTER, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use tokio::sync::OwnedSemaphorePermit;

use crate::error::AppError;
use crate::server::AppState;

const STUDY_PROXY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const STUDY_RESPONSE_BODY_BYTES: usize = 16 * 1024;
const MAX_RETRY_AFTER_SECS: u64 = 300;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyDefinitionRequest {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyEnrolRequest {
    wallet_id: String,
    signature_hex: String,
    authorization_id: String,
    signed_at: i64,
    consent_version: String,
    consent_hash_hex: String,
    enrolment_id: String,
    accepted: bool,
}

pub async fn study_definition_handler(
    State(state): State<AppState>,
    Json(_request): Json<StudyDefinitionRequest>,
) -> Result<Response, AppError> {
    let _permit = acquire_study_capacity(&state)?;
    proxy_study_request(&state, "/study/definition", serde_json::json!({})).await
}

pub async fn study_enrol_handler(
    State(state): State<AppState>,
    Json(request): Json<StudyEnrolRequest>,
) -> Result<Response, AppError> {
    if !valid_wallet_id(&request.wallet_id)
        || request.signature_hex.len() != 128
        || !request
            .signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || request.authorization_id.len() != 32
        || !request
            .authorization_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || request.signed_at <= 0
        || request.consent_version.is_empty()
        || request.consent_version.len() > 64
        || !request
            .consent_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || request.consent_hash_hex.len() != 64
        || !request
            .consent_hash_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || request.enrolment_id.len() != 32
        || !request
            .enrolment_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !request.accepted
    {
        return Err(AppError::InvalidRequest("invalid study enrolment".into()));
    }
    let _permit = acquire_study_capacity(&state)?;
    proxy_study_request(
        &state,
        "/study/enrol",
        serde_json::json!({
            "wallet_id": request.wallet_id,
            "signature_hex": request.signature_hex,
            "authorization_id": request.authorization_id,
            "signed_at": request.signed_at,
            "consent_version": request.consent_version,
            "consent_hash_hex": request.consent_hash_hex,
            "enrolment_id": request.enrolment_id,
            "accepted": request.accepted,
        }),
    )
    .await
}

fn valid_wallet_id(wallet_id: &str) -> bool {
    (32..=44).contains(&wallet_id.len())
        && bs58::decode(wallet_id)
            .into_vec()
            .is_ok_and(|bytes| bytes.len() == 32)
}

fn acquire_study_capacity(state: &AppState) -> Result<OwnedSemaphorePermit, AppError> {
    let permit = Arc::clone(&state.study_concurrency)
        .try_acquire_owned()
        .map_err(|_| AppError::StudyRouteLimited {
            retry_after_secs: 1,
        })?;
    state
        .study_service_rate_limiter
        .check_with_retry("study-service")
        .map_err(|retry_after_secs| AppError::StudyRouteLimited { retry_after_secs })?;
    Ok(permit)
}

async fn proxy_study_request(
    state: &AppState,
    path: &str,
    body: serde_json::Value,
) -> Result<Response, AppError> {
    let validation_url = state
        .validation_url
        .as_ref()
        .ok_or(AppError::ValidationServiceUnavailable)?;
    let mut request = state
        .http_client
        .post(format!("{validation_url}{path}"))
        .json(&body)
        .timeout(STUDY_PROXY_TIMEOUT);
    if let Some(key) = &state.validation_api_key {
        request = request.bearer_auth(key);
    }
    let mut upstream = request
        .send()
        .await
        .map_err(|_| AppError::ValidationServiceUnavailable)?;
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let retry_after = upstream.headers().get(RETRY_AFTER).cloned();
    let response_body = read_bounded_json(&mut upstream).await;
    let (status, response_body) = match response_body {
        Some(body) => (status, body),
        None => (
            StatusCode::BAD_GATEWAY,
            serde_json::json!({ "error": "Study service returned an invalid response" }),
        ),
    };
    let mut response = (status, Json(response_body)).into_response();
    if status == StatusCode::TOO_MANY_REQUESTS {
        if let Some(value) = retry_after.and_then(valid_retry_after) {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
    }
    Ok(response)
}

fn valid_retry_after(value: HeaderValue) -> Option<HeaderValue> {
    let seconds = value.to_str().ok()?.parse::<u64>().ok()?;
    if seconds == 0 {
        return None;
    }
    HeaderValue::from_str(&seconds.min(MAX_RETRY_AFTER_SECS).to_string()).ok()
}

async fn read_bounded_json(response: &mut reqwest::Response) -> Option<serde_json::Value> {
    if response
        .content_length()
        .is_some_and(|length| length > STUDY_RESPONSE_BODY_BYTES as u64)
    {
        return None;
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len().saturating_add(chunk.len()) > STUDY_RESPONSE_BODY_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use serde_json::Value;

    use super::*;
    use crate::auth::rate_limit::RateLimiter;
    use crate::server::{build_test_state, tracker_with_quota};

    #[test]
    fn study_requests_reject_unknown_fields() {
        let definition = serde_json::from_value::<StudyDefinitionRequest>(serde_json::json!({
            "invitation": "legacy-participant-capability"
        }));
        assert!(definition
            .expect_err("unknown definition field")
            .to_string()
            .contains("unknown field"));

        let enrolment = serde_json::from_value::<StudyEnrolRequest>(serde_json::json!({
            "wallet_id": bs58::encode([7_u8; 32]).into_string(),
            "signature_hex": "ab".repeat(64),
            "authorization_id": "cd".repeat(16),
            "signed_at": 1_775_000_000,
            "consent_version": "2026-08-13",
            "consent_hash_hex": "a".repeat(64),
            "enrolment_id": "0123456789abcdef0123456789abcdef",
            "accepted": true,
            "invitation": "legacy-participant-capability"
        }));
        assert!(enrolment
            .expect_err("unknown enrolment field")
            .to_string()
            .contains("unknown field"));
    }

    #[tokio::test]
    async fn invalid_enrolment_does_not_consume_study_capacity() {
        let tracker = tracker_with_quota("study-proxy", 10);
        let mut state = build_test_state(tracker, None);
        let limiter = Arc::new(RateLimiter::new(1));
        state.study_service_rate_limiter = Arc::clone(&limiter);

        let result = study_enrol_handler(
            State(state),
            Json(StudyEnrolRequest {
                wallet_id: "invalid".into(),
                signature_hex: "00".repeat(64),
                authorization_id: "11".repeat(16),
                signed_at: 1_775_000_000,
                consent_version: "2026-08-13".into(),
                consent_hash_hex: "aa".repeat(32),
                enrolment_id: "22".repeat(16),
                accepted: true,
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidRequest(_))));
        assert!(limiter.check("study-service").is_ok());
    }

    #[test]
    fn concurrency_rejection_does_not_consume_the_rate_bucket() {
        let tracker = tracker_with_quota("study-proxy", 10);
        let mut state = build_test_state(tracker, None);
        let limiter = Arc::new(RateLimiter::new(1));
        state.study_service_rate_limiter = Arc::clone(&limiter);
        state.study_concurrency = Arc::new(tokio::sync::Semaphore::new(0));

        assert!(matches!(
            acquire_study_capacity(&state),
            Err(AppError::StudyRouteLimited {
                retry_after_secs: 1
            })
        ));
        assert!(limiter.check("study-service").is_ok());
    }

    #[test]
    fn concurrency_permit_is_held_until_the_proxy_finishes() {
        let tracker = tracker_with_quota("study-proxy", 10);
        let mut state = build_test_state(tracker, None);
        state.study_service_rate_limiter = Arc::new(RateLimiter::new(10));
        state.study_concurrency = Arc::new(tokio::sync::Semaphore::new(1));

        let permit = acquire_study_capacity(&state).expect("first request acquires capacity");
        assert!(matches!(
            acquire_study_capacity(&state),
            Err(AppError::StudyRouteLimited {
                retry_after_secs: 1
            })
        ));
        drop(permit);
        assert!(acquire_study_capacity(&state).is_ok());
    }

    #[tokio::test]
    async fn study_concurrency_stays_bounded_under_pressure() {
        const PERMITS: usize = 8;
        const REQUESTS: usize = 64;

        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let handler_active = Arc::clone(&active);
        let handler_maximum = Arc::clone(&maximum);
        let app = Router::new().route(
            "/study/definition",
            post(move || {
                let active = Arc::clone(&handler_active);
                let maximum = Arc::clone(&handler_maximum);
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Json(serde_json::json!({ "active": current }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut state = build_test_state(
            tracker_with_quota("study-proxy", REQUESTS as u64),
            Some(format!("http://{address}")),
        );
        state.study_service_rate_limiter = Arc::new(RateLimiter::new(10_000));
        state.study_concurrency = Arc::new(tokio::sync::Semaphore::new(PERMITS));

        let barrier = Arc::new(tokio::sync::Barrier::new(REQUESTS));
        let mut tasks = Vec::with_capacity(REQUESTS);
        for _ in 0..REQUESTS {
            let request_state = state.clone();
            let request_barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                request_barrier.wait().await;
                study_definition_handler(State(request_state), Json(StudyDefinitionRequest {}))
                    .await
            }));
        }

        let mut accepted = 0;
        let mut limited = 0;
        for task in tasks {
            match task.await.expect("study task") {
                Ok(response) if response.status() == StatusCode::OK => accepted += 1,
                Err(AppError::StudyRouteLimited { .. }) => limited += 1,
                other => panic!("unexpected study response: {other:?}"),
            }
        }
        server.abort();

        assert_eq!(accepted, PERMITS);
        assert_eq!(limited, REQUESTS - PERMITS);
        assert!(maximum.load(Ordering::SeqCst) <= PERMITS);
    }

    #[tokio::test]
    async fn enrolment_proxy_preserves_the_idempotency_identifier() {
        let received = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured = Arc::clone(&received);
        let app = Router::new()
            .route(
                "/study/enrol",
                post(move |State(()): State<()>, Json(body): Json<Value>| {
                    let captured = Arc::clone(&captured);
                    async move {
                        captured.lock().expect("request log lock").push(body);
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "token": "A".repeat(43),
                                "session_id": "b".repeat(32),
                                "trial_index": 1,
                                "trial_limit": 3,
                                "expires_in": 3600
                            })),
                        )
                    }
                }),
            )
            .with_state(());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let state = build_test_state(
            tracker_with_quota("study-proxy", 10),
            Some(format!("http://{address}")),
        );

        let response = study_enrol_handler(
            State(state),
            Json(StudyEnrolRequest {
                wallet_id: bs58::encode([7_u8; 32]).into_string(),
                signature_hex: "ab".repeat(64),
                authorization_id: "cd".repeat(16),
                signed_at: 1_775_000_000,
                consent_version: "2026-08-10".into(),
                consent_hash_hex: "a".repeat(64),
                enrolment_id: "0123456789abcdef0123456789abcdef".into(),
                accepted: true,
            }),
        )
        .await
        .expect("proxy response");
        server.abort();

        assert_eq!(response.status(), StatusCode::OK);
        let requests = received.lock().expect("request log lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]["enrolment_id"],
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            requests[0]["wallet_id"],
            bs58::encode([7_u8; 32]).into_string()
        );
        assert_eq!(requests[0]["signature_hex"], "ab".repeat(64));
        assert_eq!(requests[0]["authorization_id"], "cd".repeat(16));
        assert_eq!(requests[0]["signed_at"], 1_775_000_000);
    }

    #[tokio::test]
    async fn definition_proxy_preserves_bounded_retry_after() {
        let app = Router::new().route(
            "/study/definition",
            post(|| async {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({ "error": "Rate limited" })),
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from_static("7"));
                response
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let state = build_test_state(
            tracker_with_quota("study-proxy", 10),
            Some(format!("http://{address}")),
        );

        let response = study_definition_handler(State(state), Json(StudyDefinitionRequest {}))
            .await
            .expect("proxy response");
        server.abort();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from_static("7"))
        );
    }

    #[test]
    fn retry_after_is_clamped() {
        assert_eq!(
            valid_retry_after(HeaderValue::from_static("18446744073709551615")),
            Some(HeaderValue::from_static("300"))
        );
        assert_eq!(valid_retry_after(HeaderValue::from_static("0")), None);
    }

    #[tokio::test]
    async fn oversized_upstream_response_becomes_bad_gateway() {
        let app = Router::new().route(
            "/study/definition",
            post(|| async { "x".repeat(STUDY_RESPONSE_BODY_BYTES + 1) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let state = build_test_state(
            tracker_with_quota("study-proxy", 10),
            Some(format!("http://{address}")),
        );

        let response = study_definition_handler(State(state), Json(StudyDefinitionRequest {}))
            .await
            .expect("proxy response");
        server.abort();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
