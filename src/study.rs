use axum::extract::State;
use axum::http::{header::RETRY_AFTER, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::error::AppError;
use crate::server::AppState;

const STUDY_PROXY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const STUDY_RESPONSE_BODY_BYTES: usize = 16 * 1024;
const MAX_RETRY_AFTER_SECS: u64 = 300;

#[derive(Deserialize)]
pub struct StudyDefinitionRequest {
    invitation: String,
}

#[derive(Deserialize)]
pub struct StudyEnrolRequest {
    invitation: String,
    consent_version: String,
    consent_hash_hex: String,
    enrolment_id: String,
    accepted: bool,
}

pub async fn study_definition_handler(
    State(state): State<AppState>,
    Json(request): Json<StudyDefinitionRequest>,
) -> Result<Response, AppError> {
    validate_invitation(&request.invitation)?;
    proxy_study_request(
        &state,
        "/study/definition",
        serde_json::json!({ "invitation": request.invitation }),
    )
    .await
}

pub async fn study_enrol_handler(
    State(state): State<AppState>,
    Json(request): Json<StudyEnrolRequest>,
) -> Result<Response, AppError> {
    validate_invitation(&request.invitation)?;
    if request.consent_version.is_empty()
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
        return Err(AppError::InvalidRequest(
            "invalid study consent version or hash".into(),
        ));
    }
    proxy_study_request(
        &state,
        "/study/enrol",
        serde_json::json!({
            "invitation": request.invitation,
            "consent_version": request.consent_version,
            "consent_hash_hex": request.consent_hash_hex,
            "enrolment_id": request.enrolment_id,
            "accepted": request.accepted,
        }),
    )
    .await
}

fn validate_invitation(invitation: &str) -> Result<(), AppError> {
    if (16..=256).contains(&invitation.len()) && invitation.is_ascii() {
        Ok(())
    } else {
        Err(AppError::InvalidRequest("invalid study invitation".into()))
    }
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
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use serde_json::Value;

    use super::*;
    use crate::server::{build_test_state, tracker_with_quota};

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
                invitation: "valid-study-invitation".into(),
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

        let response = study_definition_handler(
            State(state),
            Json(StudyDefinitionRequest {
                invitation: "valid-study-invitation".into(),
            }),
        )
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

        let response = study_definition_handler(
            State(state),
            Json(StudyDefinitionRequest {
                invitation: "valid-study-invitation".into(),
            }),
        )
        .await
        .expect("proxy response");
        server.abort();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
