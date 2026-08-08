use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::error::AppError;
use crate::server::AppState;

const STUDY_PROXY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Deserialize)]
pub struct StudyDefinitionRequest {
    invitation: String,
}

#[derive(Deserialize)]
pub struct StudyEnrolRequest {
    invitation: String,
    consent_version: String,
    consent_hash_hex: String,
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
    let response = request
        .send()
        .await
        .map_err(|_| AppError::ValidationServiceUnavailable)?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let response_body = response.json::<serde_json::Value>().await.unwrap_or_else(
        |_| serde_json::json!({ "error": "Study service returned an invalid response" }),
    );
    Ok((status, Json(response_body)).into_response())
}
