use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::padding::PaddedJson;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub commitment: Vec<u8>,
    #[serde(default)]
    pub is_first_verification: bool,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_quota: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn verify_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<PaddedJson<VerifyResponse>, AppError> {
    let api_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("authenticated")
        .to_string();

    if req.commitment.len() != 32 {
        return Err(AppError::InvalidRequest(format!(
            "commitment must be 32 bytes, got {}",
            req.commitment.len()
        )));
    }

    let mut commitment_arr = [0u8; 32];
    commitment_arr.copy_from_slice(&req.commitment);

    // Atomically check-and-record: returns true if commitment was already known.
    // Prevents clients from replaying is_first_verification=true for the same commitment.
    let commitment_known = state
        .commitment_registry
        .check_and_record(&api_key, commitment_arr);

    let is_first = if commitment_known {
        if req.is_first_verification {
            tracing::warn!(
                api_key = %crate::auth::redact::redact_api_key(&api_key),
                "Client claimed is_first_verification but commitment already known — forcing re-verification"
            );
        }
        false
    } else {
        req.is_first_verification
    };

    let remaining = state.tracker.check_and_deduct(&api_key)?;

    if is_first {
        tracing::info!(
            api_key = %crate::auth::redact::redact_api_key(&api_key),
            "First verification: commitment registered (no proof required)"
        );

        return Ok(PaddedJson(VerifyResponse {
            success: true,
            tx_signature: None,
            verified: None,
            registered: Some(true),
            remaining_quota: Some(remaining),
            error: None,
        }));
    }

    // Re-verification: validate and submit proof on-chain
    if req.proof_bytes.len() != 256 {
        state.tracker.refund(&api_key);
        return Err(AppError::InvalidRequest(format!(
            "proof_bytes must be 256 bytes, got {}",
            req.proof_bytes.len()
        )));
    }

    if req.public_inputs.len() != 4 {
        state.tracker.refund(&api_key);
        return Err(AppError::InvalidRequest(format!(
            "public_inputs must have 4 elements, got {}",
            req.public_inputs.len()
        )));
    }

    let mut inputs: [[u8; 32]; 4] = [[0u8; 32]; 4];
    for (i, pi) in req.public_inputs.iter().enumerate() {
        if pi.len() != 32 {
            state.tracker.refund(&api_key);
            return Err(AppError::InvalidRequest(format!(
                "public_inputs[{}] must be 32 bytes, got {}",
                i,
                pi.len()
            )));
        }
        inputs[i].copy_from_slice(pi);
    }

    tracing::info!(api_key = %crate::auth::redact::redact_api_key(&api_key), "Submitting re-verification proof");

    let outcome = match state.relayer_tx.submit_verification(&req.proof_bytes, &inputs).await {
        Ok(outcome) => outcome,
        Err(e) => {
            state.tracker.refund(&api_key);
            tracing::error!(api_key = %crate::auth::redact::redact_api_key(&api_key), error = %e, "Verification submission failed");
            return Err(e);
        }
    };

    let fresh_remaining = state.tracker.get_remaining(&api_key);

    tracing::info!(
        api_key = %crate::auth::redact::redact_api_key(&api_key),
        signature = %outcome.signature,
        verified = outcome.is_valid,
        remaining_quota = fresh_remaining,
        "Re-verification completed"
    );

    state.metrics.increment_verifications();

    Ok(PaddedJson(VerifyResponse {
        success: true,
        tx_signature: Some(outcome.signature),
        verified: Some(outcome.is_valid),
        registered: None,
        remaining_quota: Some(fresh_remaining),
        error: None,
    }))
}

pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
