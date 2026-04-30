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

/// Pure structural validation of a Groth16 proof payload. Returns the
/// parsed `[[u8; 32]; 4]` public-input array on success, or an
/// `InvalidRequest` describing the first failed shape check. Takes the
/// two raw byte slices it reads rather than a whole `VerifyRequest` so
/// the helper has no implicit dependency on unrelated request fields and
/// is trivially testable in isolation.
fn validate_proof_shape(
    proof_bytes: &[u8],
    public_inputs: &[Vec<u8>],
) -> Result<[[u8; 32]; 4], AppError> {
    if proof_bytes.len() != 256 {
        return Err(AppError::InvalidRequest(format!(
            "proof_bytes must be 256 bytes, got {}",
            proof_bytes.len()
        )));
    }

    if public_inputs.len() != 4 {
        return Err(AppError::InvalidRequest(format!(
            "public_inputs must have 4 elements, got {}",
            public_inputs.len()
        )));
    }

    let mut inputs: [[u8; 32]; 4] = [[0u8; 32]; 4];
    for (i, pi) in public_inputs.iter().enumerate() {
        if pi.len() != 32 {
            return Err(AppError::InvalidRequest(format!(
                "public_inputs[{}] must be 32 bytes, got {}",
                i,
                pi.len()
            )));
        }
        inputs[i].copy_from_slice(pi);
    }

    Ok(inputs)
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

    // Re-verification: validate proof shape, then submit on-chain. The
    // shape check is a pure structural validation against the request body
    // — separated into a helper so a single refund site replaces the three
    // earlier inline checks, and so the structural-failure invariant is
    // testable in isolation from the handler's runtime dependencies.
    let inputs = match validate_proof_shape(&req.proof_bytes, &req.public_inputs) {
        Ok(inputs) => inputs,
        Err(e) => {
            state.tracker.refund(&api_key);
            return Err(e);
        }
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_inputs() -> Vec<Vec<u8>> {
        vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32], vec![4u8; 32]]
    }

    #[test]
    fn happy_path_returns_parsed_inputs() {
        let inputs = validate_proof_shape(&vec![0u8; 256], &valid_inputs()).unwrap();
        assert_eq!(inputs[0], [1u8; 32]);
        assert_eq!(inputs[1], [2u8; 32]);
        assert_eq!(inputs[2], [3u8; 32]);
        assert_eq!(inputs[3], [4u8; 32]);
    }

    #[test]
    fn rejects_short_proof_bytes() {
        match validate_proof_shape(&vec![0u8; 255], &valid_inputs()) {
            Err(AppError::InvalidRequest(msg)) => {
                assert!(msg.contains("proof_bytes"));
                assert!(msg.contains("255"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_long_proof_bytes() {
        match validate_proof_shape(&vec![0u8; 257], &valid_inputs()) {
            Err(AppError::InvalidRequest(msg)) => assert!(msg.contains("proof_bytes")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_proof_bytes() {
        match validate_proof_shape(&[], &valid_inputs()) {
            Err(AppError::InvalidRequest(msg)) => assert!(msg.contains("proof_bytes")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_too_few_public_inputs() {
        let inputs = vec![vec![0u8; 32], vec![0u8; 32], vec![0u8; 32]];
        match validate_proof_shape(&vec![0u8; 256], &inputs) {
            Err(AppError::InvalidRequest(msg)) => {
                assert!(msg.contains("public_inputs"));
                assert!(msg.contains("3"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_too_many_public_inputs() {
        let mut inputs = valid_inputs();
        inputs.push(vec![5u8; 32]);
        match validate_proof_shape(&vec![0u8; 256], &inputs) {
            Err(AppError::InvalidRequest(msg)) => {
                assert!(msg.contains("public_inputs"));
                assert!(msg.contains("5"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_short_public_input_element() {
        let mut inputs = valid_inputs();
        inputs[2] = vec![0u8; 31];
        match validate_proof_shape(&vec![0u8; 256], &inputs) {
            Err(AppError::InvalidRequest(msg)) => {
                assert!(msg.contains("public_inputs[2]"));
                assert!(msg.contains("31"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_long_public_input_element() {
        let mut inputs = valid_inputs();
        inputs[0] = vec![0u8; 33];
        match validate_proof_shape(&vec![0u8; 256], &inputs) {
            Err(AppError::InvalidRequest(msg)) => assert!(msg.contains("public_inputs[0]")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_first_invalid_element_only() {
        let mut inputs = valid_inputs();
        inputs[1] = vec![0u8; 30];
        inputs[3] = vec![0u8; 30];
        match validate_proof_shape(&vec![0u8; 256], &inputs) {
            Err(AppError::InvalidRequest(msg)) => {
                assert!(msg.contains("public_inputs[1]"));
                assert!(!msg.contains("public_inputs[3]"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }
}
