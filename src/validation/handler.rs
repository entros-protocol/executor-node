use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

use crate::error::AppError;
use crate::padding::PaddedJson;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct ValidateFeaturesRequest {
    pub features: Vec<f64>,
    pub wallet_id: String,
    /// F0 contour per audio frame. Forwarded to the validation service for
    /// Tier 2 cross-modal temporal analysis. Absent for older SDK versions.
    #[serde(default)]
    pub f0_contour: Option<Vec<f64>>,
    /// Acceleration magnitude time-series, resampled to match `f0_contour` length.
    /// Paired with `f0_contour` for lagged cross-correlation.
    #[serde(default)]
    pub accel_magnitude: Option<Vec<f64>>,
    /// Base64-encoded 16-bit PCM audio samples (mono). Forwarded unchanged
    /// to the validation service for phrase content binding (master-list
    /// #89). Absent for older SDK versions.
    #[serde(default)]
    pub audio_samples_b64: Option<String>,
    /// Native sample rate of the transmitted audio. Forwarded unchanged to
    /// the validation service, which resamples to 16kHz if the browser
    /// delivered a rate other than the SDK target (common on iOS Safari
    /// with Bluetooth codec negotiation).
    #[serde(default)]
    pub audio_sample_rate_hz: Option<u32>,
    /// Hex-encoded 32-byte commitment that will be submitted on-chain in
    /// the upcoming `mint_anchor` transaction (master-list #146 Phase 2).
    /// Forwarded unchanged to the validation service, which signs a
    /// (wallet, commitment, validated_at) receipt when this is present and
    /// validation passes. Absent for re-verification (`update_anchor`)
    /// flows and pre-receipt SDK versions.
    #[serde(default)]
    pub commitment_new_hex: Option<String>,
}

#[derive(Serialize)]
pub struct ValidateFeaturesResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_quota: Option<u64>,
    /// Validator-signed receipt forwarded from the validation service when
    /// the request included `commitment_new_hex` (master-list #146 Phase 2).
    /// The SDK uses this to build an `Ed25519Program::verify` instruction
    /// bundled before `mint_anchor` in the same atomic transaction. Absent
    /// when the validator isn't configured for signing, when the SDK didn't
    /// supply a commitment, or when the validator returned a body without
    /// the field (older validator versions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_receipt: Option<SignedReceiptDto>,
}

/// Wire-format mirror of `entros_validation::SignedReceiptDto`. Defined
/// locally so the executor doesn't pull in the validator crate (different
/// repo, different release cadence). Wire fields must stay byte-identical
/// to the validator's serialization.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedReceiptDto {
    pub validator_pubkey_hex: String,
    pub message_hex: String,
    pub signature_hex: String,
}

pub async fn validate_features_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ValidateFeaturesRequest>,
) -> Result<PaddedJson<ValidateFeaturesResponse>, AppError> {
    let api_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("authenticated")
        .to_string();

    // Parse the wallet once. Valid wallets proceed; malformed inputs are
    // rejected before touching the rate limiter or validation service.
    let wallet = Pubkey::from_str(&req.wallet_id).map_err(|_| {
        AppError::InvalidRequest(format!("invalid wallet_id: {}", req.wallet_id))
    })?;

    // Per-wallet attempt cap (master-list #94). Atomic check-and-record
    // under a single DashMap entry write lock — concurrent requests for
    // the same wallet can never collectively bypass the cap. Slot is
    // refunded on successful validation below; failures leave it
    // consumed so failures accumulate against the budget.
    //
    // Sequenced before integrator quota so a rate-limited wallet doesn't
    // burn the integrator's quota.
    if let Err(retry_after_secs) = state.wallet_attempts.check_and_record_attempt(&wallet) {
        tracing::info!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            retry_after_secs,
            "Wallet rate limited"
        );
        return Err(AppError::WalletRateLimited { retry_after_secs });
    }

    // From this point on, the wallet attempt slot is consumed. Every
    // early-return path that does NOT correspond to a real validation
    // failure must refund the slot — otherwise legitimate users would be
    // counted against their per-wallet budget for infrastructure issues
    // (integrator quota exhausted, validator unreachable, etc.).
    let remaining = match state.tracker.check_and_deduct(&api_key) {
        Ok(r) => r,
        Err(e) => {
            // Integrator quota exhausted — not the wallet's fault.
            state.wallet_attempts.refund_on_success(&wallet);
            return Err(e);
        }
    };

    // If validation service is not configured, pass through. No
    // validation actually ran — refund the wallet slot AND the integrator
    // quota so dev environments without a validator don't tick either
    // budget, and skip the metrics increment so `validations_performed`
    // reflects work that actually happened. Re-read remaining_quota after
    // the refund so the response reflects the restored balance.
    let validation_url = match &state.validation_url {
        Some(url) => url,
        None => {
            tracing::debug!("Validation service not configured, skipping");
            state.wallet_attempts.refund_on_success(&wallet);
            state.tracker.refund(&api_key);
            let remaining_after_refund = state.tracker.get_remaining(&api_key);
            return Ok(PaddedJson(ValidateFeaturesResponse {
                valid: true,
                remaining_quota: Some(remaining_after_refund),
                signed_receipt: None,
            }));
        }
    };

    // Look up the challenge phrase for this wallet so the validation service
    // can match transcription against it (master-list #89). If no challenge
    // was issued (old SDK path) or it has aged out, forward `None` — the
    // validation service treats missing phrase as skip, preserving backward
    // compatibility for pre-0.10.0 SDK clients.
    let expected_phrase = state
        .challenge_registry
        .peek_phrase(&wallet, state.challenge_ttl_secs);

    // Build request to internal validation service. Forward time-series and
    // audio fields unchanged — the validation service handles absence of any
    // field (old SDK versions).
    //
    // Whisper-tiny inference adds ~1s to the validation round trip. Bump the
    // client-side timeout accordingly (3s → 8s) so legitimate audio payloads
    // don't time out before transcription completes.
    let mut request = state
        .http_client
        .post(format!("{validation_url}/validate"))
        .json(&serde_json::json!({
            "features": req.features,
            "wallet_id": req.wallet_id,
            "f0_contour": req.f0_contour,
            "accel_magnitude": req.accel_magnitude,
            "audio_samples_b64": req.audio_samples_b64,
            "audio_sample_rate_hz": req.audio_sample_rate_hz,
            "expected_phrase": expected_phrase,
            "commitment_new_hex": req.commitment_new_hex,
        }))
        .timeout(std::time::Duration::from_secs(8));

    // Add bearer token if configured
    if let Some(key) = &state.validation_api_key {
        request = request.bearer_auth(key);
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            // Infrastructure failure — refund integrator quota AND the
            // per-wallet attempt slot. The wallet did nothing wrong; if
            // the validator was unreachable the user shouldn't pay against
            // their per-wallet budget.
            state.tracker.refund(&api_key);
            state.wallet_attempts.refund_on_success(&wallet);
            return Err(AppError::ValidationServiceError(e.to_string()));
        }
    };

    state.metrics.increment_validations();

    if !response.status().is_success() {
        // Validator stripped its safe-reveal reason from the wire on
        // 2026-04-29 to close the directed-signal calibration channel; the
        // executor mirrors that opacity here. Server-side reason codes
        // remain in the validator's `tracing::info!` output for ops.
        //
        // Note: the per-wallet attempt slot consumed at the top of this
        // handler stays consumed — it's a real failed attempt against the
        // wallet's window budget.
        tracing::info!(
            api_key = %crate::auth::redact::redact_api_key(&api_key),
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            "Feature validation rejected"
        );
        return Err(AppError::ValidationFailed);
    }

    // Validation passed — refund the per-wallet attempt slot so a wallet
    // with all-successful verifications never accumulates against the cap.
    state.wallet_attempts.refund_on_success(&wallet);

    // Read the validator's success body to forward the signed receipt
    // (master-list #146 Phase 2). Older validator versions return
    // `{ "valid": true }` without the `signed_receipt` field — parse
    // failure or missing field both map to `None` and the SDK falls back
    // to the no-binding mint flow.
    #[derive(serde::Deserialize)]
    struct ValidatorSuccessBody {
        #[serde(default)]
        signed_receipt: Option<SignedReceiptDto>,
    }
    let signed_receipt = response
        .json::<ValidatorSuccessBody>()
        .await
        .ok()
        .and_then(|body| body.signed_receipt);

    tracing::info!(
        api_key = %crate::auth::redact::redact_api_key(&api_key),
        wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
        "Feature validation passed"
    );

    Ok(PaddedJson(ValidateFeaturesResponse {
        valid: true,
        remaining_quota: Some(remaining),
        signed_receipt,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{build_test_state, headers_with_key, random_wallet_id, tracker_with_quota};

    fn baseline_request(wallet_id: String) -> ValidateFeaturesRequest {
        ValidateFeaturesRequest {
            features: vec![0.0; 134],
            wallet_id,
            f0_contour: None,
            accel_magnitude: None,
            audio_samples_b64: None,
            audio_sample_rate_hz: None,
            commitment_new_hex: None,
        }
    }

    #[tokio::test]
    async fn dev_skip_refunds_integrator_quota() {
        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);
        let headers = headers_with_key("test-key");
        let req = baseline_request(random_wallet_id());

        let result = validate_features_handler(State(state), headers, Json(req)).await;

        assert!(result.is_ok(), "expected success, got {:?}", result.err());
        assert_eq!(
            tracker.get_remaining("test-key"),
            10,
            "dev-skip path must refund the integrator quota"
        );
    }

    #[tokio::test]
    async fn invalid_wallet_id_does_not_deduct_quota() {
        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);
        let headers = headers_with_key("test-key");
        let req = baseline_request("not-a-pubkey".into());

        let result = validate_features_handler(State(state), headers, Json(req)).await;

        assert!(
            matches!(result, Err(AppError::InvalidRequest(_))),
            "expected InvalidRequest"
        );
        assert_eq!(
            tracker.get_remaining("test-key"),
            10,
            "wallet-shape failure happens before deduct — quota must be untouched"
        );
    }
}
