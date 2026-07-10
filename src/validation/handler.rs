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
    /// Legacy mint-intent signal. Forwarded unchanged to the validation
    /// service, whose receipt is signed over a SERVER-DERIVED commitment — the
    /// bytes here are no longer trusted, only their presence triggers signing
    /// for SDKs predating `request_receipt`. Absent for re-verification
    /// (`update_anchor`) flows and pre-receipt SDK versions.
    #[serde(default)]
    pub commitment_new_hex: Option<String>,
    /// Explicit mint-intent flag (current SDKs). Forwarded unchanged; the
    /// validation service signs a receipt over the commitment it derives from
    /// `features` when this is set and validation passes. Absent for
    /// re-verification and pre-`request_receipt` SDKs.
    #[serde(default)]
    pub request_receipt: Option<bool>,
    /// Observe-only automation-detection signals (master-list #196, Layer A1).
    /// Collected client-side by the SDK and logged here for calibration. NOT
    /// forwarded to the validation service and NOT part of the pass/fail
    /// decision. Privacy-first — the SDK reports only automation-framework
    /// artifacts (the WebDriver flag + framework labels), never fingerprints or
    /// user data. Absent for older SDKs (logged as such).
    #[serde(default)]
    pub client_signals: Option<ClientSignals>,
}

/// The `client_signals` envelope (Layer A1). Wire mirror of the SDK's
/// `ClientSignals`. Namespaced so future signal groups (interaction realism,
/// capture realism) slot in as siblings of `automation` without a breaking wire
/// change. Every field is `#[serde(default)]` so a partial or older payload
/// deserializes cleanly. Observe-only — never influences the verification
/// outcome.
#[derive(Deserialize, Debug)]
pub struct ClientSignals {
    /// Envelope schema version emitted by the SDK collector.
    #[serde(default)]
    pub v: u32,
    /// "browser", or "non-browser" for React Native / Node / SSR runtimes.
    #[serde(default)]
    pub env: Option<String>,
    /// Automation-framework detection group.
    #[serde(default)]
    pub automation: Option<AutomationSignals>,
    /// Capture environment signals (e.g. virtual devices).
    #[serde(default)]
    pub capture: Option<CaptureSignals>,
}

#[derive(Deserialize, Debug)]
pub struct CaptureSignals {
    /// Virtual audio/video device detection flag.
    #[serde(default)]
    pub virtual_device: bool,
    /// Spectral flatness of the audio capture (Wiener entropy).
    #[serde(default)]
    pub flatness: Option<f64>,
    /// Spectral centroid of the audio capture in Hz.
    #[serde(default)]
    pub centroid: Option<f64>,
}

/// Automation-framework detection group inside `client_signals`. Wire mirror of
/// the SDK's `AutomationSignals`.
#[derive(Deserialize, Debug)]
pub struct AutomationSignals {
    /// `navigator.webdriver === true` — the W3C WebDriver automation flag.
    #[serde(default)]
    pub webdriver: bool,
    /// Automation-framework labels found in the page (e.g. "puppeteer",
    /// "selenium"). Empty for a real human session.
    #[serde(default)]
    pub tells: Vec<String>,
}

#[derive(Serialize)]
pub struct ValidateFeaturesResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_quota: Option<u64>,
    /// Validator-signed receipt forwarded from the validation service when the
    /// request signaled mint intent. The SDK uses this to build an
    /// `Ed25519Program::verify` instruction bundled before `mint_anchor` in
    /// the same atomic transaction. Absent when the validator isn't configured
    /// for signing, when the request didn't signal mint intent, or when the
    /// validator returned a body without the field (older validator versions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_receipt: Option<SignedReceiptDto>,
    /// Server-derived commitment (hex, 32-byte big-endian) the receipt binds —
    /// the value the SDK must submit to `mint_anchor`. Forwarded from the
    /// validation service; present iff `signed_receipt` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_hex: Option<String>,
    /// Salt (hex, 32-byte big-endian) the validator used to derive the
    /// commitment. NOT in the signed receipt; the SDK stores it to rebuild the
    /// commitment for future rotation proofs. Present iff `signed_receipt` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_hex: Option<String>,
    
    // Layer E Composite Risk Score
    pub composite_risk_score: f64,
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
    let wallet = Pubkey::from_str(&req.wallet_id)
        .map_err(|_| AppError::InvalidRequest(format!("invalid wallet_id: {}", req.wallet_id)))?;

    // Observe-only automation-detection signal (master-list #196, Layer A1).
    // Logged for real-traffic calibration; NOT forwarded to the validation
    // service and NOT part of the pass/fail decision below. Privacy-first: the
    // SDK reports only automation-framework artifacts (the WebDriver flag +
    // framework labels), never fingerprints or user data, so a privacy-hardened
    // browser (Tor / RFP) is never flagged. We measure real-user trip rates
    // before this signal influences anything. Info-level only when a tell
    // fires (the rare, interesting case); clean/absent stays at debug so prod
    // logs are quiet until we flip to debug for baseline measurement.
    if state.automation_observe {
        let signals = req.client_signals.as_ref();
        match signals.and_then(|c| c.automation.as_ref()) {
            Some(a) if a.webdriver || !a.tells.is_empty() => {
                // Cap the logged labels so a malicious oversized payload can't
                // bloat the log line; the full count is logged separately. `env`
                // is attacker-controlled free text, so it is Debug-formatted
                // (`?`) — like `tells` — to escape control chars and prevent
                // log-line injection against the plaintext log subscriber.
                let tells: Vec<&str> = a.tells.iter().take(16).map(String::as_str).collect();
                tracing::info!(
                    wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                    webdriver = a.webdriver,
                    env = ?signals.and_then(|c| c.env.as_deref()).unwrap_or("unknown"),
                    tell_count = a.tells.len(),
                    tells = ?tells,
                    schema = signals.map_or(0, |c| c.v),
                    "Automation signal observed"
                );
            }
            Some(_) => {
                tracing::debug!(
                    wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                    "Client signals present and clean"
                );
            }
            None => tracing::debug!("No automation signals on request (older SDK or non-browser)"),
        }
        if let Some(c) = signals.and_then(|sig| sig.capture.as_ref()) {
            if c.virtual_device || c.flatness.is_some() || c.centroid.is_some() {
                tracing::info!(
                    wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                    virtual_device = c.virtual_device,
                    flatness = ?c.flatness,
                    centroid = ?c.centroid,
                    "Capture signals observed"
                );
            }
        }
    }

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

    // Observe-only wallet reputation (master-list #196, Layer D1). Reads the
    // verifying wallet's PUBLIC on-chain reputation (balance + recent activity)
    // as a risk prior and logs it for calibration. Placed AFTER the per-wallet
    // cap and integrator-quota gates so rate-limited / quota-exhausted traffic
    // can't drive RPC reads — and so the logged population is real, admitted
    // verification attempts. Detached (tokio::spawn) so it adds ZERO latency and
    // can never block, fail, or alter the decision/quota. A process-wide gate
    // bounds concurrent reads (they share the relayer's RpcClient); when
    // saturated the sample is skipped. Public chain data only — no surveillance,
    // no profile store.
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
                commitment_hex: None,
                salt_hex: None,
                composite_risk_score: 0.0,
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
            "request_receipt": req.request_receipt,
        }))
        .timeout(std::time::Duration::from_secs(8));

    // Add bearer token if configured
    if let Some(key) = &state.validation_api_key {
        request = request.bearer_auth(key);
    }

    // Run the validator request and the wallet reputation fetch in parallel.
    // RPC fetch shares a semaphored concurrency limit.
    let reputation_future = async {
        if state.wallet_reputation_observe {
            if let Ok(permit) = crate::reputation::REPUTATION_RPC_GATE.try_acquire() {
                let client = state.relayer_tx.client();
                let _permit = permit;
                match tokio::time::timeout(
                    std::time::Duration::from_millis(1500),
                    crate::reputation::fetch_wallet_reputation(&client, &wallet),
                )
                .await
                {
                    Ok(Ok(rep)) => Some(rep),
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                            "Observe-only reputation fetch failed"
                        );
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                            "Observe-only reputation fetch timed out after 1500ms"
                        );
                        None
                    }
                }
            } else {
                tracing::warn!(
                    wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                    "Reputation RPC gate saturated; skipping observe-only check"
                );
                None
            }
        } else {
            None
        }
    };

    let (response_res, reputation_opt) = tokio::join!(
        request.send(),
        reputation_future
    );

    let response = match response_res {
        Ok(r) => r,
        Err(e) => {
            // Full error detail stays in ops logs; the wire response
            // body resolves to a generic "service temporarily unavailable"
            // string so reqwest internals (hostnames, ports, connect-error
            // categories) never reach external observers.
            tracing::error!(
                error = %e,
                url = %validation_url,
                wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                "Validation upstream request failed"
            );
            // Infrastructure failure — refund integrator quota AND the
            // per-wallet attempt slot. The wallet did nothing wrong; if
            // the validator was unreachable the user shouldn't pay against
            // their per-wallet budget.
            state.tracker.refund(&api_key);
            state.wallet_attempts.refund_on_success(&wallet);
            return Err(AppError::ValidationServiceUnavailable);
        }
    };

    state.metrics.increment_validations();

    // 1. Automation Risk (Layer A1)
    let mut automation_risk = 0.0;
    if let Some(signals) = req.client_signals.as_ref() {
        if let Some(a) = signals.automation.as_ref() {
            if a.webdriver {
                automation_risk = 1.0;
            } else if !a.tells.is_empty() {
                automation_risk = (a.tells.len() as f64 * 0.5).min(1.0);
            }
        }
        if let Some(c) = signals.capture.as_ref() {
            if c.virtual_device {
                automation_risk = 1.0;
            }
            if let Some(flatness) = c.flatness {
                if !(0.015..=0.85).contains(&flatness) {
                    automation_risk = (automation_risk + 0.8).min(1.0);
                }
            }
        }
    }

    // 2. Reputation Risk (Layer D1)
    let reputation_risk = if let Some(rep) = &reputation_opt {
        let sol_score = (rep.sol_lamports as f64 / 100_000_000.0).min(1.0);
        let activity_score = (rep.signature_count as f64 / 10.0).min(1.0);
        let rep_prior = 0.5 * sol_score + 0.5 * activity_score;
        let mut risk = 1.0 - rep_prior;
        if rep.sybil_risk > 0.0 {
            risk = (risk + 0.5).min(1.0);
            tracing::warn!(
                wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                parent_wallet = ?rep.parent_wallet.map(|p| p.to_string()),
                "Sybil wallet funding activity detected! Parent wallet registered within 24h."
            );
        }
        risk
    } else {
        0.5
    };

    #[derive(serde::Deserialize)]
    struct ValidatorSuccessBody {
        #[serde(default)]
        signed_receipt: Option<SignedReceiptDto>,
        #[serde(default)]
        commitment_hex: Option<String>,
        #[serde(default)]
        salt_hex: Option<String>,
        #[serde(default)]
        biometric_risk: f64,
        #[serde(default)]
        tts_risk: f64,
        #[serde(default)]
        temporal_risk: f64,
        #[serde(default)]
        audio_realism_risk: f64,
    }

    #[derive(serde::Deserialize)]
    struct ValidatorErrorBody {
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        biometric_risk: f64,
        #[serde(default)]
        tts_risk: f64,
        #[serde(default)]
        temporal_risk: f64,
        #[serde(default)]
        audio_realism_risk: f64,
    }

    if !response.status().is_success() {
        // Validator surfaces a whitelisted `reason` for `phrase_content_mismatch`
        // only (the user already knows whether they said the assigned phrase,
        // so this category carries no attacker-calibration value); all other
        // rejection categories return an opaque body and `reason` stays
        // `None`. The executor passes the reason through to the SDK +
        // entros.io frontend so the soft-reject retry UX can route on the
        // per-category hint. Other categories stay opaque end-to-end per
        // the 2026-04-29 directed-signal strip.
        const REASON_ALLOWLIST: &[&str] = &["phrase_content_mismatch"];
        
        let err_body = response.json::<ValidatorErrorBody>().await.ok();
        let raw_reason = err_body.as_ref().and_then(|body| body.reason.clone());
        let reason = raw_reason.filter(|r| REASON_ALLOWLIST.contains(&r.as_str()));

        let (biometric_risk, tts_risk, temporal_risk, _audio_realism_risk) = match &err_body {
            Some(body) => (body.biometric_risk, body.tts_risk, body.temporal_risk, body.audio_realism_risk),
            None => (1.0, 0.0, 0.0, 0.0),
        };

        let composite_risk_score = 0.35 * biometric_risk
            + 0.25 * tts_risk
            + 0.15 * temporal_risk
            + 0.15 * automation_risk
            + 0.10 * reputation_risk;

        tracing::info!(
            api_key = %crate::auth::redact::redact_api_key(&api_key),
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            reason = ?reason,
            biometric_risk,
            tts_risk,
            temporal_risk,
            automation_risk,
            reputation_risk,
            composite_risk_score,
            "Feature validation rejected"
        );
        return Err(AppError::ValidationFailed { reason });
    }

    // Validation passed — refund the per-wallet attempt slot so a wallet
    // with all-successful verifications never accumulates against the cap.
    state.wallet_attempts.refund_on_success(&wallet);

    let parsed_body = response.json::<ValidatorSuccessBody>().await.ok();
    let (signed_receipt, commitment_hex, salt_hex, biometric_risk, tts_risk, temporal_risk, _audio_realism_risk) = match parsed_body {
        Some(body) => (body.signed_receipt, body.commitment_hex, body.salt_hex, body.biometric_risk, body.tts_risk, body.temporal_risk, body.audio_realism_risk),
        None => (None, None, None, 0.0, 0.0, 0.0, 0.0),
    };

    let composite_risk_score = 0.35 * biometric_risk
        + 0.25 * tts_risk
        + 0.15 * temporal_risk
        + 0.15 * automation_risk
        + 0.10 * reputation_risk;

    tracing::info!(
        api_key = %crate::auth::redact::redact_api_key(&api_key),
        wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
        biometric_risk,
        tts_risk,
        temporal_risk,
        automation_risk,
        reputation_risk,
        composite_risk_score,
        "Feature validation passed biometric checks"
    );

    // Apply policy threshold: high risk rejects
    if composite_risk_score > 0.75 {
        tracing::warn!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            composite_risk_score,
            "Validation rejected: Composite risk score exceeds threshold"
        );
        return Err(AppError::ValidationFailed { reason: None });
    }

    // Suspicious range graduated friction (Layer C)
    let attempts = state.wallet_attempts.get_attempts(&wallet);
    if composite_risk_score >= 0.45 && attempts <= 1 {
        tracing::warn!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            composite_risk_score,
            attempts,
            "Validation flagged: Composite risk score in suspicious range on first attempt, requiring dynamic captcha"
        );
        return Err(AppError::ValidationFailed {
            reason: Some("captcha_required".to_string()),
        });
    }

    Ok(PaddedJson(ValidateFeaturesResponse {
        valid: true,
        remaining_quota: Some(remaining),
        signed_receipt,
        commitment_hex,
        salt_hex,
        composite_risk_score,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{build_test_state, headers_with_key, random_wallet_id, tracker_with_quota};
    use crate::integrator::wallet_attempts::WalletAttemptTracker;

    fn baseline_request(wallet_id: String) -> ValidateFeaturesRequest {
        ValidateFeaturesRequest {
            features: vec![0.0; 134],
            wallet_id,
            f0_contour: None,
            accel_magnitude: None,
            audio_samples_b64: None,
            audio_sample_rate_hz: None,
            commitment_new_hex: None,
            request_receipt: None,
            client_signals: None,
        }
    }

    #[test]
    fn older_payload_without_client_signals_deserializes() {
        // Backward compatibility: a pre-A1 SDK omits the field entirely.
        let json = serde_json::json!({
            "features": [0.0, 1.0, 2.0],
            "wallet_id": "abc",
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        assert!(req.client_signals.is_none());
    }

    #[test]
    fn client_signals_deserialize_and_tells_round_trip() {
        let json = serde_json::json!({
            "features": [0.0],
            "wallet_id": "abc",
            "client_signals": {
                "v": 1,
                "env": "browser",
                "automation": { "webdriver": true, "tells": ["puppeteer", "selenium"] },
            },
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        let sig = req.client_signals.expect("client_signals present");
        assert_eq!(sig.v, 1);
        assert_eq!(sig.env.as_deref(), Some("browser"));
        let automation = sig.automation.expect("automation group present");
        assert!(automation.webdriver);
        assert_eq!(automation.tells, vec!["puppeteer", "selenium"]);
    }

    #[test]
    fn partial_client_signals_default_missing_subfields() {
        // A forward-compat or trimmed payload: only the automation group with
        // `tells` present. Missing subfields fall back to defaults, not failure.
        let json = serde_json::json!({
            "features": [0.0],
            "wallet_id": "abc",
            "client_signals": { "automation": { "tells": ["phantom"] } },
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        let sig = req.client_signals.unwrap();
        assert_eq!(sig.v, 0);
        assert_eq!(sig.env, None);
        let automation = sig.automation.unwrap();
        assert!(!automation.webdriver);
        assert_eq!(automation.tells, vec!["phantom"]);
    }

    #[test]
    fn unknown_extra_fields_are_ignored() {
        // The request struct has no `deny_unknown_fields`, so a future SDK can
        // add fields without breaking an older executor.
        let json = serde_json::json!({
            "features": [0.0],
            "wallet_id": "abc",
            "some_future_field": { "nested": true },
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        assert!(req.client_signals.is_none());
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
    async fn client_signals_present_do_not_change_the_outcome() {
        // Observe-only contract: a request carrying automation tells (here, the
        // strongest — webdriver true plus framework labels) must reach the same
        // verdict as one without. The handler runs with automation_observe=true
        // (build_test_state default), so this exercises the live observe branch
        // and confirms it is side-effect-free on the decision.
        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);
        let headers = headers_with_key("test-key");
        let mut req = baseline_request(random_wallet_id());
        req.client_signals = Some(ClientSignals {
            v: 1,
            env: Some("browser".into()),
            automation: Some(AutomationSignals {
                webdriver: true,
                tells: vec!["puppeteer".into(), "selenium".into()],
            }),
            capture: None,
        });

        let result = validate_features_handler(State(state), headers, Json(req)).await;

        assert!(
            result.is_ok(),
            "automation tells must not block the verification path (observe-only); got {:?}",
            result.err()
        );
        assert_eq!(
            tracker.get_remaining("test-key"),
            10,
            "observe-only path must not perturb quota accounting"
        );
    }

    #[tokio::test]
    async fn malicious_env_string_does_not_break_the_handler() {
        // `env` is attacker-controlled free text. A newline-laden value (a
        // log-injection attempt) must neither panic nor alter the outcome; the
        // handler Debug-formats `env`, which escapes control chars in the log.
        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);
        let headers = headers_with_key("test-key");
        let mut req = baseline_request(random_wallet_id());
        req.client_signals = Some(ClientSignals {
            v: 1,
            env: Some("browser\n2099-01-01 INFO forged-admin-login".into()),
            automation: Some(AutomationSignals {
                webdriver: true,
                tells: vec!["x\nforged".into()],
            }),
            capture: None,
        });

        let result = validate_features_handler(State(state), headers, Json(req)).await;

        assert!(
            result.is_ok(),
            "malicious env must not break the path: {:?}",
            result.err()
        );
        assert_eq!(tracker.get_remaining("test-key"), 10);
    }

    #[tokio::test]
    async fn wallet_reputation_observe_does_not_change_the_outcome() {
        // The D1 reputation read is detached (fire-and-forget) and must never
        // affect the verdict or quota. build_test_state enables it; the test RPC
        // endpoint is unreachable, so the spawned read fails and logs
        // "unavailable" — the handler outcome is unchanged either way.
        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);
        assert!(
            state.wallet_reputation_observe,
            "observe flag on by default in tests"
        );
        let headers = headers_with_key("test-key");
        let req = baseline_request(random_wallet_id());

        let result = validate_features_handler(State(state), headers, Json(req)).await;

        assert!(
            result.is_ok(),
            "reputation observe must not change outcome: {:?}",
            result.err()
        );
        assert_eq!(tracker.get_remaining("test-key"), 10);
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

    #[test]
    fn client_signals_capture_realism_deserializes() {
        let json = serde_json::json!({
            "features": [0.0],
            "wallet_id": "abc",
            "client_signals": {
                "v": 3,
                "env": "browser",
                "capture": {
                    "virtual_device": true,
                    "flatness": 0.05,
                    "centroid": 1200.5
                }
            }
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        let sig = req.client_signals.expect("client_signals present");
        let cap = sig.capture.expect("capture signals present");
        assert!(cap.virtual_device);
        assert_eq!(cap.flatness, Some(0.05));
        assert_eq!(cap.centroid, Some(1200.5));
    }

    #[test]
    fn wallet_attempts_counter_tracks_increments() {
        let tracker = WalletAttemptTracker::new(5, std::time::Duration::from_secs(3600));
        let wallet = Pubkey::new_unique();
        assert_eq!(tracker.get_attempts(&wallet), 0);
        
        tracker.check_and_record_attempt(&wallet).unwrap();
        assert_eq!(tracker.get_attempts(&wallet), 1);
        
        tracker.check_and_record_attempt(&wallet).unwrap();
        assert_eq!(tracker.get_attempts(&wallet), 2);
        
        tracker.refund_on_success(&wallet);
        assert_eq!(tracker.get_attempts(&wallet), 1);
    }
}
