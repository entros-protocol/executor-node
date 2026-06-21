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
    if state.wallet_reputation_observe {
        if let Ok(permit) = crate::reputation::REPUTATION_RPC_GATE.try_acquire() {
            let client = state.relayer_tx.client();
            let redacted = crate::auth::redact::redact_wallet_id(&req.wallet_id);
            tokio::spawn(async move {
                let _permit = permit; // released when the read completes
                match crate::reputation::fetch_wallet_reputation(&client, &wallet).await {
                    Ok(rep) => tracing::info!(
                        wallet_id = %redacted,
                        sol_lamports = rep.sol_lamports,
                        signature_count = rep.signature_count,
                        oldest_block_time = ?rep.oldest_block_time,
                        "Wallet reputation observed"
                    ),
                    Err(_) => tracing::debug!(
                        wallet_id = %redacted,
                        "Wallet reputation unavailable (observe-only, non-blocking)"
                    ),
                }
            });
        }
    }

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

    let response = match request.send().await {
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

    if !response.status().is_success() {
        // Validator surfaces a whitelisted `reason` for `phrase_content_mismatch`
        // only (the user already knows whether they said the assigned phrase,
        // so this category carries no attacker-calibration value); all other
        // rejection categories return an opaque body and `reason` stays
        // `None`. The executor passes the reason through to the SDK +
        // entros.io frontend so the soft-reject retry UX can route on the
        // per-category hint. Other categories stay opaque end-to-end per
        // the 2026-04-29 directed-signal strip.
        //
        // Defense in depth: even if the validator misbehaves and returns
        // an unwhitelisted reason, this handler re-filters against the same
        // allowlist before forwarding. Locks the contract on both ends so
        // a single misconfiguration can't open a calibration channel.
        // Threat-model note: the validator's wire body length differs by
        // ~35 bytes between reason-present vs reason-absent rejections,
        // but the validator is internal-only (only the executor talks to
        // it on Railway) and the executor's `Padded::new` outbound layer
        // pads every response to a uniform length, so external observers
        // see no length oracle.
        //
        // Note: the per-wallet attempt slot consumed at the top of this
        // handler stays consumed — it's a real failed attempt against the
        // wallet's window budget.
        #[derive(serde::Deserialize)]
        struct ValidatorErrorBody {
            #[serde(default)]
            reason: Option<String>,
        }
        const REASON_ALLOWLIST: &[&str] = &["phrase_content_mismatch"];
        let raw_reason = response
            .json::<ValidatorErrorBody>()
            .await
            .ok()
            .and_then(|body| body.reason);
        let reason = raw_reason.filter(|r| REASON_ALLOWLIST.contains(&r.as_str()));
        tracing::info!(
            api_key = %crate::auth::redact::redact_api_key(&api_key),
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            reason = ?reason,
            "Feature validation rejected"
        );
        return Err(AppError::ValidationFailed { reason });
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
        #[serde(default)]
        commitment_hex: Option<String>,
        #[serde(default)]
        salt_hex: Option<String>,
    }
    // Parse the body once and forward all three receipt artifacts together so
    // they stay coherent — the SDK needs the commitment + salt alongside the
    // receipt to mint and to seed future rotation proofs. Older validators
    // omit all three; parse failure maps every field to `None` and the SDK
    // falls back to the no-binding mint flow.
    let (signed_receipt, commitment_hex, salt_hex) =
        match response.json::<ValidatorSuccessBody>().await {
            Ok(body) => (body.signed_receipt, body.commitment_hex, body.salt_hex),
            Err(_) => (None, None, None),
        };

    tracing::info!(
        api_key = %crate::auth::redact::redact_api_key(&api_key),
        wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
        "Feature validation passed"
    );

    Ok(PaddedJson(ValidateFeaturesResponse {
        valid: true,
        remaining_quota: Some(remaining),
        signed_receipt,
        commitment_hex,
        salt_hex,
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
}
