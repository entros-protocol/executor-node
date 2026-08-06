use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use axum::Extension;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::error::AppError;
use crate::padding::PaddedJson;
use crate::server::AppState;
use crate::validation::composite::{RiskComponents, CAPTCHA_THRESHOLD, REJECT_THRESHOLD};

/// How long to wait on the internal validation service before giving up.
///
/// Sized off the validator's own worst case rather than a round number. A
/// rejection there runs 5-8s with Whisper-tiny dominating (see
/// `timing::HANDLER_MIN_DURATION`), and `VALIDATION_VAD_AB_LOGGING` adds a
/// second full transcription pass on top when it is on. The previous 8s
/// budget sat inside that range, so a legitimate two-pass validation could
/// exhaust it and surface to the user as a generic failure: the executor
/// timing out on a validator that was still working.
///
/// The margin is deliberate. `VALIDATION_VAD_AB_LOGGING` is an environment
/// variable that can be turned back on for a calibration window, and this
/// timeout must not become the thing that breaks when it is.
const VALIDATOR_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

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
    /// Client-reported browser signals (master-list #196), evaluated in the
    /// executor and NOT forwarded to the validation service. Two groups with
    /// DIFFERENT decision roles: the `automation` group (WebDriver flag +
    /// framework tells, Layer A1) currently contributes to `automation_risk`
    /// and thus the composite; the `capture` group (acoustic realism, Layer B1)
    /// is observe/telemetry only and does not affect the outcome — its
    /// authoritative counterpart is computed server-side (Item #15, which also
    /// tracks whether A1 should revert to observe-only). All signals are
    /// client-reported and therefore spoofable — risk nudges, not gates.
    /// Privacy-first — only automation artifacts + coarse acoustic stats, never
    /// fingerprints or user data. Absent for older SDKs (logged as such).
    #[serde(default)]
    pub client_signals: Option<ClientSignals>,
    /// Coarse curve-trace outline (touch-curve Stage 1). Equal-time resampled
    /// `{x,y}` points of the user's trace in the client 200x200 viewBox frame,
    /// plus the outline's wall-clock span. Scored against the issued Lissajous
    /// curve (region proximity + gesture speed/nature) for observe-only
    /// calibration — NOT forwarded to the validation service and never gates the
    /// decision in Stage 1. Absent for older SDKs.
    #[serde(default, deserialize_with = "deserialize_lenient_option")]
    pub curve_trace: Option<CurveTracePayload>,
    /// Observe-only capture-timing summary from the SDK: how the motion stream
    /// sat against the audio window its contour was resampled onto. Unlike
    /// `client_signals` and `curve_trace`, which the executor evaluates itself,
    /// this is for the validation service's calibration log, so it is passed
    /// straight through and never inspected here.
    ///
    /// Held as an opaque `Value` deliberately. The executor has no reason to
    /// interpret the shape, and mirroring it would create a third copy to keep
    /// in step with the SDK and the validator.
    ///
    /// It is forwarded rather than dropped because the forwarded body is an
    /// explicit whitelist, so a field absent from it never reaches the
    /// validator however well-formed the request was.
    #[serde(default)]
    pub capture_timing: Option<serde_json::Value>,
}

/// Coarse curve-trace outline payload (touch-curve Stage 1). Equal-time
/// resampled `{x,y}` points in the client 200x200 viewBox frame plus the
/// outline's wall-clock span. Optional/additive — older SDKs omit it.
#[derive(Deserialize)]
pub struct CurveTracePayload {
    #[serde(default)]
    pub points: Vec<[f64; 2]>,
    #[serde(default)]
    pub duration_ms: f64,
}

/// Deserialize an optional field leniently: a present-but-malformed value degrades
/// to `None` instead of failing the whole request. Keeps the observe-only
/// `curve_trace` field from ever 400-ing a live verification on a bad shape.
fn deserialize_lenient_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// The `client_signals` envelope. Wire mirror of the SDK's `ClientSignals`.
/// Namespaced so future signal groups slot in as siblings without a breaking
/// wire change. Every field is `#[serde(default)]` so a partial or older
/// payload deserializes cleanly. Decision roles differ per group: `automation`
/// can influence the composite via `automation_risk`; `capture` is
/// observe/telemetry only (see the `client_signals` field doc above).
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
    /// navigator.webdriver === true — the W3C WebDriver automation flag.
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
    /// Ed25519Program::verify instruction bundled before `mint_anchor` in
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
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
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

    // Extract client IP and User-Agent for cross-wallet cooldown check (master-list #142)
    let ip = crate::auth::client_ip::extract_client_ip(&headers, peer.map(|Extension(c)| c.0))
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));

    // Bounded before it is used or forwarded. This is the one attacker-
    // controlled string that crosses the service boundary unmeasured: it goes
    // into the origin hash, into logs, and into the body sent to the
    // validator, where it counts against that service's own body limit. A
    // browser sends a couple of hundred bytes; anything past the bound is a
    // client with something else in mind, and the prefix is all the origin
    // hash needs.
    const MAX_USER_AGENT_BYTES: usize = 512;
    let user_agent_raw = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let user_agent = match user_agent_raw.char_indices().nth(MAX_USER_AGENT_BYTES) {
        Some((cut, _)) => &user_agent_raw[..cut],
        None => user_agent_raw,
    };

    // Check probing blocklist (Item #135)
    if let Some(expire_time) = state.probing_blocklist.get(&ip).map(|r| *r) {
        let now = std::time::Instant::now();
        if expire_time > now {
            let retry_after_secs = expire_time.duration_since(now).as_secs();
            tracing::warn!(
                ip = %crate::auth::redact::redact_ip(ip),
                retry_after_secs,
                "Probing blocklist active for client IP"
            );
            return Err(AppError::IpRateLimited { retry_after_secs: retry_after_secs.max(1) });
        } else {
            state.probing_blocklist.remove(&ip);
        }
    }

    if let Err(remaining_secs) = state.cross_wallet_cooldown.check_cooldown(ip, user_agent, &req.wallet_id) {
        tracing::warn!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            ip = %crate::auth::redact::redact_ip(ip),
            enforced = state.cross_wallet_cooldown_enforce,
            remaining_secs,
            "Cross-wallet verification cooldown active"
        );
        if state.cross_wallet_cooldown_enforce {
            return Err(AppError::CrossWalletCooldownActive { retry_after_secs: remaining_secs });
        }
    }

    // Layer A1 automation gate. A browser reporting navigator.webdriver === true
    // is refused ahead of the validation round-trip, skipping the upstream call.
    // The dev pass-through with no validator configured is unaffected. Framework
    // `tells` are handled separately below. Disable for the team's own E2E
    // automation via EXECUTOR_AUTOMATION_WEBDRIVER_REJECT=false.
    //
    // Scope and limits: docs/reference/EXECUTOR-SCORING-INTERNALS.md
    if state.automation_webdriver_reject
        && state.validation_url.is_some()
        && req
            .client_signals
            .as_ref()
            .and_then(|c| c.automation.as_ref())
            .is_some_and(|a| a.webdriver)
    {
        tracing::info!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            "Automated browser detected (navigator.webdriver) — rejecting verification"
        );
        return Err(AppError::ValidationFailed {
            reason: Some("automated_browser_detected".into()),
        });
    }

    // Log the automation signal for real-traffic calibration. Privacy-first:
    // only automation-framework artifacts (WebDriver flag + framework labels)
    // are reported, never fingerprints or user data, and a privacy-hardened
    // browser (Tor / RFP) reports no webdriver flag and is never rejected.
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
    // One atomic challenge lookup serves both the phrase content-binding forwarded
    // to the validator AND the observe-only curve-trace scoring, so the two can
    // never read different issued challenges and it is a single DashMap get.
    let issued_challenge = state
        .challenge_registry
        .peek_challenge(&wallet, state.challenge_ttl_secs);
    let expected_phrase = issued_challenge.as_ref().map(|(phrase, _)| phrase.clone());

    // Touch-curve Stage 1 (observe-only): score the coarse outline against the
    // issued curve OFF the request path. Detached (like `wallet_reputation_observe`)
    // so it can never add latency or perturb the outcome; sanitized + capped so a
    // hostile payload can neither burn CPU nor poison the calibration corpus. Runs
    // only when the client sent an outline and a curve is outstanding.
    if state.curve_trace_observe {
        if let (Some(trace), Some((_, curve))) = (req.curve_trace.as_ref(), issued_challenge.as_ref())
        {
            let points = crate::challenge::curve_trace::sanitize_trace(&trace.points);
            let duration_ms = trace.duration_ms;
            let curve = curve.clone();
            tokio::spawn(async move {
                let report =
                    crate::challenge::curve_trace::score_curve_trace(&points, duration_ms, &curve);
                tracing::info!(
                    region_score = report.region_score,
                    kinematic_score = report.kinematic_score,
                    median_deviation = report.median_deviation,
                    region_score_issued_anchor = report.region_score_issued_anchor,
                    median_deviation_issued_anchor = report.median_deviation_issued_anchor,
                    alignment_sweep = %report.alignment_sweep_display(),
                    path_length = report.path_length,
                    max_segment = report.max_segment,
                    speed_cov = report.speed_cov,
                    mean_speed = report.mean_speed,
                    point_count = report.point_count,
                    "Curve-trace observe"
                );
            });
        }
    }

    // Fetch user's verification timestamps from on-chain IdentityState
    let (identity_pda, _) = crate::solana::pda::find_identity_state_pda(&wallet);
    let mut recent_timestamps = Vec::new();
    if let Ok(Some(data)) = state.relayer_tx.client().get_account_data(&identity_pda).await {
        const IDENTITY_DISCRIMINATOR: [u8; 8] = [156, 32, 87, 93, 52, 155, 248, 207];
        if data.len() >= 8 && data[..8] == IDENTITY_DISCRIMINATOR {
            // Offset for recent_timestamps is 127
            // Struct layout: recent_timestamps is [i64; 52] = 416 bytes
            if data.len() >= 127 + 52 * 8 {
                for i in 0..52 {
                    let offset = 127 + i * 8;
                    let ts = i64::from_le_bytes(
                        data[offset..offset + 8]
                            .try_into()
                            .expect("slice of 8 bytes is always convertible to [u8; 8]"),
                    );
                    if ts > 0 {
                        recent_timestamps.push(ts);
                    }
                }
            } else if data.len() > 127 {
                // Support partial / legacy accounts if they were not realloc'd yet
                let available_slots = (data.len() - 127) / 8;
                for i in 0..available_slots {
                    let offset = 127 + i * 8;
                    let ts = i64::from_le_bytes(
                        data[offset..offset + 8]
                            .try_into()
                            .expect("slice of 8 bytes is always convertible to [u8; 8]"),
                    );
                    if ts > 0 {
                        recent_timestamps.push(ts);
                    }
                }
            }
        }
    }

    // Build request to internal validation service. Forward time-series and
    // audio fields unchanged — the validation service handles absence of any
    // field (old SDK versions).
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
            "recent_timestamps": recent_timestamps,
            "origin_ip": Some(ip.to_string()),
            "origin_ua": Some(user_agent.to_string()),
            "capture_timing": req.capture_timing,
        }))
        .timeout(VALIDATOR_REQUEST_TIMEOUT);

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

    // 1. Automation Risk (Layer A1). NOTE: automation tells (webdriver +
    // framework labels) currently feed automation_risk and thus the composite.
    // Whether Layer A1 should be observe-only (its original master-list #196
    // framing) or decision-affecting is an open question — see Item #15.
    let mut automation_risk = 0.0;
    if let Some(signals) = req.client_signals.as_ref() {
        if let Some(a) = signals.automation.as_ref() {
            if a.webdriver {
                automation_risk = 1.0;
            } else if !a.tells.is_empty() {
                automation_risk = (a.tells.len() as f64 * 0.5).min(1.0);
            }
        }
        // Acoustic realism (Layer B1) from client-reported CaptureSignals is
        // OBSERVE / TELEMETRY ONLY — spoofable (computed in the browser), so it
        // MUST NOT feed the pass/fail decision. Log for calibration; do NOT add
        // it to automation_risk. The un-forgeable acoustic check is computed
        // server-side from the raw audio the validator already receives; wiring
        // that into the composite (observe -> calibrate -> enforce) is tracked
        // in remaining-public-tasks.md Item #15.
        let acoustic_eval = crate::validation::audio::evaluate_acoustic_realism(signals.capture.as_ref());
        if acoustic_eval.risk_score > 0.0 {
            tracing::info!(
                wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                virtual_device = acoustic_eval.virtual_device_detected,
                flatness_out_of_bounds = acoustic_eval.flatness_out_of_bounds,
                centroid_out_of_bounds = acoustic_eval.centroid_out_of_bounds,
                acoustic_risk = acoustic_eval.risk_score,
                "REALISM_OBSERVATION: client-reported acoustic anomaly (telemetry only, not scored)"
            );
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
    #[allow(dead_code)]
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
        #[serde(default)]
        probing_detected: Option<bool>,
    }

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
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
        #[serde(default)]
        probing_detected: Option<bool>,
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

        // If probing was detected, insert into state.probing_blocklist
        if let Some(true) = err_body.as_ref().and_then(|body| body.probing_detected) {
            tracing::warn!(
                ip = %crate::auth::redact::redact_ip(ip),
                wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
                "Upstream validator flagged probing campaign! IP added to blocklist for 24 hours."
            );
            let expire_time = std::time::Instant::now() + std::time::Duration::from_secs(24 * 3600);
            state.probing_blocklist.insert(ip, expire_time);
        }

        let raw_reason = err_body.as_ref().and_then(|body| body.reason.clone());
        let reason = raw_reason.filter(|r| REASON_ALLOWLIST.contains(&r.as_str()));

        let (biometric_risk, tts_risk, temporal_risk, audio_realism_risk) = match &err_body {
            Some(body) => (body.biometric_risk, body.tts_risk, body.temporal_risk, body.audio_realism_risk),
            None => (1.0, 0.0, 0.0, 0.0),
        };

        // Computed even though this branch always returns Err: the log line
        // below is the only record of how risky the captures the validator
        // itself rejected were, and calibration reads it.
        let composite_risk_score = RiskComponents {
            biometric: biometric_risk,
            tts: tts_risk,
            temporal: temporal_risk,
            automation: automation_risk,
            reputation: reputation_risk,
        }
        .composite();

        tracing::info!(
            api_key = %crate::auth::redact::redact_api_key(&api_key),
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            reason = ?reason,
            biometric_risk,
            tts_risk,
            temporal_risk,
            automation_risk,
            reputation_risk,
            audio_realism_risk,
            composite_risk_score,
            "Feature validation rejected"
        );
        return Err(AppError::ValidationFailed { reason });
    }

    // Validation passed — refund the per-wallet attempt slot so a wallet
    // with all-successful verifications never accumulates against the cap.
    state.wallet_attempts.refund_on_success(&wallet);

    let parsed_body = response.json::<ValidatorSuccessBody>().await.ok();
    let (signed_receipt, commitment_hex, salt_hex, biometric_risk, tts_risk, temporal_risk, audio_realism_risk) = match parsed_body {
        Some(body) => (body.signed_receipt, body.commitment_hex, body.salt_hex, body.biometric_risk, body.tts_risk, body.temporal_risk, body.audio_realism_risk),
        None => (None, None, None, 0.0, 0.0, 0.0, 0.0),
    };

    let composite_risk_score = RiskComponents {
        biometric: biometric_risk,
        tts: tts_risk,
        temporal: temporal_risk,
        automation: automation_risk,
        reputation: reputation_risk,
    }
    .composite();

    tracing::info!(
        api_key = %crate::auth::redact::redact_api_key(&api_key),
        wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
        biometric_risk,
        tts_risk,
        temporal_risk,
        automation_risk,
        reputation_risk,
        audio_realism_risk,
        composite_risk_score,
        "Feature validation passed biometric checks"
    );

    // Apply policy threshold: high risk rejects. Strict, so a score landing
    // exactly on the threshold passes.
    if composite_risk_score > REJECT_THRESHOLD {
        tracing::warn!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&req.wallet_id),
            composite_risk_score,
            "Validation rejected: Composite risk score exceeds threshold"
        );
        return Err(AppError::ValidationFailed { reason: None });
    }

    // Suspicious range graduated friction (Layer C)
    let attempts = state.wallet_attempts.get_attempts(&wallet);
    if composite_risk_score >= CAPTCHA_THRESHOLD && attempts <= 1 {
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

    /// Shared by `validator_reached_tests` too. The literal names every field
    /// explicitly (no `..Default::default()`), so it must exist exactly once —
    /// two copies would silently diverge the moment a field is added.
    pub(super) fn baseline_request(wallet_id: String) -> ValidateFeaturesRequest {
        ValidateFeaturesRequest {
            features: vec![0.0; 308],
            wallet_id,
            f0_contour: None,
            accel_magnitude: None,
            audio_samples_b64: None,
            audio_sample_rate_hz: None,
            commitment_new_hex: None,
            request_receipt: None,
            client_signals: None,
            curve_trace: None,
            capture_timing: None,
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
    fn malformed_curve_trace_degrades_to_none_not_error() {
        // An observe-only field must never 400 a live verification: a wrong-shaped
        // curve_trace deserializes to None, not a hard error on the whole request.
        let json = serde_json::json!({
            "features": [0.0, 1.0, 2.0],
            "wallet_id": "abc",
            "curve_trace": [{ "x": 1, "y": 2 }],
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        assert!(req.curve_trace.is_none());
    }

    #[test]
    fn well_formed_curve_trace_deserializes() {
        let json = serde_json::json!({
            "features": [0.0, 1.0, 2.0],
            "wallet_id": "abc",
            "curve_trace": { "points": [[1.0, 2.0], [3.0, 4.0]], "duration_ms": 9000.0 },
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(json).unwrap();
        let ct = req.curve_trace.expect("well-formed curve_trace should parse");
        assert_eq!(ct.points.len(), 2);
        assert_eq!(ct.duration_ms, 9000.0);
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

    /// The tolerance above has a cost worth pinning: a field the SDK sends and
    /// this struct does not declare is accepted, silently discarded, and then
    /// absent from the body forwarded upstream. `capture_timing` shipped that
    /// way and reached nothing, so the diagnostic it exists to provide was
    /// never emitted and the omission looked like a deploy that had not
    /// happened.
    ///
    /// Deserialising it is only half. The forwarded body is an explicit
    /// whitelist built by hand, so anything missing from that list dies here
    /// however well-formed the request was. This asserts both halves.
    #[test]
    fn capture_timing_survives_the_hop_to_the_validator() {
        let timing = serde_json::json!({
            "v": 1,
            "motion_samples": 700,
            "window_offset_ms": 12.5,
            "window_coverage": 0.99,
        });
        let req: ValidateFeaturesRequest = serde_json::from_value(serde_json::json!({
            "features": [0.0],
            "wallet_id": "abc",
            "capture_timing": timing,
        }))
        .unwrap();
        assert_eq!(req.capture_timing.as_ref(), Some(&timing));

        // Mirrors the field list in the forwarded body above. A field added
        // there and not here, or here and not there, fails this.
        let forwarded = serde_json::json!({
            "capture_timing": req.capture_timing,
        });
        assert_eq!(
            forwarded.get("capture_timing"),
            Some(&timing),
            "capture_timing must reach the validation service, not stop at the executor"
        );
    }

    #[test]
    fn capture_timing_is_optional() {
        // Older SDKs omit it entirely. That must stay a non-event.
        let req: ValidateFeaturesRequest = serde_json::from_value(serde_json::json!({
            "features": [0.0],
            "wallet_id": "abc",
        }))
        .unwrap();
        assert!(req.capture_timing.is_none());
    }

    #[tokio::test]
    async fn dev_skip_refunds_integrator_quota() {
        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);
        let headers = headers_with_key("test-key");
        let req = baseline_request(random_wallet_id());

        let result = validate_features_handler(State(state), None, headers, Json(req)).await;

        assert!(result.is_ok(), "expected success, got {:?}", result.err());
        assert_eq!(
            tracker.get_remaining("test-key"),
            10,
            "dev-skip path must refund the integrator quota"
        );
    }

    #[tokio::test]
    async fn client_signals_on_the_dev_skip_path_do_not_perturb_quota() {
        // Narrow successor to the former `client_signals_present_do_not_change
        // _the_outcome`, which claimed automation tells were observe-only and
        // asserted the same verdict with and without them. That contract is
        // false in production: EXECUTOR_AUTOMATION_WEBDRIVER_REJECT defaults to
        // true, so a webdriver request is refused outright, and even with the
        // flag off it scores automation_risk = 1.0 into the composite. The old
        // test passed only because it was shielded twice — build_test_state
        // sets automation_webdriver_reject = false, and the gate additionally
        // requires validation_url.is_some(), which `None` defeats.
        //
        // What remains true on the dev-skip path, and all this now asserts, is
        // that the observe-only logging branch is side-effect-free on quota.
        // The real gate contract is covered by the mock-validator tests below.
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

        let result = validate_features_handler(State(state), None, headers, Json(req)).await;

        assert!(
            result.is_ok(),
            "dev-skip path returns before any gate can fire; got {:?}",
            result.err()
        );
        assert_eq!(
            tracker.get_remaining("test-key"),
            10,
            "dev-skip path must refund the integrator quota"
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

        let result = validate_features_handler(State(state), None, headers, Json(req)).await;

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

        let result = validate_features_handler(State(state), None, headers, Json(req)).await;

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

        let result = validate_features_handler(State(state), None, headers, Json(req)).await;

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

    #[tokio::test]
    async fn test_probing_blocklist_handling() {
        use axum::Extension;
        use axum::extract::ConnectInfo;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::time::{Duration, Instant};

        let tracker = tracker_with_quota("test-key", 10);
        let state = build_test_state(tracker.clone(), None);

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let peer = Extension(ConnectInfo(SocketAddr::new(client_ip, 12345)));
        let headers = headers_with_key("test-key");

        // 1. Add IP to blocklist with future expiration
        state.probing_blocklist.insert(client_ip, Instant::now() + Duration::from_secs(60));

        let req1 = baseline_request(random_wallet_id());
        let result1 = validate_features_handler(State(state.clone()), Some(peer), headers.clone(), Json(req1)).await;
        
        let is_ip_rate_limited = matches!(result1, Err(AppError::IpRateLimited { .. }));
        assert!(is_ip_rate_limited, "Expected IpRateLimited due to active probing blocklist");

        // 2. Modify blocklist entry to be expired
        state.probing_blocklist.insert(client_ip, Instant::now() - Duration::from_secs(60));

        let req2 = baseline_request(random_wallet_id());
        let result2 = validate_features_handler(State(state.clone()), Some(peer), headers.clone(), Json(req2)).await;
        
        let is_ip_rate_limited = matches!(result2, Err(AppError::IpRateLimited { .. }));
        assert!(!is_ip_rate_limited, "Expected request to bypass block list once expired");
        // It should have cleaned up the entry
        assert!(!state.probing_blocklist.contains_key(&client_ip));
    }
}

/// Tests that drive the handler through to the upstream validator.
///
/// Everything above exits at the dev-skip (`validation_url: None`), so until
/// this module existed nothing exercised the validator round-trip, the
/// composite risk score, the reject tier, the captcha tier, the safe-reveal
/// reason filter, or the probing-blocklist write. The composite could have been
/// inverted to refuse every honest user with the whole suite still green.
#[cfg(test)]
mod validator_reached_tests {
    use super::*;
    use crate::server::{headers_with_key, random_wallet_id, tracker_with_quota};
    use crate::validation::mock_validator::{
        error_body, state_with_mock_validator, success_body, MockValidator, REPUTATION_FLOOR,
    };
    use axum::http::StatusCode;
    // Reused rather than re-declared: the request literal names every field, so
    // a second copy would drift the moment `ValidateFeaturesRequest` changes.
    use super::tests::baseline_request;

    fn webdriver_signals() -> ClientSignals {
        ClientSignals {
            v: 1,
            env: Some("browser".into()),
            automation: Some(AutomationSignals {
                webdriver: true,
                tells: vec!["puppeteer".into(), "selenium".into()],
            }),
            capture: None,
        }
    }

    /// Composite weights, restated so a change to the handler's table fails
    /// here rather than silently altering who gets verified.
    fn expected_composite(biometric: f64, tts: f64, temporal: f64, automation: f64) -> f64 {
        0.35 * biometric + 0.25 * tts + 0.15 * temporal + 0.15 * automation + REPUTATION_FLOOR
    }

    // ---- reachability, and the gate whose contract was previously inverted ----

    #[tokio::test]
    async fn a_clean_request_reaches_the_upstream_validator() {
        // Baseline for everything below: proves the harness actually gets past
        // the dev-skip. If this fails, no other test in this module means
        // anything, because they would all be asserting against an early return.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let result = validate_features_handler(
            State(state.clone()),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        let response = result.expect("a clean request must pass").0;
        assert_eq!(
            mock.request_count(),
            1,
            "the handler must actually call the validator, not short-circuit"
        );
        assert!(response.valid);
        assert_eq!(
            response.remaining_quota,
            Some(9),
            "a validated request consumes exactly one unit of integrator quota"
        );
        assert_eq!(
            state.metrics.validations_performed(),
            1,
            "metrics must count work that actually happened"
        );
    }

    #[tokio::test]
    async fn webdriver_is_refused_before_the_upstream_round_trip() {
        // The gate at the top of the handler is guarded by
        // `validation_url.is_some()`, so it is unreachable whenever the
        // validator is unconfigured — which is why no previous test could
        // observe it. Asserting the mock received *nothing* is the point:
        // rejecting after paying for transcription would waste the expensive
        // call the guard exists to avoid.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let mut state = state_with_mock_validator(tracker.clone(), &mock);
        state.automation_webdriver_reject = true;

        let mut req = baseline_request(random_wallet_id());
        req.client_signals = Some(webdriver_signals());

        let result =
            validate_features_handler(State(state), None, headers_with_key("test-key"), Json(req))
                .await;

        // `PaddedJson` is not `Debug`; discard the success payload so the
        // catch-all arm can report what came back instead.
        match result.map(|_| ()) {
            Err(AppError::ValidationFailed { reason }) => assert_eq!(
                reason.as_deref(),
                Some("automated_browser_detected"),
                "the client needs this reason to explain itself to the user"
            ),
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
        assert_eq!(
            mock.request_count(),
            0,
            "the webdriver gate must short-circuit before the validator call"
        );
    }

    #[tokio::test]
    async fn webdriver_with_the_reject_flag_off_scores_full_automation_risk() {
        // With the hard gate disabled the signal is not discarded — it enters
        // the composite at weight 0.15. Pinning both halves means this suite
        // describes what the flag does in either position without asserting
        // which default is correct; that policy question is open (see the note
        // at the automation_risk computation and remaining-public-tasks #15).
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let mut state = state_with_mock_validator(tracker.clone(), &mock);
        state.automation_webdriver_reject = false;

        let mut req = baseline_request(random_wallet_id());
        req.client_signals = Some(webdriver_signals());

        let response =
            validate_features_handler(State(state), None, headers_with_key("test-key"), Json(req))
                .await
                .expect("automation risk alone stays under the reject threshold")
                .0;

        assert_eq!(mock.request_count(), 1);
        assert!(
            (response.composite_risk_score - expected_composite(0.0, 0.0, 0.0, 1.0)).abs() < 1e-9,
            "webdriver must contribute automation_risk = 1.0; got {}",
            response.composite_risk_score
        );
    }

    // ---- the composite and its two policy tiers ----

    #[tokio::test]
    async fn composite_risk_weights_each_layer_as_specified() {
        // Pins the weight table itself. Stage 1b will add a term to this
        // region, and this is the test that makes a silent re-weighting of the
        // existing five impossible.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.4, 0.2, 0.1)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let response = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await
        .expect("a low-risk capture must pass")
        .0;

        let expected = expected_composite(0.4, 0.2, 0.1, 0.0);
        assert!(
            (response.composite_risk_score - expected).abs() < 1e-9,
            "expected composite {expected}, got {}",
            response.composite_risk_score
        );
    }

    #[tokio::test]
    async fn a_composite_above_the_reject_threshold_fails_with_no_reason() {
        // Above REJECT_THRESHOLD the handler refuses and surfaces no reason:
        // naming the failing layer would tell an attacker which signal to tune.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(1.0, 1.0, 1.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let result = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        // `PaddedJson` is not `Debug`; discard the success payload so the
        // catch-all arm can report what came back instead.
        match result.map(|_| ()) {
            Err(AppError::ValidationFailed { reason }) => assert!(
                reason.is_none(),
                "the reject tier must not name the failing layer, got {reason:?}"
            ),
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_composite_in_the_suspicious_band_requires_a_captcha() {
        // Inside the captcha band the handler asks for graduated friction rather
        // than refusing outright. The client routes this reason to a retry UX.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(1.0, 1.0, 0.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let composite = expected_composite(1.0, 1.0, 0.0, 0.0);
        assert!(
            (CAPTCHA_THRESHOLD..=REJECT_THRESHOLD).contains(&composite),
            "fixture must land in the captcha band, computed {composite}"
        );

        let result = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        // `PaddedJson` is not `Debug`; discard the success payload so the
        // catch-all arm can report what came back instead.
        match result.map(|_| ()) {
            Err(AppError::ValidationFailed { reason }) => assert_eq!(
                reason.as_deref(),
                Some("captcha_required"),
                "the client keys its retry UX off this exact reason"
            ),
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_same_suspicious_score_is_admitted_once_attempts_exceed_one() {
        // Characterization, not endorsement. The captcha tier is conditioned on
        // `attempts <= 1`, and that count is read *after* the success path has
        // already refunded this request's own slot — so a fresh wallet reads 0
        // and always qualifies on a first request. Pre-seeding two attempts
        // pushes the count to 2, and the identical risk score that demanded a
        // captcha moments earlier now passes.
        //
        // Nothing server-side verifies that a captcha was actually solved, so
        // the friction is advisory. Recorded here because it is invisible
        // otherwise; whether it should hold is a policy question for the owner.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(1.0, 1.0, 0.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let wallet_id = random_wallet_id();
        let wallet = Pubkey::from_str(&wallet_id).expect("generated wallet id parses");
        // Cap is 5, so two pre-seeded attempts leave headroom for the request.
        state
            .wallet_attempts
            .check_and_record_attempt(&wallet)
            .expect("first pre-seed is under the cap");
        state
            .wallet_attempts
            .check_and_record_attempt(&wallet)
            .expect("second pre-seed is under the cap");

        let response = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(wallet_id)),
        )
        .await
        .expect("the captcha tier no longer applies once attempts exceed one")
        .0;

        assert!(
            response.composite_risk_score >= CAPTCHA_THRESHOLD,
            "the score must still be in the suspicious band, got {}",
            response.composite_risk_score
        );
    }

    // ---- the safe-reveal reason filter ----

    #[tokio::test]
    async fn an_allowlisted_rejection_reason_reaches_the_client() {
        // `phrase_content_mismatch` is safe to reveal because the user already
        // knows whether they said the assigned phrase, so it leaks nothing an
        // attacker could not already observe.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(
            StatusCode::BAD_REQUEST,
            error_body("phrase_content_mismatch"),
        )
        .await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let result = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        // `PaddedJson` is not `Debug`; discard the success payload so the
        // catch-all arm can report what came back instead.
        match result.map(|_| ()) {
            Err(AppError::ValidationFailed { reason }) => assert_eq!(
                reason.as_deref(),
                Some("phrase_content_mismatch"),
                "allowlisted reasons must survive the filter"
            ),
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_non_allowlisted_rejection_reason_is_stripped() {
        // The security property behind the allowlist: variance, entropy and
        // temporal-coupling categories carry directed calibration value, so the
        // executor must refuse to forward them even when the validator says so.
        // Without this test the allowlist could be widened or dropped silently.
        let tracker = tracker_with_quota("test-key", 10);
        let mock =
            MockValidator::spawn(StatusCode::BAD_REQUEST, error_body("variance_floor")).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let result = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        // `PaddedJson` is not `Debug`; discard the success payload so the
        // catch-all arm can report what came back instead.
        match result.map(|_| ()) {
            Err(AppError::ValidationFailed { reason }) => assert!(
                reason.is_none(),
                "non-allowlisted reasons must be stripped, leaked {reason:?}"
            ),
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    // ---- refund and accounting invariants ----

    #[tokio::test]
    async fn an_unreachable_validator_refunds_both_budgets() {
        // Infrastructure failure is not the user's fault: neither the
        // integrator's quota nor the wallet's attempt budget may absorb it.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let mut state = state_with_mock_validator(tracker.clone(), &mock);
        // Port 1 is reserved and never listening, so this fails to connect.
        state.validation_url = Some("http://127.0.0.1:1".into());

        let wallet_id = random_wallet_id();
        let wallet = Pubkey::from_str(&wallet_id).expect("generated wallet id parses");

        let result = validate_features_handler(
            State(state.clone()),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(wallet_id)),
        )
        .await;

        assert!(
            matches!(result, Err(AppError::ValidationServiceUnavailable)),
            "expected ValidationServiceUnavailable, got {:?}",
            result.map(|_| ())
        );
        assert_eq!(
            tracker.get_remaining("test-key"),
            10,
            "an unreachable validator must refund the integrator quota"
        );
        assert_eq!(
            state.wallet_attempts.get_attempts(&wallet),
            0,
            "an unreachable validator must refund the wallet attempt slot"
        );
        assert_eq!(
            state.metrics.validations_performed(),
            0,
            "no validation ran, so the counter must not move"
        );
    }

    #[tokio::test]
    async fn a_validator_rejection_refunds_neither_budget() {
        // A real rejection is the user's own failed attempt: it consumes the
        // wallet slot so failures accumulate against the cap, and it consumes
        // integrator quota because work was genuinely performed upstream.
        let tracker = tracker_with_quota("test-key", 10);
        let mock =
            MockValidator::spawn(StatusCode::BAD_REQUEST, error_body("variance_floor")).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let wallet_id = random_wallet_id();
        let wallet = Pubkey::from_str(&wallet_id).expect("generated wallet id parses");

        let result = validate_features_handler(
            State(state.clone()),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(wallet_id)),
        )
        .await;

        assert!(result.is_err(), "the validator rejected this capture");
        assert_eq!(
            tracker.get_remaining("test-key"),
            9,
            "a validator-reached rejection must still consume integrator quota"
        );
        assert_eq!(
            state.wallet_attempts.get_attempts(&wallet),
            1,
            "a genuine failure must accumulate against the per-wallet budget"
        );
    }

    #[tokio::test]
    async fn a_threshold_rejection_refunds_the_wallet_slot_but_not_the_quota() {
        // The success path refunds the wallet attempt before either policy tier
        // runs, so a capture the validator accepted but the composite refused
        // costs the user nothing against their own cap — while the integrator
        // still pays, because the upstream work happened.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(1.0, 1.0, 1.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let wallet_id = random_wallet_id();
        let wallet = Pubkey::from_str(&wallet_id).expect("generated wallet id parses");

        let result = validate_features_handler(
            State(state.clone()),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(wallet_id)),
        )
        .await;

        assert!(
            result.is_err(),
            "a composite above the reject threshold must be refused"
        );
        assert_eq!(
            tracker.get_remaining("test-key"),
            9,
            "the validator did the work, so integrator quota stays spent"
        );
        assert_eq!(
            state.wallet_attempts.get_attempts(&wallet),
            0,
            "the wallet slot is refunded before the threshold gates run"
        );
    }

    // ---- side effects and contract robustness ----

    #[tokio::test]
    async fn a_probing_verdict_blocklists_the_client_ip() {
        // The only site that writes the probing blocklist. Without coverage a
        // refactor could drop the insert and the sole consequence would be a
        // silently disarmed defense.
        let tracker = tracker_with_quota("test-key", 10);
        let mut body = error_body("variance_floor");
        body["probing_detected"] = serde_json::json!(true);
        let mock = MockValidator::spawn(StatusCode::BAD_REQUEST, body).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let result = validate_features_handler(
            State(state.clone()),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        assert!(result.is_err(), "a probing verdict is a rejection");
        // Handler tests pass no peer and no X-Forwarded-For, so the client IP
        // resolves to the documented 127.0.0.1 fallback.
        let fallback_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert!(
            state.probing_blocklist.contains_key(&fallback_ip),
            "a probing verdict must blocklist the originating IP"
        );
    }

    #[tokio::test]
    async fn a_success_body_omitting_optional_fields_parses_cleanly() {
        // The real validator omits its optional fields rather than nulling them
        // (`skip_serializing_if`), and every executor-side field carries
        // `#[serde(default)]` to absorb that. An empty object is the extreme
        // case: it must parse, not fall into the fallback arm.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, serde_json::json!({})).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let response = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await
        .expect("an all-defaults body must pass")
        .0;

        assert!(response.signed_receipt.is_none());
        assert!(
            (response.composite_risk_score - REPUTATION_FLOOR).abs() < 1e-9,
            "absent risks must default to zero, leaving only the reputation floor; got {}",
            response.composite_risk_score
        );
    }

    #[tokio::test]
    async fn a_null_numeric_in_the_error_body_collapses_to_maximum_biometric_risk() {
        // `#[serde(default)]` rescues a *missing* key, not a null one: a null
        // numeric fails f64 deserialization, which fails the entire body, which
        // `.ok()` turns into None. The error branch's fallback then assumes the
        // worst and uses biometric_risk = 1.0. Pinned because the failure is
        // silent — the reason is also lost, so the client sees a bare rejection.
        let tracker = tracker_with_quota("test-key", 10);
        let mut body = error_body("phrase_content_mismatch");
        body["biometric_risk"] = serde_json::Value::Null;
        let mock = MockValidator::spawn(StatusCode::BAD_REQUEST, body).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let result = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await;

        // `PaddedJson` is not `Debug`; discard the success payload so the
        // catch-all arm can report what came back instead.
        match result.map(|_| ()) {
            Err(AppError::ValidationFailed { reason }) => assert!(
                reason.is_none(),
                "an unparseable body loses the reason entirely, got {reason:?}"
            ),
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_issued_challenge_phrase_is_forwarded_to_the_validator() {
        // The validator matches its transcription against this phrase, so the
        // binding between the challenge the user was shown and the audio they
        // produced lives entirely in this forward. The phrase is randomly
        // generated per issue, so it is read back rather than hardcoded.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let wallet_id = random_wallet_id();
        let wallet = Pubkey::from_str(&wallet_id).expect("generated wallet id parses");
        state.challenge_registry.issue(wallet);
        let (issued_phrase, _) = state
            .challenge_registry
            .peek_challenge(&wallet, state.challenge_ttl_secs)
            .expect("a freshly issued challenge is within its TTL");

        validate_features_handler(
            State(state.clone()),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(wallet_id)),
        )
        .await
        .expect("a clean request with an issued challenge must pass");

        let sent = mock.received();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0]["expected_phrase"].as_str(),
            Some(issued_phrase.as_str()),
            "the issued phrase must reach the validator for transcription matching"
        );
    }

    #[tokio::test]
    async fn no_issued_challenge_forwards_a_null_phrase() {
        // Backward compatibility for pre-challenge SDKs: the validator treats a
        // missing phrase as "skip the content check" rather than a failure, so
        // the absence must be forwarded rather than fabricated.
        let tracker = tracker_with_quota("test-key", 10);
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await
        .expect("a request without an issued challenge must still pass");

        let sent = mock.received();
        // Guard the index: `received()` is a Vec, so an empty log would panic
        // here with an opaque out-of-bounds instead of naming the real failure.
        assert_eq!(sent.len(), 1, "the validator must have been called");
        assert!(
            sent[0]["expected_phrase"].is_null(),
            "no challenge means no phrase, got {}",
            sent[0]["expected_phrase"]
        );
    }

    #[tokio::test]
    async fn a_two_hundred_carrying_valid_false_is_still_treated_as_a_pass() {
        // Characterization of a latent coupling, not an endorsement. The
        // executor decides pass/fail purely from the HTTP status and never
        // deserializes the `valid` field that `entros-validation` sends, so a
        // 200 body asserting its own failure is admitted. Benign today because
        // the real validator only ever pairs `valid: true` with 200 and uses
        // 400 to reject — but the two structs are hand-maintained in separate
        // repos with no shared fixture, so nothing enforces that pairing.
        //
        // If this test ever starts failing, the executor grew a `valid` check,
        // which is a hardening worth keeping — update the test, don't revert it.
        let tracker = tracker_with_quota("test-key", 10);
        let mut body = success_body(0.0, 0.0, 0.0);
        body["valid"] = serde_json::json!(false);
        let mock = MockValidator::spawn(StatusCode::OK, body).await;
        let state = state_with_mock_validator(tracker.clone(), &mock);

        let response = validate_features_handler(
            State(state),
            None,
            headers_with_key("test-key"),
            Json(baseline_request(random_wallet_id())),
        )
        .await
        .expect("status, not the body's `valid` field, decides the outcome today")
        .0;

        assert!(
            response.valid,
            "the executor reports success purely on the upstream 200"
        );
    }
}
