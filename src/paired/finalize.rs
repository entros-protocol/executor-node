//! `POST /validate-session`: the one timed request of a paired session.
//!
//! Admission matches `/validate-features`: the probing block, the cross-wallet cooldown, the
//! WebDriver refusal, the wallet attempt cap and integrator quota all apply, and the 4-second
//! floor wraps the route. It never touches the single-capture challenge registry, because the
//! paired session is the challenge.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Extension;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

use super::{invalid_request, PairedJson, SessionSlot};
use crate::error::AppError;
use crate::padding::PaddedJson;
use crate::server::AppState;
use crate::validation::composite::RiskComponents;
use crate::validation::handler::{
    admit_attempt, automation_risk, check_cross_wallet_cooldown, check_probing_block,
    identity_intent, observe_reputation, refund_infrastructure_failure, reputation_risk,
    request_origin, score_success, screen_client_signals, ClientSignals, PreForwardBudgetGuard,
    SignedReceiptDto, ValidatorErrorBody, ValidatorSuccessBody, FEATURE_VECTOR_WIDTH,
};

/// Paired sessions run under this projection only.
const PAIRED_PROJECTION_VERSION: u16 = 1;

/// Rounds in a paired session.
const ROUNDS: usize = 3;
/// The longest segment the protocol allows: twelve seconds of 16 kHz PCM16, in padded base64.
const MAX_SEGMENT_AUDIO_B64: usize = (192_000 * 2usize).div_ceil(3) * 4;
/// The longest coarse path: a three-byte header and 64 four-byte points, in hex.
const MAX_COARSE_PATH_HEX: usize = (3 + 64 * 4) * 2;
/// A 10 ms hop over the longest session is 3,600 frames.
const MAX_CONTOUR_FRAMES: usize = 4_096;
/// Integrity tokens are a few kilobytes.
const MAX_ATTESTATION_TOKEN: usize = 16 * 1_024;

/// A paired finalize decodes up to 36 seconds of audio and runs the feature pipeline. The
/// validator bounds its own work well inside this.
const PAIRED_VALIDATOR_TIMEOUT: Duration = Duration::from_secs(30);

/// Upstream finalize responses carry a receipt and risk scores.
const FINALIZE_RESPONSE_BYTES: usize = 16 * 1_024;

/// The highest assurance tier a receipt can carry.
const MAX_ASSURANCE_TIER: u8 = 2;

/// Verdict reasons a paired finalize may carry back. Each names a content rule the person can
/// act on, and none carries a detection signal.
const PAIRED_VERDICT_REASONS: &[&str] = &["phrase_content_mismatch", "trace_incomplete"];

/// Protocol reasons a paired finalize may carry back. Each names a session rule, and none
/// carries a detection signal.
const PAIRED_PROTOCOL_REASONS: &[&str] = &[
    "session_unknown",
    "session_expired",
    "session_superseded",
    "subject_mismatch",
    "session_not_ready",
    "finalize_in_progress",
    "session_consumed",
    "final_digest_mismatch",
    "evidence_digest_mismatch",
    "evidence_length_mismatch",
    "audio_format_invalid",
    "projection_not_supported",
    "invalid_request",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentPayload {
    round_index: u32,
    audio_b64: String,
    coarse_path_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationPayload {
    platform: String,
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateSessionRequest {
    capture_protocol: String,
    wallet_id: String,
    projection_version: u16,
    session_id: String,
    final_digest: String,
    segments: Vec<SegmentPayload>,
    features: Vec<f64>,
    #[serde(default)]
    f0_contour: Option<Vec<f64>>,
    #[serde(default)]
    accel_magnitude: Option<Vec<f64>>,
    #[serde(default)]
    capture_timing: Option<serde_json::Value>,
    #[serde(default)]
    client_signals: Option<ClientSignals>,
    #[serde(default)]
    baseline_reset: bool,
    #[serde(default)]
    attestation: Option<AttestationPayload>,
}

impl ValidateSessionRequest {
    /// Every bound the validator will enforce that the executor can check without its state, so
    /// a malformed session spends no attempt and never crosses to the validator.
    fn within_bounds(&self) -> bool {
        let contour_ok = |contour: &Option<Vec<f64>>| {
            contour
                .as_ref()
                .is_none_or(|frames| frames.len() <= MAX_CONTOUR_FRAMES)
        };
        self.capture_protocol == "paired"
            && self.session_id.len() == 32
            && self.final_digest.len() == 64
            && self.features.len() == FEATURE_VECTOR_WIDTH
            && self.segments.len() == ROUNDS
            && self.segments.iter().all(|segment| {
                segment.audio_b64.len() <= MAX_SEGMENT_AUDIO_B64
                    && segment.coarse_path_hex.len() <= MAX_COARSE_PATH_HEX
            })
            && contour_ok(&self.f0_contour)
            && contour_ok(&self.accel_magnitude)
            && self.attestation.as_ref().is_none_or(|attestation| {
                attestation.platform.len() <= 32 && attestation.token.len() <= MAX_ATTESTATION_TOKEN
            })
    }
}

#[derive(Debug, Serialize)]
pub struct ValidateSessionResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_quota: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_receipt: Option<SignedReceiptDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_hex: Option<String>,
    /// 0 open, 1 bound, 2 attested. The receipt signs the same value.
    pub assurance_tier: u8,
}

#[derive(Deserialize)]
struct PairedSuccessExtras {
    #[serde(default)]
    assurance_tier: u8,
}

#[derive(Deserialize)]
struct UpstreamReason {
    #[serde(default)]
    reason: Option<String>,
}

/// The body the validator receives. An explicit field list, so a client field can never reach
/// the validator by accident, and borrowed, so the segments are never copied.
#[derive(Serialize)]
struct ValidatorSessionBody<'a> {
    capture_protocol: &'a str,
    wallet_id: &'a str,
    projection_version: u16,
    session_id: &'a str,
    final_digest: &'a str,
    segments: &'a [SegmentPayload],
    features: &'a [f64],
    f0_contour: Option<&'a [f64]>,
    accel_magnitude: Option<&'a [f64]>,
    capture_timing: Option<&'a serde_json::Value>,
    receipt_purpose: Option<&'static str>,
    recent_timestamps: &'a [i64],
    origin_ip: &'a str,
    origin_ua: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation: Option<&'a AttestationPayload>,
}

impl<'a> ValidatorSessionBody<'a> {
    fn new(
        request: &'a ValidateSessionRequest,
        receipt_purpose: Option<&'static str>,
        recent_timestamps: &'a [i64],
        origin_ip: &'a str,
        origin_ua: &'a str,
    ) -> Self {
        Self {
            capture_protocol: &request.capture_protocol,
            wallet_id: &request.wallet_id,
            projection_version: request.projection_version,
            session_id: &request.session_id,
            final_digest: &request.final_digest,
            segments: &request.segments,
            features: &request.features,
            f0_contour: request.f0_contour.as_deref(),
            accel_magnitude: request.accel_magnitude.as_deref(),
            capture_timing: request.capture_timing.as_ref(),
            receipt_purpose,
            recent_timestamps,
            origin_ip,
            origin_ua,
            attestation: request.attestation.as_ref(),
        }
    }
}

pub async fn validate_session_handler(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    // Held until this handler returns, so the timing floor that follows holds no slot.
    _slot: Option<Extension<SessionSlot>>,
    headers: HeaderMap,
    PairedJson(request): PairedJson<ValidateSessionRequest>,
) -> Result<PaddedJson<ValidateSessionResponse>, AppError> {
    let api_key = headers
        .get("X-API-Key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("authenticated")
        .to_string();
    if request.projection_version != PAIRED_PROJECTION_VERSION {
        return Err(AppError::PairedRejected {
            status: StatusCode::BAD_REQUEST,
            reason: "projection_not_supported".into(),
        });
    }
    let wallet = Pubkey::from_str(&request.wallet_id).map_err(|_| invalid_request())?;
    if !request.within_bounds() {
        return Err(invalid_request());
    }

    let (ip, user_agent) = request_origin(&headers, peer.map(|Extension(c)| c.0));
    check_probing_block(&state, ip)?;
    check_cross_wallet_cooldown(&state, ip, user_agent, &request.wallet_id)?;
    screen_client_signals(&state, &request.wallet_id, request.client_signals.as_ref())?;

    let remaining = admit_attempt(&state, &api_key, &wallet, &request.wallet_id)?;
    let budget_guard = PreForwardBudgetGuard::new(&state, &api_key, &wallet);

    let (projection_intent, timestamps) = identity_intent(
        &state,
        &wallet,
        request.projection_version,
        request.baseline_reset,
    )
    .await?;
    let origin_ip = ip.to_string();
    let body = ValidatorSessionBody::new(
        &request,
        projection_intent.receipt_purpose(request.projection_version),
        &timestamps,
        &origin_ip,
        user_agent,
    );
    let (reply, reputation) = tokio::join!(
        crate::upstream::post_json(
            &state,
            "/paired/validate",
            &body,
            PAIRED_VALIDATOR_TIMEOUT,
            FINALIZE_RESPONSE_BYTES,
        ),
        observe_reputation(&state, &wallet, &request.wallet_id)
    );
    let reply = match reply {
        Ok(reply) => {
            budget_guard.validator_reached();
            reply
        }
        Err(fault) => {
            tracing::error!(
                error = %fault,
                wallet_id = %crate::auth::redact::redact_wallet_id(&request.wallet_id),
                "Paired validation upstream request failed"
            );
            return Err(AppError::PairedUnavailable);
        }
    };
    state.metrics.increment_validations();

    let automation_risk = automation_risk(request.client_signals.as_ref(), &request.wallet_id);
    let reputation_risk = reputation_risk(reputation.as_ref(), &request.wallet_id);

    let status = reply.status;
    let Some(payload) = reply.body else {
        tracing::error!(status = %status, "Paired validation upstream returned an invalid body");
        refund_infrastructure_failure(&state, &api_key, &wallet);
        return Err(AppError::PairedUnavailable);
    };

    if status.is_success() {
        let (Ok(body), Ok(extras)) = (
            serde_json::from_value::<ValidatorSuccessBody>(payload.clone()),
            serde_json::from_value::<PairedSuccessExtras>(payload),
        ) else {
            tracing::error!("Paired validation upstream returned an invalid success body");
            refund_infrastructure_failure(&state, &api_key, &wallet);
            return Err(AppError::PairedUnavailable);
        };
        if !body.valid || extras.assurance_tier > MAX_ASSURANCE_TIER {
            tracing::error!(
                valid = body.valid,
                assurance_tier = extras.assurance_tier,
                "Paired validation upstream returned a contradictory success body"
            );
            refund_infrastructure_failure(&state, &api_key, &wallet);
            return Err(AppError::PairedUnavailable);
        }
        tracing::info!(
            wallet_id = %crate::auth::redact::redact_wallet_id(&request.wallet_id),
            biometric_risk = body.biometric_risk,
            tts_risk = body.tts_risk,
            automation_risk,
            reputation_risk,
            audio_realism_risk = body.audio_realism_risk,
            phrase_validation_status = body.phrase_validation_status.as_str(),
            assurance_tier = extras.assurance_tier,
            "Paired session passed biometric checks"
        );
        score_success(
            &state,
            &wallet,
            &request.wallet_id,
            &RiskComponents {
                biometric: body.biometric_risk,
                tts: body.tts_risk,
                temporal: body.temporal_risk,
                automation: automation_risk,
                reputation: reputation_risk,
            },
            None,
        )?;
        return Ok(PaddedJson(ValidateSessionResponse {
            valid: true,
            remaining_quota: Some(remaining),
            signed_receipt: body.signed_receipt,
            commitment_hex: body.commitment_hex,
            salt_hex: body.salt_hex,
            assurance_tier: extras.assurance_tier,
        }));
    }

    // A verdict carries the risk fields. A protocol refusal carries a reason only.
    if status == StatusCode::BAD_REQUEST {
        if let Ok(rejection) = serde_json::from_value::<ValidatorErrorBody>(payload.clone()) {
            if rejection.probing_detected == Some(true) {
                tracing::warn!(
                    ip = %crate::auth::redact::redact_ip(ip),
                    "Upstream validator flagged probing campaign! IP added to blocklist for 24 hours."
                );
                state.probing_blocklist.insert(
                    ip,
                    std::time::Instant::now() + std::time::Duration::from_secs(24 * 3600),
                );
            }
            let reason = rejection
                .reason
                .filter(|reason| PAIRED_VERDICT_REASONS.contains(&reason.as_str()));
            tracing::info!(
                wallet_id = %crate::auth::redact::redact_wallet_id(&request.wallet_id),
                reason = ?reason,
                biometric_risk = rejection.biometric_risk,
                automation_risk,
                reputation_risk,
                "Paired session rejected"
            );
            return Err(AppError::ValidationFailed { reason });
        }
    }

    let reason = serde_json::from_value::<UpstreamReason>(payload)
        .ok()
        .and_then(|body| body.reason);
    // No verdict was rendered on any path below, so the attempt and the quota come back.
    refund_infrastructure_failure(&state, &api_key, &wallet);
    match (status, reason) {
        (StatusCode::SERVICE_UNAVAILABLE, Some(reason)) if reason == "technical_failure" => {
            Err(AppError::PairedTechnicalFailure)
        }
        (status, Some(reason))
            if status.is_client_error() && PAIRED_PROTOCOL_REASONS.contains(&reason.as_str()) =>
        {
            Err(AppError::PairedRejected { status, reason })
        }
        (status, reason) => {
            tracing::error!(
                status = %status,
                reason = ?reason,
                "Paired validation upstream returned an unexpected status"
            );
            Err(AppError::PairedUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{headers_with_key, tracker_with_quota};
    use crate::validation::mock_validator::{
        error_body, state_with_mock_validator, success_body, MockValidator,
    };

    fn request_value() -> serde_json::Value {
        let segment = |round: u32| {
            serde_json::json!({
                "round_index": round,
                "audio_b64": "AAAA",
                "coarse_path_hex": "01",
            })
        };
        serde_json::json!({
            "capture_protocol": "paired",
            "wallet_id": Pubkey::new_unique().to_string(),
            "projection_version": 1,
            "session_id": "00112233445566778899aabbccddeeff",
            "final_digest": "ab".repeat(32),
            "segments": [segment(1), segment(2), segment(3)],
            "features": vec![0.5; FEATURE_VECTOR_WIDTH],
            "f0_contour": [120.0],
            "accel_magnitude": [0.1],
            "capture_timing": { "v": 1 },
            "client_signals": { "v": 1 },
            "baseline_reset": false,
            "attestation": { "platform": "play_integrity", "token": "token" }
        })
    }

    fn request() -> ValidateSessionRequest {
        serde_json::from_value(request_value()).expect("request parses")
    }

    #[test]
    fn the_forwarded_body_carries_exactly_the_validator_contract() {
        let request = request();
        let body = serde_json::to_value(ValidatorSessionBody::new(
            &request,
            Some("mint"),
            &[1, 2],
            "203.0.113.4",
            "agent",
        ))
        .expect("serializes");
        let mut keys: Vec<&str> = body
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "accel_magnitude",
                "attestation",
                "capture_protocol",
                "capture_timing",
                "f0_contour",
                "features",
                "final_digest",
                "origin_ip",
                "origin_ua",
                "projection_version",
                "receipt_purpose",
                "recent_timestamps",
                "segments",
                "session_id",
                "wallet_id",
            ]
        );
        assert_eq!(body["receipt_purpose"], "mint");
        assert_eq!(body["segments"][2]["round_index"], 3);
        assert!(body.get("client_signals").is_none());
        assert!(body.get("baseline_reset").is_none());
    }

    #[test]
    fn an_unknown_client_field_is_refused() {
        let mut value = request_value();
        value["study"] = serde_json::json!({});
        assert!(serde_json::from_value::<ValidateSessionRequest>(value).is_err());
    }

    #[test]
    fn every_bound_is_checked_before_forwarding() {
        assert!(request().within_bounds());
        let mutations: [fn(&mut serde_json::Value); 9] = [
            |value| value["capture_protocol"] = "single".into(),
            |value| value["session_id"] = "00".into(),
            |value| value["final_digest"] = "ab".into(),
            |value| value["features"] = serde_json::json!([0.5]),
            |value| {
                value["segments"].as_array_mut().expect("segments").pop();
            },
            |value| {
                value["segments"][0]["audio_b64"] = "A".repeat(MAX_SEGMENT_AUDIO_B64 + 1).into()
            },
            |value| {
                value["segments"][1]["coarse_path_hex"] = "0".repeat(MAX_COARSE_PATH_HEX + 1).into()
            },
            |value| value["f0_contour"] = serde_json::json!(vec![0.0; MAX_CONTOUR_FRAMES + 1]),
            |value| value["attestation"]["token"] = "t".repeat(MAX_ATTESTATION_TOKEN + 1).into(),
        ];
        for mutate in mutations {
            let mut value = request_value();
            mutate(&mut value);
            let request: ValidateSessionRequest =
                serde_json::from_value(value).expect("request parses");
            assert!(!request.within_bounds());
        }
    }

    async fn finalize(
        mock: &MockValidator,
        tracker: std::sync::Arc<crate::integrator::tracker::IntegratorTracker>,
        request: ValidateSessionRequest,
    ) -> Result<PaddedJson<ValidateSessionResponse>, AppError> {
        let state = state_with_mock_validator(tracker, mock);
        validate_session_handler(
            State(state),
            None,
            None,
            headers_with_key("key"),
            PairedJson(request),
        )
        .await
    }

    fn fresh_request() -> ValidateSessionRequest {
        let mut value = request_value();
        value["client_signals"] = serde_json::Value::Null;
        value["attestation"] = serde_json::Value::Null;
        serde_json::from_value(value).expect("request parses")
    }

    #[tokio::test]
    async fn a_passing_session_mints_with_its_tier() {
        let mut body = success_body(0.0, 0.0, 0.0);
        body["assurance_tier"] = serde_json::json!(2);
        body["signed_receipt"] = serde_json::json!({
            "validator_pubkey_hex": "aa",
            "message_hex": "bb",
            "signature_hex": "cc"
        });
        let mock = MockValidator::spawn(StatusCode::OK, body).await;
        let response = finalize(&mock, tracker_with_quota("key", 10), fresh_request())
            .await
            .expect("passes");
        assert!(response.0.valid);
        assert_eq!(response.0.assurance_tier, 2);
        assert!(response.0.signed_receipt.is_some());
        let sent = mock.received();
        assert_eq!(sent[0]["receipt_purpose"], "mint");
        assert!(sent[0].get("client_signals").is_none());
    }

    #[tokio::test]
    async fn a_tier_above_the_highest_is_an_invalid_upstream_answer() {
        let mut body = success_body(0.0, 0.0, 0.0);
        body["assurance_tier"] = serde_json::json!(3);
        let mock = MockValidator::spawn(StatusCode::OK, body).await;
        let tracker = tracker_with_quota("key", 10);
        let result = finalize(&mock, tracker.clone(), fresh_request()).await;
        assert!(matches!(result, Err(AppError::PairedUnavailable)));
        assert_eq!(tracker.get_remaining("key"), 10);
    }

    #[tokio::test]
    async fn a_content_verdict_rejects_with_its_reason_and_keeps_the_attempt() {
        for reason in PAIRED_VERDICT_REASONS {
            let mock = MockValidator::spawn(StatusCode::BAD_REQUEST, error_body(reason)).await;
            let tracker = tracker_with_quota("key", 10);
            let result = finalize(&mock, tracker.clone(), fresh_request()).await;
            assert!(matches!(
                result,
                Err(AppError::ValidationFailed { reason: Some(ref sent) }) if sent == reason
            ));
            assert_eq!(tracker.get_remaining("key"), 9);
        }
    }

    #[tokio::test]
    async fn a_protocol_refusal_passes_its_reason_and_refunds_the_quota() {
        let mock = MockValidator::spawn(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": "refused", "reason": "session_consumed" }),
        )
        .await;
        let tracker = tracker_with_quota("key", 10);
        let result = finalize(&mock, tracker.clone(), fresh_request()).await;
        assert!(matches!(
            result,
            Err(AppError::PairedRejected { status: StatusCode::CONFLICT, ref reason })
                if reason == "session_consumed"
        ));
        assert_eq!(tracker.get_remaining("key"), 10);
    }

    #[tokio::test]
    async fn a_reason_outside_the_allowlist_is_withheld() {
        let mock = MockValidator::spawn(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": "refused", "reason": "detector_detail" }),
        )
        .await;
        let result = finalize(&mock, tracker_with_quota("key", 10), fresh_request()).await;
        assert!(matches!(result, Err(AppError::PairedUnavailable)));
    }

    #[tokio::test]
    async fn a_technical_failure_refunds_and_asks_for_a_new_session() {
        let mock = MockValidator::spawn(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({ "error": "refused", "reason": "technical_failure" }),
        )
        .await;
        let tracker = tracker_with_quota("key", 10);
        let result = finalize(&mock, tracker.clone(), fresh_request()).await;
        assert!(matches!(result, Err(AppError::PairedTechnicalFailure)));
        assert_eq!(tracker.get_remaining("key"), 10);
    }

    #[tokio::test]
    async fn an_invalid_session_spends_nothing_and_never_reaches_the_validator() {
        let mock = MockValidator::spawn(StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let tracker = tracker_with_quota("key", 10);

        let mut projection_two = fresh_request();
        projection_two.projection_version = 2;
        assert!(matches!(
            finalize(&mock, tracker.clone(), projection_two).await,
            Err(AppError::PairedRejected { ref reason, .. }) if reason == "projection_not_supported"
        ));

        let mut short = fresh_request();
        short.features.pop();
        assert!(matches!(
            finalize(&mock, tracker.clone(), short).await,
            Err(AppError::PairedRejected { ref reason, .. }) if reason == "invalid_request"
        ));
        assert_eq!(mock.request_count(), 0);
        assert_eq!(tracker.get_remaining("key"), 10);
    }
}
