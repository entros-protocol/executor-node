use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::str::FromStr;

use crate::error::AppError;
use crate::padding::PaddedJson;
use crate::server::AppState;

/// Maximum age of a signed attestation message (seconds).
const ATTEST_MESSAGE_MAX_AGE_SECS: u64 = 60;
/// Asymmetric tolerance for forward clock skew. Client devices commonly have
/// a few seconds of drift ahead of server time; rejecting strictly on
/// `msg_timestamp > now` would lock out those clients. 30s leaves room for
/// realistic NTP variance without permitting meaningful replay-window abuse.
const ATTEST_FORWARD_SKEW_SECS: u64 = 30;

#[derive(Deserialize)]
pub struct AttestRequest {
    pub wallet_address: String,
    #[serde(default)]
    pub nonce: Option<Vec<u8>>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct AttestResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn attest_handler(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Result<PaddedJson<AttestResponse>, AppError> {
    // 1. Check SAS is configured
    let attestor = state
        .sas_attestor
        .as_ref()
        .ok_or_else(|| AppError::InvalidRequest("SAS attestation is not configured".into()))?;

    // 2. Require all three ownership-proof fields. Walletless flows no longer
    //    write to SAS — they were the captcha-equivalent tier, and aliasing
    //    them through SAS created a griefing surface where a caller could
    //    issue attestations against any target wallet pubkey without proof
    //    of control. SAS is now wallet-only. Walletless integrators get
    //    client-side ephemeral receipts only.
    let (nonce, signature, message) = match (&req.nonce, &req.signature, &req.message) {
        (Some(n), Some(s), Some(m)) => (n, s, m),
        _ => return Err(AppError::InvalidRequest("wallet_ownership_required".into())),
    };

    // 3. Parse wallet address
    let user_wallet = Pubkey::from_str(&req.wallet_address).map_err(|_| {
        AppError::InvalidRequest(format!("Invalid wallet address: {}", req.wallet_address))
    })?;

    // 4. Parse the server-issued challenge nonce.
    let nonce_arr: [u8; 32] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| AppError::InvalidRequest("Nonce must be 32 bytes".into()))?;

    // 5. Verify wallet ownership before consuming its single-use challenge.
    verify_wallet_signature(&user_wallet, signature, message)?;

    // 6. Consume the nonce the request names. Issuing a challenge needs no wallet
    // signature, so a later challenge from any caller must not void this one.
    state
        .challenge_registry
        .validate_and_consume_exact(&user_wallet, &nonce_arr)
        .map_err(|e| {
            tracing::warn!(
                wallet = %crate::auth::redact::redact_wallet_id(&user_wallet.to_string()),
                error = %e,
                "Challenge nonce validation failed"
            );
            AppError::Forbidden(format!("Challenge validation failed: {e}"))
        })?;

    // 7. Bound attestations per wallet. A request reaches this line only with a message
    // the wallet signed inside the message window, and each one consumes an unused
    // challenge, so no caller can spend these tokens without such a message. A bucket in
    // front of the signature check would be one that any caller could empty for everyone.
    state
        .attest_wallet_rate_limiter
        .check_with_retry(&user_wallet.to_string())
        .map_err(|retry_after_secs| AppError::WalletRateLimited { retry_after_secs })?;

    // 8. Issue attestation.
    match attestor.issue_attestation(&user_wallet).await {
        Ok(sig) => {
            tracing::info!(
                wallet = %crate::auth::redact::redact_wallet_id(&user_wallet.to_string()),
                attestation_sig = %sig,
                "SAS attestation issued"
            );

            state.metrics.increment_attestations();

            Ok(PaddedJson(AttestResponse {
                success: true,
                attestation_tx: Some(sig),
                error: None,
            }))
        }
        Err(e) => {
            tracing::error!(
                wallet = %crate::auth::redact::redact_wallet_id(&user_wallet.to_string()),
                error = %e,
                "SAS attestation failed"
            );
            Ok(PaddedJson(AttestResponse {
                success: false,
                attestation_tx: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Verify an ed25519 signature proving wallet ownership.
/// Message format: "Entros-ATTEST:{wallet_address}:{timestamp_secs}"
fn verify_wallet_signature(
    wallet: &Pubkey,
    signature_hex: &str,
    message: &str,
) -> Result<(), AppError> {
    // 1. Validate message format before expensive signature verification
    let parts: Vec<&str> = message.split(':').collect();
    if parts.len() != 3 || parts[0] != "Entros-ATTEST" {
        return Err(AppError::Forbidden(
            "Invalid attestation message format".into(),
        ));
    }

    if parts[1] != wallet.to_string() {
        return Err(AppError::Forbidden(
            "Message wallet does not match request".into(),
        ));
    }

    let msg_timestamp: u64 = parts[2]
        .parse()
        .map_err(|_| AppError::Forbidden("Invalid timestamp in message".into()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            tracing::error!("System clock before UNIX epoch during attestation");
            AppError::AttestationServiceUnavailable
        })?
        .as_secs();

    // Asymmetric skew check: tolerate `ATTEST_FORWARD_SKEW_SECS` of
    // forward clock drift (client time slightly ahead of server) but
    // reject anything older than `ATTEST_MESSAGE_MAX_AGE_SECS` to bound
    // replay windows. The previous `abs_diff > MAX_AGE` allowed up to
    // `MAX_AGE` seconds of forward skew too, which is symmetric and
    // unnecessarily wide for a replay-window guard.
    if msg_timestamp > now && msg_timestamp - now > ATTEST_FORWARD_SKEW_SECS {
        return Err(AppError::Forbidden(
            "Attestation message timestamp too far in future".into(),
        ));
    }
    if now > msg_timestamp && now - msg_timestamp > ATTEST_MESSAGE_MAX_AGE_SECS {
        return Err(AppError::Forbidden(
            "Attestation message has expired".into(),
        ));
    }

    // 2. Decode the hex signature and verify ed25519.
    let sig_bytes = crate::auth::signature::decode_signature_hex(signature_hex)
        .ok_or_else(|| AppError::Forbidden("Invalid signature hex encoding".into()))?;

    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| AppError::Forbidden("Invalid signature length".into()))?;

    if !sig.verify(wallet.as_ref(), message.as_bytes()) {
        return Err(AppError::Forbidden(
            "Wallet signature verification failed".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::sas::SasAttestor;
    use crate::server::{build_test_state, tracker_with_quota};
    use solana_sdk::signature::{Keypair, Signer};
    use std::sync::Arc;

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn current_attestation_message(wallet: &Pubkey) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after UNIX epoch")
            .as_secs();
        format!("Entros-ATTEST:{wallet}:{timestamp}")
    }

    #[tokio::test]
    async fn invalid_signature_does_not_consume_the_attestation_challenge() {
        let tracker = tracker_with_quota("test-key", 10);
        let mut state = build_test_state(tracker, None);
        let wallet = Keypair::new().pubkey();
        let (nonce, _, _) = state
            .challenge_registry
            .issue(wallet, crate::validation::handler::FALLBACK_ORIGIN);
        state.sas_attestor = Some(Arc::new(SasAttestor::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            Arc::clone(&state.solana),
            Keypair::new(),
        )));

        let result = attest_handler(
            State(state.clone()),
            Json(AttestRequest {
                wallet_address: wallet.to_string(),
                nonce: Some(nonce.to_vec()),
                signature: Some("00".repeat(64)),
                message: Some(current_attestation_message(&wallet)),
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(state
            .challenge_registry
            .validate_and_consume_exact(&wallet, &nonce)
            .is_ok());
    }

    /// 128 bytes that are not 128 characters once made the hex decoder panic.
    #[tokio::test]
    async fn a_signature_with_a_multi_byte_character_is_refused() {
        let tracker = tracker_with_quota("test-key", 10);
        let mut state = build_test_state(tracker, None);
        let wallet = Keypair::new().pubkey();
        let (nonce, _, _) = state
            .challenge_registry
            .issue(wallet, crate::validation::handler::FALLBACK_ORIGIN);
        state.sas_attestor = Some(Arc::new(SasAttestor::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            Arc::clone(&state.solana),
            Keypair::new(),
        )));
        let crafted = format!("a\u{e9}{}", "0".repeat(125));
        assert_eq!(crafted.len(), 128);

        let result = attest_handler(
            State(state.clone()),
            Json(AttestRequest {
                wallet_address: wallet.to_string(),
                nonce: Some(nonce.to_vec()),
                signature: Some(crafted),
                message: Some(current_attestation_message(&wallet)),
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A second challenge for the wallet, from any caller, must not void the first.
    #[tokio::test]
    async fn an_earlier_nonce_survives_a_later_challenge() {
        let tracker = tracker_with_quota("test-key", 10);
        let mut state = build_test_state(tracker, None);
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        let (earlier_nonce, _, _) = state
            .challenge_registry
            .issue(wallet, crate::validation::handler::FALLBACK_ORIGIN);
        // The later challenge comes from the request's own network, so it moves the
        // pointer that network would otherwise be checked against.
        let (later_nonce, _, _) = state
            .challenge_registry
            .issue(wallet, crate::validation::handler::FALLBACK_ORIGIN);
        state.sas_attestor = Some(Arc::new(SasAttestor::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            Arc::clone(&state.solana),
            Keypair::new(),
        )));
        let message = current_attestation_message(&wallet);
        let signature = lower_hex(keypair.sign_message(message.as_bytes()).as_ref());

        // The request passes the challenge check and reaches the attestor. No Solana
        // node is running, so the issue itself reports a failure in the response body.
        let result = attest_handler(
            State(state.clone()),
            Json(AttestRequest {
                wallet_address: wallet.to_string(),
                nonce: Some(earlier_nonce.to_vec()),
                signature: Some(signature),
                message: Some(message),
            }),
        )
        .await;

        assert!(
            !matches!(result, Err(AppError::Forbidden(_))),
            "the earlier nonce was refused"
        );
        // The earlier nonce was consumed, and the later one is untouched.
        assert!(state
            .challenge_registry
            .validate_and_consume_exact(&wallet, &earlier_nonce)
            .is_err());
        assert!(state
            .challenge_registry
            .validate_and_consume_exact(&wallet, &later_nonce)
            .is_ok());
    }

    #[tokio::test]
    async fn a_wallet_over_its_attestation_rate_is_refused_after_its_signature_is_checked() {
        let tracker = tracker_with_quota("test-key", 10);
        let mut state = build_test_state(tracker, None);
        state.attest_wallet_rate_limiter = Arc::new(crate::auth::rate_limit::RateLimiter::new(1));
        state.sas_attestor = Some(Arc::new(SasAttestor::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
            Arc::clone(&state.solana),
            Keypair::new(),
        )));
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        let request = |state: &AppState, signer: &Keypair| {
            let (nonce, _, _) = state
                .challenge_registry
                .issue(wallet, crate::validation::handler::FALLBACK_ORIGIN);
            let message = current_attestation_message(&wallet);
            AttestRequest {
                wallet_address: wallet.to_string(),
                nonce: Some(nonce.to_vec()),
                signature: Some(lower_hex(signer.sign_message(message.as_bytes()).as_ref())),
                message: Some(message),
            }
        };

        // A caller without the wallet's key is refused on its signature and spends nothing.
        let stranger = Keypair::new();
        for _ in 0..3 {
            let result =
                attest_handler(State(state.clone()), Json(request(&state, &stranger))).await;
            assert!(matches!(result, Err(AppError::Forbidden(_))));
        }

        // The owner's first request takes the wallet's one token. No Solana node is running,
        // so the issue itself reports a failure in the response body.
        let first = attest_handler(State(state.clone()), Json(request(&state, &keypair))).await;
        assert!(first.is_ok(), "the owner still had its token");
        let second = attest_handler(State(state.clone()), Json(request(&state, &keypair))).await;
        assert!(matches!(
            second,
            Err(AppError::WalletRateLimited { retry_after_secs }) if retry_after_secs > 0
        ));
    }
}
