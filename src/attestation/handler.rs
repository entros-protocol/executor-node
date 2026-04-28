use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::str::FromStr;

use crate::error::AppError;
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
) -> Result<Json<AttestResponse>, AppError> {
    // 1. Check SAS is configured
    let attestor = state.sas_attestor.as_ref().ok_or_else(|| {
        AppError::InvalidRequest("SAS attestation is not configured".into())
    })?;

    // 2. Parse wallet address
    let user_wallet = Pubkey::from_str(&req.wallet_address).map_err(|_| {
        AppError::InvalidRequest(format!("Invalid wallet address: {}", req.wallet_address))
    })?;

    // 3. Validate server-issued challenge nonce
    if let Some(nonce) = &req.nonce {
        let nonce_arr: [u8; 32] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidRequest("Nonce must be 32 bytes".into()))?;

        state
            .challenge_registry
            .validate_and_consume(&user_wallet, &nonce_arr, state.challenge_ttl_secs)
            .map_err(|e| {
                tracing::warn!(wallet = %user_wallet, error = %e, "Challenge nonce validation failed");
                AppError::Forbidden(format!("Challenge validation failed: {e}"))
            })?;
    } else {
        tracing::warn!(
            wallet = %user_wallet,
            "Attestation requested without server-issued nonce"
        );
    }

    // 4. Verify wallet ownership via signed message. Walletless / captcha-
    //    equivalent integrations DO submit attestation requests without a
    //    signature — this is INTENTIONAL per the project's two-tier
    //    integration model (wallet-connected = primary, walletless = secondary
    //    captcha-tier). The ownership-proof path is taken when both
    //    `signature` and `message` are provided; otherwise the request
    //    proceeds and is logged at WARN so operators can see which tier
    //    each call uses without forcing every walletless integrator through
    //    a signing flow.
    if let (Some(sig_str), Some(msg)) = (&req.signature, &req.message) {
        verify_wallet_signature(&user_wallet, sig_str, msg)?;
    } else {
        tracing::warn!(
            wallet = %user_wallet,
            "Attestation requested without wallet ownership proof (walletless tier)"
        );
    }

    // 5. Issue attestation
    match attestor.issue_attestation(&user_wallet).await {
        Ok(sig) => {
            tracing::info!(
                wallet = %user_wallet,
                attestation_sig = %sig,
                "SAS attestation issued"
            );

            state.metrics.increment_attestations();

            Ok(Json(AttestResponse {
                success: true,
                attestation_tx: Some(sig),
                error: None,
            }))
        }
        Err(e) => {
            tracing::error!(
                wallet = %user_wallet,
                error = %e,
                "SAS attestation failed"
            );
            Ok(Json(AttestResponse {
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
        return Err(AppError::Forbidden("Invalid attestation message format".into()));
    }

    if parts[1] != wallet.to_string() {
        return Err(AppError::Forbidden("Message wallet does not match request".into()));
    }

    let msg_timestamp: u64 = parts[2]
        .parse()
        .map_err(|_| AppError::Forbidden("Invalid timestamp in message".into()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
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
        return Err(AppError::Forbidden("Attestation message has expired".into()));
    }

    // 2. Decode hex signature and verify ed25519. Ed25519 signatures are
    //    64 bytes = 128 hex chars; reject anything else upfront so the
    //    decode loop never reads partial chunks. The previous
    //    `.unwrap_or("xx")` fallback masked odd-length input by silently
    //    producing a malformed signature that would only fail in the
    //    subsequent `Signature::try_from` step.
    if signature_hex.len() != 128 {
        return Err(AppError::Forbidden("Invalid signature hex length".into()));
    }
    let sig_bytes: Vec<u8> = (0..128)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&signature_hex[i..i + 2], 16)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Forbidden("Invalid signature hex encoding".into()))?;

    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| {
        AppError::Forbidden("Invalid signature length".into())
    })?;

    if !sig.verify(wallet.as_ref(), message.as_bytes()) {
        return Err(AppError::Forbidden("Wallet signature verification failed".into()));
    }

    Ok(())
}
