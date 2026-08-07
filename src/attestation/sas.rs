use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use solana_attestation_service_client::instructions::{
    CloseAttestationBuilder, CreateAttestationBuilder,
};
use solana_attestation_service_client::programs::SOLANA_ATTESTATION_SERVICE_ID;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

use crate::error::AppError;
use crate::solana::client::SolanaClient;
use crate::solana::pda;

/// Parsed fields from the on-chain IdentityState account.
pub struct IdentityStateData {
    pub trust_score: u16,
    /// Solana cluster timestamp of the most recent state-changing tx
    /// (`mint_anchor`, `update_anchor`, or `reset_identity_state`).
    /// Consumed by `check_attestation_freshness` to gate `/attest` on
    /// recent verification; also surfaced to Agent Anchor and Realms
    /// integrations that perform their own recency checks.
    pub last_verification_timestamp: i64,
}

/// Forward-skew tolerance for the on-chain `last_verification_timestamp`.
/// A few seconds of drift between the Solana cluster clock and the
/// executor's wall clock is expected; rejecting strictly on `ts > now`
/// would false-reject legitimate flows. Mirrors the asymmetric pattern
/// in `attestation/handler.rs::verify_wallet_signature`.
const ATTESTATION_FORWARD_SKEW_SECS: i64 = 30;

/// Maximum age of the on-chain verification timestamp accepted by
/// `/attest`. 5 minutes gives comfortable headroom over the normal SDK
/// flow (which calls `/attest` within seconds of on-chain confirmation)
/// while keeping the window tight enough that a direct API caller
/// bypassing the SDK cannot refresh attestation freshness for state
/// that didn't actually re-verify.
const ATTESTATION_VERIFICATION_MAX_AGE_SECS: i64 = 300;

/// Issues SAS attestations after successful Entros verification.
/// Uses a dedicated authority keypair (separate from the relayer/payer)
/// for signing attestation instructions.
pub struct SasAttestor {
    credential_pda: Pubkey,
    schema_pda: Pubkey,
    ttl_days: u64,
    client: Arc<SolanaClient>,
    authority_keypair: Keypair,
}

impl SasAttestor {
    pub fn new(
        credential_pda: Pubkey,
        schema_pda: Pubkey,
        ttl_days: u64,
        client: Arc<SolanaClient>,
        authority_keypair: Keypair,
    ) -> Self {
        Self {
            credential_pda,
            schema_pda,
            ttl_days,
            client,
            authority_keypair,
        }
    }

    /// Issue (or update) an SAS attestation for the given user wallet.
    /// Reads the user's on-chain IdentityState to get trust_score.
    pub async fn issue_attestation(&self, user_wallet: &Pubkey) -> Result<String, AppError> {
        // 1. Read user's IdentityState PDA
        let (identity_pda, _) = pda::find_identity_state_pda(user_wallet);
        let identity_data = self
            .client
            .get_account_data(&identity_pda)
            .await?
            .ok_or_else(|| {
                tracing::error!(
                    wallet = %user_wallet,
                    identity_pda = %identity_pda,
                    "Attestation requested but no IdentityState found on-chain"
                );
                AppError::AttestationServiceUnavailable
            })?;

        let identity = deserialize_identity_state(&identity_data).map_err(|e| {
            tracing::error!(
                error = %e,
                wallet = %user_wallet,
                "Failed to deserialize IdentityState during attestation"
            );
            AppError::AttestationServiceUnavailable
        })?;

        // 2. Capture wall-clock time once for both the freshness gate
        // below and the attestation's `verifiedAt` field (step 5). Reading
        // once is more semantically correct than re-reading after the
        // close-existing-attestation RPC — the value here is closer to
        // the actual verification time the attestation should reflect.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                tracing::error!(error = %e, "SystemTime before UNIX_EPOCH during attestation");
                AppError::AttestationServiceUnavailable
            })?
            .as_secs() as i64;

        // 3. Gate on verification recency. The on-chain `mint_anchor`,
        // `update_anchor`, and `reset_identity_state` instructions all
        // set `last_verification_timestamp` to the cluster clock; a stale
        // value here means the wallet hasn't completed a recent state-
        // changing tx and the SDK's normal client-side confirmation gate
        // was bypassed (or the on-chain tx silently reverted earlier in
        // the flow). Reject before issuing.
        check_attestation_freshness(identity.last_verification_timestamp, now).map_err(
            |reason| {
                tracing::warn!(
                    wallet = %crate::auth::redact::redact_wallet_id(&user_wallet.to_string()),
                    ts = identity.last_verification_timestamp,
                    now,
                    reason,
                    "Attestation rejected: verification not recent"
                );
                AppError::AttestationServiceUnavailable
            },
        )?;

        // 4. Derive attestation PDA
        let attestation_pda =
            find_sas_attestation_pda(&self.credential_pda, &self.schema_pda, user_wallet);

        // 5. Check if attestation already exists
        let existing = self.client.get_account_data(&attestation_pda).await?;

        let mut instructions = Vec::new();

        if existing.is_some() {
            // Close existing attestation before recreating
            let event_authority_pda = find_event_authority_pda();
            let close_ix = CloseAttestationBuilder::new()
                .payer(self.client.relayer_pubkey())
                .authority(self.authority_keypair.pubkey())
                .credential(self.credential_pda)
                .attestation(attestation_pda)
                .event_authority(event_authority_pda)
                .attestation_program(SOLANA_ATTESTATION_SERVICE_ID)
                .instruction();
            instructions.push(close_ix);
        }

        // 6. Serialize attestation data using the `now` captured at step 2.
        let data = serialize_attestation_data(identity.trust_score, now, "wallet-connected");

        // 7. Build CreateAttestation instruction
        let expiry = now + (self.ttl_days as i64 * 86_400);

        let create_ix = CreateAttestationBuilder::new()
            .payer(self.client.relayer_pubkey())
            .authority(self.authority_keypair.pubkey())
            .credential(self.credential_pda)
            .schema(self.schema_pda)
            .attestation(attestation_pda)
            .nonce(*user_wallet)
            .data(data)
            .expiry(expiry)
            .instruction();
        instructions.push(create_ix);

        // 8. Submit transaction (relayer pays, authority signs)
        let sig = self
            .client
            .send_attestation_tx(instructions, &self.authority_keypair)
            .await?;
        Ok(sig.to_string())
    }
}

/// Derive the SAS attestation PDA for a given user.
/// Seeds: ["attestation", credential, schema, nonce(user_wallet)]
fn find_sas_attestation_pda(credential: &Pubkey, schema: &Pubkey, nonce: &Pubkey) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(
        &[
            b"attestation",
            credential.as_ref(),
            schema.as_ref(),
            nonce.as_ref(),
        ],
        &SOLANA_ATTESTATION_SERVICE_ID,
    );
    pda
}

/// Derive the event authority PDA (singleton).
/// Seeds: ["__event_authority"]
fn find_event_authority_pda() -> Pubkey {
    let (pda, _) =
        Pubkey::find_program_address(&[b"__event_authority"], &SOLANA_ATTESTATION_SERVICE_ID);
    pda
}

/// Check whether the on-chain `last_verification_timestamp` is recent
/// enough to support issuing an attestation now. Returns `Ok(())` on
/// pass and an `&'static str` reason on rejection.
///
/// Rejection cases:
/// - `"future_skew"` when the timestamp is more than
///   `ATTESTATION_FORWARD_SKEW_SECS` ahead of `now` (anomalous clock
///   state or malicious account).
/// - `"stale"` when the timestamp is older than
///   `ATTESTATION_VERIFICATION_MAX_AGE_SECS`. Indicates the wallet
///   hasn't completed a recent `mint_anchor` / `update_anchor` /
///   `reset_identity_state` tx — either the SDK's client-side
///   confirmation gate was bypassed or the on-chain tx silently
///   reverted earlier in the flow.
///
/// Separated as a free function so the freshness contract is unit-
/// testable without spinning up an `AudioContext`-equivalent fixture
/// or a real SAS attestor.
fn check_attestation_freshness(ts: i64, now: i64) -> Result<(), &'static str> {
    if ts > now.saturating_add(ATTESTATION_FORWARD_SKEW_SECS) {
        return Err("future_skew");
    }
    let age = (now.saturating_sub(ts)).max(0);
    if age > ATTESTATION_VERIFICATION_MAX_AGE_SECS {
        return Err("stale");
    }
    Ok(())
}

/// Discriminator byte the SAS program writes at offset 0 of a Credential
/// account. Checked before the offsets below are trusted, so a Schema or
/// Attestation account passed by mistake is rejected rather than decoded
/// into a nonsense signer list.
const SAS_CREDENTIAL_DISCRIMINATOR: u8 = 0;

/// Decode the `authorized_signers` list from a raw SAS Credential account.
///
/// Only a key in this list may sign `CreateAttestation` or
/// `CloseAttestation` against the credential, so it is the authority the
/// executor must hold to issue attestations at all.
///
/// Layout (Solana Attestation Service `Credential`):
///   1 byte:  discriminator (0)
///  32 bytes: authority (Pubkey) — the key that may change this list
///   4 bytes: name length (u32 LE) + N bytes: name (UTF-8)
///   4 bytes: signer count (u32 LE) + 32 bytes per signer
///
/// The authority is deliberately not returned. It cannot be changed by any
/// instruction the program exposes, so nothing at runtime can act on it.
pub fn parse_credential_authorized_signers(data: &[u8]) -> Result<Vec<Pubkey>, String> {
    if data.first() != Some(&SAS_CREDENTIAL_DISCRIMINATOR) {
        return Err("SAS credential discriminator mismatch (not a Credential account)".to_string());
    }

    // Discriminator + authority, then the name's length prefix.
    let mut offset = 1 + 32;
    let name_len = read_u32_le(data, offset)? as usize;
    offset = offset
        .checked_add(4 + name_len)
        .ok_or("SAS credential name length overflows the buffer")?;

    let signer_count = read_u32_le(data, offset)? as usize;
    offset = offset
        .checked_add(4)
        .ok_or("SAS credential signer count overflows the buffer")?;

    // Reject an implausible count before allocating against it.
    let available = data.len().saturating_sub(offset);
    if signer_count.saturating_mul(32) > available {
        return Err(format!(
            "SAS credential declares {signer_count} signers but only {available} bytes remain"
        ));
    }

    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let bytes: [u8; 32] = data
            .get(offset..offset + 32)
            .ok_or("SAS credential signer list is truncated")?
            .try_into()
            .map_err(|_| "SAS credential signer is not 32 bytes")?;
        signers.push(Pubkey::from(bytes));
        offset += 32;
    }

    Ok(signers)
}

/// Read a little-endian u32 at `offset`, or describe why it is unreadable.
fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .ok_or_else(|| format!("SAS credential truncated at offset {offset}"))?
        .try_into()
        .map_err(|_| "SAS credential length prefix is not 4 bytes")?;
    Ok(u32::from_le_bytes(bytes))
}

/// Deserialize trust_score and last_verification_timestamp from raw IdentityState account data.
///
/// Layout (from protocol-core entros-anchor):
///   8 bytes: Anchor discriminator
///  32 bytes: owner (Pubkey)
///   8 bytes: creation_timestamp (i64)
///   8 bytes: last_verification_timestamp (i64)
///   4 bytes: verification_count (u32)
///   2 bytes: trust_score (u16)
///  ... remaining fields not needed
pub fn deserialize_identity_state(data: &[u8]) -> Result<IdentityStateData, String> {
    // Minimum size: 8 + 32 + 8 + 8 + 4 + 2 = 62 bytes
    if data.len() < 62 {
        return Err(format!(
            "IdentityState data too short: {} bytes (need >= 62)",
            data.len()
        ));
    }

    // Verify the Anchor account discriminator = sha256("account:IdentityState")[..8]
    // before trusting the raw offsets below. The PDA is program-derived, but a wrong-type
    // or uninitialized account at that address would otherwise have arbitrary bytes read as
    // a trust score. Mirrors the on-chain guard in entros-voter-weight so the off-chain
    // attestor enforces the same type check.
    const IDENTITY_DISCRIMINATOR: [u8; 8] = [156, 32, 87, 93, 52, 155, 248, 207];
    if data[..8] != IDENTITY_DISCRIMINATOR {
        return Err(
            "IdentityState discriminator mismatch (not an IdentityState account)".to_string(),
        );
    }

    let last_verification_timestamp = i64::from_le_bytes(
        data[48..56]
            .try_into()
            .map_err(|_| "Failed to read last_verification_timestamp")?,
    );

    let trust_score = u16::from_le_bytes(
        data[60..62]
            .try_into()
            .map_err(|_| "Failed to read trust_score")?,
    );

    Ok(IdentityStateData {
        trust_score,
        last_verification_timestamp,
    })
}

/// Serialize attestation data matching the SAS schema layout [bool, u16, i64, string].
///
/// Borsh encoding:
///   bool   = 1 byte (0x00 or 0x01)
///   u16    = 2 bytes little-endian
///   i64    = 8 bytes little-endian
///   string = 4-byte LE length prefix + UTF-8 bytes
fn serialize_attestation_data(trust_score: u16, verified_at: i64, mode: &str) -> Vec<u8> {
    let mode_bytes = mode.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + 8 + 4 + mode_bytes.len());

    // isHuman: bool
    buf.push(1u8);

    // trustScore: u16
    buf.extend_from_slice(&trust_score.to_le_bytes());

    // verifiedAt: i64
    buf.extend_from_slice(&verified_at.to_le_bytes());

    // mode: string (borsh = 4-byte LE length + utf8 bytes)
    buf.extend_from_slice(&(mode_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(mode_bytes);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_round_trip() {
        let data = serialize_attestation_data(150, 1_700_000_000, "wallet-connected");

        // isHuman
        assert_eq!(data[0], 1);

        // trustScore
        let ts = u16::from_le_bytes([data[1], data[2]]);
        assert_eq!(ts, 150);

        // verifiedAt
        let vat = i64::from_le_bytes(data[3..11].try_into().expect("8-byte slice"));
        assert_eq!(vat, 1_700_000_000);

        // mode
        let mode_len = u32::from_le_bytes(data[11..15].try_into().expect("4-byte slice")) as usize;
        let mode = std::str::from_utf8(&data[15..15 + mode_len]).expect("valid utf-8 mode tag");
        assert_eq!(mode, "wallet-connected");
    }

    #[test]
    fn deserialize_identity_state_valid() {
        let mut data = vec![0u8; 200];

        // Write Anchor discriminator
        data[..8].copy_from_slice(&[156, 32, 87, 93, 52, 155, 248, 207]);

        // Write last_verification_timestamp at offset 48
        let ts: i64 = 1_700_000_000;
        data[48..56].copy_from_slice(&ts.to_le_bytes());

        // Write trust_score at offset 60
        let score: u16 = 250;
        data[60..62].copy_from_slice(&score.to_le_bytes());

        let result = deserialize_identity_state(&data).expect("valid synthetic IdentityState");
        assert_eq!(result.trust_score, 250);
        assert_eq!(result.last_verification_timestamp, 1_700_000_000);
    }

    #[test]
    fn deserialize_identity_state_too_short() {
        let data = vec![0u8; 50];
        assert!(deserialize_identity_state(&data).is_err());
    }

    #[test]
    fn attestation_pda_is_deterministic() {
        let cred = Pubkey::new_unique();
        let schema = Pubkey::new_unique();
        let nonce = Pubkey::new_unique();

        let pda1 = find_sas_attestation_pda(&cred, &schema, &nonce);
        let pda2 = find_sas_attestation_pda(&cred, &schema, &nonce);
        assert_eq!(pda1, pda2);
    }

    // --- check_attestation_freshness ---

    #[test]
    fn freshness_accepts_just_verified_state() {
        // Verification 1 second ago: trivially within the window.
        let now = 1_700_000_000;
        assert!(check_attestation_freshness(now - 1, now).is_ok());
    }

    #[test]
    fn freshness_accepts_state_at_window_edge() {
        // Exactly at the max-age boundary — accepted (strictly greater rejects).
        let now = 1_700_000_000;
        let ts = now - ATTESTATION_VERIFICATION_MAX_AGE_SECS;
        assert!(check_attestation_freshness(ts, now).is_ok());
    }

    #[test]
    fn freshness_rejects_stale_state() {
        // One second beyond the max-age window.
        let now = 1_700_000_000;
        let ts = now - ATTESTATION_VERIFICATION_MAX_AGE_SECS - 1;
        assert_eq!(check_attestation_freshness(ts, now), Err("stale"));
    }

    #[test]
    fn freshness_accepts_small_forward_skew() {
        // Cluster clock running a few seconds ahead of executor wall clock.
        // Within ATTESTATION_FORWARD_SKEW_SECS, accepted.
        let now = 1_700_000_000;
        let ts = now + ATTESTATION_FORWARD_SKEW_SECS;
        assert!(check_attestation_freshness(ts, now).is_ok());
    }

    #[test]
    fn freshness_rejects_far_future_timestamp() {
        // Far-future timestamp is anomalous — likely cluster clock
        // misconfiguration or malicious account.
        let now = 1_700_000_000;
        let ts = now + ATTESTATION_FORWARD_SKEW_SECS + 1;
        assert_eq!(check_attestation_freshness(ts, now), Err("future_skew"));
    }

    #[test]
    fn freshness_handles_default_zero_timestamp() {
        // A freshly-created IdentityState (or a wallet that never verified)
        // has timestamp 0. Age = now, far beyond the window → rejected.
        let now = 1_700_000_000;
        assert_eq!(check_attestation_freshness(0, now), Err("stale"));
    }

    // --- parse_credential_authorized_signers ---

    /// Build a SAS Credential account body with the given name and signers.
    fn credential_bytes(name: &str, signers: &[Pubkey]) -> Vec<u8> {
        let mut data = vec![SAS_CREDENTIAL_DISCRIMINATOR];
        data.extend_from_slice(Pubkey::new_unique().as_ref()); // authority
        data.extend_from_slice(&(name.len() as u32).to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&(signers.len() as u32).to_le_bytes());
        for s in signers {
            data.extend_from_slice(s.as_ref());
        }
        data
    }

    #[test]
    fn credential_decodes_single_signer_and_matches_live_account_size() {
        let signer = Pubkey::new_unique();
        let data = credential_bytes("iam-protocol", &[signer]);

        // The live devnet credential reports space = 85. A fixture built from
        // this layout with the same name and one signer must land on the same
        // size, which cross-checks the offsets against the real account
        // without pinning a devnet snapshot that would go stale.
        assert_eq!(data.len(), 85);

        let signers = parse_credential_authorized_signers(&data).expect("valid credential");
        assert_eq!(signers, vec![signer]);
    }

    #[test]
    fn credential_decodes_two_signers() {
        // The overlap state during a rotation: outgoing and incoming keys
        // both authorized, so neither issuance nor closure breaks mid-swap.
        let outgoing = Pubkey::new_unique();
        let incoming = Pubkey::new_unique();
        let data = credential_bytes("iam-protocol", &[outgoing, incoming]);

        assert_eq!(data.len(), 85 + 32);

        let signers = parse_credential_authorized_signers(&data).expect("valid credential");
        assert_eq!(signers, vec![outgoing, incoming]);
        assert!(signers.contains(&incoming));
    }

    #[test]
    fn credential_rejects_wrong_discriminator() {
        // Discriminator 1 is a Schema account. Pointing SAS_CREDENTIAL_PDA at
        // the schema is an easy environment-variable slip, and decoding it as
        // a credential would yield an arbitrary signer list.
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        data[0] = 1;
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_rejects_empty_buffer() {
        assert!(parse_credential_authorized_signers(&[]).is_err());
    }

    #[test]
    fn credential_rejects_truncated_signer_list() {
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        data.truncate(data.len() - 1);
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_rejects_signer_count_that_overruns_the_buffer() {
        // A corrupt or hostile count must not drive a huge allocation before
        // the read fails.
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        let count_offset = 1 + 32 + 4 + "iam-protocol".len();
        data[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_rejects_name_length_that_overruns_the_buffer() {
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        data[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_with_no_signers_decodes_empty() {
        // Structurally valid, operationally dead: nothing can issue against
        // it. The decoder reports the truth and the startup preflight is what
        // refuses the boot.
        let data = credential_bytes("iam-protocol", &[]);
        let signers = parse_credential_authorized_signers(&data).expect("valid credential");
        assert!(signers.is_empty());
    }
}
