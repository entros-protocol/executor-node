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
    #[allow(dead_code)] // Used for verification recency checks in Agent Anchor and Realms integrations
    pub last_verification_timestamp: i64,
}

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

        // 2. Derive attestation PDA
        let attestation_pda = find_sas_attestation_pda(
            &self.credential_pda,
            &self.schema_pda,
            user_wallet,
        );

        // 3. Check if attestation already exists
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

        // 4. Serialize attestation data
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                tracing::error!(error = %e, "SystemTime before UNIX_EPOCH during attestation");
                AppError::AttestationServiceUnavailable
            })?
            .as_secs() as i64;

        let data = serialize_attestation_data(
            identity.trust_score,
            now,
            "wallet-connected",
        );

        // 5. Build CreateAttestation instruction
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

        // 6. Submit transaction (relayer pays, authority signs)
        let sig = self
            .client
            .send_attestation_tx(instructions, &self.authority_keypair)
            .await?;
        Ok(sig.to_string())
    }
}

/// Derive the SAS attestation PDA for a given user.
/// Seeds: ["attestation", credential, schema, nonce(user_wallet)]
fn find_sas_attestation_pda(
    credential: &Pubkey,
    schema: &Pubkey,
    nonce: &Pubkey,
) -> Pubkey {
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
    let (pda, _) = Pubkey::find_program_address(
        &[b"__event_authority"],
        &SOLANA_ATTESTATION_SERVICE_ID,
    );
    pda
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
fn deserialize_identity_state(data: &[u8]) -> Result<IdentityStateData, String> {
    // Minimum size: 8 + 32 + 8 + 8 + 4 + 2 = 62 bytes
    if data.len() < 62 {
        return Err(format!(
            "IdentityState data too short: {} bytes (need >= 62)",
            data.len()
        ));
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
}
