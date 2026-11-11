//! Solana Attestation Service instruction builders.
//!
//! The program takes a one-byte instruction index, not an Anchor discriminator.
//! Account order is part of the wire contract, so the structs below list the
//! accounts in the order the program reads them.

use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey;
use solana_sdk::pubkey::Pubkey;

const SYSTEM_PROGRAM_ID: Pubkey = pubkey!("11111111111111111111111111111111");

pub const ATTESTATION_PROGRAM_ID: Pubkey = pubkey!("22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG");

const CREATE_ATTESTATION_INDEX: u8 = 6;
const CLOSE_ATTESTATION_INDEX: u8 = 7;

pub struct CreateAttestationAccounts {
    pub payer: Pubkey,
    pub authority: Pubkey,
    pub credential: Pubkey,
    pub schema: Pubkey,
    pub attestation: Pubkey,
}

pub struct CloseAttestationAccounts {
    pub payer: Pubkey,
    pub authority: Pubkey,
    pub credential: Pubkey,
    pub attestation: Pubkey,
    pub event_authority: Pubkey,
}

/// Data: 1-byte index, 32-byte nonce, borsh `Vec<u8>`, 8-byte little-endian expiry.
pub fn build_create_attestation(
    accounts: &CreateAttestationAccounts,
    nonce: &Pubkey,
    data: &[u8],
    expiry: i64,
) -> Instruction {
    let mut buf = Vec::with_capacity(1 + 32 + 4 + data.len() + 8);
    buf.push(CREATE_ATTESTATION_INDEX);
    buf.extend_from_slice(nonce.as_ref());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf.extend_from_slice(&expiry.to_le_bytes());

    Instruction {
        program_id: ATTESTATION_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(accounts.payer, true),
            AccountMeta::new_readonly(accounts.authority, true),
            AccountMeta::new_readonly(accounts.credential, false),
            AccountMeta::new_readonly(accounts.schema, false),
            AccountMeta::new(accounts.attestation, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: buf,
    }
}

/// Data: 1-byte index. The program reads its own ID from the final account.
pub fn build_close_attestation(accounts: &CloseAttestationAccounts) -> Instruction {
    Instruction {
        program_id: ATTESTATION_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(accounts.payer, true),
            AccountMeta::new_readonly(accounts.authority, true),
            AccountMeta::new_readonly(accounts.credential, false),
            AccountMeta::new(accounts.attestation, false),
            AccountMeta::new_readonly(accounts.event_authority, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(ATTESTATION_PROGRAM_ID, false),
        ],
        data: vec![CLOSE_ATTESTATION_INDEX],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-for-byte expectations captured from the generated
    // `solana-attestation-service-client` 1.0.9 builders. They pin the wire
    // contract, so a hand-encoding mistake cannot reach the program.
    fn key(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn attestation_payload() -> Vec<u8> {
        vec![
            1, 150, 0, 0, 202, 154, 59, 101, 0, 0, 0, 0, 3, 0, 0, 0, 97, 98, 99,
        ]
    }

    #[test]
    fn program_id_is_the_deployed_attestation_service() {
        // The same identifier appears in the SDK, the partner package, and the
        // protocol tests. Pinned by bytes so an edit to the literal fails here.
        assert_eq!(
            ATTESTATION_PROGRAM_ID.to_bytes(),
            [
                15, 94, 158, 213, 55, 30, 44, 112, 137, 140, 169, 253, 14, 119, 192, 6, 92, 171,
                93, 160, 46, 86, 103, 139, 39, 19, 56, 42, 243, 116, 89, 183
            ]
        );
    }

    #[test]
    fn create_attestation_matches_the_generated_client() {
        let accounts = CreateAttestationAccounts {
            payer: key(1),
            authority: key(2),
            credential: key(3),
            schema: key(4),
            attestation: key(5),
        };
        let ix =
            build_create_attestation(&accounts, &key(6), &attestation_payload(), 1_700_086_400);

        let mut expected = vec![6u8];
        expected.extend_from_slice(&[6u8; 32]);
        expected.extend_from_slice(&19u32.to_le_bytes());
        expected.extend_from_slice(&attestation_payload());
        expected.extend_from_slice(&1_700_086_400i64.to_le_bytes());

        assert_eq!(ix.program_id, ATTESTATION_PROGRAM_ID);
        assert_eq!(ix.data, expected);
        assert_eq!(
            ix.accounts
                .iter()
                .map(|a| (a.pubkey, a.is_signer, a.is_writable))
                .collect::<Vec<_>>(),
            vec![
                (key(1), true, true),
                (key(2), true, false),
                (key(3), false, false),
                (key(4), false, false),
                (key(5), false, true),
                (SYSTEM_PROGRAM_ID, false, false),
            ]
        );
    }

    #[test]
    fn close_attestation_matches_the_generated_client() {
        let ix = build_close_attestation(&CloseAttestationAccounts {
            payer: key(1),
            authority: key(2),
            credential: key(3),
            attestation: key(5),
            event_authority: key(7),
        });

        assert_eq!(ix.program_id, ATTESTATION_PROGRAM_ID);
        assert_eq!(ix.data, vec![7u8]);
        assert_eq!(
            ix.accounts
                .iter()
                .map(|a| (a.pubkey, a.is_signer, a.is_writable))
                .collect::<Vec<_>>(),
            vec![
                (key(1), true, true),
                (key(2), true, false),
                (key(3), false, false),
                (key(5), false, true),
                (key(7), false, false),
                (SYSTEM_PROGRAM_ID, false, false),
                (ATTESTATION_PROGRAM_ID, false, false),
            ]
        );
    }

    #[test]
    fn create_attestation_length_scales_with_the_payload() {
        let accounts = CreateAttestationAccounts {
            payer: key(1),
            authority: key(2),
            credential: key(3),
            schema: key(4),
            attestation: key(5),
        };
        let ix = build_create_attestation(&accounts, &key(6), &[], 0);
        assert_eq!(ix.data.len(), 1 + 32 + 4 + 8);
    }
}
