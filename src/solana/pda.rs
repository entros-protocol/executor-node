use solana_sdk::pubkey;
use solana_sdk::pubkey::Pubkey;

const VERIFIER_PROGRAM: Pubkey = pubkey!("4F97jNoxQzT2qRbkWpW3ztC3Nz2TtKj3rnKG8ExgnrfV");
const ANCHOR_PROGRAM: Pubkey = pubkey!("GZYwTp2ozeuRA5Gof9vs4ya961aANcJBdUzB7LN6q4b2");
const REGISTRY_PROGRAM: Pubkey = pubkey!("6VBs3zr9KrfFPGd6j7aGBPQWwZa5tajVfA7HN6MMV9VW");

pub fn anchor_program_id() -> Pubkey {
    ANCHOR_PROGRAM
}

pub fn verifier_program_id() -> Pubkey {
    VERIFIER_PROGRAM
}

pub fn find_identity_state_pda(user: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"identity", user.as_ref()], &ANCHOR_PROGRAM)
}

/// The record the Anchor program writes when an identity moves to `wallet`.
pub fn find_migration_record_pda(wallet: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"migration", wallet.as_ref()], &ANCHOR_PROGRAM)
}

#[allow(dead_code)] // Reserved for integrator onboarding.
pub fn find_protocol_config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"protocol_config"], &REGISTRY_PROGRAM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pda_derivation_is_deterministic() {
        let wallet = Pubkey::new_unique();
        assert_eq!(
            find_identity_state_pda(&wallet),
            find_identity_state_pda(&wallet)
        );
        assert_eq!(
            find_migration_record_pda(&wallet),
            find_migration_record_pda(&wallet)
        );
    }

    #[test]
    fn each_wallet_and_each_seed_has_its_own_address() {
        let wallet = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        assert_ne!(
            find_identity_state_pda(&wallet).0,
            find_identity_state_pda(&other).0
        );
        assert_ne!(
            find_identity_state_pda(&wallet).0,
            find_migration_record_pda(&wallet).0
        );
    }
}
