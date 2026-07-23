use dashmap::DashMap;
use solana_sdk::pubkey::Pubkey;
use std::fmt;
use std::time::Instant;

use crate::challenge::lissajous::LissajousParams;
use crate::challenge::phrase_gen;

struct NonceEntry {
    nonce: [u8; 32],
    /// Server-issued challenge phrase (5 words drawn from the curated
    /// dictionary at `src/challenge/word_dict.rs`) bound to this nonce for
    /// master-list #89 content binding. The wallet is shown this phrase on
    /// the client; `/validate-features` looks it up here to pass to the
    /// validation service for word-level edit-distance match.
    phrase: String,
    /// Server-issued Lissajous curve parameters for the touch challenge.
    #[allow(dead_code)]
    curve: LissajousParams,
    issued_at: Instant,
}

/// Server-side challenge nonce registry. Issues nonces for wallet-connected
/// verifications and validates them at attestation time. Prevents
/// pre-computation attacks by ensuring clients use server-issued nonces
/// with a tight time window.
///
/// Keyed by wallet pubkey — one outstanding challenge per wallet at a time.
/// In-memory for devnet. Resets on restart (acceptable — worst case, the
/// client falls back to a client-generated nonce and skips attestation).
pub struct ChallengeNonceRegistry {
    entries: DashMap<Pubkey, NonceEntry>,
}

#[derive(Debug)]
pub enum ChallengeError {
    NotFound,
    NonceMismatch,
    Expired,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "No challenge issued for this wallet"),
            Self::NonceMismatch => write!(f, "Nonce does not match issued challenge"),
            Self::Expired => write!(f, "Challenge has expired"),
        }
    }
}

impl ChallengeNonceRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Issue a new challenge nonce + phrase + curve for the given wallet.
    /// Overwrites any existing outstanding challenge for this wallet.
    /// Returns the nonce bytes, the generated phrase, and the Lissajous curve;
    /// all travel back to the client via the `/challenge` response.
    pub fn issue(&self, wallet: Pubkey) -> ([u8; 32], String, LissajousParams) {
        let nonce: [u8; 32] = rand::random();
        let phrase = phrase_gen::generate_phrase(5);
        let curve = LissajousParams::generate();
        self.entries.insert(
            wallet,
            NonceEntry {
                nonce,
                phrase: phrase.clone(),
                curve: curve.clone(),
                issued_at: Instant::now(),
            },
        );
        (nonce, phrase, curve)
    }

    /// Look up the issued phrase for a wallet without consuming the entry.
    /// Returns `None` if no challenge is outstanding OR the entry has
    /// already aged past `max_age_secs`.
    pub fn peek_phrase(&self, wallet: &Pubkey, max_age_secs: u64) -> Option<String> {
        let entry = self.entries.get(wallet)?;
        if entry.issued_at.elapsed().as_secs() > max_age_secs {
            return None;
        }
        Some(entry.phrase.clone())
    }

    /// Look up the issued phrase and Lissajous curve for a wallet without consuming the entry.
    #[allow(dead_code)]
    pub fn peek_challenge(
        &self,
        wallet: &Pubkey,
        max_age_secs: u64,
    ) -> Option<(String, LissajousParams)> {
        let entry = self.entries.get(wallet)?;
        if entry.issued_at.elapsed().as_secs() > max_age_secs {
            return None;
        }
        Some((entry.phrase.clone(), entry.curve.clone()))
    }

    /// Validate that the nonce was server-issued for this wallet and is
    /// within the time window. Consumes the entry on success (single-use).
    /// Uses atomic remove_if to avoid TOCTOU race between check and removal.
    pub fn validate_and_consume(
        &self,
        wallet: &Pubkey,
        nonce: &[u8; 32],
        max_age_secs: u64,
    ) -> Result<(), ChallengeError> {
        // Atomically remove only if nonce matches
        let removed = self
            .entries
            .remove_if(wallet, |_, entry| entry.nonce == *nonce);

        match removed {
            Some((_, entry)) => {
                if entry.issued_at.elapsed().as_secs() > max_age_secs {
                    Err(ChallengeError::Expired)
                } else {
                    Ok(())
                }
            }
            None => {
                // Either wallet not found or nonce didn't match
                if self.entries.contains_key(wallet) {
                    Err(ChallengeError::NonceMismatch)
                } else {
                    Err(ChallengeError::NotFound)
                }
            }
        }
    }

    /// Evict entries older than max_age_secs. Called by background task.
    pub fn evict_stale(&self, max_age_secs: u64) {
        self.entries
            .retain(|_, entry| entry.issued_at.elapsed().as_secs() <= max_age_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet() -> Pubkey {
        Pubkey::new_unique()
    }

    #[test]
    fn issue_returns_nonce_and_phrase() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (nonce, phrase, curve) = registry.issue(wallet);
        assert_ne!(nonce, [0u8; 32]);
        assert!(!phrase.is_empty());
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 5, "phrase should be 5 words");
        assert!(curve.points == 200);
    }

    #[test]
    fn validate_and_consume_succeeds() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        assert!(registry.validate_and_consume(&wallet, &nonce, 60).is_ok());
    }

    #[test]
    fn peek_phrase_returns_issued_phrase() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (_, phrase, _) = registry.issue(wallet);
        assert_eq!(registry.peek_phrase(&wallet, 60).as_ref(), Some(&phrase));
    }

    #[test]
    fn peek_challenge_returns_issued_challenge() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (_, phrase, curve) = registry.issue(wallet);
        let (peeked_phrase, peeked_curve) = registry.peek_challenge(&wallet, 60).unwrap();
        assert_eq!(peeked_phrase, phrase);
        assert_eq!(peeked_curve, curve);
    }

    #[test]
    fn peek_phrase_returns_none_for_unknown_wallet() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        assert!(registry.peek_phrase(&wallet, 60).is_none());
    }

    #[test]
    fn peek_phrase_returns_none_for_stale_entry() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        registry.issue(wallet);

        if let Some(mut entry) = registry.entries.get_mut(&wallet) {
            entry.issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        assert!(registry.peek_phrase(&wallet, 60).is_none());
    }

    #[test]
    fn peek_phrase_does_not_consume() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        // Peeking multiple times leaves the entry consumable.
        assert!(registry.peek_phrase(&wallet, 60).is_some());
        assert!(registry.peek_phrase(&wallet, 60).is_some());
        assert!(registry.validate_and_consume(&wallet, &nonce, 60).is_ok());
    }

    #[test]
    fn validate_consumes_entry() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        registry.validate_and_consume(&wallet, &nonce, 60).unwrap();
        // Second use fails
        assert!(matches!(
            registry.validate_and_consume(&wallet, &nonce, 60),
            Err(ChallengeError::NotFound)
        ));
    }

    #[test]
    fn validate_wrong_nonce_fails() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        registry.issue(wallet);
        let wrong_nonce = [42u8; 32];
        assert!(matches!(
            registry.validate_and_consume(&wallet, &wrong_nonce, 60),
            Err(ChallengeError::NonceMismatch)
        ));
    }

    #[test]
    fn validate_unknown_wallet_fails() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let nonce = [1u8; 32];
        assert!(matches!(
            registry.validate_and_consume(&wallet, &nonce, 60),
            Err(ChallengeError::NotFound)
        ));
    }

    #[test]
    fn validate_expired_fails() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);

        // Manually age the entry
        if let Some(mut entry) = registry.entries.get_mut(&wallet) {
            entry.issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        assert!(matches!(
            registry.validate_and_consume(&wallet, &nonce, 60),
            Err(ChallengeError::Expired)
        ));
    }

    #[test]
    fn new_issue_overwrites_previous() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        let (nonce1, _, _) = registry.issue(wallet);
        let (nonce2, _, _) = registry.issue(wallet);
        // Old nonce is gone
        assert!(registry.validate_and_consume(&wallet, &nonce1, 60).is_err());
        // New nonce works
        assert!(registry.validate_and_consume(&wallet, &nonce2, 60).is_ok());
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        registry.issue(wallet);

        if let Some(mut entry) = registry.entries.get_mut(&wallet) {
            entry.issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        registry.evict_stale(60);
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let registry = ChallengeNonceRegistry::new();
        let wallet = test_wallet();
        registry.issue(wallet);
        registry.evict_stale(60);
        assert_eq!(registry.entries.len(), 1);
    }

    #[test]
    fn different_wallets_are_independent() {
        let registry = ChallengeNonceRegistry::new();
        let wallet1 = test_wallet();
        let wallet2 = test_wallet();
        let (nonce1, _, _) = registry.issue(wallet1);
        let (nonce2, _, _) = registry.issue(wallet2);
        assert!(registry.validate_and_consume(&wallet1, &nonce1, 60).is_ok());
        assert!(registry.validate_and_consume(&wallet2, &nonce2, 60).is_ok());
    }
}
