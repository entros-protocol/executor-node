use dashmap::DashMap;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use crate::challenge::lissajous::LissajousParams;
use crate::challenge::phrase_gen;

struct NonceEntry {
    /// Server-issued challenge phrase (5 words drawn from the curated
    /// dictionary at `src/challenge/word_dict.rs`) bound to this nonce for
    /// spoken-content binding. The client displays this phrase, and validation
    /// resolves it by nonce before requesting a word-level content match.
    phrase: String,
    /// Server-issued Lissajous curve parameters for the touch challenge.
    curve: LissajousParams,
    issued_at: Instant,
}

#[derive(Default)]
struct WalletChallenges {
    current_legacy_nonce: Option<[u8; 32]>,
    by_nonce: HashMap<[u8; 32], NonceEntry>,
}

/// Server-side challenge nonce registry. Issues nonces for wallet-connected
/// verifications and consumes them before projection 2 forwarding or
/// attestation. The bounded lifetime prevents challenge pre-computation.
///
/// Each wallet retains its unexpired nonce entries. A separate pointer selects
/// the latest entry for clients that do not address challenges by nonce.
/// In-memory state resets on restart, so clients must request a new challenge.
pub struct ChallengeNonceRegistry {
    entries: DashMap<Pubkey, WalletChallenges>,
    ttl_secs: u64,
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
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: DashMap::new(),
            ttl_secs,
        }
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Issue a new challenge nonce, phrase, and curve for the given wallet.
    /// Moves the legacy pointer without removing earlier unexpired entries.
    /// Returns the nonce bytes, the generated phrase, and the Lissajous curve;
    /// all travel back to the client via the `/challenge` response.
    pub fn issue(&self, wallet: Pubkey) -> ([u8; 32], String, LissajousParams) {
        let phrase = phrase_gen::generate_phrase(5);
        let curve = LissajousParams::generate();
        let mut wallet_challenges = self.entries.entry(wallet).or_default();
        self.prune_stale_wallet(&mut wallet_challenges);
        let nonce = loop {
            let candidate: [u8; 32] = rand::random();
            if !wallet_challenges.by_nonce.contains_key(&candidate) {
                break candidate;
            }
        };
        wallet_challenges.by_nonce.insert(
            nonce,
            NonceEntry {
                phrase: phrase.clone(),
                curve: curve.clone(),
                issued_at: Instant::now(),
            },
        );
        wallet_challenges.current_legacy_nonce = Some(nonce);
        (nonce, phrase, curve)
    }

    /// Look up the phrase and curve selected by the legacy pointer without
    /// consuming them. Returns `None` when the pointer is empty or stale.
    pub fn peek_challenge(&self, wallet: &Pubkey) -> Option<(String, LissajousParams)> {
        let wallet_challenges = self.entries.get(wallet)?;
        let nonce = wallet_challenges.current_legacy_nonce?;
        let entry = wallet_challenges.by_nonce.get(&nonce)?;
        self.clone_if_fresh(entry)
    }

    /// Look up one nonce-bound phrase and curve without consuming it.
    pub fn peek_exact_challenge(
        &self,
        wallet: &Pubkey,
        nonce: &[u8; 32],
    ) -> Option<(String, LissajousParams)> {
        let wallet_challenges = self.entries.get(wallet)?;
        let entry = wallet_challenges.by_nonce.get(nonce)?;
        self.clone_if_fresh(entry)
    }

    fn clone_if_fresh(&self, entry: &NonceEntry) -> Option<(String, LissajousParams)> {
        if entry.issued_at.elapsed().as_secs() > self.ttl_secs {
            return None;
        }
        Some((entry.phrase.clone(), entry.curve.clone()))
    }

    /// Validate and consume the nonce selected by the legacy pointer.
    /// A later issue moves that pointer, so earlier clients retain overwrite
    /// behavior. Concurrent calls can consume the selected nonce only once.
    pub fn validate_and_consume(
        &self,
        wallet: &Pubkey,
        nonce: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.consume(wallet, nonce, true)
    }

    /// Validate and atomically consume one nonce, independent of the legacy
    /// pointer. Concurrent calls can consume a nonce only once.
    pub fn validate_and_consume_exact(
        &self,
        wallet: &Pubkey,
        nonce: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.consume(wallet, nonce, false)
    }

    fn consume(
        &self,
        wallet: &Pubkey,
        nonce: &[u8; 32],
        require_current_legacy_nonce: bool,
    ) -> Result<(), ChallengeError> {
        use dashmap::mapref::entry::Entry;

        let Entry::Occupied(mut occupied) = self.entries.entry(*wallet) else {
            return Err(ChallengeError::NotFound);
        };
        let wallet_challenges = occupied.get_mut();
        if require_current_legacy_nonce {
            match wallet_challenges.current_legacy_nonce {
                Some(current) if current == *nonce => {}
                Some(_) => return Err(ChallengeError::NonceMismatch),
                None => return Err(ChallengeError::NotFound),
            }
        }
        let Some(entry) = wallet_challenges.by_nonce.remove(nonce) else {
            return Err(ChallengeError::NonceMismatch);
        };
        if wallet_challenges.current_legacy_nonce == Some(*nonce) {
            wallet_challenges.current_legacy_nonce = None;
        }
        let remove_wallet = wallet_challenges.by_nonce.is_empty();
        let expired = entry.issued_at.elapsed().as_secs() > self.ttl_secs;
        if remove_wallet {
            occupied.remove();
        }

        if expired {
            Err(ChallengeError::Expired)
        } else {
            Ok(())
        }
    }

    /// Evict stale nonce entries, clear stale pointers, and remove empty wallets.
    pub fn evict_stale(&self) {
        self.entries.retain(|_, wallet_challenges| {
            self.prune_stale_wallet(wallet_challenges);
            !wallet_challenges.by_nonce.is_empty()
        });
    }

    fn prune_stale_wallet(&self, wallet_challenges: &mut WalletChallenges) {
        wallet_challenges
            .by_nonce
            .retain(|_, entry| entry.issued_at.elapsed().as_secs() <= self.ttl_secs);
        if wallet_challenges
            .current_legacy_nonce
            .is_some_and(|nonce| !wallet_challenges.by_nonce.contains_key(&nonce))
        {
            wallet_challenges.current_legacy_nonce = None;
        }
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
        let registry = ChallengeNonceRegistry::new(60);
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
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        assert!(registry.validate_and_consume(&wallet, &nonce).is_ok());
    }

    #[test]
    fn peek_challenge_returns_issued_challenge() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (_, phrase, curve) = registry.issue(wallet);
        let (peeked_phrase, peeked_curve) = registry.peek_challenge(&wallet).unwrap();
        assert_eq!(peeked_phrase, phrase);
        assert_eq!(peeked_curve, curve);
    }

    #[test]
    fn peek_challenge_returns_none_for_unknown_wallet() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        assert!(registry.peek_challenge(&wallet).is_none());
    }

    #[test]
    fn peek_challenge_returns_none_for_stale_entry() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);

        if let Some(mut wallet_challenges) = registry.entries.get_mut(&wallet) {
            wallet_challenges
                .by_nonce
                .get_mut(&nonce)
                .unwrap()
                .issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        assert!(registry.peek_challenge(&wallet).is_none());
    }

    #[test]
    fn peek_challenge_does_not_consume() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        // Peeking multiple times leaves the entry consumable.
        assert!(registry.peek_challenge(&wallet).is_some());
        assert!(registry.peek_challenge(&wallet).is_some());
        assert!(registry.validate_and_consume(&wallet, &nonce).is_ok());
    }

    #[test]
    fn validate_consumes_entry() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        registry.validate_and_consume(&wallet, &nonce).unwrap();
        // Second use fails
        assert!(matches!(
            registry.validate_and_consume(&wallet, &nonce),
            Err(ChallengeError::NotFound)
        ));
    }

    #[test]
    fn validate_wrong_nonce_fails() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        registry.issue(wallet);
        let wrong_nonce = [42u8; 32];
        assert!(matches!(
            registry.validate_and_consume(&wallet, &wrong_nonce),
            Err(ChallengeError::NonceMismatch)
        ));
    }

    #[test]
    fn validate_unknown_wallet_fails() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let nonce = [1u8; 32];
        assert!(matches!(
            registry.validate_and_consume(&wallet, &nonce),
            Err(ChallengeError::NotFound)
        ));
    }

    #[test]
    fn validate_expired_fails() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);

        if let Some(mut wallet_challenges) = registry.entries.get_mut(&wallet) {
            wallet_challenges
                .by_nonce
                .get_mut(&nonce)
                .unwrap()
                .issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        assert!(matches!(
            registry.validate_and_consume(&wallet, &nonce),
            Err(ChallengeError::Expired)
        ));
    }

    #[test]
    fn new_issue_moves_the_legacy_pointer() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce1, _, _) = registry.issue(wallet);
        let (nonce2, _, _) = registry.issue(wallet);
        // Legacy callers can use only the latest issue.
        assert!(registry.validate_and_consume(&wallet, &nonce1).is_err());
        assert!(registry.validate_and_consume(&wallet, &nonce2).is_ok());
        // Moving the pointer does not delete the earlier nonce.
        assert!(registry
            .validate_and_consume_exact(&wallet, &nonce1)
            .is_ok());
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);

        if let Some(mut wallet_challenges) = registry.entries.get_mut(&wallet) {
            wallet_challenges
                .by_nonce
                .get_mut(&nonce)
                .unwrap()
                .issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        registry.evict_stale();
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        registry.issue(wallet);
        registry.evict_stale();
        assert_eq!(registry.entries.len(), 1);
    }

    #[test]
    fn different_wallets_are_independent() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet1 = test_wallet();
        let wallet2 = test_wallet();
        let (nonce1, _, _) = registry.issue(wallet1);
        let (nonce2, _, _) = registry.issue(wallet2);
        assert!(registry.validate_and_consume(&wallet1, &nonce1).is_ok());
        assert!(registry.validate_and_consume(&wallet2, &nonce2).is_ok());
    }

    #[test]
    fn exact_nonce_survives_a_later_issue_without_moving_the_legacy_pointer() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce1, phrase1, curve1) = registry.issue(wallet);
        let (nonce2, phrase2, curve2) = registry.issue(wallet);

        assert_eq!(
            registry.peek_exact_challenge(&wallet, &nonce1),
            Some((phrase1, curve1))
        );
        assert!(registry
            .validate_and_consume_exact(&wallet, &nonce1)
            .is_ok());
        assert_eq!(registry.peek_challenge(&wallet), Some((phrase2, curve2)));
        assert!(registry.validate_and_consume(&wallet, &nonce2).is_ok());
    }

    #[test]
    fn exact_nonce_concurrent_replay_succeeds_once() {
        use std::sync::{Arc, Barrier};

        let registry = Arc::new(ChallengeNonceRegistry::new(60));
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet);
        let barrier = Arc::new(Barrier::new(17));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                registry.validate_and_consume_exact(&wallet, &nonce).is_ok()
            }));
        }
        barrier.wait();

        let successes = threads
            .into_iter()
            .map(|thread| thread.join().expect("replay worker does not panic"))
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn stale_eviction_keeps_fresh_nonces_then_removes_the_empty_wallet() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (stale_nonce, _, _) = registry.issue(wallet);
        let (fresh_nonce, fresh_phrase, fresh_curve) = registry.issue(wallet);
        if let Some(mut wallet_challenges) = registry.entries.get_mut(&wallet) {
            wallet_challenges
                .by_nonce
                .get_mut(&stale_nonce)
                .unwrap()
                .issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        registry.evict_stale();
        assert!(registry
            .peek_exact_challenge(&wallet, &stale_nonce)
            .is_none());
        assert_eq!(
            registry.peek_challenge(&wallet),
            Some((fresh_phrase, fresh_curve))
        );
        assert_eq!(registry.entries.get(&wallet).unwrap().by_nonce.len(), 1);

        if let Some(mut wallet_challenges) = registry.entries.get_mut(&wallet) {
            wallet_challenges
                .by_nonce
                .get_mut(&fresh_nonce)
                .unwrap()
                .issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }
        registry.evict_stale();
        assert!(!registry.entries.contains_key(&wallet));
    }

    #[test]
    fn issue_prunes_stale_nonces_without_evicting_live_entries() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (stale_nonce, _, _) = registry.issue(wallet);
        let (live_nonce, live_phrase, live_curve) = registry.issue(wallet);
        if let Some(mut wallet_challenges) = registry.entries.get_mut(&wallet) {
            wallet_challenges
                .by_nonce
                .get_mut(&stale_nonce)
                .unwrap()
                .issued_at = Instant::now() - std::time::Duration::from_secs(120);
        }

        let (new_nonce, _, _) = registry.issue(wallet);

        let wallet_challenges = registry.entries.get(&wallet).unwrap();
        assert_eq!(wallet_challenges.by_nonce.len(), 2);
        assert!(!wallet_challenges.by_nonce.contains_key(&stale_nonce));
        assert!(wallet_challenges.by_nonce.contains_key(&live_nonce));
        assert!(wallet_challenges.by_nonce.contains_key(&new_nonce));
        drop(wallet_challenges);
        assert_eq!(
            registry.peek_exact_challenge(&wallet, &live_nonce),
            Some((live_phrase, live_curve))
        );
    }
}
