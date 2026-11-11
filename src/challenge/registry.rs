use dashmap::DashMap;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
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

/// Selects a challenge for a client that does not name its nonce.
///
/// A pointer outlives the challenge it selects, as a marker, for two challenge lifetimes.
/// While it stands, its network is answered from that challenge or told it expired, and is
/// never handed another network's challenge.
struct Pointer {
    nonce: [u8; 32],
    set_at: Instant,
}

#[derive(Default)]
struct WalletChallenges {
    /// The latest nonce issued to each client network.
    current_by_origin: HashMap<IpAddr, Pointer>,
    /// The latest nonce issued to the wallet from any network. It answers a network that
    /// asked for no challenge, such as a client whose address changed after asking.
    latest: Option<Pointer>,
    by_nonce: HashMap<[u8; 32], NonceEntry>,
}

/// Which pointer selected a peeked challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerSource {
    /// The pointer of the network the request came from.
    Network,
    /// The wallet's latest challenge, because the request's network had no pointer.
    Wallet,
}

/// Server-side challenge nonce registry. Issues nonces for wallet-connected
/// verifications and consumes them before projection 2 forwarding or
/// attestation. The bounded lifetime prevents challenge pre-computation.
///
/// Each wallet retains its unexpired nonce entries. A client that names its nonce is
/// checked against exactly that entry. For a client that does not, a pointer per client
/// network selects the latest entry that network asked for. `/challenge` needs no wallet
/// signature, so a network's own pointer always wins: no other caller can replace the
/// phrase a network is about to be checked against. Only a network with no pointer falls
/// back to the wallet's latest entry. In-memory state resets on restart, so clients must
/// request a new challenge.
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
    /// Moves the pointer of the requesting client network and the wallet's latest pointer
    /// without removing earlier unexpired entries.
    /// Returns the nonce bytes, the generated phrase, and the Lissajous curve;
    /// all travel back to the client via the `/challenge` response.
    pub fn issue(&self, wallet: Pubkey, origin: IpAddr) -> ([u8; 32], String, LissajousParams) {
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
        let now = Instant::now();
        wallet_challenges.by_nonce.insert(
            nonce,
            NonceEntry {
                phrase: phrase.clone(),
                curve: curve.clone(),
                issued_at: now,
            },
        );
        wallet_challenges
            .current_by_origin
            .insert(origin, Pointer { nonce, set_at: now });
        wallet_challenges.latest = Some(Pointer { nonce, set_at: now });
        (nonce, phrase, curve)
    }

    /// Look up, without consuming it, the challenge for a client that does not name its
    /// nonce. The network's own pointer comes first, and while it stands its answer is final:
    /// `None` once its challenge expired or was used. Only a network with no pointer is
    /// answered from the wallet's latest challenge.
    pub fn peek_challenge(
        &self,
        wallet: &Pubkey,
        origin: IpAddr,
    ) -> Option<(String, LissajousParams, PointerSource)> {
        let wallet_challenges = self.entries.get(wallet)?;
        let (pointer, source) = match wallet_challenges
            .current_by_origin
            .get(&origin)
            .filter(|pointer| self.marks(pointer))
        {
            Some(pointer) => (pointer, PointerSource::Network),
            None => (
                wallet_challenges
                    .latest
                    .as_ref()
                    .filter(|pointer| self.marks(pointer))?,
                PointerSource::Wallet,
            ),
        };
        let entry = wallet_challenges.by_nonce.get(&pointer.nonce)?;
        let (phrase, curve) = self.clone_if_fresh(entry)?;
        Some((phrase, curve, source))
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

    /// True while a pointer still stands for its network, as a selector or as a marker.
    fn marks(&self, pointer: &Pointer) -> bool {
        pointer.set_at.elapsed().as_secs() <= self.ttl_secs.saturating_mul(2)
    }

    /// Validate and atomically consume one nonce. Concurrent calls can consume a
    /// nonce only once. Pointers to it stay as markers, so the network that asked for it
    /// is not answered from another network's challenge afterwards.
    pub fn validate_and_consume_exact(
        &self,
        wallet: &Pubkey,
        nonce: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        use dashmap::mapref::entry::Entry;

        let Entry::Occupied(mut occupied) = self.entries.entry(*wallet) else {
            return Err(ChallengeError::NotFound);
        };
        let wallet_challenges = occupied.get_mut();
        let Some(entry) = wallet_challenges.by_nonce.remove(nonce) else {
            return Err(ChallengeError::NonceMismatch);
        };
        let expired = entry.issued_at.elapsed().as_secs() > self.ttl_secs;
        self.prune_stale_wallet(wallet_challenges);
        if Self::is_empty(wallet_challenges) {
            occupied.remove();
        }

        if expired {
            Err(ChallengeError::Expired)
        } else {
            Ok(())
        }
    }

    /// Evict stale nonce entries and lapsed pointers, and remove empty wallets.
    pub fn evict_stale(&self) {
        self.entries.retain(|_, wallet_challenges| {
            self.prune_stale_wallet(wallet_challenges);
            !Self::is_empty(wallet_challenges)
        });
    }

    fn prune_stale_wallet(&self, wallet_challenges: &mut WalletChallenges) {
        wallet_challenges
            .by_nonce
            .retain(|_, entry| entry.issued_at.elapsed().as_secs() <= self.ttl_secs);
        wallet_challenges
            .current_by_origin
            .retain(|_, pointer| self.marks(pointer));
        if wallet_challenges
            .latest
            .as_ref()
            .is_some_and(|pointer| !self.marks(pointer))
        {
            wallet_challenges.latest = None;
        }
    }

    fn is_empty(wallet_challenges: &WalletChallenges) -> bool {
        wallet_challenges.by_nonce.is_empty()
            && wallet_challenges.current_by_origin.is_empty()
            && wallet_challenges.latest.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const ORIGIN: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const OTHER_ORIGIN: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    const THIRD_ORIGIN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33));

    fn test_wallet() -> Pubkey {
        Pubkey::new_unique()
    }

    /// Moves one challenge back in time by `secs`.
    fn age_challenge(
        registry: &ChallengeNonceRegistry,
        wallet: &Pubkey,
        nonce: &[u8; 32],
        secs: u64,
    ) {
        let mut wallet_challenges = registry.entries.get_mut(wallet).expect("wallet");
        let entry = wallet_challenges
            .by_nonce
            .get_mut(nonce)
            .expect("challenge");
        entry.issued_at -= Duration::from_secs(secs);
    }

    /// Moves every pointer of a wallet back in time by `secs`.
    fn age_pointers(registry: &ChallengeNonceRegistry, wallet: &Pubkey, secs: u64) {
        let mut wallet_challenges = registry.entries.get_mut(wallet).expect("wallet");
        for pointer in wallet_challenges.current_by_origin.values_mut() {
            pointer.set_at -= Duration::from_secs(secs);
        }
        if let Some(latest) = wallet_challenges.latest.as_mut() {
            latest.set_at -= Duration::from_secs(secs);
        }
    }

    fn age_everything(
        registry: &ChallengeNonceRegistry,
        wallet: &Pubkey,
        nonce: &[u8; 32],
        secs: u64,
    ) {
        age_challenge(registry, wallet, nonce, secs);
        age_pointers(registry, wallet, secs);
    }

    #[test]
    fn issue_returns_nonce_and_phrase() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, phrase, curve) = registry.issue(wallet, ORIGIN);
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
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        assert!(registry.validate_and_consume_exact(&wallet, &nonce).is_ok());
    }

    #[test]
    fn peek_challenge_returns_issued_challenge() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (_, phrase, curve) = registry.issue(wallet, ORIGIN);
        assert_eq!(
            registry.peek_challenge(&wallet, ORIGIN),
            Some((phrase, curve, PointerSource::Network))
        );
    }

    #[test]
    fn peek_challenge_returns_none_for_unknown_wallet() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_none());
    }

    #[test]
    fn peek_challenge_returns_none_for_stale_entry() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        age_challenge(&registry, &wallet, &nonce, 120);
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_none());
    }

    #[test]
    fn peek_challenge_does_not_consume() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        // Peeking multiple times leaves the entry consumable.
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_some());
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_some());
        assert!(registry.validate_and_consume_exact(&wallet, &nonce).is_ok());
    }

    #[test]
    fn validate_consumes_entry() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        registry
            .validate_and_consume_exact(&wallet, &nonce)
            .unwrap();
        // Second use fails
        assert!(registry
            .validate_and_consume_exact(&wallet, &nonce)
            .is_err());
    }

    #[test]
    fn validate_wrong_nonce_fails() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        registry.issue(wallet, ORIGIN);
        let wrong_nonce = [42u8; 32];
        assert!(matches!(
            registry.validate_and_consume_exact(&wallet, &wrong_nonce),
            Err(ChallengeError::NonceMismatch)
        ));
    }

    #[test]
    fn validate_unknown_wallet_fails() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let nonce = [1u8; 32];
        assert!(matches!(
            registry.validate_and_consume_exact(&wallet, &nonce),
            Err(ChallengeError::NotFound)
        ));
    }

    #[test]
    fn validate_expired_fails() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        age_challenge(&registry, &wallet, &nonce, 120);
        assert!(matches!(
            registry.validate_and_consume_exact(&wallet, &nonce),
            Err(ChallengeError::Expired)
        ));
    }

    #[test]
    fn a_later_issue_from_one_network_moves_that_network_pointer() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce1, _, _) = registry.issue(wallet, ORIGIN);
        let (_, phrase2, curve2) = registry.issue(wallet, ORIGIN);
        assert_eq!(
            registry.peek_challenge(&wallet, ORIGIN),
            Some((phrase2, curve2, PointerSource::Network))
        );
        // Moving the pointer does not delete the earlier nonce.
        assert!(registry
            .validate_and_consume_exact(&wallet, &nonce1)
            .is_ok());
    }

    /// `/challenge` needs no wallet signature. A call from another network must not
    /// replace the phrase this network is about to be checked against.
    #[test]
    fn an_issue_from_another_network_leaves_this_network_pointer() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (_, phrase, curve) = registry.issue(wallet, ORIGIN);
        let (_, other_phrase, other_curve) = registry.issue(wallet, OTHER_ORIGIN);

        assert_eq!(
            registry.peek_challenge(&wallet, ORIGIN),
            Some((phrase, curve, PointerSource::Network))
        );
        assert_eq!(
            registry.peek_challenge(&wallet, OTHER_ORIGIN),
            Some((other_phrase, other_curve, PointerSource::Network))
        );
    }

    /// A client whose address changed after `/challenge` is answered from the wallet's latest
    /// challenge, from whichever network asked for it.
    #[test]
    fn a_network_that_asked_for_no_challenge_gets_the_wallets_latest() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        registry.issue(wallet, ORIGIN);
        let (_, latest_phrase, latest_curve) = registry.issue(wallet, OTHER_ORIGIN);
        assert_eq!(
            registry.peek_challenge(&wallet, THIRD_ORIGIN),
            Some((latest_phrase, latest_curve, PointerSource::Wallet))
        );
    }

    /// A network that asked for a challenge keeps answering from it, and its expiry is the
    /// answer. It never receives another network's challenge.
    #[test]
    fn an_expired_challenge_answers_expired_and_never_another_networks() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        age_everything(&registry, &wallet, &nonce, 61);
        registry.issue(wallet, OTHER_ORIGIN);
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_none());

        // The marker survives eviction while it is within two challenge lifetimes.
        registry.evict_stale();
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_none());
    }

    #[test]
    fn a_pointer_marker_lapses_after_two_challenge_lifetimes() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        age_everything(&registry, &wallet, &nonce, 121);
        let (_, phrase, curve) = registry.issue(wallet, OTHER_ORIGIN);
        assert_eq!(
            registry.peek_challenge(&wallet, ORIGIN),
            Some((phrase, curve, PointerSource::Wallet))
        );
    }

    #[test]
    fn consuming_a_nonce_keeps_its_network_from_falling_back() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        registry.issue(wallet, OTHER_ORIGIN);
        registry
            .validate_and_consume_exact(&wallet, &nonce)
            .unwrap();
        assert!(registry.peek_challenge(&wallet, ORIGIN).is_none());
        assert!(registry.peek_challenge(&wallet, OTHER_ORIGIN).is_some());
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
        age_everything(&registry, &wallet, &nonce, 121);
        registry.evict_stale();
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        registry.issue(wallet, ORIGIN);
        registry.evict_stale();
        assert_eq!(registry.entries.len(), 1);
    }

    #[test]
    fn different_wallets_are_independent() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet1 = test_wallet();
        let wallet2 = test_wallet();
        let (nonce1, _, _) = registry.issue(wallet1, ORIGIN);
        let (nonce2, _, _) = registry.issue(wallet2, ORIGIN);
        assert!(registry
            .validate_and_consume_exact(&wallet1, &nonce1)
            .is_ok());
        assert!(registry
            .validate_and_consume_exact(&wallet2, &nonce2)
            .is_ok());
        assert!(registry.peek_challenge(&wallet1, OTHER_ORIGIN).is_none());
    }

    #[test]
    fn exact_nonce_survives_a_later_issue_without_moving_the_pointer() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (nonce1, phrase1, curve1) = registry.issue(wallet, ORIGIN);
        let (nonce2, phrase2, curve2) = registry.issue(wallet, ORIGIN);

        assert_eq!(
            registry.peek_exact_challenge(&wallet, &nonce1),
            Some((phrase1, curve1))
        );
        assert!(registry
            .validate_and_consume_exact(&wallet, &nonce1)
            .is_ok());
        assert_eq!(
            registry.peek_challenge(&wallet, ORIGIN),
            Some((phrase2, curve2, PointerSource::Network))
        );
        assert!(registry
            .validate_and_consume_exact(&wallet, &nonce2)
            .is_ok());
    }

    #[test]
    fn exact_nonce_concurrent_replay_succeeds_once() {
        use std::sync::{Arc, Barrier};

        let registry = Arc::new(ChallengeNonceRegistry::new(60));
        let wallet = test_wallet();
        let (nonce, _, _) = registry.issue(wallet, ORIGIN);
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
        let (stale_nonce, _, _) = registry.issue(wallet, ORIGIN);
        let (fresh_nonce, fresh_phrase, fresh_curve) = registry.issue(wallet, ORIGIN);
        age_challenge(&registry, &wallet, &stale_nonce, 120);

        registry.evict_stale();
        assert!(registry
            .peek_exact_challenge(&wallet, &stale_nonce)
            .is_none());
        assert_eq!(
            registry.peek_challenge(&wallet, ORIGIN),
            Some((fresh_phrase, fresh_curve, PointerSource::Network))
        );
        assert_eq!(registry.entries.get(&wallet).unwrap().by_nonce.len(), 1);

        age_everything(&registry, &wallet, &fresh_nonce, 121);
        registry.evict_stale();
        assert!(!registry.entries.contains_key(&wallet));
    }

    #[test]
    fn issue_prunes_stale_nonces_without_evicting_live_entries() {
        let registry = ChallengeNonceRegistry::new(60);
        let wallet = test_wallet();
        let (stale_nonce, _, _) = registry.issue(wallet, ORIGIN);
        let (live_nonce, live_phrase, live_curve) = registry.issue(wallet, ORIGIN);
        age_challenge(&registry, &wallet, &stale_nonce, 120);

        let (new_nonce, _, _) = registry.issue(wallet, ORIGIN);

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
