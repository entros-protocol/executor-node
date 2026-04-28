use dashmap::DashMap;
use std::collections::HashSet;
use std::time::Instant;

/// Maximum commitments tracked per API key before oldest entries are evicted.
const MAX_COMMITMENTS_PER_KEY: usize = 10_000;

/// TTL for commitment entries. After this duration without new activity,
/// the entire key's commitment set is eligible for eviction.
const ENTRY_TTL_SECS: u64 = 3600; // 1 hour

struct CommitmentEntry {
    commitments: HashSet<[u8; 32]>,
    last_activity: Instant,
}

/// Tracks seen commitments per API key to prevent clients from replaying
/// `is_first_verification: true` to bypass proof verification.
///
/// In-memory for devnet. Resets on restart (acceptable — worst case, a
/// known commitment re-registers as first verification, which returns
/// `registered: true, verified: null` rather than `verified: true`).
pub struct CommitmentRegistry {
    entries: DashMap<String, CommitmentEntry>,
}

impl CommitmentRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Atomically check if a commitment is known and record it if not.
    /// Returns true if the commitment was already known (re-verification required).
    pub fn check_and_record(&self, api_key: &str, commitment: [u8; 32]) -> bool {
        let mut entry = self.entries.entry(api_key.to_string()).or_insert_with(|| {
            CommitmentEntry {
                commitments: HashSet::new(),
                last_activity: Instant::now(),
            }
        });

        entry.last_activity = Instant::now();

        if entry.commitments.contains(&commitment) {
            return true;
        }

        // Evict oldest entries if at capacity
        if entry.commitments.len() >= MAX_COMMITMENTS_PER_KEY {
            entry.commitments.clear();
            tracing::warn!(
                api_key = %crate::auth::redact::redact_api_key(api_key),
                "Commitment registry evicted all entries for key (capacity reached)"
            );
        }

        entry.commitments.insert(commitment);
        false
    }

    /// Evict stale entries that haven't seen activity within the TTL.
    /// Called periodically (e.g., from a background task).
    pub fn evict_stale(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            now.duration_since(entry.last_activity).as_secs() < ENTRY_TTL_SECS
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_commitment_returns_false() {
        let registry = CommitmentRegistry::new();
        let commitment = [42u8; 32];
        assert!(!registry.check_and_record("key1", commitment));
    }

    #[test]
    fn known_commitment_returns_true() {
        let registry = CommitmentRegistry::new();
        let commitment = [42u8; 32];
        registry.check_and_record("key1", commitment);
        assert!(registry.check_and_record("key1", commitment));
    }

    #[test]
    fn different_keys_are_independent() {
        let registry = CommitmentRegistry::new();
        let commitment = [42u8; 32];
        registry.check_and_record("key1", commitment);
        assert!(!registry.check_and_record("key2", commitment));
    }

    #[test]
    fn different_commitments_are_independent() {
        let registry = CommitmentRegistry::new();
        registry.check_and_record("key1", [1u8; 32]);
        assert!(!registry.check_and_record("key1", [2u8; 32]));
    }

    #[test]
    fn evicts_stale_entries() {
        let registry = CommitmentRegistry::new();
        registry.check_and_record("key1", [1u8; 32]);

        // Manually age the entry
        if let Some(mut entry) = registry.entries.get_mut("key1") {
            entry.last_activity = Instant::now() - std::time::Duration::from_secs(ENTRY_TTL_SECS + 1);
        }

        registry.evict_stale();
        // After eviction, commitment is no longer known
        assert!(!registry.check_and_record("key1", [1u8; 32]));
    }
}
