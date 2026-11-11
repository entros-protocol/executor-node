use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

pub struct StatusMetrics {
    total_attestations_issued: AtomicU64,
    total_validations_performed: AtomicU64,
    /// Per-IP rate-limiter rejections. Increments on
    /// every 429 emitted by `per_ip_rate_limit_middleware`. Surfaced via
    /// the unauthenticated `/metrics` endpoint as a Prometheus counter so
    /// ops can monitor sustained-attack signals without log scraping.
    total_per_ip_rate_limit_rejected: AtomicU64,
    /// Paired opens whose otherwise valid authorization came from another client network than
    /// the one that fetched it. Counted while the rule is observed and while it is enforced.
    total_paired_authorization_network_mismatch: AtomicU64,
    /// Unsigned single-capture requests whose network had no challenge pointer, answered from
    /// the wallet's latest challenge instead.
    total_challenge_pointer_fallback: AtomicU64,
    start_time: u64,
    balance_cache: RwLock<(u64, u64)>, // (balance, fetched_at) — updated atomically
}

impl StatusMetrics {
    pub fn new() -> Self {
        Self {
            total_attestations_issued: AtomicU64::new(0),
            total_validations_performed: AtomicU64::new(0),
            total_per_ip_rate_limit_rejected: AtomicU64::new(0),
            total_paired_authorization_network_mismatch: AtomicU64::new(0),
            total_challenge_pointer_fallback: AtomicU64::new(0),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            balance_cache: RwLock::new((0, 0)),
        }
    }

    // increase total_attestations_issued by 1
    pub fn increment_attestations(&self) {
        self.total_attestations_issued
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_validations(&self) {
        self.total_validations_performed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_per_ip_rate_limit_rejected(&self) {
        self.total_per_ip_rate_limit_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_paired_authorization_network_mismatch(&self) {
        self.total_paired_authorization_network_mismatch
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_challenge_pointer_fallback(&self) {
        self.total_challenge_pointer_fallback
            .fetch_add(1, Ordering::Relaxed);
    }

    // getters for the metrics
    pub fn attestations_issued(&self) -> u64 {
        self.total_attestations_issued.load(Ordering::Relaxed)
    }

    pub fn validations_performed(&self) -> u64 {
        self.total_validations_performed.load(Ordering::Relaxed)
    }

    pub fn per_ip_rate_limit_rejected(&self) -> u64 {
        self.total_per_ip_rate_limit_rejected
            .load(Ordering::Relaxed)
    }

    pub fn paired_authorization_network_mismatch(&self) -> u64 {
        self.total_paired_authorization_network_mismatch
            .load(Ordering::Relaxed)
    }

    pub fn challenge_pointer_fallback(&self) -> u64 {
        self.total_challenge_pointer_fallback
            .load(Ordering::Relaxed)
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    pub fn cached_balance(&self) -> (u64, u64) {
        *self.balance_cache.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn update_cached_balance(&self, balance: u64, fetched_at: u64) {
        let mut cache = self
            .balance_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *cache = (balance, fetched_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let m = StatusMetrics::new();
        assert_eq!(m.attestations_issued(), 0);
        assert_eq!(m.validations_performed(), 0);
        assert_eq!(m.per_ip_rate_limit_rejected(), 0);
    }

    #[test]
    fn increment_per_ip_rate_limit_rejected_counts_correctly() {
        let m = StatusMetrics::new();
        m.increment_per_ip_rate_limit_rejected();
        m.increment_per_ip_rate_limit_rejected();
        m.increment_per_ip_rate_limit_rejected();
        assert_eq!(m.per_ip_rate_limit_rejected(), 3);
        // Other counters untouched.
        assert_eq!(m.attestations_issued(), 0);
        assert_eq!(m.validations_performed(), 0);
    }

    #[test]
    fn counters_are_independent() {
        let m = StatusMetrics::new();
        m.increment_validations();
        m.increment_validations();
        m.increment_attestations();
        assert_eq!(m.validations_performed(), 2);
        assert_eq!(m.attestations_issued(), 1);
        assert_eq!(m.per_ip_rate_limit_rejected(), 0);
    }

    #[test]
    fn the_rollout_counters_count_independently() {
        let m = StatusMetrics::new();
        assert_eq!(m.paired_authorization_network_mismatch(), 0);
        assert_eq!(m.challenge_pointer_fallback(), 0);
        m.increment_paired_authorization_network_mismatch();
        m.increment_challenge_pointer_fallback();
        m.increment_challenge_pointer_fallback();
        assert_eq!(m.paired_authorization_network_mismatch(), 1);
        assert_eq!(m.challenge_pointer_fallback(), 2);
        assert_eq!(m.per_ip_rate_limit_rejected(), 0);
    }

    #[test]
    fn start_time_is_recent() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let m = StatusMetrics::new();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(m.start_time() >= before);
        assert!(m.start_time() <= after);
    }

    #[test]
    fn balance_cache_starts_empty() {
        let m = StatusMetrics::new();
        assert_eq!(m.cached_balance(), (0, 0));
    }

    #[test]
    fn balance_cache_updates_atomically() {
        let m = StatusMetrics::new();
        m.update_cached_balance(123, 456);
        let (balance, fetched_at) = m.cached_balance();
        assert_eq!(balance, 123);
        assert_eq!(fetched_at, 456);
    }
}
