use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

pub struct StatusMetrics {
    total_verifications_relayed: AtomicU64,
    total_attestations_issued: AtomicU64,
    total_validations_performed: AtomicU64,
    /// Per-IP rate-limiter rejections (master-list #155). Increments on
    /// every 429 emitted by `per_ip_rate_limit_middleware`. Surfaced via
    /// the unauthenticated `/metrics` endpoint as a Prometheus counter so
    /// ops can monitor sustained-attack signals without log scraping.
    total_per_ip_rate_limit_rejected: AtomicU64,
    start_time: u64,
    balance_cache: RwLock<(u64, u64)>, // (balance, fetched_at) — updated atomically
}

impl StatusMetrics {
    pub fn new() -> Self {
        Self {
            total_verifications_relayed: AtomicU64::new(0),
            total_attestations_issued: AtomicU64::new(0),
            total_validations_performed: AtomicU64::new(0),
            total_per_ip_rate_limit_rejected: AtomicU64::new(0),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            balance_cache: RwLock::new((0, 0)),
        }
    }

    // increase total_verifications_relayed by 1
    pub fn increment_verifications(&self) {
        self.total_verifications_relayed
            .fetch_add(1, Ordering::Relaxed);
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

    // getters for the metrics
    pub fn verifications_relayed(&self) -> u64 {
        self.total_verifications_relayed.load(Ordering::Relaxed)
    }

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
        assert_eq!(m.verifications_relayed(), 0);
        assert_eq!(m.attestations_issued(), 0);
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
        assert_eq!(m.verifications_relayed(), 0);
        assert_eq!(m.attestations_issued(), 0);
        assert_eq!(m.validations_performed(), 0);
    }

    #[test]
    fn increment_verifications_counts_correctly() {
        let m = StatusMetrics::new();
        m.increment_verifications();
        m.increment_verifications();
        assert_eq!(m.verifications_relayed(), 2);
        assert_eq!(m.attestations_issued(), 0);
    }

    #[test]
    fn increment_attestations_counts_correctly() {
        let m = StatusMetrics::new();
        m.increment_attestations();
        assert_eq!(m.attestations_issued(), 1);
        assert_eq!(m.verifications_relayed(), 0);
    }

    #[test]
    fn counters_are_independent() {
        let m = StatusMetrics::new();
        m.increment_verifications();
        m.increment_verifications();
        m.increment_attestations();
        assert_eq!(m.verifications_relayed(), 2);
        assert_eq!(m.attestations_issued(), 1);
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
