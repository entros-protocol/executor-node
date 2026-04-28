use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovernorLimiter};

type Limiter = GovernorLimiter<NotKeyed, InMemoryState, DefaultClock>;

const MAX_TRACKED_KEYS: usize = 10_000;
const ENTRY_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Per-API-key rate limiter using the GCRA algorithm.
/// Entries are evicted after 5 minutes of inactivity.
/// Bounded to MAX_TRACKED_KEYS to prevent memory exhaustion.
pub struct RateLimiter {
    limiters: DashMap<String, (Arc<Limiter>, Instant)>,
    quota: Quota,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        // `.max(1)` ensures the input is >= 1, so `NonZeroU32::new` cannot
        // return None on the outer call. The previous `.expect("literal 1")`
        // fallback was dead defensive code that would never execute.
        let clamped = requests_per_minute.max(1);
        let per_minute = NonZeroU32::new(clamped)
            .unwrap_or_else(|| unreachable!("clamped >= 1 by .max(1)"));
        let quota = Quota::per_minute(per_minute);
        Self {
            limiters: DashMap::new(),
            quota,
        }
    }

    /// Check if a request from the given API key is allowed.
    /// Evicts stale entries older than ENTRY_TTL on each call.
    pub fn check(&self, api_key: &str) -> Result<(), ()> {
        // Lazy eviction of stale entries
        self.limiters.retain(|_, (_, last_seen)| last_seen.elapsed() < ENTRY_TTL);

        if !self.limiters.contains_key(api_key) && self.limiters.len() >= MAX_TRACKED_KEYS {
            return Err(());
        }

        let mut limiter = self
            .limiters
            .entry(api_key.to_string())
            .or_insert_with(|| (Arc::new(GovernorLimiter::direct(self.quota)), Instant::now()));

        // Update last-seen timestamp
        limiter.1 = Instant::now();
        let lim = limiter.0.clone();
        drop(limiter);

        lim.check().map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(60);
        assert!(limiter.check("test_key").is_ok());
    }

    #[test]
    fn separate_keys_have_separate_limits() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("key_a").is_ok());
        assert!(limiter.check("key_b").is_ok());
    }
}
