use std::net::IpAddr;
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

/// Per-IP cap is keyed on a much larger address space than per-API-key
/// (a single integrator may serve many client IPs), so the bound is
/// proportionally larger. 50k IPv4 entries × ~100 bytes ≈ 5MB — fine
/// for an executor process.
const MAX_TRACKED_IPS: usize = 50_000;
const IP_ENTRY_TTL: Duration = Duration::from_secs(300); // 5 minutes

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
        let per_minute =
            NonZeroU32::new(clamped).unwrap_or_else(|| unreachable!("clamped >= 1 by .max(1)"));
        let quota = Quota::per_minute(per_minute);
        Self {
            limiters: DashMap::new(),
            quota,
        }
    }

    /// Check if a request from the given API key is allowed.
    ///
    /// Eviction of stale entries is performed by `evict_stale()` from a
    /// background task, NOT inside `check()`. The previous per-request
    /// `retain()` was a contention hotspot under high concurrency: two
    /// threads racing through the entry-creation path could both pass the
    /// `MAX_TRACKED_KEYS` guard and grow the map past the cap.
    pub fn check(&self, api_key: &str) -> Result<(), ()> {
        if !self.limiters.contains_key(api_key) && self.limiters.len() >= MAX_TRACKED_KEYS {
            return Err(());
        }

        let mut limiter = self.limiters.entry(api_key.to_string()).or_insert_with(|| {
            (
                Arc::new(GovernorLimiter::direct(self.quota)),
                Instant::now(),
            )
        });

        // Update last-seen timestamp
        limiter.1 = Instant::now();
        let lim = limiter.0.clone();
        drop(limiter);

        lim.check().map_err(|_| ())
    }

    /// Evict entries that haven't been seen for `ENTRY_TTL`. Called from
    /// a background tokio task; cheap when most keys are active. Returns
    /// the approximate number of entries removed (DashMap len() is not
    /// atomic with retain() under concurrent inserts, so this is a debug
    /// signal, not a precise count).
    pub fn evict_stale(&self) -> usize {
        let before = self.limiters.len();
        self.limiters
            .retain(|_, (_, last_seen)| last_seen.elapsed() < ENTRY_TTL);
        before.saturating_sub(self.limiters.len())
    }
}

/// Per-IP rate limiter (master-list #155). Same governor + DashMap
/// pattern as `RateLimiter`, but keyed on `IpAddr` and with a larger
/// `MAX_TRACKED_IPS` cap. Separate type rather than generic so tests
/// stay simple and the existing per-API-key call sites don't need to
/// change.
///
/// Returns `Err(retry_after_secs)` when over-limit so middleware can
/// surface a `Retry-After` header. The retry value is conservative:
/// `ceil(60 / requests_per_minute)` — an upper bound on the true wait.
pub struct PerIpRateLimiter {
    limiters: DashMap<IpAddr, (Arc<Limiter>, Instant)>,
    quota: Quota,
    retry_after_secs: u64,
}

impl PerIpRateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        let clamped = requests_per_minute.max(1);
        let per_minute =
            NonZeroU32::new(clamped).unwrap_or_else(|| unreachable!("clamped >= 1 by .max(1)"));
        let quota = Quota::per_minute(per_minute);
        // ceil(60 / clamped); never less than 1 second so the header is
        // always meaningful even at very high configured rates.
        let retry_after_secs = (60u64.div_ceil(clamped as u64)).max(1);
        Self {
            limiters: DashMap::new(),
            quota,
            retry_after_secs,
        }
    }

    /// Check if a request from `ip` is allowed. Returns `Err(retry_after_secs)`
    /// when the IP is over-limit OR when the tracked-IP cap is hit and `ip`
    /// is unknown (over-cap-reject is conservative — better to occasionally
    /// turn away a legitimate IP than let an attacker grow the map past
    /// the memory bound).
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        if !self.limiters.contains_key(&ip) && self.limiters.len() >= MAX_TRACKED_IPS {
            return Err(self.retry_after_secs);
        }

        let mut limiter = self.limiters.entry(ip).or_insert_with(|| {
            (
                Arc::new(GovernorLimiter::direct(self.quota)),
                Instant::now(),
            )
        });

        limiter.1 = Instant::now();
        let lim = limiter.0.clone();
        drop(limiter);

        lim.check().map_err(|_| self.retry_after_secs)
    }

    /// Drop entries inactive for `IP_ENTRY_TTL`. Called from a background
    /// task in `main.rs` (60-second sweep) — same pattern as `RateLimiter`.
    /// Returns the approximate count of removed entries (see `RateLimiter::evict_stale`).
    pub fn evict_stale(&self) -> usize {
        self.evict_with_ttl(IP_ENTRY_TTL)
    }

    /// TTL-parameterized eviction. Production code calls `evict_stale()`
    /// which delegates here with `IP_ENTRY_TTL`. Tests use a tiny TTL to
    /// exercise the retain logic without spending 5 minutes of wall time.
    fn evict_with_ttl(&self, ttl: Duration) -> usize {
        let before = self.limiters.len();
        self.limiters
            .retain(|_, (_, last_seen)| last_seen.elapsed() < ttl);
        before.saturating_sub(self.limiters.len())
    }

    /// Number of currently-tracked IPs. Exposed for tests.
    #[cfg(test)]
    pub fn tracked_count(&self) -> usize {
        self.limiters.len()
    }

    /// The conservative `Retry-After` value this limiter emits on rejection.
    /// Exposed for tests.
    #[cfg(test)]
    pub fn retry_after_secs(&self) -> u64 {
        self.retry_after_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn per_ip_allows_under_limit() {
        let limiter = PerIpRateLimiter::new(60);
        assert!(limiter.check(ip("203.0.113.1")).is_ok());
    }

    #[test]
    fn per_ip_rejects_over_limit() {
        let limiter = PerIpRateLimiter::new(2);
        let addr = ip("203.0.113.5");
        assert!(limiter.check(addr).is_ok());
        assert!(limiter.check(addr).is_ok());
        match limiter.check(addr) {
            Err(retry) => assert!(retry >= 1),
            Ok(()) => panic!("expected rejection at cap"),
        }
    }

    #[test]
    fn per_ip_separate_addrs_have_separate_counters() {
        let limiter = PerIpRateLimiter::new(1);
        let a = ip("203.0.113.10");
        let b = ip("203.0.113.11");
        assert!(limiter.check(a).is_ok());
        assert!(limiter.check(b).is_ok());
        assert!(limiter.check(a).is_err());
        assert!(limiter.check(b).is_err());
    }

    #[test]
    fn per_ip_ipv6_and_ipv4_are_independent() {
        let limiter = PerIpRateLimiter::new(1);
        let v4 = ip("203.0.113.20");
        let v6 = ip("2001:db8::1");
        assert!(limiter.check(v4).is_ok());
        assert!(limiter.check(v6).is_ok());
        assert!(limiter.check(v4).is_err());
        assert!(limiter.check(v6).is_err());
    }

    #[test]
    fn per_ip_retry_after_matches_configured_rate() {
        // 30 r/m → 60 / 30 = 2s retry-after.
        assert_eq!(PerIpRateLimiter::new(30).retry_after_secs(), 2);
        // 60 r/m → 1s.
        assert_eq!(PerIpRateLimiter::new(60).retry_after_secs(), 1);
        // 1 r/m → 60s.
        assert_eq!(PerIpRateLimiter::new(1).retry_after_secs(), 60);
        // Pathological: 0 clamps to 1 r/m → 60s.
        assert_eq!(PerIpRateLimiter::new(0).retry_after_secs(), 60);
    }

    #[test]
    fn per_ip_tracked_count_grows_with_distinct_addrs() {
        let limiter = PerIpRateLimiter::new(60);
        assert_eq!(limiter.tracked_count(), 0);
        limiter.check(ip("203.0.113.1")).unwrap();
        limiter.check(ip("203.0.113.2")).unwrap();
        assert_eq!(limiter.tracked_count(), 2);
        // Same IP again — count unchanged.
        limiter.check(ip("203.0.113.1")).unwrap();
        assert_eq!(limiter.tracked_count(), 2);
    }

    #[test]
    fn per_ip_evict_stale_is_a_no_op_on_fresh_entries() {
        let limiter = PerIpRateLimiter::new(60);
        limiter.check(ip("203.0.113.1")).unwrap();
        limiter.evict_stale();
        // Still tracked because last_seen < IP_ENTRY_TTL.
        assert_eq!(limiter.tracked_count(), 1);
    }

    #[test]
    fn per_ip_evict_with_ttl_drops_stale_entries() {
        // Verify the retain logic itself: an aggressive TTL of 0 marks
        // every entry as stale (since `last_seen.elapsed() < 0ns` is
        // always false), so eviction must drop them all. Catches any
        // bug where the predicate is inverted or the comparison is
        // off-by-one.
        let limiter = PerIpRateLimiter::new(60);
        limiter.check(ip("203.0.113.1")).unwrap();
        limiter.check(ip("203.0.113.2")).unwrap();
        assert_eq!(limiter.tracked_count(), 2);
        limiter.evict_with_ttl(Duration::from_nanos(0));
        assert_eq!(limiter.tracked_count(), 0);
    }

    #[test]
    fn per_ip_evict_with_ttl_returns_evicted_count() {
        // The conditional eviction log in main.rs depends on this return
        // value to suppress empty-sweep heartbeats. Lock the contract.
        let limiter = PerIpRateLimiter::new(60);
        limiter.check(ip("203.0.113.1")).unwrap();
        limiter.check(ip("203.0.113.2")).unwrap();
        assert_eq!(limiter.evict_with_ttl(Duration::from_nanos(0)), 2);
        assert_eq!(limiter.evict_with_ttl(Duration::from_nanos(0)), 0);
    }

    #[test]
    fn rate_limiter_evict_stale_returns_zero_when_nothing_is_stale() {
        // Fresh entries are within ENTRY_TTL, so the sweep must not
        // remove them — and the return must be zero so main.rs stays
        // silent.
        let limiter = RateLimiter::new(60);
        assert_eq!(limiter.evict_stale(), 0);
        limiter.check("key_a").ok();
        limiter.check("key_b").ok();
        assert_eq!(limiter.evict_stale(), 0);
    }

    #[test]
    fn per_ip_eviction_releases_the_cap() {
        // After the budget is burned and the entry evicted, a new
        // request from the same IP should pass — proving eviction
        // genuinely releases the cap rather than leaving a phantom
        // counter behind.
        let limiter = PerIpRateLimiter::new(1);
        let addr = ip("203.0.113.42");
        assert!(limiter.check(addr).is_ok());
        assert!(limiter.check(addr).is_err(), "second call should hit cap");
        limiter.evict_with_ttl(Duration::from_nanos(0));
        assert!(
            limiter.check(addr).is_ok(),
            "after eviction the IP should get a fresh budget"
        );
    }
}
