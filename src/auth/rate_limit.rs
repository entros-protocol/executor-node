use std::borrow::Borrow;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovernorLimiter};

use crate::auth::client_ip::{client_network, ipv6_site};

type Limiter = GovernorLimiter<NotKeyed, InMemoryState, DefaultClock>;

const MAX_TRACKED_KEYS: usize = 10_000;
const ENTRY_TTL: Duration = Duration::from_secs(300);

/// The per-IP map holds client networks, a much larger space than API keys. 50,000
/// entries of about 100 bytes is 5 MB.
const MAX_TRACKED_IPS: usize = 50_000;
const IP_ENTRY_TTL: Duration = Duration::from_secs(300);

/// An IPv6 /48 may send this many times the rate of one client network. One site can
/// hold all 65,536 networks in a /48, so the networks alone do not bound it.
const SITE_RATE_MULTIPLE: u32 = 16;

/// The share of a full map that goes when room is needed: one entry in this many.
const EVICTION_DIVISOR: usize = 10;

struct Bucket {
    limiter: Limiter,
    last_seen: Instant,
}

/// One GCRA bucket per key, in a map that never grows past `capacity` for long.
///
/// A full map makes room by dropping its least recently seen tenth in one pass. A full
/// map that refused new keys would turn away every new client for as long as a sender
/// kept its own entries active. A pass on every insert would cost a scan per request,
/// so one pass pays for the next tenth of the inserts.
struct Buckets<K> {
    entries: DashMap<K, Bucket>,
    quota: Quota,
    capacity: usize,
    /// Held by the one caller that makes room. The others insert without waiting.
    making_room: Mutex<()>,
}

impl<K: Eq + Hash> Buckets<K> {
    fn new(requests_per_minute: u32, capacity: usize) -> Self {
        Self {
            entries: DashMap::new(),
            quota: per_minute(requests_per_minute),
            capacity: capacity.max(1),
            making_room: Mutex::new(()),
        }
    }

    /// Takes a token from a key that already has a bucket. `None` when it has none.
    fn take_existing<Q>(&self, key: &Q) -> Option<bool>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let mut bucket = self.entries.get_mut(key)?;
        bucket.last_seen = Instant::now();
        Some(bucket.limiter.check().is_ok())
    }

    /// Takes a token for `key`, and creates its bucket first if it has none.
    fn take<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ToOwned<Owned = K> + ?Sized,
    {
        if let Some(allowed) = self.take_existing(key) {
            return allowed;
        }
        self.make_room();
        let mut bucket = self
            .entries
            .entry(key.to_owned())
            .or_insert_with(|| Bucket {
                limiter: GovernorLimiter::direct(self.quota),
                last_seen: Instant::now(),
            });
        bucket.last_seen = Instant::now();
        bucket.limiter.check().is_ok()
    }

    fn make_room(&self) {
        if self.entries.len() < self.capacity {
            return;
        }
        let _guard = match self.making_room.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        let mut seen: Vec<Instant> = self.entries.iter().map(|entry| entry.last_seen).collect();
        if seen.len() < self.capacity {
            return;
        }
        let evict = (seen.len() / EVICTION_DIVISOR).max(1);
        let (_, cutoff, _) = seen.select_nth_unstable(evict - 1);
        let cutoff = *cutoff;
        self.entries.retain(|_, bucket| bucket.last_seen > cutoff);
    }

    fn evict_idle(&self, ttl: Duration) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, bucket| bucket.last_seen.elapsed() < ttl);
        before.saturating_sub(self.entries.len())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn per_minute(requests_per_minute: u32) -> Quota {
    // `.max(1)` makes the value nonzero, so the fallback is never taken.
    let clamped = requests_per_minute.max(1);
    Quota::per_minute(NonZeroU32::new(clamped).unwrap_or(NonZeroU32::MIN))
}

/// `ceil(60 / rate)`, never under one second. An upper bound on the true wait.
fn retry_after_secs(requests_per_minute: u32) -> u64 {
    60u64.div_ceil(u64::from(requests_per_minute.max(1))).max(1)
}

/// Rate limiter keyed on a string, such as an API key or a wallet address.
/// Entries idle for five minutes are evicted by a background sweep.
pub struct RateLimiter {
    buckets: Buckets<String>,
    retry_after_secs: u64,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self::with_capacity(requests_per_minute, MAX_TRACKED_KEYS)
    }

    fn with_capacity(requests_per_minute: u32, capacity: usize) -> Self {
        Self {
            buckets: Buckets::new(requests_per_minute, capacity),
            retry_after_secs: retry_after_secs(requests_per_minute),
        }
    }

    /// Takes one token for `key`. `Err` when the key is over its rate.
    pub fn check(&self, key: &str) -> Result<(), ()> {
        if self.buckets.take(key) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn check_with_retry(&self, key: &str) -> Result<(), u64> {
        self.check(key).map_err(|()| self.retry_after_secs)
    }

    /// Drops entries idle for `ENTRY_TTL`. Called from a background task. Returns the
    /// approximate number removed, since the map changes under concurrent inserts.
    pub fn evict_stale(&self) -> usize {
        self.buckets.evict_idle(ENTRY_TTL)
    }
}

/// Rate limiter keyed on the client network: an IPv4 address or an IPv6 /64.
///
/// An IPv6 request also takes a token from the bucket of its /48, at
/// `SITE_RATE_MULTIPLE` times the network rate. Returns `Err(retry_after_secs)` when
/// over the limit, so the middleware can send a `Retry-After` header.
pub struct PerIpRateLimiter {
    networks: Buckets<IpAddr>,
    sites: Buckets<[u16; 3]>,
    retry_after_secs: u64,
}

impl PerIpRateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self::with_capacity(requests_per_minute, MAX_TRACKED_IPS)
    }

    fn with_capacity(requests_per_minute: u32, capacity: usize) -> Self {
        Self {
            networks: Buckets::new(requests_per_minute, capacity),
            sites: Buckets::new(
                requests_per_minute.saturating_mul(SITE_RATE_MULTIPLE),
                capacity,
            ),
            retry_after_secs: retry_after_secs(requests_per_minute),
        }
    }

    /// Takes one token for the network of `ip`.
    ///
    /// The order keeps two properties. A network already over its own rate is refused
    /// before the site bucket is touched, so one network cannot spend its neighbours'
    /// site tokens. A network with no bucket asks the site first, so a refused request
    /// never adds an entry and a /48 cannot fill the map with its 65,536 networks.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let network = client_network(ip);
        let allowed = match self.networks.take_existing(&network) {
            Some(within_network_rate) => within_network_rate && self.site_allows(network),
            None => self.site_allows(network) && self.networks.take(&network),
        };
        if allowed {
            Ok(())
        } else {
            Err(self.retry_after_secs)
        }
    }

    fn site_allows(&self, network: IpAddr) -> bool {
        ipv6_site(network).is_none_or(|site| self.sites.take(&site))
    }

    /// Drops entries idle for `IP_ENTRY_TTL`. Called from a background task. Returns
    /// the approximate number removed.
    pub fn evict_stale(&self) -> usize {
        self.evict_with_ttl(IP_ENTRY_TTL)
    }

    /// Eviction with an explicit TTL, so tests need not wait five minutes.
    fn evict_with_ttl(&self, ttl: Duration) -> usize {
        self.networks.evict_idle(ttl) + self.sites.evict_idle(ttl)
    }

    /// Number of client networks tracked. Exposed for tests.
    #[cfg(test)]
    pub fn tracked_count(&self) -> usize {
        self.networks.len()
    }

    /// The `Retry-After` value this limiter emits on rejection. Exposed for tests.
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

    #[test]
    fn addresses_in_one_ipv6_network_share_a_bucket() {
        let limiter = PerIpRateLimiter::new(1);
        assert!(limiter.check(ip("2001:db8:1:2::1")).is_ok());
        assert!(limiter.check(ip("2001:db8:1:2:ffff::9")).is_err());
        assert_eq!(limiter.tracked_count(), 1);
    }

    #[test]
    fn networks_in_one_ipv6_site_have_their_own_buckets() {
        let limiter = PerIpRateLimiter::new(1);
        assert!(limiter.check(ip("2001:db8:1:2::1")).is_ok());
        assert!(limiter.check(ip("2001:db8:1:3::1")).is_ok());
        assert_eq!(limiter.tracked_count(), 2);
    }

    fn network_in_site(index: u16) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 7, index, 0, 0, 0, 1))
    }

    /// A refused request must add no entry. Otherwise one /48 could fill the map with
    /// networks it holds, and push every other client out.
    #[test]
    fn a_site_over_its_rate_adds_no_network_entries() {
        let limiter = PerIpRateLimiter::new(1);
        let site_burst = u16::try_from(SITE_RATE_MULTIPLE).unwrap();
        for index in 0..site_burst {
            assert!(limiter.check(network_in_site(index)).is_ok(), "{index}");
        }
        for index in site_burst..site_burst + 50 {
            assert!(limiter.check(network_in_site(index)).is_err(), "{index}");
        }
        assert_eq!(limiter.tracked_count(), usize::from(site_burst));
        // Another site is untouched.
        assert!(limiter.check(ip("2001:db8:8:1::1")).is_ok());
    }

    #[test]
    fn a_network_over_its_own_rate_spends_no_site_tokens() {
        let limiter = PerIpRateLimiter::new(1);
        let noisy = network_in_site(0);
        assert!(limiter.check(noisy).is_ok());
        for _ in 0..200 {
            assert!(limiter.check(noisy).is_err());
        }
        // The site had 16 tokens and the noisy network took one.
        for index in 1..u16::try_from(SITE_RATE_MULTIPLE).unwrap() {
            assert!(limiter.check(network_in_site(index)).is_ok(), "{index}");
        }
    }

    #[test]
    fn ipv4_addresses_have_no_site_bucket() {
        let limiter = PerIpRateLimiter::new(1);
        for last in 0..=255u8 {
            let address = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, last));
            assert!(limiter.check(address).is_ok(), "{last}");
        }
    }

    #[test]
    fn a_full_per_ip_map_admits_a_new_network_and_drops_the_oldest() {
        let limiter = PerIpRateLimiter::with_capacity(60, 20);
        for last in 0..20u8 {
            limiter
                .check(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, last)))
                .unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(limiter.tracked_count(), 20);
        let newcomer = ip("203.0.113.200");
        assert!(limiter.check(newcomer).is_ok(), "a full map must admit it");
        // A tenth of the map went, oldest first, and the newcomer took one place.
        assert_eq!(limiter.tracked_count(), 19);
        let oldest = ip("198.51.100.0");
        let newest = ip("198.51.100.19");
        assert!(!limiter.networks.entries.contains_key(&oldest));
        assert!(limiter.networks.entries.contains_key(&newest));
        assert!(limiter.networks.entries.contains_key(&newcomer));
    }

    #[test]
    fn a_full_key_map_admits_a_new_key() {
        let limiter = RateLimiter::with_capacity(60, 10);
        for index in 0..10 {
            limiter.check(&format!("key-{index}")).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(limiter.check("newcomer").is_ok());
        assert!(limiter.buckets.len() <= 10);
        assert!(!limiter.buckets.entries.contains_key("key-0"));
    }

    #[test]
    fn a_key_over_its_rate_is_refused_with_a_wait() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check_with_retry("wallet").is_ok());
        assert!(limiter.check_with_retry("wallet").is_ok());
        assert_eq!(limiter.check_with_retry("wallet"), Err(30));
    }
}
