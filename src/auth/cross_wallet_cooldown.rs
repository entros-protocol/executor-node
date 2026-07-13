use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use dashmap::DashMap;

const MAX_TRACKED_FINGERPRINTS: usize = 50_000;

/// Tracker for cross-wallet cooldown limits (master-list #142).
/// Prevents the same client device/subnet footprint from verifying different
/// wallets in quick succession, mitigating multi-wallet bot farming.
pub struct CrossWalletCooldownTracker {
    cooldowns: DashMap<u64, (String, Instant)>,
    cooldown_duration: Duration,
    salt: u64,
}

impl CrossWalletCooldownTracker {
    pub fn new(cooldown_duration_secs: u64) -> Self {
        Self {
            cooldowns: DashMap::new(),
            cooldown_duration: Duration::from_secs(cooldown_duration_secs),
            salt: rand::random::<u64>(),
        }
    }

    /// Check if a validation request from the given client footprint and wallet is allowed.
    ///
    /// If the fingerprint is clean or matches the same wallet, verification is allowed.
    /// If a different wallet is presented from the same fingerprint, it returns
    /// `Err(remaining_seconds)` indicating the active cooldown period.
    pub fn check_cooldown(&self, ip: IpAddr, user_agent: &str, wallet_id: &str) -> Result<(), u64> {
        let canonical_ip = canonicalize_subnet(ip);
        
        let mut hasher = DefaultHasher::new();
        self.salt.hash(&mut hasher);
        canonical_ip.hash(&mut hasher);
        user_agent.hash(&mut hasher);
        let fingerprint_hash = hasher.finish();

        if !self.cooldowns.contains_key(&fingerprint_hash) && self.cooldowns.len() >= MAX_TRACKED_FINGERPRINTS {
            // Over-capacity safety valve: under memory exhaustion pressure, degrade gracefully
            // by failing-open (allow the verification) instead of false-blocking users.
            return Ok(());
        }

        let now = Instant::now();
        
        let mut entry = self.cooldowns.entry(fingerprint_hash).or_insert_with(|| {
            (wallet_id.to_string(), now)
        });

        let (tracked_wallet, first_seen) = entry.value_mut();
        
        if tracked_wallet == wallet_id {
            // Same wallet: always allowed. Refresh the timestamp to preserve the active session.
            *first_seen = now;
            Ok(())
        } else {
            // Different wallet: enforce cooldown threshold
            let elapsed = first_seen.elapsed();
            if elapsed >= self.cooldown_duration {
                // Cooldown expired: allow the wallet swap and start a new cooldown cycle
                *tracked_wallet = wallet_id.to_string();
                *first_seen = now;
                Ok(())
            } else {
                // Cooldown active: return remaining seconds
                let remaining = self.cooldown_duration.saturating_sub(elapsed).as_secs();
                Err(remaining.max(1))
            }
        }
    }

    /// Evict entries inactive for longer than the cooldown duration.
    /// Called from background task.
    pub fn evict_stale(&self) -> usize {
        let before = self.cooldowns.len();
        self.cooldowns.retain(|_, (_, last_seen)| last_seen.elapsed() < self.cooldown_duration);
        before.saturating_sub(self.cooldowns.len())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn tracked_count(&self) -> usize {
        self.cooldowns.len()
    }
}

/// Mask IPv4 to /24 and IPv6 to /48 to mitigate simple IP-cycling evasion.
fn canonicalize_subnet(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                0,
                0,
                0,
                0,
                0,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn allows_same_wallet() {
        let tracker = CrossWalletCooldownTracker::new(60);
        assert!(tracker.check_cooldown(ip("203.0.113.1"), "UserAgentA", "wallet_a").is_ok());
        assert!(tracker.check_cooldown(ip("203.0.113.1"), "UserAgentA", "wallet_a").is_ok());
    }

    #[test]
    fn rejects_different_wallet_within_cooldown() {
        let tracker = CrossWalletCooldownTracker::new(10);
        assert!(tracker.check_cooldown(ip("203.0.113.1"), "UserAgentA", "wallet_a").is_ok());
        
        match tracker.check_cooldown(ip("203.0.113.1"), "UserAgentA", "wallet_b") {
            Err(remaining) => assert!(remaining <= 10 && remaining > 0),
            Ok(()) => panic!("Expected cooldown block"),
        }
    }

    #[test]
    fn groups_by_subnet_ipv4() {
        let tracker = CrossWalletCooldownTracker::new(10);
        // Different IPs in same /24 subnet -> same fingerprint
        assert!(tracker.check_cooldown(ip("203.0.113.5"), "UserAgentA", "wallet_a").is_ok());
        assert!(tracker.check_cooldown(ip("203.0.113.99"), "UserAgentA", "wallet_b").is_err());
        
        // Different /24 subnet -> different fingerprint
        assert!(tracker.check_cooldown(ip("203.0.114.5"), "UserAgentA", "wallet_b").is_ok());
    }

    #[test]
    fn groups_by_subnet_ipv6() {
        let tracker = CrossWalletCooldownTracker::new(10);
        // Same /48 prefix -> same fingerprint
        assert!(tracker.check_cooldown(ip("2001:db8:aaaa::1"), "UserAgentA", "wallet_a").is_ok());
        assert!(tracker.check_cooldown(ip("2001:db8:aaaa:bbbb::2"), "UserAgentA", "wallet_b").is_err());

        // Different /48 prefix -> different fingerprint
        assert!(tracker.check_cooldown(ip("2001:db8:cccc::1"), "UserAgentA", "wallet_b").is_ok());
    }

    #[test]
    fn cooldown_expires_correctly() {
        let tracker = CrossWalletCooldownTracker::new(0); // instant expiry
        assert!(tracker.check_cooldown(ip("203.0.113.1"), "UserAgentA", "wallet_a").is_ok());
        
        // Since cooldown is 0s, another wallet is allowed immediately
        assert!(tracker.check_cooldown(ip("203.0.113.1"), "UserAgentA", "wallet_b").is_ok());
    }
}
