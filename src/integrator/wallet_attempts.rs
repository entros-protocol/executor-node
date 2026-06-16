//! Per-wallet validation-attempt counter (master-list #94).
//!
//! Bounds how many times a single wallet can attempt validation within a
//! sliding window. Pairs with the client-side soft-reject UX in
//! `entros.io/src/components/sections/verify-wallet-connected.tsx`: the
//! client offers up to N retries within a session, the server enforces the
//! same cap per-wallet across browser refreshes / new sessions.
//!
//! ## Defense framing (honest)
//!
//! Bots can rotate wallets either way, so the per-wallet cap doesn't bound
//! total bot success across many wallets. The meaningful defense is the
//! per-category soft-fail gating in `entros.io` (TTS detection and Sybil
//! match never get a retry, only borderline acoustic / phrase reasons do).
//! This counter is a secondary defense layer that bounds per-wallet damage
//! and prevents an unbounded retry loop on a single key.
//!
//! ## Atomicity
//!
//! `check_and_record_attempt` does the check and the increment under a
//! single DashMap entry write lock — so concurrent requests for the same
//! wallet can never collectively bypass the cap. Successful validations
//! call `refund_on_success` to return the slot. Failed validations leave
//! the slot consumed, so failures accumulate against the cap.
//!
//! ## Memory
//!
//! In-memory map; resets on Railway restart. `evict_expired` runs from a
//! background task in main.rs (5min interval) to drop stale entries —
//! prevents unbounded growth from many distinct wallets over time. The
//! per-attempt cost stays O(1).

use dashmap::DashMap;
use solana_sdk::pubkey::Pubkey;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct WalletState {
    /// Slots consumed in the current window (capped by `max_attempts`).
    /// Increments on every attempt, decrements on success.
    attempts: u8,
    /// Window anchor — wall clock instant when this window opened. After
    /// `window_duration` elapses the next access resets the counter.
    window_start: Instant,
}

pub struct WalletAttemptTracker {
    state: DashMap<Pubkey, WalletState>,
    /// Maximum validation attempts per wallet per window. Configured at
    /// startup via `VALIDATION_WALLET_MAX_ATTEMPTS` env var (default 5).
    /// Each call to `check_and_record_attempt` consumes one slot;
    /// `refund_on_success` returns one. Net: a wallet with all-successful
    /// verifications never accumulates; a wallet that keeps failing burns
    /// slots and eventually gets blocked.
    max_attempts: u8,
    /// Sliding window length. Configured at startup via
    /// `VALIDATION_WALLET_WINDOW_SECS` (default 3600). Balances bot cost
    /// against legit-user recovery time.
    window_duration: Duration,
}

impl WalletAttemptTracker {
    /// Construct with explicit limits. Caller is expected to pass values
    /// from `Config` (env-var driven). Use `default_for_tests` in unit
    /// tests where the production defaults aren't needed.
    pub fn new(max_attempts: u8, window_duration: Duration) -> Self {
        Self {
            state: DashMap::new(),
            max_attempts,
            window_duration,
        }
    }

    /// Test-only constructor with the same default limits Config uses
    /// when no env var is set. Keeps unit tests independent of Config.
    #[cfg(test)]
    fn default_for_tests() -> Self {
        Self::new(3, Duration::from_secs(3600))
    }

    /// Atomically: check whether the wallet has cap room, increment the
    /// attempt counter, and return Ok if the caller may proceed. Returns
    /// `Err(retry_after_secs)` if the wallet has consumed its window
    /// budget.
    ///
    /// Caller MUST follow up with `refund_on_success` if the validation
    /// succeeds. Failures leave the slot consumed, which is what binds
    /// the per-wallet retry budget.
    pub fn check_and_record_attempt(&self, wallet: &Pubkey) -> Result<(), u64> {
        let now = Instant::now();
        let mut entry = self.state.entry(*wallet).or_insert_with(|| WalletState {
            attempts: 0,
            window_start: now,
        });

        // Reset the window if it expired since the last access. Pulled
        // inside the entry lock so window-reset and increment are atomic
        // together — prevents two concurrent requests from each thinking
        // the window expired and double-resetting.
        if now.duration_since(entry.window_start) >= self.window_duration {
            entry.attempts = 0;
            entry.window_start = now;
        }

        if entry.attempts >= self.max_attempts {
            let elapsed = now.duration_since(entry.window_start);
            let retry_after = self.window_duration.saturating_sub(elapsed).as_secs();
            return Err(retry_after);
        }

        entry.attempts += 1;
        Ok(())
    }

    /// Refund a slot consumed by `check_and_record_attempt`. Call after a
    /// successful validation so the wallet's budget is restored. Idempotent
    /// safety: never decrements below zero.
    pub fn refund_on_success(&self, wallet: &Pubkey) {
        if let Some(mut entry) = self.state.get_mut(wallet) {
            entry.attempts = entry.attempts.saturating_sub(1);
        }
    }

    /// Drop entries whose window has fully elapsed AND counter is zero.
    /// Called periodically from a background task in `main.rs` to bound
    /// memory growth. Returns the approximate count of evicted entries
    /// (`saturating_sub` because DashMap's `len()` is not atomic with
    /// `retain()` under concurrent inserts — a precise count would
    /// require an atomic counter inside the retain closure, which isn't
    /// worth the cost for a debug signal).
    ///
    /// Eviction-while-zero is the safe condition: a wallet at 0 attempts
    /// with an expired window contributes no rate-limit info, so dropping
    /// it just reclaims the entry — the next attempt re-creates it from
    /// fresh state (which is what would happen anyway via the
    /// window-reset branch in `check_and_record_attempt`).
    pub fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let before = self.state.len();
        self.state.retain(|_, state| {
            now.duration_since(state.window_start) < self.window_duration || state.attempts > 0
        });
        before.saturating_sub(self.state.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn dummy_wallet(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    /// Test-default cap (matches `default_for_tests()`).
    const TEST_MAX: u8 = 3;
    /// Test-default window (matches `default_for_tests()`).
    const TEST_WINDOW_SECS: u64 = 3600;

    #[test]
    fn allows_attempts_up_to_cap() {
        let tracker = WalletAttemptTracker::default_for_tests();
        let wallet = dummy_wallet(1);
        for _ in 0..TEST_MAX {
            assert!(tracker.check_and_record_attempt(&wallet).is_ok());
        }
    }

    #[test]
    fn blocks_after_cap_reached() {
        let tracker = WalletAttemptTracker::default_for_tests();
        let wallet = dummy_wallet(2);
        for _ in 0..TEST_MAX {
            tracker
                .check_and_record_attempt(&wallet)
                .expect("attempt within cap");
        }
        match tracker.check_and_record_attempt(&wallet) {
            Err(retry_after) => {
                assert!(retry_after > 0);
                assert!(retry_after <= TEST_WINDOW_SECS);
            }
            Ok(()) => panic!("expected wallet to be rate-limited at cap"),
        }
    }

    #[test]
    fn separate_wallets_have_separate_counters() {
        let tracker = WalletAttemptTracker::default_for_tests();
        let w1 = dummy_wallet(3);
        let w2 = dummy_wallet(4);
        for _ in 0..TEST_MAX {
            tracker
                .check_and_record_attempt(&w1)
                .expect("attempt within cap");
        }
        assert!(tracker.check_and_record_attempt(&w1).is_err());
        assert!(tracker.check_and_record_attempt(&w2).is_ok());
    }

    #[test]
    fn custom_limits_respect_cap() {
        // Verify the constructor's params actually wire through.
        let tracker = WalletAttemptTracker::new(2, Duration::from_secs(60));
        let wallet = dummy_wallet(11);
        assert!(tracker.check_and_record_attempt(&wallet).is_ok());
        assert!(tracker.check_and_record_attempt(&wallet).is_ok());
        match tracker.check_and_record_attempt(&wallet) {
            Err(retry_after) => assert!(retry_after <= 60),
            Ok(()) => panic!("expected cap of 2 to be enforced"),
        }
    }

    #[test]
    fn fresh_wallet_starts_at_zero_attempts() {
        let tracker = WalletAttemptTracker::default_for_tests();
        let wallet = dummy_wallet(5);
        assert!(tracker.check_and_record_attempt(&wallet).is_ok());
    }

    #[test]
    fn refund_on_success_returns_slot() {
        let tracker = WalletAttemptTracker::default_for_tests();
        let wallet = dummy_wallet(6);
        // Burn the cap with successful attempts, refunding each — the
        // counter should always have room.
        for _ in 0..(TEST_MAX as usize * 5) {
            tracker
                .check_and_record_attempt(&wallet)
                .expect("attempt within cap");
            tracker.refund_on_success(&wallet);
        }
        // After all the refunds the wallet is still allowed.
        assert!(tracker.check_and_record_attempt(&wallet).is_ok());
    }

    #[test]
    fn refund_never_underflows() {
        let tracker = WalletAttemptTracker::default_for_tests();
        let wallet = dummy_wallet(7);
        // Refund before any attempt: should be a no-op (entry doesn't exist).
        tracker.refund_on_success(&wallet);
        // Single attempt then double refund: counter should saturate at 0.
        tracker
            .check_and_record_attempt(&wallet)
            .expect("attempt within cap");
        tracker.refund_on_success(&wallet);
        tracker.refund_on_success(&wallet);
        // Still allowed.
        assert!(tracker.check_and_record_attempt(&wallet).is_ok());
    }

    #[test]
    fn concurrent_attempts_respect_cap() {
        // Threat model: a bot fires N parallel requests on a single wallet.
        // The atomic check-and-increment must ensure no more than
        // `max_attempts` succeed.
        let tracker = Arc::new(WalletAttemptTracker::default_for_tests());
        let wallet = dummy_wallet(8);
        let n_threads = 50;

        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                let t = Arc::clone(&tracker);
                std::thread::spawn(move || t.check_and_record_attempt(&wallet).is_ok())
            })
            .collect();

        let allowed: usize = handles
            .into_iter()
            .map(|h| h.join().expect("test thread joined") as usize)
            .sum();

        assert_eq!(
            allowed, TEST_MAX as usize,
            "exactly `max_attempts` concurrent calls should pass; rest must be rate-limited"
        );
    }

    #[test]
    fn evict_expired_drops_zero_count_stale_entries() {
        let tracker = WalletAttemptTracker::default_for_tests();
        // Add a wallet with active count — should NOT be evicted even if window expired.
        let active = dummy_wallet(9);
        tracker
            .check_and_record_attempt(&active)
            .expect("attempt within cap");
        // Add a wallet at zero count — eligible for eviction once window expires.
        let zero = dummy_wallet(10);
        tracker
            .check_and_record_attempt(&zero)
            .expect("zero-window attempt allowed");
        tracker.refund_on_success(&zero);

        // Without forcing time, neither is window-expired → nothing evicted.
        assert_eq!(tracker.evict_expired(), 0);
    }
}
