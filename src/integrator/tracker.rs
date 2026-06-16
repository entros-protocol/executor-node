use dashmap::DashMap;

use crate::error::AppError;

const DEFAULT_FREE_QUOTA: u64 = 1_000;

/// Per-integrator verification state.
#[derive(Debug)]
struct IntegratorState {
    name: String,
    quota: u64,
    used: u64,
}

/// Thread-safe per-API-key quota tracker.
///
/// For devnet pilot: in-memory state that resets on restart.
/// Production will use on-chain escrow PDA balances.
pub struct IntegratorTracker {
    state: DashMap<String, IntegratorState>,
    allow_unknown: bool,
}

impl IntegratorTracker {
    /// Create a tracker pre-loaded with configured integrators.
    /// If no integrators are configured, unknown keys get default free tier quota.
    pub fn new(integrators: Vec<crate::config::IntegratorConfig>) -> Self {
        let allow_unknown = integrators.is_empty();
        let state = DashMap::new();
        for integrator in integrators {
            state.insert(
                integrator.api_key.clone(),
                IntegratorState {
                    name: integrator.name,
                    quota: integrator.quota,
                    used: 0,
                },
            );
        }
        Self {
            state,
            allow_unknown,
        }
    }

    /// Check quota and deduct one verification. Returns remaining count.
    /// If integrators are configured, unknown keys are rejected.
    /// If no integrators are configured (dev mode), unknown keys get free tier.
    pub fn check_and_deduct(&self, api_key: &str) -> Result<u64, AppError> {
        if !self.state.contains_key(api_key) {
            if !self.allow_unknown {
                tracing::warn!(
                    api_key = %crate::auth::redact::redact_api_key(api_key),
                    "Verification rejected: unknown integrator"
                );
                return Err(AppError::InsufficientQuota);
            }
            // Dev mode: auto-register with free tier (bounded by auth — only valid API keys reach here)
            self.state.insert(
                api_key.to_string(),
                IntegratorState {
                    name: "free-tier".into(),
                    quota: DEFAULT_FREE_QUOTA,
                    used: 0,
                },
            );
        }

        let mut entry = self
            .state
            .get_mut(api_key)
            .ok_or(AppError::InsufficientQuota)?;

        let state = entry.value_mut();

        // quota == 0 means unlimited
        if state.quota > 0 && state.used >= state.quota {
            tracing::warn!(
                api_key = %crate::auth::redact::redact_api_key(api_key),
                quota = state.quota,
                used = state.used,
                "Verification rejected: quota exhausted"
            );
            return Err(AppError::InsufficientQuota);
        }

        state.used += 1;
        let remaining = if state.quota == 0 {
            u64::MAX
        } else {
            state.quota.saturating_sub(state.used)
        };

        tracing::info!(
            api_key = %crate::auth::redact::redact_api_key(api_key),
            integrator = %state.name,
            used = state.used,
            remaining,
            "Quota deducted"
        );

        Ok(remaining)
    }

    /// Refund a deduction (e.g., on transaction failure).
    pub fn refund(&self, api_key: &str) {
        if let Some(mut entry) = self.state.get_mut(api_key) {
            entry.used = entry.used.saturating_sub(1);
            tracing::info!(api_key, used = entry.used, "Quota refunded");
        }
    }

    /// Get current remaining quota without deducting.
    pub fn get_remaining(&self, api_key: &str) -> u64 {
        self.state
            .get(api_key)
            .map(|s| {
                if s.quota == 0 {
                    u64::MAX
                } else {
                    s.quota.saturating_sub(s.used)
                }
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IntegratorConfig;

    #[test]
    fn deducts_from_configured_integrator() {
        let tracker = IntegratorTracker::new(vec![IntegratorConfig {
            api_key: "key_abc".into(),
            name: "TestApp".into(),
            quota: 100,
        }]);

        let remaining = tracker.check_and_deduct("key_abc").unwrap();
        assert_eq!(remaining, 99);
    }

    #[test]
    fn unknown_key_gets_free_tier_in_dev_mode() {
        let tracker = IntegratorTracker::new(vec![]);
        let remaining = tracker.check_and_deduct("unknown_key").unwrap();
        assert_eq!(remaining, DEFAULT_FREE_QUOTA - 1);
    }

    #[test]
    fn unknown_key_rejected_when_integrators_configured() {
        let tracker = IntegratorTracker::new(vec![IntegratorConfig {
            api_key: "key_known".into(),
            name: "Known".into(),
            quota: 100,
        }]);

        assert!(tracker.check_and_deduct("unknown_key").is_err());
    }

    #[test]
    fn rejects_when_quota_exhausted() {
        let tracker = IntegratorTracker::new(vec![IntegratorConfig {
            api_key: "key_limited".into(),
            name: "Limited".into(),
            quota: 1,
        }]);

        tracker.check_and_deduct("key_limited").unwrap();
        assert!(tracker.check_and_deduct("key_limited").is_err());
    }

    #[test]
    fn unlimited_quota_never_exhausts() {
        let tracker = IntegratorTracker::new(vec![IntegratorConfig {
            api_key: "key_unlimited".into(),
            name: "Unlimited".into(),
            quota: 0,
        }]);

        for _ in 0..100 {
            assert!(tracker.check_and_deduct("key_unlimited").is_ok());
        }
    }

    #[test]
    fn refund_restores_quota() {
        let tracker = IntegratorTracker::new(vec![IntegratorConfig {
            api_key: "key_refund".into(),
            name: "Refund".into(),
            quota: 2,
        }]);

        tracker.check_and_deduct("key_refund").unwrap();
        tracker.check_and_deduct("key_refund").unwrap();
        assert!(tracker.check_and_deduct("key_refund").is_err());

        tracker.refund("key_refund");
        assert!(tracker.check_and_deduct("key_refund").is_ok());
    }
}
