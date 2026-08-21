//! Composite risk scoring for `/validate-features`.
//!
//! The scoring configuration is immutable after startup. Accepted validator
//! responses use it to apply one consistent policy.

use std::fmt;

/// Exact weight and threshold denominator.
pub const PARTS_PER_MILLION: u32 = 1_000_000;

/// Invalid scoring configuration supplied at startup.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScoringConfigError {
    #[error("scoring weight {field} must not exceed one million parts")]
    WeightOutOfRange { field: &'static str },
    #[error("scoring weights must total one million parts")]
    WeightBudgetMismatch,
    #[error("scoring threshold {field} must not exceed one million parts")]
    ThresholdOutOfRange { field: &'static str },
    #[error("the friction threshold must be lower than the rejection threshold")]
    ThresholdOrderInvalid,
    #[error("the friction threshold is unreachable under the active weight budget")]
    FrictionThresholdUnreachable,
    #[error("the rejection threshold is unreachable under the active weight budget")]
    RejectThresholdUnreachable,
}

/// Immutable weights and policy boundaries resolved during startup.
///
/// Integer parts avoid tolerance-based budget validation. The unallocated share
/// participates in the budget but never contributes to a decision score.
#[derive(Clone)]
pub struct ScoringConfig {
    biometric_weight: f64,
    tts_weight: f64,
    automation_weight: f64,
    reputation_weight: f64,
    friction_threshold: f64,
    reject_threshold: f64,
}

impl ScoringConfig {
    /// Build a configuration whose weights form one exact budget.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        biometric_weight_ppm: u32,
        tts_weight_ppm: u32,
        unallocated_weight_ppm: u32,
        automation_weight_ppm: u32,
        reputation_weight_ppm: u32,
        friction_threshold_ppm: u32,
        reject_threshold_ppm: u32,
    ) -> Result<Self, ScoringConfigError> {
        for (field, value) in [
            ("biometric", biometric_weight_ppm),
            ("tts", tts_weight_ppm),
            ("unallocated", unallocated_weight_ppm),
            ("automation", automation_weight_ppm),
            ("reputation", reputation_weight_ppm),
        ] {
            if value > PARTS_PER_MILLION {
                return Err(ScoringConfigError::WeightOutOfRange { field });
            }
        }

        let weight_budget = u64::from(biometric_weight_ppm)
            + u64::from(tts_weight_ppm)
            + u64::from(unallocated_weight_ppm)
            + u64::from(automation_weight_ppm)
            + u64::from(reputation_weight_ppm);
        if weight_budget != u64::from(PARTS_PER_MILLION) {
            return Err(ScoringConfigError::WeightBudgetMismatch);
        }

        for (field, value) in [
            ("friction", friction_threshold_ppm),
            ("rejection", reject_threshold_ppm),
        ] {
            if value > PARTS_PER_MILLION {
                return Err(ScoringConfigError::ThresholdOutOfRange { field });
            }
        }

        if friction_threshold_ppm >= reject_threshold_ppm {
            return Err(ScoringConfigError::ThresholdOrderInvalid);
        }

        let active_maximum_ppm = PARTS_PER_MILLION - unallocated_weight_ppm;
        if friction_threshold_ppm > active_maximum_ppm {
            return Err(ScoringConfigError::FrictionThresholdUnreachable);
        }
        if reject_threshold_ppm >= active_maximum_ppm {
            return Err(ScoringConfigError::RejectThresholdUnreachable);
        }

        Ok(Self::from_ppm(
            biometric_weight_ppm,
            tts_weight_ppm,
            automation_weight_ppm,
            reputation_weight_ppm,
            friction_threshold_ppm,
            reject_threshold_ppm,
        ))
    }

    /// Neutral policy for development without signed scoring configuration.
    ///
    /// Its active score cannot reach either threshold. This keeps local
    /// interface work free from deployment calibration.
    pub fn development_default() -> Self {
        Self::from_ppm(
            200_000,
            200_000,
            200_000,
            200_000,
            900_000,
            PARTS_PER_MILLION,
        )
    }

    /// Non-production policy used by handler tests.
    #[cfg(test)]
    pub(crate) fn synthetic_test_policy() -> Self {
        Self::try_new(
            290_000, 210_000, 180_000, 160_000, 160_000, 420_000, 690_000,
        )
        .expect("synthetic scoring policy must be valid")
    }

    fn from_ppm(
        biometric_weight_ppm: u32,
        tts_weight_ppm: u32,
        automation_weight_ppm: u32,
        reputation_weight_ppm: u32,
        friction_threshold_ppm: u32,
        reject_threshold_ppm: u32,
    ) -> Self {
        let denominator = f64::from(PARTS_PER_MILLION);
        Self {
            biometric_weight: f64::from(biometric_weight_ppm) / denominator,
            tts_weight: f64::from(tts_weight_ppm) / denominator,
            automation_weight: f64::from(automation_weight_ppm) / denominator,
            reputation_weight: f64::from(reputation_weight_ppm) / denominator,
            friction_threshold: f64::from(friction_threshold_ppm) / denominator,
            reject_threshold: f64::from(reject_threshold_ppm) / denominator,
        }
    }

    /// Calculate the weighted score after bounding each untrusted component.
    pub fn score(&self, components: &RiskComponents) -> f64 {
        self.biometric_weight * bounded(components.biometric)
            + self.tts_weight * bounded(components.tts)
            + self.automation_weight * bounded(components.automation)
            + self.reputation_weight * bounded(components.reputation)
    }

    /// Return true only when the score is above the rejection threshold.
    pub fn rejects(&self, score: f64) -> bool {
        score > self.reject_threshold
    }

    /// Return true when the score reaches the graduated-friction threshold.
    pub fn requires_friction(&self, score: f64) -> bool {
        score >= self.friction_threshold
    }
}

impl fmt::Debug for ScoringConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScoringConfig([REDACTED])")
    }
}

/// Four scored signals and one unscored research signal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskComponents {
    /// Validator's biometric-distance risk.
    pub biometric: f64,
    /// Validator's synthetic-speech risk.
    pub tts: f64,
    /// Validator's temporal-coupling telemetry. This value is not scored.
    pub temporal: f64,
    /// Locally computed automation risk from client-reported signals.
    pub automation: f64,
    /// Locally computed wallet-reputation prior.
    pub reputation: f64,
}

/// Constrain one component to `[0, 1]`, mapping anything non-finite to maximum risk.
fn bounded(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_policy() -> ScoringConfig {
        ScoringConfig::synthetic_test_policy()
    }

    fn quiet() -> RiskComponents {
        RiskComponents {
            biometric: 0.0,
            tts: 0.0,
            temporal: 0.0,
            automation: 0.0,
            reputation: 0.5,
        }
    }

    fn silent() -> RiskComponents {
        RiskComponents {
            reputation: 0.0,
            ..quiet()
        }
    }

    #[test]
    fn rejects_a_weight_above_the_budget() {
        let error = ScoringConfig::try_new(1_000_001, 0, 0, 0, 0, 120_000, 240_000)
            .expect_err("an oversized weight must fail");
        assert_eq!(
            error,
            ScoringConfigError::WeightOutOfRange { field: "biometric" }
        );
    }

    #[test]
    fn rejects_any_inexact_weight_budget() {
        for biometric in [289_999, 290_001] {
            let error = ScoringConfig::try_new(
                biometric, 210_000, 180_000, 160_000, 160_000, 420_000, 690_000,
            )
            .expect_err("an inexact budget must fail");
            assert_eq!(error, ScoringConfigError::WeightBudgetMismatch);
        }
    }

    #[test]
    fn rejects_thresholds_outside_the_score_range() {
        let error = ScoringConfig::try_new(
            290_000, 210_000, 180_000, 160_000, 160_000, 420_000, 1_000_001,
        )
        .expect_err("an oversized threshold must fail");
        assert_eq!(
            error,
            ScoringConfigError::ThresholdOutOfRange { field: "rejection" }
        );
    }

    #[test]
    fn rejects_equal_or_inverted_thresholds() {
        for (friction, rejection) in [(690_000, 690_000), (700_000, 690_000)] {
            let error = ScoringConfig::try_new(
                290_000, 210_000, 180_000, 160_000, 160_000, friction, rejection,
            )
            .expect_err("misordered thresholds must fail");
            assert_eq!(error, ScoringConfigError::ThresholdOrderInvalid);
        }
    }

    #[test]
    fn deployed_policy_requires_reachable_friction() {
        let error = ScoringConfig::try_new(
            290_000, 210_000, 180_000, 160_000, 160_000, 830_000, 900_000,
        )
        .expect_err("an unreachable friction threshold must fail");
        assert_eq!(error, ScoringConfigError::FrictionThresholdUnreachable);
    }

    #[test]
    fn strict_rejection_boundary_must_sit_below_the_active_maximum() {
        let error = ScoringConfig::try_new(
            290_000, 210_000, 180_000, 160_000, 160_000, 420_000, 820_000,
        )
        .expect_err("an unreachable rejection threshold must fail");
        assert_eq!(error, ScoringConfigError::RejectThresholdUnreachable);
    }

    #[test]
    fn development_policy_is_neutral() {
        let policy = ScoringConfig::development_default();
        let maximum = RiskComponents {
            biometric: 1.0,
            tts: 1.0,
            temporal: 1.0,
            automation: 1.0,
            reputation: 1.0,
        };
        let score = policy.score(&maximum);

        assert!((score - 0.8).abs() < f64::EPSILON);
        assert!(!policy.requires_friction(score));
        assert!(!policy.rejects(score));
    }

    #[test]
    fn each_scored_component_uses_its_configured_weight() {
        type ComponentCase = (&'static str, fn(&mut RiskComponents), f64);

        let policy = synthetic_policy();
        let cases: [ComponentCase; 4] = [
            ("biometric", |c| c.biometric = 1.0, 0.29),
            ("tts", |c| c.tts = 1.0, 0.21),
            ("automation", |c| c.automation = 1.0, 0.16),
            ("reputation", |c| c.reputation = 1.0, 0.16),
        ];

        for (label, raise, expected) in cases {
            let mut components = silent();
            raise(&mut components);
            let score = policy.score(&components);
            assert!(
                (score - expected).abs() < 1e-12,
                "{label} alone should score {expected}, got {score}"
            );
        }
    }

    #[test]
    fn temporal_telemetry_never_changes_the_score() {
        let policy = synthetic_policy();
        let baseline = policy.score(&silent());
        let temporal = policy.score(&RiskComponents {
            temporal: 1.0,
            ..silent()
        });
        assert_eq!(temporal, baseline);
    }

    #[test]
    fn active_components_leave_the_reserved_share_unscored() {
        let policy = synthetic_policy();
        let score = policy.score(&RiskComponents {
            biometric: 1.0,
            tts: 1.0,
            temporal: 1.0,
            automation: 1.0,
            reputation: 1.0,
        });
        assert!((score - 0.82).abs() < 1e-12);
    }

    #[test]
    fn untrusted_components_are_bounded_before_scoring() {
        let policy = synthetic_policy();
        let inflated = RiskComponents {
            biometric: 1e300,
            ..quiet()
        };
        let capped = RiskComponents {
            biometric: 1.0,
            ..quiet()
        };
        assert_eq!(policy.score(&inflated), policy.score(&capped));

        let negative = RiskComponents {
            biometric: -5.0,
            ..quiet()
        };
        assert_eq!(policy.score(&negative), policy.score(&quiet()));

        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let score = policy.score(&RiskComponents {
                tts: bad,
                ..quiet()
            });
            let maximum_tts = policy.score(&RiskComponents {
                tts: 1.0,
                ..quiet()
            });
            assert!(score.is_finite());
            assert_eq!(score, maximum_tts);
        }
    }

    #[test]
    fn policy_boundaries_keep_strict_and_inclusive_semantics() {
        let policy = synthetic_policy();
        assert!(!policy.rejects(0.69));
        assert!(policy.rejects(0.690_001));
        assert!(!policy.requires_friction(0.419_999));
        assert!(policy.requires_friction(0.42));
    }

    #[test]
    fn debug_output_never_contains_configuration_values() {
        assert_eq!(
            format!("{:?}", synthetic_policy()),
            "ScoringConfig([REDACTED])"
        );
    }
}
