//! Composite risk scoring for `/validate-features`.
//!
//! Combines the risk components into one score and holds the two policy
//! thresholds applied to it. Both branches of the validation handler score
//! through here so the arithmetic exists once.
//!
//! Rationale for the weights, the threshold values, and the component set is
//! recorded internally in `docs/reference/EXECUTOR-SCORING-INTERNALS.md`. This
//! repository is public; keep comments here factual.

const W_BIOMETRIC: f64 = 0.35;
const W_TTS: f64 = 0.25;
const W_TEMPORAL: f64 = 0.15;
const W_AUTOMATION: f64 = 0.15;
const W_REPUTATION: f64 = 0.10;

/// The weights sum to 1.0, so a new term must take weight from the existing ones
/// rather than extend the range. Checked during compilation, because a violation
/// would otherwise move both thresholds without touching either constant.
///
/// `f64::abs` is not const, so the tolerance is bounded from both sides; the sum
/// does not land on exactly 1.0 in binary floating point.
const _: () = {
    let sum = W_BIOMETRIC + W_TTS + W_TEMPORAL + W_AUTOMATION + W_REPUTATION;
    assert!(
        sum > 1.0 - 1e-9 && sum < 1.0 + 1e-9,
        "composite weights must sum to 1.0"
    );
};

/// Scores above this are refused. The comparison is strict.
pub const REJECT_THRESHOLD: f64 = 0.75;

/// Scores at or above this take the graduated-friction path. Inclusive.
pub const CAPTCHA_THRESHOLD: f64 = 0.45;

/// Ordering the two thresholds wrongly would leave one tier unreachable, since
/// the reject tier is evaluated first.
const _: () = assert!(CAPTCHA_THRESHOLD < REJECT_THRESHOLD);

/// The five scored signals for one verification attempt.
///
/// Named fields rather than positional arguments: every component is an `f64`
/// over the same range, so a transposed pair would compile cleanly and misvalue
/// every verification afterwards.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskComponents {
    /// Validator's biometric-distance risk.
    pub biometric: f64,
    /// Validator's synthetic-speech risk.
    pub tts: f64,
    /// Validator's temporal-coupling risk.
    pub temporal: f64,
    /// Locally computed automation risk from client-reported signals.
    pub automation: f64,
    /// Locally computed wallet-reputation prior.
    pub reputation: f64,
}

impl RiskComponents {
    /// The weighted composite, always finite and always within `[0, 1]`.
    ///
    /// Components are bounded before weighting rather than trusted: they cross a
    /// service boundary and carry no range validation on arrival. A non-finite
    /// component is treated as absent, matching how `sanitize_trace` handles
    /// untrusted floats elsewhere in the crate.
    pub fn composite(&self) -> f64 {
        W_BIOMETRIC * bounded(self.biometric)
            + W_TTS * bounded(self.tts)
            + W_TEMPORAL * bounded(self.temporal)
            + W_AUTOMATION * bounded(self.automation)
            + W_REPUTATION * bounded(self.reputation)
    }
}

/// Constrain one component to `[0, 1]`, mapping anything non-finite to zero.
///
/// The `is_finite` check has to precede the clamp: `f64::clamp` propagates NaN
/// rather than resolving it.
fn bounded(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every component zero except the reputation prior at its no-snapshot
    /// default, which is the shape of an ordinary passing capture.
    fn quiet() -> RiskComponents {
        RiskComponents {
            biometric: 0.0,
            tts: 0.0,
            temporal: 0.0,
            automation: 0.0,
            reputation: 0.5,
        }
    }

    /// All five components at zero. Raising exactly one isolates its weight.
    ///
    /// There is deliberately no runtime test that the weights sum to one: the
    /// `const` block above asserts it during compilation, so a violation fails
    /// the build and any test restating it could never run to fail.
    fn silent() -> RiskComponents {
        RiskComponents {
            reputation: 0.0,
            ..quiet()
        }
    }

    /// One isolation case: the component's name, a setter that raises only that
    /// component, and the weight it should then contribute on its own.
    type WeightCase = (&'static str, fn(&mut RiskComponents), f64);

    #[test]
    fn each_component_is_wired_to_its_own_weight() {
        // Checks wiring, not values. Raising one component must move the score by
        // that component's weight and no other, which catches a field mapped to
        // the wrong constant. It cannot catch a constant whose value changed,
        // because the expectation reads the same constant: verified by mutation
        // on 2026-07-29, where transposing W_BIOMETRIC and W_TTS left this test
        // green. The values themselves are pinned independently by
        // `expected_composite` in the handler's `validator_reached_tests`, which
        // restates the table as literals for exactly that reason.
        let cases: [WeightCase; 5] = [
            ("biometric", |c| c.biometric = 1.0, W_BIOMETRIC),
            ("tts", |c| c.tts = 1.0, W_TTS),
            ("temporal", |c| c.temporal = 1.0, W_TEMPORAL),
            ("automation", |c| c.automation = 1.0, W_AUTOMATION),
            ("reputation", |c| c.reputation = 1.0, W_REPUTATION),
        ];
        for (label, raise, expected) in cases {
            let mut components = silent();
            raise(&mut components);
            let got = components.composite();
            assert!(
                (got - expected).abs() < 1e-9,
                "{label} alone should score {expected}, got {got}"
            );
        }
    }

    #[test]
    fn a_quiet_capture_scores_only_the_reputation_prior() {
        let got = quiet().composite();
        assert!(
            (got - 0.05).abs() < 1e-9,
            "expected the 0.10 weight on a 0.5 prior, got {got}"
        );
    }

    #[test]
    fn all_components_at_maximum_score_exactly_one() {
        let got = RiskComponents {
            biometric: 1.0,
            tts: 1.0,
            temporal: 1.0,
            automation: 1.0,
            reputation: 1.0,
        }
        .composite();
        assert!((got - 1.0).abs() < 1e-9, "expected 1.0, got {got}");
    }

    #[test]
    fn a_component_above_one_cannot_inflate_the_score() {
        // Components cross a service boundary unvalidated, so bounding has to
        // happen here rather than being assumed upstream.
        let inflated = RiskComponents {
            biometric: 1e300,
            ..quiet()
        };
        let capped = RiskComponents {
            biometric: 1.0,
            ..quiet()
        };
        assert_eq!(inflated.composite(), capped.composite());
        assert!(inflated.composite() <= 1.0);
    }

    #[test]
    fn a_negative_component_cannot_deflate_the_score() {
        let negative = RiskComponents {
            biometric: -5.0,
            ..quiet()
        };
        assert_eq!(negative.composite(), quiet().composite());
        assert!(negative.composite() >= 0.0);
    }

    #[test]
    fn a_non_finite_component_is_treated_as_absent() {
        // NaN compares false against everything, so an unguarded non-finite
        // component would make the resulting score meaningless downstream.
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let components = RiskComponents {
                tts: bad,
                ..quiet()
            };
            let got = components.composite();
            assert!(got.is_finite(), "{bad} produced a non-finite composite");
            assert_eq!(got, quiet().composite());
        }
    }

    #[test]
    fn the_score_stays_within_bounds_for_any_input() {
        for value in [f64::MIN, -1.0, 0.0, 0.5, 1.0, 1e300, f64::MAX, f64::NAN] {
            let got = RiskComponents {
                biometric: value,
                tts: value,
                temporal: value,
                automation: value,
                reputation: value,
            }
            .composite();
            assert!(
                got.is_finite() && (0.0..=1.0).contains(&got),
                "component {value} produced {got}, outside [0, 1]"
            );
        }
    }
}
