use crate::validation::handler::CaptureSignals;

/// Diagnostic evaluation of acoustic realism signals.
#[derive(Debug, PartialEq)]
pub struct AcousticEvaluation {
    pub risk_score: f64,
    pub virtual_device_detected: bool,
    pub flatness_out_of_bounds: bool,
    pub centroid_out_of_bounds: bool,
}

/// Evaluates acoustic realism (spectral flatness Wiener entropy and spectral
/// centroid in Hz) from `CaptureSignals`.
///
/// OBSERVE / TELEMETRY ONLY — do not treat as an authoritative anti-spoof gate.
/// These signals are computed client-side in the browser and reported by the
/// SDK, so an adversary controlling the client can forge them (a bot simply
/// reports in-range values). The un-forgeable acoustic check is computed
/// server-side by the validation service from the raw audio it already
/// receives; wiring that server-side score into the composite is the tracked
/// follow-up (remaining-public-tasks.md Item #15). Thresholds below are
/// uncalibrated starting points.
///
/// Physical microphones picking up human speech in ambient room acoustics exhibit:
/// - Spectral flatness between 0.015 and 0.85. Flatness < 0.015 indicates pure synthetic
///   tones / degenerate digital signals. Flatness > 0.85 indicates pure white-noise injection.
/// - Spectral centroid between 100 Hz and 6000 Hz. Centroid < 100 Hz indicates a
///   low-frequency DC offset / line hum. Centroid > 6000 Hz indicates an unnaturally
///   bright, high-frequency-dominant spectrum atypical of human speech in room acoustics
///   (speech centroid typically sits ~500-3000 Hz).
/// - Virtual device drivers (e.g. BlackHole, VB-Cable, Soundflower) set `virtual_device = true`.
pub fn evaluate_acoustic_realism(capture: Option<&CaptureSignals>) -> AcousticEvaluation {
    let mut risk_score: f64 = 0.0;
    let mut virtual_device_detected = false;
    let mut flatness_out_of_bounds = false;
    let mut centroid_out_of_bounds = false;

    let Some(c) = capture else {
        return AcousticEvaluation {
            risk_score: 0.0,
            virtual_device_detected: false,
            flatness_out_of_bounds: false,
            centroid_out_of_bounds: false,
        };
    };

    if c.virtual_device {
        virtual_device_detected = true;
        risk_score = 1.0;
    }

    if let Some(flatness) = c.flatness {
        if !(0.015..=0.85).contains(&flatness) {
            flatness_out_of_bounds = true;
            risk_score = (risk_score + 0.8).min(1.0);
        }
    }

    if let Some(centroid) = c.centroid {
        if !(100.0..=6000.0).contains(&centroid) {
            centroid_out_of_bounds = true;
            risk_score = (risk_score + 0.6).min(1.0);
        }
    }

    AcousticEvaluation {
        risk_score,
        virtual_device_detected,
        flatness_out_of_bounds,
        centroid_out_of_bounds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_none_capture_signals() {
        let eval = evaluate_acoustic_realism(None);
        assert_eq!(eval.risk_score, 0.0);
        assert!(!eval.virtual_device_detected);
        assert!(!eval.flatness_out_of_bounds);
        assert!(!eval.centroid_out_of_bounds);
    }

    #[test]
    fn passes_normal_physical_mic_signals() {
        let cap = CaptureSignals {
            virtual_device: false,
            voice_isolation_applied: None,
            flatness: Some(0.15),
            centroid: Some(1800.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 0.0);
        assert!(!eval.virtual_device_detected);
        assert!(!eval.flatness_out_of_bounds);
        assert!(!eval.centroid_out_of_bounds);
    }

    #[test]
    fn flags_virtual_device_driver() {
        let cap = CaptureSignals {
            virtual_device: true,
            voice_isolation_applied: None,
            flatness: Some(0.15),
            centroid: Some(1800.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 1.0);
        assert!(eval.virtual_device_detected);
    }

    #[test]
    fn flags_flatness_out_of_bounds_low() {
        let cap = CaptureSignals {
            virtual_device: false,
            voice_isolation_applied: None,
            flatness: Some(0.005),
            centroid: Some(1800.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 0.8);
        assert!(eval.flatness_out_of_bounds);
    }

    #[test]
    fn flags_flatness_out_of_bounds_high() {
        let cap = CaptureSignals {
            virtual_device: false,
            voice_isolation_applied: None,
            flatness: Some(0.92),
            centroid: Some(1800.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 0.8);
        assert!(eval.flatness_out_of_bounds);
    }

    #[test]
    fn flags_centroid_out_of_bounds_low() {
        let cap = CaptureSignals {
            virtual_device: false,
            voice_isolation_applied: None,
            flatness: Some(0.15),
            centroid: Some(45.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 0.6);
        assert!(eval.centroid_out_of_bounds);
    }

    #[test]
    fn flags_centroid_out_of_bounds_high() {
        let cap = CaptureSignals {
            virtual_device: false,
            voice_isolation_applied: None,
            flatness: Some(0.15),
            centroid: Some(7200.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 0.6);
        assert!(eval.centroid_out_of_bounds);
    }

    #[test]
    fn combines_multiple_violations_clamped_at_one() {
        let cap = CaptureSignals {
            virtual_device: false,
            voice_isolation_applied: None,
            flatness: Some(0.95),
            centroid: Some(8500.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 1.0);
        assert!(eval.flatness_out_of_bounds);
        assert!(eval.centroid_out_of_bounds);
    }

    #[test]
    fn flags_virtual_device_combined_with_out_of_bounds_flatness_and_centroid() {
        let cap = CaptureSignals {
            virtual_device: true,
            voice_isolation_applied: None,
            flatness: Some(0.99),
            centroid: Some(9500.0),
        };
        let eval = evaluate_acoustic_realism(Some(&cap));
        assert_eq!(eval.risk_score, 1.0);
        assert!(eval.virtual_device_detected);
        assert!(eval.flatness_out_of_bounds);
        assert!(eval.centroid_out_of_bounds);
    }
}
