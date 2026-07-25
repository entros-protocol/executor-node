//! Curve-trace region + kinematics scoring (Stage 1, observe-only).
//!
//! Restores the touch half of the challenge's content binding. The audio half is
//! bound by Whisper phrase-matching; this module scores whether the user's coarse
//! curve-trace outline (a) stayed in the issued curve's region and (b) has the
//! speed and nature of a genuine continuous human gesture.
//!
//! This is NOT a precision / fidelity check. The curve is a complexity +
//! temporal-coupling prompt, never a 1:1 tracing test — real traces are near the
//! lines, following, incomplete, and never perfect, and those pass. What scores
//! low is a trace that leaves the curve's region, or a synthetic gesture
//! (teleporting, constant-velocity, or no real movement). An in-region gesture
//! with human dynamics is intentionally accepted even if messy — that is a human
//! in the right place, which is exactly what the forgiving design wants.
//!
//! Stage 1 is observe-only: the scores here feed telemetry so we can calibrate a
//! forgiving threshold on real traces. Nothing gates on them yet.

use crate::challenge::lissajous::LissajousParams;

/// The client renders the curve at this size inside the 200x200 viewBox
/// (`pulse-challenge.tsx`: `p.x * size + ox`, with `size = 100`).
const CURVE_SIZE: f64 = 100.0;

/// The five anchor positions the curve box can sit at (`registry::generate` /
/// `pulse-challenge.tsx` `lissajousAnchor`). We score against all five and keep
/// the best-fitting one, so the check never depends on knowing which anchor the
/// client actually rendered.
const ANCHORS: [(f64, f64); 5] = [
    (0.0, 0.0),
    (100.0, 0.0),
    (0.0, 100.0),
    (100.0, 100.0),
    (50.0, 50.0),
];

/// A trace point counts as in-region if within this many viewBox units of the
/// nearest reference point. Generous by design (1/8 of the frame) — this is a
/// "were you near the curve", not a "did you trace it exactly", band.
const PROXIMITY_BAND: f64 = 25.0;

/// Minimum total traced path length (viewBox units) for the gesture to read as
/// real movement. A genuine trace runs to hundreds of units; this only rejects a
/// tap or a near-still pointer.
const MIN_PATH_LENGTH: f64 = 40.0;

/// A single equal-time segment longer than this reads as a teleport /
/// discontinuity rather than a continuous human gesture.
const TELEPORT_SEGMENT: f64 = 60.0;

/// Minimum coefficient of variation of per-segment speed. Real tracing speeds up
/// and slows down; a constant-velocity synthetic gesture sits near zero.
const MIN_SPEED_COV: f64 = 0.15;

/// Hard cap on the number of trace points scored. A real equal-time outline is
/// O(100) points; the 1 MB request-body limit still permits ~175k, so this bounds
/// the O(points) scoring work to stay sub-millisecond regardless of the payload.
const MAX_CURVE_TRACE_POINTS: usize = 2048;

/// Absolute viewBox envelope. The frame is 200 units; a pointer leaving the
/// container can slightly exceed it, so this is generous. It drops junk and blocks
/// huge finite literals (e.g. `1e308`) that would overflow to `+Inf` and poison
/// the calibration corpus.
const CURVE_TRACE_ENVELOPE: f64 = 10_000.0;

/// Scores plus raw sub-metrics for one curve-trace outline. The sub-metrics are
/// logged for Stage 1 calibration; `region_score` and `kinematic_score` are the
/// headline signals.
#[derive(Debug, Clone, PartialEq)]
pub struct CurveTraceReport {
    /// [0,1] fraction of trace points within the proximity band of the curve, at
    /// the best-fitting anchor. Higher means the trace stayed in the region.
    pub region_score: f64,
    /// [0,1] how human the gesture's speed and nature look — the minimum of the
    /// movement, continuity, and speed-variation sub-scores.
    pub kinematic_score: f64,
    /// Median nearest-distance to the curve, viewBox units, at the best anchor.
    pub median_deviation: f64,
    /// Total traced path length, viewBox units.
    pub path_length: f64,
    /// Longest single equal-time segment, viewBox units (the teleport detector).
    pub max_segment: f64,
    /// Coefficient of variation of per-segment speed (dt-invariant).
    pub speed_cov: f64,
    /// Mean absolute speed, viewBox units per second (from `duration_ms`).
    pub mean_speed: f64,
    /// Number of points in the outline.
    pub point_count: usize,
}

impl CurveTraceReport {
    /// Zeroed report for a degenerate outline (fewer than two points).
    fn empty(point_count: usize) -> Self {
        Self {
            region_score: 0.0,
            kinematic_score: 0.0,
            median_deviation: f64::INFINITY,
            path_length: 0.0,
            max_segment: 0.0,
            speed_cov: 0.0,
            mean_speed: 0.0,
            point_count,
        }
    }
}

/// Regenerate the issued curve's shape in the viewBox frame at a given anchor.
/// Ports `generateLissajousPoints` (pulse-sdk) exactly:
///   `x(t) = (sin(a*t + delta) + 1) / 2`, `y(t) = (sin(b*t) + 1) / 2`,
/// then maps normalized `[0,1]` to the viewBox via `n * CURVE_SIZE + anchor`.
fn reference_points(params: &LissajousParams, anchor: (f64, f64)) -> Vec<(f64, f64)> {
    let n = params.points.max(1) as usize;
    let a = f64::from(params.a);
    let b = f64::from(params.b);
    let mut pts = Vec::with_capacity(n);
    for i in 0..n {
        let t = (i as f64 / n as f64) * std::f64::consts::TAU;
        let x = (f64::sin(a * t + params.delta) + 1.0) / 2.0;
        let y = (f64::sin(b * t) + 1.0) / 2.0;
        pts.push((x * CURVE_SIZE + anchor.0, y * CURVE_SIZE + anchor.1));
    }
    pts
}

/// Nearest Euclidean distance from `p` to any reference point. Point-to-point
/// against the dense (200-point) reference; consecutive reference points sit
/// ~1-2 units apart, well under the proximity band, so this is within noise of a
/// point-to-segment distance.
fn nearest_distance(p: (f64, f64), reference: &[(f64, f64)]) -> f64 {
    let mut best = f64::INFINITY;
    for &(rx, ry) in reference {
        let dx = p.0 - rx;
        let dy = p.1 - ry;
        let d2 = dx * dx + dy * dy;
        if d2 < best {
            best = d2;
        }
    }
    best.sqrt()
}

fn median(mut xs: Vec<f64>) -> f64 {
    if xs.is_empty() {
        return f64::INFINITY;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = xs.len() / 2;
    if xs.len().is_multiple_of(2) {
        (xs[mid - 1] + xs[mid]) / 2.0
    } else {
        xs[mid]
    }
}

/// Region score at the best-fitting anchor. Returns `(fraction_in_band,
/// median_deviation)`. Assumes `trace` is non-empty (callers guard on length).
fn score_region(trace: &[(f64, f64)], params: &LissajousParams) -> (f64, f64) {
    // The curve shape is anchor-invariant — anchors only translate it — so build
    // the base shape once at the origin and shift each trace point by `-anchor`
    // when measuring, instead of regenerating the 200-point curve five times.
    let base = reference_points(params, (0.0, 0.0));
    let mut best_fraction = 0.0_f64;
    let mut best_median = f64::INFINITY;
    let mut initialized = false;
    for anchor in ANCHORS {
        let dists: Vec<f64> = trace
            .iter()
            .map(|&(px, py)| nearest_distance((px - anchor.0, py - anchor.1), &base))
            .collect();
        let in_band = dists.iter().filter(|&&d| d <= PROXIMITY_BAND).count();
        let fraction = in_band as f64 / dists.len() as f64;
        let med = median(dists);
        let better =
            !initialized || fraction > best_fraction || (fraction == best_fraction && med < best_median);
        if better {
            best_fraction = fraction;
            best_median = med;
            initialized = true;
        }
    }
    (best_fraction, best_median)
}

/// Kinematic sub-metrics from the outline. Returns `(kinematic_score,
/// path_length, max_segment, speed_cov)`. PRECONDITION: the sender supplies an
/// equal-time-resampled outline (the SDK owns this) — per-segment length is then
/// proportional to speed, and the coefficient of variation of segment lengths is
/// invariant to the constant timestep. Raw variable-`dt` pointer events would make
/// `speed_cov` and `max_segment` conflate spatial and temporal variation.
fn score_kinematics(trace: &[(f64, f64)]) -> (f64, f64, f64, f64) {
    let seg_lengths: Vec<f64> = trace
        .windows(2)
        .map(|w| {
            let dx = w[1].0 - w[0].0;
            let dy = w[1].1 - w[0].1;
            (dx * dx + dy * dy).sqrt()
        })
        .collect();

    let path_length: f64 = seg_lengths.iter().sum();
    let max_segment = seg_lengths.iter().copied().fold(0.0_f64, f64::max);

    let n = seg_lengths.len() as f64;
    let mean = if n > 0.0 { path_length / n } else { 0.0 };
    let speed_cov = if mean > 0.0 {
        let var = seg_lengths.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
        var.sqrt() / mean
    } else {
        0.0
    };

    // Forgiving [0,1] sub-scores.
    let moved = (path_length / MIN_PATH_LENGTH).clamp(0.0, 1.0);
    let continuity = if max_segment <= TELEPORT_SEGMENT {
        1.0
    } else {
        (1.0 - (max_segment - TELEPORT_SEGMENT) / TELEPORT_SEGMENT).clamp(0.0, 1.0)
    };
    let variation = (speed_cov / MIN_SPEED_COV).clamp(0.0, 1.0);

    let kinematic_score = moved.min(continuity).min(variation);
    (kinematic_score, path_length, max_segment, speed_cov)
}

/// Cap and clean a raw client outline before scoring. Keeps at most
/// `MAX_CURVE_TRACE_POINTS` points and drops any that is non-finite or outside the
/// viewBox envelope — the defensive boundary that stops a hostile payload from
/// burning CPU (bounded length) or poisoning the corpus (no `Inf`/`NaN`/absurd
/// coordinates). `take` precedes `filter`, so at most `MAX_CURVE_TRACE_POINTS`
/// points are ever examined.
pub fn sanitize_trace(points: &[[f64; 2]]) -> Vec<(f64, f64)> {
    points
        .iter()
        .take(MAX_CURVE_TRACE_POINTS)
        .filter(|p| {
            p[0].is_finite()
                && p[1].is_finite()
                && p[0].abs() <= CURVE_TRACE_ENVELOPE
                && p[1].abs() <= CURVE_TRACE_ENVELOPE
        })
        .map(|p| (p[0], p[1]))
        .collect()
}

/// Score a coarse curve-trace outline against the issued curve. `trace` is the
/// equal-time-resampled outline in the client's 200x200 viewBox frame;
/// `duration_ms` is the wall-clock span of the outline. Observe-only — the
/// caller logs the report and gates nothing on it.
pub fn score_curve_trace(
    trace: &[(f64, f64)],
    duration_ms: f64,
    params: &LissajousParams,
) -> CurveTraceReport {
    if trace.len() < 2 {
        return CurveTraceReport::empty(trace.len());
    }

    let (region_score, median_deviation) = score_region(trace, params);
    let (kinematic_score, path_length, max_segment, speed_cov) = score_kinematics(trace);

    let mean_speed = if duration_ms.is_finite() && duration_ms > 0.0 {
        path_length / (duration_ms / 1000.0)
    } else {
        0.0
    };

    CurveTraceReport {
        region_score,
        kinematic_score,
        median_deviation,
        path_length,
        max_segment,
        speed_cov,
        mean_speed,
        point_count: trace.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params(anchor: (u16, u16)) -> LissajousParams {
        LissajousParams {
            a: 3,
            b: 4,
            delta: std::f64::consts::PI * 0.5,
            points: 200,
            anchor_x: anchor.0,
            anchor_y: anchor.1,
        }
    }

    /// A trace that lies exactly on the issued curve, subsampled to `n` points
    /// (equal index spacing ~ equal time here). `fraction` in (0,1] traces only
    /// the leading part of the curve, modelling an incomplete trace.
    fn faithful_trace(params: &LissajousParams, anchor: (f64, f64), n: usize, fraction: f64) -> Vec<(f64, f64)> {
        let reference = reference_points(params, anchor);
        let span = ((reference.len() as f64) * fraction) as usize;
        let span = span.max(2).min(reference.len());
        (0..n)
            .map(|i| {
                let idx = (i * (span - 1)) / (n - 1);
                reference[idx]
            })
            .collect()
    }

    #[test]
    fn faithful_full_trace_scores_high_region() {
        let params = test_params((50, 50));
        let trace = faithful_trace(&params, (50.0, 50.0), 64, 1.0);
        let report = score_curve_trace(&trace, 9000.0, &params);
        assert!(report.region_score > 0.95, "region_score = {}", report.region_score);
        assert!(report.median_deviation < PROXIMITY_BAND);
    }

    #[test]
    fn faithful_partial_trace_still_scores_high_region() {
        // Incompleteness must not be penalised: tracing only the first ~40% of
        // the curve should still be fully in-region.
        let params = test_params((0, 0));
        let trace = faithful_trace(&params, (0.0, 0.0), 48, 0.4);
        let report = score_curve_trace(&trace, 5000.0, &params);
        assert!(report.region_score > 0.95, "region_score = {}", report.region_score);
    }

    #[test]
    fn trace_far_outside_the_box_scores_low_region() {
        let params = test_params((50, 50));
        // A cluster far from every anchor's curve.
        let trace: Vec<(f64, f64)> = (0..64)
            .map(|i| (900.0 + i as f64, 900.0 + (i % 3) as f64))
            .collect();
        let report = score_curve_trace(&trace, 9000.0, &params);
        assert!(report.region_score < 0.05, "region_score = {}", report.region_score);
    }

    #[test]
    fn best_anchor_search_is_translation_robust() {
        // Trace the curve at one anchor but score with params carrying a
        // different issued anchor; the five-anchor search should still find it.
        let issued = test_params((0, 0));
        let trace = faithful_trace(&issued, (100.0, 100.0), 64, 1.0);
        let report = score_curve_trace(&trace, 9000.0, &issued);
        assert!(report.region_score > 0.95, "region_score = {}", report.region_score);
    }

    #[test]
    fn no_movement_scores_low_kinematic() {
        let params = test_params((50, 50));
        // A single spot on the curve, repeated: perfect region, but no gesture.
        let reference = reference_points(&params, (50.0, 50.0));
        let spot = reference[10];
        let trace: Vec<(f64, f64)> = vec![spot; 64];
        let report = score_curve_trace(&trace, 9000.0, &params);
        assert!(report.region_score > 0.95, "region should be high, got {}", report.region_score);
        assert!(report.kinematic_score < 0.05, "kinematic_score = {}", report.kinematic_score);
        assert_eq!(report.path_length, 0.0);
    }

    #[test]
    fn constant_velocity_scores_low_kinematic() {
        let params = test_params((50, 50));
        // Perfectly even spacing along a straight line: no speed variation.
        let trace: Vec<(f64, f64)> = (0..64).map(|i| (50.0 + i as f64, 100.0)).collect();
        let report = score_curve_trace(&trace, 9000.0, &params);
        assert!(report.speed_cov < MIN_SPEED_COV, "speed_cov = {}", report.speed_cov);
        assert!(report.kinematic_score < 0.05, "kinematic_score = {}", report.kinematic_score);
    }

    #[test]
    fn teleport_scores_low_kinematic() {
        let params = test_params((50, 50));
        // A believable trace with one huge discontinuity injected.
        let mut trace = faithful_trace(&params, (50.0, 50.0), 64, 1.0);
        trace[32] = (5.0, 195.0);
        let report = score_curve_trace(&trace, 9000.0, &params);
        assert!(report.max_segment > TELEPORT_SEGMENT, "max_segment = {}", report.max_segment);
        assert!(report.kinematic_score < 1.0);
    }

    #[test]
    fn faithful_trace_with_jitter_has_speed_variation() {
        let params = test_params((50, 50));
        let reference = reference_points(&params, (50.0, 50.0));
        // Sample the curve with index-dependent jitter so segment lengths vary.
        let trace: Vec<(f64, f64)> = (0..64)
            .map(|i| {
                let idx = (i * (reference.len() - 1)) / 63;
                let (x, y) = reference[idx];
                let j = ((i as f64) * 0.7).sin() * 3.0;
                (x + j, y - j)
            })
            .collect();
        let report = score_curve_trace(&trace, 9000.0, &params);
        assert!(report.speed_cov > MIN_SPEED_COV, "speed_cov = {}", report.speed_cov);
        assert!(report.region_score > 0.9, "region_score = {}", report.region_score);
    }

    #[test]
    fn degenerate_trace_returns_empty_report() {
        let params = test_params((50, 50));
        let report = score_curve_trace(&[(10.0, 10.0)], 9000.0, &params);
        assert_eq!(report.region_score, 0.0);
        assert_eq!(report.kinematic_score, 0.0);
        assert_eq!(report.point_count, 1);
    }

    #[test]
    fn zero_duration_yields_zero_mean_speed_without_panic() {
        let params = test_params((50, 50));
        let trace = faithful_trace(&params, (50.0, 50.0), 64, 1.0);
        let report = score_curve_trace(&trace, 0.0, &params);
        assert_eq!(report.mean_speed, 0.0);
        // Region and CoV are duration-free, so they remain meaningful.
        assert!(report.region_score > 0.95);
    }

    #[test]
    fn sanitize_trace_caps_point_count() {
        let huge: Vec<[f64; 2]> = (0..200_000).map(|i| [(i % 200) as f64, 100.0]).collect();
        let clean = sanitize_trace(&huge);
        assert_eq!(clean.len(), MAX_CURVE_TRACE_POINTS);
    }

    #[test]
    fn sanitize_trace_drops_non_finite_and_out_of_envelope() {
        let points = vec![
            [50.0, 50.0],
            [f64::NAN, 10.0],
            [10.0, f64::INFINITY],
            [1e308, 1e308],
            [100.0, 100.0],
        ];
        assert_eq!(sanitize_trace(&points), vec![(50.0, 50.0), (100.0, 100.0)]);
    }

    /// Manual inspection helper — prints a table of scores for representative
    /// gestures so a human can eyeball the discriminator and calibrate the
    /// forgiving thresholds. Not an assertion. Run:
    ///   cargo test print_score_table -- --ignored --nocapture
    #[test]
    #[ignore = "manual inspection helper; run with --ignored --nocapture"]
    fn print_score_table() {
        let params = test_params((50, 50));
        let anchor = (50.0, 50.0);
        let reference = reference_points(&params, anchor);

        let faithful = faithful_trace(&params, anchor, 64, 1.0);
        let partial = faithful_trace(&params, anchor, 64, 0.4);
        let jittered: Vec<(f64, f64)> = (0..64)
            .map(|i| {
                let idx = (i * (reference.len() - 1)) / 63;
                let (x, y) = reference[idx];
                (x + ((i as f64) * 0.7).sin() * 4.0, y - ((i as f64) * 1.1).cos() * 4.0)
            })
            .collect();
        // Deterministic pseudo-random cloud inside the curve's region.
        let scribble: Vec<(f64, f64)> = (0..64)
            .map(|i| {
                let a = ((i as f64) * 12.9898).sin() * 43758.5453;
                let b = ((i as f64) * 78.233).sin() * 43758.5453;
                (40.0 + (a - a.floor()) * 120.0, 40.0 + (b - b.floor()) * 120.0)
            })
            .collect();
        let off_box: Vec<(f64, f64)> = (0..64).map(|i| (900.0 + i as f64, 900.0)).collect();
        let still: Vec<(f64, f64)> = vec![reference[10]; 64];
        let constant: Vec<(f64, f64)> = (0..64).map(|i| (50.0 + i as f64, 100.0)).collect();

        let cases: [(&str, &[(f64, f64)]); 7] = [
            ("faithful full trace", &faithful),
            ("faithful 40% (partial)", &partial),
            ("human + jitter", &jittered),
            ("wild scribble (in region)", &scribble),
            ("off-box cluster", &off_box),
            ("no movement (one spot)", &still),
            ("constant velocity (bot)", &constant),
        ];

        println!(
            "\n{:<28}{:>8}{:>11}{:>9}{:>9}{:>9}{:>10}",
            "gesture", "region", "kinematic", "med.dev", "pathlen", "maxseg", "speedCoV"
        );
        println!("{}", "-".repeat(84));
        for (name, trace) in cases {
            let r = score_curve_trace(trace, 9000.0, &params);
            println!(
                "{:<28}{:>8.2}{:>11.2}{:>9.1}{:>9.1}{:>9.1}{:>10.2}",
                name,
                r.region_score,
                r.kinematic_score,
                r.median_deviation,
                r.path_length,
                r.max_segment,
                r.speed_cov
            );
        }
        println!();
    }
}
