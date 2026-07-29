//! Curve-trace scoring for the touch half of the challenge.
//!
//! The audio half is bound by phrase-matching against the transcription. This
//! module scores the client's coarse curve-trace outline on three axes: whether
//! it stayed in the issued curve's region, whether its speed and nature read as a
//! continuous gesture, and whether it followed the issued path.
//!
//! It is not a precision check. The curve is a complexity and temporal-coupling
//! prompt rather than a 1:1 tracing test, so traces that are near the lines,
//! incomplete, and imperfect are expected and accepted by design.
//!
//! Calibration history, scoring status, and the reasoning behind each constant
//! are recorded internally in `docs/reference/EXECUTOR-SCORING-INTERNALS.md`.
//! This repository is public; keep comments here factual.

use crate::challenge::lissajous::LissajousParams;

/// The client renders the curve at this size inside the 200x200 viewBox
/// (`pulse-challenge.tsx`: `p.x * size + ox`, with `size = 100`).
const CURVE_SIZE: f64 = 100.0;

/// The five anchor positions the curve box can sit at (`registry::generate` /
/// `pulse-challenge.tsx` `lissajousAnchor`). `region_score` takes the best fit
/// across all five, so it never depends on knowing which anchor the client
/// rendered — at the cost of also accepting a gesture made in the *wrong* box.
/// The wallet-connected client does honour the server's anchor
/// (`pulse-challenge.tsx`: `curve.anchorX` when present), and it is the only path
/// that sends an outline, so `region_score_issued_anchor` measures the stricter
/// alternative alongside it for Stage 1b to choose between.
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

/// A single equal-time segment longer than this reads as a discontinuity rather
/// than a continuous gesture. Calibration status and history:
/// docs/reference/EXECUTOR-SCORING-INTERNALS.md
const TELEPORT_SEGMENT: f64 = 60.0;

/// Minimum coefficient of variation of per-segment speed. Real tracing speeds up
/// and slows down; a constant-velocity synthetic gesture sits near zero.
const MIN_SPEED_COV: f64 = 0.15;

/// How far along the curve the alignment cursor may advance between two
/// consecutive trace samples, in reference-point indices — the load-bearing
/// parameter of the alignment residual.
///
/// It is swept rather than fixed because the parameter has a **cliff on the low
/// side**, measured on live traffic 2026-07-26: the cursor advances at most
/// `window` indices per sample, so once a genuine trace outruns it the lag
/// compounds and can never be recovered. Windows 8 and 16 inverted outright — a
/// fast honest trace scored 46.9/48.0 against 37.9/30.8 for a rapid in-region
/// scribble — and window 24 inverted too (honest 34.1 vs scribble 23.5). Both were
/// dropped from the sweep. Too small is not "stricter", it is *wrong*, so the
/// window is chosen generously and the discrimination lives in the threshold.
///
/// The top end is bounded by the same data. As the window widens the residual
/// decays toward `median_deviation` — at the limit the cursor reaches any index and
/// the metric degenerates into the plain proximity it exists to replace. Window 40
/// is where the honest trace had already converged to its own proximity floor (8.9
/// against a deviation of 8.1, a ratio of 1.10) while the scribbles were still far
/// above theirs (17.1 against 4.8, a ratio of 3.55). Widening past the point where
/// honest traces converge can only help an attacker. The assertions below keep the
/// sweep ascending and at least 4x clear of the curve's own resolution.
///
/// Stage 1 logs the whole sweep so the window and threshold come from real traces
/// instead of from synthetic fixtures (which mispredicted the window). Stage 1b
/// collapses this to the single chosen value.
const ALIGNMENT_WINDOW_SWEEP: [usize; 4] = [24, 32, 40, 48];

/// Resolution the server issues curves at (`LissajousParams::generate`).
const ISSUED_CURVE_POINTS: usize = 200;

const _: () = {
    assert!(!ALIGNMENT_WINDOW_SWEEP.is_empty());
    let mut i = 1;
    while i < ALIGNMENT_WINDOW_SWEEP.len() {
        assert!(
            ALIGNMENT_WINDOW_SWEEP[i - 1] < ALIGNMENT_WINDOW_SWEEP[i],
            "sweep must be strictly ascending, and free of duplicates: the log \
             rendering, the calibration table and every window lookup read it in \
             order. Note residuals do NOT fall monotonically with a wider window — \
             the greedy cursor is path-dependent and can overshoot."
        );
        i += 1;
    }
    assert!(
        ALIGNMENT_WINDOW_SWEEP[ALIGNMENT_WINDOW_SWEEP.len() - 1] * 4 <= ISSUED_CURVE_POINTS,
        "the widest window must stay well clear of the curve resolution, or the \
         residual degenerates into unconstrained proximity"
    );
};

/// Stride between candidate alignment start indices. The trace may begin anywhere
/// on the curve, so starts are swept; every 4th index is ample given the curve is
/// sampled at 200 points and consecutive points sit ~1-2 units apart.
///
/// Doubling this halves the scoring cost, but it is deliberately NOT done during
/// calibration: at stride 8 two degenerate fixtures shift (48.4 -> 48.8, 29.6 ->
/// 31.1), and every datapoint gathered so far was measured at stride 4. Comparable
/// numbers across devices are worth more than a fraction of a millisecond of
/// detached CPU. Revisit once Stage 1b collapses the sweep to one window.
const ALIGNMENT_START_STRIDE: usize = 4;

/// Hard cap on the number of trace points scored. A real equal-time outline is
/// O(100) points; the 1 MB request-body limit still permits ~175k, so this bounds
/// the scoring work regardless of the payload.
const MAX_CURVE_TRACE_POINTS: usize = 2048;

/// Point budget for the alignment residual specifically. Alignment costs
/// `O(starts x points x window)` — an order more than the region and kinematic
/// terms — so a payload above this is uniformly subsampled before aligning. The
/// SDK always sends exactly 64, so this only ever engages on a payload that is not
/// a real outline; subsampling an equal-time series stays equal-time (it only
/// widens the timestep), so the score remains meaningful rather than skipped.
const ALIGNMENT_MAX_POINTS: usize = 256;

/// `subsample_for_alignment` divides by `ALIGNMENT_MAX_POINTS - 1`.
const _: () = assert!(ALIGNMENT_MAX_POINTS > 1);

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
    /// [0,1] fraction in band scored at the *issued* anchor only, rather than the
    /// best-fitting of the five. Observe-only companion to `region_score`: the
    /// wallet-connected client honours the server anchor, so if this tracks
    /// `region_score` on real traffic the best-of-five search can be dropped, which
    /// would restore the positional binding that the search currently gives away.
    pub region_score_issued_anchor: f64,
    /// Median nearest-distance at the *issued* anchor, viewBox units. Shares a
    /// frame with `alignment_residuals`, so `residual - median_deviation_issued_anchor`
    /// is the **ordering penalty**: how much worse the trace gets when forced to be
    /// explained as forward motion, versus merely being near the curve. Live traces
    /// separate far better on that difference than on either term alone, because it
    /// divides out how precisely the user can trace — which is device- and
    /// person-dependent and explicitly not what the challenge tests.
    pub median_deviation_issued_anchor: f64,
    /// Median residual, viewBox units, of the trace against the issued curve under
    /// a monotonic correspondence — one entry per [`ALIGNMENT_WINDOW_SWEEP`] window,
    /// in the same order. Low means the trace is explainable as forward motion along
    /// the issued path: pauses and incompleteness cost nothing, sloppiness degrades
    /// gracefully, and a wander that merely stays *near* the curve cannot be
    /// explained cheaply.
    pub alignment_residuals: [f64; ALIGNMENT_WINDOW_SWEEP.len()],
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
            region_score_issued_anchor: 0.0,
            median_deviation_issued_anchor: f64::INFINITY,
            alignment_residuals: [f64::INFINITY; ALIGNMENT_WINDOW_SWEEP.len()],
            path_length: 0.0,
            max_segment: 0.0,
            speed_cov: 0.0,
            mean_speed: 0.0,
            point_count,
        }
    }

    /// Compact `window:residual` rendering, e.g. `8:55.1 16:12.3 24:7.5`. One log
    /// field that stays correct if the sweep changes, and stays greppable.
    pub fn alignment_sweep_display(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(ALIGNMENT_WINDOW_SWEEP.len() * 12);
        for (window, residual) in ALIGNMENT_WINDOW_SWEEP.iter().zip(&self.alignment_residuals) {
            if !out.is_empty() {
                out.push(' ');
            }
            // Infallible for String; the result is discarded deliberately.
            let _ = write!(out, "{window}:{residual:.2}");
        }
        out
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

/// Median by selection rather than a full sort — `O(n)` instead of `O(n log n)`,
/// which matters because the alignment sweep takes a median per candidate start.
/// Reorders `xs` in place. Empty input yields infinity.
fn median(xs: &mut [f64]) -> f64 {
    if xs.is_empty() {
        return f64::INFINITY;
    }
    let mid = xs.len() / 2;
    let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    let (_, upper, _) = xs.select_nth_unstable_by(mid, cmp);
    let upper = *upper;
    if !xs.len().is_multiple_of(2) {
        return upper;
    }
    // Selection leaves everything at or below `mid` in the left partition, so the
    // lower of the two middle values is that partition's maximum.
    let lower = xs[..mid].iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (lower + upper) / 2.0
}

/// Proximity measured two ways: at the best-fitting anchor of the five, and at the
/// issued anchor alone.
struct RegionScores {
    /// Fraction in band at the best-fitting anchor.
    best_fraction: f64,
    /// Median nearest-distance at the best-fitting anchor.
    best_median: f64,
    /// Fraction in band at the issued anchor.
    issued_fraction: f64,
    /// Median nearest-distance at the issued anchor. Pairs with the alignment
    /// residual, which is also measured at the issued anchor — the two must share a
    /// frame for their difference (the ordering penalty) to mean anything.
    issued_median: f64,
}

/// Region proximity at the best-fitting anchor and at the issued anchor.
///
/// `base` is the curve generated at the origin: anchors only translate the shape,
/// so each candidate anchor is measured by shifting the trace rather than
/// regenerating the curve. Assumes `trace` is non-empty (callers guard on length).
fn score_region(trace: &[(f64, f64)], base: &[(f64, f64)], issued: (f64, f64)) -> RegionScores {
    let mut dists = Vec::with_capacity(trace.len());
    let mut fraction_at = |anchor: (f64, f64)| -> (f64, f64) {
        dists.clear();
        dists.extend(
            trace
                .iter()
                .map(|&(px, py)| nearest_distance((px - anchor.0, py - anchor.1), base)),
        );
        let in_band = dists.iter().filter(|&&d| d <= PROXIMITY_BAND).count();
        let fraction = in_band as f64 / dists.len() as f64;
        (fraction, median(&mut dists))
    };

    let mut best_fraction = 0.0_f64;
    let mut best_median = f64::INFINITY;
    let mut initialized = false;
    // The issued anchor is normally one of the five, so it is picked up during the
    // sweep; the fallback below only runs if a client ever renders off-lattice.
    let mut issued_scores = None;
    for anchor in ANCHORS {
        let (fraction, med) = fraction_at(anchor);
        if anchor == issued {
            issued_scores = Some((fraction, med));
        }
        let better =
            !initialized || fraction > best_fraction || (fraction == best_fraction && med < best_median);
        if better {
            best_fraction = fraction;
            best_median = med;
            initialized = true;
        }
    }
    let (issued_fraction, issued_median) = issued_scores.unwrap_or_else(|| fraction_at(issued));
    RegionScores {
        best_fraction,
        best_median,
        issued_fraction,
        issued_median,
    }
}

/// Uniformly subsample a trace down to [`ALIGNMENT_MAX_POINTS`], preserving the
/// first and last points. Borrowed unchanged when already within budget, so the
/// real 64-point case allocates nothing.
fn subsample_for_alignment(trace: &[(f64, f64)]) -> std::borrow::Cow<'_, [(f64, f64)]> {
    if trace.len() <= ALIGNMENT_MAX_POINTS {
        return std::borrow::Cow::Borrowed(trace);
    }
    let last = trace.len() - 1;
    let picked = (0..ALIGNMENT_MAX_POINTS)
        .map(|i| trace[i * last / (ALIGNMENT_MAX_POINTS - 1)])
        .collect();
    std::borrow::Cow::Owned(picked)
}

/// Median residual of the trace against the curve under a *monotonic*
/// correspondence — the check for whether the user **followed** the path, as
/// opposed to merely hovering near it.
///
/// Proximity alone cannot answer that question: a Lissajous curve fills its own
/// box densely enough that any point inside the box sits within the proximity band
/// of some part of the curve, so a scribble reads as perfectly in-region. Picking
/// each point's nearest index independently does not fix it either — the curve
/// self-intersects, so ordinary positional noise snaps the nearest index onto a
/// neighbouring branch and a sloppy honest trace scores like a scribble.
///
/// So the correspondence is constrained instead: a cursor walks the curve in one
/// direction, advancing at most `window` indices per trace sample, and each trace
/// point is charged the distance to the best reference point within that reach.
/// Staying put is free, so pauses cost nothing and an incomplete trace is never
/// penalised for what it did not reach. Both directions and a sweep of start
/// indices are tried, so the trace may begin anywhere and run either way.
///
/// `reference` is the curve at the origin and `offset` is the issued anchor, so
/// the trace is shifted point-by-point instead of the curve being regenerated.
///
/// Bounded by construction: `trace` is pre-capped by [`subsample_for_alignment`]
/// and the reference is the curve's own point count, so the work is
/// `O(starts x points x window)` with every term fixed. Returns `f64::INFINITY`
/// for an empty trace or reference.
fn alignment_residual(
    trace: &[(f64, f64)],
    reference: &[(f64, f64)],
    offset: (f64, f64),
    window: usize,
) -> f64 {
    let n = reference.len();
    if n == 0 || trace.is_empty() {
        return f64::INFINITY;
    }
    let n_i = n as i64;
    let window = window as i64;
    // More than half the points already worse than the best median found so far
    // forces this candidate's median above it too, so the pass can be abandoned.
    // Exact for both parities, not a heuristic.
    let half = trace.len() / 2;
    let mut best = f64::INFINITY;
    let mut residuals: Vec<f64> = Vec::with_capacity(trace.len());
    for start in (0..n).step_by(ALIGNMENT_START_STRIDE) {
        'dir: for dir in [1_i64, -1] {
            let mut cursor = start as i64;
            let mut exceeding = 0usize;
            residuals.clear();
            for &(px, py) in trace {
                let (px, py) = (px - offset.0, py - offset.1);
                let mut best_distance = f64::INFINITY;
                let mut best_index = cursor;
                for step in 0..=window {
                    let j = (cursor + dir * step).rem_euclid(n_i);
                    let (rx, ry) = reference[j as usize];
                    let d = (px - rx) * (px - rx) + (py - ry) * (py - ry);
                    if d < best_distance {
                        best_distance = d;
                        best_index = j;
                    }
                }
                // The window search compares squared distances; rooting once per
                // trace point rather than per candidate keeps the median exact.
                let d = best_distance.sqrt();
                if d > best {
                    exceeding += 1;
                    if exceeding > half {
                        continue 'dir;
                    }
                }
                residuals.push(d);
                cursor = best_index;
            }
            let med = median(&mut residuals);
            if med < best {
                best = med;
            }
        }
    }
    best
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
/// `duration_ms` is the wall-clock span of the outline. The caller decides what
/// to do with the report.
pub fn score_curve_trace(
    trace: &[(f64, f64)],
    duration_ms: f64,
    params: &LissajousParams,
) -> CurveTraceReport {
    if trace.len() < 2 {
        return CurveTraceReport::empty(trace.len());
    }

    // Anchors only translate the shape, so the curve is generated once at the
    // origin and every measurement shifts the trace instead.
    debug_assert_eq!(
        usize::from(params.points),
        ISSUED_CURVE_POINTS,
        "the sweep's upper bound assumes the server's curve resolution"
    );
    let base = reference_points(params, (0.0, 0.0));
    let issued = (f64::from(params.anchor_x), f64::from(params.anchor_y));

    let region = score_region(trace, &base, issued);
    let (kinematic_score, path_length, max_segment, speed_cov) = score_kinematics(trace);

    // Alignment is measured at the issued anchor alone: the wallet-connected client
    // renders the server's anchor, and it is the only path that sends an outline
    // today, so there is nothing to search over here.
    let aligned = subsample_for_alignment(trace);
    let mut alignment_residuals = [f64::INFINITY; ALIGNMENT_WINDOW_SWEEP.len()];
    for (slot, &window) in alignment_residuals
        .iter_mut()
        .zip(ALIGNMENT_WINDOW_SWEEP.iter())
    {
        *slot = alignment_residual(&aligned, &base, issued, window);
    }

    let mean_speed = if duration_ms.is_finite() && duration_ms > 0.0 {
        path_length / (duration_ms / 1000.0)
    } else {
        0.0
    };

    CurveTraceReport {
        region_score: region.best_fraction,
        kinematic_score,
        median_deviation: region.best_median,
        region_score_issued_anchor: region.issued_fraction,
        median_deviation_issued_anchor: region.issued_median,
        alignment_residuals,
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

    /// Window the live 2026-07-26 calibration selected: the narrower ones inverted
    /// on real traces, and honest traces had converged to their proximity floor by
    /// this point. Assertions are written against it rather than a swept extreme.
    const TEST_WINDOW: usize = 40;

    /// Residual at [`TEST_WINDOW`], by position in the sweep.
    fn residual(report: &CurveTraceReport) -> f64 {
        let slot = ALIGNMENT_WINDOW_SWEEP
            .iter()
            .position(|&w| w == TEST_WINDOW)
            .expect("TEST_WINDOW must be present in ALIGNMENT_WINDOW_SWEEP");
        report.alignment_residuals[slot]
    }

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

    /// A *continuous* in-box scribble — the realistic negative, unlike the random
    /// cloud in `print_score_table` (which only fails because it teleports). A human
    /// scribbling produces a smooth, contiguous, speed-varying wander that stays in
    /// the curve's box. `cycles` sets how many loops the wander makes in the capture
    /// window, i.e. how fast the person scribbled.
    fn scribble_trace(anchor: (f64, f64), n: usize, cycles: f64) -> Vec<(f64, f64)> {
        let (cx, cy) = (anchor.0 + 50.0, anchor.1 + 50.0);
        (0..n)
            .map(|i| {
                let t = i as f64 / (n - 1) as f64;
                let u = t * cycles * std::f64::consts::TAU;
                let x = cx + 50.0 * (0.62 * (u + 0.7).sin() + 0.38 * (u * 1.7).sin());
                let y = cy + 50.0 * (0.62 * (u * 1.3).sin() + 0.38 * (u * 2.1 + 1.3).sin());
                (x, y)
            })
            .collect()
    }

    /// Manual calibration helper for Stage 1b. Answers the two questions any
    /// enforcement threshold depends on:
    ///   (1) does a *continuous* in-box scribble separate from an honest trace?
    ///   (2) does `region_score` bind to the *issued* curve, or merely to "in the box"?
    /// Run:
    ///   cargo test print_stage1b_calibration -- --ignored --nocapture
    #[test]
    #[ignore = "manual calibration helper; run with --ignored --nocapture"]
    fn print_stage1b_calibration() {
        const CAPTURE_MS: f64 = 12_000.0;
        let params = test_params((50, 50));
        let anchor = (50.0, 50.0);

        println!("\n=== (1) continuous in-box scribble vs honest trace (12s capture, 64 pts) ===");
        print!(
            "\n{:<30}{:>8}{:>10}{:>11}{:>9}{:>9}",
            "gesture", "region", "issuedAnc", "kinematic", "med.dev", "issMed"
        );
        for window in ALIGNMENT_WINDOW_SWEEP {
            print!("{:>8}", format!("W{window}"));
        }
        println!("{:>10}{:>9}{:>11}", "penalty", "maxseg", "speed u/s");
        println!("{}", "-".repeat(124));
        let honest = faithful_trace(&params, anchor, 64, 1.0);
        let honest_ref = honest.clone();
        let mut cases: Vec<(String, Vec<(f64, f64)>)> =
            vec![("honest full trace".to_string(), honest)];
        for cycles in [1.0_f64, 2.0, 3.0, 5.0, 8.0] {
            cases.push((
                format!("continuous scribble x{cycles:.0}"),
                scribble_trace(anchor, 64, cycles),
            ));
        }
        // What does best-of-5-anchor region actually still reject? The four corner
        // anchors tile the whole 200x200 frame, so a trace spread across the entire
        // frame is the honest worst case for the check's remaining power.
        let full_frame: Vec<(f64, f64)> = (0..64)
            .map(|i| {
                let a = ((i as f64) * 12.9898).sin() * 43758.5453;
                let b = ((i as f64) * 78.233).sin() * 43758.5453;
                ((a - a.floor()) * 200.0, (b - b.floor()) * 200.0)
            })
            .collect();
        cases.push(("scatter over whole frame".to_string(), full_frame));
        // Concentrated in a box, but the WRONG anchor from the one issued.
        cases.push((
            "scribble in a different box".to_string(),
            scribble_trace((100.0, 100.0), 64, 3.0),
        ));
        for (name, trace) in &cases {
            let r = score_curve_trace(trace, CAPTURE_MS, &params);
            print!(
                "{:<30}{:>8.2}{:>10.2}{:>11.2}{:>9.1}{:>9.1}",
                name,
                r.region_score,
                r.region_score_issued_anchor,
                r.kinematic_score,
                r.median_deviation,
                r.median_deviation_issued_anchor
            );
            for value in r.alignment_residuals {
                print!("{value:>8.1}");
            }
            let penalty = residual(&r) - r.median_deviation_issued_anchor;
            println!(
                "{penalty:>10.1}{:>9.1}{:>11.0}",
                r.max_segment, r.mean_speed
            );
        }

        println!("\n=== (2) cross-curve region confusion: trace curve A, score vs issued B ===");
        println!("    (same anchor, same delta — isolates ratio discrimination)");
        let ratios: [(u8, u8); 5] = [(1, 2), (2, 3), (3, 4), (3, 5), (4, 5)];
        let mk = |(a, b): (u8, u8), delta: f64| LissajousParams {
            a,
            b,
            delta,
            points: 200,
            anchor_x: 50,
            anchor_y: 50,
        };
        let d0 = std::f64::consts::PI * 0.5;
        print!("\n{:<14}", "traced \\ issued");
        for (a, b) in ratios {
            print!("{:>10}", format!("{a}:{b}"));
        }
        println!();
        println!("{}", "-".repeat(64));
        for traced in ratios {
            print!("{:<14}", format!("{}:{}", traced.0, traced.1));
            let trace = faithful_trace(&mk(traced, d0), anchor, 64, 1.0);
            for issued in ratios {
                let r = score_curve_trace(&trace, CAPTURE_MS, &mk(issued, d0));
                print!("{:>10.2}", r.region_score);
            }
            println!();
        }

        println!(
            "\n=== (3) delta sensitivity: same ratio, issued delta swept over [PI/4, 3PI/4] ==="
        );
        let traced_params = mk((3, 4), d0);
        let trace = faithful_trace(&traced_params, anchor, 64, 1.0);
        print!("\n{:<14}", "issued delta");
        for k in 0..5 {
            let f = 0.25 + 0.125 * k as f64;
            print!("{:>10}", format!("{f:.3}PI"));
        }
        println!();
        print!("{:<14}", "region");
        for k in 0..5 {
            let delta = std::f64::consts::PI * (0.25 + 0.125 * k as f64);
            let r = score_curve_trace(&trace, CAPTURE_MS, &mk((3, 4), delta));
            print!("{:>10.2}", r.region_score);
        }
        println!();

        println!(
            "\n=== (4) cost per verification (scoring runs detached, off the request path) ==="
        );
        let worst = scribble_trace(anchor, MAX_CURVE_TRACE_POINTS, 8.0);
        for (label, t) in [
            ("typical 64-point outline", &honest_ref),
            ("capped 2048-point payload", &worst),
        ] {
            let started = std::time::Instant::now();
            const REPS: u32 = 20;
            for _ in 0..REPS {
                std::hint::black_box(score_curve_trace(t, CAPTURE_MS, &params));
            }
            println!(
                "  {:<28} {:>8.2} ms/verification",
                label,
                started.elapsed().as_secs_f64() * 1000.0 / f64::from(REPS)
            );
        }
        println!();
    }

    // --- alignment residual (the "did you follow the path" check) ---

    #[test]
    fn faithful_trace_aligns_with_near_zero_residual() {
        let params = test_params((50, 50));
        let trace = faithful_trace(&params, (50.0, 50.0), 64, 1.0);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            residual(&report) < 1.0,
            "alignment_residual = {}",
            residual(&report)
        );
    }

    #[test]
    fn incomplete_trace_is_not_penalised_by_alignment() {
        // The design forbids requiring a complete trace: tracing 15% of the curve
        // must align as cheaply as tracing all of it.
        let params = test_params((0, 0));
        let trace = faithful_trace(&params, (0.0, 0.0), 64, 0.15);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            residual(&report) < 1.0,
            "alignment_residual = {}",
            residual(&report)
        );
    }

    #[test]
    fn pausing_mid_trace_is_free() {
        // Staying put costs nothing: a long pause must not raise the residual.
        // The user resumes from where they stopped, so the pause consumes samples
        // rather than skipping curve — the trace covers the same path in fewer
        // moving samples.
        let params = test_params((50, 50));
        let moving = faithful_trace(&params, (50.0, 50.0), 52, 1.0);
        let mut trace = Vec::with_capacity(64);
        trace.extend_from_slice(&moving[..20]);
        for _ in 0..12 {
            trace.push(moving[19]);
        }
        trace.extend_from_slice(&moving[20..]);
        assert_eq!(trace.len(), 64);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            residual(&report) < 1.0,
            "alignment_residual = {}",
            residual(&report)
        );
    }

    #[test]
    fn sloppy_trace_degrades_gracefully_not_catastrophically() {
        // A trace carrying more positional noise than any observed real one must
        // still align far below where a scribble lands. This is the case the naive
        // nearest-index formulation failed: noise snaps onto a neighbouring branch
        // of the self-intersecting curve.
        let params = test_params((50, 50));
        let reference = reference_points(&params, (50.0, 50.0));
        let trace: Vec<(f64, f64)> = (0..64)
            .map(|i| {
                let idx = (i * (reference.len() - 1)) / 63;
                let (x, y) = reference[idx];
                (
                    x + ((i as f64) * 0.7).sin() * 8.0,
                    y - ((i as f64) * 1.1).cos() * 8.0,
                )
            })
            .collect();
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            residual(&report) < 8.0,
            "sloppy honest trace should stay well aligned, got {}",
            residual(&report)
        );
    }

    #[test]
    fn continuous_in_region_scribble_fails_alignment_though_region_passes() {
        // The finding this metric exists for: a continuous scribble inside the
        // curve's box is perfectly "in region" and kinematically human, and only
        // the alignment residual separates it from an honest trace.
        let params = test_params((50, 50));
        let trace = scribble_trace((50.0, 50.0), 64, 3.0);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            report.region_score > 0.95,
            "region should pass a scribble, got {}",
            report.region_score
        );
        assert!(
            report.kinematic_score > 0.95,
            "kinematics should pass a scribble, got {}",
            report.kinematic_score
        );
        // Measured against an honest trace scored the same way rather than an
        // absolute number, so the margin survives a change of window.
        let honest = residual(&score_curve_trace(
            &faithful_trace(&params, (50.0, 50.0), 64, 1.0),
            12_000.0,
            &params,
        ));
        assert!(
            residual(&report) > honest + 8.0,
            "alignment must separate scribble {} from honest {honest}",
            residual(&report)
        );
    }

    #[test]
    fn tracing_a_different_curve_fails_alignment() {
        // A trace replayed from another session's curve sits in-region (the boxes
        // coincide) but cannot be explained as forward motion along this curve.
        let issued = test_params((50, 50));
        let other = LissajousParams {
            a: 1,
            b: 2,
            delta: std::f64::consts::PI * 0.3,
            points: 200,
            anchor_x: 50,
            anchor_y: 50,
        };
        let trace = faithful_trace(&other, (50.0, 50.0), 64, 1.0);
        let report = score_curve_trace(&trace, 12_000.0, &issued);
        assert!(
            residual(&report) > 8.0,
            "alignment_residual = {}",
            residual(&report)
        );
    }

    #[test]
    fn oversized_payload_is_subsampled_and_still_scores() {
        // A payload at the hard cap must stay bounded in cost without losing the
        // gesture: a dense faithful trace still aligns, a dense scribble still does
        // not. Guards the alignment budget against silently discarding the signal.
        let params = test_params((50, 50));
        let dense_faithful = faithful_trace(&params, (50.0, 50.0), MAX_CURVE_TRACE_POINTS, 1.0);
        let dense_scribble = scribble_trace((50.0, 50.0), MAX_CURVE_TRACE_POINTS, 3.0);
        assert_eq!(
            subsample_for_alignment(&dense_faithful).len(),
            ALIGNMENT_MAX_POINTS
        );
        let faithful = residual(&score_curve_trace(&dense_faithful, 12_000.0, &params));
        let scribble = residual(&score_curve_trace(&dense_scribble, 12_000.0, &params));
        assert!(faithful < 2.0, "dense faithful = {faithful}");
        assert!(
            scribble > faithful + 8.0,
            "separation lost after subsampling: faithful {faithful} vs scribble {scribble}"
        );
    }

    #[test]
    fn subsample_preserves_endpoints_and_is_borrowed_when_within_budget() {
        let small: Vec<(f64, f64)> = (0..64).map(|i| (i as f64, 0.0)).collect();
        assert!(matches!(
            subsample_for_alignment(&small),
            std::borrow::Cow::Borrowed(_)
        ));
        let big: Vec<(f64, f64)> = (0..2048).map(|i| (i as f64, 0.0)).collect();
        let out = subsample_for_alignment(&big);
        assert_eq!(out.len(), ALIGNMENT_MAX_POINTS);
        assert_eq!(out[0], big[0]);
        assert_eq!(out[out.len() - 1], big[big.len() - 1]);
    }

    #[test]
    fn alignment_residual_is_infinite_for_degenerate_trace() {
        let params = test_params((50, 50));
        let report = score_curve_trace(&[(10.0, 10.0)], 12_000.0, &params);
        assert!(
            report.alignment_residuals.iter().all(|r| r.is_infinite()),
            "every swept window must report infinity, got {:?}",
            report.alignment_residuals
        );
    }

    #[test]
    fn honest_trace_stays_aligned_at_every_swept_window() {
        // The safety property: an honest trace must not depend on which window is
        // chosen. Window 8 inverted on *live* traces (see ALIGNMENT_WINDOW_SWEEP),
        // so the sweep exists to pick the window from data — but no window may
        // false-reject a clean trace.
        //
        // Note the residual is deliberately NOT asserted to fall monotonically with
        // a wider window. The cursor is greedy and path-dependent, so a wider reach
        // can overshoot and strand itself: a scribble measured here scores
        // [29.7, 15.8, 12.0, 11.4, 13.3] — worse at 40 than at 32. Do not reintroduce
        // a monotonicity assumption.
        let params = test_params((50, 50));
        let report = score_curve_trace(
            &faithful_trace(&params, (50.0, 50.0), 64, 1.0),
            12_000.0,
            &params,
        );
        for (window, value) in ALIGNMENT_WINDOW_SWEEP
            .iter()
            .zip(&report.alignment_residuals)
        {
            assert!(
                *value < 2.0,
                "honest trace penalised at window {window}: {:?}",
                report.alignment_residuals
            );
        }
    }

    #[test]
    fn sweep_display_pairs_every_window_with_its_residual() {
        let params = test_params((50, 50));
        let trace = faithful_trace(&params, (50.0, 50.0), 64, 1.0);
        let rendered = score_curve_trace(&trace, 12_000.0, &params).alignment_sweep_display();
        let fields: Vec<&str> = rendered.split(' ').collect();
        assert_eq!(fields.len(), ALIGNMENT_WINDOW_SWEEP.len());
        for (field, window) in fields.iter().zip(ALIGNMENT_WINDOW_SWEEP.iter()) {
            let (label, value) = field
                .split_once(':')
                .expect("field must be window:residual");
            assert_eq!(label.parse::<usize>().ok(), Some(*window));
            assert!(value.parse::<f64>().is_ok(), "unparseable residual {value}");
        }
    }

    // --- issued-anchor region companion ---

    #[test]
    fn issued_anchor_region_rejects_the_wrong_box() {
        // Best-of-five anchoring accepts a gesture made in any box; scoring at the
        // issued anchor alone is what would restore positional binding. Both are
        // logged in Stage 1 so the choice can be made from real traffic.
        let params = test_params((50, 50));
        let trace = scribble_trace((100.0, 100.0), 64, 3.0);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            report.region_score > 0.95,
            "best-of-five accepts the wrong box, got {}",
            report.region_score
        );
        assert!(
            report.region_score_issued_anchor < report.region_score,
            "issued-anchor region should be stricter: issued {} vs best {}",
            report.region_score_issued_anchor,
            report.region_score
        );
    }

    #[test]
    fn issued_anchor_region_matches_best_when_the_anchor_is_honoured() {
        let params = test_params((50, 50));
        let trace = faithful_trace(&params, (50.0, 50.0), 64, 1.0);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert_eq!(report.region_score_issued_anchor, report.region_score);
        assert_eq!(
            report.median_deviation_issued_anchor,
            report.median_deviation
        );
    }

    #[test]
    fn ordering_penalty_separates_a_scribble_from_a_sloppy_honest_trace() {
        // The decision statistic: `residual - median_deviation_issued_anchor`, both
        // measured at the issued anchor. It asks only whether forcing the trace to be
        // ordered makes it worse, so imprecision divides out — which is the whole
        // point, since how accurately someone can trace depends on their device.
        let params = test_params((50, 50));
        let reference = reference_points(&params, (50.0, 50.0));
        // Honest but far sloppier than any observed real trace.
        let sloppy: Vec<(f64, f64)> = (0..64)
            .map(|i| {
                let idx = (i * (reference.len() - 1)) / 63;
                let (x, y) = reference[idx];
                (
                    x + ((i as f64) * 0.7).sin() * 10.0,
                    y - ((i as f64) * 1.1).cos() * 10.0,
                )
            })
            .collect();
        let scribble = scribble_trace((50.0, 50.0), 64, 3.0);

        let penalty = |trace: &[(f64, f64)]| {
            let r = score_curve_trace(trace, 12_000.0, &params);
            residual(&r) - r.median_deviation_issued_anchor
        };
        let honest_penalty = penalty(&sloppy);
        let scribble_penalty = penalty(&scribble);
        assert!(
            honest_penalty < 4.0,
            "sloppiness must not create an ordering penalty, got {honest_penalty}"
        );
        assert!(
            scribble_penalty > honest_penalty + 5.0,
            "penalty must separate: honest {honest_penalty} vs scribble {scribble_penalty}"
        );
    }

    #[test]
    fn off_lattice_issued_anchor_is_measured_not_silently_zero() {
        // The five-anchor sweep cannot supply the issued fraction when the issued
        // anchor is off the known lattice, so a fallback recomputes it. Covers that
        // branch: a faithful trace at an off-lattice anchor must report a real
        // in-band fraction rather than defaulting to zero.
        let params = LissajousParams {
            a: 3,
            b: 4,
            delta: std::f64::consts::PI * 0.5,
            points: 200,
            anchor_x: 30,
            anchor_y: 70,
        };
        assert!(
            !ANCHORS.contains(&(f64::from(params.anchor_x), f64::from(params.anchor_y))),
            "fixture must sit off the anchor lattice to exercise the fallback"
        );
        let trace = faithful_trace(&params, (30.0, 70.0), 64, 1.0);
        let report = score_curve_trace(&trace, 12_000.0, &params);
        assert!(
            report.region_score_issued_anchor > 0.95,
            "fallback should measure the issued anchor, got {}",
            report.region_score_issued_anchor
        );
    }
}
