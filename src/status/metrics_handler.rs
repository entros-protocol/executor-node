//! Prometheus exposition endpoint for executor metrics.
//!
//! Exposes existing `StatusMetrics` aggregate counters plus uptime in the
//! standard Prometheus text exposition format. No external crate dependency —
//! at this metric count (5 counters, 1 gauge) hand-rolling the exposition is
//! simpler than wiring `prometheus` or `metrics-exporter-prometheus`.
//!
//! ## Why a separate handler from `/status`
//!
//! `/status` returns JSON for human consumption and the website's stats page,
//! AND it gates sensitive fields (relayer balance, internal counts) behind
//! API-key authentication. `/metrics` returns Prometheus exposition for
//! scrapers (Grafana, Datadog, Railway built-in metrics, etc.) and is
//! unauthenticated by deliberate choice — but exposes ONLY data that is safe
//! to publish without auth.
//!
//! ## Public-safe data only
//!
//! This endpoint deliberately omits the relayer SOL balance, even though
//! `StatusMetrics::cached_balance` makes it cheaply available. The balance is
//! treated as operational-sensitive (an attacker who knows the relayer's
//! balance can cost-model DoS attacks more precisely). It stays gated behind
//! `/status`'s API-key check.
//!
//! What IS exposed here: aggregate counters (attestations are observable on
//! chain, and validations, per-IP rejections, paired network mismatches and
//! challenge pointer fallbacks are counts with no wallet, key or address
//! attached), and process uptime which carries no security sensitivity.
//!
//! ## Naming convention
//!
//! All metrics prefixed `entros_` per Prometheus best-practice. Counter names
//! suffixed `_total` per Prometheus convention. Gauges have no suffix.
//!
//! ## What's NOT here yet
//!
//! - Per-reason validation rejection counts (would need to extend
//!   `WalletAttemptTracker` / `validation/handler.rs` to surface counters)
//! - Latency histograms (would benefit from a real histogram crate)
//! - Per-API-key quota usage (would expose customer-specific data)
//! - Wallet rate-limit hit count (similar — exposes per-wallet behavior)
//!
//! Add a metric here once there is a scraper for it and a specific action it
//! informs.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::server::AppState;

/// Prometheus content type per the v0.0.4 exposition format spec. Scrapers
/// (Prometheus, Grafana Agent, Vector, etc.) negotiate via this header to
/// know how to parse the body.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = render_metrics(&state.metrics);
    ([(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)], body)
}

/// Pure render function — separated from the handler so unit tests can
/// invoke it with a constructed `StatusMetrics` and verify the exact output
/// without standing up an axum router. Keeps the handler trivially thin.
fn render_metrics(metrics: &crate::status::status_metrics::StatusMetrics) -> String {
    let attestations = metrics.attestations_issued();
    let validations = metrics.validations_performed();
    let per_ip_rejected = metrics.per_ip_rate_limit_rejected();
    let network_mismatch = metrics.paired_authorization_network_mismatch();
    let pointer_fallback = metrics.challenge_pointer_fallback();
    let start_time_secs = metrics.start_time();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(start_time_secs);
    let uptime_secs = now_secs.saturating_sub(start_time_secs);

    format!(
        concat!(
            "# HELP entros_attestations_issued_total Cumulative count of SAS attestations issued by the executor.\n",
            "# TYPE entros_attestations_issued_total counter\n",
            "entros_attestations_issued_total {attestations}\n",
            "\n",
            "# HELP entros_validations_performed_total Cumulative count of /validate-features calls forwarded to the validator.\n",
            "# TYPE entros_validations_performed_total counter\n",
            "entros_validations_performed_total {validations}\n",
            "\n",
            "# HELP entros_per_ip_rate_limit_rejected_total Cumulative count of requests rejected by the per-IP rate limiter.\n",
            "# TYPE entros_per_ip_rate_limit_rejected_total counter\n",
            "entros_per_ip_rate_limit_rejected_total {per_ip_rejected}\n",
            "\n",
            "# HELP entros_paired_authorization_network_mismatch_total Cumulative count of paired opens with a valid authorization from another client network than the one that fetched it.\n",
            "# TYPE entros_paired_authorization_network_mismatch_total counter\n",
            "entros_paired_authorization_network_mismatch_total {network_mismatch}\n",
            "\n",
            "# HELP entros_challenge_pointer_fallback_total Cumulative count of unsigned single-capture requests answered with the wallet's latest challenge because their network had none.\n",
            "# TYPE entros_challenge_pointer_fallback_total counter\n",
            "entros_challenge_pointer_fallback_total {pointer_fallback}\n",
            "\n",
            "# HELP entros_uptime_seconds Seconds since the executor process started.\n",
            "# TYPE entros_uptime_seconds gauge\n",
            "entros_uptime_seconds {uptime_secs}\n",
        ),
        attestations = attestations,
        validations = validations,
        per_ip_rejected = per_ip_rejected,
        network_mismatch = network_mismatch,
        pointer_fallback = pointer_fallback,
        uptime_secs = uptime_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::status_metrics::StatusMetrics;

    #[test]
    fn renders_zero_state_correctly() {
        let metrics = StatusMetrics::new();
        let body = render_metrics(&metrics);
        assert!(body.contains("entros_attestations_issued_total 0"));
        assert!(body.contains("entros_validations_performed_total 0"));
        assert!(body.contains("entros_per_ip_rate_limit_rejected_total 0"));
    }

    #[test]
    fn counter_increments_visible_in_output() {
        let metrics = StatusMetrics::new();
        metrics.increment_attestations();
        metrics.increment_validations();
        metrics.increment_validations();

        let body = render_metrics(&metrics);
        assert!(
            body.contains("entros_attestations_issued_total 1"),
            "expected 1 attestation, body: {body}"
        );
        assert!(
            body.contains("entros_validations_performed_total 2"),
            "expected 2 validations, body: {body}"
        );
    }

    #[test]
    fn every_metric_has_help_and_type_lines() {
        // Per the Prometheus exposition spec, every metric MUST have one
        // `# HELP` and one `# TYPE` line preceding the sample. Drift here
        // breaks parsers silently — they'd ignore the metric.
        let metrics = StatusMetrics::new();
        let body = render_metrics(&metrics);
        let metric_names = [
            "entros_attestations_issued_total",
            "entros_validations_performed_total",
            "entros_per_ip_rate_limit_rejected_total",
            "entros_paired_authorization_network_mismatch_total",
            "entros_challenge_pointer_fallback_total",
            "entros_uptime_seconds",
        ];
        for name in metric_names {
            assert!(
                body.contains(&format!("# HELP {name} ")),
                "missing HELP line for {name}"
            );
            assert!(
                body.contains(&format!("# TYPE {name} ")),
                "missing TYPE line for {name}"
            );
        }
    }

    #[test]
    fn the_rollout_counters_are_rendered() {
        let metrics = StatusMetrics::new();
        metrics.increment_paired_authorization_network_mismatch();
        metrics.increment_challenge_pointer_fallback();
        metrics.increment_challenge_pointer_fallback();
        let body = render_metrics(&metrics);
        assert!(body.contains("entros_paired_authorization_network_mismatch_total 1\n"));
        assert!(body.contains("entros_challenge_pointer_fallback_total 2\n"));
    }

    #[test]
    fn does_not_expose_relayer_balance() {
        // Security regression guard: the relayer balance is gated behind
        // `/status`'s API-key check (`status::handler::status_handler`
        // returns balance only when authenticated). The /metrics endpoint
        // is unauthenticated and MUST NOT leak it.
        let metrics = StatusMetrics::new();
        metrics.update_cached_balance(123_456_789, 1_000_000);
        let body = render_metrics(&metrics);
        assert!(
            !body.contains("123456789"),
            "balance value leaked into /metrics output: {body}"
        );
        assert!(
            !body.contains("relayer_balance"),
            "relayer_balance metric name leaked into /metrics output: {body}"
        );
    }

    #[test]
    fn uptime_is_present_and_non_negative() {
        let metrics = StatusMetrics::new();
        let body = render_metrics(&metrics);
        // Uptime starts at 0 (start_time captured "now" in StatusMetrics::new).
        // It MUST NOT be negative — saturating_sub guards against clock skew.
        // A naive subtraction would underflow if SystemTime drifts backwards.
        assert!(
            body.contains("entros_uptime_seconds 0") || body.contains("entros_uptime_seconds 1")
        );
    }

    #[test]
    fn content_type_is_prometheus_v004() {
        // Scrapers parse based on this header. Drift = scraper drops the body.
        assert_eq!(
            PROMETHEUS_CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }
}
