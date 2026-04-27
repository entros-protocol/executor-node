//! Prometheus exposition endpoint for executor metrics (master-list / phases.md
//! "Monitoring + metrics (Prometheus)" item).
//!
//! Exposes existing `StatusMetrics` aggregate counters plus uptime in the
//! standard Prometheus text exposition format. No external crate dependency —
//! at this metric count (3 counters, 1 gauge) hand-rolling the exposition is
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
//! What IS exposed here: aggregate counters that are derivable from on-chain
//! state anyway (verifications, attestations, validations are all observable
//! via `getProgramAccounts` + Solana Explorer + the public `/stats` page),
//! and process uptime which carries no security sensitivity.
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
//! Added 2026-04-27 as MV implementation. Expand when scraping infrastructure
//! is in place and we have a specific metric to action on.

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
    (
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        body,
    )
}

/// Pure render function — separated from the handler so unit tests can
/// invoke it with a constructed `StatusMetrics` and verify the exact output
/// without standing up an axum router. Keeps the handler trivially thin.
fn render_metrics(metrics: &crate::status::status_metrics::StatusMetrics) -> String {
    let verifications = metrics.verifications_relayed();
    let attestations = metrics.attestations_issued();
    let validations = metrics.validations_performed();
    let start_time_secs = metrics.start_time();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(start_time_secs);
    let uptime_secs = now_secs.saturating_sub(start_time_secs);

    format!(
        concat!(
            "# HELP entros_verifications_relayed_total Cumulative count of verification transactions relayed to Solana.\n",
            "# TYPE entros_verifications_relayed_total counter\n",
            "entros_verifications_relayed_total {verifications}\n",
            "\n",
            "# HELP entros_attestations_issued_total Cumulative count of SAS attestations issued by the executor.\n",
            "# TYPE entros_attestations_issued_total counter\n",
            "entros_attestations_issued_total {attestations}\n",
            "\n",
            "# HELP entros_validations_performed_total Cumulative count of /validate-features calls forwarded to the validator.\n",
            "# TYPE entros_validations_performed_total counter\n",
            "entros_validations_performed_total {validations}\n",
            "\n",
            "# HELP entros_uptime_seconds Seconds since the executor process started.\n",
            "# TYPE entros_uptime_seconds gauge\n",
            "entros_uptime_seconds {uptime_secs}\n",
        ),
        verifications = verifications,
        attestations = attestations,
        validations = validations,
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
        assert!(body.contains("entros_verifications_relayed_total 0"));
        assert!(body.contains("entros_attestations_issued_total 0"));
        assert!(body.contains("entros_validations_performed_total 0"));
    }

    #[test]
    fn counter_increments_visible_in_output() {
        let metrics = StatusMetrics::new();
        metrics.increment_verifications();
        metrics.increment_verifications();
        metrics.increment_verifications();
        metrics.increment_attestations();
        metrics.increment_validations();
        metrics.increment_validations();

        let body = render_metrics(&metrics);
        assert!(
            body.contains("entros_verifications_relayed_total 3"),
            "expected 3 verifications, body: {body}"
        );
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
            "entros_verifications_relayed_total",
            "entros_attestations_issued_total",
            "entros_validations_performed_total",
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
        assert!(body.contains("entros_uptime_seconds 0") || body.contains("entros_uptime_seconds 1"));
    }

    #[test]
    fn content_type_is_prometheus_v004() {
        // Scrapers parse based on this header. Drift = scraper drops the body.
        assert_eq!(PROMETHEUS_CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8");
    }
}
