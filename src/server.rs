use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::attestation::handler::attest_handler;
use crate::attestation::sas::SasAttestor;
use crate::auth::api_key::api_key_auth;
use crate::auth::client_ip::extract_client_ip;
use crate::auth::cross_wallet_cooldown::CrossWalletCooldownTracker;
use crate::auth::rate_limit::{PerIpRateLimiter, RateLimiter};
use crate::challenge::handler::challenge_handler;
use crate::challenge::registry::ChallengeNonceRegistry;
use crate::error::AppError;
use crate::integrator::tracker::IntegratorTracker;
use crate::integrator::wallet_attempts::WalletAttemptTracker;
use crate::relayer::commitment_registry::CommitmentRegistry;
use crate::relayer::handler::{health_handler, verify_handler};
use crate::relayer::transaction::RelayerTransaction;
use crate::status::handler::status_handler;
use crate::status::metrics_handler::metrics_handler;
use crate::status::status_metrics::StatusMetrics;
use crate::validation::handler::validate_features_handler;

#[derive(Clone)]
pub struct AppState {
    pub relayer_tx: Arc<RelayerTransaction>,
    pub api_keys: Arc<Vec<String>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub attest_rate_limiter: Arc<RateLimiter>,
    pub per_ip_rate_limiter: Arc<PerIpRateLimiter>,
    pub tracker: Arc<IntegratorTracker>,
    pub wallet_attempts: Arc<WalletAttemptTracker>,
    pub commitment_registry: Arc<CommitmentRegistry>,
    pub sas_attestor: Option<Arc<SasAttestor>>,
    pub metrics: Arc<StatusMetrics>,
    pub http_client: Arc<reqwest::Client>,
    pub validation_url: Option<String>,
    pub validation_api_key: Option<String>,
    pub challenge_registry: Arc<ChallengeNonceRegistry>,
    pub challenge_ttl_secs: u64,
    /// Observe-only automation-detection logging (master-list #196, Layer A1).
    /// Gates the calibration log in `validate_features_handler`; never affects
    /// the verification decision.
    pub automation_observe: bool,
    /// Observe-only wallet-reputation logging (master-list #196, Layer D1).
    /// Gates the detached on-chain reputation read in `validate_features_handler`;
    /// never affects the verification decision, quota, or latency.
    pub wallet_reputation_observe: bool,
    /// Cross-wallet verification cooldown tracker (master-list #142).
    pub cross_wallet_cooldown: Arc<CrossWalletCooldownTracker>,
    /// Enforces cross-wallet cooldown blocks when true.
    pub cross_wallet_cooldown_enforce: bool,
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    api_key_auth(request, next, &state.api_keys).await
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("authenticated");

    if state.rate_limiter.check(key).is_err() {
        tracing::warn!(api_key = %crate::auth::redact::redact_api_key(key), "Rate limit exceeded");
        return Err(AppError::RateLimited);
    }

    Ok(next.run(request).await)
}

/// Per-IP rate-limit gate (master-list #155). Sits OUTSIDE the
/// min-duration timing equalizer so over-cap IPs fail fast — there's no
/// privacy benefit to padding here (the same IP already knows from its
/// own request count whether it's rate-limited), and short-circuiting
/// frees server resources for legitimate traffic.
///
/// Runs before auth and quota deduction, so a hostile IP cannot burn
/// integrator quota or trigger Whisper inference by rotating wallets
/// behind a single IP.
async fn per_ip_rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // ConnectInfo is populated by `into_make_service_with_connect_info`
    // in main.rs. Tests that exercise the middleware directly (without
    // the full server stack) are expected to either set this extension
    // or rely on the X-Forwarded-For path.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = extract_client_ip(request.headers(), peer);

    if let Some(addr) = ip {
        if let Err(retry_after_secs) = state.per_ip_rate_limiter.check(addr) {
            state.metrics.increment_per_ip_rate_limit_rejected();
            tracing::warn!(
                ip = %crate::auth::redact::redact_ip(addr),
                retry_after_secs,
                "per-IP rate limit exceeded"
            );
            return Err(AppError::IpRateLimited { retry_after_secs });
        }
    } else {
        // No IP source available — log and allow. Reaching this branch
        // in production would mean axum lost the peer address AND the
        // request had no X-Forwarded-For, which is unreachable on
        // Railway. In dev (e.g. unit tests bypassing the server), allow
        // the request to flow through rather than failing closed —
        // failing closed would break tests that don't care about IP
        // gating.
        tracing::debug!("per-IP rate limit middleware: no IP source available, allowing");
    }

    Ok(next.run(request).await)
}

async fn attest_rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("authenticated");

    if state.attest_rate_limiter.check(key).is_err() {
        tracing::warn!(
            api_key = %crate::auth::redact::redact_api_key(key),
            "Attestation rate limit exceeded"
        );
        return Err(AppError::RateLimited);
    }

    Ok(next.run(request).await)
}

pub fn create_router(state: AppState, cors_origins: &[String]) -> Router {
    // Attest route with its own tighter rate limit (10/min)
    let attest_route = Router::new()
        .route("/attest", post(attest_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            attest_rate_limit_middleware,
        ));

    // Endpoints whose timing distinguishes outcome classes go through a
    // min-duration clamp so rate-limit and quota rejections take the same
    // wall-time as a successful validator round-trip. /challenge and /attest
    // stay off this path: their UX hits the user-perceptible latency budget
    // and their outcomes are already wallet-attributable.
    let timed_routes = Router::new()
        .route("/verify", post(verify_handler))
        .route("/validate-features", post(validate_features_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(middleware::from_fn(crate::timing::min_duration_middleware));

    // Untimed authenticated routes: /challenge issues nonces (fast by design,
    // user-blocking before the verify call) and /attest already exposes its
    // outcome shape via a wallet-attributable error.
    //
    // The duplicated rate_limit + auth route_layer applications below are
    // intentional: timed_routes need min_duration to wrap auth+rate_limit so
    // pre-handler short-circuits also clamp to the timing budget. Each
    // Router carries its own layer stack but the same `state.rate_limiter`
    // (Arc) backs both, so counters merge across the route groups.
    let untimed_routes = Router::new()
        .route("/challenge", get(challenge_handler))
        .merge(attest_route)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Apply per-IP rate limiting to ALL verify routes (timed + untimed).
    // Sits OUTSIDE both min-duration and per-API-key/per-wallet limiters
    // so hostile traffic is rejected before consuming server resources.
    // Excluded: /health, /status, /metrics — Railway healthchecks and
    // Prometheus scrapers are expected to hit at high cadence.
    let verify_routes =
        timed_routes
            .merge(untimed_routes)
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                per_ip_rate_limit_middleware,
            ));

    let cors = if cors_origins.is_empty() {
        // No origins configured — permissive for development
        CorsLayer::permissive()
    } else {
        let parsed: Vec<axum::http::HeaderValue> = cors_origins
            .iter()
            .filter_map(|o| match o.parse() {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(origin = %o, "Ignoring unparseable CORS origin");
                    None
                }
            })
            .collect();
        tracing::info!(
            count = parsed.len(),
            "CORS restricted to configured origins"
        );
        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::HeaderName::from_static("x-api-key"),
            ])
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        // Prometheus exposition for scrapers (Grafana / Datadog / Railway built-in
        // metrics). Public, unauthenticated — exposes aggregate counters only,
        // no per-wallet or per-API-key data. See `status/metrics_handler.rs`.
        .route("/metrics", get(metrics_handler))
        .merge(verify_routes)
        // 1MB covers the MAX_CAPTURE_MS=60s path from the SDK plus the
        // base64-encoded audio payload for phrase content binding (#89):
        // 12s @ 16kHz × 2 bytes × 4/3 base64 overhead ≈ 512KB. The 134-
        // element feature vector + F0/accel time-series still fit under the
        // previous 256KB; audio is the only reason to grow the limit.
        // Rate-limiting (60/min/key) bounds DoS exposure regardless.
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Build an `AppState` for handler-level tests. Tests call handlers
/// directly (bypassing the auth/rate-limit middleware stack), so
/// `api_keys` is intentionally empty — modeling middleware behavior is
/// not the responsibility of these scaffolds.
#[cfg(test)]
pub fn build_test_state(
    tracker: Arc<IntegratorTracker>,
    validation_url: Option<String>,
) -> AppState {
    use solana_sdk::signature::Keypair;
    use std::time::Duration;

    let solana_client = Arc::new(crate::solana::client::SolanaClient::new(
        "http://127.0.0.1:8899",
        Keypair::new(),
    ));
    AppState {
        relayer_tx: Arc::new(RelayerTransaction::new(solana_client)),
        api_keys: Arc::new(vec![]),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        attest_rate_limiter: Arc::new(RateLimiter::new(10)),
        per_ip_rate_limiter: Arc::new(PerIpRateLimiter::new(30)),
        tracker,
        wallet_attempts: Arc::new(WalletAttemptTracker::new(5, Duration::from_secs(3600))),
        commitment_registry: Arc::new(CommitmentRegistry::new()),
        sas_attestor: None,
        metrics: Arc::new(StatusMetrics::new()),
        http_client: Arc::new(reqwest::Client::new()),
        validation_url,
        validation_api_key: None,
        challenge_registry: Arc::new(ChallengeNonceRegistry::new()),
        challenge_ttl_secs: 300,
        automation_observe: true,
        wallet_reputation_observe: true,
        cross_wallet_cooldown: Arc::new(CrossWalletCooldownTracker::new(86400)),
        cross_wallet_cooldown_enforce: false,
    }
}

/// Build an `IntegratorTracker` pre-loaded with a single key + quota.
#[cfg(test)]
pub fn tracker_with_quota(api_key: &str, quota: u64) -> Arc<IntegratorTracker> {
    use crate::config::IntegratorConfig;
    Arc::new(IntegratorTracker::new(vec![IntegratorConfig {
        api_key: api_key.into(),
        name: "TestApp".into(),
        quota,
    }]))
}

/// Build an `axum::http::HeaderMap` carrying just `X-API-Key`. Other
/// headers are not material to the structural-failure invariants these
/// tests cover.
#[cfg(test)]
pub fn headers_with_key(api_key: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-api-key", api_key.parse().unwrap());
    headers
}

/// Generate a fresh, valid Solana wallet id (base58 pubkey) for tests
/// that need a parseable wallet but don't care about its identity.
#[cfg(test)]
pub fn random_wallet_id() -> String {
    use solana_sdk::signature::{Keypair, Signer};
    Keypair::new().pubkey().to_string()
}

#[cfg(test)]
mod per_ip_middleware_tests {
    //! Per-IP rate-limit middleware tests (master-list #155). Exercise
    //! the middleware via `tower::ServiceExt::oneshot` against a minimal
    //! Router so we get true middleware semantics (extension extraction,
    //! header pass-through, AppError::IntoResponse) instead of mocking
    //! the pieces.
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use std::net::SocketAddr;
    use tower::util::ServiceExt;

    /// Tiny router that pipes every request through the per-IP rate
    /// limiter and short-circuits to a 200 if the middleware allows.
    /// The real router under test would have many handlers; we use one
    /// trivial handler so failures come from the middleware, not the
    /// handler.
    fn app(per_ip_rate_limiter: Arc<PerIpRateLimiter>) -> Router {
        let tracker = tracker_with_quota("dummy", 100);
        let mut state = build_test_state(tracker, None);
        state.per_ip_rate_limiter = per_ip_rate_limiter;
        Router::new()
            .route("/probe", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                per_ip_rate_limit_middleware,
            ))
            .with_state(state)
    }

    fn req_with_xff(xff: &str) -> Request<Body> {
        Request::builder()
            .uri("/probe")
            .header("x-forwarded-for", xff)
            .body(Body::empty())
            .unwrap()
    }

    fn req_with_peer(peer: SocketAddr) -> Request<Body> {
        let mut req = Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req
    }

    #[tokio::test]
    async fn allows_first_request_under_limit() {
        let limiter = Arc::new(PerIpRateLimiter::new(30));
        let app = app(limiter);
        let resp = app.oneshot(req_with_xff("203.0.113.1")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_with_429_and_retry_after_when_over_limit() {
        let limiter = Arc::new(PerIpRateLimiter::new(2));
        let app = app(limiter);
        // Burn the budget.
        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(req_with_xff("203.0.113.5"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = app.oneshot(req_with_xff("203.0.113.5")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("Retry-After header must be present on per-IP 429")
            .to_str()
            .unwrap();
        let secs: u64 = retry_after
            .parse()
            .expect("Retry-After must be integer seconds");
        assert!(secs >= 1, "Retry-After must be at least 1s, got {secs}");
    }

    #[tokio::test]
    async fn separate_ips_have_independent_budgets() {
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let app = app(limiter);
        // IP A: burn the budget, then verify it's rejected.
        let r1 = app
            .clone()
            .oneshot(req_with_xff("203.0.113.10"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app
            .clone()
            .oneshot(req_with_xff("203.0.113.10"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
        // IP B: should still pass first request.
        let r3 = app.oneshot(req_with_xff("203.0.113.11")).await.unwrap();
        assert_eq!(
            r3.status(),
            StatusCode::OK,
            "different IP must have its own budget"
        );
    }

    #[tokio::test]
    async fn forwarded_for_takes_precedence_over_peer() {
        // Limiter caps the X-Forwarded-For IP after one request. If the
        // middleware were keying on peer instead, the second request would
        // pass — proving precedence is the easiest way to verify which
        // source the middleware actually uses.
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let app = app(limiter);
        let peer: SocketAddr = "10.0.0.99:5000".parse().unwrap();

        let mut req1 = req_with_xff("203.0.113.42");
        req1.extensions_mut().insert(ConnectInfo(peer));
        let r1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let mut req2 = req_with_xff("203.0.113.42");
        req2.extensions_mut().insert(ConnectInfo(peer));
        let r2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "limiter must key on X-Forwarded-For, not peer"
        );
    }

    #[tokio::test]
    async fn falls_back_to_peer_address_when_no_forwarded_for() {
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let app = app(limiter);
        let peer: SocketAddr = "192.0.2.50:8080".parse().unwrap();
        let r1 = app.clone().oneshot(req_with_peer(peer)).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app.oneshot(req_with_peer(peer)).await.unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "peer-only requests must still hit the per-IP cap"
        );
    }

    #[tokio::test]
    async fn missing_ip_source_allows_request() {
        // Production-impossible (Railway always provides the peer
        // address), but keep the fail-open behavior so unit tests that
        // don't care about IP wiring continue to work.
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let app = app(limiter);
        let req = Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ip_rejection_does_not_deduct_integrator_quota() {
        // The middleware rejects BEFORE auth + quota deduction. A
        // rejected IP must not touch the IntegratorTracker — a hostile
        // IP holding a leaked API key shouldn't burn that key's quota
        // by hammering past its IP cap.
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let tracker = tracker_with_quota("test-key", 100);
        let mut state = build_test_state(tracker.clone(), None);
        state.per_ip_rate_limiter = limiter;
        let app = Router::new()
            .route("/probe", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                per_ip_rate_limit_middleware,
            ))
            .with_state(state);

        // 1 r/m budget — first request OK, second rejected.
        let r1 = app
            .clone()
            .oneshot(req_with_xff("203.0.113.99"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app.oneshot(req_with_xff("203.0.113.99")).await.unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);

        // Quota should be untouched — the middleware short-circuits
        // before any handler that would call check_and_deduct.
        assert_eq!(
            tracker.get_remaining("test-key"),
            100,
            "per-IP rejection must not deduct integrator quota"
        );
    }

    #[tokio::test]
    async fn ip_rejection_increments_prometheus_counter() {
        // Per-IP rejections must surface as
        // `entros_per_ip_rate_limit_rejected_total` so ops can monitor
        // sustained-attack signals via the unauthenticated /metrics
        // scrape, not via log scraping.
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let tracker = tracker_with_quota("dummy", 100);
        let mut state = build_test_state(tracker, None);
        state.per_ip_rate_limiter = limiter;
        let metrics = Arc::clone(&state.metrics);
        let app = Router::new()
            .route("/probe", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                per_ip_rate_limit_middleware,
            ))
            .with_state(state);

        // First request: under cap → no counter increment.
        let r1 = app
            .clone()
            .oneshot(req_with_xff("203.0.113.123"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        assert_eq!(metrics.per_ip_rate_limit_rejected(), 0);

        // Two more requests: both over cap → two increments.
        for _ in 0..2 {
            let r = app
                .clone()
                .oneshot(req_with_xff("203.0.113.123"))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        assert_eq!(metrics.per_ip_rate_limit_rejected(), 2);
    }
}
