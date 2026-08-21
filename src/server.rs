use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::RequestBodyTimeoutLayer;
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
use crate::study::{study_definition_handler, study_enrol_handler};
use crate::validation::composite::ScoringConfig;
use crate::validation::handler::validate_features_handler;

#[derive(Clone)]
pub struct AppState {
    pub relayer_tx: Arc<RelayerTransaction>,
    pub api_keys: Arc<Vec<String>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub attest_rate_limiter: Arc<RateLimiter>,
    pub study_service_rate_limiter: Arc<RateLimiter>,
    pub study_concurrency: Arc<tokio::sync::Semaphore>,
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
    pub challenge_required: bool,
    pub scoring_config: Arc<ScoringConfig>,
    /// Observe-only automation-detection logging.
    /// Gates the calibration log in `validate_features_handler`; never affects
    /// the verification decision.
    pub automation_observe: bool,
    /// Reject requests that report navigator.webdriver === true in production.
    /// Disable this check for end-to-end tests with
    /// `EXECUTOR_AUTOMATION_WEBDRIVER_REJECT`.
    pub automation_webdriver_reject: bool,
    /// Observe-only wallet-reputation logging.
    /// Gates the detached on-chain reputation read in `validate_features_handler`;
    /// never affects the verification decision, quota, or latency.
    pub wallet_reputation_observe: bool,
    /// Observe-only curve-trace region/kinematics logging (touch-curve Stage 1).
    /// Gates the curve-trace scoring log in `validate_features_handler`; never
    /// affects the verification decision.
    pub curve_trace_observe: bool,
    /// Cross-wallet verification cooldown tracker.
    pub cross_wallet_cooldown: Arc<CrossWalletCooldownTracker>,
    /// Enforces cross-wallet cooldown blocks when true.
    pub cross_wallet_cooldown_enforce: bool,
    /// IP blocklist for probing attacks. Maps IP address to block expiration time.
    pub probing_blocklist: Arc<dashmap::DashMap<std::net::IpAddr, std::time::Instant>>,
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

/// Per-IP rate-limit gate. Sits outside the
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
    // ConnectInfo identifies the immediate peer. The client-IP extractor
    // trusts proxy headers only when this peer is private.
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
        // Axum supplies a peer in production. Direct handler tests do not.
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

const STUDY_REQUEST_BODY_BYTES: usize = 4 * 1024;

/// Largest request body the executor accepts, in bytes.
///
/// The `/validate-features` body is the only one that approaches it. At the
/// SDK's canonical 16 kHz and its 20 s transmitted-capture cap
/// (`pulse-sdk` `MAX_TRANSMITTED_CAPTURE_MS`), the base64 audio is at most
/// 640,000 raw bytes expanded 4/3, which leaves room for the 308-element
/// feature vector, the two contours and the curve-trace outline.
///
/// Enforced three ways, all reading this one constant: `RequestBodyLimitLayer`
/// rejects on `Content-Length` before a byte is read, the same layer caps the
/// stream when that header is absent, and `DefaultBodyLimit` bounds what an
/// extractor will buffer.
pub const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;

/// How long a request body may go without delivering a frame before the
/// connection is reclaimed.
///
/// This is an inactivity timeout, not a total-duration budget:
/// `RequestBodyTimeoutLayer` resets it every time a frame arrives. A slow
/// uplink that is still making progress is never killed, which is the whole
/// point. The mobile failure this replaces was a healthy 9.4 s upload
/// aborted by a fixed deadline. A genuinely stalled upload no longer holds a
/// task and its partial buffer indefinitely.
pub const REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn make_http_request_span<B>(request: &axum::http::Request<B>) -> tracing::Span {
    tracing::debug_span!(
        target: "tower_http::trace",
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        version = ?request.version()
    )
}

pub fn create_router(state: AppState, cors_origins: &[axum::http::HeaderValue]) -> Router {
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
    //
    // Layer order here is a security control, not a style choice.
    // `route_layer` applies outermost-last, so this reads inside-out and the
    // effective order is auth → min_duration → rate_limit → handler.
    //
    //   min_duration stays OUTSIDE rate_limit, because clamping the
    //   sub-10ms rate-limit and quota rejections up to the validator's
    //   5-8s is the entire reason the clamp exists. Moving it inside
    //   reopens the oracle.
    //
    //   min_duration sits INSIDE auth, because it drains the request body
    //   before starting its clock (see `timing::min_duration_middleware`).
    //   Outside auth it would buffer bodies for callers holding no valid
    //   key, which is the resource-exhaustion path this stack is meant to
    //   close. Auth failures are already distinguishable by their 401, so
    //   leaving them unclamped reveals nothing new.
    let timed_routes = Router::new()
        .route("/verify", post(verify_handler))
        .route("/validate-features", post(validate_features_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .route_layer(middleware::from_fn(crate::timing::min_duration_middleware))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Untimed authenticated routes: /challenge issues nonces (fast by design,
    // user-blocking before the verify call) and /attest already exposes its
    // outcome shape via a wallet-attributable error.
    //
    // The duplicated rate_limit + auth route_layer applications below are
    // intentional: timed_routes need min_duration to wrap auth+rate_limit so
    // pre-handler short-circuits also clamp to the timing budget. Each
    // Router carries its own layer stack but the same `state.rate_limiter`
    // (Arc) backs both, so counters merge across the route groups.
    let study_routes = Router::new()
        .route("/study/definition", post(study_definition_handler))
        .route("/study/enrol", post(study_enrol_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(RequestBodyLimitLayer::new(STUDY_REQUEST_BODY_BYTES));

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
    let verify_routes = timed_routes
        .merge(untimed_routes)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            per_ip_rate_limit_middleware,
        ))
        .merge(study_routes);

    let cors = if cors_origins.is_empty() {
        // No origins configured — permissive for development
        CorsLayer::permissive()
    } else {
        let parsed = cors_origins.to_vec();
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
        // Extractor-level backstop. `DefaultBodyLimit` is a request
        // extension that `Json`/`Bytes` consult while buffering, NOT a
        // Service. Axum's own docs say so and recommend `tower_http::limit`
        // for untrusted remotes. On its own it bounds nothing before an
        // extractor runs, which is why the real limit is the layer below.
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        // Reclaim a stalled upload. Applied inside the size limit so only
        // bodies that passed the cheap `Content-Length` check get wrapped.
        .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_READ_TIMEOUT))
        // The actual size limit. Rejects with 413 straight from the
        // `Content-Length` header before reading any of the body, and caps
        // the stream when the header is absent. Outermost of the three so
        // an oversized upload never reaches auth, the rate limiters, or the
        // body-buffering inside `min_duration_middleware`.
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(cors)
        .layer(TraceLayer::new_for_http().make_span_with(make_http_request_span))
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
        study_service_rate_limiter: Arc::new(RateLimiter::new(600)),
        study_concurrency: Arc::new(tokio::sync::Semaphore::new(32)),
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
        challenge_required: false,
        scoring_config: Arc::new(ScoringConfig::synthetic_test_policy()),
        automation_observe: true,
        automation_webdriver_reject: false,
        wallet_reputation_observe: true,
        curve_trace_observe: true,
        cross_wallet_cooldown: Arc::new(CrossWalletCooldownTracker::new(86400)),
        cross_wallet_cooldown_enforce: false,
        probing_blocklist: Arc::new(dashmap::DashMap::new()),
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

#[cfg(test)]
mod request_trace_tests {
    use super::*;
    use axum::http::Request;
    use std::io::{self, Write};
    use std::sync::Mutex;
    use tracing_subscriber::fmt::format::FmtSpan;

    struct LogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn request_trace_excludes_query_values() {
        const SECRET_QUERY_VALUE: &str = "wallet-query-must-not-appear";

        let logs = Arc::new(Mutex::new(Vec::new()));
        let writer_logs = Arc::clone(&logs);
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "executor_node=info,tower_http=debug",
            ))
            .with_span_events(FmtSpan::NEW)
            .with_writer(move || LogWriter(Arc::clone(&writer_logs)))
            .finish();
        let request = Request::builder()
            .uri(format!("/health?wallet={SECRET_QUERY_VALUE}"))
            .body(())
            .expect("request");
        tracing::subscriber::with_default(subscriber, || {
            let span = make_http_request_span(&request);
            span.in_scope(|| tracing::debug!("request accepted"));
        });

        let bytes = logs.lock().expect("log buffer lock").clone();
        let output = String::from_utf8(bytes).expect("trace output must be UTF-8");
        assert!(output.contains("/health"), "trace output: {output}");
        assert!(
            !output.contains(SECRET_QUERY_VALUE),
            "trace output exposed a query value: {output}"
        );
    }
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
    //! Per-IP rate-limit middleware tests. Exercise
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

    async fn study_definition_upstream() -> impl axum::response::IntoResponse {
        axum::Json(serde_json::json!({
            "study_id": "population-v1",
            "consent_version": "2026-08-10",
            "consent_hash_hex": "a".repeat(64),
            "retention_days": 14,
            "trial_limit": 5,
            "visit_gap_secs": 14_400,
            "feature_schema_version": 4,
            "projection_version": 1
        }))
    }

    async fn mock_study_service() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/study/definition",
            axum::routing::post(study_definition_upstream),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind study mock");
        let address = listener.local_addr().expect("study mock address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve study mock");
        });
        (format!("http://{address}"), task)
    }

    fn study_definition_request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/study/definition")
            .header("content-type", "application/json")
            .header("x-api-key", "study-key")
            .header("x-real-ip", "203.0.113.44")
            .body(Body::from("{}"))
            .expect("study request")
    }

    #[tokio::test]
    async fn study_participants_do_not_share_proxy_rate_buckets() {
        let (validation_url, server) = mock_study_service().await;
        let tracker = tracker_with_quota("study-key", 100);
        let mut state = build_test_state(tracker, Some(validation_url));
        state.api_keys = Arc::new(vec!["study-key".into()]);
        state.rate_limiter = Arc::new(RateLimiter::new(1));
        state.per_ip_rate_limiter = Arc::new(PerIpRateLimiter::new(1));
        let app = create_router(state, &[]);

        let first = app
            .clone()
            .oneshot(study_definition_request())
            .await
            .expect("first study response");
        let second = app
            .oneshot(study_definition_request())
            .await
            .expect("second study response");
        server.abort();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
    }

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

    #[tokio::test]
    async fn study_routes_reject_oversized_bodies_before_proxying() {
        let tracker = tracker_with_quota("study-key", 100);
        let mut state = build_test_state(tracker, Some("http://127.0.0.1:9".into()));
        state.api_keys = Arc::new(vec!["study-key".into()]);
        let app = create_router(state, &[]);
        let body =
            serde_json::json!({ "padding": "A".repeat(STUDY_REQUEST_BODY_BYTES) }).to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/study/definition")
                    .header("content-type", "application/json")
                    .header("content-length", body.len().to_string())
                    .header("x-api-key", "study-key")
                    .body(Body::from(body))
                    .expect("study request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    fn req_with_proxy_ip(real_ip: &str) -> Request<Body> {
        let mut request = Request::builder()
            .uri("/probe")
            .header("x-real-ip", real_ip)
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo("10.0.0.8:8080".parse::<SocketAddr>().unwrap()));
        request
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
        let resp = app.oneshot(req_with_proxy_ip("203.0.113.1")).await.unwrap();
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
                .oneshot(req_with_proxy_ip("203.0.113.5"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = app.oneshot(req_with_proxy_ip("203.0.113.5")).await.unwrap();
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
            .oneshot(req_with_proxy_ip("203.0.113.10"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app
            .clone()
            .oneshot(req_with_proxy_ip("203.0.113.10"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
        // IP B: should still pass first request.
        let r3 = app
            .oneshot(req_with_proxy_ip("203.0.113.11"))
            .await
            .unwrap();
        assert_eq!(
            r3.status(),
            StatusCode::OK,
            "different IP must have its own budget"
        );
    }

    #[tokio::test]
    async fn real_ip_from_a_private_proxy_takes_precedence() {
        let limiter = Arc::new(PerIpRateLimiter::new(1));
        let app = app(limiter);
        let req1 = req_with_proxy_ip("203.0.113.42");
        let r1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let req2 = req_with_proxy_ip("203.0.113.42");
        let r2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "limiter must key on Railway's client address"
        );
    }

    #[tokio::test]
    async fn falls_back_to_peer_address_without_real_ip() {
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
            .oneshot(req_with_proxy_ip("203.0.113.99"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app
            .oneshot(req_with_proxy_ip("203.0.113.99"))
            .await
            .unwrap();
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
            .oneshot(req_with_proxy_ip("203.0.113.123"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        assert_eq!(metrics.per_ip_rate_limit_rejected(), 0);

        // Two more requests: both over cap → two increments.
        for _ in 0..2 {
            let r = app
                .clone()
                .oneshot(req_with_proxy_ip("203.0.113.123"))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        assert_eq!(metrics.per_ip_rate_limit_rejected(), 2);
    }
}
