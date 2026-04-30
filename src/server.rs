use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth::api_key::api_key_auth;
use crate::auth::rate_limit::RateLimiter;
use crate::error::AppError;
use crate::integrator::tracker::IntegratorTracker;
use crate::integrator::wallet_attempts::WalletAttemptTracker;
use crate::relayer::commitment_registry::CommitmentRegistry;
use crate::attestation::handler::attest_handler;
use crate::attestation::sas::SasAttestor;
use crate::challenge::handler::challenge_handler;
use crate::challenge::registry::ChallengeNonceRegistry;
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

    let verify_routes = timed_routes.merge(untimed_routes);

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
        tracing::info!(count = parsed.len(), "CORS restricted to configured origins");
        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::HeaderName::from_static("x-api-key")])
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
