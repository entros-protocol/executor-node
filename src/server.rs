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
        tracing::warn!(api_key = key, "Rate limit exceeded");
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
        tracing::warn!(api_key = key, "Attestation rate limit exceeded");
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

    // Standard routes with shared rate limit (60/min)
    let verify_routes = Router::new()
        .route("/verify", post(verify_handler))
        .route("/validate-features", post(validate_features_handler))
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
