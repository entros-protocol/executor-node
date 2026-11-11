use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::collections::HashSet;
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
use crate::paired::authorization::PairedAuthorizer;
use crate::solana::client::SolanaClient;
use crate::status::handler::{health_handler, status_handler};
use crate::status::metrics_handler::metrics_handler;
use crate::status::status_metrics::StatusMetrics;
use crate::study::{study_definition_handler, study_enrol_handler};
use crate::timing::{min_duration_middleware, BodyPolicy};
use crate::validation::composite::ScoringConfig;
use crate::validation::handler::validate_features_handler;

#[derive(Clone)]
pub struct AppState {
    pub validation_identity_program: solana_sdk::pubkey::Pubkey,
    pub solana: Arc<SolanaClient>,
    pub api_keys: Arc<Vec<String>>,
    /// Keys that ship in a public client. Every visitor holds one, so a bucket keyed on it
    /// would be one bucket for all of them. The per-IP limiter bounds their requests.
    pub public_api_keys: Arc<HashSet<String>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub attest_rate_limiter: Arc<RateLimiter>,
    /// Attestations per wallet. Taken after the wallet signature is checked, so no caller
    /// can spend another wallet's tokens.
    pub attest_wallet_rate_limiter: Arc<RateLimiter>,
    pub study_service_rate_limiter: Arc<RateLimiter>,
    pub study_concurrency: Arc<tokio::sync::Semaphore>,
    pub per_ip_rate_limiter: Arc<PerIpRateLimiter>,
    pub tracker: Arc<IntegratorTracker>,
    pub wallet_attempts: Arc<WalletAttemptTracker>,
    pub sas_attestor: Option<Arc<SasAttestor>>,
    pub metrics: Arc<StatusMetrics>,
    pub http_client: Arc<reqwest::Client>,
    pub validation_url: Option<String>,
    pub validation_api_key: Option<String>,
    pub challenge_registry: Arc<ChallengeNonceRegistry>,
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
    /// Observe-only curve-trace region/kinematics logging.
    /// Gates the curve-trace scoring log in `validate_features_handler`; never
    /// affects the verification decision.
    pub curve_trace_observe: bool,
    /// Cross-wallet verification cooldown tracker.
    pub cross_wallet_cooldown: Arc<CrossWalletCooldownTracker>,
    /// Enforces cross-wallet cooldown blocks when true.
    pub cross_wallet_cooldown_enforce: bool,
    /// IP blocklist for probing attacks. Maps IP address to block expiration time.
    pub probing_blocklist: Arc<dashmap::DashMap<std::net::IpAddr, std::time::Instant>>,
    /// Serves the paired-session routes when true.
    pub paired_enabled: bool,
    /// Bounds paired finalize requests processed at once. A finalize takes a slot only once
    /// its body is read and its authorization holds.
    pub session_gate: Arc<tokio::sync::Semaphore>,
    /// Bounds paired finalize bodies uploading or held at once, in total and per network.
    pub session_uploads: Arc<crate::paired::uploads::UploadGate>,
    /// Issues and checks the wallet-signed authorization for paired sessions.
    pub paired_authorizer: Arc<PairedAuthorizer>,
    /// Refuses updates on `/validate-features`, as it refuses baseline writes.
    pub single_capture_updates_refused: bool,
    /// Serves the study routes when true.
    pub study_routes_enabled: bool,
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    api_key_auth(request, next, &state.api_keys).await
}

fn api_key_of(request: &Request) -> &str {
    request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("authenticated")
}

/// True when the per-IP limiter is the limit for this request: it carries a public key, and
/// its client network resolved. A public key with no resolvable network keeps the shared
/// bucket, so no request is ever without a limit.
fn limited_per_client(state: &AppState, request: &Request) -> bool {
    if !state.public_api_keys.contains(api_key_of(request)) {
        return false;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    extract_client_ip(request.headers(), peer).is_some()
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let key = api_key_of(&request);
    if !limited_per_client(&state, &request) && state.rate_limiter.check(key).is_err() {
        tracing::warn!(api_key = %crate::auth::redact::redact_api_key(key), "Rate limit exceeded");
        return Err(AppError::RateLimited);
    }

    Ok(next.run(request).await)
}

/// The study routes serve the site's server. A public key reaches every browser, so it
/// gets no path to them.
async fn study_key_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    if state.public_api_keys.contains(api_key_of(&request)) {
        return Err(AppError::Forbidden(
            "This API key cannot use the study routes".into(),
        ));
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

/// The per-key attestation bucket. It runs before the handler checks the wallet signature,
/// so for a public key it would let any holder spend it for all the others. A public key is
/// bound by the per-wallet bucket inside the handler.
async fn attest_rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let key = api_key_of(&request);
    if !limited_per_client(&state, &request) && state.attest_rate_limiter.check(key).is_err() {
        tracing::warn!(
            api_key = %crate::auth::redact::redact_api_key(key),
            "Attestation rate limit exceeded"
        );
        return Err(AppError::RateLimited);
    }

    Ok(next.run(request).await)
}

/// Admits one paired finalize upload before its body is read, or refuses once no place frees
/// in time. The network place returns once the body has been read. The total place travels
/// with the request to the handler, which holds it until it returns, so the gate bounds the
/// bodies held in memory and the timing floor after it holds none.
async fn session_upload_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let network = extract_client_ip(request.headers(), peer);
    let admission = state
        .session_uploads
        .admit(network)
        .await
        .ok_or(AppError::PairedBusy)?;
    Ok(next.run(admission.attach(request)).await)
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

/// The whole paired finalize body must arrive within this. A paired body is larger than any
/// other, and each one holds an upload place while it uploads.
const SESSION_BODY_READ_DEADLINE: Duration = Duration::from_secs(20);

/// Wraps one group of verify routes. The per-IP limiter runs outside the group's auth and
/// timing stack, and the body limit runs outside the limiter, so an oversized upload is refused
/// on its `Content-Length` before it counts against its network or reaches anything else.
/// `RequestBodyLimitLayer` also caps a stream without that header, and `DefaultBodyLimit`
/// bounds what an extractor buffers.
fn verify_group(router: Router<AppState>, state: &AppState, limit: usize) -> Router<AppState> {
    router
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            per_ip_rate_limit_middleware,
        ))
        .route_layer(DefaultBodyLimit::max(limit))
        .route_layer(RequestBodyLimitLayer::new(limit))
}

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

async fn validation_deployment_handler(
    State(state): State<AppState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "schemaVersion": 1,
        "identityProgram": state.validation_identity_program.to_string(),
        "validationOnly": state.validation_identity_program != crate::solana::pda::anchor_program_id(),
        "challengeRequired": state.challenge_required,
    }))
}

pub fn create_router(state: AppState, cors_origins: &[axum::http::HeaderValue]) -> Router {
    let validation_only =
        state.validation_identity_program != crate::solana::pda::anchor_program_id();
    // Attest route with its own tighter rate limit (10/min per key that is not public)
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
    let timed_routes = verify_group(
        Router::new()
            .route("/validate-features", post(validate_features_handler))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .route_layer(middleware::from_fn_with_state(
                BodyPolicy::limit(MAX_REQUEST_BODY_BYTES),
                min_duration_middleware,
            ))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        &state,
        MAX_REQUEST_BODY_BYTES,
    );

    // The paired finalize is timed like `/validate-features`, with its own body limit, a total
    // upload deadline, and a gate that bounds how many of its larger bodies are held at once.
    // The handler takes a processing slot only after the body is read and authorized.
    let session_routes = if state.paired_enabled {
        verify_group(
            Router::new()
                .route(
                    "/validate-session",
                    post(crate::paired::finalize::validate_session_handler),
                )
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    rate_limit_middleware,
                ))
                .route_layer(middleware::from_fn_with_state(
                    BodyPolicy {
                        max_bytes: crate::paired::SESSION_BODY_BYTES,
                        read_deadline: Some(SESSION_BODY_READ_DEADLINE),
                    },
                    min_duration_middleware,
                ))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    session_upload_middleware,
                ))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                )),
            &state,
            crate::paired::SESSION_BODY_BYTES,
        )
    } else {
        Router::new()
    };

    // Untimed authenticated routes: /challenge issues nonces (fast by design,
    // user-blocking before the verify call) and /attest already exposes its
    // outcome shape via a wallet-attributable error.
    //
    // The duplicated rate_limit + auth route_layer applications below are
    // intentional: timed_routes need min_duration to wrap auth+rate_limit so
    // pre-handler short-circuits also clamp to the timing budget. Each
    // Router carries its own layer stack but the same `state.rate_limiter`
    // (Arc) backs both, so counters merge across the route groups.
    // The study routes exist only while intake is open. They carry no per-key or per-IP
    // limit, because the site's server sends every participant's request from one address.
    let study_routes = if validation_only || !state.study_routes_enabled {
        Router::new()
    } else {
        Router::new()
            .route("/study/definition", post(study_definition_handler))
            .route("/study/enrol", post(study_enrol_handler))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                study_key_middleware,
            ))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .route_layer(RequestBodyLimitLayer::new(STUDY_REQUEST_BODY_BYTES))
    };

    let untimed_routes = verify_group(
        Router::new()
            .route("/challenge", get(challenge_handler))
            .route("/validation-deployment", get(validation_deployment_handler))
            .merge(if validation_only {
                Router::new()
            } else {
                attest_route
            })
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        &state,
        MAX_REQUEST_BODY_BYTES,
    );

    // Opening a session and committing a round stay untimed. A commit carries digests only,
    // and a timing floor on every round would add seconds inside the interaction.
    let paired_round_routes = if state.paired_enabled {
        let paired = |path: &str, handler, limit| {
            verify_group(
                Router::new()
                    .route(path, handler)
                    .route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        rate_limit_middleware,
                    ))
                    .route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        auth_middleware,
                    )),
                &state,
                limit,
            )
        };
        paired(
            "/challenge/paired",
            post(crate::paired::open_handler),
            crate::paired::OPEN_BODY_BYTES,
        )
        .merge(paired(
            "/paired/authorization",
            get(crate::paired::authorization::authorization_handler),
            crate::paired::OPEN_BODY_BYTES,
        ))
        .merge(paired(
            "/paired/commit",
            post(crate::paired::commit_handler),
            crate::paired::COMMIT_BODY_BYTES,
        ))
        .merge(paired(
            "/paired/cue",
            post(crate::paired::cue_handler),
            crate::paired::COMMIT_BODY_BYTES,
        ))
    } else {
        Router::new()
    };

    // Every verify group carries per-IP rate limiting (see `verify_group`). It sits OUTSIDE
    // both min-duration and the per-API-key and per-wallet limiters, so hostile traffic is
    // rejected before consuming server resources. /health, /status and /metrics carry none,
    // because Railway healthchecks and Prometheus scrapers hit them at high cadence.
    let verify_routes = timed_routes
        .merge(session_routes)
        .merge(untimed_routes)
        .merge(paired_round_routes)
        .merge(study_routes);

    // The outer transport limit is the largest body any served route accepts.
    let transport_limit = if state.paired_enabled {
        crate::paired::SESSION_BODY_BYTES
    } else {
        MAX_REQUEST_BODY_BYTES
    };

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
        .layer(DefaultBodyLimit::max(transport_limit))
        // Reclaim a stalled upload. Applied inside the size limit so only
        // bodies that passed the cheap `Content-Length` check get wrapped.
        .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_READ_TIMEOUT))
        // The actual size limit. Rejects with 413 straight from the
        // `Content-Length` header before reading any of the body, and caps
        // the stream when the header is absent. Outermost of the three so
        // an oversized upload never reaches auth, the rate limiters, or the
        // body-buffering inside `min_duration_middleware`.
        .layer(RequestBodyLimitLayer::new(transport_limit))
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
        validation_identity_program: crate::solana::pda::anchor_program_id(),
        solana: solana_client,
        api_keys: Arc::new(vec![]),
        public_api_keys: Arc::new(HashSet::new()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        attest_rate_limiter: Arc::new(RateLimiter::new(10)),
        attest_wallet_rate_limiter: Arc::new(RateLimiter::new(2)),
        study_service_rate_limiter: Arc::new(RateLimiter::new(600)),
        study_concurrency: Arc::new(tokio::sync::Semaphore::new(32)),
        per_ip_rate_limiter: Arc::new(PerIpRateLimiter::new(30)),
        tracker,
        wallet_attempts: Arc::new(WalletAttemptTracker::new(5, Duration::from_secs(3600))),
        sas_attestor: None,
        metrics: Arc::new(StatusMetrics::new()),
        http_client: Arc::new(reqwest::Client::new()),
        validation_url,
        validation_api_key: None,
        challenge_registry: Arc::new(ChallengeNonceRegistry::new(300)),
        challenge_required: false,
        scoring_config: Arc::new(ScoringConfig::synthetic_test_policy()),
        automation_observe: true,
        automation_webdriver_reject: false,
        wallet_reputation_observe: true,
        curve_trace_observe: true,
        cross_wallet_cooldown: Arc::new(CrossWalletCooldownTracker::new(86400)),
        cross_wallet_cooldown_enforce: false,
        probing_blocklist: Arc::new(dashmap::DashMap::new()),
        paired_enabled: false,
        session_gate: Arc::new(tokio::sync::Semaphore::new(16)),
        session_uploads: crate::paired::uploads::UploadGate::new(
            crate::paired::uploads::SESSION_UPLOADS,
            crate::paired::uploads::SESSION_UPLOADS_PER_NETWORK,
        ),
        // Handler tests that are not about the authorization send none. The tests that are
        // about it set `Required`, the production default.
        paired_authorizer: Arc::new(
            PairedAuthorizer::new(
                &[0x11; 32],
                crate::paired::authorization::DEFAULT_TTL_SECS,
                crate::paired::authorization::AuthorizationMode::Optional,
                crate::paired::authorization::NetworkMode::Enforce,
            )
            .expect("test authorizer"),
        ),
        single_capture_updates_refused: false,
        study_routes_enabled: false,
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
        public: false,
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
pub(crate) static LOG_CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) fn enable_test_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // Parallel tests register callsites outside the capture subscriber.
        // Keep their interest enabled; scoped subscribers still own the captured output.
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(std::io::sink)
                .finish(),
        )
        .expect("one test tracing initializer");
    });
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

    #[tokio::test]
    async fn request_trace_excludes_query_values() {
        const SECRET_QUERY_VALUE: &str = "wallet-query-must-not-appear";

        let _log_capture_guard = LOG_CAPTURE_LOCK.lock().await;
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

#[cfg(test)]
mod request_body_limit_tests {
    use super::*;
    use crate::validation::handler::ValidateFeaturesRequest;
    use crate::validation::transport_fixture::{
        padded_request_body, synthetic_transport_fixture, MAXIMUM_DURATION_MS,
        REPRESENTATIVE_DURATION_MS,
    };
    use axum::body::{Body, Bytes};
    use axum::http::{header, Request, StatusCode};
    use axum::routing::post;
    use axum::Json;
    use futures_util::stream::{self, StreamExt};
    use std::time::{Duration, Instant};
    use tower::util::ServiceExt;

    const PRESSURE_RUNS: usize = 30;
    const PRESSURE_CONCURRENCY: [usize; 5] = [1, 4, 8, 16, 30];

    async fn accept_synthetic_request(Json(_request): Json<ValidateFeaturesRequest>) -> StatusCode {
        StatusCode::NO_CONTENT
    }

    fn boundary_router() -> Router {
        Router::new()
            .route("/validate-features", post(accept_synthetic_request))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_READ_TIMEOUT))
            .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
    }

    async fn send_to(router: Router, body: Bytes) -> StatusCode {
        let content_length = body.len();
        router
            .oneshot(
                Request::post("/validate-features")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, content_length)
                    .body(Body::from(body))
                    .expect("request builds"),
            )
            .await
            .expect("router responds")
            .status()
    }

    async fn send(body: Vec<u8>) -> StatusCode {
        send_to(boundary_router(), Bytes::from(body)).await
    }

    fn percentile_ms(sorted: &[Duration], percentile: usize) -> f64 {
        let rank = (sorted.len() * percentile).div_ceil(100);
        sorted[rank.saturating_sub(1)].as_secs_f64() * 1_000.0
    }

    #[tokio::test]
    async fn synthetic_transport_request_freezes_the_one_mebibyte_boundary() {
        let exact = padded_request_body(MAXIMUM_DURATION_MS, MAX_REQUEST_BODY_BYTES);
        assert_eq!(send(exact).await, StatusCode::NO_CONTENT);

        let oversized = padded_request_body(MAXIMUM_DURATION_MS, MAX_REQUEST_BODY_BYTES + 1);
        assert_eq!(send(oversized).await, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn synthetic_transport_request_rejects_oversized_bodies_without_content_length() {
        let body = Bytes::from(padded_request_body(
            MAXIMUM_DURATION_MS,
            MAX_REQUEST_BODY_BYTES + 1,
        ));
        let response = boundary_router()
            .oneshot(
                Request::post("/validate-features")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert!(response.status().is_client_error());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn synthetic_transport_request_boundary_pressure_is_failure_free() {
        for (payload, duration_ms) in [
            ("representative", REPRESENTATIVE_DURATION_MS),
            ("maximum", MAXIMUM_DURATION_MS),
        ] {
            let source_body = Bytes::from(
                serde_json::to_vec(&synthetic_transport_fixture(duration_ms).request)
                    .expect("synthetic request serializes"),
            );
            assert!(source_body.len() < MAX_REQUEST_BODY_BYTES);

            for concurrency in PRESSURE_CONCURRENCY {
                let router = boundary_router();
                let arrivals = vec![Instant::now(); PRESSURE_RUNS];
                let batch_started = Instant::now();
                let results: Vec<(StatusCode, Duration, Duration)> = stream::iter(arrivals)
                    .map(|arrived| {
                        let router = router.clone();
                        let body = Bytes::copy_from_slice(source_body.as_ref());
                        tokio::spawn(async move {
                            let service_started = Instant::now();
                            let status = send_to(router, body).await;
                            (status, arrived.elapsed(), service_started.elapsed())
                        })
                    })
                    .buffer_unordered(concurrency)
                    .map(|result| result.expect("request task joins"))
                    .collect()
                    .await;
                let batch_elapsed = batch_started.elapsed();

                assert_eq!(results.len(), PRESSURE_RUNS);
                assert!(results
                    .iter()
                    .all(|(status, _, _)| *status == StatusCode::NO_CONTENT));

                if std::env::var_os("ENTROS_TRANSPORT_BENCHMARK").as_deref()
                    == Some(std::ffi::OsStr::new("1"))
                {
                    let mut sojourn: Vec<Duration> =
                        results.iter().map(|(_, latency, _)| *latency).collect();
                    let mut service: Vec<Duration> =
                        results.iter().map(|(_, _, latency)| *latency).collect();
                    sojourn.sort_unstable();
                    service.sort_unstable();
                    println!(
                        "{}",
                        serde_json::json!({
                            "payload": payload,
                            "bytes": source_body.len(),
                            "runs": PRESSURE_RUNS,
                            "concurrency": concurrency,
                            "rps": PRESSURE_RUNS as f64 / batch_elapsed.as_secs_f64(),
                            "p50_ms": percentile_ms(&sojourn, 50),
                            "p95_ms": percentile_ms(&sojourn, 95),
                            "service_p50_ms": percentile_ms(&service, 50),
                            "service_p95_ms": percentile_ms(&service, 95),
                        })
                    );
                }
            }
        }
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
        state.study_routes_enabled = true;
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
        state.study_routes_enabled = true;
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

#[cfg(test)]
mod validation_deployment_tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn isolated_gateway_metadata_requires_authentication_and_disables_writes() {
        let mut state = build_test_state(tracker_with_quota("fixture", 10), None);
        state.api_keys = Arc::new(vec!["fixture".into()]);
        state.validation_identity_program = solana_sdk::pubkey::Pubkey::new_unique();
        state.challenge_required = true;
        state.study_routes_enabled = true;
        let expected_program = state.validation_identity_program.to_string();
        let router = create_router(state, &[]);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/validation-deployment")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/validation-deployment")
                    .header("x-api-key", "fixture")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["identityProgram"], expected_program);
        assert_eq!(body["validationOnly"], true);
        assert_eq!(body["challengeRequired"], true);
        for path in ["/verify", "/attest", "/study/definition", "/study/enrol"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("x-api-key", "fixture")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}

#[cfg(test)]
mod load_pressure {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    async fn spawn_server() -> String {
        let tracker = tracker_with_quota("load-key", u64::MAX);
        let state = build_test_state(tracker, None);
        let app = create_router(state, &[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        format!("http://{addr}")
    }

    async fn drive(client: reqwest::Client, url: String, workers: usize, per_worker: usize) {
        let ok = Arc::new(AtomicU64::new(0));
        let bad = Arc::new(AtomicU64::new(0));
        let latencies = Arc::new(tokio::sync::Mutex::new(Vec::<u128>::new()));
        let start = Instant::now();

        let mut handles = Vec::new();
        for _ in 0..workers {
            let (client, url) = (client.clone(), url.clone());
            let (ok, bad, latencies) = (Arc::clone(&ok), Arc::clone(&bad), Arc::clone(&latencies));
            handles.push(tokio::spawn(async move {
                let mut local = Vec::with_capacity(per_worker);
                for _ in 0..per_worker {
                    let t = Instant::now();
                    match client.get(&url).send().await {
                        Ok(r) if r.status().is_success() => {
                            let _ = r.bytes().await;
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    local.push(t.elapsed().as_micros());
                }
                latencies.lock().await.extend(local);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let elapsed = start.elapsed();
        let mut lat = latencies.lock().await.clone();
        lat.sort_unstable();
        let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
        let (ok, bad) = (ok.load(Ordering::Relaxed), bad.load(Ordering::Relaxed));
        let path = url.rsplit('/').next().unwrap().to_string();
        println!(
            "  {path:<22} n={:<6} ok={:<6} err={:<4} {:>8.0} req/s  p50={:>6}us p95={:>7}us p99={:>7}us",
            ok + bad, ok, bad, (ok + bad) as f64 / elapsed.as_secs_f64(),
            pct(0.50), pct(0.95), pct(0.99),
        );
        assert_eq!(bad, 0, "{path} dropped requests under load");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "load measurement; run with --ignored --nocapture"]
    async fn both_protocols_stay_error_free_under_concurrency() {
        // The `h2` advisory this release closes is a stream-handling denial of
        // service, so the HTTP/2 pass drives multiplexed streams rather than
        // separate connections.
        let base = spawn_server().await;

        println!("HTTP/1.1, 128 connections");
        let http1 = reqwest::Client::builder()
            .pool_max_idle_per_host(256)
            .build()
            .unwrap();
        for path in ["/health", "/status", "/metrics"] {
            drive(http1.clone(), format!("{base}{path}"), 128, 100).await;
        }

        println!("HTTP/2 prior knowledge, 256 concurrent streams");
        let http2 = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        for path in ["/health", "/status"] {
            drive(http2.clone(), format!("{base}{path}"), 256, 50).await;
        }
    }

    /// Every finalize holds its slot and its upload place only while its handler runs. With
    /// 16 slots and a 4 s floor, a slot held through the floor would cap the route at 4
    /// finalizes a second and refuse most of this burst as busy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "load measurement; run with --ignored --nocapture"]
    async fn paired_finalize_frees_its_slot_before_the_floor() {
        use crate::validation::mock_validator::{
            state_with_mock_validator, success_body, MockValidator,
        };
        const WORKERS: usize = 64;
        const PER_WORKER: usize = 4;

        let mock =
            MockValidator::spawn(axum::http::StatusCode::OK, success_body(0.0, 0.0, 0.0)).await;
        let mut state = state_with_mock_validator(tracker_with_quota("load-key", u64::MAX), &mock);
        state.api_keys = Arc::new(vec!["load-key".into()]);
        state.paired_enabled = true;
        state.rate_limiter = Arc::new(RateLimiter::new(1_000_000));
        state.per_ip_rate_limiter = Arc::new(PerIpRateLimiter::new(1_000_000));
        // Every worker sends from one address, so the network bound is lifted to the total.
        state.session_uploads = crate::paired::uploads::UploadGate::new(
            crate::paired::uploads::SESSION_UPLOADS,
            crate::paired::uploads::SESSION_UPLOADS,
        );
        let app = create_router(state, &[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(WORKERS)
            .build()
            .unwrap();
        let segment = |round: u32| {
            serde_json::json!({
                "round_index": round,
                "audio_b64": "A".repeat(160_000),
                "coarse_path_hex": "01",
            })
        };
        let passed = Arc::new(AtomicU64::new(0));
        let busy = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let (client, base) = (client.clone(), base.clone());
            let (passed, busy) = (Arc::clone(&passed), Arc::clone(&busy));
            let body = serde_json::json!({
                "capture_protocol": "paired",
                "projection_version": 1,
                "session_id": "00112233445566778899aabbccddeeff",
                "final_digest": "ab".repeat(32),
                "segments": [segment(1), segment(2), segment(3)],
                "features": vec![0.5; 308],
            });
            handles.push(tokio::spawn(async move {
                for _ in 0..PER_WORKER {
                    let mut body = body.clone();
                    body["wallet_id"] = solana_sdk::pubkey::Pubkey::new_unique().to_string().into();
                    let response = client
                        .post(format!("{base}/validate-session"))
                        .header("x-api-key", "load-key")
                        .json(&body)
                        .send()
                        .await
                        .unwrap();
                    match response.status().as_u16() {
                        200 => passed.fetch_add(1, Ordering::Relaxed),
                        503 => busy.fetch_add(1, Ordering::Relaxed),
                        other => panic!("unexpected status {other}"),
                    };
                }
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let (passed, busy) = (passed.load(Ordering::Relaxed), busy.load(Ordering::Relaxed));
        println!(
            "  /validate-session      n={:<5} passed={passed:<5} busy={busy:<4} {:>6.1} finalizes/s over {elapsed:.1} s",
            WORKERS * PER_WORKER,
            (passed + busy) as f64 / elapsed,
        );
        assert_eq!(busy, 0, "a finalize slot outlived its handler");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "load measurement; run with --ignored --nocapture"]
    async fn oversized_bodies_never_reach_a_handler() {
        // The size limit answers from `Content-Length` before reading the body,
        // so a client can lose the connection mid-upload instead of reading the
        // 413. Both outcomes prove the body never buffered. A 2xx would not.
        let base = spawn_server().await;
        let client = reqwest::Client::new();
        let oversized = vec![0u8; MAX_REQUEST_BODY_BYTES + 4096];
        let offered = 640u64 * oversized.len() as u64 / (1024 * 1024);

        let start = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..64 {
            let client = client.clone();
            let url = format!("{base}/validate-features");
            let body = oversized.clone();
            handles.push(tokio::spawn(async move {
                let (mut refused, mut accepted) = (0u32, 0u32);
                for _ in 0..10 {
                    match client.post(&url).body(body.clone()).send().await {
                        Ok(r) if r.status().is_success() => accepted += 1,
                        _ => refused += 1,
                    }
                }
                (refused, accepted)
            }));
        }
        let (mut refused, mut accepted) = (0u32, 0u32);
        for h in handles {
            let (r, a) = h.await.unwrap();
            refused += r;
            accepted += a;
        }
        println!(
            "  oversized-body         n=640   refused={refused:<4} accepted={accepted:<4} {:>8.0} req/s  ({offered} MiB offered)",
            640.0 / start.elapsed().as_secs_f64(),
        );
        assert_eq!(accepted, 0, "an oversized body reached a handler");

        // The server must still serve normally after the burst.
        let health = client.get(format!("{base}/health")).send().await.unwrap();
        assert!(
            health.status().is_success(),
            "server degraded after the burst"
        );
        println!("  post-burst /health     {}", health.status());
    }
}

#[cfg(test)]
mod route_limit_tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::http::{header, Request as HttpRequest, StatusCode};
    use tower::util::ServiceExt;

    fn state(paired_enabled: bool) -> AppState {
        let mut state = build_test_state(tracker_with_quota("key", 10), None);
        state.api_keys = Arc::new(vec!["key".into()]);
        state.paired_enabled = paired_enabled;
        state
    }

    async fn status_of(state: AppState, path: &str, body_len: usize) -> StatusCode {
        create_router(state, &[])
            .oneshot(
                HttpRequest::post(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, body_len)
                    .header("x-api-key", "key")
                    .body(Body::from(Bytes::from(vec![b' '; body_len])))
                    .expect("request builds"),
            )
            .await
            .expect("router responds")
            .status()
    }

    #[tokio::test(start_paused = true)]
    async fn each_route_group_holds_its_own_limit() {
        for (paired, path, limit) in [
            (false, "/validate-features", MAX_REQUEST_BODY_BYTES),
            (true, "/validate-features", MAX_REQUEST_BODY_BYTES),
            (false, "/attest", MAX_REQUEST_BODY_BYTES),
            (true, "/validate-session", crate::paired::SESSION_BODY_BYTES),
            (true, "/challenge/paired", crate::paired::OPEN_BODY_BYTES),
            (true, "/paired/commit", crate::paired::COMMIT_BODY_BYTES),
            (true, "/paired/cue", crate::paired::COMMIT_BODY_BYTES),
        ] {
            assert_ne!(
                status_of(state(paired), path, limit).await,
                StatusCode::PAYLOAD_TOO_LARGE,
                "{path} accepts exactly its limit"
            );
            assert_eq!(
                status_of(state(paired), path, limit + 1).await,
                StatusCode::PAYLOAD_TOO_LARGE,
                "{path} refuses one byte over its limit"
            );
        }
    }

    #[tokio::test]
    async fn paired_routes_do_not_exist_while_paired_sessions_are_off() {
        for path in [
            "/challenge/paired",
            "/paired/commit",
            "/paired/cue",
            "/validate-session",
        ] {
            assert_eq!(
                status_of(state(false), path, 2).await,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
    }

    fn post(path: &str, body: Body) -> HttpRequest<Body> {
        let mut request = HttpRequest::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-api-key", "key")
            .body(body)
            .expect("request builds");
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [203, 0, 113, 9],
                4_000,
            ))));
        request
    }

    /// A body the finalize handler parses and then refuses, so the request runs the whole
    /// stack, handler included.
    fn out_of_bounds_session() -> Body {
        Body::from(
            serde_json::json!({
                "capture_protocol": "paired",
                "wallet_id": "11111111111111111111111111111111",
                "projection_version": 1,
                "session_id": "00",
                "final_digest": "00",
                "segments": [],
                "features": [],
            })
            .to_string(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_finalize_slot_frees_when_the_handler_returns_not_after_the_floor() {
        let mut single_slot = state(true);
        single_slot.session_gate = Arc::new(tokio::sync::Semaphore::new(1));
        let router = create_router(single_slot, &[]);

        let first = tokio::spawn(
            router
                .clone()
                .oneshot(post("/validate-session", out_of_bounds_session())),
        );
        // The first request is now inside its timing floor.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let second = router
            .oneshot(post("/validate-session", out_of_bounds_session()))
            .await
            .expect("router responds");
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        let first = first.await.expect("task").expect("router responds");
        assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(start_paused = true)]
    async fn a_malformed_paired_body_is_refused_as_invalid_request() {
        for path in [
            "/challenge/paired",
            "/paired/commit",
            "/paired/cue",
            "/validate-session",
        ] {
            let response = create_router(state(true), &[])
                .oneshot(post(path, Body::from("{\"wallet\":1}")))
                .await
                .expect("router responds");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
            let bytes = axum::body::to_bytes(response.into_body(), 64_000)
                .await
                .expect("body");
            let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
            assert_eq!(body["reason"], "invalid_request", "{path}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_chunked_body_over_the_group_limit_is_refused() {
        for (path, limit) in [
            ("/paired/commit", crate::paired::COMMIT_BODY_BYTES),
            ("/paired/cue", crate::paired::COMMIT_BODY_BYTES),
            ("/validate-session", crate::paired::SESSION_BODY_BYTES),
            ("/validate-features", MAX_REQUEST_BODY_BYTES),
        ] {
            let chunks = futures_util::stream::iter(
                vec![b' '; limit + 1]
                    .chunks(4_096)
                    .map(|chunk| Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(chunk)))
                    .collect::<Vec<_>>(),
            );
            let response = create_router(state(true), &[])
                .oneshot(post(path, Body::from_stream(chunks)))
                .await
                .expect("router responds");
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_oversized_body_is_refused_before_it_counts_against_its_network() {
        let mut limited = state(true);
        limited.per_ip_rate_limiter = Arc::new(PerIpRateLimiter::new(1));
        let router = create_router(limited, &[]);
        let spend = router
            .clone()
            .oneshot(post("/paired/commit", Body::from("{}")))
            .await
            .expect("router responds");
        assert_ne!(spend.status(), StatusCode::TOO_MANY_REQUESTS);
        let oversized = vec![b' '; crate::paired::COMMIT_BODY_BYTES + 1];
        let mut request = post("/paired/commit", Body::from(oversized.clone()));
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, oversized.len().into());
        assert_eq!(
            router.oneshot(request).await.expect("responds").status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn the_transport_limit_follows_the_paired_flag() {
        // With paired sessions off, nothing larger than the single-capture limit is read.
        assert_eq!(
            status_of(
                state(false),
                "/validate-session",
                MAX_REQUEST_BODY_BYTES + 1
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    /// A body the finalize handler accepts as well formed, so the request reaches the
    /// processing slot.
    fn in_bounds_session() -> Body {
        let segment = |round: u32| {
            serde_json::json!({
                "round_index": round,
                "audio_b64": "AAAA",
                "coarse_path_hex": "01",
            })
        };
        Body::from(
            serde_json::json!({
                "capture_protocol": "paired",
                "wallet_id": "11111111111111111111111111111111",
                "projection_version": 1,
                "session_id": "00112233445566778899aabbccddeeff",
                "final_digest": "ab".repeat(32),
                "segments": [segment(1), segment(2), segment(3)],
                "features": vec![0.5; 308],
            })
            .to_string(),
        )
    }

    /// A body that delivers its first byte and then stalls until the returned sender is
    /// dropped. The request it carries never parses.
    fn held_body() -> (Body, tokio::sync::oneshot::Sender<()>) {
        use futures_util::StreamExt;
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let first = futures_util::stream::once(async {
            Ok::<_, std::convert::Infallible>(Bytes::from_static(b"{"))
        });
        let rest = futures_util::stream::once(async move {
            let _ = released.await;
            Ok::<_, std::convert::Infallible>(Bytes::new())
        });
        (Body::from_stream(first.chain(rest)), release)
    }

    fn post_from(path: &str, body: Body, peer: [u8; 4]) -> HttpRequest<Body> {
        let mut request = post(path, body);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                peer, 4_000,
            ))));
        request
    }

    async fn reason_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64_000)
            .await
            .expect("body");
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")["reason"].clone()
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_upload_holds_no_processing_slot() {
        let mut single_slot = state(true);
        single_slot.session_gate = Arc::new(tokio::sync::Semaphore::new(1));
        let router = create_router(single_slot, &[]);

        let (slow, _release) = held_body();
        let uploading = tokio::spawn(router.clone().oneshot(post("/validate-session", slow)));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let response = router
            .oneshot(post("/validate-session", in_bounds_session()))
            .await
            .expect("router responds");
        assert_ne!(reason_of(response).await, "session_busy");
        uploading.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_processing_gate_refuses_only_an_authorized_request() {
        let mut busy = state(true);
        busy.session_gate = Arc::new(tokio::sync::Semaphore::new(0));
        let router = create_router(busy.clone(), &[]);

        let response = router
            .clone()
            .oneshot(post("/validate-session", in_bounds_session()))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reason_of(response).await, "session_busy");

        // A request that fails its own checks is answered before it waits for a slot.
        let response = router
            .oneshot(post("/validate-session", out_of_bounds_session()))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        busy.paired_authorizer = Arc::new(
            crate::paired::authorization::PairedAuthorizer::with_random_key(
                600,
                crate::paired::authorization::AuthorizationMode::Required,
                crate::paired::authorization::NetworkMode::Enforce,
            )
            .expect("authorizer"),
        );
        let response = create_router(busy, &[])
            .oneshot(post("/validate-session", in_bounds_session()))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_uploads_at_most_two_bodies_at_once() {
        let router = create_router(state(true), &[]);
        let crowded = [198, 51, 100, 7];

        let mut held = Vec::new();
        for _ in 0..2 {
            let (body, release) = held_body();
            held.push((
                tokio::spawn(
                    router
                        .clone()
                        .oneshot(post_from("/validate-session", body, crowded)),
                ),
                release,
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let third = router
            .clone()
            .oneshot(post_from(
                "/validate-session",
                out_of_bounds_session(),
                crowded,
            ))
            .await
            .expect("router responds");
        assert_eq!(third.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reason_of(third).await, "session_busy");

        let elsewhere = router
            .oneshot(post_from(
                "/validate-session",
                out_of_bounds_session(),
                [192, 0, 2, 44],
            ))
            .await
            .expect("router responds");
        assert_eq!(elsewhere.status(), StatusCode::BAD_REQUEST);
        for (upload, _) in held {
            upload.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_upload_waits_for_a_place_on_its_network() {
        let router = create_router(state(true), &[]);
        let crowded = [198, 51, 100, 7];

        let mut releases = Vec::new();
        let mut uploads = Vec::new();
        for _ in 0..2 {
            let (body, release) = held_body();
            uploads.push(tokio::spawn(router.clone().oneshot(post_from(
                "/validate-session",
                body,
                crowded,
            ))));
            releases.push(release);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let waiting = tokio::spawn(router.oneshot(post_from(
            "/validate-session",
            out_of_bounds_session(),
            crowded,
        )));
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        drop(releases.remove(0));

        let response = waiting.await.expect("task").expect("router responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        for upload in uploads {
            upload.abort();
        }
    }

    /// A request that has finished its upload returns its network place while it is still
    /// processed, so another client behind the same address gets a place at once.
    #[tokio::test(start_paused = true)]
    async fn a_network_place_frees_once_its_body_is_read() {
        let mut slow = state(true);
        slow.session_gate = Arc::new(tokio::sync::Semaphore::new(1));
        // Hold the only processing slot, so the first request stays in its handler.
        let _processing = Arc::clone(&slow.session_gate)
            .acquire_owned()
            .await
            .expect("slot");
        slow.session_uploads = crate::paired::uploads::UploadGate::new(4, 1);
        let router = create_router(slow, &[]);
        let crowded = [198, 51, 100, 7];

        let first = tokio::spawn(router.clone().oneshot(post_from(
            "/validate-session",
            in_bounds_session(),
            crowded,
        )));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let started = tokio::time::Instant::now();
        let second = router
            .oneshot(post_from(
                "/validate-session",
                out_of_bounds_session(),
                crowded,
            ))
            .await
            .expect("router responds");
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        // The answer waits only for the timing floor, not for the first request.
        assert_eq!(started.elapsed(), crate::timing::HANDLER_MIN_DURATION);
        let first = first.await.expect("task").expect("router responds");
        assert_eq!(reason_of(first).await, "session_busy");
    }

    /// The total place is kept until the handler returns, so it still bounds what is held.
    #[tokio::test(start_paused = true)]
    async fn the_total_upload_bound_holds_while_a_request_is_processed() {
        let mut slow = state(true);
        slow.session_gate = Arc::new(tokio::sync::Semaphore::new(1));
        let _processing = Arc::clone(&slow.session_gate)
            .acquire_owned()
            .await
            .expect("slot");
        slow.session_uploads = crate::paired::uploads::UploadGate::new(1, 2);
        let gate = Arc::clone(&slow.session_uploads);
        let router = create_router(slow, &[]);

        let first = tokio::spawn(router.oneshot(post_from(
            "/validate-session",
            in_bounds_session(),
            [198, 51, 100, 7],
        )));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The first request waits for a processing slot until well past this window.
        let elsewhere = "192.0.2.44".parse().expect("address");
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(1),
            gate.admit(Some(elsewhere))
        )
        .await
        .is_err());
        first.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_upload_gate_refuses_before_buffering() {
        let mut full = state(true);
        full.session_uploads = crate::paired::uploads::UploadGate::new(0, 2);
        let (stalled, _release) = held_body();
        let response = create_router(full, &[])
            .oneshot(post("/validate-session", stalled))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reason_of(response).await, "session_busy");
    }
}

#[cfg(test)]
mod key_scope_tests {
    //! A public key ships to every visitor. These tests hold the rule that none of its
    //! holders can spend a limit the others share.
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::util::ServiceExt;

    const PUBLIC_KEY: &str = "site-key";
    const SERVER_KEY: &str = "server-key";

    fn state() -> AppState {
        let mut state = build_test_state(tracker_with_quota(PUBLIC_KEY, 0), None);
        state.api_keys = Arc::new(vec![PUBLIC_KEY.into(), SERVER_KEY.into()]);
        state.public_api_keys = Arc::new(HashSet::from([PUBLIC_KEY.to_owned()]));
        state.rate_limiter = Arc::new(RateLimiter::new(1));
        state.attest_rate_limiter = Arc::new(RateLimiter::new(1));
        state.per_ip_rate_limiter = Arc::new(PerIpRateLimiter::new(1_000));
        state
    }

    fn challenge(key: &str, peer: Option<&str>) -> HttpRequest<Body> {
        let mut request = HttpRequest::get(format!("/challenge?wallet={}", random_wallet_id()))
            .header("x-api-key", key)
            .body(Body::empty())
            .expect("request builds");
        if let Some(peer) = peer {
            request.extensions_mut().insert(ConnectInfo(
                peer.parse::<SocketAddr>().expect("socket address"),
            ));
        }
        request
    }

    async fn statuses(
        router: &Router,
        requests: impl IntoIterator<Item = HttpRequest<Body>>,
    ) -> Vec<StatusCode> {
        let mut statuses = Vec::new();
        for request in requests {
            statuses.push(
                router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("router responds")
                    .status(),
            );
        }
        statuses
    }

    #[tokio::test]
    async fn one_visitor_cannot_spend_the_bucket_of_a_public_key_for_the_others() {
        let router = create_router(state(), &[]);
        let noisy = (0..5).map(|_| challenge(PUBLIC_KEY, Some("198.51.100.9:4000")));
        assert!(statuses(&router, noisy)
            .await
            .iter()
            .all(|status| *status == StatusCode::OK));
        let other = challenge(PUBLIC_KEY, Some("203.0.113.7:4000"));
        assert_eq!(statuses(&router, [other]).await, [StatusCode::OK]);
    }

    #[tokio::test]
    async fn a_private_key_keeps_its_shared_bucket() {
        let router = create_router(state(), &[]);
        let requests = (0..2).map(|_| challenge(SERVER_KEY, Some("198.51.100.9:4000")));
        assert_eq!(
            statuses(&router, requests).await,
            [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]
        );
    }

    #[tokio::test]
    async fn a_public_key_is_still_bound_by_the_per_ip_limit() {
        let mut limited = state();
        limited.per_ip_rate_limiter = Arc::new(PerIpRateLimiter::new(1));
        let router = create_router(limited, &[]);
        let requests = (0..2).map(|_| challenge(PUBLIC_KEY, Some("198.51.100.9:4000")));
        assert_eq!(
            statuses(&router, requests).await,
            [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]
        );
    }

    /// The per-IP limiter passes a request whose address it cannot resolve. Such a request
    /// must fall back to the shared bucket, or it would have no limit at all.
    #[tokio::test]
    async fn a_public_key_with_no_resolvable_address_falls_back_to_the_shared_bucket() {
        let router = create_router(state(), &[]);
        let requests = (0..2).map(|_| challenge(PUBLIC_KEY, None));
        assert_eq!(
            statuses(&router, requests).await,
            [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]
        );
    }

    fn attest(key: &str) -> HttpRequest<Body> {
        let mut request = HttpRequest::post("/attest")
            .header("x-api-key", key)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "wallet_address": random_wallet_id() }).to_string(),
            ))
            .expect("request builds");
        request.extensions_mut().insert(ConnectInfo(
            "198.51.100.9:4000".parse::<SocketAddr>().expect("address"),
        ));
        request
    }

    /// The per-key attestation bucket runs before the wallet signature is checked. Under a
    /// public key, one caller could empty it for every visitor.
    #[tokio::test]
    async fn the_attestation_bucket_of_a_public_key_cannot_be_emptied_by_one_caller() {
        let router = create_router(state(), &[]);
        let public = statuses(&router, (0..3).map(|_| attest(PUBLIC_KEY))).await;
        assert!(
            public
                .iter()
                .all(|status| *status == StatusCode::BAD_REQUEST),
            "each request reached the handler, which has no attestor here: {public:?}"
        );
        assert_eq!(
            statuses(&router, (0..2).map(|_| attest(SERVER_KEY))).await,
            [StatusCode::BAD_REQUEST, StatusCode::TOO_MANY_REQUESTS]
        );
    }

    fn study(key: &str) -> HttpRequest<Body> {
        HttpRequest::post("/study/definition")
            .header("x-api-key", key)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request builds")
    }

    #[tokio::test]
    async fn the_study_routes_are_absent_until_enabled_and_refuse_a_public_key() {
        let closed = create_router(state(), &[]);
        assert_eq!(
            statuses(&closed, [study(SERVER_KEY), study(PUBLIC_KEY)]).await,
            [StatusCode::NOT_FOUND, StatusCode::NOT_FOUND]
        );

        let mut open = state();
        open.study_routes_enabled = true;
        // No validator is configured, so a request that reaches the handler answers 502.
        let open = create_router(open, &[]);
        assert_eq!(
            statuses(&open, [study(SERVER_KEY), study(PUBLIC_KEY)]).await,
            [StatusCode::BAD_GATEWAY, StatusCode::FORBIDDEN]
        );
    }

    #[tokio::test]
    async fn the_relay_route_is_gone() {
        let router = create_router(state(), &[]);
        let request = HttpRequest::post("/verify")
            .header("x-api-key", SERVER_KEY)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request builds");
        assert_eq!(statuses(&router, [request]).await, [StatusCode::NOT_FOUND]);
    }

    #[tokio::test]
    async fn the_authorization_route_exists_with_paired_sessions_only() {
        let request = || {
            let mut request = HttpRequest::get(format!(
                "/paired/authorization?wallet={}",
                random_wallet_id()
            ))
            .header("x-api-key", SERVER_KEY)
            .body(Body::empty())
            .expect("request builds");
            request.extensions_mut().insert(ConnectInfo(
                "198.51.100.9:4000".parse::<SocketAddr>().expect("address"),
            ));
            request
        };
        let off = create_router(state(), &[]);
        assert_eq!(statuses(&off, [request()]).await, [StatusCode::NOT_FOUND]);

        let mut paired = state();
        paired.paired_enabled = true;
        paired.rate_limiter = Arc::new(RateLimiter::new(100));
        let on = create_router(paired, &[]);
        assert_eq!(statuses(&on, [request()]).await, [StatusCode::OK]);
        let missing_wallet = HttpRequest::get("/paired/authorization")
            .header("x-api-key", SERVER_KEY)
            .body(Body::empty())
            .expect("request builds");
        assert_eq!(
            statuses(&on, [missing_wallet]).await,
            [StatusCode::BAD_REQUEST]
        );
    }
}
