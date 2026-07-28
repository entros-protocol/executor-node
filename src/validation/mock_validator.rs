//! In-process mock of the upstream validation service, for handler tests.
//!
//! `validate_features_handler` reaches its decision code only when
//! `AppState::validation_url` is `Some`; with `None` it short-circuits at the
//! dev-skip and roughly 400 lines — the validator round-trip, the composite
//! risk score, and both policy tiers — never execute. Every test in the crate
//! passed `None` until this module existed, so that region had no coverage.
//!
//! Deliberately dependency-free: `axum`, `tokio` and `reqwest` are already
//! regular dependencies, so binding a real loopback listener costs nothing in
//! `Cargo.lock` and mirrors the Router-driving idiom in `server.rs`'s
//! `per_ip_middleware_tests`.
//!
//! The bodies handed to [`MockValidator::spawn`] must mirror what
//! `entros-validation` actually emits (`ValidateResponse` / `ErrorResponse` in
//! its `main.rs`): `200` on success, `400` on rejection, and optional fields
//! *omitted* rather than sent as `null`. That distinction is load-bearing —
//! `#[serde(default)]` on the executor side rescues a missing key but not a
//! `null` one, which fails the whole body parse and silently drops the handler
//! into its fallback arm.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde_json::Value;

/// A running mock validator bound to an ephemeral loopback port.
///
/// The server task is aborted on drop, so a test cannot leak a listener into
/// the rest of the suite.
pub struct MockValidator {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Value>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockValidator {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[derive(Clone)]
struct MockState {
    status: StatusCode,
    body: Value,
    received: Arc<Mutex<Vec<Value>>>,
}

impl MockValidator {
    /// Bind a mock validator that answers every `POST /validate` with
    /// `status` and `body`, recording each request body it was sent.
    pub async fn spawn(status: StatusCode, body: Value) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            status,
            body,
            received: received.clone(),
        };

        let app = Router::new()
            .route("/validate", post(handle))
            .with_state(state);

        // Port 0 lets the OS pick a free port, so parallel tests never collide.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral loopback port must succeed");
        let addr = listener
            .local_addr()
            .expect("a bound listener always has a local address");

        let server = tokio::spawn(async move {
            // Errors here mean the test dropped the mock; nothing to report.
            let _ = axum::serve(listener, app).await;
        });

        Self {
            addr,
            received,
            server,
        }
    }

    /// Base URL for `AppState::validation_url`.
    ///
    /// Deliberately without a trailing slash: the handler builds its target as
    /// `format!("{validation_url}/validate")`, so a trailing slash would
    /// produce `//validate` and miss the route.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Request bodies received so far, in arrival order.
    ///
    /// Asserting this is empty is how a test proves a gate short-circuited
    /// *before* the upstream round-trip rather than merely discarding its
    /// result.
    pub fn received(&self) -> Vec<Value> {
        self.received
            .lock()
            .expect("mock request log is never held across a panic")
            .clone()
    }

    /// Number of upstream requests received.
    pub fn request_count(&self) -> usize {
        self.received().len()
    }
}

async fn handle(
    State(state): State<MockState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state
        .received
        .lock()
        .expect("mock request log is never held across a panic")
        .push(body);
    (state.status, Json(state.body.clone()))
}

/// An `AppState` wired to `mock`, with every nondeterministic input disabled.
///
/// Three hazards are neutralized here rather than left for each test:
///
/// * `wallet_reputation_observe` — `REPUTATION_RPC_GATE` is a *process-wide*
///   semaphore with 8 permits shared by every test in the binary. Once
///   `validation_url` is `Some`, the reputation future goes live in every such
///   test and above 8 concurrent tests `try_acquire` fails nondeterministically,
///   flipping `reputation_risk` between a computed value and its `0.5` default.
///   Disabling it pins that term, and with it the composite.
/// * `relayer_tx` — the identity-PDA read is unconditional and carries no
///   per-call timeout (the `RpcClient` default is 30s). `build_test_state`
///   points at `127.0.0.1:8899`, so a developer running `solana-test-validator`
///   would get real chain data or a long stall. Port 1 is guaranteed closed, so
///   the read fails instantly and `recent_timestamps` stays empty.
/// * `curve_trace_observe` — silences the detached scoring task, which is
///   irrelevant to these assertions.
///
/// With `reputation_risk` pinned at its `0.5` default, every composite in these
/// tests carries a fixed `0.10 * 0.5 = 0.05` floor.
///
/// Bind the [`MockValidator`] to a local first. Passing a temporary drops it at
/// the end of the statement, which aborts the server and leaves the returned
/// state pointing at a closed port.
pub fn state_with_mock_validator(
    tracker: Arc<crate::integrator::tracker::IntegratorTracker>,
    mock: &MockValidator,
) -> crate::server::AppState {
    use solana_sdk::signature::Keypair;

    let mut state = crate::server::build_test_state(tracker, Some(mock.url()));
    state.wallet_reputation_observe = false;
    state.curve_trace_observe = false;
    state.relayer_tx = Arc::new(crate::relayer::transaction::RelayerTransaction::new(
        Arc::new(crate::solana::client::SolanaClient::new(
            "http://127.0.0.1:1",
            Keypair::new(),
        )),
    ));
    state
}

/// The fixed contribution of `reputation_risk` to every composite in these
/// tests: the `0.5` no-snapshot default weighted at `0.10`.
pub const REPUTATION_FLOOR: f64 = 0.05;

/// A success body shaped like `entros-validation`'s `ValidateResponse` with the
/// given risk components. Optional fields are omitted, not nulled, exactly as
/// the real validator's `skip_serializing_if` produces.
pub fn success_body(biometric: f64, tts: f64, temporal: f64) -> Value {
    serde_json::json!({
        "valid": true,
        "biometric_risk": biometric,
        "tts_risk": tts,
        "temporal_risk": temporal,
        "audio_realism_risk": 0.0,
    })
}

/// A rejection body shaped like `entros-validation`'s `ErrorResponse`.
pub fn error_body(reason: &str) -> Value {
    serde_json::json!({
        "error": "Verification failed",
        "reason": reason,
        "biometric_risk": 0.0,
        "tts_risk": 0.0,
        "temporal_risk": 0.0,
        "audio_realism_risk": 0.0,
    })
}
