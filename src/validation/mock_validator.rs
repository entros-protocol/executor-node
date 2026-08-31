//! In-process HTTP mock for validation handler tests.
//!
//! Response bodies must match the private validator contract. Every numeric
//! risk field is required and must contain a finite value from zero to one.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::Value;

/// A running mock validator bound to an ephemeral loopback port.
///
/// The server task is aborted on drop, so a test cannot leak a listener into
/// the rest of the suite.
pub struct MockValidator {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Value>>>,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for MockValidator {
    fn drop(&mut self) {
        if let Some(server) = self.server.as_ref() {
            server.abort();
        }
    }
}

#[derive(Clone)]
struct MockState {
    status: StatusCode,
    body: MockBody,
    received: Arc<Mutex<Vec<Value>>>,
}

#[derive(Clone)]
enum MockBody {
    Json(Value),
    Raw(Vec<u8>),
}

impl MockValidator {
    /// Bind a mock validator that answers every `POST /validate` with
    /// `status` and `body`, recording each request body it was sent.
    pub async fn spawn(status: StatusCode, body: Value) -> Self {
        Self::spawn_with_body(status, MockBody::Json(body)).await
    }

    /// Bind a mock validator that returns bytes which are not valid JSON.
    pub async fn spawn_raw(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self::spawn_with_body(status, MockBody::Raw(body.into())).await
    }

    async fn spawn_with_body(status: StatusCode, body: MockBody) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            status,
            body,
            received: received.clone(),
        };

        let app = Router::new()
            .route("/validate", post(handle))
            .route("/", post(handle_rpc))
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
            server: Some(server),
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

    /// Stop the server and wait until its listener has closed.
    pub async fn shutdown(mut self) -> SocketAddr {
        let addr = self.addr;
        if let Some(server) = self.server.take() {
            server.abort();
            match server.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(error) => panic!("mock validator task failed during shutdown: {error}"),
            }
        }
        addr
    }
}

async fn handle(State(state): State<MockState>, Json(body): Json<Value>) -> Response {
    state
        .received
        .lock()
        .expect("mock request log is never held across a panic")
        .push(body);
    match state.body {
        MockBody::Json(body) => (state.status, Json(body)).into_response(),
        MockBody::Raw(body) => (state.status, body).into_response(),
    }
}

async fn handle_rpc(Json(body): Json<Value>) -> Json<Value> {
    let value = if body.get("method").and_then(Value::as_str) == Some("getMultipleAccounts") {
        serde_json::json!([null])
    } else {
        Value::Null
    };
    Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": body.get("id").cloned().unwrap_or(Value::Null),
        "result": {
            "context": { "slot": 1 },
            "value": value
        }
    }))
}

/// Build deterministic state that routes validation and identity RPC calls to `mock`.
///
/// Bind the [`MockValidator`] before this call. The returned state borrows its
/// address, so dropping the mock closes both test endpoints.
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
            &mock.url(),
            Keypair::new(),
        )),
    ));
    state
}

/// A success body shaped like `entros-validation`'s `ValidateResponse` with the
/// given risk components. Optional fields are omitted, not nulled, exactly as
/// the real validator's `skip_serializing_if` produces.
pub fn success_body(biometric: f64, tts: f64, temporal: f64) -> Value {
    serde_json::json!({
        "valid": true,
        "phrase_validation_status": "validated",
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
