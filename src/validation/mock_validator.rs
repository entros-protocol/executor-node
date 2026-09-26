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
    accounts: Arc<Mutex<std::collections::HashMap<String, Value>>>,
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
    retry_after: Option<&'static str>,
    received: Arc<Mutex<Vec<Value>>>,
    accounts: Arc<Mutex<std::collections::HashMap<String, Value>>>,
}

#[derive(Clone)]
enum MockBody {
    Json(Value),
    Raw(Vec<u8>),
}

impl MockValidator {
    /// Bind a mock validator that answers every `POST /validate` and every paired route with
    /// `status` and `body`, recording each request body it was sent.
    pub async fn spawn(status: StatusCode, body: Value) -> Self {
        Self::spawn_with_body(status, MockBody::Json(body), None).await
    }

    /// Bind a mock validator that also sends `Retry-After: retry_after`.
    pub async fn spawn_retry_after(
        status: StatusCode,
        body: Value,
        retry_after: &'static str,
    ) -> Self {
        Self::spawn_with_body(status, MockBody::Json(body), Some(retry_after)).await
    }

    /// Bind a mock validator that returns bytes which are not valid JSON.
    pub async fn spawn_raw(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self::spawn_with_body(status, MockBody::Raw(body.into()), None).await
    }

    async fn spawn_with_body(
        status: StatusCode,
        body: MockBody,
        retry_after: Option<&'static str>,
    ) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let accounts = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let state = MockState {
            accounts: accounts.clone(),
            status,
            body,
            retry_after,
            received: received.clone(),
        };

        let app = Router::new()
            .route("/validate", post(handle))
            .route("/paired/sessions", post(handle))
            .route("/paired/commit", post(handle))
            .route("/paired/validate", post(handle))
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
            accounts,
        }
    }

    /// Base URL for `AppState::validation_url`.
    ///
    /// Deliberately without a trailing slash: the handler builds its target as
    /// `format!("{validation_url}/validate")`, so a trailing slash would
    /// produce `//validate` and miss the route.
    pub fn set_account(
        &self,
        address: &solana_sdk::pubkey::Pubkey,
        owner: &solana_sdk::pubkey::Pubkey,
        data: &[u8],
        executable: bool,
    ) {
        use base64::Engine;
        self.accounts.lock().expect("mock accounts lock").insert(address.to_string(), serde_json::json!({"lamports":1,"owner":owner.to_string(),"executable":executable,"rentEpoch":0,"data":[base64::engine::general_purpose::STANDARD.encode(data),"base64"]}));
    }

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
    let mut response = match state.body {
        MockBody::Json(body) => (state.status, Json(body)).into_response(),
        MockBody::Raw(body) => (state.status, body).into_response(),
    };
    if let Some(seconds) = state.retry_after {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static(seconds),
        );
    }
    response
}

async fn handle_rpc(State(state): State<MockState>, Json(body): Json<Value>) -> Json<Value> {
    let value = if body.get("method").and_then(Value::as_str) == Some("getMultipleAccounts") {
        let accounts = state.accounts.lock().expect("mock accounts lock");
        Value::Array(
            body["params"][0]
                .as_array()
                .expect("RPC addresses")
                .iter()
                .map(|address| {
                    accounts
                        .get(address.as_str().expect("address string"))
                        .cloned()
                        .unwrap_or(Value::Null)
                })
                .collect(),
        )
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

/// A success body shaped like the validation service's `ValidateResponse` with
/// the given risk components. Optional fields are omitted, not nulled, exactly as
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

/// A rejection body shaped like the validation service's `ErrorResponse`.
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
