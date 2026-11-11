use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;

use crate::error::AppError;
use crate::server::AppState;

const BALANCE_CACHE_TTL_SECONDS: u64 = 30;

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestations_issued: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validations_performed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relayer_balance_lamports: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sas_configured: Option<bool>,
}

pub async fn status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // A public key ships to every client, so it reads only the anonymous status.
    let is_authenticated = headers
        .get("X-API-Key")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|key| {
            crate::auth::api_key::is_valid_api_key(key.as_bytes(), &state.api_keys)
                && !state.public_api_keys.contains(key)
        });

    if !is_authenticated {
        return Ok(Json(StatusResponse {
            status: "ok",
            uptime_seconds: None,
            attestations_issued: None,
            validations_performed: None,
            relayer_balance_lamports: None,
            sas_configured: None,
        }));
    }

    let (cached_balance, fetched_at) = state.metrics.cached_balance();
    let balance = if now.saturating_sub(fetched_at) < BALANCE_CACHE_TTL_SECONDS {
        cached_balance
    } else {
        let balance = state.solana.get_balance().await?;
        state.metrics.update_cached_balance(balance, now);
        balance
    };

    Ok(Json(StatusResponse {
        status: "ok",
        uptime_seconds: Some(now.saturating_sub(state.metrics.start_time())),
        attestations_issued: Some(state.metrics.attestations_issued()),
        validations_performed: Some(state.metrics.validations_performed()),
        relayer_balance_lamports: Some(balance),
        sas_configured: Some(state.sas_attestor.is_some()),
    }))
}

pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{build_test_state, tracker_with_quota};
    use std::collections::HashSet;
    use std::sync::Arc;

    const PUBLIC_KEY: &str = "site-key";
    const SERVER_KEY: &str = "server-key";

    fn state() -> AppState {
        let mut state = build_test_state(tracker_with_quota(SERVER_KEY, 10), None);
        state.api_keys = Arc::new(vec![PUBLIC_KEY.into(), SERVER_KEY.into()]);
        state.public_api_keys = Arc::new(HashSet::from([PUBLIC_KEY.to_owned()]));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        state.metrics.update_cached_balance(5_000, now);
        state
    }

    async fn status_with(key: Option<&str>) -> StatusResponse {
        let mut headers = HeaderMap::new();
        if let Some(key) = key {
            headers.insert("X-API-Key", key.parse().expect("header value"));
        }
        let Json(response) = status_handler(State(state()), headers)
            .await
            .unwrap_or_else(|_| panic!("status answers"));
        response
    }

    /// A public key ships to every client, so it reads only what an anonymous caller reads.
    #[tokio::test]
    async fn a_public_key_reads_the_anonymous_status() {
        for key in [Some(PUBLIC_KEY), None, Some("unknown-key")] {
            let response = status_with(key).await;
            assert_eq!(response.relayer_balance_lamports, None, "{key:?}");
            assert_eq!(response.uptime_seconds, None, "{key:?}");
            assert_eq!(response.sas_configured, None, "{key:?}");
        }
    }

    #[tokio::test]
    async fn a_server_key_reads_the_full_status() {
        let response = status_with(Some(SERVER_KEY)).await;
        assert_eq!(response.relayer_balance_lamports, Some(5_000));
        assert!(response.uptime_seconds.is_some());
    }
}
