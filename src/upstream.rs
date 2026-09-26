//! JSON requests to the validation service for the routes that relay its answer to the client.

use std::time::Duration;

use axum::http::{header::RETRY_AFTER, HeaderValue, StatusCode};
use serde::Serialize;

use crate::server::AppState;

/// The longest wait this service relays to a client.
const MAX_RETRY_AFTER_SECS: u64 = 300;

/// What the validator answered.
pub(crate) struct Reply {
    pub status: StatusCode,
    /// A positive `Retry-After` in seconds, capped.
    pub retry_after: Option<HeaderValue>,
    /// The body, when it was JSON within the bound.
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamFault {
    #[error("no validation service is configured")]
    NotConfigured,
    #[error("validation service unreachable: {0}")]
    Unreachable(#[from] reqwest::Error),
}

/// Posts `body` to the validator at `path` and reads a JSON reply of at most `reply_limit`
/// bytes. An `Ok` means the validator answered, whatever it answered.
pub(crate) async fn post_json<B: Serialize + ?Sized>(
    state: &AppState,
    path: &str,
    body: &B,
    timeout: Duration,
    reply_limit: usize,
) -> Result<Reply, UpstreamFault> {
    let validation_url = state
        .validation_url
        .as_deref()
        .ok_or(UpstreamFault::NotConfigured)?;
    let mut request = state
        .http_client
        .post(format!("{validation_url}{path}"))
        .json(body)
        .timeout(timeout);
    if let Some(key) = &state.validation_api_key {
        request = request.bearer_auth(key);
    }
    let mut response = request.send().await?;
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .cloned()
        .and_then(valid_retry_after);
    Ok(Reply {
        status: response.status(),
        retry_after,
        body: read_bounded_json(&mut response, reply_limit).await,
    })
}

fn valid_retry_after(value: HeaderValue) -> Option<HeaderValue> {
    let seconds = value.to_str().ok()?.parse::<u64>().ok()?;
    if seconds == 0 {
        return None;
    }
    HeaderValue::from_str(&seconds.min(MAX_RETRY_AFTER_SECS).to_string()).ok()
}

/// Reads a JSON body no larger than `limit` bytes. Anything larger, or anything that is not
/// JSON, reads as `None`.
pub(crate) async fn read_bounded_json(
    response: &mut reqwest::Response,
    limit: usize,
) -> Option<serde_json::Value> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len().saturating_add(chunk.len()) > limit {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_positive_and_capped() {
        assert_eq!(
            valid_retry_after(HeaderValue::from_static("18446744073709551615")),
            Some(HeaderValue::from_static("300"))
        );
        assert_eq!(
            valid_retry_after(HeaderValue::from_static("12")),
            Some(HeaderValue::from_static("12"))
        );
        assert_eq!(valid_retry_after(HeaderValue::from_static("0")), None);
        assert_eq!(valid_retry_after(HeaderValue::from_static("soon")), None);
    }
}
