//! Timing oracle closure for handler responses.
//!
//! Without this, an attacker probing `/verify` and `/validate-features` can
//! distinguish outcome classes by latency: rate-limit and quota rejections
//! return in <10ms, validator-rejections take 5-8s (Whisper-tiny dominates),
//! and validator-passes take 5-8s + on-chain submission. Clamping every
//! request on these endpoints to a fixed minimum duration means an outside
//! observer can no longer tell from timing alone whether the handler ever
//! reached the validator.
//!
//! 4 seconds is the 25th percentile of validator pass time — short enough
//! that legitimate users on the validator path don't see extra latency,
//! long enough that early-return paths blend with validator outcomes.

use std::future::Future;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::time::Instant;

use crate::error::AppError;
use crate::server::MAX_REQUEST_BODY_BYTES;

/// Lower bound on response time for endpoints that talk to the validator.
/// Calibrated to match `validate-features` 25th-percentile latency on a
/// warmed validator with Whisper-tiny.en.
pub const HANDLER_MIN_DURATION: Duration = Duration::from_secs(4);

/// Run `fut` to completion and ensure the total elapsed time is at least
/// `min`. If the future finishes faster, sleep the remainder before
/// returning. Generic over the future's output and exposed as a unit
/// rather than buried in middleware so it can be unit-tested at short
/// durations without requiring real 4-second test runs.
///
/// Measures on `tokio::time::Instant` rather than `std::time::Instant` so
/// `tokio::time::pause()` moves the clock and the sleep together. That is
/// what lets the middleware test below assert against the real 4-second
/// clamp in virtual time. Outside a paused runtime the two are the same
/// clock, so production behaviour is unchanged.
pub async fn min_duration<F, T>(min: Duration, fut: F) -> T
where
    F: Future<Output = T>,
{
    let start = Instant::now();
    let result = fut.await;
    let elapsed = start.elapsed();
    if elapsed < min {
        tokio::time::sleep(min - elapsed).await;
    }
    result
}

/// Axum middleware that ensures a request takes at least `HANDLER_MIN_DURATION`
/// **measured from the moment the request body finished arriving**. If the
/// wrapped pipeline (rate limit, handler) completes faster, sleep the remainder
/// before returning. Apply only to endpoints whose timing distinguishes outcome
/// classes. `/health`, `/status`, `/metrics`, `/challenge`, and `/attest`
/// deliberately don't go through here.
///
/// Draining the body first is the whole correctness argument. The body is
/// consumed downstream by the handler's `Json` extractor, so a clock started on
/// entry counts upload time inside the budget. An attacker who uploads slowly
/// on purpose spends the entire 4 seconds getting their bytes in, the clamp
/// then has nothing left to pad, and the latency difference between a
/// sub-10ms rate-limit rejection and a 5-8s validator round trip is legible
/// again. That is a control the attacker can switch off at will, which is no
/// control at all. Draining here moves the start line past anything they can
/// stretch.
///
/// For a request that reaches the handler this costs no extra memory: the
/// `Json` extractor buffers the same bytes moments later, and rebuilding the
/// request from them means it reads from memory instead of the socket.
///
/// For a request the per-key rate limiter rejects, it does cost. That limiter
/// sits inside this middleware, so its rejections now arrive after the body
/// has been buffered where they used to short-circuit before anything read
/// it. That ordering is forced: hoisting the limiter outside the clamp would
/// let its sub-10ms rejection return unpadded, which is the exact leak the
/// clamp exists to close. The cost is bounded rather than eliminated:
/// `RequestBodyLimitLayer` caps each body at `MAX_REQUEST_BODY_BYTES`, and
/// the per-IP limiter runs outside this stack, so the transient ceiling is
/// that limiter's per-minute allowance times the body cap, freed on response.
///
/// A tighter arrangement exists: drain in a separate middleware inside the
/// rate limiter, stamp the completion time into the response extensions, and
/// have this one measure from that stamp when present. It buys back the
/// rejected-request allocation at the price of a second middleware and a
/// cross-middleware handshake that a later edit can silently break. Not worth
/// it for an allocation this size, but it is the move if the body cap ever
/// grows.
///
/// The size cap here is a backstop. `RequestBodyLimitLayer` sits outside the
/// whole stack and rejects on `Content-Length` before a byte is read, so a
/// body reaching this point has already been bounded once.
pub async fn min_duration_middleware(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();

    let bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        // Classify rather than collapse. Three different conditions surface
        // here as one error type, and they do not mean the same thing to a
        // client: an oversized body is a permanent input error, while a body
        // that stopped arriving is a network condition worth retrying.
        // Reporting the second as the first told a mobile client on a flaky
        // uplink that its data was too large, and it lost the capture.
        //
        // Neither is clamped. Both are self-evident to the sender from the
        // status code, and neither reached the validator, so the timing
        // oracle has nothing to hide here.
        Err(err) => return classify_body_error(err).into_response(),
    };

    let request = Request::from_parts(parts, Body::from(bytes));
    min_duration(HANDLER_MIN_DURATION, async move { next.run(request).await }).await
}

/// Map a body-read failure onto the error that describes it.
///
/// `axum::body::to_bytes` erases the cause behind `axum::Error`, so the
/// concrete type has to be recovered from the boxed source. `LengthLimitError`
/// comes from the limit wrapper, `TimeoutError` from
/// `RequestBodyTimeoutLayer`. Anything else is a transport fault mid-upload,
/// which is far closer to a stall than to an oversized payload, so it takes
/// the retryable branch.
fn classify_body_error(err: axum::Error) -> AppError {
    let source: Box<dyn std::error::Error + Send + Sync> = err.into_inner();
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = Some(source.as_ref());
    while let Some(cause) = cursor {
        if cause.is::<http_body_util::LengthLimitError>() {
            return AppError::PayloadTooLarge;
        }
        if cause.is::<tower_http::timeout::TimeoutError>() {
            return AppError::RequestBodyTimeout;
        }
        cursor = cause.source();
    }
    AppError::RequestBodyTimeout
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    /// A body whose only frame arrives after `delay`, standing in for a
    /// client on a slow uplink (or one stalling deliberately).
    fn slow_body(payload: &'static [u8], delay: Duration) -> Body {
        Body::from_stream(futures_util::stream::once(async move {
            tokio::time::sleep(delay).await;
            Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(payload))
        }))
    }

    fn echo_router() -> Router {
        Router::new()
            .route("/t", post(|body: String| async move { body }))
            .route_layer(axum::middleware::from_fn(min_duration_middleware))
    }

    /// The security claim of this module: a slow upload cannot eat the
    /// clamp. Fails against a clock started on middleware entry, which
    /// would return in `max(UPLOAD, HANDLER_MIN_DURATION)` = 4s.
    #[tokio::test(start_paused = true)]
    async fn the_clamp_measures_from_after_the_body_arrives() {
        const UPLOAD: Duration = Duration::from_secs(3);

        let request = Request::builder()
            .method("POST")
            .uri("/t")
            .body(slow_body(b"payload", UPLOAD))
            .expect("request builds");

        let started = Instant::now();
        let response = echo_router().oneshot(request).await.expect("response");
        let elapsed = started.elapsed();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            elapsed >= UPLOAD + HANDLER_MIN_DURATION,
            "clamp started before the body finished: {elapsed:?} < {:?}",
            UPLOAD + HANDLER_MIN_DURATION
        );
    }

    /// Draining and rebuilding the request must leave the handler reading
    /// exactly what the client sent.
    #[tokio::test(start_paused = true)]
    async fn the_rebuilt_request_still_carries_its_body() {
        let request = Request::builder()
            .method("POST")
            .uri("/t")
            .body(Body::from("round trips intact"))
            .expect("request builds");

        let response = echo_router().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64_000)
            .await
            .expect("body bytes");
        assert_eq!(&body[..], b"round trips intact");
    }

    /// A body that stops arriving must not be reported as an oversized one.
    /// Both surface from `to_bytes` as the same error type, and collapsing
    /// them told a client on a flaky uplink that its data was too large,
    /// which is permanent where the truth was retryable.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_body_is_a_timeout_not_an_oversized_payload() {
        use futures_util::StreamExt;

        let app = Router::new()
            .route("/t", post(|body: String| async move { body }))
            .route_layer(axum::middleware::from_fn(min_duration_middleware))
            .layer(tower_http::timeout::RequestBodyTimeoutLayer::new(
                Duration::from_secs(5),
            ));

        // One frame, then silence for as long as anyone cares to wait.
        let stream = futures_util::stream::once(async {
            Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(b"partial"))
        })
        .chain(futures_util::stream::pending());

        let request = Request::builder()
            .method("POST")
            .uri("/t")
            .body(Body::from_stream(stream))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_TIMEOUT,
            "a stalled body must not be reported as PAYLOAD_TOO_LARGE"
        );
    }

    /// The in-stack backstop, for anything that reaches here without having
    /// passed `RequestBodyLimitLayer` first.
    #[tokio::test]
    async fn an_oversized_body_is_refused_before_the_handler() {
        let request = Request::builder()
            .method("POST")
            .uri("/t")
            .body(Body::from(vec![b'x'; MAX_REQUEST_BODY_BYTES + 1]))
            .expect("request builds");

        let response = echo_router().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn pads_fast_future_to_minimum() {
        let start = Instant::now();
        let result: u32 = min_duration(Duration::from_millis(150), async { 42 }).await;
        let elapsed = start.elapsed();
        assert_eq!(result, 42);
        assert!(elapsed >= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn does_not_extend_slow_future() {
        let start = Instant::now();
        let result: u32 = min_duration(Duration::from_millis(50), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            7
        })
        .await;
        let elapsed = start.elapsed();
        assert_eq!(result, 7);
        assert!(elapsed >= Duration::from_millis(200));
        // Headroom for tokio's scheduler so this doesn't flake on slow CI.
        assert!(elapsed < Duration::from_millis(400));
    }

    #[tokio::test]
    async fn propagates_future_output_unchanged() {
        let result: Result<&str, &str> =
            min_duration(Duration::from_millis(10), async { Err("bad") }).await;
        assert_eq!(result, Err("bad"));
    }
}
