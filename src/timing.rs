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
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Lower bound on response time for endpoints that talk to the validator.
/// Calibrated to match `validate-features` 25th-percentile latency on a
/// warmed validator with Whisper-tiny.en.
pub const HANDLER_MIN_DURATION: Duration = Duration::from_secs(4);

/// Run `fut` to completion and ensure the total elapsed time is at least
/// `min`. If the future finishes faster, sleep the remainder before
/// returning. Generic over the future's output and exposed as a unit
/// rather than buried in middleware so it can be unit-tested at short
/// durations without requiring real 4-second test runs.
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

/// Axum middleware that ensures a request takes at least `HANDLER_MIN_DURATION`.
/// If the wrapped pipeline (auth, rate limit, handler) completes faster, sleep
/// the remainder before returning the response. Apply only to endpoints whose
/// timing distinguishes outcome classes — `/health`, `/status`, `/metrics`,
/// `/challenge`, and `/attest` deliberately don't go through here.
pub async fn min_duration_middleware(request: Request, next: Next) -> Response {
    min_duration(HANDLER_MIN_DURATION, async move { next.run(request).await }).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
