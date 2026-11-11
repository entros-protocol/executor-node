use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::challenge::lissajous::LissajousParams;
use crate::error::AppError;
use crate::padding::PaddedJson;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub wallet: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub nonce: Vec<u8>,
    pub expires_in: u64,
    /// Server-issued 5-word phrase the user must speak aloud (drawn from
    /// the curated dictionary at `src/challenge/word_dict.rs`). Bound to the
    /// nonce in `ChallengeNonceRegistry`. Validation resolves the phrase by
    /// nonce and forwards it for word-level content matching.
    pub phrase: String,
    /// Server-issued Lissajous curve parameters for the touch challenge.
    pub curve: LissajousParams,
}

pub async fn challenge_handler(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Query(req): Query<ChallengeRequest>,
) -> Result<PaddedJson<ChallengeResponse>, AppError> {
    let wallet = Pubkey::from_str(&req.wallet)
        .map_err(|_| AppError::InvalidRequest(format!("Invalid wallet address: {}", req.wallet)))?;

    // The challenge belongs to the network that asked for it. This route takes no
    // wallet signature, so a caller elsewhere must not move another client's challenge.
    let (origin, _) = crate::validation::handler::request_origin(
        &headers,
        peer.map(|Extension(connect)| connect.0),
    );
    let (nonce, phrase, curve) = state.challenge_registry.issue(wallet, origin);

    tracing::debug!(
        wallet = %crate::auth::redact::redact_wallet_id(&wallet.to_string()),
        "Challenge nonce, phrase, and curve issued"
    );

    Ok(PaddedJson(ChallengeResponse {
        nonce: nonce.to_vec(),
        expires_in: state.challenge_registry.ttl_secs(),
        phrase,
        curve,
    }))
}
