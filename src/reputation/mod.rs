//! Observe-only wallet reputation (master-list #196, Layer D1).
//!
//! Reads a verifying wallet's PUBLIC on-chain history and uses it as a risk
//! PRIOR — the Solana-native analog to a cross-site reputation graph, without
//! any surveillance. A fresh bot-farm wallet has near-zero balance and activity;
//! an established wallet carries costly-to-fabricate history. This is logged for
//! calibration and never gates a verification, never affects quota, and stores
//! no per-user profile (the data is public chain state, read on demand).

use solana_sdk::pubkey::Pubkey;
use tokio::sync::Semaphore;

use crate::error::AppError;
use crate::solana::client::SolanaClient;

/// Caps concurrent observe-only reputation RPC reads process-wide. They share
/// the relayer's single `RpcClient`, so an unbounded burst could throttle the
/// RPC provider and starve consensus-critical transaction sends. When the gate
/// is saturated the read is skipped — dropping an observe sample is free;
/// starving the decision path is not.
const MAX_CONCURRENT_REPUTATION_READS: usize = 8;
pub static REPUTATION_RPC_GATE: Semaphore = Semaphore::const_new(MAX_CONCURRENT_REPUTATION_READS);

/// A verifying wallet's public on-chain reputation snapshot.
#[derive(Debug, Clone, Default)]
pub struct WalletReputation {
    /// Native SOL balance, in lamports.
    pub sol_lamports: u64,
    /// Recent signature count in the RPC's default window (capped at ~1000).
    /// Near-zero for a fresh wallet; large for an active one.
    pub signature_count: usize,
    /// Block time of the oldest signature in the window — an approximate
    /// account-age anchor (exact for wallets below the window size).
    pub oldest_block_time: Option<i64>,
}

/// Fetch the reputation snapshot for `wallet`. The balance and activity reads
/// are independent, so they run concurrently to minimize latency. Returns an
/// error if either RPC read fails; callers treat that as "reputation
/// unavailable" and proceed (observe-only — it never blocks verification).
pub async fn fetch_wallet_reputation(
    client: &SolanaClient,
    wallet: &Pubkey,
) -> Result<WalletReputation, AppError> {
    let (balance, activity) = tokio::join!(
        client.get_balance_of(wallet),
        client.get_recent_activity(wallet)
    );
    let activity = activity?;
    Ok(WalletReputation {
        sol_lamports: balance?,
        signature_count: activity.signature_count,
        oldest_block_time: activity.oldest_block_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_reputation_is_empty() {
        let rep = WalletReputation::default();
        assert_eq!(rep.sol_lamports, 0);
        assert_eq!(rep.signature_count, 0);
        assert_eq!(rep.oldest_block_time, None);
    }
}
