use std::time::Duration;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::transaction::Transaction;
use solana_transaction_status::UiTransactionEncoding;

use crate::error::AppError;

const MAX_RETRIES: usize = 3;
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Cap on the signature-history window for observe-only reputation reads
/// (#196, D1). 100 is plenty to distinguish a fresh wallet (≈0 signatures) from
/// one with real history, while keeping the RPC response small — avoiding the
/// ~1000-entry default for active wallets on a per-verification path.
const RECENT_SIGNATURE_WINDOW: usize = 100;

/// Recent on-chain activity summary for a wallet (#196, D1).
#[derive(Debug, Clone, Default)]
pub struct RecentActivity {
    /// Signatures seen in the query window (saturates at `RECENT_SIGNATURE_WINDOW`).
    /// Near-zero for a fresh wallet — the coarse signal a risk prior needs.
    pub signature_count: usize,
    /// Block time of the oldest signature in the window that carries one — an
    /// approximate account-age anchor (exact for wallets below the window).
    pub oldest_block_time: Option<i64>,
}

pub struct SolanaClient {
    rpc: RpcClient,
    relayer_keypair: Keypair,
}

impl SolanaClient {
    pub fn new(rpc_url: &str, keypair: Keypair) -> Self {
        let rpc =
            RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
        Self {
            rpc,
            relayer_keypair: keypair,
        }
    }

    pub fn relayer_pubkey(&self) -> Pubkey {
        self.relayer_keypair.pubkey()
    }

    pub async fn get_balance(&self) -> Result<u64, AppError> {
        self.rpc
            .get_balance(&self.relayer_keypair.pubkey())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "get_balance RPC call failed");
                AppError::SolanaRpcUnavailable
            })
    }

    pub async fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, AppError> {
        match self.rpc.get_account(pubkey).await {
            Ok(account) => Ok(Some(account.data)),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("AccountNotFound") || err_str.contains("could not find account")
                {
                    Ok(None)
                } else {
                    tracing::error!(
                        error = %err_str,
                        pubkey = %pubkey,
                        "get_account_data RPC call failed"
                    );
                    Err(AppError::SolanaRpcUnavailable)
                }
            }
        }
    }

    /// Native SOL balance (lamports) of an arbitrary wallet. Used by the
    /// observe-only wallet-reputation read (#196, D1) — public on-chain data,
    /// never a gate. Failures log at `debug` (not `error` like the decision-path
    /// reads): a miss on this non-blocking calibration read is non-actionable.
    pub async fn get_balance_of(&self, pubkey: &Pubkey) -> Result<u64, AppError> {
        self.rpc.get_balance(pubkey).await.map_err(|e| {
            tracing::debug!(error = %e, pubkey = %pubkey, "get_balance_of RPC call failed");
            AppError::SolanaRpcUnavailable
        })
    }

    /// Recent on-chain activity for an arbitrary wallet (#196, D1, observe-only):
    /// signature count + the oldest block time in a bounded window. The window
    /// is capped at `RECENT_SIGNATURE_WINDOW` and read at the client's commitment
    /// (matching `get_balance_of`) so the snapshot is internally consistent.
    pub async fn get_recent_activity(&self, pubkey: &Pubkey) -> Result<RecentActivity, AppError> {
        let config = GetConfirmedSignaturesForAddress2Config {
            limit: Some(RECENT_SIGNATURE_WINDOW),
            commitment: Some(self.rpc.commitment()),
            ..Default::default()
        };
        match self
            .rpc
            .get_signatures_for_address_with_config(pubkey, config)
            .await
        {
            Ok(sigs) => {
                // Signatures come newest-first; the last entry carrying a block
                // time is the oldest in the window.
                let oldest_block_time = sigs.iter().rev().find_map(|s| s.block_time);
                Ok(RecentActivity {
                    signature_count: sigs.len(),
                    oldest_block_time,
                })
            }
            Err(e) => {
                tracing::debug!(error = %e, pubkey = %pubkey, "get_recent_activity RPC call failed");
                Err(AppError::SolanaRpcUnavailable)
            }
        }
    }

    /// Send a transaction with the given instructions, signed by the relayer keypair.
    /// Retries up to MAX_RETRIES times with exponential backoff on transient failures.
    /// Fetches a fresh blockhash on each retry.
    pub async fn send_verification_tx(
        &self,
        instructions: Vec<Instruction>,
    ) -> Result<Signature, AppError> {
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..MAX_RETRIES {
            let mut all_instructions =
                vec![ComputeBudgetInstruction::set_compute_unit_limit(400_000)];
            all_instructions.extend(instructions.clone());

            let recent_blockhash = match self.rpc.get_latest_blockhash().await {
                Ok(bh) => bh,
                Err(e) => {
                    let last_error = e.to_string();
                    if attempt < MAX_RETRIES - 1 {
                        tracing::warn!(
                            attempt,
                            error = %last_error,
                            "Blockhash fetch failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                    tracing::error!(
                        error = %last_error,
                        attempts = attempt + 1,
                        "Blockhash fetch failed after retries (send_verification_tx)"
                    );
                    return Err(AppError::SolanaRpcUnavailable);
                }
            };

            let tx = Transaction::new_signed_with_payer(
                &all_instructions,
                Some(&self.relayer_keypair.pubkey()),
                &[&self.relayer_keypair],
                recent_blockhash,
            );

            match self.rpc.send_and_confirm_transaction(&tx).await {
                Ok(sig) => return Ok(sig),
                Err(e) => {
                    let last_error = e.to_string();
                    if attempt < MAX_RETRIES - 1 {
                        tracing::warn!(
                            attempt,
                            error = %last_error,
                            "Transaction failed, retrying with fresh blockhash"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                    tracing::error!(
                        error = %last_error,
                        attempts = attempt + 1,
                        "Transaction send failed after retries (send_verification_tx)"
                    );
                    return Err(AppError::TransactionSubmissionFailed);
                }
            }
        }

        // Unreachable in practice: the loop above returns Ok or Err on every iteration.
        // Kept as a defensive fallback so the function signature stays total.
        Err(AppError::TransactionSubmissionFailed)
    }

    /// Send a transaction signed by both the relayer (payer) and a separate authority.
    /// If authority == relayer, uses a single signer to avoid duplicate signer errors.
    pub async fn send_attestation_tx(
        &self,
        instructions: Vec<Instruction>,
        authority: &Keypair,
    ) -> Result<Signature, AppError> {
        let mut backoff = INITIAL_BACKOFF;

        let same_signer = authority.pubkey() == self.relayer_keypair.pubkey();

        for attempt in 0..MAX_RETRIES {
            let mut all_instructions =
                vec![ComputeBudgetInstruction::set_compute_unit_limit(400_000)];
            all_instructions.extend(instructions.clone());

            let recent_blockhash = match self.rpc.get_latest_blockhash().await {
                Ok(bh) => bh,
                Err(e) => {
                    let last_error = e.to_string();
                    if attempt < MAX_RETRIES - 1 {
                        tracing::warn!(
                            attempt,
                            error = %last_error,
                            "Blockhash fetch failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                    tracing::error!(
                        error = %last_error,
                        attempts = attempt + 1,
                        "Blockhash fetch failed after retries (send_attestation_tx)"
                    );
                    return Err(AppError::SolanaRpcUnavailable);
                }
            };

            let tx = if same_signer {
                Transaction::new_signed_with_payer(
                    &all_instructions,
                    Some(&self.relayer_keypair.pubkey()),
                    &[&self.relayer_keypair],
                    recent_blockhash,
                )
            } else {
                Transaction::new_signed_with_payer(
                    &all_instructions,
                    Some(&self.relayer_keypair.pubkey()),
                    &[&self.relayer_keypair, authority],
                    recent_blockhash,
                )
            };

            match self.rpc.send_and_confirm_transaction(&tx).await {
                Ok(sig) => return Ok(sig),
                Err(e) => {
                    let last_error = e.to_string();
                    if attempt < MAX_RETRIES - 1 {
                        tracing::warn!(
                            attempt,
                            error = %last_error,
                            "Attestation transaction failed, retrying with fresh blockhash"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                    tracing::error!(
                        error = %last_error,
                        attempts = attempt + 1,
                        "Attestation transaction send failed after retries"
                    );
                    return Err(AppError::TransactionSubmissionFailed);
                }
            }
        }

        // Unreachable in practice: the loop above returns Ok or Err on every iteration.
        // Kept as a defensive fallback so the function signature stays total.
        Err(AppError::TransactionSubmissionFailed)
    }

    /// Trace the funding source (Parent Wallet) of `pubkey`.
    /// Fetches up to 10 signatures of the account, grabs the oldest one, and
    /// decodes the transaction to find the fee payer (which funded the account).
    pub async fn get_funding_parent(&self, pubkey: &Pubkey) -> Result<Option<Pubkey>, AppError> {
        let config = GetConfirmedSignaturesForAddress2Config {
            limit: Some(10),
            commitment: Some(self.rpc.commitment()),
            ..Default::default()
        };

        let sigs = match self
            .rpc
            .get_signatures_for_address_with_config(pubkey, config)
            .await
        {
            Ok(sigs) => sigs,
            Err(e) => {
                tracing::debug!(error = %e, pubkey = %pubkey, "get_funding_parent: signatures read failed");
                return Err(AppError::SolanaRpcUnavailable);
            }
        };

        // If no signatures, the account is fresh or has no history
        let oldest_sig_info = match sigs.last() {
            Some(sig) => sig,
            None => return Ok(None),
        };

        let signature = match oldest_sig_info.signature.parse::<Signature>() {
            Ok(sig) => sig,
            Err(_) => return Ok(None),
        };

        // Fetch transaction details in base64 binary encoding for robust decoding
        let tx = match self
            .rpc
            .get_transaction(&signature, UiTransactionEncoding::Base64)
            .await
        {
            Ok(tx) => tx,
            Err(e) => {
                tracing::debug!(error = %e, signature = %signature, "get_funding_parent: transaction fetch failed");
                return Err(AppError::SolanaRpcUnavailable);
            }
        };

        // Extract fee payer key from the decoded VersionedTransaction
        if let Some(versioned_tx) = tx.transaction.transaction.decode() {
            let account_keys = versioned_tx.message.static_account_keys();
            if let Some(parent) = account_keys.first() {
                if parent != pubkey {
                    return Ok(Some(*parent));
                }
            }
        }

        Ok(None)
    }
}
