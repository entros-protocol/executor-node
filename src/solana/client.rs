use std::time::Duration;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::transaction::Transaction;

use crate::error::AppError;

const MAX_RETRIES: usize = 3;
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

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
}
