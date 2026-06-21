use std::sync::Arc;

use crate::error::AppError;
use crate::solana::client::SolanaClient;
use crate::solana::instructions;
use crate::solana::pda;

pub struct VerificationOutcome {
    pub signature: String,
    pub is_valid: bool,
}

pub struct RelayerTransaction {
    client: Arc<SolanaClient>,
}

impl RelayerTransaction {
    pub fn new(client: Arc<SolanaClient>) -> Self {
        Self { client }
    }

    /// Shared Solana client handle. Cloned (cheap Arc bump) by the observe-only
    /// wallet-reputation read (#196, D1) so the read can run in a detached task
    /// without borrowing the request path.
    pub fn client(&self) -> Arc<SolanaClient> {
        Arc::clone(&self.client)
    }

    /// Submit a verification: create_challenge + verify_proof in one transaction.
    /// After the verify_proof revert fix, a confirmed transaction guarantees the
    /// proof was valid (invalid proofs revert the entire transaction).
    pub async fn submit_verification(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[[u8; 32]],
    ) -> Result<VerificationOutcome, AppError> {
        let nonce: [u8; 32] = rand::random();

        let relayer = self.client.relayer_pubkey();
        let (challenge_pda, _) = pda::find_challenge_pda(&relayer, &nonce);
        let (verification_pda, _) = pda::find_verification_result_pda(&relayer, &nonce);

        tracing::info!(
            nonce = %bs58::encode(&nonce).into_string(),
            "Generated verification nonce"
        );

        let ix1 = instructions::build_create_challenge(&relayer, &challenge_pda, &nonce);
        let ix2 = instructions::build_verify_proof(
            &relayer,
            &challenge_pda,
            &verification_pda,
            proof_bytes,
            public_inputs,
            &nonce,
        );

        let signature = self.client.send_verification_tx(vec![ix1, ix2]).await?;

        tracing::info!(
            signature = %signature,
            "Verification transaction confirmed — proof valid"
        );

        // Transaction confirmed = proof was valid (invalid proofs revert on-chain)
        Ok(VerificationOutcome {
            signature: signature.to_string(),
            is_valid: true,
        })
    }

    pub async fn get_balance(&self) -> Result<u64, AppError> {
        self.client.get_balance().await
    }
}
