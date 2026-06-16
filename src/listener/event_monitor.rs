use futures_util::StreamExt;
use solana_client::nonblocking::pubsub_client::PubsubClient;
use solana_client::rpc_config::RpcTransactionLogsConfig;
use solana_client::rpc_config::RpcTransactionLogsFilter;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use std::time::Duration;

/// Monitors on-chain verification events via Solana WebSocket subscription.
/// Read-only observability for the devnet pilot.
pub struct EventMonitor {
    ws_url: String,
    verifier_program_id: Pubkey,
}

impl EventMonitor {
    pub fn new(ws_url: &str, verifier_program_id: Pubkey) -> Self {
        Self {
            ws_url: ws_url.to_string(),
            verifier_program_id,
        }
    }

    /// Run the event monitor loop. Reconnects on disconnection with exponential backoff.
    /// This method runs forever and should be spawned in a background tokio task.
    pub async fn start(&self) {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);

        loop {
            tracing::info!(
                program = %self.verifier_program_id,
                url = %self.ws_url,
                "Connecting to Solana WebSocket"
            );

            match self.subscribe().await {
                Ok(()) => {
                    tracing::warn!("WebSocket subscription ended, reconnecting");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        backoff_secs = backoff.as_secs(),
                        "WebSocket connection failed, retrying"
                    );
                }
            }

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    async fn subscribe(&self) -> Result<(), Box<dyn std::error::Error>> {
        let client = PubsubClient::new(&self.ws_url).await?;

        let filter = RpcTransactionLogsFilter::Mentions(vec![self.verifier_program_id.to_string()]);

        let config = RpcTransactionLogsConfig {
            commitment: Some(CommitmentConfig::confirmed()),
        };

        let (mut stream, _unsub) = client.logs_subscribe(filter, config).await?;

        tracing::info!("WebSocket subscription active, listening for verification events");

        while let Some(log_response) = stream.next().await {
            let logs = &log_response.value.logs;
            let signature = &log_response.value.signature;
            let err = &log_response.value.err;

            if err.is_some() {
                tracing::warn!(
                    signature,
                    error = ?err,
                    "Verification transaction failed on-chain"
                );
                continue;
            }

            // Match log entries from the verifier program only
            let program_id_str = self.verifier_program_id.to_string();
            let is_verifier_log = |l: &str| l.contains(&program_id_str);
            let has_challenge = logs
                .iter()
                .any(|l| is_verifier_log(l) && l.contains("ChallengeCreated"));
            let has_verification = logs
                .iter()
                .any(|l| is_verifier_log(l) && l.contains("VerificationComplete"));

            if has_verification {
                tracing::info!(signature, "Verification completed on-chain");
            } else if has_challenge {
                tracing::info!(signature, "Challenge created on-chain");
            }
        }

        Ok(())
    }
}
