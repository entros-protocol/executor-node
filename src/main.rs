mod attestation;
mod auth;
mod challenge;
mod config;
mod error;
mod integrator;
mod listener;
mod padding;
mod relayer;
mod server;
mod solana;
mod status;
mod timing;
mod validation;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use attestation::sas::SasAttestor;
use challenge::registry::ChallengeNonceRegistry;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use zeroize::Zeroize;
use config::Config;
use integrator::tracker::IntegratorTracker;
use integrator::wallet_attempts::WalletAttemptTracker;
use listener::event_monitor::EventMonitor;
use relayer::commitment_registry::CommitmentRegistry;
use relayer::transaction::RelayerTransaction;
use server::{create_router, AppState};
use solana::client::SolanaClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "dev".into());

    // Capture relayer keypair bytes BEFORE moving the keypair into SolanaClient.
    // The bytes are only needed for the dev-mode SAS authority fallback below
    // and are zeroized immediately afterward to minimize the in-memory window
    // for the security-critical relayer secret. `mut` lets us call `.zeroize()`.
    let mut relayer_keypair_bytes = config.relayer_keypair.to_bytes();
    let solana_client = Arc::new(SolanaClient::new(&config.rpc_url, config.relayer_keypair));

    let balance = solana_client.get_balance().await?;
    tracing::info!(
        balance_sol = balance as f64 / 1_000_000_000.0,
        relayer = %solana_client.relayer_pubkey(),
        "Relayer initialized"
    );

    let relayer_tx = Arc::new(RelayerTransaction::new(Arc::clone(&solana_client)));

    // Initialize per-API-key rate limiters
    let rate_limiter = Arc::new(auth::rate_limit::RateLimiter::new(
        config.rate_limit_per_minute,
    ));
    let attest_rate_limiter = Arc::new(auth::rate_limit::RateLimiter::new(10));
    let per_ip_rate_limiter = Arc::new(auth::rate_limit::PerIpRateLimiter::new(
        config.per_ip_rate_limit_per_minute,
    ));
    tracing::info!(
        requests_per_minute = config.rate_limit_per_minute,
        attest_per_minute = 10,
        per_ip_per_minute = config.per_ip_rate_limit_per_minute,
        "Rate limiters initialized"
    );

    // Initialize integrator quota tracker. Refuse to start in production
    // unless `INTEGRATORS` is explicitly populated. `API_KEYS` alone is not
    // sufficient: keys without an integrator entry fall through to the
    // tracker's auto-register path with the default free-tier quota
    // (`integrator/tracker.rs::DEFAULT_FREE_QUOTA`), which is dev-mode
    // behaviour and produces unconfigured/implicit keys in production. In
    // prod, every key should have an explicit name + quota declared via
    // `INTEGRATORS`.
    let integrator_count = config.integrators.len();
    if environment == "prod" && integrator_count == 0 {
        return Err(
            "INTEGRATORS must be populated when ENVIRONMENT=prod (prod_mode_requires_integrators). \
             API_KEYS alone is not sufficient — keys would auto-register at the dev-mode free-tier \
             quota. Configure each integrator with explicit name + quota in the INTEGRATORS env var."
                .into(),
        );
    }
    let tracker = Arc::new(IntegratorTracker::new(config.integrators));
    let wallet_attempts = Arc::new(WalletAttemptTracker::new(
        config.wallet_max_attempts,
        std::time::Duration::from_secs(config.wallet_window_secs),
    ));
    tracing::info!(
        max_attempts = config.wallet_max_attempts,
        window_secs = config.wallet_window_secs,
        "Wallet attempt tracker initialized"
    );
    tracing::info!(
        integrators = integrator_count,
        "Integrator tracker initialized (in-memory, resets on restart)"
    );

    let commitment_registry = Arc::new(CommitmentRegistry::new());
    tracing::info!("Commitment registry initialized (in-memory, resets on restart)");

    let challenge_registry = Arc::new(ChallengeNonceRegistry::new());
    tracing::info!(
        ttl_secs = config.challenge_ttl_secs,
        "Challenge nonce registry initialized"
    );

    let http_client = Arc::new(reqwest::Client::new());
    // Pin VALIDATION_SERVICE_URL with a deploy-time Ed25519 signature so an
    // attacker with environment-variable access cannot repoint validation
    // traffic to a malicious validator. In prod, both URL and signature are
    // required; the signature must verify against the hardcoded protocol
    // authority pubkey. In dev, the signature is advisory — verified if
    // present, skipped otherwise so local development isn't blocked on the
    // signing tool. Use `scripts/sign-validator-url.ts` to produce signatures.
    if let Some(url) = &config.validation_service_url {
        match (environment.as_str(), &config.validation_service_url_signature) {
            ("prod", None) => {
                return Err(
                    "VALIDATION_SERVICE_URL_SIGNATURE is required when ENVIRONMENT=prod \
                     (refusing to launch with an unsigned validator URL — sign with \
                     scripts/sign-validator-url.ts)"
                        .into(),
                );
            }
            (_, Some(sig)) => {
                config::verify_validation_url_signature(url, sig)?;
                tracing::info!(url = %url, "Validation service configured (URL signature verified)");
            }
            (_, None) => {
                tracing::info!(url = %url, "Validation service configured (dev mode, no URL signature)");
            }
        }
    } else {
        tracing::info!("Validation service not configured (VALIDATION_SERVICE_URL not set)");
    }

    // Initialize SAS attestor if configured. SAS authority keypair selection:
    //   1. Dedicated SAS_AUTHORITY_KEYPAIR is preferred (separation of concerns
    //      between relayer + attestor signers).
    //   2. Dev-mode fallback: clone the relayer keypair as the SAS authority.
    //      Refused in production to enforce a clean key-separation invariant.
    let sas_attestor = match (&config.sas_credential_pda, &config.sas_schema_pda) {
        (Some(cred), Some(schema)) => {
            let authority = match config.sas_authority_keypair {
                Some(k) => k,
                None => {
                    if environment == "prod" {
                        return Err(
                            "SAS_AUTHORITY_KEYPAIR is required when ENVIRONMENT=prod \
                             (refusing to use relayer keypair as SAS authority in production)"
                                .into(),
                        );
                    }
                    tracing::warn!(
                        environment,
                        "SAS authority keypair not set, falling back to relayer keypair (non-prod)"
                    );
                    Keypair::try_from(relayer_keypair_bytes.as_slice())
                        .map_err(|_| "Relayer keypair bytes failed to parse for SAS fallback")?
                }
            };
            tracing::info!(
                credential = %cred,
                schema = %schema,
                authority = %authority.pubkey(),
                ttl_days = config.sas_attestation_ttl_days,
                "SAS attestor initialized"
            );
            Some(Arc::new(SasAttestor::new(
                *cred,
                *schema,
                config.sas_attestation_ttl_days,
                Arc::clone(&solana_client),
                authority,
            )))
        }
        _ => {
            tracing::info!("SAS attestation disabled (SAS_CREDENTIAL_PDA or SAS_SCHEMA_PDA not set)");
            None
        }
    };

    // Relayer keypair bytes are no longer needed in this scope; zeroize the
    // local copy. The Keypair owned by SolanaClient remains intact.
    relayer_keypair_bytes.zeroize();

    // Spawn background eviction task for stale commitment entries
    let registry_ref = Arc::clone(&commitment_registry);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            registry_ref.evict_stale();
        }
    });

    // Spawn background eviction tasks for stale rate-limiter entries.
    // Previously, eviction ran inside RateLimiter::check() on every request,
    // creating contention under load. Moving to a 60-second background sweep
    // matches the WalletAttemptTracker / commitment registry pattern.
    for (name, limiter_ref) in [
        ("rate_limiter", Arc::clone(&rate_limiter)),
        ("attest_rate_limiter", Arc::clone(&attest_rate_limiter)),
    ] {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let evicted = limiter_ref.evict_stale();
                if evicted > 0 {
                    tracing::debug!(limiter = name, evicted, "Evicted stale rate-limit entries");
                }
            }
        });
    }

    // Per-IP rate-limiter eviction. Same 60s sweep cadence; the limiter
    // type differs (DashMap keyed on IpAddr) so it doesn't share the loop
    // above without a generic wrapper, which isn't worth the extra
    // indirection for two limiters.
    let per_ip_ref = Arc::clone(&per_ip_rate_limiter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let evicted = per_ip_ref.evict_stale();
            if evicted > 0 {
                tracing::debug!(
                    limiter = "per_ip_rate_limiter",
                    evicted,
                    "Evicted stale rate-limit entries"
                );
            }
        }
    });

    // Spawn background eviction task for stale challenge nonces
    let challenge_ref = Arc::clone(&challenge_registry);
    let challenge_ttl = config.challenge_ttl_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            challenge_ref.evict_stale(challenge_ttl);
        }
    });

    // Spawn background eviction task for stale wallet-attempt entries.
    // Bounds memory growth from many distinct wallets over time —
    // entries with an expired window AND zero in-flight attempts are
    // dropped (next attempt re-creates them from fresh state, identical
    // to the window-reset branch in check_and_record_attempt).
    let wallet_attempts_ref = Arc::clone(&wallet_attempts);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let evicted = wallet_attempts_ref.evict_expired();
            if evicted > 0 {
                tracing::debug!(evicted, "Evicted stale wallet-attempt entries");
            }
        }
    });

    let state = AppState {
        relayer_tx,
        api_keys: Arc::new(config.api_keys),
        rate_limiter,
        attest_rate_limiter,
        per_ip_rate_limiter,
        tracker,
        wallet_attempts,
        commitment_registry,
        sas_attestor,
        metrics: Arc::new(status::status_metrics::StatusMetrics::new()),
        http_client,
        validation_url: config.validation_service_url,
        validation_api_key: config.validation_api_key,
        challenge_registry,
        challenge_ttl_secs: config.challenge_ttl_secs,
    };

    let app = create_router(state, &config.cors_origins);

    // Spawn RPC event listener in background
    let verifier_program_id = solana::pda::verifier_program_id();
    let ws_url = config.ws_url;
    tokio::spawn(async move {
        let monitor = EventMonitor::new(&ws_url, verifier_program_id);
        monitor.start().await;
    });

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "Executor node started");

    // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
    // peer socket address to middleware via `ConnectInfo` extension —
    // required by the per-IP rate-limiter fallback path when no
    // `X-Forwarded-For` header is present (local dev, direct curl).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
