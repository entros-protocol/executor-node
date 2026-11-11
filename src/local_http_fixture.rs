use super::*;
use std::net::IpAddr;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires an isolated database, validator, RPC fixture and explicit test settings"]
async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    assert!(config.listen_addr.ip().is_loopback());
    for endpoint in [
        &config.rpc_url,
        config
            .validation_service_url
            .as_ref()
            .ok_or("missing validator")?,
    ] {
        let url = reqwest::Url::parse(endpoint)?;
        assert_eq!(url.scheme(), "http");
        assert!(url
            .host_str()
            .ok_or("missing host")?
            .parse::<IpAddr>()?
            .is_loopback());
    }
    assert!(config.environment.is_prod());
    assert_eq!(
        config.scoring_config.source,
        config::ScoringConfigSource::Signed
    );
    assert!(!config.api_keys.is_empty());
    assert!(config.api_keys.iter().all(|key| config
        .integrators
        .iter()
        .any(|integrator| integrator.api_key == *key)));
    assert!(config.validation_api_key.is_some());
    assert!(config.paired_enabled);
    println!(
        "paired authorization: {:?}",
        config.paired_authorization_mode
    );
    // How long the fixture serves before its graceful shutdown. One hour covered
    // the 2026-09-27 campaigns; longer isolated campaigns set the override.
    let ttl_secs: u64 = std::env::var("EXECUTOR_FIXTURE_TTL_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3600);
    println!("fixture ttl: {ttl_secs}s");
    let solana_client = Arc::new(SolanaClient::new(&config.rpc_url, config.relayer_keypair));
    let state = AppState {
        validation_identity_program: config.validation_identity_program,
        solana: solana_client,
        api_keys: Arc::new(config.api_keys),
        public_api_keys: Arc::new(
            config
                .integrators
                .iter()
                .filter(|integrator| integrator.public)
                .map(|integrator| integrator.api_key.clone())
                .collect(),
        ),
        rate_limiter: Arc::new(auth::rate_limit::RateLimiter::new(
            config.rate_limit_per_minute,
        )),
        attest_rate_limiter: Arc::new(auth::rate_limit::RateLimiter::new(10)),
        attest_wallet_rate_limiter: Arc::new(auth::rate_limit::RateLimiter::new(
            ATTESTATIONS_PER_WALLET_PER_MINUTE,
        )),
        study_service_rate_limiter: Arc::new(auth::rate_limit::RateLimiter::new(
            config.study_rate_limit_per_minute,
        )),
        study_concurrency: Arc::new(tokio::sync::Semaphore::new(config.study_max_in_flight)),
        per_ip_rate_limiter: Arc::new(auth::rate_limit::PerIpRateLimiter::new(
            config.per_ip_rate_limit_per_minute,
        )),
        tracker: Arc::new(IntegratorTracker::new(config.integrators)),
        wallet_attempts: Arc::new(WalletAttemptTracker::new(
            config.wallet_max_attempts,
            Duration::from_secs(config.wallet_window_secs),
        )),
        sas_attestor: None,
        metrics: Arc::new(status::status_metrics::StatusMetrics::new()),
        http_client: Arc::new(reqwest::Client::new()),
        validation_url: config.validation_service_url,
        validation_api_key: config.validation_api_key,
        challenge_registry: Arc::new(ChallengeNonceRegistry::new(config.challenge_ttl_secs)),
        challenge_required: true,
        scoring_config: Arc::new(config.scoring_config.config),
        automation_observe: config.automation_observe,
        automation_webdriver_reject: config.automation_webdriver_reject,
        wallet_reputation_observe: config.wallet_reputation_observe,
        curve_trace_observe: config.curve_trace_observe,
        cross_wallet_cooldown: Arc::new(CrossWalletCooldownTracker::new(
            config.cross_wallet_cooldown_secs,
        )),
        cross_wallet_cooldown_enforce: config.cross_wallet_cooldown_enforce,
        probing_blocklist: Arc::new(dashmap::DashMap::new()),
        paired_enabled: config.paired_enabled,
        session_gate: Arc::new(tokio::sync::Semaphore::new(
            config.paired_session_concurrency,
        )),
        session_uploads: crate::paired::uploads::UploadGate::new(
            crate::paired::uploads::SESSION_UPLOADS,
            crate::paired::uploads::SESSION_UPLOADS_PER_NETWORK,
        ),
        paired_authorizer: Arc::new(match config.paired_authorization_key {
            Some(key) => PairedAuthorizer::new(
                &key,
                config.paired_authorization_ttl_secs,
                config.paired_authorization_mode,
                config.paired_authorization_network,
            )?,
            None => PairedAuthorizer::with_random_key(
                config.paired_authorization_ttl_secs,
                config.paired_authorization_mode,
                config.paired_authorization_network,
            )?,
        }),
        single_capture_updates_refused: config.single_capture_updates_refused,
        study_routes_enabled: config.study_routes_enabled,
    };
    let app = create_router(state, &config.cors_origins);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    println!("ISOLATED_HTTP_READY");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::time::sleep(Duration::from_secs(ttl_secs)).await;
    })
    .await?;
    Ok(())
}
