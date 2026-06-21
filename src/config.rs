use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Keypair, Signature};
use std::net::SocketAddr;
use std::str::FromStr;

/// Protocol authority pubkey that signs `VALIDATION_SERVICE_URL` for
/// deploy-time pinning. Hardcoded so an attacker with environment-variable
/// access cannot repoint validation traffic — they can change the URL but
/// they cannot produce a signature against it from this keypair.
///
/// Devnet authority. Mainnet would compile a different binary (or guard
/// behind a feature flag) with the production authority pubkey baked in.
const VALIDATION_URL_AUTHORITY_BS58: &str = "GYm3f7DTvTZ6dN1Gfe7UowHRerxTU4FK2u1w6zVGVT3Y";

/// Domain separator for the URL signature message. Prevents a signature
/// from another tool that happens to be signed by the same authority key
/// from being a valid validator-URL signature here.
const VALIDATION_URL_DOMAIN_PREFIX: &str = "Entros-VALIDATOR-URL-V1:";

/// Verify that `signature_bs58` is a valid Ed25519 signature by `authority`
/// over `DOMAIN_PREFIX || url`. Internal helper, exposed for tests so they
/// can sign with an ad-hoc keypair without touching the production
/// authority constant.
fn verify_url_signature_against(
    url: &str,
    signature_bs58: &str,
    authority: &Pubkey,
) -> Result<(), String> {
    let signature_bytes = bs58::decode(signature_bs58)
        .into_vec()
        .map_err(|e| format!("VALIDATION_SERVICE_URL_SIGNATURE is not valid bs58: {e}"))?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| format!("VALIDATION_SERVICE_URL_SIGNATURE has invalid length: {e}"))?;
    let message = format!("{VALIDATION_URL_DOMAIN_PREFIX}{url}");
    if !signature.verify(authority.as_ref(), message.as_bytes()) {
        return Err(format!(
            "VALIDATION_SERVICE_URL_SIGNATURE does not verify against authority {authority} \
             — refusing to start with an unsigned URL"
        ));
    }
    Ok(())
}

/// Verify that `signature_bs58` is a valid Ed25519 signature by
/// `VALIDATION_URL_AUTHORITY_BS58` over `DOMAIN_PREFIX || url`.
pub fn verify_validation_url_signature(url: &str, signature_bs58: &str) -> Result<(), String> {
    let authority = Pubkey::from_str(VALIDATION_URL_AUTHORITY_BS58)
        .map_err(|e| format!("hardcoded validation URL authority is invalid: {e}"))?;
    verify_url_signature_against(url, signature_bs58, &authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::Signer;

    fn sign(authority: &Keypair, url: &str) -> String {
        let message = format!("{VALIDATION_URL_DOMAIN_PREFIX}{url}");
        bs58::encode(authority.sign_message(message.as_bytes()).as_ref()).into_string()
    }

    #[test]
    fn hardcoded_authority_constant_is_well_formed() {
        Pubkey::from_str(VALIDATION_URL_AUTHORITY_BS58)
            .expect("VALIDATION_URL_AUTHORITY_BS58 must parse as a valid Solana pubkey");
    }

    #[test]
    fn accepts_signature_from_authority() {
        let authority = Keypair::new();
        let url = "http://validator.example:8080";
        let sig = sign(&authority, url);
        verify_url_signature_against(url, &sig, &authority.pubkey()).unwrap();
    }

    #[test]
    fn rejects_signature_for_different_url() {
        let authority = Keypair::new();
        let sig = sign(&authority, "http://attacker.example");
        assert!(verify_url_signature_against(
            "http://validator.example",
            &sig,
            &authority.pubkey(),
        )
        .is_err());
    }

    #[test]
    fn rejects_signature_from_wrong_authority() {
        let authority = Keypair::new();
        let other = Keypair::new();
        let url = "http://validator.example";
        let sig = sign(&authority, url);
        assert!(verify_url_signature_against(url, &sig, &other.pubkey()).is_err());
    }

    #[test]
    fn rejects_malformed_bs58() {
        let authority = Keypair::new();
        assert!(
            verify_url_signature_against("http://x", "not-valid-bs58!!!", &authority.pubkey())
                .is_err()
        );
    }

    #[test]
    fn rejects_wrong_length_signature() {
        let authority = Keypair::new();
        let too_short = bs58::encode([0u8; 32]).into_string();
        assert!(verify_url_signature_against("http://x", &too_short, &authority.pubkey()).is_err());
    }

    #[test]
    fn domain_prefix_blocks_signatures_for_other_payloads() {
        // A signature over the URL alone (without DOMAIN_PREFIX) must not
        // verify, even with the right authority — domain separation is the
        // whole point of the prefix.
        let authority = Keypair::new();
        let url = "http://validator.example";
        let bare = bs58::encode(authority.sign_message(url.as_bytes()).as_ref()).into_string();
        assert!(verify_url_signature_against(url, &bare, &authority.pubkey()).is_err());
    }
}

#[derive(Deserialize)]
pub struct IntegratorConfig {
    pub api_key: String,
    pub name: String,
    pub quota: u64,
}

pub struct Config {
    pub rpc_url: String,
    pub ws_url: String,
    pub relayer_keypair: Keypair,
    pub sas_authority_keypair: Option<Keypair>,
    pub listen_addr: SocketAddr,
    pub api_keys: Vec<String>,
    pub rate_limit_per_minute: u32,
    /// Per-IP request cap (master-list #155). Bounds the throughput a
    /// single client IP can sustain across rotated wallets / API keys
    /// before the per-API-key and per-wallet limiters fire. Configurable
    /// via `EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN`. Default 30 — covers
    /// legitimate verification flows + dashboard reads while bounding
    /// damage from a single hostile IP. On Railway, the leftmost
    /// `X-Forwarded-For` entry is trusted as the client IP because the
    /// edge layer rewrites the header on every inbound request.
    pub per_ip_rate_limit_per_minute: u32,
    pub integrators: Vec<IntegratorConfig>,
    pub cors_origins: Vec<String>,
    pub sas_credential_pda: Option<Pubkey>,
    pub sas_schema_pda: Option<Pubkey>,
    pub sas_attestation_ttl_days: u64,
    pub validation_service_url: Option<String>,
    /// Ed25519 signature (bs58-encoded) over `Entros-VALIDATOR-URL-V1:<url>`
    /// signed by the protocol authority. Verified against
    /// `VALIDATION_URL_AUTHORITY_BS58` on startup when `ENVIRONMENT=prod`.
    pub validation_service_url_signature: Option<String>,
    pub validation_api_key: Option<String>,
    pub challenge_ttl_secs: u64,
    /// Per-wallet validation-attempt cap (master-list #94 C4). Soft cap on
    /// the number of attempts a single wallet can make in the configured
    /// window before being rate-limited. Successful attempts refund their
    /// slot; only failures persist against the cap. Configurable via
    /// `VALIDATION_WALLET_MAX_ATTEMPTS`. Default 5 — permissive enough
    /// for legit users with borderline mics / accents to retry, tight
    /// enough to bound per-wallet retry damage.
    pub wallet_max_attempts: u8,
    /// Sliding-window length for `wallet_max_attempts`. Configurable via
    /// `VALIDATION_WALLET_WINDOW_SECS`. Default 3600 (1 hour).
    pub wallet_window_secs: u64,
    /// Observe-only automation-detection logging (master-list #196, Layer A1).
    /// When true, the `/validate-features` handler logs the client-collected
    /// automation signal for calibration — it never affects the verification
    /// decision either way. Configurable via `EXECUTOR_AUTOMATION_OBSERVE`.
    /// Default true (observe-first).
    pub automation_observe: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let rpc_url =
            std::env::var("RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".into());

        let ws_url =
            std::env::var("WS_URL").unwrap_or_else(|_| "wss://api.devnet.solana.com".into());

        let relayer_keypair = if let Ok(json) = std::env::var("RELAYER_KEYPAIR") {
            let bytes: Vec<u8> = serde_json::from_str(&json)
                .map_err(|e| format!("RELAYER_KEYPAIR is not valid JSON: {e}"))?;
            Keypair::try_from(bytes.as_slice())
                .map_err(|e| format!("RELAYER_KEYPAIR contains invalid keypair: {e}"))?
        } else {
            let keypair_path = std::env::var("RELAYER_KEYPAIR_PATH")
                .unwrap_or_else(|_| "./relayer-keypair.json".into());
            read_keypair_file(&keypair_path)
                .map_err(|e| format!("Failed to read keypair from {keypair_path}: {e}"))?
        };

        let listen_addr: SocketAddr = if let Ok(port) = std::env::var("PORT") {
            format!("0.0.0.0:{port}").parse()?
        } else {
            std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3001".into())
                .parse()?
        };

        let api_keys: Vec<String> = match std::env::var("API_KEYS") {
            Ok(s) => serde_json::from_str(&s)
                .map_err(|e| format!("API_KEYS contains invalid JSON: {e}"))?,
            Err(_) => vec![],
        };

        let rate_limit_per_minute: u32 = match std::env::var("RATE_LIMIT_PER_MINUTE") {
            Ok(s) => s
                .parse()
                .map_err(|e| format!("RATE_LIMIT_PER_MINUTE is not a valid u32: {e}"))?,
            Err(_) => 60,
        };

        let per_ip_rate_limit_per_minute: u32 =
            match std::env::var("EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN") {
                Ok(s) => s.parse().map_err(|e| {
                    format!("EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN is not a valid u32: {e}")
                })?,
                Err(_) => 30,
            };

        let integrators: Vec<IntegratorConfig> = match std::env::var("INTEGRATORS") {
            Ok(s) => serde_json::from_str(&s)
                .map_err(|e| format!("INTEGRATORS contains invalid JSON: {e}"))?,
            Err(_) => vec![],
        };

        let api_keys = if api_keys.is_empty() && !integrators.is_empty() {
            integrators.iter().map(|i| i.api_key.clone()).collect()
        } else {
            api_keys
        };

        let cors_origins: Vec<String> = match std::env::var("CORS_ORIGINS") {
            Ok(s) => serde_json::from_str(&s)
                .map_err(|e| format!("CORS_ORIGINS contains invalid JSON: {e}"))?,
            Err(_) => vec![],
        };

        let sas_authority_keypair = if let Ok(json) = std::env::var("SAS_AUTHORITY_KEYPAIR") {
            let bytes: Vec<u8> = serde_json::from_str(&json)
                .map_err(|e| format!("SAS_AUTHORITY_KEYPAIR is not valid JSON: {e}"))?;
            Some(
                Keypair::try_from(bytes.as_slice())
                    .map_err(|e| format!("SAS_AUTHORITY_KEYPAIR contains invalid keypair: {e}"))?,
            )
        } else if let Ok(path) = std::env::var("SAS_AUTHORITY_KEYPAIR_PATH") {
            Some(
                read_keypair_file(&path).map_err(|e| {
                    format!("Failed to read SAS authority keypair from {path}: {e}")
                })?,
            )
        } else {
            None
        };

        let sas_credential_pda = std::env::var("SAS_CREDENTIAL_PDA")
            .ok()
            .and_then(|s| Pubkey::from_str(&s).ok());

        let sas_schema_pda = std::env::var("SAS_SCHEMA_PDA")
            .ok()
            .and_then(|s| Pubkey::from_str(&s).ok());

        let sas_attestation_ttl_days: u64 = std::env::var("SAS_ATTESTATION_TTL_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let validation_service_url = std::env::var("VALIDATION_SERVICE_URL").ok();
        let validation_service_url_signature =
            std::env::var("VALIDATION_SERVICE_URL_SIGNATURE").ok();
        let validation_api_key = std::env::var("VALIDATION_API_KEY").ok();

        let challenge_ttl_secs: u64 = std::env::var("CHALLENGE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        // Default 5 attempts / 1h. Permissive at launch — tightenable
        // via env var once we have real-user failure-rate data.
        let wallet_max_attempts: u8 = std::env::var("VALIDATION_WALLET_MAX_ATTEMPTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let wallet_window_secs: u64 = std::env::var("VALIDATION_WALLET_WINDOW_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);

        // Observe-first: default ON so we collect calibration data as soon as
        // SDKs start sending the signal. Set `EXECUTOR_AUTOMATION_OBSERVE=false`
        // (or `0`/`no`/`off`) to silence the logging. An unrecognized value
        // KEEPS the observe-first default rather than silently disabling the
        // signal on a typo; the resolved value is logged at startup in main.rs.
        let automation_observe: bool = match std::env::var("EXECUTOR_AUTOMATION_OBSERVE") {
            Err(_) => true,
            Ok(s) => match s.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => true,
            },
        };

        Ok(Config {
            rpc_url,
            ws_url,
            relayer_keypair,
            sas_authority_keypair,
            listen_addr,
            api_keys,
            rate_limit_per_minute,
            per_ip_rate_limit_per_minute,
            integrators,
            cors_origins,
            sas_credential_pda,
            sas_schema_pda,
            sas_attestation_ttl_days,
            validation_service_url,
            validation_service_url_signature,
            validation_api_key,
            challenge_ttl_secs,
            wallet_max_attempts,
            wallet_window_secs,
            automation_observe,
        })
    }
}
