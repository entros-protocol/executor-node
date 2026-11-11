//! Proof that the owner of a wallet asked for its paired session.
//!
//! A paired open and a paired finalize both name a wallet. Without proof of control, any caller
//! could open sessions for a wallet it does not hold, or spend that wallet's attempts. The
//! executor issues a challenge, the wallet signs it once, and the client sends that signed
//! authorization with every open and finalize until it expires.
//!
//! The executor stores nothing about what it issued. A keyed MAC over the wallet, the challenge,
//! the expiry and the requester's network shows that this service issued those values, and the
//! wallet signature shows that the wallet's owner accepted them.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::QueryRejection;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header::CACHE_CONTROL, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;

use super::invalid_request;
use crate::auth::signature::decode_signature_hex;
use crate::error::AppError;
use crate::integrator::wallet_attempts::AttemptSubject;
use crate::server::AppState;
use crate::validation::handler::{check_probing_block, request_origin};

type HmacSha256 = Hmac<Sha256>;

const MAC_DOMAIN: &[u8] = b"entros-paired-authorization-v1\0";
const ORIGIN_DOMAIN: &[u8] = b"entros-paired-origin-v1\0";
const MESSAGE_DOMAIN: &str = "Entros-Paired-Open-v1";

pub(crate) const DEFAULT_TTL_SECS: u64 = 900;
/// Clients drop an authorization with under 120 s left, so a shorter lifetime leaves them
/// almost no time to use one.
pub(crate) const MIN_TTL_SECS: u64 = 300;
/// The signed text tells the wallet's owner that the authorization expires within the hour.
pub(crate) const MAX_TTL_SECS: u64 = 3_600;

/// What the wallet's owner reads before signing. It states what the signature allows and
/// what it does not, and it is part of every signed message.
const MESSAGE_PREAMBLE: &str = "Entros verification\n\
     Sign to start verification sessions for this wallet. The authorization expires within \
     the hour. It moves no funds and approves no transaction.";

/// The longest a paired session lives. A session opened just before its authorization expired
/// can still finalize within this.
const FINALIZE_GRACE_SECS: i64 = 600;

/// Whether a paired request must carry an authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationMode {
    /// A request without an authorization is refused.
    Required,
    /// A request without an authorization is served and charged to its client network. A
    /// request that carries one must carry a valid one. For the client rollout alone.
    Optional,
}

impl AuthorizationMode {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("required") => Ok(Self::Required),
            Some("optional") => Ok(Self::Optional),
            Some(other) => Err(format!(
                "EXECUTOR_PAIRED_AUTHORIZATION must be required or optional, got {other:?}"
            )),
        }
    }
}

/// Whether an open must come from the client network that fetched its grant.
///
/// Some honest clients change address between connections, so the rule is observed and
/// counted before it is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    /// An open from another network is refused, and a finalize from another network is
    /// charged to the wallet.
    Enforce,
    /// An open from another network is served and counted. Requests from another network are
    /// charged to the wallet as seen from that network.
    Observe,
}

impl NetworkMode {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("enforce") => Ok(Self::Enforce),
            Some("observe") => Ok(Self::Observe),
            Some(other) => Err(format!(
                "EXECUTOR_PAIRED_AUTHORIZATION_NETWORK must be enforce or observe, got {other:?}"
            )),
        }
    }
}

/// The step a request takes in a paired session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The authorization must be unexpired. The network mode decides an open from another
    /// network.
    Open,
    /// The authorization may be past its expiry by one session lifetime. A finalize from
    /// another network is accepted, so a session survives a change of network.
    Finalize,
}

/// Whether a valid authorization came from the client network that fetched its grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkMatch {
    Same,
    Other,
}

/// Who a paired request is charged to, and whether its valid authorization came from another
/// network than the one that fetched the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Authorized {
    pub(crate) subject: AttemptSubject,
    pub(crate) network_mismatch: bool,
}

/// What the executor issues for a wallet to sign.
#[derive(Debug, Serialize)]
pub struct AuthorizationGrant {
    challenge: String,
    expires_at: i64,
    /// Lifetime in seconds, so a client can time it without its wall clock.
    expires_in: u64,
    origin: String,
    mac: String,
}

/// What a client sends back: the grant's values and the wallet's signature over them.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPayload {
    challenge: String,
    expires_at: i64,
    origin: String,
    mac: String,
    signature_hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationError {
    Required,
    Invalid,
    /// A valid authorization presented at open from another network while the network rule
    /// is enforced. It answers as an invalid one.
    NetworkMismatch,
}

impl From<AuthorizationError> for AppError {
    fn from(error: AuthorizationError) -> Self {
        let reason = match error {
            AuthorizationError::Required => "authorization_required",
            AuthorizationError::Invalid | AuthorizationError::NetworkMismatch => {
                "authorization_invalid"
            }
        };
        AppError::PairedRejected {
            status: StatusCode::UNAUTHORIZED,
            reason: reason.into(),
        }
    }
}

pub struct PairedAuthorizer {
    /// HMAC state under the service key. Each computation works on a clone.
    keyed: HmacSha256,
    ttl_secs: u64,
    mode: AuthorizationMode,
    network: NetworkMode,
}

impl PairedAuthorizer {
    pub fn new(
        key: &[u8; 32],
        ttl_secs: u64,
        mode: AuthorizationMode,
        network: NetworkMode,
    ) -> Result<Self, String> {
        let keyed = HmacSha256::new_from_slice(key)
            .map_err(|_| "the paired authorization key was refused".to_string())?;
        Ok(Self {
            keyed,
            ttl_secs,
            mode,
            network,
        })
    }

    /// A key drawn at start. Every authorization dies with the process, so production sets a
    /// key instead.
    pub fn with_random_key(
        ttl_secs: u64,
        mode: AuthorizationMode,
        network: NetworkMode,
    ) -> Result<Self, String> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::new(&key, ttl_secs, mode, network)
    }

    /// A keyed tag for a client network. It lets a later request be matched to the network that
    /// asked, and it shows no address to whoever holds it.
    fn origin_tag(&self, origin: IpAddr) -> [u8; 16] {
        let mut mac = self.keyed.clone();
        mac.update(ORIGIN_DOMAIN);
        match origin {
            IpAddr::V4(address) => {
                mac.update(&[4]);
                mac.update(&address.octets());
            }
            IpAddr::V6(address) => {
                mac.update(&[6]);
                mac.update(&address.octets());
            }
        }
        let digest = mac.finalize().into_bytes();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&digest[..16]);
        tag
    }

    /// Every field has a fixed width, so the concatenation has one reading.
    fn grant_mac(
        &self,
        wallet: &Pubkey,
        challenge: &[u8; 32],
        expires_at: i64,
        origin_tag: &[u8; 16],
    ) -> HmacSha256 {
        let mut mac = self.keyed.clone();
        mac.update(MAC_DOMAIN);
        mac.update(wallet.as_ref());
        mac.update(challenge);
        mac.update(&expires_at.to_le_bytes());
        mac.update(origin_tag);
        mac
    }

    pub(crate) fn issue(&self, wallet: &Pubkey, origin: IpAddr, now: i64) -> AuthorizationGrant {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        self.issue_for(wallet, origin, now, &challenge)
    }

    fn issue_for(
        &self,
        wallet: &Pubkey,
        origin: IpAddr,
        now: i64,
        challenge: &[u8; 32],
    ) -> AuthorizationGrant {
        let expires_at = now.saturating_add(i64::try_from(self.ttl_secs).unwrap_or(i64::MAX));
        let origin_tag = self.origin_tag(origin);
        let mac = self
            .grant_mac(wallet, challenge, expires_at, &origin_tag)
            .finalize()
            .into_bytes();
        AuthorizationGrant {
            challenge: lower_hex(challenge),
            expires_at,
            expires_in: self.ttl_secs,
            origin: lower_hex(&origin_tag),
            mac: lower_hex(&mac),
        }
    }

    /// Checks that this service issued the authorization for `wallet`, that it is in time for
    /// `step`, and that the wallet signed it. Then reports whether it came from the network
    /// that fetched the grant. The network is compared last, so only an authorization that
    /// passed every other check is ever reported as one from another network. The MAC is
    /// checked before the signature, so a made-up authorization costs one hash and never a
    /// signature check.
    pub(crate) fn verify(
        &self,
        wallet: &Pubkey,
        authorization: &AuthorizationPayload,
        step: Step,
        origin: IpAddr,
        now: i64,
    ) -> Result<NetworkMatch, AuthorizationError> {
        let invalid = AuthorizationError::Invalid;
        let challenge: [u8; 32] = decode_lower_hex(&authorization.challenge).ok_or(invalid)?;
        let origin_tag: [u8; 16] = decode_lower_hex(&authorization.origin).ok_or(invalid)?;
        let mac: [u8; 32] = decode_lower_hex(&authorization.mac).ok_or(invalid)?;
        let signature = decode_signature_hex(&authorization.signature_hex).ok_or(invalid)?;

        // Constant-time comparison inside `verify_slice`.
        self.grant_mac(wallet, &challenge, authorization.expires_at, &origin_tag)
            .verify_slice(&mac)
            .map_err(|_| invalid)?;

        let deadline = match step {
            Step::Open => authorization.expires_at,
            Step::Finalize => authorization.expires_at.saturating_add(FINALIZE_GRACE_SECS),
        };
        if now >= deadline {
            return Err(invalid);
        }

        // The decoder accepted lowercase hex alone, so the text the client sent is the text
        // the wallet signed.
        let message =
            authorization_message(wallet, &authorization.challenge, authorization.expires_at);
        if !Signature::from(signature).verify(wallet.as_ref(), message.as_bytes()) {
            return Err(invalid);
        }

        if self.origin_tag(origin) == origin_tag {
            Ok(NetworkMatch::Same)
        } else {
            Ok(NetworkMatch::Other)
        }
    }

    /// Who a paired request is charged to.
    ///
    /// A valid authorization from the network that fetched its grant proves the wallet, so
    /// the wallet is charged. From another network:
    /// - An open is refused under `enforce` and charged to the wallet as seen from that
    ///   network under `observe`.
    /// - A finalize is charged to the wallet under `enforce`, because only the grant network
    ///   can have opened its session. Under `observe` it is charged to the wallet as seen from
    ///   that network, because an open from any network was served.
    ///
    /// A request without an authorization names a wallet it may not hold, so it is charged to
    /// the wallet as seen from its network, or refused when one is required.
    pub(crate) fn attempt_subject(
        &self,
        wallet: &Pubkey,
        authorization: Option<&AuthorizationPayload>,
        step: Step,
        origin: IpAddr,
    ) -> Result<Authorized, AuthorizationError> {
        let unproven = AttemptSubject::WalletAtOrigin(*wallet, origin);
        match (authorization, self.mode) {
            (Some(authorization), _) => {
                match self.verify(wallet, authorization, step, origin, unix_now())? {
                    NetworkMatch::Same => Ok(Authorized {
                        subject: AttemptSubject::Wallet(*wallet),
                        network_mismatch: false,
                    }),
                    NetworkMatch::Other => match (step, self.network) {
                        (Step::Open, NetworkMode::Enforce) => {
                            Err(AuthorizationError::NetworkMismatch)
                        }
                        (Step::Finalize, NetworkMode::Enforce) => Ok(Authorized {
                            subject: AttemptSubject::Wallet(*wallet),
                            network_mismatch: true,
                        }),
                        (_, NetworkMode::Observe) => Ok(Authorized {
                            subject: unproven,
                            network_mismatch: true,
                        }),
                    },
                }
            }
            (None, AuthorizationMode::Required) => Err(AuthorizationError::Required),
            (None, AuthorizationMode::Optional) => Ok(Authorized {
                subject: unproven,
                network_mismatch: false,
            }),
        }
    }
}

/// The text a wallet signs. Clients build it from the grant's fields and never sign text the
/// server supplies whole.
pub(crate) fn authorization_message(
    wallet: &Pubkey,
    challenge_hex: &str,
    expires_at: i64,
) -> String {
    format!(
        "{MESSAGE_PREAMBLE}\n\n\
         {MESSAGE_DOMAIN}\nwallet:{wallet}\nchallenge:{challenge_hex}\nexpires:{expires_at}"
    )
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Decodes exactly `N` bytes from lowercase hex. One encoding per value, so a field that takes
/// part in a signed message has one text form.
fn decode_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = (lower_nibble(pair[0])? << 4) | lower_nibble(pair[1])?;
    }
    Some(output)
}

fn lower_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizationQuery {
    wallet: String,
}

/// `GET /paired/authorization?wallet=`: issues the values a wallet signs to open paired
/// sessions. Issuing proves nothing and stores nothing, so it needs no wallet signature.
pub async fn authorization_handler(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    query: Result<Query<AuthorizationQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(query) = query.map_err(|_| invalid_request())?;
    let wallet = Pubkey::from_str(&query.wallet).map_err(|_| invalid_request())?;
    let (origin, _) = request_origin(&headers, peer.map(|Extension(connect)| connect.0));
    check_probing_block(&state, origin)?;
    let grant = state.paired_authorizer.issue(&wallet, origin, unix_now());
    Ok(([(CACHE_CONTROL, "no-store")], Json(grant)).into_response())
}

/// A valid authorization for `keypair`, as a client would send it. Tests in other modules use
/// it to act as the wallet's owner.
#[cfg(test)]
pub(crate) fn signed_authorization(
    authorizer: &PairedAuthorizer,
    keypair: &solana_sdk::signature::Keypair,
    origin: IpAddr,
) -> AuthorizationPayload {
    use solana_sdk::signer::Signer;

    authorization_signed_by(authorizer, &keypair.pubkey(), keypair, origin)
}

/// A grant issued for `wallet` and signed by `signer`. Valid only when `signer` holds
/// `wallet`, so tests use it to act as a caller that does not.
#[cfg(test)]
pub(crate) fn authorization_signed_by(
    authorizer: &PairedAuthorizer,
    wallet: &Pubkey,
    signer: &solana_sdk::signature::Keypair,
    origin: IpAddr,
) -> AuthorizationPayload {
    use solana_sdk::signer::Signer;

    let grant = authorizer.issue(wallet, origin, unix_now());
    let message = authorization_message(wallet, &grant.challenge, grant.expires_at);
    AuthorizationPayload {
        challenge: grant.challenge,
        expires_at: grant.expires_at,
        origin: grant.origin,
        mac: grant.mac,
        signature_hex: lower_hex(signer.sign_message(message.as_bytes()).as_ref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::keypair::keypair_from_seed;
    use solana_sdk::signer::Signer;

    const NOW: i64 = 1_799_999_100;
    const ORIGIN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));
    const OTHER_ORIGIN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));

    fn authorizer(mode: AuthorizationMode) -> PairedAuthorizer {
        PairedAuthorizer::new(&[0x11; 32], 900, mode, NetworkMode::Enforce).expect("authorizer")
    }

    fn observing() -> PairedAuthorizer {
        PairedAuthorizer::new(
            &[0x11; 32],
            900,
            AuthorizationMode::Required,
            NetworkMode::Observe,
        )
        .expect("authorizer")
    }

    fn golden_keypair() -> Keypair {
        keypair_from_seed(&[7u8; 32]).expect("keypair")
    }

    fn sign(keypair: &Keypair, grant: AuthorizationGrant) -> AuthorizationPayload {
        sign_as(keypair, &keypair.pubkey(), grant)
    }

    fn sign_as(
        signer: &Keypair,
        wallet: &Pubkey,
        grant: AuthorizationGrant,
    ) -> AuthorizationPayload {
        let message = authorization_message(wallet, &grant.challenge, grant.expires_at);
        AuthorizationPayload {
            challenge: grant.challenge,
            expires_at: grant.expires_at,
            origin: grant.origin,
            mac: grant.mac,
            signature_hex: lower_hex(signer.sign_message(message.as_bytes()).as_ref()),
        }
    }

    fn granted(authorizer: &PairedAuthorizer, keypair: &Keypair) -> AuthorizationPayload {
        sign(keypair, authorizer.issue(&keypair.pubkey(), ORIGIN, NOW))
    }

    /// The values the browser SDK and the mobile client pin in their own tests. A change here
    /// is a protocol change for every client.
    #[test]
    fn the_grant_and_the_signed_message_match_the_shared_vector() {
        let keypair = golden_keypair();
        let wallet = keypair.pubkey();
        assert_eq!(
            wallet.to_string(),
            "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB"
        );
        let grant =
            authorizer(AuthorizationMode::Required).issue_for(&wallet, ORIGIN, NOW, &[0x22; 32]);
        assert_eq!(grant.challenge, "22".repeat(32));
        assert_eq!(grant.expires_at, 1_800_000_000);
        assert_eq!(grant.expires_in, 900);
        assert_eq!(grant.origin, "4bd598d57ec9d5aacaffc4f0ca573ece");
        assert_eq!(
            grant.mac,
            "92dd5d5e281678bc041d28c30a9d49e2878f0e87b18710fec211dc70f61379fb"
        );

        let message = authorization_message(&wallet, &grant.challenge, grant.expires_at);
        assert_eq!(
            message,
            "Entros verification\n\
             Sign to start verification sessions for this wallet. The authorization expires \
             within the hour. It moves no funds and approves no transaction.\n\
             \n\
             Entros-Paired-Open-v1\n\
             wallet:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB\n\
             challenge:2222222222222222222222222222222222222222222222222222222222222222\n\
             expires:1800000000"
        );
        assert_eq!(message.len(), 331);
        let payload = sign(&keypair, grant);
        assert_eq!(
            payload.signature_hex,
            "a50c16c0bac5a61d9c017184d803de45e7451b782e25be1c2d684e6c6814cff0\
             bea246c5d0e2a4484a4798034f376c1a2db2498b75428045ba1a7cc803bd7a08"
        );
    }

    /// The signed text promises the wallet's owner that the authorization expires within the
    /// hour, so no configurable lifetime may outlast that.
    #[test]
    fn the_longest_lifetime_keeps_the_promise_in_the_signed_text() {
        let message = authorization_message(&golden_keypair().pubkey(), &"22".repeat(32), 0);
        assert!(message.contains("expires within the hour"));
        const { assert!(MAX_TTL_SECS <= 3_600) };
    }

    #[test]
    fn an_ipv6_network_has_its_own_tag() {
        let network: IpAddr = "2001:db8:1:2::".parse().expect("address");
        assert_eq!(
            lower_hex(&authorizer(AuthorizationMode::Required).origin_tag(network)),
            "6a8d5aab1ebdc9653aafa1bc01fa2816"
        );
    }

    #[test]
    fn a_signed_grant_opens_and_finalizes() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let payload = granted(&authorizer, &keypair);
        for step in [Step::Open, Step::Finalize] {
            assert_eq!(
                authorizer.verify(&keypair.pubkey(), &payload, step, ORIGIN, NOW + 1),
                Ok(NetworkMatch::Same)
            );
        }
    }

    #[test]
    fn an_authorization_is_reusable_until_it_expires() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let payload = granted(&authorizer, &keypair);
        let wallet = keypair.pubkey();
        assert!(authorizer
            .verify(&wallet, &payload, Step::Open, ORIGIN, NOW + 899)
            .is_ok());
        assert!(authorizer
            .verify(&wallet, &payload, Step::Open, ORIGIN, NOW + 900)
            .is_err());
    }

    #[test]
    fn a_session_that_opened_in_time_can_still_finalize() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let payload = granted(&authorizer, &keypair);
        let wallet = keypair.pubkey();
        assert!(authorizer
            .verify(&wallet, &payload, Step::Finalize, ORIGIN, NOW + 900 + 599)
            .is_ok());
        assert!(authorizer
            .verify(&wallet, &payload, Step::Finalize, ORIGIN, NOW + 900 + 600)
            .is_err());
    }

    #[test]
    fn verification_reports_another_network_without_refusing_it() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let payload = granted(&authorizer, &keypair);
        let wallet = keypair.pubkey();
        for step in [Step::Open, Step::Finalize] {
            assert_eq!(
                authorizer.verify(&wallet, &payload, step, OTHER_ORIGIN, NOW + 1),
                Ok(NetworkMatch::Other)
            );
        }
    }

    /// The network is compared last, so an authorization that fails any other check is
    /// invalid and never reported as one from another network.
    #[test]
    fn only_an_otherwise_valid_authorization_is_from_another_network() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        let valid = granted(&authorizer, &keypair);

        let mut unsigned = valid.clone();
        unsigned.signature_hex = "00".repeat(64);
        let mut forged = valid.clone();
        forged.mac = "00".repeat(32);
        for (payload, now) in [
            (&valid, NOW + 900),
            (&unsigned, NOW + 1),
            (&forged, NOW + 1),
        ] {
            assert_eq!(
                authorizer.verify(&wallet, payload, Step::Open, OTHER_ORIGIN, now),
                Err(AuthorizationError::Invalid)
            );
        }
        assert_eq!(
            authorizer.verify(
                &wallet,
                &valid,
                Step::Finalize,
                OTHER_ORIGIN,
                NOW + 900 + 600
            ),
            Err(AuthorizationError::Invalid)
        );
    }

    #[test]
    fn an_open_from_another_network_follows_the_network_mode() {
        let owner = Keypair::new();
        let wallet = owner.pubkey();

        let enforcing = authorizer(AuthorizationMode::Required);
        let payload = signed_authorization(&enforcing, &owner, ORIGIN);
        assert_eq!(
            enforcing.attempt_subject(&wallet, Some(&payload), Step::Open, OTHER_ORIGIN),
            Err(AuthorizationError::NetworkMismatch)
        );

        let observing = observing();
        let payload = signed_authorization(&observing, &owner, ORIGIN);
        assert_eq!(
            observing.attempt_subject(&wallet, Some(&payload), Step::Open, OTHER_ORIGIN),
            Ok(Authorized {
                subject: AttemptSubject::WalletAtOrigin(wallet, OTHER_ORIGIN),
                network_mismatch: true,
            })
        );
    }

    /// A session survives a change of network, but an authorization used from another network
    /// never spends the wallet's own attempts.
    #[test]
    fn a_finalize_from_another_network_follows_the_network_mode() {
        let owner = Keypair::new();
        let wallet = owner.pubkey();
        // Under enforce only the grant network can have opened the session, so every valid
        // finalize is the wallet's own.
        let enforcing = authorizer(AuthorizationMode::Required);
        let payload = signed_authorization(&enforcing, &owner, ORIGIN);
        assert_eq!(
            enforcing.attempt_subject(&wallet, Some(&payload), Step::Finalize, OTHER_ORIGIN),
            Ok(Authorized {
                subject: AttemptSubject::Wallet(wallet),
                network_mismatch: true,
            })
        );
        // Under observe an open can come from anywhere, so a finalize from another network
        // is charged to the wallet as seen from that network.
        let observer = observing();
        let payload = signed_authorization(&observer, &owner, ORIGIN);
        assert_eq!(
            observer.attempt_subject(&wallet, Some(&payload), Step::Finalize, OTHER_ORIGIN),
            Ok(Authorized {
                subject: AttemptSubject::WalletAtOrigin(wallet, OTHER_ORIGIN),
                network_mismatch: true,
            })
        );
        for authorizer in [enforcing, observer] {
            let payload = signed_authorization(&authorizer, &owner, ORIGIN);
            for step in [Step::Open, Step::Finalize] {
                assert_eq!(
                    authorizer.attempt_subject(&wallet, Some(&payload), step, ORIGIN),
                    Ok(Authorized {
                        subject: AttemptSubject::Wallet(wallet),
                        network_mismatch: false,
                    })
                );
            }
        }
    }

    #[test]
    fn the_network_mode_parses_strictly() {
        assert_eq!(NetworkMode::parse(None), Ok(NetworkMode::Enforce));
        assert_eq!(
            NetworkMode::parse(Some(" enforce ")),
            Ok(NetworkMode::Enforce)
        );
        assert_eq!(
            NetworkMode::parse(Some("observe")),
            Ok(NetworkMode::Observe)
        );
        for value in ["off", "", "Observe"] {
            assert!(NetworkMode::parse(Some(value)).is_err());
        }
    }

    #[test]
    fn another_wallet_cannot_use_the_authorization() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let owner = Keypair::new();
        let payload = granted(&authorizer, &owner);
        let other = Keypair::new().pubkey();
        assert_eq!(
            authorizer.verify(&other, &payload, Step::Open, ORIGIN, NOW + 1),
            Err(AuthorizationError::Invalid)
        );
    }

    /// A caller that asks for a grant in the victim's name cannot sign it.
    #[test]
    fn a_grant_signed_by_another_key_is_refused() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let victim = Keypair::new();
        let attacker = Keypair::new();
        let payload = sign_as(
            &attacker,
            &victim.pubkey(),
            authorizer.issue(&victim.pubkey(), ORIGIN, NOW),
        );
        assert_eq!(
            authorizer.verify(&victim.pubkey(), &payload, Step::Open, ORIGIN, NOW + 1),
            Err(AuthorizationError::Invalid)
        );
    }

    #[test]
    fn a_changed_field_breaks_the_mac() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        let valid = granted(&authorizer, &keypair);

        // A later expiry that the wallet signs itself still fails: the service never issued it.
        let mut extended = valid.clone();
        extended.expires_at += 86_400;
        let message = authorization_message(&wallet, &extended.challenge, extended.expires_at);
        extended.signature_hex = lower_hex(keypair.sign_message(message.as_bytes()).as_ref());
        assert!(authorizer
            .verify(&wallet, &extended, Step::Open, ORIGIN, NOW + 1)
            .is_err());

        let other_tag = lower_hex(&authorizer.origin_tag(OTHER_ORIGIN));
        let mut moved = valid.clone();
        moved.origin = other_tag;
        assert!(authorizer
            .verify(&wallet, &moved, Step::Open, OTHER_ORIGIN, NOW + 1)
            .is_err());

        let mut other_challenge = valid;
        other_challenge.challenge = "33".repeat(32);
        assert!(authorizer
            .verify(&wallet, &other_challenge, Step::Open, ORIGIN, NOW + 1)
            .is_err());
    }

    #[test]
    fn a_grant_from_another_key_is_refused() {
        let issuer = PairedAuthorizer::new(
            &[0x12; 32],
            900,
            AuthorizationMode::Required,
            NetworkMode::Enforce,
        )
        .expect("authorizer");
        let keypair = Keypair::new();
        let payload = granted(&issuer, &keypair);
        assert!(authorizer(AuthorizationMode::Required)
            .verify(&keypair.pubkey(), &payload, Step::Finalize, ORIGIN, NOW + 1)
            .is_err());
    }

    #[test]
    fn malformed_fields_are_refused_without_a_panic() {
        let authorizer = authorizer(AuthorizationMode::Required);
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        let valid = granted(&authorizer, &keypair);
        let multi_byte = format!("a\u{e9}{}", "0".repeat(61));
        assert_eq!(multi_byte.len(), 64);
        let mutations: [fn(&mut AuthorizationPayload, &str); 5] = [
            |payload, _| payload.challenge = payload.challenge.to_uppercase(),
            |payload, _| {
                payload.challenge.pop();
            },
            |payload, crafted| payload.mac = crafted.to_owned(),
            |payload, _| payload.origin = String::new(),
            |payload, _| payload.signature_hex = "zz".repeat(64),
        ];
        for mutate in mutations {
            let mut payload = valid.clone();
            mutate(&mut payload, &multi_byte);
            assert_eq!(
                authorizer.verify(&wallet, &payload, Step::Open, ORIGIN, NOW + 1),
                Err(AuthorizationError::Invalid)
            );
        }
    }

    #[test]
    fn the_subject_follows_the_proof() {
        let wallet_key = Keypair::new();
        let wallet = wallet_key.pubkey();
        let required = authorizer(AuthorizationMode::Required);
        let optional = authorizer(AuthorizationMode::Optional);

        assert_eq!(
            required.attempt_subject(&wallet, None, Step::Open, ORIGIN),
            Err(AuthorizationError::Required)
        );
        assert_eq!(
            optional.attempt_subject(&wallet, None, Step::Open, ORIGIN),
            Ok(Authorized {
                subject: AttemptSubject::WalletAtOrigin(wallet, ORIGIN),
                network_mismatch: false,
            })
        );

        let payload = signed_authorization(&optional, &wallet_key, ORIGIN);
        assert_eq!(
            optional.attempt_subject(&wallet, Some(&payload), Step::Open, ORIGIN),
            Ok(Authorized {
                subject: AttemptSubject::Wallet(wallet),
                network_mismatch: false,
            })
        );
        // Optional mode never accepts a bad authorization as if none was sent.
        let mut forged = payload;
        forged.mac = "00".repeat(32);
        assert_eq!(
            optional.attempt_subject(&wallet, Some(&forged), Step::Open, ORIGIN),
            Err(AuthorizationError::Invalid)
        );
    }

    #[test]
    fn the_mode_parses_strictly() {
        assert_eq!(
            AuthorizationMode::parse(None),
            Ok(AuthorizationMode::Required)
        );
        assert_eq!(
            AuthorizationMode::parse(Some(" required ")),
            Ok(AuthorizationMode::Required)
        );
        assert_eq!(
            AuthorizationMode::parse(Some("optional")),
            Ok(AuthorizationMode::Optional)
        );
        assert!(AuthorizationMode::parse(Some("off")).is_err());
        assert!(AuthorizationMode::parse(Some("")).is_err());
    }

    #[test]
    fn an_error_answers_unauthorized_with_its_reason() {
        for (error, reason) in [
            (AuthorizationError::Required, "authorization_required"),
            (AuthorizationError::Invalid, "authorization_invalid"),
            (AuthorizationError::NetworkMismatch, "authorization_invalid"),
        ] {
            assert!(matches!(
                AppError::from(error),
                AppError::PairedRejected { status: StatusCode::UNAUTHORIZED, reason: sent }
                    if sent == reason
            ));
        }
    }
}
