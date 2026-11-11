use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

use crate::attestation::instructions::{
    build_close_attestation, build_create_attestation, CloseAttestationAccounts,
    CreateAttestationAccounts, ATTESTATION_PROGRAM_ID,
};
use crate::error::AppError;
use crate::solana::client::{AccountSnapshot, SolanaClient};
use crate::solana::pda;

/// Parsed fields from the on-chain IdentityState account.
pub struct IdentityStateData {
    pub trust_score: u16,
    /// Solana cluster timestamp of the most recent state-changing tx
    /// (`mint_anchor`, `update_anchor`, or `reset_identity_state`).
    /// Consumed by `check_attestation_freshness` to gate `/attest` on
    /// recent verification; also surfaced to Agent Anchor and Realms
    /// integrations that perform their own recency checks.
    pub last_verification_timestamp: i64,
}

/// Forward-skew tolerance for the on-chain `last_verification_timestamp`.
/// A few seconds of drift between the Solana cluster clock and the
/// executor's wall clock is expected; rejecting strictly on `ts > now`
/// would false-reject legitimate flows. Mirrors the asymmetric pattern
/// in `attestation/handler.rs::verify_wallet_signature`.
const ATTESTATION_FORWARD_SKEW_SECS: i64 = 30;

/// Maximum age of the on-chain verification timestamp accepted by
/// `/attest`. 5 minutes gives comfortable headroom over the normal SDK
/// flow (which calls `/attest` within seconds of on-chain confirmation)
/// while keeping the window tight enough that a direct API caller
/// bypassing the SDK cannot refresh attestation freshness for state
/// that didn't actually re-verify.
const ATTESTATION_VERIFICATION_MAX_AGE_SECS: i64 = 300;

/// Issues SAS attestations after successful Entros verification.
/// Uses a dedicated authority keypair (separate from the relayer/payer)
/// for signing attestation instructions.
pub struct SasAttestor {
    credential_pda: Pubkey,
    schema_pda: Pubkey,
    ttl_days: u64,
    client: Arc<SolanaClient>,
    authority_keypair: Keypair,
}

impl SasAttestor {
    pub fn new(
        credential_pda: Pubkey,
        schema_pda: Pubkey,
        ttl_days: u64,
        client: Arc<SolanaClient>,
        authority_keypair: Keypair,
    ) -> Self {
        Self {
            credential_pda,
            schema_pda,
            ttl_days,
            client,
            authority_keypair,
        }
    }

    /// Issue (or update) an SAS attestation for the given user wallet.
    /// Reads the user's on-chain IdentityState to get trust_score.
    pub async fn issue_attestation(&self, user_wallet: &Pubkey) -> Result<String, AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                tracing::error!(error = %e, "SystemTime before UNIX_EPOCH during attestation");
                AppError::AttestationServiceUnavailable
            })?
            .as_secs() as i64;
        let issuer = Issuer {
            payer: self.client.relayer_pubkey(),
            authority: self.authority_keypair.pubkey(),
            credential: self.credential_pda,
            schema: self.schema_pda,
        };
        let inputs = PlanInputs {
            wallet: *user_wallet,
            credential: self.credential_pda,
            schema: self.schema_pda,
            ttl_days: self.ttl_days,
        };

        // Read the wallet's accounts, then those of each earlier holder the plan asks
        // for, one call per wallet. The walk is bounded, so the loop is too.
        let mut snapshots = Vec::new();
        let mut next = *user_wallet;
        let plan = loop {
            let accounts = wallet_accounts(&next, &self.credential_pda, &self.schema_pda);
            snapshots.extend(self.client.get_account_snapshots(&accounts).await?);
            match plan_attestation(&inputs, &snapshots, now) {
                Ok(PlanStep::Read(wallet)) => next = wallet,
                Ok(PlanStep::Issue(plan)) => break plan,
                Err(reason) => {
                    tracing::warn!(
                        wallet = %crate::auth::redact::redact_wallet_id(&user_wallet.to_string()),
                        reason,
                        "Attestation refused"
                    );
                    return Err(AppError::AttestationServiceUnavailable);
                }
            }
        };

        // Relayer pays, authority signs.
        let sig = self
            .client
            .send_attestation_tx(
                plan_instructions(&plan, &issuer, user_wallet),
                &self.authority_keypair,
            )
            .await?;
        Ok(sig.to_string())
    }
}

/// The keys every instruction of one issue names.
struct Issuer {
    payer: Pubkey,
    authority: Pubkey,
    credential: Pubkey,
    schema: Pubkey,
}

/// What one issue decides from.
struct PlanInputs {
    wallet: Pubkey,
    credential: Pubkey,
    schema: Pubkey,
    ttl_days: u64,
}

/// The transaction one issue submits.
#[derive(Debug, PartialEq, Eq)]
struct AttestationPlan {
    /// Attestation accounts to close, in order: those that earlier holders of the
    /// identity left behind, then the wallet's own if it exists.
    closes: Vec<Pubkey>,
    /// The wallet's own attestation account, created last.
    attestation: Pubkey,
    data: Vec<u8>,
    expiry: i64,
}

#[derive(Debug, PartialEq, Eq)]
enum PlanStep {
    /// The plan needs this wallet's accounts, appended in `wallet_accounts` order.
    Read(Pubkey),
    Issue(AttestationPlan),
}

/// Earlier holders of an identity whose attestations one issue cleans up.
const MAX_EARLIER_WALLETS: usize = 3;

/// The accounts read for each wallet, in the order `plan_attestation` expects them.
fn wallet_accounts(wallet: &Pubkey, credential: &Pubkey, schema: &Pubkey) -> [Pubkey; 3] {
    [
        pda::find_identity_state_pda(wallet).0,
        pda::find_migration_record_pda(wallet).0,
        find_sas_attestation_pda(credential, schema, wallet),
    ]
}

/// Decide what one issue submits, from the accounts read so far.
///
/// `snapshots` holds, per wallet, its identity, migration record and attestation
/// accounts: first the requesting wallet, then each earlier wallet in the order this
/// function asked for them. Each account is checked against its owner, because anyone
/// can send lamports to a derived address and create a System-owned account there.
///
/// The wallet must hold an identity verified recently and, if the identity migrated
/// here, verified again since. Its migration record names the wallet the identity came
/// from. An earlier wallet's attestation is closed only when that wallet holds no
/// identity and its account parses as this service's attestation for it. The walk
/// stops at a wallet already seen, after `MAX_EARLIER_WALLETS`, or at a wallet with no
/// readable record.
fn plan_attestation(
    inputs: &PlanInputs,
    snapshots: &[Option<AccountSnapshot>],
    now: i64,
) -> Result<PlanStep, &'static str> {
    if !snapshots.len().is_multiple_of(3) {
        return Err("snapshot_layout");
    }
    let mut wallets = snapshots.chunks_exact(3);
    let [identity, record, own_attestation] = wallets.next().ok_or("snapshot_layout")? else {
        return Err("snapshot_layout");
    };

    let identity = identity
        .as_ref()
        .filter(|account| account.owner == pda::anchor_program_id())
        .ok_or("identity_missing")?;
    let identity = deserialize_identity_state(&identity.data).map_err(|_| "identity_layout")?;
    check_attestation_freshness(identity.last_verification_timestamp, now)?;

    // A migrated identity keeps its verification time. An attestation must stand for a
    // verification on this wallet, so a wallet that received the identity after its
    // last verification verifies again first.
    let record = migration_record(record.as_ref())?;
    if record
        .as_ref()
        .is_some_and(|record| record.migrated_at >= identity.last_verification_timestamp)
    {
        return Err("not_verified_since_migration");
    }

    let mut closes = Vec::new();
    let mut visited = vec![inputs.wallet];
    let mut next = record.map(|record| record.previous_wallet);
    while let Some(wallet) = next.take() {
        if visited.contains(&wallet) || visited.len() > MAX_EARLIER_WALLETS {
            break;
        }
        let Some(accounts) = wallets.next() else {
            return Ok(PlanStep::Read(wallet));
        };
        let [identity, record, attestation] = accounts else {
            return Err("snapshot_layout");
        };
        visited.push(wallet);
        let holds_identity = identity
            .as_ref()
            .is_some_and(|account| account.owner == pda::anchor_program_id());
        if !holds_identity
            && attestation.as_ref().is_some_and(|account| {
                is_attestation_of(account, &wallet, &inputs.credential, &inputs.schema)
            })
        {
            closes.push(find_sas_attestation_pda(
                &inputs.credential,
                &inputs.schema,
                &wallet,
            ));
        }
        next = migration_record(record.as_ref())
            .ok()
            .flatten()
            .map(|record| record.previous_wallet);
    }

    let attestation = find_sas_attestation_pda(&inputs.credential, &inputs.schema, &inputs.wallet);
    if must_close_existing(own_attestation.as_ref()) {
        closes.push(attestation);
    }
    // `verifiedAt` carries the on-chain verification time. Readers compare it with the
    // on-chain reset time, so both must come from the cluster clock.
    let data = serialize_attestation_data(
        identity.trust_score,
        identity.last_verification_timestamp,
        "wallet-connected",
    );
    let ttl_secs = i64::try_from(inputs.ttl_days)
        .unwrap_or(i64::MAX)
        .saturating_mul(86_400);
    Ok(PlanStep::Issue(AttestationPlan {
        closes,
        attestation,
        data,
        expiry: now.saturating_add(ttl_secs),
    }))
}

/// The plan's instructions: each close in plan order, then the create.
fn plan_instructions(plan: &AttestationPlan, issuer: &Issuer, wallet: &Pubkey) -> Vec<Instruction> {
    let event_authority = find_event_authority_pda();
    let mut instructions: Vec<Instruction> = plan
        .closes
        .iter()
        .map(|attestation| {
            build_close_attestation(&CloseAttestationAccounts {
                payer: issuer.payer,
                authority: issuer.authority,
                credential: issuer.credential,
                attestation: *attestation,
                event_authority,
            })
        })
        .collect();
    instructions.push(build_create_attestation(
        &CreateAttestationAccounts {
            payer: issuer.payer,
            authority: issuer.authority,
            credential: issuer.credential,
            schema: issuer.schema,
            attestation: plan.attestation,
        },
        wallet,
        &plan.data,
        plan.expiry,
    ));
    instructions
}

/// Derive the SAS attestation PDA for a given user.
/// Seeds: ["attestation", credential, schema, nonce(user_wallet)]
fn find_sas_attestation_pda(credential: &Pubkey, schema: &Pubkey, nonce: &Pubkey) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(
        &[
            b"attestation",
            credential.as_ref(),
            schema.as_ref(),
            nonce.as_ref(),
        ],
        &ATTESTATION_PROGRAM_ID,
    );
    pda
}

/// Derive the event authority PDA (singleton).
/// Seeds: ["__event_authority"]
fn find_event_authority_pda() -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(&[b"__event_authority"], &ATTESTATION_PROGRAM_ID);
    pda
}

/// Check whether the on-chain `last_verification_timestamp` is recent
/// enough to support issuing an attestation now. Returns `Ok(())` on
/// pass and an `&'static str` reason on rejection.
///
/// Rejection cases:
/// - `"future_skew"` when the timestamp is more than
///   `ATTESTATION_FORWARD_SKEW_SECS` ahead of `now` (anomalous clock
///   state or malicious account).
/// - `"stale"` when the timestamp is older than
///   `ATTESTATION_VERIFICATION_MAX_AGE_SECS`. Indicates the wallet
///   hasn't completed a recent `mint_anchor` / `update_anchor` /
///   `reset_identity_state` tx — either the SDK's client-side
///   confirmation gate was bypassed or the on-chain tx silently
///   reverted earlier in the flow.
///
/// Separated as a free function so the freshness contract is unit-
/// testable without spinning up an `AudioContext`-equivalent fixture
/// or a real SAS attestor.
fn check_attestation_freshness(ts: i64, now: i64) -> Result<(), &'static str> {
    if ts > now.saturating_add(ATTESTATION_FORWARD_SKEW_SECS) {
        return Err("future_skew");
    }
    let age = (now.saturating_sub(ts)).max(0);
    if age > ATTESTATION_VERIFICATION_MAX_AGE_SECS {
        return Err("stale");
    }
    Ok(())
}

/// True when a close instruction must precede the create instruction.
///
/// The attestation program refuses to close an account it does not own, and the
/// transaction is atomic. A close against an address that only holds lamports
/// would fail the whole issue, for as long as the lamports stay there.
fn must_close_existing(existing: Option<&AccountSnapshot>) -> bool {
    existing
        .is_some_and(|account| account.owner == ATTESTATION_PROGRAM_ID && !account.data.is_empty())
}

/// Anchor account discriminator for MigrationRecord = sha256("account:MigrationRecord")[..8].
const MIGRATION_RECORD_DISCRIMINATOR: [u8; 8] = [16, 36, 116, 243, 192, 61, 40, 1];

/// MigrationRecord bytes: discriminator, `migrated_at` i64, `migrated_slot` u64, bump,
/// then `previous_wallet` at offset 25. A longer account parses on these bytes alone.
const MIGRATION_RECORD_LEN: usize = 57;

/// The fields of a migration record that attestation reads.
#[derive(Debug, PartialEq, Eq)]
struct MigrationRecord {
    /// When the identity arrived at this wallet.
    migrated_at: i64,
    /// The wallet that held the identity before it.
    previous_wallet: Pubkey,
}

/// The wallet's migration record, or `None` if the identity was minted here.
///
/// An account the Anchor program does not own is no record, lamports sent to the
/// address included. A record the program owns must parse.
fn migration_record(
    record: Option<&AccountSnapshot>,
) -> Result<Option<MigrationRecord>, &'static str> {
    let Some(record) = record.filter(|account| account.owner == pda::anchor_program_id()) else {
        return Ok(None);
    };
    let bytes = record
        .data
        .get(..MIGRATION_RECORD_LEN)
        .ok_or("migration_record_layout")?;
    if bytes[..8] != MIGRATION_RECORD_DISCRIMINATOR {
        return Err("migration_record_layout");
    }
    let migrated_at = i64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| "migration_record_layout")?,
    );
    let previous_wallet: [u8; 32] = bytes[25..57]
        .try_into()
        .map_err(|_| "migration_record_layout")?;
    Ok(Some(MigrationRecord {
        migrated_at,
        previous_wallet: Pubkey::from(previous_wallet),
    }))
}

/// Discriminator byte the SAS program writes at offset 0 of an Attestation account.
const SAS_ATTESTATION_DISCRIMINATOR: u8 = 2;

/// Attestation bytes other than its data: discriminator, nonce, credential, schema,
/// data length, signer, expiry and token account.
const SAS_ATTESTATION_FIXED_LEN: usize = 173;

/// True when `account` is the SAS program's attestation for `nonce` under this
/// credential and schema.
///
/// Layout: discriminator (2), nonce at 1..33, credential at 33..65, schema at 65..97,
/// data length u32 LE at 97, then the data and 72 fixed bytes.
fn is_attestation_of(
    account: &AccountSnapshot,
    nonce: &Pubkey,
    credential: &Pubkey,
    schema: &Pubkey,
) -> bool {
    let data = &account.data;
    let Some(data_len) = data
        .get(97..101)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .and_then(|len| usize::try_from(len).ok())
    else {
        return false;
    };
    account.owner == ATTESTATION_PROGRAM_ID
        && data[0] == SAS_ATTESTATION_DISCRIMINATOR
        && data[1..33] == nonce.to_bytes()
        && data[33..65] == credential.to_bytes()
        && data[65..97] == schema.to_bytes()
        && SAS_ATTESTATION_FIXED_LEN.checked_add(data_len) == Some(data.len())
}

/// Discriminator byte the SAS program writes at offset 0 of a Credential
/// account. Checked before the offsets below are trusted, so a Schema or
/// Attestation account passed by mistake is rejected rather than decoded
/// into a nonsense signer list.
const SAS_CREDENTIAL_DISCRIMINATOR: u8 = 0;

/// Decode the `authorized_signers` list from a raw SAS Credential account.
///
/// Only a key in this list may sign `CreateAttestation` or
/// `CloseAttestation` against the credential, so it is the authority the
/// executor must hold to issue attestations at all.
///
/// Layout (Solana Attestation Service `Credential`):
///   1 byte:  discriminator (0)
///  32 bytes: authority (Pubkey) — the key that may change this list
///   4 bytes: name length (u32 LE) + N bytes: name (UTF-8)
///   4 bytes: signer count (u32 LE) + 32 bytes per signer
///
/// The authority is deliberately not returned. It cannot be changed by any
/// instruction the program exposes, so nothing at runtime can act on it.
pub fn parse_credential_authorized_signers(data: &[u8]) -> Result<Vec<Pubkey>, String> {
    if data.first() != Some(&SAS_CREDENTIAL_DISCRIMINATOR) {
        return Err("SAS credential discriminator mismatch (not a Credential account)".to_string());
    }

    // Discriminator + authority, then the name's length prefix.
    let mut offset = 1 + 32;
    let name_len = read_u32_le(data, offset)? as usize;
    offset = offset
        .checked_add(4 + name_len)
        .ok_or("SAS credential name length overflows the buffer")?;

    let signer_count = read_u32_le(data, offset)? as usize;
    offset = offset
        .checked_add(4)
        .ok_or("SAS credential signer count overflows the buffer")?;

    // Reject an implausible count before allocating against it.
    let available = data.len().saturating_sub(offset);
    if signer_count.saturating_mul(32) > available {
        return Err(format!(
            "SAS credential declares {signer_count} signers but only {available} bytes remain"
        ));
    }

    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let bytes: [u8; 32] = data
            .get(offset..offset + 32)
            .ok_or("SAS credential signer list is truncated")?
            .try_into()
            .map_err(|_| "SAS credential signer is not 32 bytes")?;
        signers.push(Pubkey::from(bytes));
        offset += 32;
    }

    Ok(signers)
}

/// Confirm that `authority` may sign for the credential read at `credential`, returning
/// how many signers it lists. An `Err` is a definite wrong answer: no account the
/// attestation program owns, a body that does not decode, or a list without the authority.
///
/// The owner check comes first. Anyone can create or fund an account at that address
/// under another owner, with bytes that decode as a credential.
pub fn check_credential_authority(
    account: Option<&AccountSnapshot>,
    credential: &Pubkey,
    authority: &Pubkey,
) -> Result<usize, String> {
    let account = account.ok_or_else(|| {
        format!("SAS credential {credential} does not exist on the configured cluster")
    })?;
    if account.owner != ATTESTATION_PROGRAM_ID {
        return Err(format!(
            "SAS credential {credential} is not owned by the attestation program"
        ));
    }
    let signers = parse_credential_authorized_signers(&account.data).map_err(|e| {
        format!("Could not decode SAS credential {credential} to verify the authority: {e}")
    })?;
    if !signers.contains(authority) {
        return Err(format!(
            "SAS authority {authority} is not an authorized signer on credential {credential} \
             ({} signer(s) registered). Every attestation would fail at send time. Add it with \
             ChangeAuthorizedSigners before starting.",
            signers.len()
        ));
    }
    Ok(signers.len())
}

/// Read a little-endian u32 at `offset`, or describe why it is unreadable.
fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .ok_or_else(|| format!("SAS credential truncated at offset {offset}"))?
        .try_into()
        .map_err(|_| "SAS credential length prefix is not 4 bytes")?;
    Ok(u32::from_le_bytes(bytes))
}

/// Deserialize trust_score and last_verification_timestamp from raw IdentityState account data.
///
/// Layout (from protocol-core entros-anchor):
///   8 bytes: Anchor discriminator
///  32 bytes: owner (Pubkey)
///   8 bytes: creation_timestamp (i64)
///   8 bytes: last_verification_timestamp (i64)
///   4 bytes: verification_count (u32)
///   2 bytes: trust_score (u16)
///  ... remaining fields not needed
pub fn deserialize_identity_state(data: &[u8]) -> Result<IdentityStateData, String> {
    // Minimum size: 8 + 32 + 8 + 8 + 4 + 2 = 62 bytes
    if data.len() < 62 {
        return Err(format!(
            "IdentityState data too short: {} bytes (need >= 62)",
            data.len()
        ));
    }

    // Verify the Anchor account discriminator = sha256("account:IdentityState")[..8]
    // before trusting the raw offsets below. The PDA is program-derived, but a wrong-type
    // or uninitialized account at that address would otherwise have arbitrary bytes read as
    // a trust score. Mirrors the on-chain guard in entros-voter-weight so the off-chain
    // attestor enforces the same type check.
    const IDENTITY_DISCRIMINATOR: [u8; 8] = [156, 32, 87, 93, 52, 155, 248, 207];
    if data[..8] != IDENTITY_DISCRIMINATOR {
        return Err(
            "IdentityState discriminator mismatch (not an IdentityState account)".to_string(),
        );
    }

    let last_verification_timestamp = i64::from_le_bytes(
        data[48..56]
            .try_into()
            .map_err(|_| "Failed to read last_verification_timestamp")?,
    );

    let trust_score = u16::from_le_bytes(
        data[60..62]
            .try_into()
            .map_err(|_| "Failed to read trust_score")?,
    );

    Ok(IdentityStateData {
        trust_score,
        last_verification_timestamp,
    })
}

/// Serialize attestation data matching the SAS schema layout [bool, u16, i64, string].
///
/// Borsh encoding:
///   bool   = 1 byte (0x00 or 0x01)
///   u16    = 2 bytes little-endian
///   i64    = 8 bytes little-endian
///   string = 4-byte LE length prefix + UTF-8 bytes
fn serialize_attestation_data(trust_score: u16, verified_at: i64, mode: &str) -> Vec<u8> {
    let mode_bytes = mode.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + 8 + 4 + mode_bytes.len());

    // isHuman: bool
    buf.push(1u8);

    // trustScore: u16
    buf.extend_from_slice(&trust_score.to_le_bytes());

    // verifiedAt: i64
    buf.extend_from_slice(&verified_at.to_le_bytes());

    // mode: string (borsh = 4-byte LE length + utf8 bytes)
    buf.extend_from_slice(&(mode_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(mode_bytes);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_round_trip() {
        let data = serialize_attestation_data(150, 1_700_000_000, "wallet-connected");

        // isHuman
        assert_eq!(data[0], 1);

        // trustScore
        let ts = u16::from_le_bytes([data[1], data[2]]);
        assert_eq!(ts, 150);

        // verifiedAt
        let vat = i64::from_le_bytes(data[3..11].try_into().expect("8-byte slice"));
        assert_eq!(vat, 1_700_000_000);

        // mode
        let mode_len = u32::from_le_bytes(data[11..15].try_into().expect("4-byte slice")) as usize;
        let mode = std::str::from_utf8(&data[15..15 + mode_len]).expect("valid utf-8 mode tag");
        assert_eq!(mode, "wallet-connected");
    }

    /// The owner of an address that only holds lamports.
    const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0; 32]);

    fn snapshot(owner: Pubkey, data: Vec<u8>) -> AccountSnapshot {
        AccountSnapshot { owner, data }
    }

    #[test]
    fn an_existing_attestation_is_closed_first() {
        let existing = snapshot(ATTESTATION_PROGRAM_ID, vec![1; 204]);
        assert!(must_close_existing(Some(&existing)));
    }

    #[test]
    fn an_address_with_no_account_needs_no_close() {
        assert!(!must_close_existing(None));
    }

    /// Lamports sent to the attestation address create this account. A close
    /// against it fails, and the atomic transaction would then issue nothing.
    #[test]
    fn a_funded_address_with_no_data_needs_no_close() {
        let funded = snapshot(SYSTEM_PROGRAM, Vec::new());
        assert!(!must_close_existing(Some(&funded)));
    }

    #[test]
    fn an_account_of_another_program_is_never_closed() {
        let foreign = snapshot(Pubkey::new_unique(), vec![1; 204]);
        assert!(!must_close_existing(Some(&foreign)));
        let empty_owned = snapshot(ATTESTATION_PROGRAM_ID, Vec::new());
        assert!(!must_close_existing(Some(&empty_owned)));
    }

    /// The bytes the Anchor program serializes for a migration record whose identity
    /// came from the wallet `[0x11; 32]`.
    const MIGRATION_RECORD_BYTES: [u8; 57] = {
        let head: [u8; 25] = [
            0x10, 0x24, 0x74, 0xf3, 0xc0, 0x3d, 0x28, 0x01, 0x80, 0x7c, 0x12, 0x69, 0x00, 0x00,
            0x00, 0x00, 0x51, 0x4b, 0x0c, 0x1f, 0x00, 0x00, 0x00, 0x00, 0xfe,
        ];
        let mut bytes = [0x11; 57];
        let mut index = 0;
        while index < head.len() {
            bytes[index] = head[index];
            index += 1;
        }
        bytes
    };

    #[test]
    fn migration_record_reads_the_anchor_program_record() {
        let expected = Some(MigrationRecord {
            migrated_at: 1_762_819_200,
            previous_wallet: Pubkey::from([0x11; 32]),
        });
        let record = snapshot(pda::anchor_program_id(), MIGRATION_RECORD_BYTES.to_vec());
        assert_eq!(migration_record(Some(&record)), Ok(expected));

        let mut longer = MIGRATION_RECORD_BYTES.to_vec();
        longer.extend_from_slice(&[0; 7]);
        let record = snapshot(pda::anchor_program_id(), longer);
        assert_eq!(
            migration_record(Some(&record)).map(|record| record.map(|r| r.migrated_at)),
            Ok(Some(1_762_819_200))
        );
    }

    #[test]
    fn a_wallet_without_a_record_was_not_migrated() {
        assert_eq!(migration_record(None), Ok(None));
        let funded = snapshot(SYSTEM_PROGRAM, Vec::new());
        assert_eq!(migration_record(Some(&funded)), Ok(None));
    }

    #[test]
    fn an_unreadable_record_is_an_error() {
        let mut wrong_type = MIGRATION_RECORD_BYTES.to_vec();
        wrong_type[0] ^= 1;
        let record = snapshot(pda::anchor_program_id(), wrong_type);
        assert!(migration_record(Some(&record)).is_err());
        let short = snapshot(
            pda::anchor_program_id(),
            MIGRATION_RECORD_BYTES[..56].to_vec(),
        );
        assert!(migration_record(Some(&short)).is_err());
    }

    // --- plan_attestation ---

    const NOW: i64 = 1_700_000_000;
    const VERIFIED_AT: i64 = NOW - 10;

    fn plan_inputs(wallet: Pubkey) -> PlanInputs {
        PlanInputs {
            wallet,
            credential: Pubkey::new_from_array([0xc1; 32]),
            schema: Pubkey::new_from_array([0x5c; 32]),
            ttl_days: 365,
        }
    }

    fn identity_account(verified_at: i64) -> Option<AccountSnapshot> {
        let mut data = vec![0u8; 200];
        data[..8].copy_from_slice(&[156, 32, 87, 93, 52, 155, 248, 207]);
        data[48..56].copy_from_slice(&verified_at.to_le_bytes());
        data[60..62].copy_from_slice(&250u16.to_le_bytes());
        Some(snapshot(pda::anchor_program_id(), data))
    }

    fn record_account(migrated_at: i64, previous_wallet: &Pubkey) -> Option<AccountSnapshot> {
        let mut data = MIGRATION_RECORD_BYTES.to_vec();
        data[8..16].copy_from_slice(&migrated_at.to_le_bytes());
        data[25..57].copy_from_slice(previous_wallet.as_ref());
        Some(snapshot(pda::anchor_program_id(), data))
    }

    /// An attestation the SAS program wrote for `wallet` under the inputs' credential.
    fn attestation_bytes(inputs: &PlanInputs, wallet: &Pubkey) -> Vec<u8> {
        let payload = serialize_attestation_data(250, VERIFIED_AT, "wallet-connected");
        let mut data = vec![SAS_ATTESTATION_DISCRIMINATOR];
        data.extend_from_slice(wallet.as_ref());
        data.extend_from_slice(inputs.credential.as_ref());
        data.extend_from_slice(inputs.schema.as_ref());
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(&payload);
        data.extend_from_slice(&[0x22; 72]);
        data
    }

    fn attestation_account(inputs: &PlanInputs, wallet: &Pubkey) -> Option<AccountSnapshot> {
        Some(snapshot(
            ATTESTATION_PROGRAM_ID,
            attestation_bytes(inputs, wallet),
        ))
    }

    fn attestation_address(inputs: &PlanInputs, wallet: &Pubkey) -> Pubkey {
        find_sas_attestation_pda(&inputs.credential, &inputs.schema, wallet)
    }

    /// Run the plan as the issuer does, feeding each requested wallet's accounts from
    /// `chain` until it issues. Returns the plan and the wallets it asked for.
    fn run_plan(
        inputs: &PlanInputs,
        own: [Option<AccountSnapshot>; 3],
        chain: &[(Pubkey, [Option<AccountSnapshot>; 3])],
    ) -> (Result<AttestationPlan, &'static str>, Vec<Pubkey>) {
        let mut snapshots = own.to_vec();
        let mut asked = Vec::new();
        loop {
            match plan_attestation(inputs, &snapshots, NOW) {
                Ok(PlanStep::Issue(plan)) => return (Ok(plan), asked),
                Err(reason) => return (Err(reason), asked),
                Ok(PlanStep::Read(wallet)) => {
                    assert!(asked.len() < 8, "the walk must end");
                    asked.push(wallet);
                    let accounts = chain
                        .iter()
                        .find(|(held, _)| *held == wallet)
                        .map(|(_, accounts)| accounts.clone())
                        .unwrap_or([None, None, None]);
                    snapshots.extend(accounts);
                }
            }
        }
    }

    #[test]
    fn a_wallet_that_received_its_identity_at_its_last_verification_is_refused() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let previous = Pubkey::new_unique();
        let own = |migrated_at| {
            [
                identity_account(VERIFIED_AT),
                record_account(migrated_at, &previous),
                None,
            ]
        };

        let (refused, asked) = run_plan(&inputs, own(VERIFIED_AT), &[]);
        assert_eq!(refused, Err("not_verified_since_migration"));
        assert!(asked.is_empty());
        let (later, _) = run_plan(&inputs, own(VERIFIED_AT + 1), &[]);
        assert_eq!(later, Err("not_verified_since_migration"));

        let (issued, _) = run_plan(&inputs, own(VERIFIED_AT - 1), &[]);
        assert!(issued.is_ok());
    }

    #[test]
    fn a_funded_attestation_address_with_a_record_needs_no_close() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let previous = Pubkey::new_unique();
        let own = [
            identity_account(VERIFIED_AT),
            record_account(VERIFIED_AT - 60, &previous),
            Some(snapshot(SYSTEM_PROGRAM, Vec::new())),
        ];

        let (plan, asked) = run_plan(&inputs, own, &[]);
        assert_eq!(asked, vec![previous]);
        let plan = plan.expect("a verified wallet is issued");
        assert!(plan.closes.is_empty());
        assert_eq!(plan.attestation, attestation_address(&inputs, &wallet));
        assert_eq!(
            plan.data,
            serialize_attestation_data(250, VERIFIED_AT, "wallet-connected")
        );
        assert_eq!(plan.expiry, NOW + 365 * 86_400);
    }

    #[test]
    fn the_snapshots_are_read_as_identity_record_attestation_per_wallet() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let previous = Pubkey::new_unique();
        let own = || {
            [
                identity_account(VERIFIED_AT),
                record_account(VERIFIED_AT - 60, &previous),
                attestation_account(&inputs, &wallet),
            ]
        };

        let (plan, _) = run_plan(
            &inputs,
            own(),
            &[(
                previous,
                [None, None, attestation_account(&inputs, &previous)],
            )],
        );
        assert_eq!(
            plan.expect("issued").closes,
            vec![
                attestation_address(&inputs, &previous),
                attestation_address(&inputs, &wallet),
            ],
            "earlier closes come before the wallet's own"
        );

        // The same attestation in another position is not read as one.
        let (plan, _) = run_plan(
            &inputs,
            own(),
            &[(
                previous,
                [attestation_account(&inputs, &previous), None, None],
            )],
        );
        assert_eq!(
            plan.expect("issued").closes,
            vec![attestation_address(&inputs, &wallet)]
        );
    }

    #[test]
    fn a_chain_whose_middle_wallet_has_no_attestation_still_reaches_the_next() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let middle = Pubkey::new_unique();
        let first = Pubkey::new_unique();
        let own = [
            identity_account(VERIFIED_AT),
            record_account(VERIFIED_AT - 60, &middle),
            None,
        ];
        let chain = [
            (
                middle,
                [None, record_account(VERIFIED_AT - 120, &first), None],
            ),
            (first, [None, None, attestation_account(&inputs, &first)]),
        ];

        let (plan, asked) = run_plan(&inputs, own, &chain);
        assert_eq!(asked, vec![middle, first]);
        assert_eq!(
            plan.expect("issued").closes,
            vec![attestation_address(&inputs, &first)]
        );
    }

    #[test]
    fn a_cycle_back_to_an_earlier_wallet_ends_the_walk() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let previous = Pubkey::new_unique();
        let own = [
            identity_account(VERIFIED_AT),
            record_account(VERIFIED_AT - 60, &previous),
            None,
        ];
        let chain = [(
            previous,
            [
                None,
                record_account(VERIFIED_AT - 120, &wallet),
                attestation_account(&inputs, &previous),
            ],
        )];

        let (plan, asked) = run_plan(&inputs, own, &chain);
        assert_eq!(asked, vec![previous]);
        assert_eq!(
            plan.expect("issued").closes,
            vec![attestation_address(&inputs, &previous)]
        );
    }

    #[test]
    fn the_walk_reads_at_most_three_earlier_wallets() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let earlier: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let own = [
            identity_account(VERIFIED_AT),
            record_account(VERIFIED_AT - 60, &earlier[0]),
            None,
        ];
        let chain: Vec<_> = earlier
            .iter()
            .enumerate()
            .map(|(index, held)| {
                let before = earlier.get(index + 1).copied().unwrap_or_default();
                (
                    *held,
                    [
                        None,
                        record_account(VERIFIED_AT - 60 * (index as i64 + 2), &before),
                        attestation_account(&inputs, held),
                    ],
                )
            })
            .collect();

        let (plan, asked) = run_plan(&inputs, own, &chain);
        assert_eq!(asked, earlier[..MAX_EARLIER_WALLETS].to_vec());
        assert_eq!(plan.expect("issued").closes.len(), MAX_EARLIER_WALLETS);
    }

    #[test]
    fn an_earlier_wallet_that_holds_an_identity_again_keeps_its_attestation() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let previous = Pubkey::new_unique();
        let first = Pubkey::new_unique();
        let own = [
            identity_account(VERIFIED_AT),
            record_account(VERIFIED_AT - 60, &previous),
            None,
        ];
        let chain = [
            (
                previous,
                [
                    identity_account(VERIFIED_AT - 30),
                    record_account(VERIFIED_AT - 120, &first),
                    attestation_account(&inputs, &previous),
                ],
            ),
            (first, [None, None, attestation_account(&inputs, &first)]),
        ];

        let (plan, asked) = run_plan(&inputs, own, &chain);
        assert_eq!(asked, vec![previous, first]);
        assert_eq!(
            plan.expect("issued").closes,
            vec![attestation_address(&inputs, &first)]
        );
    }

    #[test]
    fn an_account_that_does_not_parse_as_the_attestation_is_never_closed() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let previous = Pubkey::new_unique();
        let valid = attestation_bytes(&inputs, &previous);
        let mutate = |offset: usize| {
            let mut data = valid.clone();
            data[offset] ^= 1;
            snapshot(ATTESTATION_PROGRAM_ID, data)
        };
        let mut longer = valid.clone();
        longer.push(0);
        let unparsed = [
            mutate(0),
            mutate(1),
            mutate(33),
            mutate(65),
            mutate(97),
            snapshot(ATTESTATION_PROGRAM_ID, valid[..valid.len() - 1].to_vec()),
            snapshot(ATTESTATION_PROGRAM_ID, longer),
            snapshot(ATTESTATION_PROGRAM_ID, valid[..100].to_vec()),
            snapshot(ATTESTATION_PROGRAM_ID, Vec::new()),
            snapshot(Pubkey::new_unique(), valid.clone()),
            snapshot(ATTESTATION_PROGRAM_ID, attestation_bytes(&inputs, &wallet)),
        ];
        for account in unparsed {
            let own = [
                identity_account(VERIFIED_AT),
                record_account(VERIFIED_AT - 60, &previous),
                None,
            ];
            let (plan, _) = run_plan(&inputs, own, &[(previous, [None, None, Some(account)])]);
            assert!(plan.expect("issued").closes.is_empty());
        }
    }

    #[test]
    fn a_wallet_without_a_recent_identity_is_refused() {
        let inputs = plan_inputs(Pubkey::new_unique());
        let (missing, _) = run_plan(&inputs, [None, None, None], &[]);
        assert_eq!(missing, Err("identity_missing"));
        let funded = Some(snapshot(SYSTEM_PROGRAM, Vec::new()));
        let (funded, _) = run_plan(&inputs, [funded, None, None], &[]);
        assert_eq!(funded, Err("identity_missing"));
        let (stale, _) = run_plan(&inputs, [identity_account(NOW - 3_600), None, None], &[]);
        assert_eq!(stale, Err("stale"));
        let unreadable = Some(snapshot(
            pda::anchor_program_id(),
            MIGRATION_RECORD_BYTES[..30].to_vec(),
        ));
        let (unreadable, _) = run_plan(
            &inputs,
            [identity_account(VERIFIED_AT), unreadable, None],
            &[],
        );
        assert_eq!(unreadable, Err("migration_record_layout"));
    }

    #[test]
    fn an_identity_minted_here_reads_no_other_wallet() {
        let wallet = Pubkey::new_unique();
        let inputs = plan_inputs(wallet);
        let (plan, asked) = run_plan(
            &inputs,
            [
                identity_account(VERIFIED_AT),
                None,
                attestation_account(&inputs, &wallet),
            ],
            &[],
        );
        assert!(asked.is_empty());
        assert_eq!(
            plan.expect("issued").closes,
            vec![attestation_address(&inputs, &wallet)]
        );
    }

    #[test]
    fn the_transaction_closes_in_plan_order_then_creates() {
        let wallet = Pubkey::new_unique();
        let earlier = Pubkey::new_unique();
        let plan = AttestationPlan {
            closes: vec![earlier, Pubkey::new_unique()],
            attestation: Pubkey::new_unique(),
            data: vec![1, 2, 3],
            expiry: NOW,
        };
        let issuer = Issuer {
            payer: Pubkey::new_unique(),
            authority: Pubkey::new_unique(),
            credential: Pubkey::new_unique(),
            schema: Pubkey::new_unique(),
        };

        let instructions = plan_instructions(&plan, &issuer, &wallet);
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].accounts[3].pubkey, plan.closes[0]);
        assert_eq!(instructions[1].accounts[3].pubkey, plan.closes[1]);
        assert_eq!(instructions[2].accounts[4].pubkey, plan.attestation);
        assert_ne!(instructions[2].data, instructions[0].data);
    }

    #[test]
    fn deserialize_identity_state_valid() {
        let mut data = vec![0u8; 200];

        // Write Anchor discriminator
        data[..8].copy_from_slice(&[156, 32, 87, 93, 52, 155, 248, 207]);

        // Write last_verification_timestamp at offset 48
        let ts: i64 = 1_700_000_000;
        data[48..56].copy_from_slice(&ts.to_le_bytes());

        // Write trust_score at offset 60
        let score: u16 = 250;
        data[60..62].copy_from_slice(&score.to_le_bytes());

        let result = deserialize_identity_state(&data).expect("valid synthetic IdentityState");
        assert_eq!(result.trust_score, 250);
        assert_eq!(result.last_verification_timestamp, 1_700_000_000);
    }

    #[test]
    fn deserialize_identity_state_too_short() {
        let data = vec![0u8; 50];
        assert!(deserialize_identity_state(&data).is_err());
    }

    #[test]
    fn attestation_pda_is_deterministic() {
        let cred = Pubkey::new_unique();
        let schema = Pubkey::new_unique();
        let nonce = Pubkey::new_unique();

        let pda1 = find_sas_attestation_pda(&cred, &schema, &nonce);
        let pda2 = find_sas_attestation_pda(&cred, &schema, &nonce);
        assert_eq!(pda1, pda2);
    }

    // --- check_attestation_freshness ---

    #[test]
    fn freshness_accepts_just_verified_state() {
        // Verification 1 second ago: trivially within the window.
        let now = 1_700_000_000;
        assert!(check_attestation_freshness(now - 1, now).is_ok());
    }

    #[test]
    fn freshness_accepts_state_at_window_edge() {
        // Exactly at the max-age boundary — accepted (strictly greater rejects).
        let now = 1_700_000_000;
        let ts = now - ATTESTATION_VERIFICATION_MAX_AGE_SECS;
        assert!(check_attestation_freshness(ts, now).is_ok());
    }

    #[test]
    fn freshness_rejects_stale_state() {
        // One second beyond the max-age window.
        let now = 1_700_000_000;
        let ts = now - ATTESTATION_VERIFICATION_MAX_AGE_SECS - 1;
        assert_eq!(check_attestation_freshness(ts, now), Err("stale"));
    }

    #[test]
    fn freshness_accepts_small_forward_skew() {
        // Cluster clock running a few seconds ahead of executor wall clock.
        // Within ATTESTATION_FORWARD_SKEW_SECS, accepted.
        let now = 1_700_000_000;
        let ts = now + ATTESTATION_FORWARD_SKEW_SECS;
        assert!(check_attestation_freshness(ts, now).is_ok());
    }

    #[test]
    fn freshness_rejects_far_future_timestamp() {
        // Far-future timestamp is anomalous — likely cluster clock
        // misconfiguration or malicious account.
        let now = 1_700_000_000;
        let ts = now + ATTESTATION_FORWARD_SKEW_SECS + 1;
        assert_eq!(check_attestation_freshness(ts, now), Err("future_skew"));
    }

    #[test]
    fn freshness_handles_default_zero_timestamp() {
        // A freshly-created IdentityState (or a wallet that never verified)
        // has timestamp 0. Age = now, far beyond the window → rejected.
        let now = 1_700_000_000;
        assert_eq!(check_attestation_freshness(0, now), Err("stale"));
    }

    // --- parse_credential_authorized_signers ---

    /// Build a SAS Credential account body with the given name and signers.
    fn credential_bytes(name: &str, signers: &[Pubkey]) -> Vec<u8> {
        let mut data = vec![SAS_CREDENTIAL_DISCRIMINATOR];
        data.extend_from_slice(Pubkey::new_unique().as_ref()); // authority
        data.extend_from_slice(&(name.len() as u32).to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&(signers.len() as u32).to_le_bytes());
        for s in signers {
            data.extend_from_slice(s.as_ref());
        }
        data
    }

    #[test]
    fn credential_decodes_single_signer_and_matches_live_account_size() {
        let signer = Pubkey::new_unique();
        let data = credential_bytes("iam-protocol", &[signer]);

        // The live devnet credential reports space = 85. A fixture built from
        // this layout with the same name and one signer must land on the same
        // size, which cross-checks the offsets against the real account
        // without pinning a devnet snapshot that would go stale.
        assert_eq!(data.len(), 85);

        let signers = parse_credential_authorized_signers(&data).expect("valid credential");
        assert_eq!(signers, vec![signer]);
    }

    #[test]
    fn credential_decodes_two_signers() {
        // The overlap state during a rotation: outgoing and incoming keys
        // both authorized, so neither issuance nor closure breaks mid-swap.
        let outgoing = Pubkey::new_unique();
        let incoming = Pubkey::new_unique();
        let data = credential_bytes("iam-protocol", &[outgoing, incoming]);

        assert_eq!(data.len(), 85 + 32);

        let signers = parse_credential_authorized_signers(&data).expect("valid credential");
        assert_eq!(signers, vec![outgoing, incoming]);
        assert!(signers.contains(&incoming));
    }

    #[test]
    fn credential_rejects_wrong_discriminator() {
        // Discriminator 1 is a Schema account. Pointing SAS_CREDENTIAL_PDA at
        // the schema is an easy environment-variable slip, and decoding it as
        // a credential would yield an arbitrary signer list.
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        data[0] = 1;
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_rejects_empty_buffer() {
        assert!(parse_credential_authorized_signers(&[]).is_err());
    }

    #[test]
    fn credential_rejects_truncated_signer_list() {
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        data.truncate(data.len() - 1);
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_rejects_signer_count_that_overruns_the_buffer() {
        // A corrupt or hostile count must not drive a huge allocation before
        // the read fails.
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        let count_offset = 1 + 32 + 4 + "iam-protocol".len();
        data[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn credential_rejects_name_length_that_overruns_the_buffer() {
        let mut data = credential_bytes("iam-protocol", &[Pubkey::new_unique()]);
        data[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_credential_authorized_signers(&data).is_err());
    }

    #[test]
    fn a_credential_the_attestation_program_owns_confirms_its_signer() {
        let authority = Pubkey::new_unique();
        let credential = Pubkey::new_unique();
        let account = snapshot(
            ATTESTATION_PROGRAM_ID,
            credential_bytes("iam-protocol", &[Pubkey::new_unique(), authority]),
        );
        assert_eq!(
            check_credential_authority(Some(&account), &credential, &authority),
            Ok(2)
        );
    }

    /// Anyone can create an account at the credential address under another owner, or fund
    /// it with lamports, and either one can hold bytes that decode as a credential.
    #[test]
    fn a_credential_not_owned_by_the_attestation_program_is_a_wrong_answer() {
        let authority = Pubkey::new_unique();
        let credential = Pubkey::new_unique();
        let forged = snapshot(
            Pubkey::new_unique(),
            credential_bytes("iam-protocol", &[authority]),
        );
        let funded = snapshot(SYSTEM_PROGRAM, Vec::new());
        for account in [Some(&forged), Some(&funded), None] {
            assert!(check_credential_authority(account, &credential, &authority).is_err());
        }
    }

    #[test]
    fn a_credential_without_the_authority_is_a_wrong_answer() {
        let credential = Pubkey::new_unique();
        let account = snapshot(
            ATTESTATION_PROGRAM_ID,
            credential_bytes("iam-protocol", &[Pubkey::new_unique()]),
        );
        assert!(
            check_credential_authority(Some(&account), &credential, &Pubkey::new_unique()).is_err()
        );
        let undecodable = snapshot(ATTESTATION_PROGRAM_ID, vec![1; 85]);
        assert!(
            check_credential_authority(Some(&undecodable), &credential, &Pubkey::new_unique())
                .is_err()
        );
    }

    #[test]
    fn credential_with_no_signers_decodes_empty() {
        // Structurally valid, operationally dead: nothing can issue against
        // it. The decoder reports the truth and the startup preflight is what
        // refuses the boot.
        let data = credential_bytes("iam-protocol", &[]);
        let signers = parse_credential_authorized_signers(&data).expect("valid credential");
        assert!(signers.is_empty());
    }
}
