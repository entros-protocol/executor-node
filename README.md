# executor-node

Entros Protocol executor node. Validation server and relayer service for the Entros Protocol. Generates signed challenges, validates behavioral features server-side using proprietary models, issues SAS attestations, and relays walletless verification transactions to Solana.

## Architecture

The executor serves two roles:

1. **Validation server**—receives a length-agnostic `Vec<f64>` of statistical features from the Pulse SDK (308 dimensions under the v3 layout: 170 audio + 81 motion + 57 touch). Runs proprietary validation models (loaded from the private `entros-validation` crate), performs cross-wallet Sybil detection via the fingerprint registry, and issues signed challenges.

2. **Walletless relayer** — accepts ZK proofs and submits on-chain `create_challenge` + `verify_proof` for users without wallets (liveness-check tier). API key required. Walletless flows do not receive SAS attestations.

## API

### POST /verify

Accepts a Groth16 proof for walletless verification. Submits `create_challenge` + `verify_proof` on-chain.

```json
Request:
{
  "proof_bytes": [0, 1, 2, ...],
  "public_inputs": [[0, 1, ...], ...],
  "commitment": [0, 1, ...]
}

Response:
{
  "success": true,
  "tx_signature": "5abc..."
}
```

Requires `X-API-Key` header (walletless tier only).

### POST /attest

Issues a Solana Attestation Service (SAS) attestation on a verified wallet. Requires the wallet to prove ownership via a signed message + server-issued nonce challenge — unauthenticated walletless flows do not reach this endpoint.

### GET /status

Returns service metrics (uptime, relayer balance, verifications processed).

### GET /health

Returns service status (no auth required).

## Setup

```bash
# Prerequisites: Rust, Solana CLI

# Configure environment
cp .env.example .env
# Edit .env: set RPC_URL, RELAYER_KEYPAIR_PATH

# Build
cargo build --release

# Run
cargo run

# Test
cargo test
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPC_URL` | `https://api.devnet.solana.com` | Solana RPC endpoint |
| `WS_URL` | `wss://api.devnet.solana.com` | Solana WebSocket endpoint |
| `RELAYER_KEYPAIR_PATH` | `./relayer-keypair.json` | Path to relayer keypair JSON |
| `LISTEN_ADDR` | `0.0.0.0:3001` | Server bind address |
| `API_KEYS` | `[]` | JSON array of valid API keys |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per minute per API key |
| `EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN` | `30` | Per-IP request cap, applied across all API keys and wallets |
| `CORS_ORIGINS` | `[]` | JSON array of allowed origins (permissive if empty) |
| `SAS_CREDENTIAL_PDA` | — | SAS credential PDA for attestation issuance |
| `SAS_SCHEMA_PDA` | — | SAS schema PDA for attestation issuance |
| `EXECUTOR_AUTOMATION_OBSERVE` | `true` | Log client automation signals for calibration (observe-only; never affects the decision). `0`/`false`/`no`/`off` to disable |
| `EXECUTOR_WALLET_REPUTATION_OBSERVE` | `true` | Log a verifying wallet's on-chain reputation for calibration (observe-only; never affects the decision). `0`/`false`/`no`/`off` to disable |
| `EXECUTOR_CURVE_TRACE_OBSERVE` | `true` | Score the client's coarse curve-trace outline against the issued curve (region proximity, gesture kinematics, and alignment residual) for calibration (observe-only, detached off the request path; never affects the decision). `0`/`false`/`no`/`off` to disable |

## License

MIT
