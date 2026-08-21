# executor-node

Authenticated gateway, challenge service, risk composer, SAS issuer, and Solana relayer for Entros.

The executor does not contain proprietary behavioral models. It forwards validation requests to the separate private `entros-validation` HTTP service.

## Responsibilities

- Authenticate integrators and enforce quotas.
- Issue and consume challenge nonces.
- Apply request, wallet, and IP rate limits.
- Forward feature summaries and phrase audio to the private validator.
- Combine returned risk signals under the configured policy.
- Issue best-effort SAS attestations for eligible wallet flows.
- Relay walletless proof transactions to Solana devnet.
- Expose health and aggregate operational metrics.

The private validator performs feature checks, phrase transcription, acoustic analysis, and cross-wallet fingerprint comparison.

## API

| Route | Auth | Purpose |
|---|---|---|
| `GET /challenge` | API key | Issue a server challenge and nonce |
| `POST /validate-features` | API key | Forward capture evidence to the private validator |
| `POST /verify` | API key | Relay a walletless Groth16 verification transaction |
| `POST /attest` | API key and wallet proof | Issue a SAS attestation when configured |
| `GET /health` | Public | Return service health |
| `GET /status` | Optional API key | Return `status` publicly and detailed metrics to authenticated callers |
| `GET /metrics` | Public | Return aggregate Prometheus counters |

Walletless verification does not issue SAS attestations.

## Local development

```bash
cp .env.example .env
cargo build
cargo test
cargo run
```

The example configuration uses `ENVIRONMENT=dev`. Without `VALIDATION_SERVICE_URL`, feature requests use an insecure local pass-through.

That mode supports interface development only. It does not perform Entros behavioral validation.

Debug builds use a neutral scoring policy when `EXECUTOR_SCORING_CONFIG_BUNDLE`
is absent. Every release build requires a valid signed bundle.

Install the script dependencies with `npm ci` before signing a policy. The signer uses the installed `tsx` binary.

Keep the policy, authority keypair, and bundle under `../.config`. The signer rejects private artifacts inside this public worktree.

## Production startup boundary

`ENVIRONMENT` accepts only `dev` or `prod`. Unknown values stop startup.

Production requires:

- At least one explicit `INTEGRATORS` entry.
- A private `VALIDATION_SERVICE_URL`.
- A valid `VALIDATION_SERVICE_URL_SIGNATURE`.
- A valid `EXECUTOR_SCORING_CONFIG_BUNDLE`.
- At least one valid `CORS_ORIGINS` entry.
- A dedicated SAS authority when SAS credential fields are configured.

Production refuses the dev validator pass-through and permissive CORS mode.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` | `dev` | Exact runtime mode: `dev` or `prod` |
| `RPC_URL` | Solana devnet | Solana RPC endpoint |
| `WS_URL` | Solana devnet | Solana WebSocket endpoint |
| `RELAYER_KEYPAIR` | unset | Relayer keypair JSON |
| `RELAYER_KEYPAIR_PATH` | `./relayer-keypair.json` | Relayer keypair path |
| `LISTEN_ADDR` | `0.0.0.0:3001` | Local bind address when `PORT` is absent |
| `PORT` | unset | Platform-provided listen port |
| `API_KEYS` | `[]` | Development API-key list |
| `INTEGRATORS` | `[]` | Named API keys and explicit quotas |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per-key request limit |
| `EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN` | `30` | Per-IP request limit |
| `CORS_ORIGINS` | `[]` | Exact allowed HTTP origins |
| `VALIDATION_SERVICE_URL` | unset | Private validator endpoint |
| `VALIDATION_SERVICE_URL_SIGNATURE` | unset | Authority signature over the validator URL |
| `VALIDATION_API_KEY` | unset | Credential sent to the private validator |
| `EXECUTOR_SCORING_CONFIG_BUNDLE` | unset | Signed scoring configuration required by release builds |
| `CHALLENGE_TTL_SECS` | `60` | Challenge nonce lifetime |
| `VALIDATION_WALLET_MAX_ATTEMPTS` | `5` | Failed attempts allowed per wallet window |
| `VALIDATION_WALLET_WINDOW_SECS` | `3600` | Wallet attempt window |
| `SAS_CREDENTIAL_PDA` | unset | SAS credential address |
| `SAS_SCHEMA_PDA` | unset | SAS schema address |
| `SAS_AUTHORITY_KEYPAIR` | unset | Dedicated SAS authority JSON |
| `SAS_AUTHORITY_KEYPAIR_PATH` | unset | Dedicated SAS authority path |
| `SAS_ATTESTATION_TTL_DAYS` | `30` | Attestation lifetime |
| `EXECUTOR_AUTOMATION_OBSERVE` | `true` | Record bounded automation telemetry |
| `EXECUTOR_AUTOMATION_WEBDRIVER_REJECT` | `true` | Reject reported WebDriver sessions when validation runs |
| `EXECUTOR_WALLET_REPUTATION_OBSERVE` | `true` | Record public wallet signals |
| `EXECUTOR_CURVE_TRACE_OBSERVE` | `true` | Record bounded curve-trace telemetry |
| `VALIDATION_CROSS_WALLET_COOLDOWN_SECS` | `86400` | Cross-wallet cooldown duration |
| `VALIDATION_CROSS_WALLET_COOLDOWN_ENFORCE` | `false` | Enforce the cooldown when enabled |

Do not place keypairs or API credentials in source control.

## Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## License

MIT.
