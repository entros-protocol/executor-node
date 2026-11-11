# executor-node

Authenticated gateway, challenge service, risk composer, and SAS issuer for Entros.

The executor does not contain proprietary behavioral models. It forwards validation requests to a separate, private validation HTTP service.

## Responsibilities

- Authenticate integrators and enforce quotas.
- Issue and consume challenge nonces.
- Apply request, wallet, and IP rate limits.
- Forward feature summaries and phrase audio to the private validator.
- Combine returned risk signals under the configured policy.
- Issue best-effort SAS attestations for eligible wallet flows.
- Expose health and aggregate operational metrics.

The private validator performs feature checks, phrase transcription, acoustic analysis, and cross-wallet fingerprint comparison.

## API

| Route | Auth | Purpose |
|---|---|---|
| `GET /challenge` | API key | Issue a server challenge and nonce |
| `POST /validate-features` | API key | Forward capture evidence to the private validator |
| `POST /attest` | API key and wallet proof | Issue a SAS attestation when configured |
| `GET /paired/authorization` | API key | Issue the values a wallet signs for paired sessions |
| `POST /challenge/paired` | API key and wallet authorization | Open a paired session when paired sessions are enabled |
| `POST /paired/cue` | API key | Release the outstanding round cue |
| `POST /paired/commit` | API key | Commit one paired round when paired sessions are enabled |
| `POST /validate-session` | API key and wallet authorization | Finalize a paired session when paired sessions are enabled |
| `POST /study/definition` | Private API key | Return the study definition when the study routes are enabled |
| `POST /study/enrol` | Private API key | Enrol a study participant when the study routes are enabled |
| `GET /health` | Public | Return service health |
| `GET /status` | Optional API key | Return `status` publicly and detailed metrics to callers with a key that is not public |
| `GET /metrics` | Public | Return aggregate Prometheus counters |

Wallet clients submit their own protocol transactions. The executor relays none.

`/attest` writes the on-chain verification time into the attestation. It issues nothing for a
wallet that received its identity by migration and has not verified since. In the same
transaction it closes the attestations this service issued to earlier holders of the identity,
up to three wallets back, when those wallets hold no identity.

`/validate-features` accepts an optional `challenge_nonce`: the 32-byte array that `/challenge`
returned, in the same JSON form. A request that names it is checked against exactly that
challenge, from any client network. Send it with every capture. A request without it is checked
against the latest challenge its own client network asked for, or, when that network asked for
none, against the wallet's latest challenge. A signed request must name the nonce its wallet
authorization covers. A nonce of another length, or one that differs from the signed nonce,
answers 400.

A paired session runs three rounds of one word and one short path. The validator holds the
round state, so this service keeps none. The current source requires paired protocol version 2 at open.
Cue responses bind the outstanding round. The validator enforces round and cue expiry.
Open, cue and commit omit the finalize timing floor. The finalize
request goes through the same timing floor, quota and admission checks as
`/validate-features`. The paired routes answer 404 until `EXECUTOR_PAIRED_ENABLED` is set.

### Paired authorization

A paired open and a paired finalize must show that the wallet's owner asked for them.

1. The client calls `GET /paired/authorization?wallet=<base58>`.
2. The executor answers `challenge`, `expires_at`, `expires_in`, `origin` and `mac`.
3. The wallet signs this UTF-8 text, with `\n` line ends and no trailing newline:

   ```text
   Entros verification
   Sign to start verification sessions for this wallet. The authorization expires within the hour. It moves no funds and approves no transaction.

   Entros-Paired-Open-v1
   wallet:<base58>
   challenge:<hex>
   expires:<expires_at>
   ```

4. The client sends `authorization` with each open and finalize. The object holds the five
   answered values, without `expires_in`, and `signature_hex`.

Build the signed text from the fields. Do not sign text that a server supplies whole.
One authorization serves every session until it expires. `expires_in` gives its lifetime in
seconds, so a client can time it without the device clock. A lifetime is 300 seconds at least,
because clients drop an authorization with under 120 seconds left. A finalize can come from
another network, and the executor accepts it up to one session lifetime after the expiry.

`EXECUTOR_PAIRED_AUTHORIZATION_NETWORK` decides an open from another client network than the
one that asked for the authorization. `enforce` refuses it. `observe` serves it and counts it in
`entros_paired_authorization_network_mismatch_total`. Failed attempts are charged as follows:

- `enforce`: every request with a valid authorization is charged to the wallet.
- `observe`: a request with a valid authorization is charged to the wallet when it comes from
  the network that asked for the authorization. Otherwise it is charged to the wallet as seen
  from the network it came from.

The executor answers 401 with reason `authorization_required` or `authorization_invalid`.
On either reason, the client asks for a new authorization.
`EXECUTOR_PAIRED_AUTHORIZATION=optional` serves a request that carries no authorization.
Use it during a client rollout only. Roll out in this order:

1. Set `EXECUTOR_PAIRED_AUTHORIZATION=optional` and `EXECUTOR_PAIRED_AUTHORIZATION_NETWORK=observe`.
2. Ship the clients that send an authorization.
3. Set `EXECUTOR_PAIRED_AUTHORIZATION=required`.
4. Set `EXECUTOR_PAIRED_AUTHORIZATION_NETWORK=enforce` once
   `entros_paired_authorization_network_mismatch_total` stays near zero.

Paired rounds show that the client fixed each round's evidence before the next round was
revealed. They show nothing more about where that evidence came from.

Finalize uploads are bounded in total and per client network. A finalize that has read its
body and passed its authorization check then takes one of `EXECUTOR_PAIRED_SESSION_CONCURRENCY`
processing slots. A request that finds no free place or
slot within two seconds answers 503 with reason `session_busy`. Nothing was consumed, so the
client sends the same finalize again. A finalize body must arrive within 20 seconds.

## Limits

- **Client network.** `EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN` applies to one client network: an
  IPv4 address or an IPv6 /64. An IPv6 /48 has a second limit at 16 times that rate. Every
  network in that /48 shares it, and it matters only once the service has IPv6 ingress.
- **API key.** `RATE_LIMIT_PER_MINUTE` applies to each key that is not public. `/attest` has a
  second limit of 10 requests per minute for each such key.
- **Public key.** Mark every key that ships in a browser or an app with `"public": true` in
  `INTEGRATORS`. The client-network limit then applies to its requests, and no holder shares
  a limit with another. A public key must have quota `0`, it cannot use the study routes, and
  `/status` answers it as an anonymous caller.
- **Attestation.** Each wallet can attest twice per minute. The executor counts a request
  after it checks the wallet signature.
- **Attempts.** `VALIDATION_WALLET_MAX_ATTEMPTS` counts failed validations. A request that
  carries a valid wallet signature counts against the wallet. Any other request counts
  against the wallet as seen from its client network.

`EXECUTOR_SINGLE_CAPTURE_UPDATES=refuse` makes `/validate-features` answer 409 with reason
`paired_required` for each request. It needs `EXECUTOR_PAIRED_ENABLED=true`. The route refuses
each baseline write in both modes.

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
- `EXECUTOR_PAIRED_AUTHORIZATION_KEY_HEX` when paired sessions are enabled.

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
| `INTEGRATORS` | `[]` | Named API keys with explicit quotas and the optional `public` flag |
| `RATE_LIMIT_PER_MINUTE` | `60` | Request limit for each key that is not public |
| `EXECUTOR_PER_IP_RATE_LIMIT_PER_MIN` | `30` | Request limit for each client network |
| `CORS_ORIGINS` | `[]` | Exact allowed HTTP origins |
| `VALIDATION_SERVICE_URL` | unset | Private validator endpoint |
| `VALIDATION_SERVICE_URL_SIGNATURE` | unset | Authority signature over the validator URL |
| `VALIDATION_API_KEY` | unset | Credential sent to the private validator |
| `EXECUTOR_SCORING_CONFIG_BUNDLE` | unset | Signed scoring configuration required by release builds |
| `CHALLENGE_TTL_SECS` | `180` | Challenge nonce lifetime in seconds. Allowed range: 1-300. |
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
| `EXECUTOR_PAIRED_ENABLED` | `false` | Serve the paired-session routes |
| `EXECUTOR_PAIRED_SESSION_CONCURRENCY` | `16` | Paired finalize requests processed at once. Allowed range: 1-128. |
| `EXECUTOR_PAIRED_AUTHORIZATION` | `required` | `required` or `optional`. Whether a paired open and finalize must carry a wallet authorization. |
| `EXECUTOR_PAIRED_AUTHORIZATION_KEY_HEX` | unset | 32 random bytes as 64 hex characters. The executor signs each authorization with it. Unset draws a key at start. |
| `EXECUTOR_PAIRED_AUTHORIZATION_NETWORK` | `enforce` | `enforce` or `observe`. Whether a paired open from another client network than the authorization's is refused. |
| `EXECUTOR_PAIRED_AUTHORIZATION_TTL_SECS` | `900` | Authorization lifetime in seconds. Allowed range: 300-3600. |
| `EXECUTOR_SINGLE_CAPTURE_UPDATES` | `allow` | `allow` or `refuse`. Whether `/validate-features` serves updates. `refuse` needs paired sessions. |
| `EXECUTOR_STUDY_ROUTES_ENABLED` | `false` | Serve the study routes |

Do not place keypairs or API credentials in source control.

## Verification

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
cd scripts
npm ci
npm run test:sign-scoring
```

## License

MIT.

### Local validation deployment selection

`VALIDATION_IDENTITY_PROGRAM_ID` selects the program used to read validation identity state. The default is the official Anchor program.
An alternate program requires a loopback listener, Solana devnet, and `ENVIRONMENT=prod`. Signed scoring and validator URL checks still apply.
The gateway derives receipt intent from the selected on-chain identity. Client receipt flags do not override that decision.

Authenticated `GET /validation-deployment` returns the identity program, validation-only mode, and challenge requirement.
Alternate mode excludes `/attest` and the study routes.
