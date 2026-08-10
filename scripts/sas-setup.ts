/**
 * One-time setup script: Create Entros credential + schema on Solana devnet
 * for the Solana Attestation Service (SAS) integration.
 *
 * Run: cd executor-node/scripts && npm install
 *      AUTHORITY_KEYPAIR_PATH=<path> EXPECTED_AUTHORITY=<pubkey> \
 *      CREDENTIAL_NAME=<name> SCHEMA_NAME=<name> npm run setup
 *
 * Add `-- --apply` only after reviewing the derived addresses.
 *
 * Both names are REQUIRED and both are permanent once created. A credential
 * PDA derives from authority plus name, so a different name means a different
 * account, not an edit to an existing one.
 *
 * Prerequisites:
 *   - Explicit authority keypair path and expected public key
 *   - Devnet SOL in the authority account
 *
 * Output: Credential PDA and Schema PDA to add to executor .env
 */

import { readFileSync } from "fs";
import { resolve } from "path";
import {
  deriveCredentialPda,
  deriveSchemaPda,
  getCreateCredentialInstruction,
  getCreateSchemaInstruction,
  SOLANA_ATTESTATION_SERVICE_PROGRAM_ADDRESS,
} from "sas-lib";
import {
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createSignerFromKeyPair,
  createKeyPairFromBytes,
  pipe,
  createTransactionMessage,
  address,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  appendTransactionMessageInstructions,
  signTransactionMessageWithSigners,
  sendAndConfirmTransactionFactory,
  getSignatureFromTransaction,
  assertIsTransactionWithBlockhashLifetime,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";

const DEVNET_RPC = "https://api.devnet.solana.com";
const DEVNET_WS = "wss://api.devnet.solana.com";

async function loadKeypairSigner(): Promise<KeyPairSigner> {
  const configuredPath = process.env.AUTHORITY_KEYPAIR_PATH;
  if (!configuredPath) {
    throw new Error("AUTHORITY_KEYPAIR_PATH is required");
  }
  const keypairPath = resolve(configuredPath);

  const raw = readFileSync(keypairPath, "utf-8");
  const parsed: unknown = JSON.parse(raw);
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 64 ||
    !parsed.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)
  ) {
    throw new Error(`Expected a 64-byte Solana keypair at ${keypairPath}`);
  }
  const secretKey = new Uint8Array(parsed);

  const keypair = await createKeyPairFromBytes(secretKey);
  const signer = await createSignerFromKeyPair(keypair);
  const expectedAuthority = process.env.EXPECTED_AUTHORITY;
  if (!expectedAuthority) {
    throw new Error("EXPECTED_AUTHORITY is required");
  }
  if (signer.address !== expectedAuthority) {
    throw new Error(
      `Loaded authority ${signer.address} does not match EXPECTED_AUTHORITY ${expectedAuthority}`,
    );
  }
  return signer;
}

async function main() {
  const apply = process.argv.slice(2).includes("--apply");
  const expectedAuthority = process.env.EXPECTED_AUTHORITY;
  if (!expectedAuthority) {
    throw new Error("EXPECTED_AUTHORITY is required");
  }
  const authorityAddress = address(expectedAuthority);
  console.log(`Authority: ${authorityAddress}`);

  // 1. Create Entros Credential
  console.log("\n--- Creating Entros Credential ---");

  // A credential name is permanent and changes the derived account address.
  const credentialName = process.env.CREDENTIAL_NAME;
  if (!credentialName) {
    console.error("CREDENTIAL_NAME is required");
    process.exit(1);
  }

  const [credentialPda] = await deriveCredentialPda({
    authority: authorityAddress,
    name: credentialName,
  });
  console.log(`Credential name: ${credentialName}`);
  console.log(`Credential PDA: ${credentialPda}`);

  const schemaName = process.env.SCHEMA_NAME;
  if (!schemaName) {
    console.error("SCHEMA_NAME is required");
    process.exit(1);
  }
  const schemaVersion = 1;
  const [schemaPda] = await deriveSchemaPda({
    credential: credentialPda,
    name: schemaName,
    version: schemaVersion,
  });
  console.log(`Schema name: ${schemaName}`);
  console.log(`Schema PDA: ${schemaPda}`);

  if (!apply) {
    console.log("Dry run complete. Re-run with --apply after reviewing these addresses.");
    return;
  }

  console.log("Loading the explicit credential authority...");
  const authority = await loadKeypairSigner();
  const rpc = createSolanaRpc(DEVNET_RPC);
  const rpcSubscriptions = createSolanaRpcSubscriptions(DEVNET_WS);
  const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });

  const balance = await rpc.getBalance(authority.address).send();
  console.log(`Balance: ${Number(balance.value) / 1e9} SOL`);
  if (Number(balance.value) < 0.05e9) {
    console.error("The authority balance is too low for account creation");
    process.exit(1);
  }

  async function submitTx(
    instructions: readonly Instruction[],
  ): Promise<string> {
    const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();
    const txMessage = pipe(
      createTransactionMessage({ version: 0 }),
      (msg) => setTransactionMessageFeePayerSigner(authority, msg),
      (msg) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
      (msg) => appendTransactionMessageInstructions(instructions, msg),
    );
    const signedTx = await signTransactionMessageWithSigners(txMessage);
    assertIsTransactionWithBlockhashLifetime(signedTx);
    await sendAndConfirm(signedTx, { commitment: "confirmed" });
    return getSignatureFromTransaction(signedTx);
  }

  const credentialAccount = await rpc.getAccountInfo(credentialPda, { encoding: "base64" }).send();
  if (credentialAccount.value) {
    console.log("Credential already exists, skipping creation.");
  } else {
    const sig = await submitTx([
      getCreateCredentialInstruction({
        payer: authority,
        credential: credentialPda,
        authority: authority,
        name: credentialName,
        signers: [authority.address],
      }),
    ]);
    console.log(`Credential created: ${sig}`);
  }

  // 2. Create Entros Schema
  console.log("\n--- Creating Entros Schema ---");

  // A schema name is permanent and changes the derived account address.
  const schemaAccount = await rpc.getAccountInfo(schemaPda, { encoding: "base64" }).send();
  if (schemaAccount.value) {
    console.log("Schema already exists, skipping creation.");
  } else {
    const sig = await submitTx([
      getCreateSchemaInstruction({
        authority: authority,
        payer: authority,
        name: schemaName,
        credential: credentialPda,
        description: "Entros Protocol Proof-of-Personhood attestation",
        fieldNames: ["isHuman", "trustScore", "verifiedAt", "mode"],
        schema: schemaPda,
        layout: Buffer.from([10, 1, 8, 12]), // Bool=10, U16=1, I64=8, String=12
      }),
    ]);
    console.log(`Schema created: ${sig}`);
  }

  // 3. Output for .env
  console.log("\n=== Add these to executor-node .env ===");
  console.log(`SAS_CREDENTIAL_PDA=${credentialPda}`);
  console.log(`SAS_SCHEMA_PDA=${schemaPda}`);
  console.log(`SAS_ATTESTATION_TTL_DAYS=30`);
  console.log(`SAS_PROGRAM_ID=${SOLANA_ATTESTATION_SERVICE_PROGRAM_ADDRESS}`);
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
