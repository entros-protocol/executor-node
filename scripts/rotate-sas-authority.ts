/**
 * Rotate the authorized signers on an Entros SAS credential.
 *
 * The executor signs every attestation with `SAS_AUTHORITY_KEYPAIR`. That key
 * must appear in the credential's `authorized_signers` list. This script reads
 * that list and replaces it.
 *
 * `ChangeAuthorizedSigners` replaces the whole list rather than adding to it,
 * so a zero-downtime rotation passes both keys first and drops the old one in a
 * second run. Verify the current signer list before each change.
 *
 * Only the credential's authority can sign this instruction, and no instruction
 * exists to change that authority. Whoever created the credential controls its
 * signer list permanently.
 *
 * Reads are the default. Nothing is sent without `--apply`.
 *
 * Usage:
 *   cd executor-node/scripts && npm install
 *
 *   # Show the current signer list and exit.
 *   npx tsx rotate-sas-authority.ts --credential <PDA>
 *
 *   # Show the change that would be made.
 *   npx tsx rotate-sas-authority.ts --credential <PDA> \
 *     --signers <PUBKEY_A>,<PUBKEY_B>
 *
 *   # Send it.
 *   npx tsx rotate-sas-authority.ts --credential <PDA> \
 *     --expected-authority <PUBKEY> \
 *     --authority-keypair ../../.config/admin-devnet.json \
 *     --signers <PUBKEY_A>,<PUBKEY_B> --apply
 */

import { readFileSync } from "fs";
import {
  getChangeAuthorizedSignersInstruction,
  SOLANA_ATTESTATION_SERVICE_PROGRAM_ADDRESS,
} from "sas-lib";
import {
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createSignerFromKeyPair,
  createKeyPairFromBytes,
  getAddressFromPublicKey,
  address,
  pipe,
  createTransactionMessage,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  appendTransactionMessageInstructions,
  signTransactionMessageWithSigners,
  sendAndConfirmTransactionFactory,
  getSignatureFromTransaction,
  assertIsTransactionWithBlockhashLifetime,
  getBase58Encoder,
  getBase58Decoder,
  type Address,
  type KeyPairSigner,
} from "@solana/kit";

const RPC_URL = process.env.RPC_URL ?? "https://api.devnet.solana.com";
const WS_URL = process.env.WS_URL ?? "wss://api.devnet.solana.com";

/** Discriminator the SAS program writes at offset 0 of a Credential account. */
const CREDENTIAL_DISCRIMINATOR = 0;

interface CredentialState {
  authority: Address;
  name: string;
  authorizedSigners: Address[];
}

/**
 * Decode a raw SAS Credential account.
 *
 * Layout: 1 byte discriminator (0), 32 bytes authority, 4-byte LE name length
 * plus name, 4-byte LE signer count plus 32 bytes per signer. Mirrors
 * `parse_credential_authorized_signers` in
 * `executor-node/src/attestation/sas.rs`. Change both together.
 */
function decodeCredential(data: Uint8Array): CredentialState {
  if (data.length < 1 || data[0] !== CREDENTIAL_DISCRIMINATOR) {
    throw new Error(
      `Account is not a SAS Credential (discriminator ${data[0]}, expected ${CREDENTIAL_DISCRIMINATOR})`,
    );
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const decoder = getBase58Decoder();

  let offset = 1;
  const authority = decoder.decode(data.subarray(offset, offset + 32)) as Address;
  offset += 32;

  const nameLength = view.getUint32(offset, true);
  offset += 4;
  if (offset + nameLength > data.length) {
    throw new Error("Credential name length overruns the account");
  }
  const name = new TextDecoder().decode(data.subarray(offset, offset + nameLength));
  offset += nameLength;

  const signerCount = view.getUint32(offset, true);
  offset += 4;
  if (offset + signerCount * 32 > data.length) {
    throw new Error(
      `Credential declares ${signerCount} signers but only ${data.length - offset} bytes remain`,
    );
  }

  const authorizedSigners: Address[] = [];
  for (let i = 0; i < signerCount; i++) {
    authorizedSigners.push(decoder.decode(data.subarray(offset, offset + 32)) as Address);
    offset += 32;
  }

  return { authority, name, authorizedSigners };
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
}

async function loadSigner(path: string): Promise<KeyPairSigner> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf-8"));
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 64 ||
    !parsed.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)
  ) {
    throw new Error(`Expected a 64-byte Solana keypair at ${path}`);
  }
  const secretKey = new Uint8Array(parsed);
  return createSignerFromKeyPair(await createKeyPairFromBytes(secretKey));
}

async function readCredential(
  rpc: ReturnType<typeof createSolanaRpc>,
  credential: Address,
): Promise<CredentialState> {
  const account = await rpc.getAccountInfo(credential, { encoding: "base64" }).send();
  if (!account.value) {
    throw new Error(`Credential ${credential} does not exist`);
  }
  if (account.value.owner !== SOLANA_ATTESTATION_SERVICE_PROGRAM_ADDRESS) {
    throw new Error(
      `Credential ${credential} is owned by ${account.value.owner}, not the attestation service`,
    );
  }
  return decodeCredential(Buffer.from(account.value.data[0], "base64"));
}

function printCredential(label: string, state: CredentialState): void {
  console.log(`\n${label}`);
  console.log(`  name      ${state.name}`);
  console.log(`  authority ${state.authority}   (permanent, no instruction changes it)`);
  console.log(`  signers   ${state.authorizedSigners.length}`);
  for (const signer of state.authorizedSigners) {
    console.log(`            ${signer}`);
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  const credentialArg = args.credential;
  if (typeof credentialArg !== "string") {
    console.error("Required: --credential <PDA>. See the header of this file for usage.");
    process.exit(1);
  }
  const credential = address(credentialArg);

  const rpc = createSolanaRpc(RPC_URL);
  const current = await readCredential(rpc, credential);
  printCredential(`Current state of ${credential}`, current);

  const signersArg = args.signers;
  if (typeof signersArg !== "string") {
    console.log("\nNo --signers given, so nothing to change. Read-only run complete.");
    return;
  }

  // The new list is always explicit. Never derive it by adding to or removing
  // from the current list, because a stale read would then silently write the
  // wrong set.
  const requested = signersArg
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (requested.length === 0) {
    console.error("\nRefusing to write an empty signer list. Nothing could issue attestations.");
    process.exit(1);
  }

  const seen = new Set(requested);
  if (seen.size !== requested.length) {
    console.error("\nRefusing to write a list containing duplicates.");
    process.exit(1);
  }

  const newSigners = requested.map((s) => address(s));

  console.log(`\nRequested signer list (${newSigners.length})`);
  for (const signer of newSigners) {
    const status = current.authorizedSigners.includes(signer) ? "unchanged" : "ADDED";
    console.log(`  ${signer}   ${status}`);
  }
  for (const signer of current.authorizedSigners) {
    if (!newSigners.includes(signer)) {
      console.log(`  ${signer}   REMOVED`);
    }
  }

  if (args.apply !== true) {
    console.log("\nDry run complete. No authority key was read and nothing was sent.");
    return;
  }

  const expectedAuthorityArg = args["expected-authority"];
  if (typeof expectedAuthorityArg !== "string") {
    throw new Error("--expected-authority <PUBKEY> is required with --apply");
  }
  const expectedAuthority = address(expectedAuthorityArg);
  if (current.authority !== expectedAuthority) {
    throw new Error("The credential authority does not match --expected-authority");
  }

  const keypairArg = args["authority-keypair"];
  if (typeof keypairArg !== "string") {
    throw new Error("--authority-keypair <PATH> is required with --apply");
  }
  const authority = await loadSigner(keypairArg);
  if (authority.address !== expectedAuthority) {
    throw new Error("The loaded authority key does not match --expected-authority");
  }

  console.log("\nSending ChangeAuthorizedSigners...");
  const rpcSubscriptions = createSolanaRpcSubscriptions(WS_URL);
  const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();

  const instruction = getChangeAuthorizedSignersInstruction({
    payer: authority,
    authority,
    credential,
    signers: newSigners,
  });

  const txMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (msg) => setTransactionMessageFeePayerSigner(authority, msg),
    (msg) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
    (msg) => appendTransactionMessageInstructions([instruction], msg),
  );

  const signedTx = await signTransactionMessageWithSigners(txMessage);
  assertIsTransactionWithBlockhashLifetime(signedTx);
  await sendAndConfirm(signedTx, { commitment: "confirmed" });
  console.log(`Signature: ${getSignatureFromTransaction(signedTx)}`);

  // Re-read rather than trusting the send. The point of the rotation is the
  // resulting on-chain state, so report that and nothing else.
  const updated = await readCredential(rpc, credential);
  printCredential(`New state of ${credential}`, updated);

  const applied =
    updated.authorizedSigners.length === newSigners.length &&
    newSigners.every((s) => updated.authorizedSigners.includes(s));
  if (!applied) {
    console.error("\nOn-chain list does not match what was requested. Investigate before deploying.");
    process.exit(1);
  }
  console.log("\nOn-chain signer list matches the request.");
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
