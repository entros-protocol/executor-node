/**
 * Sign a `VALIDATION_SERVICE_URL` so the executor accepts it on startup.
 *
 * The executor refuses to launch in production with an unsigned URL — this
 * script produces the bs58 Ed25519 signature the executor expects in
 * `VALIDATION_SERVICE_URL_SIGNATURE`. The hardcoded authority pubkey on
 * the executor side is the only key whose signature it will accept; an
 * attacker with Railway env access can change the URL but cannot produce
 * a matching signature without this keypair.
 *
 * Usage:
 *   cd executor-node/scripts && npm install
 *   npx tsx sign-validator-url.ts <keypair-path> <url>
 *
 * Example:
 *   npx tsx sign-validator-url.ts ../../.config/admin-devnet.json \
 *     http://serene-possibility.railway.internal:8080
 */

import { readFileSync } from "fs";
import bs58 from "bs58";
import nacl from "tweetnacl";

const DOMAIN_PREFIX = "Entros-VALIDATOR-URL-V1:";

const [keypairPath, url] = process.argv.slice(2);
if (!keypairPath || !url) {
  console.error("Usage: npx tsx sign-validator-url.ts <keypair-path> <url>");
  process.exit(1);
}

const secretKey = Uint8Array.from(JSON.parse(readFileSync(keypairPath, "utf8")));
if (secretKey.length !== 64) {
  console.error(
    `Expected a 64-byte Solana keypair file at ${keypairPath}, got ${secretKey.length} bytes`,
  );
  process.exit(1);
}

// Solana keypair files are 64 bytes: 32-byte seed || 32-byte pubkey.
// nacl.sign.detached takes the full 64-byte expanded secret key directly.
const message = new TextEncoder().encode(`${DOMAIN_PREFIX}${url}`);
const signature = nacl.sign.detached(message, secretKey);

const pubkey = bs58.encode(secretKey.slice(32));
const signatureBs58 = bs58.encode(signature);

console.log(`Pubkey:    ${pubkey}`);
console.log(`Message:   ${DOMAIN_PREFIX}${url}`);
console.log(`Signature: ${signatureBs58}`);
console.log(``);
console.log(`Set on the executor service:`);
console.log(`  VALIDATION_SERVICE_URL=${url}`);
console.log(`  VALIDATION_SERVICE_URL_SIGNATURE=${signatureBs58}`);
