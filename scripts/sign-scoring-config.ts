import { constants as fsConstants } from "node:fs";
import {
  closeSync,
  fstatSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import bs58 from "bs58";
import nacl from "tweetnacl";

const DOMAIN = Buffer.from("Entros\0executor-scoring-config\0v1\0", "ascii");
const SERVICE = Buffer.from("entros-executor\0", "ascii");
const SCHEMA_VERSION = 1;
const EXPECTED_REVISION = 1;
const PARTS_PER_MILLION = 1_000_000;
const PAYLOAD_LENGTH = 87;
const POLICY_FILE_MAX_BYTES = 16 * 1024;
const KEYPAIR_FILE_MAX_BYTES = 4 * 1024;
const PUBLIC_WORKTREE = realpathSync(
  resolve(fileURLToPath(new URL("..", import.meta.url))),
);

const CLUSTER_IDS = {
  devnet: 1,
} as const;

const ENVIRONMENT_IDS = {
  dev: 1,
  prod: 2,
} as const;

type Cluster = keyof typeof CLUSTER_IDS;
type Environment = keyof typeof ENVIRONMENT_IDS;

export interface ScoringPolicy {
  cluster: Cluster;
  environment: Environment;
  revision: number;
  auditNonce: Uint8Array;
  biometricPpm: number;
  ttsPpm: number;
  unallocatedPpm: number;
  automationPpm: number;
  reputationPpm: number;
  frictionThresholdPpm: number;
  rejectThresholdPpm: number;
}

export interface SignedScoringConfig {
  bundle: string;
  configId: string;
  revision: number;
}

interface CliOptions {
  configPath: string;
  keypairPath: string;
  expectedAuthority: string;
  outputPath: string;
}

type JsonRecord = Record<string, unknown>;

function requireRecord(value: unknown, label: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as JsonRecord;
}

function requireExactKeys(
  record: JsonRecord,
  expectedKeys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function requirePpm(value: unknown, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > PARTS_PER_MILLION
  ) {
    throw new Error(`${label} must be an integer from 0 to 1000000`);
  }
  return value;
}

function requireRevision(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value !== EXPECTED_REVISION
  ) {
    throw new Error(`revision must equal ${EXPECTED_REVISION}`);
  }
  return value;
}

function requireChoice<T extends string>(
  value: unknown,
  choices: Readonly<Record<T, number>>,
  label: string,
): T {
  if (typeof value !== "string" || !(value in choices)) {
    throw new Error(`${label} is not supported`);
  }
  return value as T;
}

function copyAuditNonce(value: Uint8Array): Uint8Array {
  const nonce = Uint8Array.from(value);
  if (nonce.length !== 32) {
    nonce.fill(0);
    throw new Error("audit nonce must contain 32 bytes");
  }
  if (nonce.every((byte) => byte === 0)) {
    nonce.fill(0);
    throw new Error("audit nonce must not be all zeroes");
  }
  return nonce;
}

export function parseScoringPolicy(
  value: unknown,
  auditNonce: Uint8Array,
): ScoringPolicy {
  const root = requireRecord(value, "scoring configuration");
  requireExactKeys(
    root,
    [
      "cluster",
      "environment",
      "revision",
      "weights_ppm",
      "thresholds_ppm",
    ],
    "scoring configuration",
  );

  const weights = requireRecord(root.weights_ppm, "weights_ppm");
  requireExactKeys(
    weights,
    ["biometric", "tts", "unallocated", "automation", "reputation"],
    "weights_ppm",
  );

  const thresholds = requireRecord(root.thresholds_ppm, "thresholds_ppm");
  requireExactKeys(thresholds, ["friction", "reject"], "thresholds_ppm");

  const ownedAuditNonce = copyAuditNonce(auditNonce);
  try {
    const policy: ScoringPolicy = {
      cluster: requireChoice(root.cluster, CLUSTER_IDS, "cluster"),
      environment: requireChoice(
        root.environment,
        ENVIRONMENT_IDS,
        "environment",
      ),
      revision: requireRevision(root.revision),
      auditNonce: ownedAuditNonce,
      biometricPpm: requirePpm(weights.biometric, "weights_ppm.biometric"),
      ttsPpm: requirePpm(weights.tts, "weights_ppm.tts"),
      unallocatedPpm: requirePpm(
        weights.unallocated,
        "weights_ppm.unallocated",
      ),
      automationPpm: requirePpm(
        weights.automation,
        "weights_ppm.automation",
      ),
      reputationPpm: requirePpm(
        weights.reputation,
        "weights_ppm.reputation",
      ),
      frictionThresholdPpm: requirePpm(
        thresholds.friction,
        "thresholds_ppm.friction",
      ),
      rejectThresholdPpm: requirePpm(
        thresholds.reject,
        "thresholds_ppm.reject",
      ),
    };

    validateScoringPolicy(policy);
    return policy;
  } catch (error: unknown) {
    ownedAuditNonce.fill(0);
    throw error;
  }
}

function validateScoringPolicy(policy: ScoringPolicy): void {
  requireChoice(policy.cluster, CLUSTER_IDS, "cluster");
  requireChoice(policy.environment, ENVIRONMENT_IDS, "environment");
  requireRevision(policy.revision);
  if (
    policy.auditNonce.length !== 32 ||
    policy.auditNonce.every((byte) => byte === 0)
  ) {
    throw new Error("audit nonce must contain 32 bytes and must not be all zeroes");
  }

  requirePpm(policy.biometricPpm, "biometric PPM");
  requirePpm(policy.ttsPpm, "TTS PPM");
  requirePpm(policy.unallocatedPpm, "unallocated PPM");
  requirePpm(policy.automationPpm, "automation PPM");
  requirePpm(policy.reputationPpm, "reputation PPM");
  requirePpm(policy.frictionThresholdPpm, "friction threshold PPM");
  requirePpm(policy.rejectThresholdPpm, "reject threshold PPM");

  const budget =
    policy.biometricPpm +
    policy.ttsPpm +
    policy.unallocatedPpm +
    policy.automationPpm +
    policy.reputationPpm;
  if (budget !== PARTS_PER_MILLION) {
    throw new Error("weights_ppm must sum to 1000000");
  }
  if (policy.frictionThresholdPpm >= policy.rejectThresholdPpm) {
    throw new Error("friction threshold must be lower than reject threshold");
  }

  const activeBudget = PARTS_PER_MILLION - policy.unallocatedPpm;
  if (policy.frictionThresholdPpm > activeBudget) {
    throw new Error("friction threshold exceeds the active scoring budget");
  }
  if (policy.rejectThresholdPpm >= activeBudget) {
    throw new Error("reject threshold must be below the active scoring budget");
  }
}

export function encodeScoringPayload(policy: ScoringPolicy): Buffer {
  validateScoringPolicy(policy);
  if (SERVICE.length !== 16) {
    throw new Error("internal service identifier has an invalid length");
  }
  const payload = Buffer.alloc(PAYLOAD_LENGTH);
  payload.writeUInt8(SCHEMA_VERSION, 0);
  SERVICE.copy(payload, 1);
  payload.writeUInt8(CLUSTER_IDS[policy.cluster], 17);
  payload.writeUInt8(ENVIRONMENT_IDS[policy.environment], 18);
  payload.writeBigUInt64LE(BigInt(policy.revision), 19);
  Buffer.from(policy.auditNonce).copy(payload, 27);

  const ppmFields = [
    policy.biometricPpm,
    policy.ttsPpm,
    policy.unallocatedPpm,
    policy.automationPpm,
    policy.reputationPpm,
    policy.frictionThresholdPpm,
    policy.rejectThresholdPpm,
  ];
  ppmFields.forEach((field, index) => {
    payload.writeUInt32LE(field, 59 + index * 4);
  });

  return payload;
}

function decodeCanonicalPublicKey(value: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = bs58.decode(value);
  } catch {
    throw new Error("expected authority must be canonical base58");
  }
  if (decoded.length !== nacl.sign.publicKeyLength || bs58.encode(decoded) !== value) {
    throw new Error("expected authority must be a canonical Solana public key");
  }
  return decoded;
}

function assertOutsidePublicWorktree(
  path: string,
  label: string,
  existing: boolean,
): void {
  const absolute = resolve(path);
  const candidate = existing
    ? realpathSync(absolute)
    : resolve(realpathSync(dirname(absolute)), basename(absolute));
  const location = relative(PUBLIC_WORKTREE, candidate);
  if (location === "" || (!location.startsWith("..") && !isAbsolute(location))) {
    throw new Error(`${label} must be outside the public executor worktree`);
  }
}

function readPrivateJson(
  path: string,
  label: string,
  maximumBytes: number,
): unknown {
  let descriptor: number | undefined;
  let encoded: Buffer | undefined;
  try {
    descriptor = openSync(
      path,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) {
      throw new Error(`${label} must be a regular file`);
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(`${label} permissions must not allow group or other access`);
    }
    if (stat.size > maximumBytes) {
      throw new Error(`${label} exceeds the maximum file size`);
    }
    encoded = readFileSync(descriptor);
    // Node strings cannot be zeroed. The short-lived CLI process is the final
    // boundary for the temporary UTF-8 copy created during JSON parsing.
    const text = encoded.toString("utf8");
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`${label} must contain valid JSON`);
    }
  } finally {
    encoded?.fill(0);
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
}

function readSigningKeypair(
  path: string,
  expectedAuthority: Uint8Array,
): Uint8Array {
  const parsed = readPrivateJson(path, "keypair file", KEYPAIR_FILE_MAX_BYTES);
  const values: number[] = [];
  let storedKey: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  let storedPublicKey: Uint8Array | undefined;
  let derived: nacl.SignKeyPair | undefined;
  let returningSecret = false;

  try {
    if (!Array.isArray(parsed) || parsed.length !== nacl.sign.secretKeyLength) {
      throw new Error("keypair file must contain a 64-byte Solana keypair array");
    }
    for (const value of parsed) {
      if (
        typeof value !== "number" ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > 255
      ) {
        throw new Error("keypair file must contain byte values only");
      }
      values.push(value);
    }

    storedKey = Uint8Array.from(values);
    seed = storedKey.slice(0, nacl.sign.seedLength);
    storedPublicKey = storedKey.slice(nacl.sign.seedLength);
    derived = nacl.sign.keyPair.fromSeed(seed);

    if (!timingSafeEqual(derived.publicKey, storedPublicKey)) {
      throw new Error("keypair file contains an inconsistent public key");
    }
    if (!timingSafeEqual(derived.publicKey, expectedAuthority)) {
      throw new Error("keypair does not match the expected scoring authority");
    }

    returningSecret = true;
    return derived.secretKey;
  } finally {
    if (Array.isArray(parsed)) {
      parsed.fill(0);
    }
    values.fill(0);
    storedKey?.fill(0);
    seed?.fill(0);
    storedPublicKey?.fill(0);
    derived?.publicKey.fill(0);
    if (!returningSecret) {
      derived?.secretKey.fill(0);
    }
  }
}

export function signScoringPolicy(
  policy: ScoringPolicy,
  secretKey: Uint8Array,
): SignedScoringConfig {
  const payload = encodeScoringPayload(policy);
  const message = Buffer.concat([DOMAIN, payload]);
  const signature = nacl.sign.detached(message, secretKey);
  try {
    return {
      bundle: `${bs58.encode(payload)}.${bs58.encode(signature)}`,
      configId: bs58.encode(createHash("sha256").update(message).digest()),
      revision: policy.revision,
    };
  } finally {
    payload.fill(0);
    message.fill(0);
    signature.fill(0);
  }
}

function parseCliOptions(args: readonly string[]): CliOptions {
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || !value || value.startsWith("--")) {
      throw new Error(
        "Usage: sign-scoring-config --config <path> --keypair <path> --expected-authority <pubkey> --output <path>",
      );
    }
    if (options.has(flag)) {
      throw new Error(`duplicate option: ${flag}`);
    }
    options.set(flag, value);
  }

  const expectedFlags = [
    "--config",
    "--keypair",
    "--expected-authority",
    "--output",
  ];
  if (
    options.size !== expectedFlags.length ||
    expectedFlags.some((flag) => !options.has(flag))
  ) {
    throw new Error(
      "Usage: sign-scoring-config --config <path> --keypair <path> --expected-authority <pubkey> --output <path>",
    );
  }

  return {
    configPath: options.get("--config")!,
    keypairPath: options.get("--keypair")!,
    expectedAuthority: options.get("--expected-authority")!,
    outputPath: options.get("--output")!,
  };
}

export function runCli(
  args: readonly string[],
  print: (line: string) => void = console.log,
): void {
  const options = parseCliOptions(args);
  assertOutsidePublicWorktree(
    options.configPath,
    "scoring configuration file",
    true,
  );
  assertOutsidePublicWorktree(options.keypairPath, "keypair file", true);
  assertOutsidePublicWorktree(options.outputPath, "output file", false);
  const expectedAuthority = decodeCanonicalPublicKey(options.expectedAuthority);
  const auditNonce = randomBytes(32);
  let policy: ScoringPolicy | undefined;
  let secretKey: Uint8Array | undefined;

  try {
    policy = parseScoringPolicy(
      readPrivateJson(
        options.configPath,
        "scoring configuration file",
        POLICY_FILE_MAX_BYTES,
      ),
      auditNonce,
    );
    secretKey = readSigningKeypair(options.keypairPath, expectedAuthority);
    const signed = signScoringPolicy(policy, secretKey);
    writeFileSync(options.outputPath, `${signed.bundle}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    print(`Output: ${resolve(options.outputPath)}`);
    print(`Revision: ${signed.revision}`);
    print(`Config ID: ${signed.configId}`);
  } finally {
    secretKey?.fill(0);
    expectedAuthority.fill(0);
    auditNonce.fill(0);
    policy?.auditNonce.fill(0);
  }
}

const isMainModule =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (isMainModule) {
  try {
    runCli(process.argv.slice(2));
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "signing failed";
    console.error(`Error: ${message}`);
    process.exitCode = 1;
  }
}
