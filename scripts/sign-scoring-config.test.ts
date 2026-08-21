import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, test } from "node:test";
import bs58 from "bs58";
import nacl from "tweetnacl";
import {
  encodeScoringPayload,
  parseScoringPolicy,
  signScoringPolicy,
} from "./sign-scoring-config.ts";

const SCRIPT_PATH = fileURLToPath(
  new URL("./sign-scoring-config.ts", import.meta.url),
);
const SCRIPT_DIRECTORY = resolve(fileURLToPath(new URL(".", import.meta.url)));
const DOMAIN = Buffer.from("Entros\0executor-scoring-config\0v1\0", "ascii");
const NONCE_HEX = Array.from({ length: 32 }, (_, index) =>
  index.toString(16).padStart(2, "0"),
).join("");

const tempDirectories: string[] = [];

afterEach(() => {
  for (const directory of tempDirectories.splice(0)) {
    rmSync(directory, { recursive: true });
  }
});

function syntheticConfig(): Record<string, unknown> {
  return {
    cluster: "devnet",
    environment: "dev",
    revision: 1,
    weights_ppm: {
      biometric: 111_111,
      tts: 222_222,
      unallocated: 333_333,
      automation: 123_456,
      reputation: 209_878,
    },
    thresholds_ppm: {
      friction: 123_456,
      reject: 654_321,
    },
  };
}

function deterministicNonce(): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => index);
}

function syntheticPolicy(
  config: Record<string, unknown> = syntheticConfig(),
) {
  const nonce = deterministicNonce();
  try {
    return parseScoringPolicy(config, nonce);
  } finally {
    nonce.fill(0);
  }
}

function deterministicKeypair(): nacl.SignKeyPair {
  return nacl.sign.keyPair.fromSeed(
    Uint8Array.from({ length: 32 }, (_, index) => index + 1),
  );
}

function createPrivateFile(
  directory: string,
  name: string,
  contents: string,
): string {
  const path = join(directory, name);
  writeFileSync(path, contents, { encoding: "utf8", mode: 0o600 });
  return path;
}

function createFixture(): {
  directory: string;
  configPath: string;
  keypairPath: string;
  outputPath: string;
  authority: string;
} {
  const directory = mkdtempSync(join(tmpdir(), "entros-scoring-signer-"));
  tempDirectories.push(directory);
  const keypair = deterministicKeypair();
  const configPath = createPrivateFile(
    directory,
    "policy.json",
    `${JSON.stringify(syntheticConfig())}\n`,
  );
  const keypairPath = createPrivateFile(
    directory,
    "authority.json",
    `${JSON.stringify(Array.from(keypair.secretKey))}\n`,
  );
  const authority = bs58.encode(keypair.publicKey);
  keypair.secretKey.fill(0);
  keypair.publicKey.fill(0);
  return {
    directory,
    configPath,
    keypairPath,
    outputPath: join(directory, "bundle.txt"),
    authority,
  };
}

function executeCli(fixture: ReturnType<typeof createFixture>) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      SCRIPT_PATH,
      "--config",
      fixture.configPath,
      "--keypair",
      fixture.keypairPath,
      "--expected-authority",
      fixture.authority,
      "--output",
      fixture.outputPath,
    ],
    {
      cwd: SCRIPT_DIRECTORY,
      encoding: "utf8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    },
  );
}

describe("fixed scoring payload", () => {
  test("matches the agreed Borsh byte layout", () => {
    const policy = syntheticPolicy();
    const payload = encodeScoringPayload(policy);
    assert.equal(payload.length, 87);
    assert.equal(
      payload.toString("hex"),
      "01656e74726f732d6578656375746f720001010100000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f07b201000e6403001516050040e20100d633030040e20100f1fb0900",
    );
    policy.auditNonce.fill(0);
  });

  test("signs the domain and raw payload as one canonical bundle", () => {
    const policy = syntheticPolicy();
    const keypair = deterministicKeypair();
    const signed = signScoringPolicy(policy, keypair.secretKey);
    const parts = signed.bundle.split(".");
    assert.equal(parts.length, 2);
    const payload = bs58.decode(parts[0]);
    const signature = bs58.decode(parts[1]);
    assert.equal(bs58.encode(payload), parts[0]);
    assert.equal(bs58.encode(signature), parts[1]);
    assert.equal(
      nacl.sign.detached.verify(
        Buffer.concat([DOMAIN, payload]),
        signature,
        keypair.publicKey,
      ),
      true,
    );
    assert.equal(signed.configId, "2xErAkDVeReZF517Qroi2UaDxMtnUh75yqFzz71dnh9A");
    keypair.secretKey.fill(0);
    keypair.publicKey.fill(0);
    policy.auditNonce.fill(0);
  });
});

describe("policy validation", () => {
  test("rejects operator-supplied nonces and invalid injected nonces", () => {
    assert.throws(
      () => syntheticPolicy({ ...syntheticConfig(), extra: true }),
      /missing or unknown fields/,
    );
    assert.throws(
      () =>
        syntheticPolicy({
          ...syntheticConfig(),
          audit_nonce_hex: NONCE_HEX,
        }),
      /missing or unknown fields/,
    );
    assert.throws(
      () => parseScoringPolicy(syntheticConfig(), new Uint8Array(31)),
      /must contain 32 bytes/,
    );
    assert.throws(
      () => parseScoringPolicy(syntheticConfig(), new Uint8Array(32)),
      /must not be all zeroes/,
    );
  });

  test("rejects clusters outside the deployed runtime binding", () => {
    assert.throws(
      () => syntheticPolicy({ ...syntheticConfig(), cluster: "mainnet" }),
      /cluster is not supported/,
    );
  });

  test("rejects invalid budgets, thresholds, and revisions", () => {
    const badBudget = syntheticConfig();
    (badBudget.weights_ppm as Record<string, unknown>).biometric = 111_112;
    assert.throws(() => syntheticPolicy(badBudget), /must sum to 1000000/);

    const unordered = syntheticConfig();
    (unordered.thresholds_ppm as Record<string, unknown>).friction = 654_321;
    assert.throws(() => syntheticPolicy(unordered), /must be lower/);

    const unreachable = syntheticConfig();
    (unreachable.thresholds_ppm as Record<string, unknown>).reject = 666_667;
    assert.throws(() => syntheticPolicy(unreachable), /must be below/);

    assert.throws(
      () => syntheticPolicy({ ...syntheticConfig(), revision: 2 }),
      /revision must equal 1/,
    );
    assert.throws(
      () =>
        syntheticPolicy({
          ...syntheticConfig(),
          revision: Number.MAX_SAFE_INTEGER + 1,
        }),
      /revision must equal 1/,
    );
  });
});

describe("signing command", () => {
  test("writes one private bundle and prints only its release identifiers", () => {
    const fixture = createFixture();
    const result = executeCli(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.match(
      result.stdout,
      new RegExp(
        `^Output: ${fixture.outputPath}\\nRevision: 1\\nConfig ID: ([1-9A-HJ-NP-Za-km-z]+)\\n$`,
      ),
    );
    assert.equal(statSync(fixture.outputPath).mode & 0o777, 0o600);
    const bundle = readFileSync(fixture.outputPath, "utf8");
    assert.match(bundle, /^[1-9A-HJ-NP-Za-km-z]+\.[1-9A-HJ-NP-Za-km-z]+\n$/);
    const [payloadText, signatureText] = bundle.trim().split(".");
    assert.ok(payloadText);
    assert.ok(signatureText);
    const payload = Buffer.from(bs58.decode(payloadText));
    assert.equal(payload.length, 87);
    assert.equal(payload.subarray(27, 59).every((byte) => byte === 0), false);
    const expectedConfigId = bs58.encode(
      createHash("sha256").update(DOMAIN).update(payload).digest(),
    );
    assert.match(result.stdout, new RegExp(`Config ID: ${expectedConfigId}\\n$`));
    assert.notEqual(
      expectedConfigId,
      "2xErAkDVeReZF517Qroi2UaDxMtnUh75yqFzz71dnh9A",
    );
    payload.fill(0);
  });

  test("refuses to overwrite an existing output", () => {
    const fixture = createFixture();
    writeFileSync(fixture.outputPath, "preserve-me\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    const result = executeCli(fixture);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /Error: EEXIST:/);
    assert.equal(readFileSync(fixture.outputPath, "utf8"), "preserve-me\n");
  });

  test("rejects a keypair that does not match the expected authority", () => {
    const fixture = createFixture();
    const other = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(77));
    fixture.authority = bs58.encode(other.publicKey);
    other.secretKey.fill(0);
    other.publicKey.fill(0);
    const result = executeCli(fixture);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /does not match the expected scoring authority/);
    assert.equal(statSync(fixture.outputPath, { throwIfNoEntry: false }), undefined);
  });

  test("rejects a keypair with an inconsistent public-key suffix", () => {
    const fixture = createFixture();
    const values = JSON.parse(readFileSync(fixture.keypairPath, "utf8")) as number[];
    values[63] ^= 1;
    writeFileSync(fixture.keypairPath, `${JSON.stringify(values)}\n`, "utf8");
    values.fill(0);
    const result = executeCli(fixture);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /inconsistent public key/);
    assert.equal(statSync(fixture.outputPath, { throwIfNoEntry: false }), undefined);
  });

  test("refuses symlinked private inputs", () => {
    for (const input of ["configPath", "keypairPath"] as const) {
      const fixture = createFixture();
      const linkPath = join(fixture.directory, `${input}.link`);
      symlinkSync(fixture[input], linkPath);
      fixture[input] = linkPath;
      const result = executeCli(fixture);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /ELOOP|symbolic link|too many levels/i);
      assert.equal(
        statSync(fixture.outputPath, { throwIfNoEntry: false }),
        undefined,
      );
    }
  });

  test("rejects policy files exposed to group or other users", () => {
    const fixture = createFixture();
    chmodSync(fixture.configPath, 0o644);
    const result = executeCli(fixture);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /permissions must not allow group or other access/);
  });

  test("rejects oversized private inputs before reading them", () => {
    for (const input of ["configPath", "keypairPath"] as const) {
      const fixture = createFixture();
      writeFileSync(fixture[input], "0".repeat(20 * 1024), {
        encoding: "utf8",
        mode: 0o600,
      });
      const result = executeCli(fixture);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /exceeds the maximum file size/);
      assert.equal(
        statSync(fixture.outputPath, { throwIfNoEntry: false }),
        undefined,
      );
    }
  });

  test("keeps every private signing artifact outside the public worktree", () => {
    const privateInput = createFixture();
    privateInput.configPath = join(SCRIPT_DIRECTORY, "package.json");
    const inputResult = executeCli(privateInput);
    assert.equal(inputResult.status, 1);
    assert.match(inputResult.stderr, /outside the public executor worktree/);

    const privateOutput = createFixture();
    privateOutput.outputPath = join(
      SCRIPT_DIRECTORY,
      ".scoring-bundle-must-not-exist",
    );
    const outputResult = executeCli(privateOutput);
    assert.equal(outputResult.status, 1);
    assert.match(outputResult.stderr, /outside the public executor worktree/);
    assert.equal(
      statSync(privateOutput.outputPath, { throwIfNoEntry: false }),
      undefined,
    );
  });

  test("resolves parent directories before checking the worktree boundary", () => {
    const fixture = createFixture();
    const worktreeLink = join(fixture.directory, "public-worktree");
    symlinkSync(resolve(SCRIPT_DIRECTORY, ".."), worktreeLink);
    fixture.outputPath = join(worktreeLink, ".scoring-bundle-must-not-exist");

    const result = executeCli(fixture);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /outside the public executor worktree/);
    assert.equal(
      statSync(fixture.outputPath, { throwIfNoEntry: false }),
      undefined,
    );
  });
});
