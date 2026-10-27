import assert from "node:assert/strict";
import test from "node:test";
import {
  BASE_FUND_CIRCUIT_METADATA,
  BASE_FUND_LOCAL_CIRCUIT_METADATA,
  GrantCoordinator,
  GrantQueue,
  LOCAL_CIRCUIT_METADATA,
  P,
  StaleWitnessError,
  assertCircuitMetadata,
  assertPublicSignals,
  createGapProver,
  sampleField,
  type ProverConfig,
  type TmEncryptionContext,
  type WitnessData,
  SPENDING_BLIND_TAG,
} from "../src/index";

test("circuit metadata freezes the 19-signal order and production depths", () => {
  assert.doesNotThrow(() => assertCircuitMetadata(BASE_FUND_CIRCUIT_METADATA));
  assert.equal(BASE_FUND_CIRCUIT_METADATA.publicSignals.length, 19);
  assert.deepEqual(BASE_FUND_CIRCUIT_METADATA.depths, {
    did: 16,
    spendingKey: 8,
    credential: 16,
    risk: 20,
  });
});

test("joined local metadata keeps Base Fund wallet-set depth without production ceremony claims", () => {
  assert.doesNotThrow(() => assertCircuitMetadata(BASE_FUND_LOCAL_CIRCUIT_METADATA));
  assert.deepEqual(BASE_FUND_LOCAL_CIRCUIT_METADATA.depths, {
    did: 16,
    spendingKey: 8,
    credential: 16,
    risk: 14,
  });
});

test("public signal validation rejects wrong lengths and out-of-field values", () => {
  assert.equal(assertPublicSignals(Array(19).fill("0")).length, 19);
  assert.throws(() => assertPublicSignals(Array(18).fill("0")), /expected 19/);
  assert.throws(
    () => assertPublicSignals([...Array(18).fill("0"), P.toString()]),
    /outside the BN254 field/,
  );
});

test("field sampling rejects zero and returns a nonzero field element", () => {
  let calls = 0;
  const random = () => {
    calls += 1;
    const bytes = new Uint8Array(32);
    if (calls > 1) bytes[31] = 7;
    return bytes;
  };
  assert.equal(sampleField(random), 7n);
  assert.equal(calls, 2);
});

test("grant queue cleans settled keys and stale retries rerun the complete task", async () => {
  const queue = new GrantQueue();
  assert.equal(await queue.enqueue("alice", async () => 42), 42);
  await Promise.resolve();
  assert.equal(queue.size, 0);

  const coordinator = new GrantCoordinator(undefined);
  let attempts = 0;
  const result = await coordinator.runWithStaleRetry(
    {
      chainId: 84532,
      sessionManager: "0x0000000000000000000000000000000000000001",
      account: "0x0000000000000000000000000000000000000002",
    },
    async () => {
      attempts += 1;
      if (attempts === 1) throw new StaleWitnessError();
      return "canonical";
    },
  );
  assert.equal(result, "canonical");
  assert.equal(attempts, 2);
});

class TinyTree {
  private values = new Map<bigint, bigint>();

  constructor(readonly depth: number) {}
  async init(): Promise<void> {}
  setByKey(key: bigint, value: bigint): void {
    this.values.set(key, value);
  }
  indexOf(key: bigint): number {
    return Number(key & ((1n << BigInt(this.depth)) - 1n));
  }
  root(): bigint {
    return [...this.values.values()].reduce((a, b) => (a + b) % P, 0n);
  }
  proof(index: number) {
    return {
      siblings: Array(this.depth).fill(0n),
      pathIndices: Array.from({ length: this.depth }, (_, i) => (index >> i) & 1),
    };
  }
}

const tinyHash = (left: bigint, right: bigint) =>
  (left * 31n + right * 17n + 1n) % P;

const tinyHash4 = (a: bigint, b: bigint, c: bigint, d: bigint) =>
  (a * 31n + b * 17n + c * 13n + d * 7n + 2n) % P;

const cryptoModule: ProverConfig["crypto"] = {
  h2: async (a, b) => tinyHash(BigInt(a as bigint), BigInt(b as bigint)),
  // Deliberately NOT a chain of h2: the real h4 is a genuine Poseidon(4), and a stub that
  // collapsed the two would hide a caller using the wrong fold. Same reasoning for h3, which also
  // has to be DISTINGUISHABLE from h2 so a caller using the wrong one is visible, see the
  // ikRefCommitment test at the end of this file.
  h3: async (a: unknown, b: unknown, c: unknown) =>
    (tinyHash(BigInt(a as bigint), BigInt(b as bigint)) * 7n + BigInt(c as bigint) * 13n + 5n) % P,
  h4: async (a, b, c, d) =>
    tinyHash4(BigInt(a as bigint), BigInt(b as bigint), BigInt(c as bigint), BigInt(d as bigint)),
  chain: async (items) =>
    items.reduce<bigint>(
      (acc, value) => (acc * 31n + BigInt(value as bigint) * 17n + 1n) % P,
      0n,
    ),
  SparseTree: TinyTree,
};

/** @param spendingBlind the holder's blind: the circuit's `skLeaf` carries it, so this must too. */
/** The salt the witness below carries; the blind derives from it, so they must agree. */
const LOCAL_SALT = 12n;

function oneWalletSpendingWitness(account: bigint, depth: number, spendingBlind: bigint) {
  const slot = Number(account & ((1n << BigInt(depth)) - 1n));
  const siblings: bigint[] = [];
  const pathIndices: number[] = [];
  let node = tinyHash(account, spendingBlind);
  let empty = 0n;
  for (let level = 0; level < depth; level += 1) {
    const path = (slot >> level) & 1;
    siblings.push(empty);
    pathIndices.push(path);
    node = path === 0 ? tinyHash(node, empty) : tinyHash(empty, node);
    empty = tinyHash(empty, empty);
  }
  return { root: node, siblings, pathIndices };
}

function witness(overrides: Partial<WitnessData> = {}): WitnessData {
  const depths = BASE_FUND_CIRCUIT_METADATA.depths;
  return {
    did: 11n,
    privateSalt: LOCAL_SALT,
    account: 13n,
    attrs: [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n],
    credExpiresAt: [9999n, 9999n],
    ikId0: 21n,
    ikId1: 22n,
    ita0: 0x100n,
    ita1: 0x200n,
    regime0: 31n,
    regime1: 32n,
    sessionManager: 0x300n,
    chainId: 84532n,
    policyId: 41n,
    policyVersion: 1n,
    validUntil: 9000n,
    accountNonce: 0n,
    gatedContract: 0x400n,
    ordbId: 0x500n,
    monitorKeyId: 51n,
    clauses: [
      { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 1n },
      { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 1n },
      { enabled: 1, groupId: 0, attrIndex: 2, op: 1, value: 1n },
      { enabled: 1, groupId: 0, attrIndex: 3, op: 1, value: 1n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    ],
    didRoot: 61n,
    credRoot0: 62n,
    credRoot1: 63n,
    didSiblings: Array(depths.did).fill(0n),
    didIndex: 11,
    spendingKeyWitness: oneWalletSpendingWitness(
      13n, depths.spendingKey, tinyHash(LOCAL_SALT, SPENDING_BLIND_TAG),
    ),
    cred0Siblings: Array(depths.credential).fill(0n),
    cred0Index: 11,
    cred1Siblings: Array(depths.credential).fill(0n),
    cred1Index: 11,
    rdb: {
      root: 64n,
      lowKey: 0n,
      nextKey: 0n,
      siblings: Array(depths.risk).fill(0n),
      index: 0,
    },
    ...overrides,
  };
}

test("production witness preserves independent identity anchors and injected encryption", async () => {
  let captured: TmEncryptionContext | undefined;
  const prover = createGapProver({
    crypto: cryptoModule,
    metadata: BASE_FUND_CIRCUIT_METADATA,
    randomBytes: () => {
      const bytes = new Uint8Array(32);
      bytes[31] = 9;
      return bytes;
    },
    tmCipher: {
      async encrypt(_plaintext, context) {
        captured = context;
        return "0x1234";
      },
    },
  });
  const result = await prover.buildSessionInputFromWitness(witness());
  assert.equal(result.input.ita0, "256");
  assert.equal(result.input.ita1, "512");
  assert.equal(result.input.chainId, "84532");
  assert.equal(result.input.blindingR, "9");
  assert.equal(result.ciphertext, "0x1234");
  assert.equal(captured?.policyVersion, 1n);
});

test("production profile rejects a collapsed two-anchor trust model", async () => {
  const prover = createGapProver({
    crypto: cryptoModule,
    metadata: BASE_FUND_CIRCUIT_METADATA,
    tmCipher: { encrypt: async () => "0x01" },
  });
  await assert.rejects(
    prover.buildSessionInputFromWitness(witness({ ita1: 0x100n })),
    /distinct identity anchors/,
  );
});

test("production server proving requires the verification-key artifact", async () => {
  const prover = createGapProver({
    crypto: cryptoModule,
    metadata: BASE_FUND_CIRCUIT_METADATA,
    groth16: {},
    wasm: { source: new Uint8Array([1]), sha256: `0x${"00".repeat(32)}` },
    zkey: { source: new Uint8Array([2]), sha256: `0x${"00".repeat(32)}` },
  });
  await assert.rejects(prover.proveInputServer({}), /verification-key artifact/);
});

test("production artifacts must match deployment-pinned circuit metadata", async () => {
  const artifact = { source: new Uint8Array([1]), sha256: `0x${"11".repeat(32)}` as const };
  const unpinned = createGapProver({
    crypto: cryptoModule,
    metadata: BASE_FUND_CIRCUIT_METADATA,
    groth16: {},
    wasm: artifact,
    zkey: artifact,
    verificationKey: artifact,
  });
  await assert.rejects(unpinned.proveInputServer({}), /metadata must pin/);

  const pinned = createGapProver({
    crypto: cryptoModule,
    metadata: {
      ...BASE_FUND_CIRCUIT_METADATA,
      artifactDigests: {
        wasm: `0x${"22".repeat(32)}`,
        zkey: artifact.sha256,
        verificationKey: artifact.sha256,
      },
    },
    groth16: {},
    wasm: artifact,
    zkey: artifact,
    verificationKey: artifact,
  });
  await assert.rejects(pinned.proveInputServer({}), /wasm reference/);
});

test("local profile retains an explicit, chain-31337-only regression cipher", async () => {
  const depths = LOCAL_CIRCUIT_METADATA.depths;
  const local = witness({
    chainId: 31337n,
    ita1: 0x100n,
    spendingKeyWitness: undefined,
    didSiblings: Array(depths.did).fill(0n),
    cred0Siblings: Array(depths.credential).fill(0n),
    cred1Siblings: Array(depths.credential).fill(0n),
    rdb: {
      root: 1n,
      lowKey: 0n,
      nextKey: 0n,
      siblings: Array(depths.risk).fill(0n),
      index: 0,
    },
  });
  const prover = createGapProver({
    crypto: cryptoModule,
    metadata: LOCAL_CIRCUIT_METADATA,
    allowInsecureLocalCipher: true,
    randomBytes: () => {
      const bytes = new Uint8Array(32);
      bytes[31] = 1;
      return bytes;
    },
  });
  // 0x + five 32-byte field elements. It was four (258 chars) until `ikBlind` joined the plaintext;
  // the cleartext stand-in has to carry every field or a monitor cannot reopen ikRefCommitment.
  assert.equal((await prover.buildSessionInputFromWitness(local)).ciphertext.length, 2 + 5 * 64);
});

/**
 * THE IDENTITY KEEPER MUST NOT BE RECOVERABLE FROM pub[17], asserted THROUGH THE BUILDER.
 *
 * `ikRefCommitment` was `Poseidon(ita0, ikId0)` over two public values, `ita0` is a contract address
 * and `ikId0` is emitted in the clear by `IKRegistered`, so it inverted by table lookup. On a live
 * chain that named the keeper in 6 of 6 sessions, with no keys.
 *
 * An earlier version called the hash helpers directly, which is a statement about Poseidon rather than
 * about this repository: reverting the builder to the unblinded form left it green. This runs the real
 * builder, and the mock's h2 and h3 are deliberately distinguishable, so a builder that went back to
 * h2(ita0, ikId0) would produce exactly the value asserted against.
 */
test("the Identity Keeper cannot be recovered from ikRefCommitment by table lookup", async () => {
  // A stub cipher: this test is about the COMMITMENT, not the envelope, and the builder refuses to
  // seal without one.
  const prover = createGapProver({
    crypto: cryptoModule,
    metadata: BASE_FUND_CIRCUIT_METADATA,
    tmCipher: { async encrypt() { return "0x01" as `0x${string}`; } },
  });
  const w = witness();

  // What an unblinded commitment would equal: the attacker builds this from public data alone.
  const tableEntry = String(await cryptoModule.h2(w.ita0, w.ikId0));

  const [a, b] = await Promise.all([
    prover.buildSessionInputFromWitness(w),
    prover.buildSessionInputFromWitness(w),
  ]);
  const refA = String((a.input as Record<string, unknown>).ikRefCommitment);
  const refB = String((b.input as Record<string, unknown>).ikRefCommitment);

  assert.notEqual(refA, tableEntry, "the builder must not emit the table-lookup value");
  assert.notEqual(refA, refB, "two sessions must not share one, or the keeper is still trackable");
});
