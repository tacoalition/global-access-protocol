import assert from "node:assert/strict";
import test from "node:test";
import {
  BASE_FUND_CIRCUIT_METADATA,
  P,
  createGapProver,
  type ProverConfig,
  type SpendingKeyWitness,
  type WitnessData,
  SPENDING_BLIND_TAG,
} from "../src/index";

const h2 = (left: bigint, right: bigint) =>
  (left * 31n + right * 17n + 1n) % P;

class UnusedSparseTree {
  constructor(readonly _depth: number) {}
  async init(): Promise<void> {}
  setByKey(): void {}
  indexOf(): number { return 0; }
  root(): bigint { return 0n; }
  proof(): { siblings: bigint[]; pathIndices: number[] } {
    return { siblings: [], pathIndices: [] };
  }
}

const cryptoModule: ProverConfig["crypto"] = {
  h2: async (left, right) => h2(BigInt(left as bigint), BigInt(right as bigint)),
  // Unused by the spending-witness path; present so the port is satisfied. Deliberately distinct
  // from a chain of h2, see the real h4 in circuits/scripts/v2/gap_crypto.js.
  h3: async (a: unknown, b: unknown, c: unknown) => 0n,
  h4: async (a, b, c, d) =>
    [b, c, d].reduce<bigint>((acc, value) => h2(acc, BigInt(value as bigint)) + 1n, BigInt(a as bigint)),
  chain: async (items) => items.reduce<bigint>(
    (acc, value) => h2(acc, BigInt(value as bigint)),
    0n,
  ),
  SparseTree: UnusedSparseTree,
};

/**
 * @param spendingBlind the holder's blind. Every leaf carries it, exactly as the circuit's
 *   `skLeaf` does: a fixture that built unblinded leaves would agree with an unblinded builder
 *   and disagree with the circuit, which is how the blinding change reached the joined lane
 *   with this file still green.
 */
/** The salt `productionWitness` carries; the blind is derived from it, so they must not drift. */
const PRODUCTION_SALT = 12n;

function assignedSlotProof(
  entries: readonly { account: bigint; slot: number }[],
  targetSlot: number,
  depth: number,
  spendingBlind: bigint,
): SpendingKeyWitness {
  let nodes = Array<bigint>(2 ** depth).fill(0n);
  for (const entry of entries) nodes[entry.slot] = h2(entry.account, spendingBlind);
  const siblings: bigint[] = [];
  const pathIndices: number[] = [];
  let index = targetSlot;
  for (let level = 0; level < depth; level += 1) {
    siblings.push(nodes[index ^ 1]);
    pathIndices.push(index & 1);
    const parents: bigint[] = [];
    for (let offset = 0; offset < nodes.length; offset += 2) {
      parents.push(h2(nodes[offset], nodes[offset + 1]));
    }
    nodes = parents;
    index >>= 1;
  }
  return { root: nodes[0], siblings, pathIndices };
}

function productionWitness(spendingKeyWitness?: SpendingKeyWitness): WitnessData {
  const depths = BASE_FUND_CIRCUIT_METADATA.depths;
  return {
    did: 11n,
    privateSalt: PRODUCTION_SALT,
    account: 0x101n,
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
    spendingKeyWitness,
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
  };
}

function prover() {
  return createGapProver({
    crypto: cryptoModule,
    metadata: BASE_FUND_CIRCUIT_METADATA,
    randomBytes: () => new Uint8Array(32).fill(1),
    tmCipher: { encrypt: async () => "0x1234" },
  });
}

test("production input uses an explicit proof from a two-wallet assigned-slot root", async () => {
  const depth = BASE_FUND_CIRCUIT_METADATA.depths.spendingKey;
  const spending = assignedSlotProof(
    [
      { account: 1n, slot: 1 },
      { account: 0x101n, slot: 2 },
    ],
    2,
    depth,
    h2(PRODUCTION_SALT, SPENDING_BLIND_TAG),
  );
  const result = await prover().buildSessionInputFromWitness(productionWitness(spending));
  assert.equal(result.input.spendingKeyRoot, String(spending.root));
  assert.deepEqual(result.input.skSiblings, spending.siblings.map(String));
  assert.deepEqual(result.input.skPathIndices, spending.pathIndices.map(String));
});

test("production input rejects a missing or invalid explicit spending proof", async () => {
  await assert.rejects(
    prover().buildSessionInputFromWitness(productionWitness()),
    /requires an explicit spending-key witness/,
  );
  const depth = BASE_FUND_CIRCUIT_METADATA.depths.spendingKey;
  const spending = assignedSlotProof(
    [{ account: 0x101n, slot: 2 }], 2, depth, h2(PRODUCTION_SALT, SPENDING_BLIND_TAG),
  );
  await assert.rejects(
    prover().buildSessionInputFromWitness(productionWitness({ ...spending, root: spending.root + 1n })),
    /does not match its root/,
  );
});

test("production cannot opt into the local one-wallet fallback or insecure cipher", async () => {
  await assert.rejects(
    createGapProver({
      crypto: cryptoModule,
      metadata: BASE_FUND_CIRCUIT_METADATA,
      allowInsecureLocalCipher: true,
    }).buildSessionInputFromWitness(productionWitness()),
    /requires an explicit spending-key witness/,
  );

  const depth = BASE_FUND_CIRCUIT_METADATA.depths.spendingKey;
  const spending = assignedSlotProof(
    [{ account: 0x101n, slot: 1 }], 1, depth, h2(PRODUCTION_SALT, SPENDING_BLIND_TAG),
  );
  await assert.rejects(
    createGapProver({
      crypto: cryptoModule,
      metadata: BASE_FUND_CIRCUIT_METADATA,
      allowInsecureLocalCipher: true,
      randomBytes: () => new Uint8Array(32).fill(1),
    }).buildSessionInputFromWitness(productionWitness(spending)),
    /authenticated TM cipher is required/,
  );
});
