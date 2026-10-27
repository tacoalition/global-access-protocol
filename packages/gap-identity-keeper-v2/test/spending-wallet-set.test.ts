import assert from "node:assert/strict";
import test from "node:test";
import { computeOneLeafRoot } from "../src/credential-builder";
import { addressToField, createPoseidon2 } from "../src/field";
import {
  AssignedSlotSpendingWalletSet,
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
  type SpendingWalletMembershipProof,
} from "../src/spending-wallet-set";

/** One blind for this file: these tests are about slots and packaging, not about the blind. */
const TEST_BLIND = 0x5eedn;
const TEST_BLIND_HEX = `0x${TEST_BLIND.toString(16).padStart(64, "0")}` as `0x${string}`;

const wallet = (value: bigint) =>
  `0x${value.toString(16).padStart(40, "0")}` as const;

async function assertMembership(
  proof: SpendingWalletMembershipProof,
): Promise<void> {
  const hasher = await createPoseidon2();
  let node = BigInt(proof.leaf);
  for (let level = 0; level < proof.siblings.length; level += 1) {
    const sibling = BigInt(proof.siblings[level]);
    node = proof.pathIndices[level] === 0
      ? hasher.hash2(node, sibling)
      : hasher.hash2(sibling, node);
  }
  assert.equal(node, BigInt(proof.root));
}

/**
 * THE ROOT IS NO LONGER COMPUTABLE FROM THE ADDRESS ALONE, and that is the point.
 *
 * This test used to assert the opposite: that a one-wallet set produced the "frozen low-bit
 * root", `computeOneLeafRoot(H2(address, 0), address & 0xff, 8)`. Everything in that expression is
 * public, so anyone could evaluate it over a candidate address and match it against the
 * `spendingKeyRoot` DIDRegistryV2 publishes, recovering did↔wallet permanently
 * (SPENDING_SET_PRIVACY.md (full stack, not in this repository)). The leaf is blinded now, so the same computation gives a
 * DIFFERENT root, asserted below, because that inequality IS the security property.
 *
 * The slot is deliberately still the address's low bits: the slot is private witness, never
 * published, and changing it would buy nothing the blind does not already buy.
 */
test("one assigned wallet's root is blinded, so the public computation no longer reproduces it", async () => {
  const hasher = await createPoseidon2();
  const account = `0x${"11".repeat(20)}` as const;
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  const change = set.add(account, 0n);

  const slot = Number(addressToField(account) & 0xffn);
  const blinded = computeOneLeafRoot(
    hasher, hasher.hash2(addressToField(account), TEST_BLIND), slot, 8,
  );
  assert.equal(change.snapshot.root, `0x${blinded.toString(16).padStart(64, "0")}`);

  // What an observer with only the address can compute, and it is not this holder's root.
  const preimage = computeOneLeafRoot(
    hasher, hasher.hash2(addressToField(account), 0n), slot, 8,
  );
  assert.notEqual(
    change.snapshot.root,
    `0x${preimage.toString(16).padStart(64, "0")}`,
    "the published root must not be a keyless function of the address",
  );

  assert.equal(change.snapshot.profile, GAP_SPENDING_WALLET_SET_V2);
  assert.equal(change.snapshot.schemaVersion, SPENDING_WALLET_SET_SCHEMA_VERSION);
  assert.equal(change.snapshot.spendingBlind, TEST_BLIND_HEX);
  assert.equal(change.membership?.slot, slot);
  await assertMembership(change.membership!);
});

test("two wallets share one root and receive valid membership proofs", async () => {
  const hasher = await createPoseidon2();
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(wallet(1n), 0n);
  const second = set.add(wallet(2n), 1n);
  const proofs = set.proofs();
  assert.equal(proofs.length, 2);
  assert.equal(proofs[0].root, second.snapshot.root);
  assert.equal(proofs[1].root, second.snapshot.root);
  await Promise.all(proofs.map(assertMembership));
});

test("low-bit collisions receive stable unique assigned slots", async () => {
  const hasher = await createPoseidon2();
  const first = wallet(1n);
  const collision = wallet(0x101n);
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(first, 0n);
  set.add(collision, 1n);
  assert.equal(set.proof(first).slot, 1);
  assert.equal(set.proof(collision).slot, 2);

  const restored = new AssignedSlotSpendingWalletSet(hasher, null, set.snapshot());
  assert.equal(restored.proof(first).slot, 1);
  assert.equal(restored.proof(collision).slot, 2);
  await assertMembership(restored.proof(collision));
});

test("add and remove use expected revisions without moving surviving wallets", async () => {
  const hasher = await createPoseidon2();
  const first = wallet(1n);
  const second = wallet(0x101n);
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(first, 0n);
  set.add(second, 1n);
  const rootBeforeStaleWrite = set.root();
  assert.throws(() => set.remove(first, 1n), /stale spending wallet revision/);
  assert.equal(set.root(), rootBeforeStaleWrite);

  const removal = set.remove(first, 2n);
  assert.equal(removal.snapshot.revision, 3n);
  assert.deepEqual(removal.snapshot.assignments, [{ account: second, slot: 2 }]);
  assert.equal(set.proof(second).slot, 2);
  assert.throws(() => set.proof(first), /not assigned/);
  await assertMembership(set.proof(second));

  const replacement = set.add(wallet(0x201n), 3n);
  assert.equal(replacement.snapshot.revision, 4n);
  assert.equal(replacement.membership?.slot, 1);
  assert.equal(set.proof(second).slot, 2);
});

test("invalid persisted assignments and duplicate mutations fail closed", async () => {
  const hasher = await createPoseidon2();
  const account = wallet(7n);
  const set = new AssignedSlotSpendingWalletSet(hasher, TEST_BLIND);
  set.add(account, 0n);
  assert.throws(() => set.add(account, 1n), /already assigned/);
  assert.throws(() => set.remove(wallet(8n), 1n), /not assigned/);
  assert.throws(
    () => new AssignedSlotSpendingWalletSet(hasher, null, {
      profile: GAP_SPENDING_WALLET_SET_V2,
      schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
      spendingBlind: TEST_BLIND_HEX,
      revision: 1n,
      depth: 8,
      assignments: [
        { account: wallet(1n), slot: 1 },
        { account: wallet(2n), slot: 1 },
      ],
    }),
    /duplicate spending wallet slot/,
  );
  assert.throws(
    () => new AssignedSlotSpendingWalletSet(hasher, null, {
      profile: GAP_SPENDING_WALLET_SET_V2,
      schemaVersion: 1 as typeof SPENDING_WALLET_SET_SCHEMA_VERSION,
      spendingBlind: TEST_BLIND_HEX,
      revision: 0n,
      depth: 8,
      assignments: [],
    }),
    /unsupported spending wallet set schema version/,
  );
  assert.throws(
    () => new AssignedSlotSpendingWalletSet(hasher, null, {
      profile: "GAP_SPENDING_WALLET_SET_V1" as typeof GAP_SPENDING_WALLET_SET_V2,
      // The CURRENT schema, so the PROFILE check is the one this case exercises.
      schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
      spendingBlind: TEST_BLIND_HEX,
      revision: 0n,
      depth: 8,
      assignments: [],
    }),
    /unsupported spending wallet set profile/,
  );
});
