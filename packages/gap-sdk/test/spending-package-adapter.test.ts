import assert from "node:assert/strict";
import test from "node:test";
import {
  GAP_SPENDING_WALLET_SET_V2_PROFILE,
  GAP_SPENDING_WALLET_SET_V2_SCHEMA,
  P,
  spendingKeyWitnessFromV2Package,
} from "../src/index";

const bytes32 = (value: bigint) => `0x${value.toString(16).padStart(64, "0")}`;

function packaged() {
  return {
    profile: GAP_SPENDING_WALLET_SET_V2_PROFILE,
    schemaVersion: GAP_SPENDING_WALLET_SET_V2_SCHEMA,
    revision: 2n,
    assignedSlot: 2,
    root: bytes32(9n),
    siblings: Array.from({ length: 8 }, (_, index) => bytes32(BigInt(index))),
    pathIndices: [0, 1, 0, 0, 0, 0, 0, 0],
  };
}

test("V2 package membership converts to an SDK spending-key witness", () => {
  const input = packaged();
  const witness = spendingKeyWitnessFromV2Package(input);
  assert.equal(witness.root, 9n);
  assert.deepEqual(witness.siblings, Array.from({ length: 8 }, (_, index) => BigInt(index)));
  assert.deepEqual(witness.pathIndices, input.pathIndices);
  assert.notEqual(witness.pathIndices, input.pathIndices);
});

test("adapter rejects malformed or non-field roots and siblings", () => {
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), root: "0x01" }),
    /root must be exactly 32 bytes/,
  );
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), root: bytes32(P) }),
    /root is outside the BN254 field/,
  );
  const malformedSibling = packaged();
  malformedSibling.siblings[3] = "0x01";
  assert.throws(
    () => spendingKeyWitnessFromV2Package(malformedSibling),
    /sibling 3 must be exactly 32 bytes/,
  );
  const nonFieldSibling = packaged();
  nonFieldSibling.siblings[4] = bytes32(P);
  assert.throws(
    () => spendingKeyWitnessFromV2Package(nonFieldSibling),
    /sibling 4 is outside the BN254 field/,
  );
});

test("adapter rejects wrong profile, schema, revision, and assigned-slot path", () => {
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), profile: "GAP_SPENDING_WALLET_SET_V1" }),
    /wrong profile/,
  );
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), schemaVersion: 1 }),
    /wrong schema/,
  );
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), siblings: packaged().siblings.slice(1) }),
    /eight siblings/,
  );
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), pathIndices: packaged().pathIndices.slice(1) }),
    /eight path indices/,
  );
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), revision: 0n }),
    /revision must be nonzero uint64/,
  );
  assert.throws(
    () => spendingKeyWitnessFromV2Package({ ...packaged(), assignedSlot: 3 }),
    /path does not match assigned slot/,
  );
});

test("adapter rejects every omitted V2 package identity field", () => {
  const required = [
    "profile", "schemaVersion", "revision", "assignedSlot", "root", "siblings", "pathIndices",
  ] as const;
  const unchecked = (value: unknown) => spendingKeyWitnessFromV2Package(value);

  for (const field of required) {
    const input: Record<string, unknown> = { ...packaged() };
    delete input[field];
    assert.throws(
      () => unchecked(input),
      (error: unknown) => error instanceof Error,
      `missing ${field} must fail closed`,
    );
  }
});
