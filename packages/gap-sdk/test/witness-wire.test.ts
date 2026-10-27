/**
 * The witness wire is the ONLY thing standing between "the Identity Keeper assembled this"
 * and "the holder's device proved it". Everything asserted here is about that crossing:
 * a round trip that loses nothing, and a decoder that refuses rather than coerces.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  P,
  WITNESS_WIRE_VERSION,
  decodeWitnessWire,
  encodeWitnessWire,
  type WitnessData,
} from "../src/index";

function witness(overrides: Partial<WitnessData> = {}): WitnessData {
  return {
    did: 7n,
    privateSalt: 11n,
    account: 0x1234n,
    attrs: [840n, 0n, 840n, 0n, 1n, 1n, 0n, 0n],
    credExpiresAt: [1_900_000_000n, 1_900_000_001n],
    ikId0: 21n,
    ikId1: 22n,
    ita0: 31n,
    ita1: 32n,
    regime0: 41n,
    regime1: 42n,
    sessionManager: 51n,
    chainId: 84532n,
    policyId: 61n,
    policyVersion: 3n,
    validUntil: 1_800_000_000n,
    accountNonce: 5n,
    gatedContract: 71n,
    ordbId: 81n,
    monitorKeyId: 91n,
    clauses: [
      { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n },
      { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },
      { enabled: 1, groupId: 0, attrIndex: 4, op: 1, value: 1n },
      { enabled: 1, groupId: 0, attrIndex: 5, op: 1, value: 1n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    ],
    didRoot: 101n,
    credRoot0: 102n,
    credRoot1: 103n,
    didSiblings: [1n, 2n, 3n],
    didIndex: 4,
    spendingKeyWitness: { root: 200n, siblings: [5n, 6n], pathIndices: [0, 1] },
    cred0Siblings: [7n],
    cred0Index: 1,
    cred1Siblings: [8n],
    cred1Index: 2,
    rdb: { root: 301n, lowKey: 0n, nextKey: 302n, siblings: [9n, 10n], index: 3 },
    ...overrides,
  };
}

test("a witness survives the crossing unchanged, field for field", () => {
  const original = witness();
  const restored = decodeWitnessWire(JSON.parse(JSON.stringify(encodeWitnessWire(original))));
  assert.deepEqual(restored, original);
});

test("a witness without a wallet-set membership proof stays without one", () => {
  const original = witness();
  delete (original as { spendingKeyWitness?: unknown }).spendingKeyWitness;
  const restored = decodeWitnessWire(encodeWitnessWire(original));
  assert.equal("spendingKeyWitness" in restored, false);
});

test("the wire declares its version and a device refuses a version it does not speak", () => {
  const wire = encodeWitnessWire(witness()) as unknown as Record<string, unknown>;
  assert.equal(wire.version, WITNESS_WIRE_VERSION);
  assert.throws(
    () => decodeWitnessWire({ ...wire, version: WITNESS_WIRE_VERSION + 1 }),
    /unsupported version/,
  );
});

test("a scalar at or above the BN254 modulus is refused, not wrapped", () => {
  const wire = { ...encodeWitnessWire(witness()), privateSalt: P.toString() };
  assert.throws(() => decodeWitnessWire(wire), /privateSalt is outside the BN254 field/);
});

test("a number where a field element belongs is refused rather than coerced", () => {
  // A JSON producer that "helpfully" emits 7 instead of "7" loses precision above 2^53,
  // so accepting it would silently corrupt exactly the large values that matter.
  const wire = { ...encodeWitnessWire(witness()), did: 7 };
  assert.throws(() => decodeWitnessWire(wire), /did must be a decimal string/);
});

test("a truncated fixed-width array is named, not padded", () => {
  const wire = { ...encodeWitnessWire(witness()), attrs: ["840", "0", "1"] };
  assert.throws(() => decodeWitnessWire(wire), /attrs must have 8 entries/);
});

test("a clause set that is not the circuit's four is refused", () => {
  const encoded = encodeWitnessWire(witness());
  const wire = { ...encoded, clauses: encoded.clauses.slice(0, 3) };
  assert.throws(() => decodeWitnessWire(wire), /clauses must be an array of six/);
});

test("a membership path whose indices are not binary is refused", () => {
  const encoded = encodeWitnessWire(witness());
  const wire = {
    ...encoded,
    spendingKeyWitness: { ...encoded.spendingKeyWitness!, pathIndices: [0, 2] },
  };
  assert.throws(() => decodeWitnessWire(wire), /pathIndices entries must be 0 or 1/);
});

test("a membership path and its siblings must pair up", () => {
  const encoded = encodeWitnessWire(witness());
  const wire = {
    ...encoded,
    spendingKeyWitness: { ...encoded.spendingKeyWitness!, pathIndices: [0] },
  };
  assert.throws(() => decodeWitnessWire(wire), /siblings and path indices must pair up/);
});

test("a negative merkle index is refused", () => {
  const wire = { ...encodeWitnessWire(witness()), didIndex: -1 };
  assert.throws(() => decodeWitnessWire(wire), /didIndex must be a non-negative integer/);
});

test("anything that is not an object is not a witness", () => {
  assert.throws(() => decodeWitnessWire(null), /witness must be an object/);
  assert.throws(() => decodeWitnessWire([]), /witness must be an object/);
});
