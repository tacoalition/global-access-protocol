import assert from "node:assert/strict";
import test from "node:test";
import { BN254_FIELD } from "../src/field";
import { assertDerivedPersonDid, derivePersonDid } from "../src/person-did";
import { LINK_A, LINK_B, PERSON_DID_KEY } from "./provider-fixture";

const base = { personDidKey: PERSON_DID_KEY, environment: "sandbox" } as const;

test("person DID is stable for the same person and distinct across people", () => {
  const first = derivePersonDid({ ...base, accountLinkId: LINK_A });
  const again = derivePersonDid({ ...base, accountLinkId: LINK_A });
  const other = derivePersonDid({ ...base, accountLinkId: LINK_B });
  assert.equal(first, again);
  assert.notEqual(first, other);
  assert.match(first, /^0x[0-9a-f]{64}$/);
});

test("person DID is a nonzero BN254 field element with no modular bias", () => {
  for (const link of [LINK_A, LINK_B]) {
    const value = BigInt(derivePersonDid({ ...base, accountLinkId: link }));
    assert.ok(value > 0n && value < BN254_FIELD);
    // 253-bit mask: strictly below 2^253, which is itself below the field order,
    // so the value is in-field without any reduction.
    assert.ok(value < 1n << 253n);
  }
});

test("rotating the IK key re-identifies the person", () => {
  const rotated = derivePersonDid({
    ...base, personDidKey: new Uint8Array(32).fill(9), accountLinkId: LINK_A,
  });
  assert.notEqual(rotated, derivePersonDid({ ...base, accountLinkId: LINK_A }));
});

test("person DID derivation fails closed on key length, environment, and link shape", () => {
  assert.throws(
    () => derivePersonDid({ ...base, personDidKey: new Uint8Array(31), accountLinkId: LINK_A }),
    /exactly 32 bytes/,
  );
  assert.throws(
    () => derivePersonDid({ ...base, environment: "production" as never, accountLinkId: LINK_A }),
    /unsupported person DID environment/,
  );
  for (const bad of ["gap-link-person-a", LINK_A.toUpperCase(), "", `${LINK_A} `]) {
    assert.throws(
      () => derivePersonDid({ ...base, accountLinkId: bad }),
      /canonical lowercase UUIDv4/,
      `expected refusal for ${JSON.stringify(bad)}`,
    );
  }
});

test("a supplied DID is cross-checked against the derivation rather than trusted", () => {
  const derived = derivePersonDid({ ...base, accountLinkId: LINK_A });
  assert.equal(assertDerivedPersonDid(derived, { ...base, accountLinkId: LINK_A }), derived);
  assert.equal(assertDerivedPersonDid(derived.toUpperCase().replace("0X", "0x"), { ...base, accountLinkId: LINK_A }), derived);
  // The historical demo fixture DID (1001) is no longer acceptable.
  assert.throws(
    () => assertDerivedPersonDid(`0x${BigInt(1001).toString(16).padStart(64, "0")}`, { ...base, accountLinkId: LINK_A }),
    /does not match the derived per-person DID/,
  );
  assert.throws(
    () => assertDerivedPersonDid(derived, { ...base, accountLinkId: LINK_B }),
    /does not match the derived per-person DID/,
  );
  assert.throws(() => assertDerivedPersonDid("0xdead", { ...base, accountLinkId: LINK_A }), /does not match/);
});
