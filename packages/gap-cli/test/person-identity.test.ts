// One human = one DID = one salt, across every wallet that human owns.
//
// These cover the two properties the per-person model has to hold before anything
// else is worth checking: the derivation is STABLE for a person and DISTINCT
// across people, and a persistent deployment can host the lane more than once.
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import {
  PERSON_SALT_DOMAIN,
  PUBLIC_SALT_FALLBACK_FLAG,
  derivePersonIdentity,
  derivePersonSalt,
  personDidKey,
  personSaltKey,
  personSaltMaterial,
  runScopedAccountLinkId,
} from "../src/person";
import { derivePersonDid } from "../../gap-identity-keeper-v2/src/person-did";

const BN254_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const ALICE = "8f1d6c2a-1b3e-4a7c-9d21-5c0e2f7a41b8";
const BOB = "2c9a4e70-63d5-4f18-8b6a-77e1c3d0951f";

const FLAG = "GAP_DEMO_ALLOW_PUBLIC_SALT";
const SUPPLIED_KEY = "GAP_DEMO_PERSON_SALT_KEY";

function withEnvironment(values: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

/**
 * Every derivation below runs on the PUBLIC demo-custody fallback, which is now
 * refused unless the operator asks for it by name. Acknowledging it here is the
 * point: these tests are the demo lane, and the lane must opt in like anyone else.
 */
withEnvironment({ [FLAG]: "1" });
afterEach(() => withEnvironment({ [FLAG]: "1", [SUPPLIED_KEY]: undefined }));

test("a person's DID and salt are stable and in-field, and differ across people", () => {
  const alice = derivePersonIdentity(ALICE);
  const bob = derivePersonIdentity(BOB);

  assert.deepEqual(derivePersonIdentity(ALICE), alice, "same person must re-derive identically");
  assert.notEqual(alice.did, bob.did);
  assert.notEqual(alice.privateSalt, bob.privateSalt);
  for (const value of [alice.did, alice.privateSalt, bob.did, bob.privateSalt]) {
    assert.ok(value > 0n && value < BN254_FIELD, "identity values must be BN254 field elements");
  }
  // 253-bit masking, not a mod-p reduction: no residue is over-represented.
  assert.ok(alice.did < 1n << 253n);
  assert.ok(alice.privateSalt < 1n << 253n);
});

test("the DID is THE per-person derivation, not a second implementation of it", () => {
  const identity = derivePersonIdentity(ALICE);
  const canonical = derivePersonDid({
    personDidKey: personDidKey(), environment: "sandbox", accountLinkId: ALICE,
  });
  assert.equal(identity.did, BigInt(canonical));
});

test("the salt is domain-separated from the DID and keyed by a DIFFERENT secret", () => {
  assert.equal(PERSON_SALT_DOMAIN, "DSI_PERSON_SALT_V1");
  // The IK holds the DID key by necessity; it must not thereby hold the salt.
  assert.notDeepEqual(Buffer.from(personDidKey()), Buffer.from(personSaltKey()));
  // And even under the DID key the salt derivation lands somewhere else entirely.
  const underDidKey = derivePersonSalt({
    personSaltKey: personDidKey(), environment: "sandbox", accountLinkId: ALICE,
  });
  assert.notEqual(underDidKey, derivePersonIdentity(ALICE).did);
});

test("derivations refuse anything that is not a canonical account link", () => {
  for (const bad of ["", "not-a-uuid", ALICE.toUpperCase(), "123e4567-e89b-12d3-a456-426614174000"]) {
    assert.throws(() => derivePersonIdentity(bad), /canonical lowercase UUIDv4/);
  }
  assert.throws(
    () => derivePersonSalt({
      personSaltKey: new Uint8Array(31), environment: "sandbox", accountLinkId: ALICE,
    }),
    /exactly 32 bytes/,
  );
});

test("a run scope gives one PERSISTENT deployment a fresh person per lane run", () => {
  // No scope: the fresh-chain lane keeps its stable, reproducible person.
  assert.equal(runScopedAccountLinkId(ALICE), ALICE);
  assert.equal(runScopedAccountLinkId(ALICE, "   "), ALICE);

  const runOne = runScopedAccountLinkId(ALICE, "run-1");
  const runTwo = runScopedAccountLinkId(ALICE, "run-2");
  assert.notEqual(runOne, ALICE);
  assert.notEqual(runOne, runTwo);
  assert.equal(runScopedAccountLinkId(ALICE, "run-1"), runOne, "a run scope is deterministic");

  // The point of the scope: no DID collision, so the second run can register a DID
  // and mint a credential rather than being refused as an existing identity.
  const dids = new Set([ALICE, runOne, runTwo].map((link) => derivePersonIdentity(link).did));
  assert.equal(dids.size, 3);

  // Two different people stay different under the same run scope.
  assert.notEqual(runScopedAccountLinkId(BOB, "run-1"), runOne);
});

// ---- salt custody: the public fallback is a demo, and must say so ----

test("the PUBLIC salt fallback refuses by name unless the demo flag asks for it", () => {
  withEnvironment({ [FLAG]: undefined, [SUPPLIED_KEY]: undefined });

  for (const call of [
    () => personSaltKey(),
    () => personSaltMaterial(),
    () => derivePersonIdentity(ALICE),
  ]) {
    assert.throws(call, (error: unknown) => {
      const { message } = error as Error;
      // Says what it would have done ...
      assert.match(message, /sha256/);
      assert.match(message, /gap-v2-local-person-salt-key-v1/);
      // ... why that is unacceptable ...
      assert.match(message, /de-anonymise|de-anonymize/);
      // ... and how a demo asks for it anyway.
      assert.match(message, new RegExp(FLAG));
      assert.match(message, new RegExp(SUPPLIED_KEY));
      return true;
    });
  }

  // Only an explicit "1" is an acknowledgement; a truthy-looking value is not.
  for (const value of ["0", "true", "yes", ""]) {
    withEnvironment({ [FLAG]: value });
    assert.throws(() => personSaltKey(), new RegExp(FLAG));
  }
});

test("the acknowledged fallback derives as before, stamped IK_CUSTODY_DEMO", () => {
  withEnvironment({ [FLAG]: "1", [SUPPLIED_KEY]: undefined });
  const material = personSaltMaterial();
  assert.equal(material.custodyModel, "IK_CUSTODY_DEMO");
  assert.equal(material.key.length, 32);
  // The flag changes the CUSTODY STORY, not the arithmetic: a lane that
  // acknowledged the fixture still gets the person it had before.
  assert.deepEqual(Buffer.from(personSaltKey()), Buffer.from(material.key));
  assert.equal(
    derivePersonIdentity(ALICE).privateSalt,
    derivePersonSalt({ personSaltKey: material.key, environment: "sandbox", accountLinkId: ALICE }),
  );
});

test("every identity carries the custody model its salt was derived under", () => {
  withEnvironment({ [FLAG]: "1", [SUPPLIED_KEY]: undefined });
  assert.equal(derivePersonIdentity(ALICE).custodyModel, "IK_CUSTODY_DEMO");

  // A supplied key is the holder's own key management: no flag needed, and the
  // artifact must NOT claim demo custody for it.
  withEnvironment({ [FLAG]: undefined, [SUPPLIED_KEY]: `0x${"7c".repeat(32)}` });
  const supplied = derivePersonIdentity(ALICE);
  assert.equal(supplied.custodyModel, "CLIENT_HELD");
  assert.equal(personSaltMaterial().custodyModel, "CLIENT_HELD");
  // Different key, therefore a different person-salt: the stamp tracks a real split.
  withEnvironment({ [FLAG]: "1", [SUPPLIED_KEY]: undefined });
  assert.notEqual(supplied.privateSalt, derivePersonIdentity(ALICE).privateSalt);
  assert.equal(supplied.did, derivePersonIdentity(ALICE).did, "the DID key is untouched");
});

test("a malformed supplied salt key is refused, flag or no flag", () => {
  for (const flag of ["1", undefined]) {
    withEnvironment({ [FLAG]: flag, [SUPPLIED_KEY]: "not-hex" });
    assert.throws(() => personSaltMaterial(), /32-byte hex secret/);
  }
});

test("a run-scoped link is still a canonical UUIDv4 the whole stack accepts", () => {
  const scoped = runScopedAccountLinkId(ALICE, "persistent-chain-run-17");
  assert.match(
    scoped,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  // It must survive the IK's own validator, which is what the launcher's bootstrap
  // cross-check runs against.
  assert.doesNotThrow(() => derivePersonDid({
    personDidKey: personDidKey(), environment: "sandbox", accountLinkId: scoped,
  }));
  assert.throws(() => runScopedAccountLinkId("nope", "run-1"), /canonical lowercase UUIDv4/);
});
