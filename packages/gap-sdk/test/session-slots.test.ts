// The ONE mirror of SessionManager's two-slot storage, tested as such.
//
// Every cell that talks to SessionManager now resolves sessions through `inspectNamedSession`, so
// these are the tests that stop the "live fields, staged digest" defect class coming back: they
// pin the selection rule, the field/digest pairing, and the refusal to guess when the two reads
// disagree.
import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeAbiParameters, keccak256, type Address, type Hex } from "viem";
import {
  computeSessionDigest,
  inspectNamedSession,
  selectNamedSessionSlot,
  type SessionSlotView,
} from "../src/session-slots";

const ACCOUNT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address;
const POLICY = `0x${"22".repeat(32)}` as Hex;
const SCOPE = "0x000000000000000000000000000000000000bf06" as Address;
const ORDB = "0x000000000000000000000000000000000000bf04" as Address;
const ZERO = "0x0000000000000000000000000000000000000000" as Address;

/** A never-written slot, exactly as the getters return one. */
const EMPTY: SessionSlotView = {
  validUntil: 0n,
  policyId: `0x${"00".repeat(32)}`,
  policyVersion: 0,
  gatedContract: ZERO,
  ordb: ZERO,
  attested: false,
  encryptedPseudonym: "0x",
};

const session = (over: Partial<SessionSlotView> = {}): SessionSlotView => ({
  validUntil: 1_786_229_710n,
  policyId: POLICY,
  policyVersion: 3,
  gatedContract: SCOPE,
  ordb: ORDB,
  attested: false,
  encryptedPseudonym: `0x${"ab".repeat(48)}`,
  ...over,
});

const scope = { policyId: POLICY, gatedContract: SCOPE, ordb: ORDB };

test("names the staged slot when a renewal is staged, the live slot otherwise", () => {
  const live = session({ attested: true });
  const pending = session({ validUntil: 1_786_229_872n });

  const staged = selectNamedSessionSlot({ live, pending });
  assert.equal(staged.staged, true);
  assert.equal(staged.session, pending);

  const direct = selectNamedSessionSlot({ live, pending: EMPTY });
  assert.equal(direct.staged, false);
  assert.equal(direct.session, live);
});

test("the fields and the digest always come from the SAME slot", () => {
  // The exact shape of the reported failure: the live slot still holds the previous attested
  // session while `sessionDigestOf` names the freshly staged one.
  const live = session({ attested: true });
  const pending = session({ validUntil: 1_786_229_872n });
  const named = computeSessionDigest(ACCOUNT, pending);

  const check = inspectNamedSession(ACCOUNT, { live, pending, named }, {
    nowSeconds: 1_786_229_000n,
    scope,
  });
  assert.equal(check.staged, true);
  assert.equal(check.digest, named);
  assert.equal(BigInt(check.session.validUntil), 1_786_229_872n);
  assert.equal(check.attested, false, "a stage is never installed already attested");
  assert.equal(check.digestMatchesNamed, true);
  assert.equal(check.present, true);
  assert.equal(check.expired, false);
  assert.equal(check.inScope, true);
  // The live session's digest is NOT what was resolved: that pairing is the defect.
  assert.notEqual(computeSessionDigest(ACCOUNT, live), check.digest);
});

test("a live-only session resolves to the live slot with the live digest", () => {
  const live = session({ attested: true });
  const check = inspectNamedSession(
    ACCOUNT,
    { live, pending: EMPTY, named: computeSessionDigest(ACCOUNT, live) },
    { nowSeconds: 1_786_229_000n, scope },
  );
  assert.equal(check.staged, false);
  assert.equal(check.attested, true);
  assert.equal(check.digestMatchesNamed, true);
  assert.equal(check.digest, computeSessionDigest(ACCOUNT, live));
});

test("a genuinely absent session is reported absent, not merely unexpired", () => {
  const check = inspectNamedSession(
    ACCOUNT,
    { live: EMPTY, pending: EMPTY, named: computeSessionDigest(ACCOUNT, EMPTY) },
    { nowSeconds: 1_786_229_000n, scope },
  );
  assert.equal(check.present, false);
  assert.equal(check.staged, false);
  assert.equal(check.inScope, false);
});

test("a digest naming the other slot is reported as skew, never quietly accepted", () => {
  const live = session({ attested: true });
  const pending = session({ validUntil: 1_786_229_872n });
  // `named` taken from the live slot while a stage exists: the slots moved between the reads, or
  // the contract's preimage drifted. Either way the caller cannot say which session it holds.
  const check = inspectNamedSession(ACCOUNT, {
    live, pending, named: computeSessionDigest(ACCOUNT, live),
  });
  assert.equal(check.digestMatchesNamed, false);
});

test("expiry and scope are reported as NOT CHECKED when the caller supplies neither", () => {
  const live = session({ attested: true });
  const check = inspectNamedSession(ACCOUNT, {
    live, pending: EMPTY, named: computeSessionDigest(ACCOUNT, live),
  });
  assert.equal(check.expired, null, "an unchecked fact must never read as a pass");
  assert.equal(check.inScope, null);
});

test("scope and expiry are evaluated against the NAMED slot, not the live one", () => {
  const live = session({ attested: true });
  const pending = session({ validUntil: 1n, gatedContract: ZERO });
  const check = inspectNamedSession(
    ACCOUNT,
    { live, pending, named: computeSessionDigest(ACCOUNT, pending) },
    { nowSeconds: 1_786_229_000n, scope },
  );
  assert.equal(check.expired, true);
  assert.equal(check.inScope, false);
});

test("the digest is SessionManager._digestOf's own preimage and excludes `attested`", () => {
  const granted = session();
  const promoted = session({ attested: true });
  // Promotion copies the staged session into the live slot and only then sets `attested`, so the
  // digest a monitor validated under must survive the promotion unchanged.
  assert.equal(
    computeSessionDigest(ACCOUNT, granted),
    computeSessionDigest(ACCOUNT, promoted),
  );
  assert.equal(
    computeSessionDigest(ACCOUNT, granted),
    keccak256(encodeAbiParameters(
      [
        { type: "address" }, { type: "bytes32" }, { type: "uint32" }, { type: "uint64" },
        { type: "address" }, { type: "address" }, { type: "bytes" },
      ],
      [
        ACCOUNT.toLowerCase() as Address,
        granted.policyId,
        Number(granted.policyVersion),
        BigInt(granted.validUntil),
        granted.gatedContract.toLowerCase() as Address,
        granted.ordb.toLowerCase() as Address,
        granted.encryptedPseudonym,
      ],
    )),
  );
});
