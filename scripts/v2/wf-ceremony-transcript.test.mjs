/**
 * THE FLAG THAT SAYS THESE KEYS ARE REAL MUST BE UNREACHABLE BY ACCIDENT.
 *
 * `developmentOnly: false` is the entire security claim of the well-formedness lane. It is also
 * exactly the flag someone flips after running a script that printed a lot of output. These assert
 * that it is a function of the transcript rather than a flag: three distinct contributors per
 * circuit, a closing beacon, and a recorded verification AFTER that beacon, and a specific,
 * actionable refusal naming whichever is missing.
 */
import assert from "node:assert/strict";
// `fileURLToPath`, not `.pathname`: a file URL percent-encodes, so a checkout under a path with
// a space reads ".../space%20test/..." and fails ENOENT.
import { fileURLToPath } from "node:url";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  MINIMUM_CONTRIBUTIONS,
  assertPromotable,
  emptyTranscript,
  participantsFor,
  productionPinsHeader,
  readTranscript,
  recordBeacon,
  recordContribution,
  recordVerification,
  writeTranscript,
} from "./wf-ceremony-transcript.mjs";

/** Every circuit's phase-1 file, pinned. Schema 2 refuses a promotion without this. */
const phase1For = (circuits) => Object.fromEntries(circuits.map((c) => [c, {
  name: "powersOfTau28_hez_final_13.ptau", sha256: "a".repeat(64),
}]));

const CIRCUITS = ["wf_salt_binding", "wf_cred", "wf_pseudonym"];
const AT = "2026-08-17T12:00:00.000Z";
const BEACON = {
  publicRandomness: "d3adb33fd3adb33f", iterations: 10,
  source: "drand quicknet round 6389234", at: AT,
};

const contributed = (people = ["Ada", "Grace", "Katherine"]) => {
  let t = emptyTranscript(phase1For(CIRCUITS), CIRCUITS);
  for (const circuit of CIRCUITS) {
    for (const participant of people) {
      t = recordContribution(t, { participant, circuit, contributionHash: `0x${circuit}`, at: AT });
    }
  }
  return t;
};

const closed = () => {
  let t = recordBeacon(contributed(), BEACON);
  for (const circuit of CIRCUITS) t = recordVerification(t, { circuit, passed: true, at: AT });
  return t;
};

test("a complete ceremony promotes, and says who ran it", () => {
  const header = productionPinsHeader(closed());
  assert.equal(header.developmentOnly, false);
  assert.equal(header.profile, "gap-wf-production");
  assert.deepEqual(header.contributors, ["Ada", "Grace", "Katherine"]);
  assert.equal(header.beacon.publicRandomness, BEACON.publicRandomness);
});

test("too few parties refuses, and names the circuit and the shortfall", () => {
  assert.throws(
    () => assertPromotable(recordBeacon(contributed(["Ada", "Grace"]), BEACON)),
    (error) => /wf_cred: 2 distinct contributor\(s\), needs 3/.test(error.message),
  );
  assert.equal(MINIMUM_CONTRIBUTIONS, 3);
});

test("one person contributing twice is one party, not two", () => {
  const twice = contributed(["Ada", "Grace"]);
  assert.throws(
    () => recordContribution(twice, {
      participant: "Ada", circuit: "wf_cred", contributionHash: "0xagain", at: AT,
    }),
    /has already contributed to wf_cred/,
  );
  assert.equal(participantsFor(twice, "wf_cred").size, 2);
});

test("no beacon refuses: the last contributor must not also be the last word", () => {
  assert.throws(() => assertPromotable(contributed()), /no closing beacon/);
});

test("a contribution cannot follow the beacon", () => {
  assert.throws(
    () => recordContribution(recordBeacon(contributed(), BEACON), {
      participant: "Mallory", circuit: "wf_cred", contributionHash: "0x", at: AT,
    }),
    /beacon has already closed/,
  );
});

test("an unverified or failed circuit refuses", () => {
  let missing = recordBeacon(contributed(), BEACON);
  missing = recordVerification(missing, { circuit: "wf_cred", passed: true, at: AT });
  assert.throws(() => assertPromotable(missing), /wf_salt_binding: no recorded snarkjs zkey verify/);

  let failed = closed();
  failed = recordVerification(failed, { circuit: "wf_pseudonym", passed: false, at: AT });
  assert.throws(() => assertPromotable(failed), /wf_pseudonym: recorded verification FAILED/);
});

test("verifying before the beacon is refused: it describes a key nobody ships", () => {
  assert.throws(
    () => recordVerification(contributed(), { circuit: "wf_cred", passed: true, at: AT }),
    /verify after the beacon/,
  );
});

test("a re-beacon clears stale verifications, so old passes cannot carry a new key", () => {
  const reopened = recordBeacon(closed(), { ...BEACON, publicRandomness: "0123456789abcdef" });
  assert.deepEqual(reopened.verifications, []);
  assert.throws(() => assertPromotable(reopened), /no recorded snarkjs zkey verify/);
});

test("a participant name is a name, not a path", () => {
  for (const bad of ["../escape", "a/b", "", "x", "a".repeat(80)]) {
    assert.throws(
      () => recordContribution(emptyTranscript(phase1For(CIRCUITS), CIRCUITS), {
        participant: bad, circuit: "wf_cred", contributionHash: "0x", at: AT,
      }),
      /is not a usable name/,
      JSON.stringify(bad),
    );
  }
});

test("a transcript round-trips, and a foreign one is refused rather than half-read", () => {
  const dir = mkdtempSync(join(tmpdir(), "gap-wf-ceremony-"));
  try {
    const path = join(dir, "nested", "transcript.json");
    writeTranscript(path, closed());
    assert.deepEqual(readTranscript(path).contributions.length, CIRCUITS.length * 3);
    assert.equal(readTranscript(join(dir, "absent.json")), undefined);
    writeTranscript(path, { ...closed(), schemaVersion: 99 });
    assert.throws(() => readTranscript(path), /not a version 2 ceremony transcript/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a ceremony whose phase-1 file is not pinned cannot be promoted", () => {
  // Three contributors and a closing beacon over a SUBSTITUTED phase-1 file are worth nothing:
  // the trapdoor everyone contributed to destroying was never the one in play. A transcript that
  // records only a filename cannot tell those two ceremonies apart.
  let t = emptyTranscript(phase1For(CIRCUITS), CIRCUITS);
  for (const circuit of CIRCUITS) {
    for (const who of ["ana", "ben", "cleo"]) {
      t = recordContribution(t, { participant: who, circuit, contributionHash: "0x" + "1".repeat(64), at: AT });
    }
  }
  t = recordBeacon(t, {
    publicRandomness: "2".repeat(64), iterations: 10,
    source: "drand quicknet round 6389234", at: AT,
  });
  // After the beacon, deliberately: a verification recorded before it describes a key nobody ships.
  for (const circuit of CIRCUITS) {
    t = recordVerification(t, { circuit, passed: true, at: AT });
  }
  assert.doesNotThrow(() => assertPromotable(t));

  const unpinned = { ...t, phase1: Object.fromEntries(CIRCUITS.map((c) => [c, { name: "x.ptau" }])) };
  assert.throws(() => assertPromotable(unpinned), /not pinned by sha256/);

  const bogus = { ...t, phase1: Object.fromEntries(CIRCUITS.map((c) => [c, { name: "x.ptau", sha256: "nope" }])) };
  assert.throws(() => assertPromotable(bogus), /not pinned by sha256/);
});

test("the ceremony covers the circuits whose verifiers are DEPLOYED, not just the wf set", () => {
  // S-3. The harness used to cover wf_cred, wf_pseudonym and wf_salt_binding, and not the
  // session circuit whose verifier gates every transfer. The multi-contributor gate was pointed
  // at the three circuits that matter least, so a promoted ceremony proved nothing about the one
  // an attacker would forge against.
  const harness = readFileSync(
    fileURLToPath(new URL("./wf-ceremony.sh", import.meta.url)), "utf8",
  );
  for (const circuit of ["session"]) {
    // Anchored to an ACTIVE table entry. A bare substring match also accepts a commented-out
    // line, which is exactly how this circuit would leave the ceremony in practice: the first
    // red-first run of this guard passed against `#"session:src/...` and proved it.
    assert.match(
      harness, new RegExp(`^\\s*"${circuit}:`, "m"),
      `${circuit} must be an active entry in the ceremony: its verifier is deployed`,
    );
  }
  // And it must be set up against the 2^16 phase-1: session is 59,143 constraints, so a 2^13
  // file cannot hold it.
  assert.match(harness, /"session:[^"]*:\$PTAU_16"/);
});

test("promotion is decided by the transcript, never by a marker in generated Solidity", () => {
  // Every development verifier now stamps LOCAL_DEVELOPMENT_ARTIFACT, but the marker still cannot
  // decide promotion, because it only ever reads in ONE direction. Presence is a confession and
  // is trustworthy. Absence is not evidence of a ceremony: a hand-rolled verifier, one built
  // before the marker existed, or one from any tool that does not stamp it is equally unmarked
  // and equally forgeable. The only positive evidence is the transcript: distinct contributors,
  // a closing beacon with a traceable source, a passing post-beacon verify, and a pinned phase-1.
  const source = readFileSync(
    fileURLToPath(new URL("./wf-ceremony-transcript.mjs", import.meta.url)), "utf8",
  );
  assert.doesNotMatch(
    source, /LOCAL_DEVELOPMENT_ARTIFACT/,
    "promotion must not consult a marker in generated Solidity",
  );
  for (const required of ["MINIMUM_CONTRIBUTIONS", "beacon", "verifications", "phase1"]) {
    assert.match(source, new RegExp(required), `${required} is part of the promotion decision`);
  }
});

test("a beacon with no traceable source cannot close a ceremony", () => {
  // A bare hex string is not public randomness: it is a number somebody typed. The closing
  // beacon's whole purpose is that nobody could have chosen it in advance and everybody can check
  // it afterwards; neither is verifiable without knowing WHICH beacon it was.
  assert.throws(
    () => recordBeacon(contributed(), { ...BEACON, source: undefined }),
    /SOURCE an auditor can check/,
  );
  assert.throws(
    () => recordBeacon(contributed(), { ...BEACON, source: "  " }),
    /SOURCE an auditor can check/,
  );
  const closedWithoutSource = { ...closed(), beacon: { publicRandomness: "ab".repeat(8), iterations: 10 } };
  assert.throws(() => assertPromotable(closedWithoutSource), /names no source/);
});
