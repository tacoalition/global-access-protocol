/**
 * THE CEREMONY TRANSCRIPT, AND THE ONE GUARD THAT MATTERS.
 *
 * `pins.json` carries `developmentOnly: true` and `ceremony: "DEV_SINGLE_CONTRIBUTION"` because
 * the keys under it come from ONE contribution with a checked-in entropy string, run on one
 * machine by whoever typed the command. Anyone holding this repository can reproduce the toxic
 * waste, so a proof verified under those keys proves nothing to anyone but a local test.
 *
 * Flipping that flag is the entire security claim of the well-formedness lane, and it is exactly
 * the kind of flag that gets flipped by someone who "ran the ceremony script". So the flip is not
 * a flag here: it is a FUNCTION OF THE TRANSCRIPT, and the transcript records things a single
 * operator on a single machine cannot fake into existence:
 *
 *   1. contributions from DISTINCT named participants, at least `MINIMUM_CONTRIBUTIONS` of them;
 *   2. a closing BEACON over public randomness, which fixes the ceremony at a public instant and
 *      means the last contributor cannot also be the last word;
 *   3. a recorded `snarkjs zkey verify` PASS for every circuit, after the beacon.
 *
 * Miss any one and `assertPromotable` refuses by name. That is the whole point: the refusal is the
 * feature, and the message says which of the three is missing so an operator can finish rather
 * than guess.
 *
 * WHAT THIS CANNOT DO, stated plainly because it is the honest limit. Nothing here proves the
 * participants were independent people, that they used real entropy, or that they discarded it.
 * A transcript is a record of a process, not evidence of the secrecy that process was for. It
 * makes a single-contribution ceremony impossible to MISREPRESENT; it does not make a bad
 * ceremony good. Publish the transcript so a third party can judge it, step 3 of the follow-up
 * list in `build-wf.sh`, and treat that publication as part of the ceremony, not as paperwork.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Three, because two is a pair who can trivially be one person twice and one is what we have.
 * Raise it for a real production ceremony: this is a floor, not a target.
 */
export const MINIMUM_CONTRIBUTIONS = 3;

export const CEREMONY_SCHEMA_VERSION = 2;

/**
 * @param phase1 `{ [circuit]: { name, sha256 } }`: the phase-1 file each circuit was set up
 *   against, PINNED BY DIGEST.
 *
 * SCHEMA 2 CHANGED THIS FROM A BARE STRING, for two reasons. The circuits no longer share one
 * file: the wf set is sized to a 2^13 ptau and the session circuits need 2^16. And a ceremony
 * that records a phase-1 FILENAME proves nothing, three contributors and a closing beacon run
 * over a substituted phase-1 file are worth nothing, because the trapdoor everyone contributed
 * to destroying was never the one in play. `assertPromotable` refuses a circuit whose phase-1
 * file is not pinned.
 */
export function emptyTranscript(phase1, circuits) {
  return {
    schemaVersion: CEREMONY_SCHEMA_VERSION,
    ceremony: "MULTI_CONTRIBUTION_PHASE2",
    phase1,
    circuits,
    contributions: [],
    beacon: undefined,
    verifications: [],
  };
}

export function readTranscript(path) {
  if (!existsSync(path)) return undefined;
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  if (parsed?.schemaVersion !== CEREMONY_SCHEMA_VERSION) {
    throw new Error(`${path} is not a version ${CEREMONY_SCHEMA_VERSION} ceremony transcript`);
  }
  return parsed;
}

export function writeTranscript(path, transcript) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(transcript, null, 2)}\n`, { mode: 0o644 });
  return path;
}

/** A participant name is published in the transcript, so it must be a name and not a path. */
const PARTICIPANT = /^[A-Za-z0-9][A-Za-z0-9 ._-]{1,62}$/;

/**
 * A contribution, once. Re-running under a name already present is REFUSED rather than appended:
 * the count is the security parameter, and a script re-run must not inflate it.
 */
export function recordContribution(transcript, { participant, circuit, contributionHash, at }) {
  if (!PARTICIPANT.test(String(participant ?? ""))) {
    throw new Error(`participant ${JSON.stringify(participant)} is not a usable name`);
  }
  if (transcript.beacon) {
    throw new Error("the beacon has already closed this ceremony; contributions cannot follow it");
  }
  const already = transcript.contributions.some(
    (entry) => entry.participant === participant && entry.circuit === circuit,
  );
  if (already) {
    throw new Error(
      `${participant} has already contributed to ${circuit}. A second contribution under one name`
      + " does not add a party, and the count of parties is the security parameter",
    );
  }
  return {
    ...transcript,
    contributions: [...transcript.contributions, { participant, circuit, contributionHash, at }],
  };
}

/**
 * @param source WHERE the randomness came from, in words an auditor can act on, "drand quicknet
 *   round 6389234", "Bitcoin block 000000…". REQUIRED, because a bare hex string is not public
 *   randomness: it is a number somebody typed. The whole point of a closing beacon is that nobody
 *   could have chosen it in advance and everybody can check it afterwards, and neither property is
 *   verifiable without knowing which beacon it was.
 */
export function recordBeacon(transcript, { publicRandomness, iterations, source, at }) {
  if (!/^[0-9a-f]{16,128}$/.test(String(publicRandomness ?? ""))) {
    throw new Error("the beacon needs public randomness as lowercase hex, 8 to 64 bytes");
  }
  if (typeof source !== "string" || source.trim().length < 8) {
    throw new Error(
      "the beacon needs a SOURCE an auditor can check, e.g. 'drand quicknet round 6389234'. "
      + "Randomness with no provenance is a number somebody typed.",
    );
  }
  return {
    ...transcript,
    beacon: { publicRandomness, iterations, source: source.trim(), at },
    verifications: [],
  };
}

export function recordVerification(transcript, { circuit, passed, at }) {
  if (!transcript.beacon) {
    throw new Error("verify after the beacon: a verification before it describes a key nobody ships");
  }
  return {
    ...transcript,
    verifications: [
      ...transcript.verifications.filter((entry) => entry.circuit !== circuit),
      { circuit, passed, at },
    ],
  };
}

/** Distinct participant names, which is what "how many parties" actually means. */
export function participantsFor(transcript, circuit) {
  return new Set(
    transcript.contributions.filter((e) => e.circuit === circuit).map((e) => e.participant),
  );
}

/**
 * @returns nothing; THROWS with the specific unmet condition. Never returns a boolean, because a
 *   boolean invites `if (promotable) { ... }` and a caller that forgot the else.
 */
export function assertPromotable(transcript) {
  const shortfalls = [];
  for (const circuit of transcript.circuits) {
    const parties = participantsFor(transcript, circuit);
    if (parties.size < MINIMUM_CONTRIBUTIONS) {
      shortfalls.push(
        `${circuit}: ${parties.size} distinct contributor(s), needs ${MINIMUM_CONTRIBUTIONS}`,
      );
    }
    const verification = transcript.verifications.find((e) => e.circuit === circuit);
    if (!verification) shortfalls.push(`${circuit}: no recorded snarkjs zkey verify`);
    else if (!verification.passed) shortfalls.push(`${circuit}: recorded verification FAILED`);
    // The phase-1 pin. Without it the contributions above are ceremony theatre: every one of them
    // could have been made over a file nobody checked.
    const phase1 = transcript.phase1?.[circuit];
    if (!phase1?.sha256 || !/^[0-9a-f]{64}$/.test(phase1.sha256)) {
      shortfalls.push(`${circuit}: phase-1 file is not pinned by sha256`);
    }
  }
  if (!transcript.beacon) {
    shortfalls.push(
      "no closing beacon: without public randomness the last contributor is also the last word",
    );
  } else if (!transcript.beacon.source) {
    shortfalls.push(
      "the beacon names no source: a hex string nobody can trace is not public randomness",
    );
  }
  if (shortfalls.length) {
    throw new Error(
      "this ceremony cannot be promoted to production keys:\n  - "
      + `${shortfalls.join("\n  - ")}\n`
      + "developmentOnly stays true. See scripts/v2/wf-ceremony-transcript.mjs for why each of"
      + " these is required, and what a transcript still cannot prove.",
    );
  }
}

/** The pins header a PROMOTED ceremony earns. Only ever produced through `assertPromotable`. */
export function productionPinsHeader(transcript) {
  assertPromotable(transcript);
  return {
    profile: "gap-wf-production",
    developmentOnly: false,
    ceremony: transcript.ceremony,
    phase1: transcript.phase1,
    contributors: [...new Set(transcript.contributions.map((e) => e.participant))].sort(),
    beacon: transcript.beacon,
  };
}
