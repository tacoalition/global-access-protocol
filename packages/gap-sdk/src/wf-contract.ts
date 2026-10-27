// GAP v2; THE IDENTITY KEEPER'S WELL-FORMEDNESS VERIFIER: INPUT CONTRACT (design only).
//
// This module is types and constants. It implements nothing; the next slice wires it into
// `services/gap-ik-api`. It exists now so the shape the device must submit, and the checks the IK
// must make, are fixed BEFORE either side is written: the two have to agree field for field, and
// a contract discovered by writing one end first is a contract shaped by that end's convenience.
//
// ════════════════════════════════════════════════════════════════════════════════════════════
// WHAT CHANGED, AND WHY THERE IS ANYTHING TO VERIFY AT ALL
// ════════════════════════════════════════════════════════════════════════════════════════════
// Under IK custody the Keeper holds the salt, so it answers every question by recomputing:
// `assertSaltMatchesCommitment` rehashes the salt (`.../regulatory/salt-commitment.ts`),
// `computeCredentialLeaf` rebuilds the leaf (`gap-identity-keeper-v2/src/credential-builder.ts`),
// `PoseidonPseudonymComputer.compute` folds the pseudonym (`.../regulatory/pseudonym.ts`). All
// three take the salt as an argument.
//
// Under CLIENT custody (the `CLIENT_HELD` arm of `CustodyModel`, recorded write-once by the S0
// `CustodyModelRegistry` in gap-platform-core, where a change of model is a migration, not a
// write) the salt is on the holder's device and none of those three can run. The
// IK's choice is to anchor values it cannot check, or to check a proof instead. This contract is
// the second option: the device sends a Groth16 proof per statement, and the IK compares the
// proof's PUBLIC SIGNALS against records it already holds, then verifies the proof.
//
// THE ONE VALUE THE IK ACCEPTS RATHER THAN COMPUTES is the credential leaf. Everything that leaf
// commits to except the salt is a public signal compared field by field against the IK's own
// issuance record, and the salt is pinned by `saltCommitment` against the DID registry. The
// device's only remaining degree of freedom is a salt it cannot change without breaking that
// commitment, which is the whole statement.
//
// ════════════════════════════════════════════════════════════════════════════════════════════
// REQUIREMENT; THESE PROOFS ARE NOT AUTHENTICATION, AND CARRY NO FRESHNESS
// ════════════════════════════════════════════════════════════════════════════════════════════
// None of the three circuits binds a nonce, a subject id, a session or a channel. Each proves a
// true statement about its public values, and that statement STAYS TRUE ON REPLAY. A party who
// observes a holder's salt-binding proof can present it again and appear to hold that salt.
//
// So the implementing slice MUST take freshness and identity from outside the proof:
//   * the submission arrives on a channel already authenticated as this subject, and
//   * `WfSubmission.requestId` is a nonce the IK issued and records as spent, one use each.
// Neither is optional, and neither is a property of the circuits. If a later slice wants the
// proof to carry its own freshness, that is a fourth public signal and a new ceremony, not a
// looser check here.

import type { Hex } from "./types";
import type { WfCircuitId } from "./wf-layout";
import type { WfProofJson } from "./wf-verify";

/** A 32-byte field value as the services lane spells it. Mirrors `Hex32` in gap-platform-core. */
export type WfHex32 = Hex;

// ════════════════════════════════════════════════════════════════════════════════════════════
// WHAT THE DEVICE SUBMITS
// ════════════════════════════════════════════════════════════════════════════════════════════

/**
 * One proof. `publicSignals` is positional and its length is the circuit's: the verifier must
 * pass it through `assertWfPublicSignals` / `decodeWfPublicSignals` and compare by NAME, never by
 * index. Decimal strings, because that is what snarkjs emits and what survives the wire.
 */
export interface WfSubmission {
  readonly circuit: WfCircuitId;
  readonly proof: WfProofJson;
  readonly publicSignals: readonly string[];
  /** The nonce the IK issued for this exchange. Recorded spent on acceptance; single use. */
  readonly requestId: string;
}

/**
 * Custody handover / DID registration. Sent once, before the IK writes a DID document.
 *
 * The IK already knows `did` and the commitment it is about to register (the device computed the
 * salt; the commitment travelled with the enrolment request). `saltBinding` is what turns "the
 * device sent me a 32-byte value" into "the device holds its preimage".
 */
export interface WfCustodyHandover {
  readonly subjectId: string;
  readonly did: WfHex32;
  readonly saltCommitment: WfHex32;
  readonly saltBinding: WfSubmission;
}

/**
 * A credential the device wants anchored. One per regime, identity and fund credentials are
 * separate leaves under separate roots (`docs/ATTRIBUTE_ENCODING.md`).
 */
export interface WfCredentialAnchorRequest {
  readonly subjectId: string;
  readonly did: WfHex32;
  /** The leaf the IK will write. Taken from the proof's publics, never from this field alone. */
  readonly leaf: WfHex32;
  readonly credentialWellFormed: WfSubmission;
}

/**
 * A pseudonym the device wants the IK to publish, in a referral response, a securityholder file
 * row, or an ORDB lookup. One per scope anchor.
 */
export interface WfPseudonymRequest {
  readonly subjectId: string;
  readonly did: WfHex32;
  /** The scope the MANDATE authorised. Compared against the proof; never taken from it. */
  readonly fundScopeAnchor: WfHex32;
  readonly pseudonymWellFormed: WfSubmission;
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// WHAT THE IK CHECKS AGAINST, AND FROM WHERE
// ════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The IK's own records. Every field here is one the IK held BEFORE the submission arrived; not
 * one of them may be defaulted from the proof. That is the whole discipline: a check whose
 * expected value came from the thing being checked is not a check.
 */
export interface WfIssuanceRecord {
  readonly subjectId: string;
  /** The subject's DID, as reserved by `CredentialBuilder.reserveSeedForDid`. */
  readonly did: WfHex32;
  /**
   * The registered `privateSaltCommitment`, read from `DIDRegistryV2` or the pinned register: 
   * the same `SaltCommitmentDirectory` port `salt-commitment.ts` (full stack, not in this repository) already defines, and the same
   * fail-closed rule: an unregistered DID is as refusable as a mismatched commitment.
   */
  readonly saltCommitment: WfHex32;
  /** The identity anchor this credential is written to. */
  readonly ita: WfHex32;
  /** `GapLib.regimeHash(regimeId, major, minor, patch)` for the regime being issued. */
  readonly regimeHash: WfHex32;
  /** The IK's own id: the value it folds into leaves, not one the device may name. */
  readonly ikId: WfHex32;
  /**
   * `Poseidon2(attrs[0], attrs[1])` over the attributes THE IK DERIVED, from
   * `deriveIdentityAttributes` or `verifySuitabilityAttestation`, never from the device. This is
   * the field that keeps client custody from becoming client-asserted eligibility.
   */
  readonly attrsHash: WfHex32;
  /** The expiry its mint guard computed, already clamped (`gap-cli/src/mint-guard.ts`). */
  readonly expiresAt: bigint;
}

/**
 * The cross-venue join key, recorded on first sighting.
 *
 * `masterPseudonym` is `H2(H2(did, salt), regimeHash)`: the prefix every per-contract pseudonym
 * for this subject and regime is built on. The IK stores it the first time a subject proves one
 * and requires equality afterwards. That is what lets it tell a holder's SECOND security from a
 * second person, which per-security scoping otherwise makes indistinguishable
 * (`docs/ATTRIBUTE_ENCODING.md` § Per-security scope), without holding the salt that
 * links them. It is a write-once record for the same reason the custody model is: a changed
 * master anchor under an unchanged DID is a migration, not an update.
 */
export interface WfMasterAnchorRecord {
  readonly subjectId: string;
  readonly regimeHash: WfHex32;
  readonly masterPseudonym: WfHex32;
}

/**
 * Which verification key each circuit is verified under, and the digest it must hash to.
 *
 * The IK loads exactly these: it does not discover keys from a directory, and it never reads a
 * key a submission points at. Digests come from `circuits/build/wf/pins.json` (full stack, not in this repository)
 * (`scripts/v2/build-wf.sh`).
 *
 * `developmentOnly` is carried, not inferred. The keys that script produces are a SINGLE
 * contribution with checked-in entropy: anyone holding the repo can forge under them. A lane that
 * is not a local demo must refuse to start when this is true, the way the joined demo already
 * refuses a production claim over a local artifact (`BaseFundLocalSessionVerifier`'s
 * `LOCAL_DEVELOPMENT_ARTIFACT`). The production multi-contributor ceremony is documented as a
 * follow-up in the header of `scripts/v2/build-wf.sh`.
 */
export interface WfVerificationKeyPins {
  readonly developmentOnly: boolean;
  readonly ceremony: "DEV_SINGLE_CONTRIBUTION" | "MULTI_CONTRIBUTION_BEACON";
  readonly keys: Readonly<Record<WfCircuitId, { readonly sha256: Hex; readonly source: string }>>;
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// THE CHECKS, ENUMERATED: one refusal per way a submission can be wrong
// ════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Refusal reasons. Each names WHAT disagreed, because "well-formedness failed" tells an operator
 * nothing and a pseudonym is by construction unrecognisable once it is wrong.
 *
 * Ordering is normative: shape, then freshness, then field comparison, then the pairing check.
 * The proof is verified LAST: it is the expensive step and the least informative failure, and a
 * submission that names the wrong DID should be refused for naming the wrong DID.
 */
export const WF_REFUSALS = {
  /** The publics are not this circuit's layout, or a value is outside BN254. */
  MALFORMED_SUBMISSION: "MALFORMED_SUBMISSION",
  /** `requestId` was never issued, or has already been spent. */
  STALE_OR_UNKNOWN_REQUEST: "STALE_OR_UNKNOWN_REQUEST",
  /** No commitment is registered for this DID. Fail closed; do not proceed unchecked. */
  SALT_COMMITMENT_UNAVAILABLE: "SALT_COMMITMENT_UNAVAILABLE",
  /** The proof's `saltCommitment` is not the one registered for this subject's DID. */
  SALT_COMMITMENT_MISMATCH: "SALT_COMMITMENT_MISMATCH",
  /** The proof's `did` is not the subject's. */
  DID_MISMATCH: "DID_MISMATCH",
  /** `ita`, `regimeHash` or `ikId` is not what the IK is issuing under. */
  ISSUANCE_ROUTE_MISMATCH: "ISSUANCE_ROUTE_MISMATCH",
  /** `attrsHash` is not the hash of the attributes the IK derived and attested. */
  ATTRIBUTES_NOT_THE_ATTESTED_ONES: "ATTRIBUTES_NOT_THE_ATTESTED_ONES",
  /** `expiresAt` is not the clamped expiry the mint guard computed. */
  EXPIRY_MISMATCH: "EXPIRY_MISMATCH",
  /** The scope anchor in the proof is not the one the mandate authorised. */
  SCOPE_NOT_MANDATED: "SCOPE_NOT_MANDATED",
  /** A master anchor already recorded for this subject and regime, and this is a different one. */
  MASTER_ANCHOR_MIGRATION: "MASTER_ANCHOR_MIGRATION",
  /** The subject's salt is not under `CLIENT_HELD`; this lane does not apply to them. */
  CUSTODY_MODEL_MISMATCH: "CUSTODY_MODEL_MISMATCH",
  /**
   * THIS CELL SERVES NOBODY BY THAT NAME.
   *
   * Added by the implementing slice, because the list above enumerates the ways a submission's
   * CONTENT can be wrong and this is the one refusal that precedes content: the header requires
   * the submission to arrive "on a channel already authenticated as this subject", and a
   * channel that authenticates a subject the cell does not serve has still authenticated
   * nobody it can check anything against. Folding it into `DID_MISMATCH` would file "I have
   * never heard of this person" under "you named the wrong DID", which reads to an operator as
   * a device bug rather than an admission gap.
   */
  SUBJECT_NOT_SERVED: "SUBJECT_NOT_SERVED",
  /**
   * The IK will not mint another `requestId` right now: its live nonce table is at its bound.
   *
   * Also the implementing slice's, and named rather than left as a 500 for the same reason as
   * every code above it. The table is swept before this fires, so it means "this many nonces
   * are genuinely live", not "this many have ever been issued", see the eviction story in
   * `services/gap-ik-api/src/wf/nonces.ts` (full stack, not in this repository).
   */
  REQUEST_CAPACITY_EXHAUSTED: "REQUEST_CAPACITY_EXHAUSTED",
  /** Groth16 verification failed under the pinned key. */
  PROOF_INVALID: "PROOF_INVALID",
  /** The loaded verification key does not match its pinned digest. */
  VERIFICATION_KEY_UNPINNED: "VERIFICATION_KEY_UNPINNED",
} as const;

export type WfRefusal = (typeof WF_REFUSALS)[keyof typeof WF_REFUSALS];

/**
 * Which publics each statement is compared against, named rather than left to the implementer.
 * `WF_CIRCUITS[id].publicSignals` is the full list; these are the ones with an expected value.
 *
 *   saltBinding          saltCommitment   ← the DID's registered commitment
 *
 *   credentialWellFormed saltCommitment   ← the DID's registered commitment
 *                        did              ← the subject's DID
 *                        ita              ← the anchor being written to
 *                        regimeHash       ← the regime being issued
 *                        ikId             ← the IK's own id
 *                        attrsHash        ← Poseidon2 of the attributes the IK derived
 *                        expiresAt        ← the clamped mint-guard expiry
 *                        leaf             ← ACCEPTED (this is the value being learned)
 *
 *   pseudonymWellFormed  saltCommitment   ← the DID's registered commitment
 *                        did              ← the subject's DID
 *                        regimeHash       ← the credential's identity regime
 *                        gatedContract    ← the scope the mandate authorised
 *                        masterPseudonym  ← the recorded anchor, or recorded on first sighting
 *                        pseudonym        ← ACCEPTED (this is the value being learned)
 *
 * Exactly two publics across the three statements are learned rather than checked, and both are
 * the output the statement exists to produce.
 */
export const WF_ACCEPTED_PUBLICS = {
  saltBinding: [],
  credentialWellFormed: ["leaf"],
  pseudonymWellFormed: ["pseudonym"],
} as const satisfies Record<WfCircuitId, readonly string[]>;

/**
 * The order the implementing slice must write in: VERIFY, then persist, then publish, then
 * anchor. `CustodyModelRegistry` (S0) is the precedent and the reason: a record that is
 * published before it is durable is a record that can be contradicted by a restart, and an
 * anchor written before its well-formedness proof is checked is the thing this slice exists to
 * stop. A refusal at any step leaves nothing written.
 */
export const WF_VERIFY_THEN_ANCHOR = [
  "assert the subject's custody model is CLIENT_HELD",
  "assert requestId is live, then spend it",
  "decode publics by name and compare against the issuance record",
  "verify the proof under the pinned verification key",
  "persist the accepted publics (leaf / pseudonym, and the master anchor on first sighting)",
  "publish, then anchor on chain",
] as const;
