// The FUND-IK SUITABILITY ATTESTATION: the authority for attrs[2..3].
//
// WHY THIS EXISTS
// The KYC provider attests IDENTITY facts and nothing else: residency country
// and sanctions screening (attrs[0..1]). It has no view of a subscriber's
// income, net worth, or investment holdings, and it is not the party that bears
// the Reg D / 3(c)(7) determination. Before this module, attrs[2..3]
// (accredited, qualified purchaser) were minted by the demo lane from a
// hardcoded constant with NO attestation and NO expiry: "nobody, forever", 
// and `state.ts` ZONES["reg-d"] turns attrs[2] == 1 into access to the Reg D
// zone. That unbacked leaf was the suitability hole.
//
// The fund IK makes the suitability determination itself, against evidence it
// reviewed, and signs THIS artifact. Every writer of an accredited/QP leaf
// verifies it first.
//
// ONE VERIFIER, TWO LANES. This module lives in the shared Identity Keeper
// package because BOTH writers of attrs[2..3] must decide with the same code:
//   • the CLI demo lane (`packages/gap-cli/src/mint-guard.ts`), and
//   • the IK SERVICE lane (`services/gap-ik-api/src/anvil-fund-credential.ts` (full stack, not in this repository),
//     which used to mint attrs[2..3] from the constant `[1n, 1n]`).
// It was previously a gap-cli module, which is why the service could not reach
// it and shipped a hardcoded pair instead. A second copy of a verifier is the
// exact pattern that produced this repository's session-slot defect class, so
// the two lanes import this file and neither re-implements it.
//
// DISTINCT IN ORIGIN FROM THE KYC DECISION, three independent separations, so
// that a KYC GREEN can never be sufficient to mint accredited/QP:
//   1. a different profile tag, so a provider envelope cannot even parse here
//      (and a suitability envelope cannot parse as a provider decision);
//   2. a different authority slot ("fund-ik", never "kyc-provider");
//   3. a different pinned key set, which the suitability gate
//      (`services/gap-ik-api/src/suitability-credential-gate.ts` (full stack, not in this repository)) refuses to let
//      overlap the KYC provider's pinned keys.
//
// NO SECOND VERIFIER: the envelope parse, the pinned-Ed25519 rule and the
// positional-slot decode all come from `./signed-attestation`, the same module
// the KYC provider attestation is built on. Only the payload semantics below
// are this profile's own.
import {
  SHA256_HEX_PATTERN,
  epochSeconds,
  expectBooleanSlot,
  expectIsoUtc,
  expectString,
  expectUint64,
  openSignedAttestation,
  type EnvelopeShape,
  type SignedAttestationEnvelope,
} from "./signed-attestation";

// V2 inserts `evidenceTier` at slot 11, shifting reviewedAt and expiresAt up by one. The profile
// string moves with the shape so a V1 payload is REFUSED on profile mismatch rather than decoded
// against the wrong positions.
export const SUITABILITY_PROFILE = "DSI_FUND_IK_SUITABILITY_ATTESTATION_V2";
export const SUITABILITY_SLOTS = 14;
/**
 * How long a reviewed determination may be relied on. 90 days is the SEC's own
 * Rule 506(c) verification safe harbor: a written accreditation verification is
 * deemed reasonable for three months, so a determination older than that has
 * to be re-reviewed, not re-signed.
 */
export const DEFAULT_DETERMINATION_FRESHNESS_SECONDS = 90n * 24n * 60n * 60n;
export const DEFAULT_REVIEW_SKEW_SECONDS = 60n;

/** The evidence classes a fund IK may record as the basis of its determination. */
export const SUITABILITY_BASES = [
  "INCOME",
  "NET_WORTH",
  "PROFESSIONAL_CERTIFICATION",
  "ENTITY_ASSETS",
  "THIRD_PARTY_LETTER",
] as const;
export type SuitabilityBasis = (typeof SUITABILITY_BASES)[number];

/**
 * Evidence tier per basis: the gateable numeric behind `attrs[6]`.
 *
 * THE ORDERING IS A POLICY DECISION, NOT AN INFERENCE, which is why it is pinned in a table with a
 * revision rather than computed. The argument `country-table.ts` makes applies here: a value a clause
 * compares against must come from a reviewed set, or a venue is gating on something nobody signed
 * off. The IK does not DERIVE the tier: the fund IK attests it, and this table is what the IK checks
 * the attested value against, so a desk cannot quietly promote its own evidence class.
 *
 * Bump SUITABILITY_TIER_REVISION whenever a row moves: a venue's `GTE` clause is written against a
 * revision, and changing a row silently would change what every existing clause means.
 */
export const SUITABILITY_TIER_REVISION = 1;
export const EVIDENCE_TIER_BY_BASIS: Readonly<Record<SuitabilityBasis, bigint>> = {
  THIRD_PARTY_LETTER: 1n,          // a third party asserts it; the fund holds no underlying document
  INCOME: 2n,                      // documented, but self-reported and single-period
  NET_WORTH: 3n,                   // a documented balance sheet
  ENTITY_ASSETS: 4n,               // entity-level, ordinarily audited
  PROFESSIONAL_CERTIFICATION: 5n,  // a licence, independently verifiable against a public register
};

const DID_HEX = /^0x[0-9a-f]{64}$/;
const IDENT = /^[A-Za-z0-9_.:-]{1,128}$/;

/** The envelope shape a suitability attestation must present. */
const SUITABILITY_ENVELOPE: EnvelopeShape = {
  profile: SUITABILITY_PROFILE,
  noun: "suitability attestation",
};

export interface SuitabilityDetermination {
  readonly profile: typeof SUITABILITY_PROFILE;
  readonly authority: "fund-ik";
  readonly environment: "sandbox";
  readonly fundIkId: string;
  /** The person DID this determination is about, bound into the signed bytes. */
  readonly subjectDid: `0x${string}`;
  readonly determinationRevision: bigint;
  readonly reviewerId: string;
  readonly evidenceDigest: `0x${string}`;
  readonly basis: SuitabilityBasis;
  /** attrs[2], 1 iff the fund IK determined the subject is accredited. */
  readonly accredited: bigint;
  /** attrs[5], 1 iff the fund IK determined the subject is a qualified purchaser. */
  readonly qualifiedPurchaser: bigint;
  /**
   * attrs[6]: the evidence tier, 1..5, per EVIDENCE_TIER_BY_BASIS. This is the field a venue gates
   * with a THRESHOLD (`GTE`) rather than an equality, so a holder proves their determination rests on
   * evidence at least as strong as the bar WITHOUT revealing which basis it was.
   */
  readonly evidenceTier: bigint;
  readonly reviewedAt: string;
  readonly expiresAt: bigint;
}

export interface SuitabilityPolicy {
  readonly fundIkId: string;
  readonly environment: "sandbox";
  /** keyId -> `0x`-prefixed 32-byte Ed25519 public key. Unknown keyId => refuse. */
  readonly publicKeys: Readonly<Record<string, string>>;
}

export interface SuitabilityVerifyContext {
  readonly policy: SuitabilityPolicy;
  /** The DID whose investor-status leaf is about to be written. */
  readonly expectedSubjectDid: `0x${string}`;
  readonly now: bigint;
  readonly determinationFreshnessSeconds?: bigint;
  readonly reviewSkewSeconds?: bigint;
}

/**
 * Decode the canonical 14-slot positional payload. Slot order is normative.
 *
 *   0  profile tag       7  evidenceDigest
 *   1  authority         8  basis
 *   2  environment       9  accredited            (attrs[4])
 *   3  fundIkId         10  qualifiedPurchaser    (attrs[5])
 *   4  subjectDid       11  evidenceTier          (attrs[6])
 *   5  revision         12  reviewedAt
 *   6  reviewerId       13  expiresAt
 */
export function decodeSuitabilitySlots(slots: readonly unknown[]): SuitabilityDetermination {
  // The authority slot is the payload-level twin of the profile tag: a KYC
  // provider decision says "kyc-provider" here and can never say "fund-ik".
  if (slots[1] !== "fund-ik") throw new Error("suitability attestation authority is not the fund IK");
  if (slots[2] !== "sandbox") throw new Error("suitability attestation environment is not sandbox");
  const fundIkId = expectString(slots, 3, "fundIkId");
  if (!IDENT.test(fundIkId)) throw new Error("fundIkId is malformed");
  const subjectDid = expectString(slots, 4, "suitability subjectDid");
  if (!DID_HEX.test(subjectDid)) {
    throw new Error("suitability subjectDid must be lowercase 0x 32-byte hex");
  }
  const determinationRevision = expectUint64(slots, 5, "determinationRevision");
  if (determinationRevision < 1n) throw new Error("determinationRevision must be >= 1");
  const reviewerId = expectString(slots, 6, "reviewerId");
  if (!IDENT.test(reviewerId)) throw new Error("reviewerId is malformed");
  const evidenceDigest = expectString(slots, 7, "suitability evidenceDigest");
  if (!SHA256_HEX_PATTERN.test(evidenceDigest)) {
    throw new Error("suitability evidenceDigest must be lowercase 0x sha-256 hex");
  }
  const basis = expectString(slots, 8, "suitability basis");
  if (!(SUITABILITY_BASES as readonly string[]).includes(basis)) {
    throw new Error(`suitability basis ${basis} is not a reviewed evidence class`);
  }
  const accredited = expectBooleanSlot(slots, 9, "accredited");
  const qualifiedPurchaser = expectBooleanSlot(slots, 10, "qualifiedPurchaser");
  // A qualified purchaser who is not accredited is not a state that exists:
  // the QP thresholds strictly dominate the accreditation ones.
  if (qualifiedPurchaser === 1n && accredited !== 1n) {
    throw new Error("a qualified purchaser determination requires accreditation");
  }
  // The attested tier must be the reviewed tier for the attested basis. A desk that signed a higher
  // tier than its evidence class carries is refused HERE, not at some venue's clause.
  const evidenceTier = expectUint64(slots, 11, "suitability evidenceTier");
  const expectedTier = EVIDENCE_TIER_BY_BASIS[basis as SuitabilityBasis];
  if (evidenceTier !== expectedTier) {
    throw new Error(
      `suitability evidenceTier ${evidenceTier} is not the reviewed tier ${expectedTier} for basis ${basis}`,
    );
  }
  const reviewedAt = expectIsoUtc(slots, 12, "reviewedAt");
  const expiresAt = expectUint64(slots, 13, "suitability expiresAt");
  if (expiresAt <= epochSeconds(reviewedAt)) {
    throw new Error("suitability expiresAt must be after reviewedAt");
  }
  return {
    profile: SUITABILITY_PROFILE,
    authority: "fund-ik",
    environment: "sandbox",
    fundIkId,
    subjectDid: subjectDid as `0x${string}`,
    determinationRevision,
    reviewerId,
    evidenceDigest: evidenceDigest as `0x${string}`,
    basis: basis as SuitabilityBasis,
    accredited,
    qualifiedPurchaser,
    evidenceTier,
    reviewedAt,
    expiresAt,
  };
}

export interface VerifiedSuitability {
  readonly envelope: SignedAttestationEnvelope;
  readonly determination: SuitabilityDetermination;
  /** [accredited, qualifiedPurchaser]: the ONLY source of attrs[2..3]. */
  readonly attributes: readonly [bigint, bigint, bigint, bigint];
}

/**
 * Full verification, run over the bytes the fund IK signed. Every failure is a
 * refusal; there is no downgrade path and no "attest anyway".
 */
export function verifySuitabilityAttestation(
  input: unknown,
  context: SuitabilityVerifyContext,
): VerifiedSuitability {
  const opened = openSignedAttestation(input, {
    ...SUITABILITY_ENVELOPE,
    slotCount: SUITABILITY_SLOTS,
    publicKeys: context.policy.publicKeys,
    payloadLabel: "suitability attestation payload",
  });
  const determination = decodeSuitabilitySlots(opened.slots);
  if (determination.fundIkId !== context.policy.fundIkId
    || determination.environment !== context.policy.environment) {
    throw new Error("suitability attestation was not issued by the configured fund IK");
  }
  if (determination.subjectDid.toLowerCase() !== context.expectedSubjectDid.toLowerCase()) {
    throw new Error("suitability attestation is about a different person DID");
  }
  const skew = context.reviewSkewSeconds ?? DEFAULT_REVIEW_SKEW_SECONDS;
  const freshness = context.determinationFreshnessSeconds ?? DEFAULT_DETERMINATION_FRESHNESS_SECONDS;
  if (epochSeconds(determination.reviewedAt) > context.now + skew) {
    throw new Error("suitability determination was reviewed in the future");
  }
  if (context.now >= determination.expiresAt) {
    throw new Error("suitability determination has expired");
  }
  if (context.now - epochSeconds(determination.reviewedAt) > freshness) {
    throw new Error("suitability determination is stale: the evidence must be re-reviewed");
  }
  return {
    envelope: opened.envelope,
    determination,
    attributes: [determination.accredited, determination.qualifiedPurchaser, determination.evidenceTier, 0n],
  };
}
