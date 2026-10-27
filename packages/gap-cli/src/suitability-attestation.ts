// MOVED: the fund-IK suitability verifier now lives in
// `packages/gap-identity-keeper-v2/src/suitability-attestation.ts`.
//
// WHY IT MOVED. This file was the only implementation of the attrs[2..3]
// authority, and it sat inside the CLI package. The IK SERVICE could not import
// it, so `services/gap-ik-api/src/anvil-fund-credential.ts` (full stack, not in this repository) minted accredited/QP
// from a hardcoded `[1n, 1n]` instead: a suitability claim nobody determined,
// unlocked by a KYC GREEN alone. The verifier therefore had to move somewhere
// both lanes can reach; writing a second copy for the service is the pattern
// that produced this repository's session-slot defect class.
//
// This module is kept as the CLI's import surface so its callers and tests keep
// one path. It adds nothing: every symbol below is the shared one.
export {
  DEFAULT_DETERMINATION_FRESHNESS_SECONDS,
  DEFAULT_REVIEW_SKEW_SECONDS,
  SUITABILITY_BASES,
  SUITABILITY_PROFILE,
  SUITABILITY_SLOTS,
  decodeSuitabilitySlots,
  verifySuitabilityAttestation,
  type SuitabilityBasis,
  type SuitabilityDetermination,
  type SuitabilityPolicy,
  type SuitabilityVerifyContext,
  type VerifiedSuitability,
} from "../../gap-identity-keeper-v2/src/suitability-attestation";
