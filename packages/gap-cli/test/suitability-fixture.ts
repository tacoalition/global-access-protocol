// MOVED: the fund-IK signing fixture now lives beside the verifier it exercises,
// in `packages/gap-identity-keeper-v2/test/suitability-fixture.ts`, so the CLI
// lane's tests and the IK SERVICE lane's tests sign the same artifact with the
// same code. Two fixtures would be two definitions of the 14-slot payload, and
// only one of them would be the one the verifier reads.
//
// Kept as this suite's import surface; it adds nothing.
export {
  EVIDENCE_DIGEST,
  FUND_IK_ID,
  REVIEWER_ID,
  SUBJECT_DID,
  SUITABILITY_KEY_ID,
  createSigningKey,
  signSuitability,
  suitabilityEnv,
  suitabilitySlots,
  type Envelope,
  type SigningKey,
  type SuitabilityOverrides,
} from "../../gap-identity-keeper-v2/test/suitability-fixture";
