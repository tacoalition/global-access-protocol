// MOVED: the fund-IK suitability gate now lives in
// `packages/gap-identity-keeper-v2/src/suitability-gate.ts`, beside the verifier
// it composes.
//
// WHY IT MOVED. This composition lived in the CLI package, so the IK SERVICE: 
// the lane that mints the fund credential on the joined deployment, could not
// reach it, and `services/gap-ik-api/src/anvil-fund-credential.ts` (full stack, not in this repository) wrote
// attrs[2..3] from a hardcoded `[1n, 1n]` gated on the KYC decision alone. Two
// gates would have been two answers to "who determined this"; there is one.
//
// This module is kept as the CLI's import surface (`./mint-guard` and the CLI
// tests read it) and adds nothing of its own.
export {
  assertSuitabilityKeysAreDistinct,
  gatedSuitabilityAttributes,
  suitabilityGateConfigFromEnvironment,
  suitabilityGateIsConfigured,
  type SuitabilityGateConfig,
} from "../../gap-identity-keeper-v2/src/suitability-gate";
