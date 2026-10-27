// @tac-gap/sdk, reusable GAP v2 client core. Config-injected proving primitives + shared types.
// Consumed by the CLI/sidecar (Node) AND, through the bundled browser session runtime, by the
// holder's device: `inputFromWitness` seals the TM envelope and assembles the circuit input
// wherever it runs. `witness-wire` is how an assembled witness reaches the device that proves it.
export * from "./types";
export * from "./metadata";
export * from "./random";
export * from "./artifacts";
export * from "./session-slots";
export * from "./tm-cipher";
export * from "./tm-envelope";
export * from "./tm-review";
export * from "./witness-wire";
export * from "./errors";
export * from "./spending-witness";
// Client-custody well-formedness: three small circuits with their OWN layouts, sharing the
// session lane's folds and nothing else. See src/wf-contract.ts for the IK verifier's contract.
export * from "./wf-layout";
export * from "./wf-witness";
export * from "./wf-verify";
export * from "./wf-prover";
export * from "./wf-contract";
export {
  EMPTY_SPENDING_BLIND,
  clausesHash,
  spendingBlindFor,
  spendingKeyRootFor,
} from "./input-builder";
export {
  createGapProver,
  formatProof,
  assertPublicSignals,
  type GapProver,
  type FormattedProof,
} from "./prover";
export {
  GrantQueue,
  GrantCoordinator,
  StaleWitnessError,
  grantLockName,
  type GapSigner,
  type GrantLockKey,
} from "./queue";
