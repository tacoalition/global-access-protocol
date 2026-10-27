// GAP v2 SDK shared types. Runtime/network values are injected; nothing here assumes Anvil.

import type { CircuitMetadata } from "./metadata";

export const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** keccak256("GAP_ATTR_CRED_V3") mod P. */
export const CRED_TAG =
  7398619034839472060957547841361825911550539606183619483712186628328937676175n;
/** keccak256("GAP_SPENDING_BLIND_V2") mod p, blinds the spending-key leaf so the published
 *  `spendingKeyRoot` stops being a preimage of the holder's wallets.
 *  MIRRORS: circuits/src/v2/lib/gap_session.circom, packages/gap-sdk/src/types.ts,
 *  circuits/scripts/v2/prove_session.js. See SPENDING_SET_PRIVACY.md (full stack, not in this repository). */
export const SPENDING_BLIND_TAG =
  20739668207314188630064942382150002554459284316356860011996029219836196127177n;

export type Hex = `0x${string}`;
export type Clause = {
  enabled: number;
  groupId: number;
  attrIndex: number;
  op: number;
  value: bigint;
};

export interface Holder {
  did: bigint;
  privateSalt: bigint;
  /** The wallet this holder is transacting from RIGHT NOW, one of many, not the identity. */
  account: bigint;
  credExpiresAt: [bigint, bigint];
  credLeaves: [bigint, bigint];
  /**
   * The PERSON's authoritative spending-wallet-set root (the IK's
   * AssignedSlotSpendingWalletSet), which is what the on-chain DID document pins.
   * It is a property of the person, not of `account`: every wallet the person owns
   * proves membership in this one root, so the DID leaf is identical whichever
   * wallet transacts. Omitted only by the legacy one-wallet-per-DID fixtures, where
   * the builder falls back to a singleton tree over `account`.
   */
  spendingKeyRoot?: bigint;
  /** `account`'s membership proof inside `spendingKeyRoot`. Required whenever that root is set. */
  spendingKeyWitness?: SpendingKeyWitness;
}

/** Local mirror path retained only for the explicit chain-31337 reference CLI. */
export interface SessionScenario {
  holder: Holder;
  allHolders: Holder[];
  chainId: bigint;
  sessionManager: bigint;
  policyId: bigint;
  policyVersion: bigint;
  validUntil: bigint;
  accountNonce: bigint;
  ita0: bigint;
  ita1: bigint;
  regime0: bigint;
  regime1: bigint;
  ikId0: bigint;
  ikId1: bigint;
  gatedContract: bigint;
  ordbId: bigint;
  monitorKeyId: bigint;
  /** All EIGHT attributes: regime 0 is attrs[0..3], regime 1 is attrs[4..7]. */
  attrs: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
  clauses: Clause[];
  rdb: { root: bigint; index: number; lowKey: bigint; nextKey: bigint; siblings: bigint[] };
}

export interface SessionInput {
  input: Record<string, unknown>;
  ciphertext: Hex;
  /** The AAD the envelope was sealed under. A monitor must open against exactly this. */
  tmContext: TmEncryptionContext;
  pseudonym: bigint;
  roots: { didRoot: bigint; credRoot0: bigint; credRoot1: bigint; riskRoot: bigint };
}

/** Membership of the active account in its versioned, assigned-slot wallet set. */
export interface SpendingKeyWitness {
  root: bigint;
  siblings: bigint[];
  pathIndices: number[];
}

/** Full-privacy witness assembled from holder secrets and public chain reads. */
export interface WitnessData {
  did: bigint;
  privateSalt: bigint;
  account: bigint;
  /** All EIGHT attributes: regime 0 is attrs[0..3], regime 1 is attrs[4..7]. */
  attrs: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
  credExpiresAt: [bigint, bigint];
  ikId0: bigint;
  ikId1: bigint;
  ita0: bigint;
  ita1: bigint;
  regime0: bigint;
  regime1: bigint;
  sessionManager: bigint;
  chainId: bigint;
  policyId: bigint;
  policyVersion: bigint;
  validUntil: bigint;
  accountNonce: bigint;
  gatedContract: bigint;
  ordbId: bigint;
  monitorKeyId: bigint;
  clauses: Clause[];
  didRoot: bigint;
  credRoot0: bigint;
  credRoot1: bigint;
  didSiblings: bigint[];
  didIndex: number;
  spendingKeyWitness?: SpendingKeyWitness;
  cred0Siblings: bigint[];
  cred0Index: number;
  cred1Siblings: bigint[];
  cred1Index: number;
  rdb: { root: bigint; lowKey: bigint; nextKey: bigint; siblings: bigint[]; index: number };
}

export interface SessionTarget {
  gatedContract: string;
  ordbAddress: string;
  clauses: Clause[];
}

export interface TmEncryptionContext {
  chainId: bigint;
  sessionManager: bigint;
  account: bigint;
  policyId: bigint;
  policyVersion: bigint;
  validUntil: bigint;
  accountNonce: bigint;
  ordb: bigint;
  gatedContract: bigint;
  monitorKeyId: bigint;
  pseudonymCommitment: bigint;
  ikRefCommitment: bigint;
}

export interface TmEncryptionPlaintext {
  pseudonym: bigint;
  blindingR: bigint;
  ita0: bigint;
  ikId0: bigint;
  /** Blinds `ikRefCommitment`. Without it pub[17] inverts by table lookup: both its other
   *  preimages are public, and the Identity Keeper is readable by anyone. */
  ikBlind: bigint;
}

export interface TmCipher {
  encrypt(plaintext: TmEncryptionPlaintext, context: TmEncryptionContext): Promise<Hex>;
}

export interface ArtifactReference {
  source: string | Uint8Array;
  sha256: Hex;
}

export interface ProverConfig {
  crypto: {
    h2(a: unknown, b: unknown): Promise<bigint>;
    /** Genuine Poseidon(4): the per-regime attribute fold. NOT `chain` of four items. */
    h3(a: unknown, b: unknown, c: unknown): Promise<bigint>;
    h4(a: unknown, b: unknown, c: unknown, d: unknown): Promise<bigint>;
    chain(items: unknown[]): Promise<bigint>;
    SparseTree: new (depth: number) => {
      init(): Promise<void>;
      setByKey(key: bigint, value: bigint): void;
      indexOf(key: bigint): number;
      root(): bigint;
      proof(i: number): { siblings: bigint[]; pathIndices: number[] };
    };
  };
  metadata?: CircuitMetadata;
  tmCipher?: TmCipher;
  randomBytes?: (length: number) => Uint8Array;
  /** Only the chain-31337 reference CLI may opt into its legacy cleartext envelope. */
  allowInsecureLocalCipher?: boolean;
  // snarkjs has no stable exported TypeScript interface.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  groth16?: any;
  wasm?: ArtifactReference;
  zkey?: ArtifactReference;
  verificationKey?: ArtifactReference;
  verifyArtifact?: (artifact: ArtifactReference) => Promise<void>;
}
