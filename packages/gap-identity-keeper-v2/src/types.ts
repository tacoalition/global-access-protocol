export type Hex = `0x${string}`;
export type Address = Hex;
export type Bytes32 = Hex;
export type CredentialSlot = "IDENTITY" | "FUND";
export type CredentialAction = "ISSUE" | "REVOKE";
export type TransitionStatus = "PENDING" | "SUBMITTED" | "CONFIRMED" | "ABANDONED";

export interface CredentialRoute {
  readonly chainId: 84532;
  readonly anchor: Address;
  readonly regimeHash: Bytes32;
  readonly did: Bytes32;
  readonly ikId: Bytes32;
}

export interface CredentialPreimage extends CredentialRoute {
  readonly attributes: readonly [bigint, bigint, bigint, bigint];
  readonly privateSalt: Bytes32;
  readonly expiresAt: bigint;
  readonly commitment: Bytes32;
}

export interface CanonicalReceipt {
  readonly transactionHash: Bytes32;
  readonly blockNumber: bigint;
  readonly blockHash: Bytes32;
  readonly canonical: boolean;
  readonly status: "SUCCESS" | "REVERTED";
  readonly from: Address;
  readonly to: Address;
  readonly calldataDigest: Bytes32;
}

export interface CredentialReadback {
  readonly commitment: Bytes32;
  readonly issuerIKId: Bytes32;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly revoked: boolean;
  readonly treeIndex: number;
}

export interface DidBindingReadback {
  readonly exists: boolean;
  readonly privateSaltCommitment: Bytes32;
  readonly spendingKeyRoot: Bytes32;
  readonly governanceKeys: readonly Address[];
}

export interface SourceDecisionSnapshot {
  readonly revision: bigint;
  readonly evidenceDigest: Bytes32;
  readonly approved: boolean;
  readonly subjectId: string;
  /** Absent for a holder whose first enrollment has not happened yet. */
  readonly wallet?: Address;
  readonly did: Bytes32;
  readonly token?: Address;
  readonly expiresAt?: bigint;
  /**
   * attrs[0..1] derived from the verified provider decision. Required for
   * IDENTITY issuance: without provenance, the command's own commitment and
   * calldata digests only prove internal consistency, never where the
   * attributes came from.
   */
  readonly attributes?: readonly [bigint, bigint, bigint, bigint];
}
