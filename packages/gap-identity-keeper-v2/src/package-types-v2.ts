import type { Poseidon2 } from "./field";
import type { IssuedSlot, PackageHeader } from "./package-profile";
import type { PackageReplayPort } from "./package-replay";
import type { ConfirmedPackageSlot } from "./package-validation";
import {
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
} from "./spending-wallet-set";
import type { Address, Bytes32 } from "./types";

export interface PackagedSpendingWalletWitnessV2 {
  readonly profile: typeof GAP_SPENDING_WALLET_SET_V2;
  readonly schemaVersion: typeof SPENDING_WALLET_SET_SCHEMA_VERSION;
  readonly root: Bytes32;
  readonly revision: bigint;
  readonly assignedSlot: number;
  readonly siblings: readonly Bytes32[];
  readonly pathIndices: readonly number[];
}

export interface SeedPlaintextV2 {
  readonly did: Bytes32;
  readonly privateSalt: Bytes32;
  readonly saltCommitment: Bytes32;
  readonly boundAccount: Address;
  readonly walletMembership: PackagedSpendingWalletWitnessV2;
  readonly reservedDidIndex: number;
  readonly governanceControllers: readonly Address[];
}

export interface IssuedPlaintextV2 {
  readonly did: Bytes32;
  readonly privateSalt: Bytes32;
  /** All EIGHT attributes: regime 0 is [0..3], regime 1 is [4..7]. */
  readonly attributes: readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
  readonly slots: readonly [IssuedSlot, IssuedSlot];
  readonly policyId: Bytes32;
  readonly holderPolicyVersion: number;
  readonly levelPolicyRevision: number;
  readonly walletMembership: PackagedSpendingWalletWitnessV2;
}

interface V2ContentBase {
  readonly hasher: Poseidon2;
  readonly expectedSpendingRoot: Bytes32;
  /**
   * The blind the spending leaves are folded under, the holder's own, so it travels with a
   * package addressed to them. Required rather than derived, because a type-1 package carries no
   * salt to derive it from. See SPENDING_SET_PRIVACY.md (full stack, not in this repository).
   */
  readonly expectedSpendingBlind: Bytes32;
  readonly walletSetRevision: bigint;
}

export type PackageContentExpectationsV2 =
  | (V2ContentBase & {
      readonly packageType: 1;
      readonly governanceControllers: readonly Address[];
    })
  | (V2ContentBase & {
      readonly packageType: 2;
      readonly did: Bytes32;
      readonly privateSalt: Bytes32;
      readonly policyId: Bytes32;
      readonly slots: readonly [ConfirmedPackageSlot, ConfirmedPackageSlot];
    });

export interface PackageExpectationsV2 {
  readonly packageType: 1 | 2;
  readonly wallet: Address;
  readonly walletBindingDigest: Bytes32;
  readonly didRegistry: Address;
  readonly minimumSequence: bigint;
  readonly now: bigint;
  readonly holderPolicyVersion: number;
  readonly levelPolicyRevision: number;
  readonly content: PackageContentExpectationsV2;
  readonly replay: PackageReplayPort;
}

export type PackageHeaderV2 = PackageHeader;
