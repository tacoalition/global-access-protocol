import { randomBytes } from "node:crypto";
import {
  computeSaltCommitment,
  type DidReservation,
  type DidReservationPort,
} from "./credential-builder";
import { assertStableGovernanceControllers } from "./governance-v2";
import type { SeedPlaintextV2 } from "./package-types-v2";
import {
  AssignedSlotSpendingWalletSet,
  DEFAULT_SPENDING_WALLET_DEPTH,
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
  assertSpendingWalletMembership,
  type SpendingWalletMembershipProof,
  type SpendingWalletSetSnapshot,
} from "./spending-wallet-set";
import {
  assertBytes,
  sampleField,
  toBytes32,
  type Poseidon2,
} from "./field";
import type { Address, Bytes32 } from "./types";

export interface AssignedWalletSeedInputV2 {
  readonly boundWallet: Address;
  readonly governanceControllers: readonly Address[];
  readonly walletSet: SpendingWalletSetSnapshot;
  readonly membership: SpendingWalletMembershipProof;
}

export interface AssignedWalletSeedBuildResultV2 {
  readonly reservation: DidReservation;
  readonly seed: SeedPlaintextV2;
  readonly didLeaf: Bytes32;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function assertSameProof(
  expected: SpendingWalletMembershipProof,
  supplied: SpendingWalletMembershipProof,
): void {
  if (
    expected.slot !== supplied.slot ||
    !sameHex(expected.account, supplied.account) ||
    !sameHex(expected.leaf, supplied.leaf) ||
    !sameHex(expected.root, supplied.root) ||
    expected.siblings.some((value, index) => !sameHex(value, supplied.siblings[index] ?? "")) ||
    expected.pathIndices.some((value, index) => value !== supplied.pathIndices[index])
  ) {
    throw new Error("injected spending wallet proof does not match assigned wallet-set state");
  }
}

export class AssignedWalletCredentialBuilderV2 {
  constructor(
    private readonly hasher: Poseidon2,
    private readonly random: (size: number) => Uint8Array = randomBytes,
  ) {}

  async reserveSeed(
    input: AssignedWalletSeedInputV2,
    reservations: DidReservationPort,
    maxAttempts = 128,
  ): Promise<AssignedWalletSeedBuildResultV2> {
    this.assertWalletSet(input);
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const didValue = sampleField(this.random);
      const saltValue = sampleField(this.random);
      const did = toBytes32(didValue);
      const privateSalt = toBytes32(saltValue);
      const index = Number(didValue & 0xffffn);
      if (!(await reservations.areAllSlotsEmpty(did, index))) continue;
      const stored = await reservations.tryReserve(did, index);
      if (!stored) continue;
      const saltCommitment = computeSaltCommitment(this.hasher, saltValue);
      const spendingRoot = BigInt(input.walletSet.root);
      const didLeaf = this.hasher.hash2(
        this.hasher.hash2(didValue, saltCommitment),
        spendingRoot,
      );
      return {
        reservation: { did, privateSalt, index, ...stored },
        didLeaf: toBytes32(didLeaf),
        seed: {
          did,
          privateSalt,
          saltCommitment: toBytes32(saltCommitment),
          boundAccount: input.boundWallet,
          walletMembership: {
            profile: GAP_SPENDING_WALLET_SET_V2,
            schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
            root: input.walletSet.root,
            revision: input.walletSet.revision,
            assignedSlot: input.membership.slot,
            siblings: input.membership.siblings,
            pathIndices: input.membership.pathIndices,
          },
          reservedDidIndex: index,
          governanceControllers: [...input.governanceControllers],
        },
      };
    }
    throw new Error("unable to reserve an empty DID/credential index");
  }

  private assertWalletSet(input: AssignedWalletSeedInputV2): void {
    assertBytes(input.boundWallet, 20, "boundWallet");
    if (input.walletSet.depth !== DEFAULT_SPENDING_WALLET_DEPTH) {
      throw new Error("V2 packages require an eight-level spending wallet set");
    }
    if (input.walletSet.revision <= 0n) {
      throw new Error("V2 spending wallet set revision must be nonzero");
    }
    const reconstructed = new AssignedSlotSpendingWalletSet(this.hasher, null, input.walletSet);
    if (!sameHex(reconstructed.root(), input.walletSet.root)) {
      throw new Error("injected spending wallet-set root does not match its assignments");
    }
    assertSpendingWalletMembership(this.hasher, input.membership, BigInt(input.walletSet.spendingBlind));
    const expected = reconstructed.proof(input.boundWallet);
    assertSameProof(expected, input.membership);
    assertStableGovernanceControllers(
      input.governanceControllers,
      input.walletSet.assignments.map(({ account }) => account),
    );
  }
}
