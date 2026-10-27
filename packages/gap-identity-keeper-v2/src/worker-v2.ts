import { createHash } from "node:crypto";
import {
  parseIkCommandV2,
  serializeIkCommandV2,
  type IkCommandJsonV2,
  type IkCommandV2,
} from "./command-schema-v2";
import { computeCredentialLeaf, computeSaltCommitment } from "./credential-builder";
import { assertStableGovernanceControllers, sameControllerSet } from "./governance-v2";
import {
  IdentityAnchorClient,
  ReorgDetectedError,
  type AnchorMutationResult,
} from "./identity-anchor-client";
import {
  AssignedSlotSpendingWalletSet,
  GAP_SPENDING_WALLET_SET_V2,
  type SpendingWalletSetSnapshot,
} from "./spending-wallet-set";
import type {
  Address,
  Bytes32,
  CredentialReadback,
  CredentialSlot,
  DidBindingReadback,
  TransitionStatus,
} from "./types";
import type { Poseidon2 } from "./field";

/** Subject eligibility only. Wallet-specific TA approval is deliberately outside this port. */
export interface SubjectDecisionSnapshotV2 {
  readonly revision: bigint;
  readonly evidenceDigest: Bytes32;
  readonly approved: boolean;
  readonly subjectId: string;
  readonly did: Bytes32;
  readonly token?: Address;
  readonly expiresAt?: bigint;
}

export interface AuthoritativeSubjectDecisionPortV2 {
  readSubjectDecision(
    slot: CredentialSlot,
    subjectId: string,
    token?: Address,
  ): Promise<SubjectDecisionSnapshotV2>;
}

export interface AuthoritativeWalletSetRecordV2 {
  readonly subjectId: string;
  readonly activeDID: Bytes32;
  readonly walletSet: SpendingWalletSetSnapshot;
  readonly governanceControllers: readonly Address[];
}

export interface AuthoritativeWalletSetPortV2 {
  readWalletSet(subjectId: string, activeDID: Bytes32): Promise<AuthoritativeWalletSetRecordV2>;
}

export interface IkPolicyReadPortV2 {
  readDid(did: Bytes32): Promise<DidBindingReadback>;
  isIkActiveAndAuthorized(
    anchor: Address,
    ikId: Bytes32,
    regimeHash: Bytes32,
    signer: Address,
  ): Promise<boolean>;
  readCredential(anchor: Address, regimeHash: Bytes32, did: Bytes32): Promise<CredentialReadback>;
}

export interface WorkerTransitionV2 {
  readonly idempotencyKey: string;
  readonly commandDigest: Bytes32;
  readonly status: TransitionStatus;
  readonly transactionHash?: Bytes32;
  readonly result?: AnchorMutationResult;
}

export interface WorkerStateStoreV2 {
  begin(command: IkCommandV2, commandDigest: Bytes32): Promise<WorkerTransitionV2>;
  submitted(idempotencyKey: string, transactionHash: Bytes32): Promise<void>;
  confirmed(idempotencyKey: string, result: AnchorMutationResult): Promise<void>;
  pendingAfterReorg(idempotencyKey: string): Promise<void>;
}

export class InMemoryWorkerStateStoreV2 implements WorkerStateStoreV2 {
  private readonly rows = new Map<string, WorkerTransitionV2>();

  async begin(command: IkCommandV2, digest: Bytes32): Promise<WorkerTransitionV2> {
    const prior = this.rows.get(command.idempotencyKey);
    if (prior) {
      if (prior.commandDigest !== digest) throw new Error("V2 idempotency key reused with different bytes");
      return prior;
    }
    const row: WorkerTransitionV2 = {
      idempotencyKey: command.idempotencyKey,
      commandDigest: digest,
      status: "PENDING",
    };
    this.rows.set(command.idempotencyKey, row);
    return row;
  }

  async submitted(key: string, transactionHash: Bytes32): Promise<void> {
    this.rows.set(key, { ...this.require(key), status: "SUBMITTED", transactionHash });
  }

  async confirmed(key: string, result: AnchorMutationResult): Promise<void> {
    this.rows.set(key, { ...this.require(key), status: "CONFIRMED", result,
      transactionHash: result.transactionHash });
  }

  async pendingAfterReorg(key: string): Promise<void> {
    const row = this.require(key);
    this.rows.set(key, { idempotencyKey: key, commandDigest: row.commandDigest, status: "PENDING" });
  }

  get(key: string): WorkerTransitionV2 | undefined { return this.rows.get(key); }

  private require(key: string): WorkerTransitionV2 {
    const row = this.rows.get(key);
    if (!row) throw new Error("V2 worker transition does not exist");
    return row;
  }
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return left?.toLowerCase() === right?.toLowerCase();
}

function digest(command: IkCommandV2): Bytes32 {
  return `0x${createHash("sha256").update(JSON.stringify(serializeIkCommandV2(command))).digest("hex")}`;
}

export class GapIdentityKeeperSubjectWorkerV2 {
  constructor(
    private readonly slot: CredentialSlot,
    private readonly hasher: Poseidon2,
    private readonly decisions: AuthoritativeSubjectDecisionPortV2,
    private readonly walletSets: AuthoritativeWalletSetPortV2,
    private readonly policy: IkPolicyReadPortV2,
    private readonly anchor: IdentityAnchorClient,
    private readonly state: WorkerStateStoreV2,
    private readonly signerAddress: Address,
    private readonly now: () => bigint = () => BigInt(Math.floor(Date.now() / 1000)),
  ) {}

  async handle(json: IkCommandJsonV2 | unknown): Promise<AnchorMutationResult> {
    const command = parseIkCommandV2(json);
    if (command.slot !== this.slot) throw new Error("V2 command routed to wrong IK worker");
    const transition = await this.state.begin(command, digest(command));
    if (transition.status === "CONFIRMED" && transition.result) return transition.result;
    try {
      let transactionHash = transition.transactionHash;
      if (transition.status === "PENDING") {
        await this.authorize(command);
        const submitted = await this.anchor.submit(command);
        transactionHash = submitted.transactionHash;
        await this.state.submitted(command.idempotencyKey, transactionHash);
      }
      if (!transactionHash) throw new Error("submitted V2 transition is missing transaction hash");
      const result = await this.anchor.confirm(command, transactionHash);
      await this.state.confirmed(command.idempotencyKey, result);
      return result;
    } catch (error) {
      if (error instanceof ReorgDetectedError) {
        await this.state.pendingAfterReorg(command.idempotencyKey);
      }
      throw error;
    }
  }

  private async authorize(command: IkCommandV2): Promise<void> {
    if (!sameHex(this.anchor.digestFor(command), command.calldataDigest)) {
      throw new Error("V2 command calldata digest mismatch");
    }
    const decision = await this.decisions.readSubjectDecision(
      command.slot,
      command.subjectId,
      command.token,
    );
    if (
      decision.revision !== command.sourceDecisionRevision ||
      !sameHex(decision.evidenceDigest, command.sourceDecisionDigest)
    ) {
      throw new Error("stale or substituted V2 subject decision");
    }
    if (decision.subjectId !== command.subjectId || !sameHex(decision.did, command.activeDID)) {
      throw new Error("V2 decision subject/DID mismatch");
    }
    if (command.slot === "FUND" && !sameHex(decision.token, command.token)) {
      throw new Error("V2 fund eligibility token mismatch");
    }
    if (command.action === "ISSUE") {
      if (!decision.approved) throw new Error("V2 subject decision is not approved");
      const lifetime = command.expiresAt - this.now();
      const maximum = command.slot === "IDENTITY" ? 86_400n : 3_600n;
      if (lifetime <= 0n || lifetime > maximum) throw new Error("V2 credential lifetime violation");
      if (decision.expiresAt !== undefined && command.expiresAt > decision.expiresAt) {
        throw new Error("V2 credential outlives subject decision");
      }
    } else if (command.reason === "HOLDER_DISABLED" && decision.approved) {
      throw new Error("V2 holder-disabled revoke requires an adverse subject decision");
    }
    if (!(await this.policy.isIkActiveAndAuthorized(
      command.anchor,
      command.ikId,
      command.regimeHash,
      this.signerAddress,
    ))) throw new Error("V2 IK is inactive or unauthorized");

    const authoritative = await this.walletSets.readWalletSet(command.subjectId, command.activeDID);
    this.assertWalletSet(command, authoritative);
    const did = await this.policy.readDid(command.activeDID);
    if (!did.exists || !sameHex(did.spendingKeyRoot, authoritative.walletSet.root)) {
      throw new Error("V2 DID spending-wallet root mismatch");
    }
    if (!sameControllerSet(did.governanceKeys, authoritative.governanceControllers)) {
      throw new Error("V2 DID governance controllers mismatch");
    }
    if (command.action === "ISSUE") {
      if (BigInt(did.privateSaltCommitment) !== computeSaltCommitment(this.hasher, BigInt(command.privateSalt))) {
        throw new Error("V2 DID private-salt commitment mismatch");
      }
      const recomputed = computeCredentialLeaf(this.hasher, {
        chainId: command.chainId, anchor: command.anchor, regimeHash: command.regimeHash,
        did: command.activeDID, ikId: command.ikId, attributes: command.attributes,
        privateSalt: command.privateSalt, expiresAt: command.expiresAt,
      });
      if (!sameHex(recomputed, command.commitment)) {
        throw new Error("V2 credential commitment differs from recomputed leaf");
      }
    }
    const existing = await this.policy.readCredential(
      command.anchor,
      command.regimeHash,
      command.activeDID,
    );
    if (command.action === "ISSUE" && existing.issuedAt !== 0n && !existing.revoked) {
      throw new Error("V2 credential slot is already active");
    }
    if (command.action === "REVOKE" && (existing.issuedAt === 0n || existing.revoked)) {
      throw new Error("no active V2 credential to revoke");
    }
  }

  private assertWalletSet(
    command: IkCommandV2,
    authoritative: AuthoritativeWalletSetRecordV2,
  ): void {
    const set = authoritative.walletSet;
    if (
      authoritative.subjectId !== command.subjectId ||
      !sameHex(authoritative.activeDID, command.activeDID)
    ) throw new Error("V2 authoritative wallet set subject/DID mismatch");
    if (set.profile !== GAP_SPENDING_WALLET_SET_V2 || set.assignments.length === 0) {
      throw new Error("V2 authoritative wallet set profile/content mismatch");
    }
    if (set.revision !== command.walletSetRevision) throw new Error("stale V2 wallet-set revision");
    if (!sameHex(set.root, command.expectedSpendingRoot)) throw new Error("stale V2 wallet-set root");
    const reconstructed = new AssignedSlotSpendingWalletSet(this.hasher, null, set);
    if (!sameHex(reconstructed.root(), set.root)) throw new Error("invalid authoritative V2 wallet-set root");
    assertStableGovernanceControllers(
      authoritative.governanceControllers,
      set.assignments.map(({ account }) => account),
    );
  }
}
