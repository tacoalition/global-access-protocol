import { createHash } from "node:crypto";
import { parseIkCommand, serializeIkCommand, type IkCommand, type IkCommandJson } from "./command-schema";
import { computeCredentialLeaf, computeOneLeafRoot, computeSaltCommitment } from "./credential-builder";
import { addressToField, type Poseidon2 } from "./field";
import { IdentityAnchorClient, ReorgDetectedError, type AnchorMutationResult } from "./identity-anchor-client";
import type { CredentialReadback, CredentialSlot, DidBindingReadback, SourceDecisionSnapshot, TransitionStatus, Bytes32 } from "./types";

export interface AuthoritativeDecisionPort {
  readDecision(slot: CredentialSlot, subjectId: string, token?: `0x${string}`): Promise<SourceDecisionSnapshot>;
}

export interface IkPolicyReadPort {
  readDid(did: Bytes32): Promise<DidBindingReadback>;
  isIkActiveAndAuthorized(anchor: `0x${string}`, ikId: Bytes32, regimeHash: Bytes32, signer: `0x${string}`): Promise<boolean>;
  readCredential(anchor: `0x${string}`, regimeHash: Bytes32, did: Bytes32): Promise<CredentialReadback>;
}

export interface WorkerTransition {
  readonly idempotencyKey: string;
  readonly commandDigest: Bytes32;
  readonly status: TransitionStatus;
  readonly transactionHash?: Bytes32;
  readonly result?: AnchorMutationResult;
  readonly auditedAbandonReason?: string;
}

export interface WorkerStateStore {
  begin(command: IkCommand, commandDigest: Bytes32): Promise<WorkerTransition>;
  submitted(idempotencyKey: string, transactionHash: Bytes32): Promise<void>;
  confirmed(idempotencyKey: string, result: AnchorMutationResult): Promise<void>;
  pendingAfterReorg(idempotencyKey: string): Promise<void>;
}

export class InMemoryWorkerStateStore implements WorkerStateStore {
  private readonly rows = new Map<string, WorkerTransition>();

  async begin(command: IkCommand, commandDigest: Bytes32): Promise<WorkerTransition> {
    const prior = this.rows.get(command.idempotencyKey);
    if (prior) {
      if (prior.commandDigest !== commandDigest) throw new Error("idempotency key reused with different command bytes");
      return prior;
    }
    const row: WorkerTransition = { idempotencyKey: command.idempotencyKey, commandDigest, status: "PENDING" };
    this.rows.set(command.idempotencyKey, row);
    return row;
  }

  async submitted(idempotencyKey: string, transactionHash: Bytes32): Promise<void> {
    const row = this.require(idempotencyKey);
    this.rows.set(idempotencyKey, { ...row, status: "SUBMITTED", transactionHash });
  }

  async confirmed(idempotencyKey: string, result: AnchorMutationResult): Promise<void> {
    const row = this.require(idempotencyKey);
    this.rows.set(idempotencyKey, { ...row, status: "CONFIRMED", transactionHash: result.transactionHash, result });
  }

  async pendingAfterReorg(idempotencyKey: string): Promise<void> {
    const row = this.require(idempotencyKey);
    this.rows.set(idempotencyKey, { idempotencyKey, commandDigest: row.commandDigest, status: "PENDING" });
  }

  get(idempotencyKey: string): WorkerTransition | undefined { return this.rows.get(idempotencyKey); }

  private require(key: string): WorkerTransition {
    const row = this.rows.get(key);
    if (!row) throw new Error("worker transition does not exist");
    return row;
  }
}

function commandDigest(command: IkCommand): Bytes32 {
  return `0x${createHash("sha256").update(JSON.stringify(serializeIkCommand(command))).digest("hex")}`;
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return left?.toLowerCase() === right?.toLowerCase();
}

export class GapIdentityKeeperV2Worker {
  constructor(
    private readonly slot: CredentialSlot,
    private readonly hasher: Poseidon2,
    private readonly decisions: AuthoritativeDecisionPort,
    private readonly policy: IkPolicyReadPort,
    private readonly anchor: IdentityAnchorClient,
    private readonly state: WorkerStateStore,
    private readonly signerAddress: `0x${string}`,
    private readonly now: () => bigint = () => BigInt(Math.floor(Date.now() / 1000)),
  ) {}

  async handle(json: IkCommandJson | unknown): Promise<AnchorMutationResult> {
    const command = parseIkCommand(json);
    if (command.slot !== this.slot) throw new Error("command routed to wrong IK worker");
    const digest = commandDigest(command);
    const transition = await this.state.begin(command, digest);
    if (transition.status === "CONFIRMED" && transition.result) return transition.result;
    if (transition.status === "ABANDONED") throw new Error("credential transition was abandoned");
    try {
      let transactionHash = transition.transactionHash;
      if (transition.status === "PENDING") {
        await this.authorize(command);
        const submitted = await this.anchor.submit(command);
        transactionHash = submitted.transactionHash;
        await this.state.submitted(command.idempotencyKey, transactionHash);
      }
      if (!transactionHash) throw new Error("submitted transition is missing transaction hash");
      const result = await this.anchor.confirm(command, transactionHash);
      await this.state.confirmed(command.idempotencyKey, result);
      return result;
    } catch (error) {
      if (error instanceof ReorgDetectedError) await this.state.pendingAfterReorg(command.idempotencyKey);
      throw error;
    }
  }

  private async authorize(command: IkCommand): Promise<void> {
    if (this.anchor.digestFor(command).toLowerCase() !== command.calldataDigest.toLowerCase()) throw new Error("command calldata digest mismatch");
    const decision = await this.decisions.readDecision(command.slot, command.subjectId, command.token);
    if (decision.revision !== command.sourceDecisionRevision || !sameHex(decision.evidenceDigest, command.sourceDecisionDigest)) throw new Error("stale or substituted source decision");
    if (decision.subjectId !== command.subjectId || !sameHex(decision.wallet, command.wallet) || !sameHex(decision.did, command.activeDID)) throw new Error("decision subject/wallet/DID mismatch");
    if (command.slot === "FUND" && !sameHex(decision.token, command.token)) throw new Error("TA decision token mismatch");
    if (command.action === "ISSUE") {
      if (!decision.approved) throw new Error("source decision is not approved");
      if (command.slot === "IDENTITY") {
        if (!decision.attributes) throw new Error("identity issuance requires provider-derived attributes");
        if (command.attributes[0] !== decision.attributes[0] || command.attributes[1] !== decision.attributes[1]) {
          throw new Error("credential attributes do not match the verified provider decision");
        }
      }
      const lifetime = command.expiresAt - this.now();
      const maximum = command.slot === "IDENTITY" ? 24n * 60n * 60n : 60n * 60n;
      if (lifetime <= 0n || lifetime > maximum) throw new Error("credential expiry violates slot lifetime policy");
      if (decision.expiresAt !== undefined && command.expiresAt > decision.expiresAt) throw new Error("credential outlives source decision");
    } else if (command.reason === "HOLDER_DISABLED" && decision.approved) {
      throw new Error("holder-disabled revoke requires an adverse decision");
    }
    if (!(await this.policy.isIkActiveAndAuthorized(command.anchor, command.ikId, command.regimeHash, this.signerAddress))) throw new Error("IK is inactive, unauthorized, or controlled by another signer");
    const did = await this.policy.readDid(command.activeDID);
    if (!did.exists || did.governanceKeys.length !== 1 || !sameHex(did.governanceKeys[0], command.wallet)) throw new Error("DID does not have the exact one-wallet governance binding");
    if (command.action === "ISSUE") {
      const spendingLeaf = this.hasher.hash2(addressToField(command.wallet), 0n);
      const spendingRoot = computeOneLeafRoot(this.hasher, spendingLeaf, Number(addressToField(command.wallet) & 0xffn), 8);
      if (BigInt(did.spendingKeyRoot) !== spendingRoot || BigInt(command.expectedSpendingRoot) !== spendingRoot) throw new Error("DID spending-key root mismatch");
      if (BigInt(did.privateSaltCommitment) !== computeSaltCommitment(this.hasher, BigInt(command.privateSalt))) throw new Error("DID private-salt commitment mismatch");
      const recomputed = computeCredentialLeaf(this.hasher, {
        chainId: command.chainId, anchor: command.anchor, regimeHash: command.regimeHash,
        did: command.activeDID, ikId: command.ikId, attributes: command.attributes,
        privateSalt: command.privateSalt, expiresAt: command.expiresAt,
      });
      if (!sameHex(recomputed, command.commitment)) throw new Error("credential commitment differs from recomputed leaf");
      const existing = await this.policy.readCredential(command.anchor, command.regimeHash, command.activeDID);
      if (existing.issuedAt !== 0n && !existing.revoked) throw new Error("credential slot is already active");
    } else {
      const existing = await this.policy.readCredential(command.anchor, command.regimeHash, command.activeDID);
      if (existing.issuedAt === 0n || existing.revoked) throw new Error("no active credential to revoke");
    }
  }
}
