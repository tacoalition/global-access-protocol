import { createHash } from "node:crypto";
import type { RevokeReason } from "./command-schema";
import type { CanonicalReceipt, CredentialReadback, Bytes32 } from "./types";
import { SchemaRestrictedSigner, type AnchorMutation } from "./signer";

export const IDENTITY_ANCHOR_V2_ABI = [
  "issueCredential(bytes32 regimeHash,bytes32 did,bytes32 commitment,uint256 expiresAt,bytes32 ikId,bytes32 metadata)",
  "revokeCredential(bytes32 regimeHash,bytes32 did,string reason)",
  "getCredential(bytes32 regimeHash,bytes32 did)",
  "getCredentialProof(bytes32 regimeHash,bytes32 did)",
] as const;

export interface IdentityAnchorReadPort {
  simulateCredentialMutation(mutation: AnchorMutation, from: `0x${string}`): Promise<void>;
  waitForCanonicalReceipt(transactionHash: Bytes32, confirmations: number): Promise<CanonicalReceipt>;
  getCredential(anchor: `0x${string}`, regimeHash: Bytes32, did: Bytes32, blockNumber?: bigint): Promise<CredentialReadback>;
}

export interface AnchorMutationResult {
  readonly transactionHash: Bytes32;
  readonly receipt: CanonicalReceipt;
  readonly readback: CredentialReadback;
  readonly calldataDigest: Bytes32;
}

export interface SubmittedAnchorMutation {
  readonly transactionHash: Bytes32;
  readonly calldataDigest: Bytes32;
}

export type AnchorCommand =
  | {
      readonly action: "ISSUE";
      readonly anchor: `0x${string}`;
      readonly regimeHash: Bytes32;
      readonly activeDID: Bytes32;
      readonly commitment: Bytes32;
      readonly expiresAt: bigint;
      readonly ikId: Bytes32;
      /**
       * Issuer-set, opaque, PUBLIC and in no proof. OPTIONAL: omitted means `0x00..00`, "none",
       * which is what every lane here uses. An Identity Trust Anchor doing Appendix III Sybil
       * detection is the reason it exists, read the warning on IdentityAnchor.Credential.metadata
       * before putting anything derived from PII in it.
       */
      readonly metadata?: Bytes32;
    }
  | {
      readonly action: "REVOKE";
      readonly anchor: `0x${string}`;
      readonly regimeHash: Bytes32;
      readonly activeDID: Bytes32;
      readonly reason: RevokeReason;
      readonly ikId: Bytes32;
    };

export class ReorgDetectedError extends Error {
  constructor() { super("credential mutation receipt is not canonical"); }
}

/** "No metadata": the default, and what every lane in this repository issues. */
export const NO_METADATA = `0x${"0".repeat(64)}` as const;

function word(value: string | bigint): Buffer {
  const hex = typeof value === "bigint" ? value.toString(16) : value.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length > 64) throw new Error("ABI word exceeds 32 bytes");
  return Buffer.from(hex.padStart(64, "0"), "hex");
}

export function anchorCalldata(mutation: AnchorMutation): Uint8Array {
  if (mutation.functionName === "issueCredential") {
    return Buffer.concat([
      Buffer.from("cbaf4a8f", "hex"), word(mutation.regimeHash), word(mutation.did),
      word(mutation.commitment), word(mutation.expiresAt), word(mutation.ikId),
      word(mutation.metadata ?? NO_METADATA),
    ]);
  }
  const reason = Buffer.from(mutation.reason, "utf8");
  const padding = Buffer.alloc((32 - (reason.length % 32)) % 32);
  return Buffer.concat([
    Buffer.from("276b3854", "hex"), word(mutation.regimeHash), word(mutation.did), word(96n),
    word(BigInt(reason.length)), reason, padding,
  ]);
}

export function anchorCalldataDigest(mutation: AnchorMutation): Bytes32 {
  return `0x${createHash("sha256").update(anchorCalldata(mutation)).digest("hex")}`;
}

export class IdentityAnchorClient {
  constructor(
    private readonly reader: IdentityAnchorReadPort,
    private readonly signer: SchemaRestrictedSigner,
    private readonly confirmations: number,
  ) {
    if (!Number.isInteger(confirmations) || confirmations < 1) throw new Error("confirmations must be positive");
  }

  mutationFor(command: AnchorCommand): AnchorMutation {
    return command.action === "ISSUE"
      ? {
          functionName: "issueCredential", anchor: command.anchor, regimeHash: command.regimeHash,
          did: command.activeDID, commitment: command.commitment, expiresAt: command.expiresAt,
          ikId: command.ikId, metadata: command.metadata ?? NO_METADATA,
        }
      : {
          functionName: "revokeCredential", anchor: command.anchor, regimeHash: command.regimeHash,
          did: command.activeDID, reason: command.reason, ikId: command.ikId,
        };
  }

  digestFor(command: AnchorCommand): Bytes32 {
    return anchorCalldataDigest(this.mutationFor(command));
  }

  async execute(command: AnchorCommand): Promise<AnchorMutationResult> {
    const submitted = await this.submit(command);
    return this.confirm(command, submitted.transactionHash);
  }

  async submit(command: AnchorCommand): Promise<SubmittedAnchorMutation> {
    const mutation = this.mutationFor(command);
    await this.reader.simulateCredentialMutation(mutation, this.signer.address);
    const transactionHash = await this.signer.submit(mutation);
    return { transactionHash, calldataDigest: anchorCalldataDigest(mutation) };
  }

  async confirm(command: AnchorCommand, transactionHash: Bytes32): Promise<AnchorMutationResult> {
    const mutation = this.mutationFor(command);
    const calldataDigest = anchorCalldataDigest(mutation);
    const receipt = await this.reader.waitForCanonicalReceipt(transactionHash, this.confirmations);
    if (!receipt.canonical) throw new ReorgDetectedError();
    if (
      receipt.status !== "SUCCESS" ||
      receipt.transactionHash.toLowerCase() !== transactionHash.toLowerCase() ||
      receipt.from.toLowerCase() !== this.signer.address.toLowerCase() ||
      receipt.to.toLowerCase() !== command.anchor.toLowerCase() ||
      receipt.calldataDigest.toLowerCase() !== calldataDigest.toLowerCase()
    ) {
      throw new Error("canonical receipt does not match the exact submitted credential mutation");
    }
    const readback = await this.reader.getCredential(command.anchor, command.regimeHash, command.activeDID, receipt.blockNumber);
    if (command.action === "ISSUE") {
      if (readback.revoked || readback.commitment.toLowerCase() !== command.commitment.toLowerCase() ||
          readback.issuerIKId.toLowerCase() !== command.ikId.toLowerCase() || readback.expiresAt !== command.expiresAt) {
        throw new Error("canonical issue receipt does not match anchor readback");
      }
    } else if (!readback.revoked) {
      throw new Error("canonical revoke receipt does not match anchor readback");
    }
    return { transactionHash, receipt, readback, calldataDigest };
  }
}
