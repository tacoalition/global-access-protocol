import { assertBytes, assertField } from "./field";
import type { Address, Bytes32, CredentialAction, CredentialSlot } from "./types";

export const UINT64_MAX = (1n << 64n) - 1n;
export const REVOKE_REASONS = ["HOLDER_DISABLED", "EXPIRED_FOR_REISSUE", "IK_REPLACED"] as const;
export type RevokeReason = (typeof REVOKE_REASONS)[number];

interface CommandBase {
  readonly schemaVersion: 1;
  readonly slot: CredentialSlot;
  readonly action: CredentialAction;
  readonly chainId: 84532;
  readonly anchor: Address;
  readonly regimeHash: Bytes32;
  readonly activeDID: Bytes32;
  readonly ikId: Bytes32;
  readonly subjectId: string;
  readonly wallet: Address;
  readonly token?: Address;
  readonly sourceDecisionRevision: bigint;
  readonly credentialRevision: bigint;
  readonly sourceDecisionDigest: Bytes32;
  readonly calldataDigest: Bytes32;
  readonly idempotencyKey: string;
}

export interface IssueCredentialCommand extends CommandBase {
  readonly action: "ISSUE";
  /**
   * One REGIME's four attributes under GAP_ATTR_CRED_V3.
   * IDENTITY (regime 0): [residency, sanctions, citizenship, reserved], derived from the
   * verified provider decision. FUND (regime 1): always exactly [1n, 1n, 0n, 0n]: a KYC
   * vendor does not attest suitability, so the fund slot stays constant.
   */
  readonly attributes: readonly [bigint, bigint, bigint, bigint];
  readonly privateSalt: Bytes32;
  readonly expiresAt: bigint;
  readonly commitment: Bytes32;
  readonly expectedSpendingRoot: Bytes32;
}

export interface RevokeCredentialCommand extends CommandBase {
  readonly action: "REVOKE";
  readonly reason: RevokeReason;
}

export type IkCommand = IssueCredentialCommand | RevokeCredentialCommand;

export interface IkCommandJson {
  readonly schemaVersion: 1;
  readonly slot: CredentialSlot;
  readonly action: CredentialAction;
  readonly chainId: 84532;
  readonly anchor: string;
  readonly regimeHash: string;
  readonly activeDID: string;
  readonly ikId: string;
  readonly subjectId: string;
  readonly wallet: string;
  readonly token?: string;
  readonly sourceDecisionRevision: string;
  readonly credentialRevision: string;
  readonly sourceDecisionDigest: string;
  readonly calldataDigest: string;
  readonly idempotencyKey: string;
  readonly attributes?: readonly [string, string, string, string];
  readonly privateSalt?: string;
  readonly expiresAt?: string;
  readonly commitment?: string;
  readonly expectedSpendingRoot?: string;
  readonly reason?: string;
}

export function parseUint64(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} must be canonical decimal uint64`);
  const parsed = BigInt(value);
  if (parsed > UINT64_MAX) throw new Error(`${label} exceeds uint64`);
  return parsed;
}

export function formatUint64(value: bigint, label = "value"): string {
  if (value < 0n || value > UINT64_MAX) throw new Error(`${label} exceeds uint64`);
  return value.toString(10);
}

export function canonicalIdempotencyKey(command: Pick<IkCommand, "chainId" | "anchor" | "regimeHash" | "activeDID" | "slot" | "credentialRevision" | "action">): string {
  return ["dsi-ik-v1", command.chainId, command.anchor.toLowerCase(), command.regimeHash.toLowerCase(), command.activeDID.toLowerCase(), command.slot, command.credentialRevision, command.action].join(":");
}

function expectObject(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("IK command must be an object");
  return input as Record<string, unknown>;
}

function expectString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a nonempty string`);
  return value;
}

function expectBytes(value: unknown, length: number, label: string): `0x${string}` {
  const text = expectString(value, label);
  assertBytes(text, length, label);
  return text.toLowerCase() as `0x${string}`;
}

function expectSubject(value: unknown): string {
  const subject = expectString(value, "subjectId");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(subject)) {
    throw new Error("subjectId must be canonical lowercase UUIDv4");
  }
  return subject;
}

function allowedKeys(action: CredentialAction): Set<string> {
  const base = ["schemaVersion", "slot", "action", "chainId", "anchor", "regimeHash", "activeDID", "ikId", "subjectId", "wallet", "token", "sourceDecisionRevision", "credentialRevision", "sourceDecisionDigest", "calldataDigest", "idempotencyKey"];
  return new Set(action === "ISSUE" ? [...base, "attributes", "privateSalt", "expiresAt", "commitment", "expectedSpendingRoot"] : [...base, "reason"]);
}

function parseAttributes(value: unknown, slot: CredentialSlot): readonly [bigint, bigint, bigint, bigint] {
  if (!Array.isArray(value) || value.length !== 4) {
    throw new Error("issuer attributes must be four values (one regime under GAP_ATTR_CRED_V3)");
  }
  if (slot === "FUND") {
    // The Fund IK does not derive attributes from a KYC decision: accredited and QP are its own
    // determination, and the two trailing slots are reserved and must be zero.
    if (value[0] !== "1" || value[1] !== "1" || value[2] !== "0" || value[3] !== "0") {
      throw new Error("fund issuer attributes must be exactly [1,1,0,0]");
    }
    return [1n, 1n, 0n, 0n];
  }
  return [
    parseUint64(value[0], "attributes[0]"),
    parseUint64(value[1], "attributes[1]"),
    parseUint64(value[2], "attributes[2]"),
    parseUint64(value[3], "attributes[3]"),
  ];
}

export function parseIkCommand(input: unknown): IkCommand {
  const value = expectObject(input);
  if (value.schemaVersion !== 1 || value.chainId !== 84532) throw new Error("unsupported IK command version/chain");
  if (value.slot !== "IDENTITY" && value.slot !== "FUND") throw new Error("invalid credential slot");
  if (value.action !== "ISSUE" && value.action !== "REVOKE") throw new Error("invalid credential action");
  for (const key of Object.keys(value)) if (!allowedKeys(value.action).has(key)) throw new Error(`unexpected IK command key: ${key}`);
  const common = {
    schemaVersion: 1 as const,
    slot: value.slot as CredentialSlot,
    action: value.action,
    chainId: 84532 as const,
    anchor: expectBytes(value.anchor, 20, "anchor"),
    regimeHash: expectBytes(value.regimeHash, 32, "regimeHash"),
    activeDID: expectBytes(value.activeDID, 32, "activeDID"),
    ikId: expectBytes(value.ikId, 32, "ikId"),
    subjectId: expectSubject(value.subjectId),
    wallet: expectBytes(value.wallet, 20, "wallet"),
    ...(value.slot === "FUND" ? { token: expectBytes(value.token, 20, "token") } : {}),
    sourceDecisionRevision: parseUint64(value.sourceDecisionRevision, "sourceDecisionRevision"),
    credentialRevision: parseUint64(value.credentialRevision, "credentialRevision"),
    sourceDecisionDigest: expectBytes(value.sourceDecisionDigest, 32, "sourceDecisionDigest"),
    calldataDigest: expectBytes(value.calldataDigest, 32, "calldataDigest"),
    idempotencyKey: expectString(value.idempotencyKey, "idempotencyKey"),
  };
  if (common.credentialRevision === 0n || common.sourceDecisionRevision === 0n) throw new Error("mutating revisions must be nonzero");
  let command: IkCommand;
  if (value.action === "ISSUE") {
    const attributes = parseAttributes(value.attributes, common.slot);
    const privateSalt = expectBytes(value.privateSalt, 32, "privateSalt");
    assertField(BigInt(privateSalt), "privateSalt");
    const commitment = expectBytes(value.commitment, 32, "commitment");
    assertField(BigInt(commitment), "commitment");
    const expiresAt = parseUint64(value.expiresAt, "expiresAt");
    if (expiresAt === 0n) throw new Error("demo credentials require a finite expiry");
    command = { ...common, action: "ISSUE", attributes, privateSalt, expiresAt, commitment, expectedSpendingRoot: expectBytes(value.expectedSpendingRoot, 32, "expectedSpendingRoot") };
  } else {
    if (!REVOKE_REASONS.includes(value.reason as RevokeReason)) throw new Error("revoke reason is not allowlisted");
    command = { ...common, action: "REVOKE", reason: value.reason as RevokeReason };
  }
  if (command.idempotencyKey !== canonicalIdempotencyKey(command)) throw new Error("noncanonical idempotency key");
  return command;
}

export function serializeIkCommand(command: IkCommand): IkCommandJson {
  const common: IkCommandJson = {
    schemaVersion: 1, slot: command.slot, action: command.action, chainId: 84532,
    anchor: command.anchor, regimeHash: command.regimeHash, activeDID: command.activeDID,
    ikId: command.ikId, subjectId: command.subjectId, wallet: command.wallet,
    ...(command.token ? { token: command.token } : {}),
    sourceDecisionRevision: formatUint64(command.sourceDecisionRevision), credentialRevision: formatUint64(command.credentialRevision),
    sourceDecisionDigest: command.sourceDecisionDigest, calldataDigest: command.calldataDigest,
    idempotencyKey: command.idempotencyKey,
  };
  return command.action === "ISSUE"
    ? { ...common, attributes: [
        formatUint64(command.attributes[0], "attributes[0]"),
        formatUint64(command.attributes[1], "attributes[1]"),
        formatUint64(command.attributes[2], "attributes[2]"),
        formatUint64(command.attributes[3], "attributes[3]"),
      ], privateSalt: command.privateSalt, expiresAt: formatUint64(command.expiresAt), commitment: command.commitment, expectedSpendingRoot: command.expectedSpendingRoot }
    : { ...common, reason: command.reason };
}
