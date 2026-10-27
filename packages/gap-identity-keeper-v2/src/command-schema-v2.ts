import { REVOKE_REASONS, formatUint64, parseUint64, type RevokeReason } from "./command-schema";
import { assertBytes, assertField } from "./field";
import { GAP_SPENDING_WALLET_SET_V2 } from "./spending-wallet-set";
import type { Address, Bytes32, CredentialAction, CredentialSlot } from "./types";

interface CommandBaseV2 {
  readonly schemaVersion: 2;
  readonly credentialScope: "SUBJECT";
  readonly walletSetProfile: typeof GAP_SPENDING_WALLET_SET_V2;
  readonly slot: CredentialSlot;
  readonly action: CredentialAction;
  readonly chainId: 84532;
  readonly anchor: Address;
  readonly regimeHash: Bytes32;
  readonly activeDID: Bytes32;
  readonly ikId: Bytes32;
  readonly subjectId: string;
  readonly token?: Address;
  readonly sourceDecisionRevision: bigint;
  readonly credentialRevision: bigint;
  readonly sourceDecisionDigest: Bytes32;
  readonly calldataDigest: Bytes32;
  readonly idempotencyKey: string;
  readonly expectedSpendingRoot: Bytes32;
  readonly walletSetRevision: bigint;
}

export interface IssueCredentialCommandV2 extends CommandBaseV2 {
  readonly action: "ISSUE";
  /** One regime's four attributes under GAP_ATTR_CRED_V3; the trailing two are reserved. */
  readonly attributes: readonly [1n, 1n, 0n, 0n];
  readonly privateSalt: Bytes32;
  readonly expiresAt: bigint;
  readonly commitment: Bytes32;
}

export interface RevokeCredentialCommandV2 extends CommandBaseV2 {
  readonly action: "REVOKE";
  readonly reason: RevokeReason;
}

export type IkCommandV2 = IssueCredentialCommandV2 | RevokeCredentialCommandV2;

export interface IkCommandJsonV2 {
  readonly schemaVersion: 2;
  readonly credentialScope: "SUBJECT";
  readonly walletSetProfile: typeof GAP_SPENDING_WALLET_SET_V2;
  readonly slot: CredentialSlot;
  readonly action: CredentialAction;
  readonly chainId: 84532;
  readonly anchor: string;
  readonly regimeHash: string;
  readonly activeDID: string;
  readonly ikId: string;
  readonly subjectId: string;
  readonly token?: string;
  readonly sourceDecisionRevision: string;
  readonly credentialRevision: string;
  readonly sourceDecisionDigest: string;
  readonly calldataDigest: string;
  readonly idempotencyKey: string;
  readonly expectedSpendingRoot: string;
  readonly walletSetRevision: string;
  readonly attributes?: readonly [string, string, string, string];
  readonly privateSalt?: string;
  readonly expiresAt?: string;
  readonly commitment?: string;
  readonly reason?: string;
}

export function canonicalIdempotencyKeyV2(
  command: Pick<
    IkCommandV2,
    "chainId" | "anchor" | "regimeHash" | "activeDID" | "slot" | "credentialRevision" | "action"
  >,
): string {
  return [
    "dsi-ik-v2",
    command.chainId,
    command.anchor.toLowerCase(),
    command.regimeHash.toLowerCase(),
    command.activeDID.toLowerCase(),
    command.slot,
    command.credentialRevision,
    command.action,
  ].join(":");
}

function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("V2 IK command must be an object");
  }
  return input as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a nonempty string`);
  }
  return value;
}

function bytes(value: unknown, length: number, label: string): `0x${string}` {
  const encoded = string(value, label);
  assertBytes(encoded, length, label);
  return encoded.toLowerCase() as `0x${string}`;
}

function subject(value: unknown): string {
  const id = string(value, "subjectId");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
    throw new Error("subjectId must be canonical lowercase UUIDv4");
  }
  return id;
}

function allowedKeys(action: CredentialAction): Set<string> {
  const common = [
    "schemaVersion", "credentialScope", "walletSetProfile", "slot", "action", "chainId",
    "anchor", "regimeHash", "activeDID", "ikId", "subjectId", "token",
    "sourceDecisionRevision", "credentialRevision", "sourceDecisionDigest", "calldataDigest",
    "idempotencyKey", "expectedSpendingRoot", "walletSetRevision",
  ];
  return new Set(action === "ISSUE"
    ? [...common, "attributes", "privateSalt", "expiresAt", "commitment"]
    : [...common, "reason"]);
}

export function parseIkCommandV2(input: unknown): IkCommandV2 {
  const value = object(input);
  if (
    value.schemaVersion !== 2 ||
    value.credentialScope !== "SUBJECT" ||
    value.walletSetProfile !== GAP_SPENDING_WALLET_SET_V2 ||
    value.chainId !== 84532
  ) {
    throw new Error("unsupported V2 IK command profile/version/chain");
  }
  if (value.slot !== "IDENTITY" && value.slot !== "FUND") throw new Error("invalid credential slot");
  if (value.action !== "ISSUE" && value.action !== "REVOKE") throw new Error("invalid credential action");
  for (const key of Object.keys(value)) {
    if (!allowedKeys(value.action).has(key)) throw new Error(`unexpected V2 IK command key: ${key}`);
  }
  const common = {
    schemaVersion: 2 as const,
    credentialScope: "SUBJECT" as const,
    walletSetProfile: GAP_SPENDING_WALLET_SET_V2,
    slot: value.slot as CredentialSlot,
    action: value.action,
    chainId: 84532 as const,
    anchor: bytes(value.anchor, 20, "anchor"),
    regimeHash: bytes(value.regimeHash, 32, "regimeHash"),
    activeDID: bytes(value.activeDID, 32, "activeDID"),
    ikId: bytes(value.ikId, 32, "ikId"),
    subjectId: subject(value.subjectId),
    ...(value.slot === "FUND" ? { token: bytes(value.token, 20, "token") } : {}),
    sourceDecisionRevision: parseUint64(value.sourceDecisionRevision, "sourceDecisionRevision"),
    credentialRevision: parseUint64(value.credentialRevision, "credentialRevision"),
    sourceDecisionDigest: bytes(value.sourceDecisionDigest, 32, "sourceDecisionDigest"),
    calldataDigest: bytes(value.calldataDigest, 32, "calldataDigest"),
    idempotencyKey: string(value.idempotencyKey, "idempotencyKey"),
    expectedSpendingRoot: bytes(value.expectedSpendingRoot, 32, "expectedSpendingRoot"),
    walletSetRevision: parseUint64(value.walletSetRevision, "walletSetRevision"),
  };
  if (
    common.sourceDecisionRevision === 0n ||
    common.credentialRevision === 0n ||
    common.walletSetRevision === 0n
  ) {
    throw new Error("V2 mutating revisions must be nonzero");
  }
  let command: IkCommandV2;
  if (value.action === "ISSUE") {
    if (
      !Array.isArray(value.attributes) || value.attributes.length !== 4
      || value.attributes[0] !== "1" || value.attributes[1] !== "1"
      || value.attributes[2] !== "0" || value.attributes[3] !== "0"
    ) {
      throw new Error("issuer attributes must be exactly [1,1,0,0]");
    }
    const privateSalt = bytes(value.privateSalt, 32, "privateSalt");
    const commitment = bytes(value.commitment, 32, "commitment");
    assertField(BigInt(privateSalt), "privateSalt");
    assertField(BigInt(commitment), "commitment");
    const expiresAt = parseUint64(value.expiresAt, "expiresAt");
    if (expiresAt === 0n) throw new Error("V2 credentials require a finite expiry");
    command = { ...common, action: "ISSUE", attributes: [1n, 1n, 0n, 0n], privateSalt, commitment, expiresAt };
  } else {
    if (!REVOKE_REASONS.includes(value.reason as RevokeReason)) {
      throw new Error("revoke reason is not allowlisted");
    }
    command = { ...common, action: "REVOKE", reason: value.reason as RevokeReason };
  }
  if (command.idempotencyKey !== canonicalIdempotencyKeyV2(command)) {
    throw new Error("noncanonical V2 idempotency key");
  }
  return command;
}

export function serializeIkCommandV2(command: IkCommandV2): IkCommandJsonV2 {
  const common: IkCommandJsonV2 = {
    schemaVersion: 2, credentialScope: "SUBJECT", walletSetProfile: GAP_SPENDING_WALLET_SET_V2,
    slot: command.slot, action: command.action, chainId: 84532, anchor: command.anchor,
    regimeHash: command.regimeHash, activeDID: command.activeDID, ikId: command.ikId,
    subjectId: command.subjectId, ...(command.token ? { token: command.token } : {}),
    sourceDecisionRevision: formatUint64(command.sourceDecisionRevision),
    credentialRevision: formatUint64(command.credentialRevision),
    sourceDecisionDigest: command.sourceDecisionDigest, calldataDigest: command.calldataDigest,
    idempotencyKey: command.idempotencyKey, expectedSpendingRoot: command.expectedSpendingRoot,
    walletSetRevision: formatUint64(command.walletSetRevision),
  };
  return command.action === "ISSUE"
    ? { ...common, attributes: ["1", "1", "0", "0"], privateSalt: command.privateSalt,
        expiresAt: formatUint64(command.expiresAt), commitment: command.commitment }
    : { ...common, reason: command.reason };
}
