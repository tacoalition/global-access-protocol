// THE fund-IK suitability gate: the only source of attrs[2..3].
//
// It is the exact twin of `services/gap-ik-api/src/provider-gate-config` +
// `identity-credential-gate` and follows the same two rules those follow: an
// unconfigured gate is a REFUSAL and never a bypass, and partial configuration
// throws rather than half-arming anything.
//
// WHY IT IS HERE AND NOT IN THE CLI. This composition was written for the CLI
// demo lane and lived in `packages/gap-cli/src/suitability-gate.ts`, so the IK
// SERVICE: the lane that actually mints the fund credential on the joined
// deployment, could not reach it and wrote `attrs[2..3] = [1n, 1n]` from a
// constant instead. That constant is what `packages/gap-cli/src/state.ts`
// ZONES["reg-d"] turns into access to the regulated zone, so a GREEN identity
// check alone unlocked it. It now sits beside the verifier it composes, in the
// one package BOTH lanes already import; `packages/gap-cli/src/suitability-gate.ts`
// re-exports it so there is one implementation, not two.
//
// Nothing here re-decides what `./suitability-attestation` decides. This module
// only answers "what did the operator configure, and where is the artifact".
import * as fs from "fs";
import {
  verifySuitabilityAttestation,
  type SuitabilityPolicy,
  type VerifiedSuitability,
} from "./suitability-attestation";

export interface SuitabilityGateConfig {
  readonly policy: SuitabilityPolicy;
  /** The signed artifact itself, as the operator supplied it. */
  readonly attestation: unknown;
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) throw new Error(`${key} is required once the suitability gate is configured`);
  return value;
}

function parsePinnedKeys(raw: string, variable: string): Readonly<Record<string, string>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${variable} must be valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${variable} must be a keyId -> public key object`);
  }
  const keys: Record<string, string> = {};
  for (const [keyId, value] of Object.entries(parsed)) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyId)) throw new Error(`pinned suitability keyId ${keyId} is malformed`);
    if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) {
      throw new Error(`pinned suitability public key for ${keyId} must be 32 bytes of lowercase hex`);
    }
    keys[keyId] = value;
  }
  if (Object.keys(keys).length === 0) {
    throw new Error("at least one fund-IK suitability key must be pinned");
  }
  return Object.freeze(keys);
}

/**
 * THE separation-of-origin check.
 *
 * The whole point of this slice is that a KYC GREEN is not sufficient to mint
 * accredited/QP. That guarantee is only real while the two authorities are
 * genuinely different signers: if the operator pinned the KYC provider's key as
 * a suitability key, the provider could mint suitability by signing whatever it
 * likes into the other profile. So an overlap, of keyId OR of key material, 
 * is a configuration error, not a convenience.
 */
export function assertSuitabilityKeysAreDistinct(
  suitabilityKeys: Readonly<Record<string, string>>,
  env: NodeJS.ProcessEnv,
): void {
  const providerJson = env.GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON?.trim();
  if (!providerJson) return;
  let providerKeys: Record<string, unknown>;
  try {
    providerKeys = JSON.parse(providerJson) as Record<string, unknown>;
  } catch {
    return; // the identity gate's own config parser owns this refusal
  }
  if (!providerKeys || typeof providerKeys !== "object" || Array.isArray(providerKeys)) return;
  const providerMaterial = new Set(
    Object.values(providerKeys)
      .filter((value): value is string => typeof value === "string")
      .map((value) => value.toLowerCase()),
  );
  for (const [keyId, material] of Object.entries(suitabilityKeys)) {
    if (Object.prototype.hasOwnProperty.call(providerKeys, keyId)) {
      throw new Error(
        `suitability keyId ${keyId} is also pinned as a KYC provider key: the fund IK's `
        + "suitability determination must not be signable by the KYC provider",
      );
    }
    if (providerMaterial.has(material.toLowerCase())) {
      throw new Error(
        "a pinned suitability key is the same key material as a pinned KYC provider key: a KYC "
        + "decision must never be sufficient to mint accredited/QP",
      );
    }
  }
}

function readAttestation(env: NodeJS.ProcessEnv): unknown {
  const inline = env.GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON?.trim();
  const path = env.GAP_FUND_IK_SUITABILITY_ATTESTATION_PATH?.trim();
  if (inline && path) {
    throw new Error(
      "set GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON or _PATH, never both, two sources is two "
      + "answers to which artifact was verified",
    );
  }
  const raw = inline ?? (path ? readFile(path) : undefined);
  if (!raw) {
    throw new Error(
      "GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON or GAP_FUND_IK_SUITABILITY_ATTESTATION_PATH is "
      + "required once the suitability gate is configured",
    );
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("the fund-IK suitability attestation is not valid JSON");
  }
}

function readFile(path: string): string {
  try {
    return fs.readFileSync(path, "utf8");
  } catch (error) {
    throw new Error(`cannot read the fund-IK suitability attestation: ${(error as Error).message}`);
  }
}

/** Named once; every refusal below points the operator at the same three variables. */
const REQUIRED_VARIABLES =
  "GAP_FUND_IK_SUITABILITY_KEYS_JSON, GAP_FUND_IK_ID, "
  + "GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON|_PATH";

/**
 * Reads the gate configuration, or returns undefined when the operator has not
 * configured one. Undefined is NOT a bypass, `gatedSuitabilityAttributes`
 * turns it into a refusal, exactly as an unconfigured identity gate installs a
 * decision port that refuses every read.
 */
export function suitabilityGateConfigFromEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): SuitabilityGateConfig | undefined {
  const keysJson = env.GAP_FUND_IK_SUITABILITY_KEYS_JSON?.trim();
  if (!keysJson) return undefined;
  const publicKeys = parsePinnedKeys(keysJson, "GAP_FUND_IK_SUITABILITY_KEYS_JSON");
  assertSuitabilityKeysAreDistinct(publicKeys, env);
  return {
    policy: {
      fundIkId: required(env, "GAP_FUND_IK_ID"),
      environment: "sandbox",
      publicKeys,
    },
    attestation: readAttestation(env),
  };
}

/** True only when the operator has armed a fund-IK suitability gate. */
export function suitabilityGateIsConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return (env.GAP_FUND_IK_SUITABILITY_KEYS_JSON?.trim() ?? "") !== "";
}

/**
 * Read + verify in one step. The ONLY way to obtain attrs[2..3].
 *
 * Throws when no gate is configured: there is no third state, no fixture
 * fallback, and no flag that reopens one. A verified KYC decision does not
 * reach this function and cannot substitute for what it returns.
 */
export function gatedSuitabilityAttributes(input: {
  readonly did: `0x${string}`;
  readonly now?: bigint;
  readonly env?: NodeJS.ProcessEnv;
}): VerifiedSuitability {
  const env = input.env ?? process.env;
  const config = suitabilityGateConfigFromEnvironment(env);
  if (!config) {
    throw new Error(
      "accredited/qualified-purchaser issuance requires a fund-IK suitability attestation. A "
      + "verified KYC decision attests residency and sanctions only and is NOT sufficient. "
      + `Configure the suitability gate (${REQUIRED_VARIABLES})`,
    );
  }
  return verifySuitabilityAttestation(config.attestation, {
    policy: config.policy,
    expectedSubjectDid: input.did,
    now: input.now ?? BigInt(Math.floor(Date.now() / 1000)),
  });
}
