import { countryNumeric } from "./country-table";
import type { ProviderDecision } from "./provider-attestation";

/**
 * Derivation of credential attrs[0..3] (regime 0) from a verified provider decision.
 *
 * attrs[0] = ISO 3166-1 numeric RESIDENCY country, where the person lives.
 * attrs[1] = sanctions flag, always 0n on an issued credential (see below).
 * attrs[2] = ISO 3166-1 numeric CITIZENSHIP country: what they are a national of.
 * attrs[3] = reserved (0n).
 *
 * Residency and citizenship are deliberately DISTINCT indices. Conflating them
 * admits a US citizen resident abroad under a `residency == 840` clause and
 * rejects a US resident holding a foreign passport, and a jurisdictional
 * programme may key on either. Only one country is carried per index: a dual
 * national cannot be encoded here, and a packed or sentinel encoding would
 * defeat `EQ` clauses exactly as `country-table.ts` refuses to do for unknown
 * jurisdictions. Screening a prohibited-nationality list at issuance (the
 * fail-closed shape attrs[1] uses) is the natural next step and is NOT yet
 * implemented, see docs/ATTRIBUTE_ENCODING.md.
 *
 * Regime 1 (accredited, QP) is NOT derived here: a KYC vendor does not attest
 * suitability, so the Fund IK keeps those constant.
 */
export type IdentityAttributes = readonly [bigint, bigint, bigint, bigint];

/** Mirrors the adapter's IdentityState vocabulary. */
export type ProviderState =
  | "CREATED" | "PENDING" | "APPROVED" | "RETRY_REQUIRED"
  | "REJECTED" | "SUSPENDED" | "REVOKED" | "RECONCILE_REQUIRED";

export interface ProviderStatusView {
  readonly type?: string;
  readonly reviewStatus: string;
  readonly reviewMode?: "ongoingAml" | "ongoingDocExpired";
  readonly reviewResult?: {
    readonly reviewAnswer?: "GREEN" | "RED";
    readonly reviewRejectType?: "FINAL" | "RETRY";
  };
}

const REVOKE_EVENTS = new Set([
  "applicantDeactivated", "applicantDeleted", "applicantReset", "applicantStepsReset",
  "applicantPersonalDataDeleted", "applicantLevelChanged",
]);
const RECONCILE_EVENTS = new Set(["applicantPersonalInfoChanged", "applicantActivated"]);
const PENDING_STATUSES = new Set(["pending", "prechecked", "queued", "awaitingService"]);
const KNOWN_EVENTS = new Set([
  "applicantCreated", "applicantPending", "applicantOnHold", "applicantReviewed",
  ...REVOKE_EVENTS, ...RECONCILE_EVENTS,
]);

/**
 * Local mirror of the adapter state machine for an AUTHORITATIVE status read.
 * Duplicated deliberately: the IK must not depend on a value the adapter
 * computed for it. Any divergence resolves to RECONCILE_REQUIRED, which blocks.
 */
export function normalizeProviderStatusState(input: ProviderStatusView): ProviderState {
  if (input.type && REVOKE_EVENTS.has(input.type)) return "REVOKED";
  if (input.type && RECONCILE_EVENTS.has(input.type)) return "RECONCILE_REQUIRED";
  if (input.type && !KNOWN_EVENTS.has(input.type)) return "RECONCILE_REQUIRED";
  if (input.type === "applicantOnHold" || input.reviewStatus === "onHold") return "SUSPENDED";
  if (input.type === "applicantPending"
    && (input.reviewMode === "ongoingAml" || input.reviewMode === "ongoingDocExpired")) return "SUSPENDED";
  if (input.reviewStatus === "init" || input.type === "applicantCreated") return "CREATED";
  if (input.reviewStatus === "awaitingUser") return "RECONCILE_REQUIRED";
  if (PENDING_STATUSES.has(input.reviewStatus)) return "PENDING";
  if (input.reviewStatus === "completed") {
    if (input.reviewResult?.reviewAnswer === "GREEN") return "APPROVED";
    if (input.reviewResult?.reviewAnswer === "RED" && input.reviewResult.reviewRejectType === "RETRY") {
      return "RETRY_REQUIRED";
    }
    if (input.reviewResult?.reviewAnswer === "RED" && input.reviewResult.reviewRejectType === "FINAL") {
      return "REJECTED";
    }
    return "RECONCILE_REQUIRED";
  }
  return "RECONCILE_REQUIRED";
}

export function requiresImmediateHold(state: ProviderState): boolean {
  return state === "SUSPENDED" || state === "REVOKED" || state === "REJECTED"
    || state === "RETRY_REQUIRED" || state === "RECONCILE_REQUIRED";
}

export function assertIssuableProviderState(status: ProviderStatusView, channel: string): void {
  const state = normalizeProviderStatusState(status);
  if (state !== "APPROVED" || requiresImmediateHold(state)) {
    throw new Error(`${channel} provider state ${state} does not permit issuance`);
  }
}

/**
 * attrs[0..3] from the verified decision. Every non-clean case refuses.
 *
 * A credential is never issued carrying attrs[1] = 1n. Encoding "sanctioned"
 * into a live credential and relying on a fund's {attrIndex:1, EQ, 0} clause to
 * block it is policy-dependent, not fail-closed: clauses are individually
 * enabled, so a fund that does not test attrIndex 1 would admit the holder.
 * A post-issuance HIT is handled by the existing revoke path.
 */
export function deriveIdentityAttributes(
  decision: ProviderDecision,
  countryTableRevision: number,
): IdentityAttributes {
  if (decision.countryTableRevision !== countryTableRevision) {
    throw new Error("country table revision mismatch");
  }
  if (decision.reviewAnswer !== "GREEN") {
    throw new Error("provider review answer is not GREEN; no credential is issued");
  }
  if (decision.reviewRejectType !== null) {
    throw new Error("provider decision carries a reject type; no credential is issued");
  }
  if (decision.screeningResult !== "CLEAR") {
    throw new Error("sanctions screening produced an unresolved hit; no credential is issued");
  }
  // Throws for an absent, misshapen, or out-of-table alpha-3: there is no
  // unknown-jurisdiction sentinel. Both countries go through the same table, so a
  // citizenship the reviewed table does not carry refuses issuance rather than
  // degrading to a value a clause could not distinguish from a real country.
  const residency = countryNumeric(decision.residencyCountryAlpha3);
  const citizenship = countryNumeric(decision.citizenshipCountryAlpha3);
  const attributes: IdentityAttributes = [residency, 0n, citizenship, 0n];
  for (const attribute of attributes) {
    if (attribute < 0n || attribute > 0xffffffffffffffffn) {
      throw new Error("derived credential attribute exceeds uint64");
    }
  }
  return attributes;
}
