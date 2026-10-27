// The v2 CLI demo lane's credential-mint guard.
//
// This lane (`gap onboard`, `gap demo`, the sidecar verb, queue-test) mints its
// own credentials with the Anvil deployer key, against the standalone
// `contracts/deployments/31337-v2.json` stack.
//
// It writes TWO credentials per party, and each one needs its own authority:
//   • the identity leaf carries attrs[0..3] = [residency, sanctions, citizenship, reserved],
//     attested by the KYC provider (services/gap-ik-api/src/
//     identity-credential-gate.ts: the Identity Keeper's own gate, never a
//     second copy of those checks);
//   • the investor-status leaf carries attrs[4..7] = [accredited, qualified
//     purchaser], attested by the FUND IK's own reviewed suitability
//     determination (./suitability-attestation.ts).
//
// The guard therefore checks ALL FOUR attributes on EVERY call, whichever leaf
// the caller is about to write, and every `issueCredential` in this lane is
// preceded by a call. A widened request type is what makes that structural: a
// two-element request could not see attrs[4..7], so the investor credential used
// to be minted after the guard had already returned, unattested and, with
// exp1 = 0, forever. `state.ts` ZONES["reg-d"] gates on attrs[4] == 1, so that
// leaf was the key to the Reg D zone.
//
// KYC IS NOT SUITABILITY. A verified provider decision authorizes attrs[0..3]
// and nothing more. When an identity gate is armed but no suitability gate is,
// this guard refuses outright: there is no fixture escape from that case,
// because "we KYC'd them, so they're accredited" is exactly the conflation this
// slice exists to end.
import {
  composeEnvironmentIdentityMint,
  gatedIdentityAttributes,
  identityGateIsConfigured,
} from "./identity-gate";
import { gatedSuitabilityAttributes, suitabilityGateIsConfigured } from "./suitability-gate";

export const LOCAL_DEMO_CHAIN_ID = 31337;

/**
 * How long an investor-status credential may live.
 *
 * 7 days, matching the identity credential this lane mints beside it (the IK
 * service uses 24h for its live-attested lane; this CLI lane's convention is 7
 * days, and these two leaves are proven together in one session, so they get one
 * number). Chosen rather than a longer suitability-specific window because:
 *   • a suitability determination presupposes a verified identity, so it must
 *     never outlive the identity credential standing next to it;
 *   • 7 days sits well inside the SEC's Rule 506(c) 90-day verification safe
 *     harbor, so the credential can never outlive the reasonable-belief window
 *     the fund IK's determination rests on;
 *   • the previous value was 0n, "never expires", which is not a defensible
 *     lifetime for any suitability determination at all.
 * The effective expiry is additionally clamped to the attestation's own
 * expiresAt (see `investorCredentialExpiresAt`), so a determination expiring in
 * two days yields a two-day credential, never a seven-day one.
 */
export const INVESTOR_CREDENTIAL_TTL_SECONDS = 7n * 24n * 60n * 60n;

export type CredentialLeaf = "identity" | "investor";

export interface IdentityMintRequest {
  readonly chainId: number;
  readonly did: `0x${string}`;
  /**
   * ALL EIGHT attributes this lane will fold into its leaves:
   * regime 0 [residency, sanctions, citizenship, reserved],
   * regime 1 [accredited, qualified purchaser, reserved, reserved].
   * The guard checks every one of them on every call, so no credential can be
   * minted outside its view.
   */
  readonly attributes: readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
  /** Which leaf is about to be written. Both are gated; this names the caller. */
  readonly leaf: CredentialLeaf;
  readonly warn?: (message: string) => void;
  readonly env?: NodeJS.ProcessEnv;
  readonly now?: bigint;
}

export interface MintAuthorization {
  readonly leaf: CredentialLeaf;
  /** True only when BOTH authorities attested: a fully backed mint. */
  readonly attested: boolean;
  /**
   * Wall-clock unix second at which the fund IK's suitability determination
   * stops authorizing attrs[4..7]. Undefined on the unattested fixture path.
   */
  readonly suitabilityExpiresAt?: bigint;
}

function warnWith(request: IdentityMintRequest): (message: string) => void {
  return request.warn ?? ((message: string) => process.stderr.write(`${message}\n`));
}

/** attrs[0..3]: the KYC provider's decision is authoritative when armed. */
async function assertIdentityAttributes(
  request: IdentityMintRequest,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  const composed = composeEnvironmentIdentityMint(env);
  const { attributes } = await gatedIdentityAttributes({
    decisions: composed.decisions,
    subject: {
      // subjectId and accountLinkId come from the configured cell, never from
      // this process: a caller that could name its own case could point at a
      // stranger's approved decision.
      subjectId: composed.subject.subjectId,
      did: request.did,
      ...(composed.subject.accountLinkId === undefined
        ? {}
        : { accountLinkId: composed.subject.accountLinkId }),
    },
  });
  for (let i = 0; i < 4; i++) {
    if (attributes[i] !== request.attributes[i]) {
      throw new Error(
        "the verified identity decision does not attest the attributes this lane would mint "
        + ", refusing to issue a credential the provider never decided",
      );
    }
  }
}

/** attrs[4..7]: the fund IK's signed suitability determination is authoritative. */
function assertSuitabilityAttributes(request: IdentityMintRequest): bigint {
  const verified = gatedSuitabilityAttributes({
    did: request.did,
    ...(request.now === undefined ? {} : { now: request.now }),
    ...(request.env === undefined ? {} : { env: request.env }),
  });
  const [accredited, qualifiedPurchaser, evidenceTier, reservedSeven] = verified.attributes;
  if (
    accredited !== request.attributes[4] || qualifiedPurchaser !== request.attributes[5]
    || evidenceTier !== request.attributes[6] || reservedSeven !== request.attributes[7]
  ) {
    throw new Error(
      "the fund IK's suitability attestation does not attest the accredited/qualified-purchaser "
      + "attributes this lane would mint, refusing to issue a credential nobody determined",
    );
  }
  return verified.determination.expiresAt;
}

/**
 * Refuses before the caller writes anything. Throwing is the only outcome that
 * blocks a mint, callers must await this ahead of EVERY `issueCredential`, for
 * both leaves.
 */
export async function assertIdentityCredentialMintAllowed(
  request: IdentityMintRequest,
): Promise<MintAuthorization> {
  if (request.chainId !== LOCAL_DEMO_CHAIN_ID) {
    throw new Error(
      `the GAP v2 CLI issues credentials on local Anvil ${LOCAL_DEMO_CHAIN_ID} only `
      + `(connected chain ${request.chainId})`,
    );
  }
  const env = request.env ?? process.env;
  const identityArmed = identityGateIsConfigured(env);
  const suitabilityArmed = suitabilityGateIsConfigured(env);

  // A KYC decision authorizes attrs[0..3] only. Once the operator is running a
  // real identity gate, "accredited" may not ride in on it, and no fixture flag
  // reopens that door.
  if (identityArmed && !suitabilityArmed) {
    throw new Error(
      "a verified KYC decision attests residency and sanctions only, it is NOT sufficient to "
      + "mint accredited/qualified-purchaser. Configure the fund-IK suitability gate "
      + "(GAP_FUND_IK_SUITABILITY_KEYS_JSON, GAP_FUND_IK_ID, "
      + "GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON|_PATH)",
    );
  }
  if (identityArmed) await assertIdentityAttributes(request, env);
  const suitabilityExpiresAt = suitabilityArmed ? assertSuitabilityAttributes(request) : undefined;
  if (identityArmed && suitabilityArmed) {
    return { leaf: request.leaf, attested: true, suitabilityExpiresAt };
  }

  // Whatever is still unattested falls back to the stated local-fixture path: 
  // no weaker than before: an unattested attrs[0..3] needed the operator's
  // acknowledgement then and still needs it now, even when the fund IK has
  // signed for attrs[4..7].
  const missing = [
    ...(identityArmed ? [] : ["a verified provider decision (attrs[0..3])"]),
    ...(suitabilityArmed ? [] : ["a fund-IK suitability attestation (attrs[4..7])"]),
  ].join(" and ");
  if (env.GAP_ALLOW_INSECURE_LOCAL_FIXTURES !== "1") {
    throw new Error(
      `credential issuance requires ${missing}. Configure the identity gate `
      + "(GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON, GAP_IK_PROVIDER_*, GAP_IK_BOOTSTRAP_JSON, "
      + "GAP_IK_PERSON_DID_KEY, GAP_IK_IDENTITY_ANCHOR_ADDRESS) and the suitability gate "
      + "(GAP_FUND_IK_SUITABILITY_KEYS_JSON, GAP_FUND_IK_ID, "
      + "GAP_FUND_IK_SUITABILITY_ATTESTATION_JSON|_PATH), or acknowledge the unattested local "
      + "demo credentials with GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1",
    );
  }
  warnWith(request)(
    `WARNING: minting a PARTLY UNATTESTED local demo ${request.leaf} credential, missing `
    + `${missing}. Local Anvil fixtures only.`,
  );
  return { leaf: request.leaf, attested: false, ...(suitabilityExpiresAt === undefined ? {} : { suitabilityExpiresAt }) };
}

/**
 * The investor-status credential's `expiresAt`, in CHAIN time (the leaf expiry
 * is folded into the commitment and enforced against `block.timestamp`).
 *
 * Never 0. The TTL is capped by whatever remains of the fund IK's determination,
 * expressed as a duration so that Anvil's clock drifting from wall clock cannot
 * produce an already-expired leaf.
 */
export function investorCredentialExpiresAt(input: {
  readonly chainNow: bigint;
  readonly authorization: MintAuthorization;
  readonly now?: bigint;
}): bigint {
  const now = input.now ?? BigInt(Math.floor(Date.now() / 1000));
  let ttl = INVESTOR_CREDENTIAL_TTL_SECONDS;
  const attested = input.authorization.suitabilityExpiresAt;
  if (attested !== undefined) {
    const remaining = attested - now;
    // The verifier already refused an expired determination; clamp defensively.
    if (remaining <= 0n) throw new Error("the fund-IK suitability determination has expired");
    if (remaining < ttl) ttl = remaining;
  }
  return input.chainNow + ttl;
}
