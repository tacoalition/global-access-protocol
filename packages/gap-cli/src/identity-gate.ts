/**
 * THE IDENTITY GATE, AS THE LIGHT STACK SEES IT.
 *
 * WHAT THE GATE IS FOR. A credential may not be minted from a KYC decision alone. The rule is that
 * `attrs[0..3]` come from a VERIFIED PROVIDER DECISION and `attrs[4..7]` from a SIGNED SUITABILITY
 * ATTESTATION, because "we KYC'd them, so they're accredited" is exactly the conflation the design
 * exists to end. That rule is core to the compliance story, not scaffolding, and it is the refusal
 * you meet on a fresh checkout:
 *
 *   credential issuance requires a verified provider decision (attrs[0..3]) and a
 *   fund-IK suitability attestation (attrs[4..7])
 *
 * WHY THIS FILE EXISTS RATHER THAN AN IMPORT. In the full stack these functions live in the
 * Identity Keeper service (`gap-ik-api/src/identity-credential-gate.ts` (full stack, not in this repository)), whose import graph reaches
 * a specific KYC vendor's adapter. The light stack runs no services at all, so importing them would
 * drag a vendor integration into a reference implementation that never calls it.
 *
 * WHAT IS AND IS NOT HERE. `identityGateIsConfigured` is REAL: it reads the same four variables the
 * service reads, so a deployment that arms the gate is detected here exactly as it is there. The
 * two functions that would *drive* an armed gate are not implemented, and they REFUSE rather than
 * return something plausible: reaching them means the gate is armed, and an armed gate must be
 * served by the real Identity Keeper, not by a local approximation of it.
 */

/**
 * The four variables that arm a provider gate, mirroring
 * `identityGateConfigFromEnvironment` in the Identity Keeper. All four are required there, so a
 * partially-set gate reads as unarmed here exactly as it does there.
 */
const PROVIDER_GATE_ENV = [
  "GAP_IK_PROVIDER_ATTESTATION_KEYS_JSON",
  "GAP_IK_PROVIDER_CLIENT_ID",
  "GAP_IK_PROVIDER_LEVEL_NAME",
  "GAP_IK_PROVIDER_REVIEWED_CONFIG_SHA256",
] as const;

/** True only when the operator has armed a provider gate in this environment. */
export function identityGateIsConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return PROVIDER_GATE_ENV.every((name) => (env[name] ?? "").trim().length > 0);
}

/** Named so the refusal says which stack the caller has asked for. */
function armedGateNeedsTheFullStack(what: string): never {
  throw new Error(
    `${what} requires the Identity Keeper service, which this build does not run.\n`
      + "  The provider gate is armed (GAP_IK_PROVIDER_* are set), so a credential must be minted\n"
      + "  from a real verified decision: this reference build cannot stand in for that.\n"
      + "  Either run the full stack, or unset the GAP_IK_PROVIDER_* variables and acknowledge the\n"
      + "  unattested local credentials with GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1.",
  );
}

/**
 * The SHAPES are declared even though the bodies refuse, so a caller typechecks against the real
 * service's contract rather than against `never`. Returning `never` made every line after the call
 * unreachable, which quietly un-typechecked `mint-guard.ts`: the one file whose job is to be
 * exactly right about which authority attested which attribute.
 */
export interface ComposedIdentityMint {
  readonly decisions: unknown;
  readonly subject: {
    readonly subjectId: string;
    readonly accountLinkId?: string;
  };
}

/** Regime 0 under GAP_ATTR_CRED_V3: residency, sanctions, citizenship, reserved. */
export interface GatedIdentityAttributes {
  readonly attributes: readonly [bigint, bigint, bigint, bigint];
}

export function composeEnvironmentIdentityMint(
  _env: NodeJS.ProcessEnv = process.env,
): ComposedIdentityMint {
  return armedGateNeedsTheFullStack("composing a gated identity mint");
}

export function gatedIdentityAttributes(_input: unknown): Promise<GatedIdentityAttributes> {
  return armedGateNeedsTheFullStack("reading gated identity attributes");
}
