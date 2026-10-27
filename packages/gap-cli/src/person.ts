// Per-PERSON identity for the v2 CLI lane: one human = one DID = one private salt,
// across every wallet that human owns.
//
// WHAT THIS REPLACES. The lane used to derive `did` and `privateSalt` from an
// EIP-712 signature made by the transacting wallet key (the old
// `state.ts deriveIdentity`). That is per-WALLET by construction: a second
// account wallet signs a different signature, so it got a different DID and a
// different salt, and the person's credential, which binds H(did, salt), could
// not be reopened from it. One person with two wallets was therefore two people.
//
// WHAT SUPPLIES EACH SECRET NOW (the wallet signature supplied both before):
//   * the DID  <- derivePersonDid(personDidKey, environment, accountLinkId), the
//     ONE keyed derivation in the tree (packages/gap-identity-keeper-v2/src/person-did.ts).
//     `personDidKey` is the IDENTITY KEEPER's secret; the IK re-derives the DID and
//     refuses a bootstrap that disagrees. The DID is public on-chain, so this key
//     exists purely so that holding a platform customer-link id is not enough to
//     link a person to their on-chain credentials.
//   * the SALT <- derivePersonSalt(personSaltKey, environment, accountLinkId), a
//     SEPARATE 32-byte secret that belongs to the HOLDER's wallet vault and is
//     never shared with the IK. Two keys, not one: the DID key must be held by the
//     IK to do its job, and the salt must never be. Same account link on both sides
//     is what keeps the pair addressing one person.
//
// The salt is a per-person secret, not a per-wallet one, precisely because the
// credential leaf and the pseudonym both fold it together with the DID: a
// per-wallet salt would give one human as many pseudonyms and as many credentials
// as they hold wallets, which is the thing this change exists to end.
//
// The default keys below are chain-31337 demo fixtures. In production both come
// from their holders' key management and neither is ever printed.
import { createHash, createHmac } from "node:crypto";
import {
  derivePersonDid,
  isCanonicalSubjectId,
  PERSON_DID_DOMAIN,
} from "../../gap-identity-keeper-v2/src/person-did";
// The custody vocabulary is single-sourced in the Identity Keeper, so a stamp written here and a
// model recorded there cannot drift into two spellings of one fact.
import type { CustodyModel } from "../../gap-identity-keeper-v2/src/person-did";

export { PERSON_DID_DOMAIN };
export type { CustodyModel };

/** Domain-separates the salt from the DID under the same key discipline. */
export const PERSON_SALT_DOMAIN = "DSI_PERSON_SALT_V1";

export type PersonEnvironment = "sandbox";

/**
 * Mask to 253 bits, identical treatment to the DID. 2^253 < BN254_FIELD, so the
 * result is in-field with zero modular bias; reducing a full 256-bit digest mod p
 * would make residues below (2^256 mod p) about 25% more likely.
 */
const FIELD_MASK = (1n << 253n) - 1n;

function fixtureKey(label: string): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(label, "utf8").digest());
}

/** The key an operator supplied, or undefined when they supplied none. */
function suppliedKey(name: string): Uint8Array | undefined {
  const raw = process.env[name]?.trim();
  if (!raw) return undefined;
  if (!/^0x[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(`${name} must be a 32-byte hex secret`);
  }
  return Uint8Array.from(Buffer.from(raw.slice(2), "hex"));
}

function keyFromEnv(name: string, fixtureLabel: string): Uint8Array {
  return suppliedKey(name) ?? fixtureKey(fixtureLabel);
}

/** IK-held. Rotating it re-identifies every person in the lane. */
export function personDidKey(): Uint8Array {
  return keyFromEnv("GAP_DEMO_PERSON_DID_KEY", "gap-v2-local-person-did-key-v1");
}

/** The one acknowledgement that turns the public salt fixture back on. */
export const PUBLIC_SALT_FALLBACK_FLAG = "GAP_DEMO_ALLOW_PUBLIC_SALT";

const SALT_KEY_VARIABLE = "GAP_DEMO_PERSON_SALT_KEY";
const SALT_FIXTURE_LABEL = "gap-v2-local-person-salt-key-v1";

/** The salt key, and the custody model whatever it derives must be stamped with. */
export interface PersonSaltMaterial {
  readonly key: Uint8Array;
  readonly custodyModel: CustodyModel;
}

/**
 * WHERE THE HOLDER'S SALT KEY CAME FROM, and it is never "from nowhere".
 *
 * The fallback used to be silent: with `GAP_DEMO_PERSON_SALT_KEY` unset this
 * function returned `sha256("gap-v2-local-person-salt-key-v1")`, a constant
 * checked into this repo. That is not a key, it is a published number: anyone
 * with the repo and an `accountLinkId` recomputes the salt, reopens the
 * credential leaf and links every pseudonym derived from it. The joined lane
 * has refused its guessable fixture salt for a while (`joined/config.ts` (full stack, not in this repository)
 * `localSalt`); this is the same discipline arriving on the v2 CLI lane, and it
 * is the open half of design gap 3.1 (`design-gaps.md`, full stack, not in this repository).
 *
 * Two paths, each stamped with what is actually true of it:
 *   * a SUPPLIED key comes from its holder's own key management, off the
 *     platform's premises, `CLIENT_HELD`, and no acknowledgement is needed;
 *   * the FIXTURE runs only when an operator names the flag, and everything it
 *     derives is stamped `IK_CUSTODY_DEMO` so no artifact can pass a public
 *     demo salt off as a custodied one.
 *
 * The flag does not change the arithmetic. A lane that acknowledges the fixture
 * gets exactly the person it had before, only now it says so out loud.
 */
export function personSaltMaterial(): PersonSaltMaterial {
  const supplied = suppliedKey(SALT_KEY_VARIABLE);
  if (supplied) return { key: supplied, custodyModel: "CLIENT_HELD" };
  if (process.env[PUBLIC_SALT_FALLBACK_FLAG] !== "1") {
    throw new Error(
      `${SALT_KEY_VARIABLE} is unset, and the fallback would derive the holder's salt key as `
      + `sha256("${SALT_FIXTURE_LABEL}"): a constant checked into this repo, so anyone holding `
      + "the repo and an accountLinkId can recompute the salt and de-anonymise every pseudonym "
      + `derived from it. Supply the holder's own 32-byte salt key in ${SALT_KEY_VARIABLE}, or `
      + `acknowledge the public demo-custody salt with ${PUBLIC_SALT_FALLBACK_FLAG}=1`,
    );
  }
  return { key: fixtureKey(SALT_FIXTURE_LABEL), custodyModel: "IK_CUSTODY_DEMO" };
}

/** Wallet-vault-held. Never leaves the holder; the IK must not be able to derive it. */
export function personSaltKey(): Uint8Array {
  return personSaltMaterial().key;
}

export interface PersonSaltInput {
  readonly personSaltKey: Uint8Array;
  readonly environment: PersonEnvironment;
  readonly accountLinkId: string;
}

export function derivePersonSalt(input: PersonSaltInput): bigint {
  if (!(input.personSaltKey instanceof Uint8Array) || input.personSaltKey.length !== 32) {
    throw new Error("personSaltKey must be exactly 32 bytes");
  }
  if (input.environment !== "sandbox") throw new Error("unsupported person salt environment");
  if (!isCanonicalSubjectId(input.accountLinkId)) {
    throw new Error("accountLinkId must be a canonical lowercase UUIDv4");
  }
  const preimage = JSON.stringify([
    PERSON_SALT_DOMAIN, input.environment, input.accountLinkId,
  ]);
  const raw = createHmac("sha256", input.personSaltKey).update(preimage, "utf8").digest("hex");
  const value = BigInt(`0x${raw}`) & FIELD_MASK;
  // Probability 2^-253. A zero salt would make the salt commitment a constant, so
  // there is no safe fallback to substitute, refuse instead.
  if (value === 0n) throw new Error("derived person salt is zero");
  return value;
}

export interface PersonIdentity {
  readonly accountLinkId: string;
  readonly did: bigint;
  readonly privateSalt: bigint;
  /**
   * The custody model this person's SALT lives under, the CLI's provenance
   * stamp, carried on the identity itself because the v2 lane has no other
   * artifact surface to hang it from. A consumer that writes an artifact from
   * this identity must carry the stamp with it: `IK_CUSTODY_DEMO` means the
   * salt is public and the pseudonyms behind it are not anonymous.
   */
  readonly custodyModel: CustodyModel;
}

/** The whole per-person secret set, from the account link alone. */
export function derivePersonIdentity(
  accountLinkId: string,
  environment: PersonEnvironment = "sandbox",
): PersonIdentity {
  const did = derivePersonDid({ personDidKey: personDidKey(), environment, accountLinkId });
  const salt = personSaltMaterial();
  return {
    accountLinkId,
    did: BigInt(did),
    privateSalt: derivePersonSalt({ personSaltKey: salt.key, environment, accountLinkId }),
    custodyModel: salt.custodyModel,
  };
}

/**
 * A run-scoped account link, so one PERSISTENT deployment can host the lane more
 * than once.
 *
 * The DID is a function of the account link, and the registries refuse a second
 * write for a DID that already exists (`DIDRegistryV2: "DID: exists"`, and
 * `anvil-fund-credential.ts` (full stack, not in this repository) refuses while an active credential is on file). A
 * fixed link id therefore makes the second run of the lane a collision rather
 * than a second run. `GAP_DEMO_RUN_ID` gives the run its own person: same human
 * story, a genuinely different person, no state to tear down.
 *
 * Empty/unset run id returns the base link unchanged, so a fresh chain keeps the
 * stable, reproducible person it has today.
 */
export function runScopedAccountLinkId(baseLinkId: string, runId?: string): string {
  if (!isCanonicalSubjectId(baseLinkId)) {
    throw new Error("base accountLinkId must be a canonical lowercase UUIDv4");
  }
  const scope = (runId ?? "").trim();
  if (!scope) return baseLinkId;
  const digest = createHash("sha256")
    .update(JSON.stringify(["DSI_DEMO_RUN_SCOPED_LINK_V1", baseLinkId, scope]), "utf8")
    .digest("hex");
  return formatUuidV4(digest);
}

/** Force the version (4) and variant (10xx) nibbles so the result is a canonical UUIDv4. */
function formatUuidV4(digestHex: string): string {
  const bytes = Buffer.from(digestHex.slice(0, 32), "hex");
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  const uuid = [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32),
  ].join("-");
  if (!isCanonicalSubjectId(uuid)) throw new Error("run-scoped account link is not a UUIDv4");
  return uuid;
}
