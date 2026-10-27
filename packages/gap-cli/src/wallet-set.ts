// The v2 CLI lane's spending-wallet set: the AUTHORITATIVE one, not a singleton.
//
// WHAT THIS REPLACES. The lane used to pin `spendingKeyRootFor(id.address)`: a
// tree holding exactly ONE leaf, the transacting wallet. The circuit has always
// supported many (gap_session.circom folds `spendingKeyRoot` into the DID leaf and
// separately proves `H2(account, spendingBlind)` is a member of it, blinded, because an unblinded
// leaf made the published root a preimage of a one-wallet holder's address), but a singleton root
// admits exactly one wallet, so a person's second account wallet could not
// transact under their DID no matter what the onboarding platform's database said.
//
// This module builds the SAME structure the Identity Keeper publishes, 
// `AssignedSlotSpendingWalletSet` from packages/gap-identity-keeper-v2, so the
// local lane and the joined lane agree on how a wallet set hashes. It is
// instantiated at the LOCAL circuit's SK_DEPTH (4) rather than the Base Fund
// depth (8); the class is depth-parameterised and the tree rules are identical.
//
// Backwards compatible on purpose: a one-wallet person still gets the old root,
// because a first wallet takes its preferred low-bit slot and that is exactly the
// index a SparseTree keyed by the address would have used.
import {
  AssignedSlotSpendingWalletSet,
  DEFAULT_SPENDING_WALLET_DEPTH,
  spendingBlindFor,
  GAP_SPENDING_WALLET_SET_V2,
  SPENDING_WALLET_SET_SCHEMA_VERSION,
  type SpendingWalletMembershipProof,
} from "../../gap-identity-keeper-v2/src/spending-wallet-set";
import { createPoseidon2, type Poseidon2 } from "../../gap-identity-keeper-v2/src/field";
import type { Address } from "../../gap-identity-keeper-v2/src/types";
import type { SpendingKeyWitness } from "@tac-gap/sdk";
import { SK_DEPTH } from "./state";

export { DEFAULT_SPENDING_WALLET_DEPTH };

let hasher: Poseidon2 | undefined;
async function poseidon(): Promise<Poseidon2> {
  hasher ??= await createPoseidon2();
  return hasher;
}

/**
 * Build the person's wallet set. Wallets are added in the order the person's
 * record lists them, which is what fixes each wallet's assigned slot; the set
 * never moves a slot once assigned, so adding a wallet later cannot invalidate an
 * earlier wallet's membership proof.
 */
export async function buildWalletSet(
  accounts: readonly string[],
  privateSalt: bigint,
  depth: number = SK_DEPTH,
): Promise<AssignedSlotSpendingWalletSet> {
  if (accounts.length === 0) throw new Error("a person must own at least one spending wallet");
  const hasher = await poseidon();
  const spendingBlind = spendingBlindFor(hasher, privateSalt);
  const set = new AssignedSlotSpendingWalletSet(hasher, spendingBlind, {
    profile: GAP_SPENDING_WALLET_SET_V2,
    schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
    revision: 0n,
    depth,
    spendingBlind: `0x${spendingBlind.toString(16).padStart(64, "0")}`,
    assignments: [],
  });
  for (const account of accounts) {
    set.add(account.toLowerCase() as Address, set.snapshot().revision);
  }
  return set;
}

/** The root the DID document pins: a property of the PERSON, not of any one wallet. */
export async function walletSetRoot(
  accounts: readonly string[],
  privateSalt: bigint,
  depth: number = SK_DEPTH,
): Promise<bigint> {
  return BigInt((await buildWalletSet(accounts, privateSalt, depth)).root());
}

/**
 * The acting wallet's membership proof. Throws for a wallet outside the set, 
 * which is the point: a wallet the person does not own has no witness to offer,
 * and a forged one fails the SDK's root recomputation before any proving starts.
 */
export async function walletSetWitness(
  accounts: readonly string[],
  account: string,
  privateSalt: bigint,
  depth: number = SK_DEPTH,
): Promise<SpendingKeyWitness> {
  const set = await buildWalletSet(accounts, privateSalt, depth);
  return toSpendingKeyWitness(set.proof(account.toLowerCase() as Address));
}

export function toSpendingKeyWitness(
  proof: SpendingWalletMembershipProof,
): SpendingKeyWitness {
  return {
    root: BigInt(proof.root),
    siblings: proof.siblings.map((sibling) => BigInt(sibling)),
    pathIndices: [...proof.pathIndices],
  };
}
