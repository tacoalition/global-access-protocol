import {
  SPENDING_BLIND_TAG,
  addressToField,
  assertBytes,
  assertField,
  fromHex,
  toBytes32,
  type Poseidon2,
} from "./field";
import type { Address, Bytes32 } from "./types";

export const GAP_SPENDING_WALLET_SET_V2 = "GAP_SPENDING_WALLET_SET_V2" as const;
// 3: the leaf gained its blind. A version-2 state has no `spendingBlind`, and guessing one would
// rebuild a DIFFERENT tree than the root on chain, so restore refuses it by name instead.
export const SPENDING_WALLET_SET_SCHEMA_VERSION = 3 as const;
export const DEFAULT_SPENDING_WALLET_DEPTH = 8;

export interface SpendingWalletAssignment {
  readonly account: Address;
  readonly slot: number;
}

export interface SpendingWalletSetState {
  readonly profile: typeof GAP_SPENDING_WALLET_SET_V2;
  readonly schemaVersion: typeof SPENDING_WALLET_SET_SCHEMA_VERSION;
  readonly revision: bigint;
  readonly depth: number;
  readonly assignments: readonly SpendingWalletAssignment[];
  /**
   * The per-holder blind every leaf is folded under. PERSISTED so a restore rebuilds the same
   * tree without reaching for the subject's salt, only genuine creation needs the vault.
   * Secret: it is what stops the published root being a preimage of the holder's wallets.
   */
  readonly spendingBlind: Bytes32;
}

export interface SpendingWalletSetSnapshot extends SpendingWalletSetState {
  readonly root: Bytes32;
}

export interface SpendingWalletMembershipProof {
  readonly account: Address;
  readonly slot: number;
  readonly leaf: Bytes32;
  readonly root: Bytes32;
  readonly siblings: readonly Bytes32[];
  readonly pathIndices: readonly number[];
}

export interface SpendingWalletSetChange {
  readonly snapshot: SpendingWalletSetSnapshot;
  readonly membership?: SpendingWalletMembershipProof;
}

function canonicalAddress(account: Address): Address {
  assertBytes(account, 20, "spending wallet");
  return account.toLowerCase() as Address;
}

/**
 * The blind for a holder: `H2(privateSalt, SPENDING_BLIND_TAG)`.
 *
 * Derived from the salt the session circuit already takes as a private input, so the prover
 * recomputes it in-circuit with no extra witness field. See SPENDING_SET_PRIVACY.md (full stack, not in this repository).
 */
export function spendingBlindFor(hasher: Poseidon2, privateSalt: bigint): bigint {
  assertField(privateSalt, "private salt");
  return hasher.hash2(privateSalt, SPENDING_BLIND_TAG);
}

/**
 * The blind for a tree that holds NO leaves and never will under this instance: the empty set a
 * bootstrap publishes, or a placeholder root.
 *
 * It is a named constant rather than a default because a DEFAULT is how the unblinded leaf comes
 * back: a call site that forgot to pass a real blind would silently rebuild the preimage. Passing
 * this says "there are no leaves for it to blind", and if one is ever added under it the tree is
 * wrong in a way the on-chain root will not match.
 */
export const EMPTY_SET_BLIND = 0n;

function assertDepth(depth: number): void {
  if (!Number.isSafeInteger(depth) || depth <= 0 || depth > 30) {
    throw new Error("spending wallet depth must be an integer from 1 through 30");
  }
}

export function assertSpendingWalletMembership(
  hasher: Poseidon2,
  proof: SpendingWalletMembershipProof,
  spendingBlind: bigint,
  expectedDepth = DEFAULT_SPENDING_WALLET_DEPTH,
): void {
  const account = canonicalAddress(proof.account);
  if (proof.siblings.length !== expectedDepth || proof.pathIndices.length !== expectedDepth) {
    throw new Error(`spending wallet proof must have depth ${expectedDepth}`);
  }
  if (proof.pathIndices.some((path) => path !== 0 && path !== 1)) {
    throw new Error("spending wallet path indices must be binary");
  }
  if (!Number.isSafeInteger(proof.slot) || proof.slot < 0 || proof.slot >= 2 ** expectedDepth) {
    throw new Error("spending wallet proof slot is outside the tree");
  }
  const expectedPath = Array.from(
    { length: expectedDepth },
    (_, level) => (proof.slot >> level) & 1,
  );
  if (expectedPath.some((path, level) => path !== proof.pathIndices[level])) {
    throw new Error("spending wallet proof path does not match assigned slot");
  }
  const leaf = hasher.hash2(addressToField(account), spendingBlind);
  if (toBytes32(leaf).toLowerCase() !== proof.leaf.toLowerCase()) {
    throw new Error("spending wallet proof leaf does not match account under this blind");
  }
  let node = leaf;
  for (let level = 0; level < expectedDepth; level += 1) {
    assertBytes(proof.siblings[level], 32, `spending wallet sibling ${level}`);
    const sibling = fromHex(proof.siblings[level]);
    assertField(sibling, `spending wallet sibling ${level}`);
    node = proof.pathIndices[level] === 0
      ? hasher.hash2(node, sibling)
      : hasher.hash2(sibling, node);
  }
  assertBytes(proof.root, 32, "spending wallet root");
  if (toBytes32(node).toLowerCase() !== proof.root.toLowerCase()) {
    throw new Error("spending wallet proof does not match root");
  }
}

/**
 * Versioned, assigned-slot spending-wallet tree.
 *
 * The first wallet at a preferred low-bit slot preserves the frozen one-wallet
 * root. Collisions use linear probing, and persisted assignments never move.
 */
export class AssignedSlotSpendingWalletSet {
  private readonly assignments = new Map<Address, number>();
  private revision: bigint;
  readonly depth: number;

  /** The blind every leaf is folded under. Never zero for a set that holds a wallet. */
  private readonly spendingBlind: bigint;

  /**
   * @param spendingBlind the holder's blind, or `null` to take the one the state carries. There is
   *   deliberately no default: a default is how the unblinded leaf comes back.
   */
  constructor(
    private readonly hasher: Poseidon2,
    spendingBlind: bigint | null,
    state?: SpendingWalletSetState,
  ) {
    if (state && state.schemaVersion !== SPENDING_WALLET_SET_SCHEMA_VERSION) {
      throw new Error("unsupported spending wallet set schema version");
    }
    if (state && state.profile !== GAP_SPENDING_WALLET_SET_V2) {
      throw new Error("unsupported spending wallet set profile");
    }
    const fromState = state?.spendingBlind === undefined ? undefined : BigInt(state.spendingBlind);
    // `??` so a MISSING argument fails exactly like an explicit null: a call site that predates
    // the blind must not silently rebuild the unblinded tree.
    const resolved = spendingBlind ?? fromState;
    if (resolved === undefined) {
      throw new Error(
        "a spending wallet set needs its blind: pass spendingBlindFor(hasher, privateSalt), or"
        + " EMPTY_SET_BLIND for a tree that holds no leaves",
      );
    }
    if (spendingBlind != null && fromState !== undefined && spendingBlind !== fromState) {
      throw new Error("spending wallet blind disagrees with the restored state's");
    }
    this.spendingBlind = resolved;
    assertField(this.spendingBlind, "spending wallet blind");
    this.depth = state?.depth ?? DEFAULT_SPENDING_WALLET_DEPTH;
    assertDepth(this.depth);
    this.revision = state?.revision ?? 0n;
    if (this.revision < 0n) throw new Error("spending wallet revision cannot be negative");

    const occupied = new Set<number>();
    for (const assignment of state?.assignments ?? []) {
      const account = canonicalAddress(assignment.account);
      this.assertSlot(assignment.slot);
      if (this.assignments.has(account)) throw new Error("duplicate spending wallet assignment");
      if (occupied.has(assignment.slot)) throw new Error("duplicate spending wallet slot");
      this.assignments.set(account, assignment.slot);
      occupied.add(assignment.slot);
    }
  }

  snapshot(): SpendingWalletSetSnapshot {
    return {
      profile: GAP_SPENDING_WALLET_SET_V2,
      schemaVersion: SPENDING_WALLET_SET_SCHEMA_VERSION,
      revision: this.revision,
      depth: this.depth,
      assignments: [...this.assignments.entries()]
        .map(([account, slot]) => ({ account, slot }))
        .sort((left, right) => left.slot - right.slot),
      spendingBlind: toBytes32(this.spendingBlind),
      root: this.root(),
    };
  }

  root(): Bytes32 {
    const { root } = this.merkle(undefined);
    return toBytes32(root);
  }

  proof(account: Address): SpendingWalletMembershipProof {
    const canonical = canonicalAddress(account);
    const slot = this.assignments.get(canonical);
    if (slot === undefined) throw new Error("spending wallet is not assigned");
    const leaf = this.hasher.hash2(addressToField(canonical), this.spendingBlind);
    const { root, siblings } = this.merkle(slot);
    return {
      account: canonical,
      slot,
      leaf: toBytes32(leaf),
      root: toBytes32(root),
      siblings: siblings.map(toBytes32),
      pathIndices: Array.from({ length: this.depth }, (_, level) => (slot >> level) & 1),
    };
  }

  proofs(): readonly SpendingWalletMembershipProof[] {
    return this.snapshot().assignments.map(({ account }) => this.proof(account));
  }

  add(account: Address, expectedRevision: bigint): SpendingWalletSetChange {
    this.assertRevision(expectedRevision);
    const canonical = canonicalAddress(account);
    if (this.assignments.has(canonical)) throw new Error("spending wallet is already assigned");
    const slot = this.nextSlot(canonical);
    this.assignments.set(canonical, slot);
    this.revision += 1n;
    return { snapshot: this.snapshot(), membership: this.proof(canonical) };
  }

  remove(account: Address, expectedRevision: bigint): SpendingWalletSetChange {
    this.assertRevision(expectedRevision);
    const canonical = canonicalAddress(account);
    if (!this.assignments.delete(canonical)) throw new Error("spending wallet is not assigned");
    this.revision += 1n;
    return { snapshot: this.snapshot() };
  }

  private assertRevision(expected: bigint): void {
    if (expected !== this.revision) {
      throw new Error(`stale spending wallet revision: expected ${expected}, current ${this.revision}`);
    }
  }

  private assertSlot(slot: number): void {
    if (!Number.isSafeInteger(slot) || slot < 0 || slot >= 2 ** this.depth) {
      throw new Error("spending wallet slot is outside the tree");
    }
  }

  private nextSlot(account: Address): number {
    const capacity = 2 ** this.depth;
    const preferred = Number(addressToField(account) & ((1n << BigInt(this.depth)) - 1n));
    const occupied = new Set(this.assignments.values());
    for (let offset = 0; offset < capacity; offset += 1) {
      const slot = (preferred + offset) % capacity;
      if (!occupied.has(slot)) return slot;
    }
    throw new Error("spending wallet set is full");
  }

  private merkle(proofSlot: number | undefined): { root: bigint; siblings: bigint[] } {
    const empty = [0n];
    for (let level = 0; level < this.depth; level += 1) {
      empty.push(this.hasher.hash2(empty[level], empty[level]));
    }
    let nodes = new Map<number, bigint>();
    for (const [account, slot] of this.assignments) {
      nodes.set(slot, this.hasher.hash2(addressToField(account), this.spendingBlind));
    }
    const siblings: bigint[] = [];
    let proofIndex = proofSlot;
    for (let level = 0; level < this.depth; level += 1) {
      if (proofIndex !== undefined) siblings.push(nodes.get(proofIndex ^ 1) ?? empty[level]);
      const parents = new Set([...nodes.keys()].map((slot) => slot >> 1));
      const next = new Map<number, bigint>();
      for (const parent of parents) {
        const left = nodes.get(parent * 2) ?? empty[level];
        const right = nodes.get(parent * 2 + 1) ?? empty[level];
        next.set(parent, this.hasher.hash2(left, right));
      }
      nodes = next;
      if (proofIndex !== undefined) proofIndex >>= 1;
    }
    return { root: nodes.get(0) ?? empty[this.depth], siblings };
  }
}
