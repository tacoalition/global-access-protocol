import { randomBytes } from "node:crypto";
import { CRED_TAG, addressToField, assertBytes, assertField, foldHash, fromHex, sampleField, toBytes32, type Poseidon2 } from "./field";
import type { CredentialPreimage, CredentialRoute, Bytes32, Address } from "./types";
import type { SeedPlaintext } from "./package-profile";

export interface DidReservation {
  readonly did: Bytes32;
  readonly privateSalt: Bytes32;
  readonly index: number;
  readonly finalizedBlockHash: Bytes32;
  readonly reservationId: string;
}

export interface DidReservationPort {
  areAllSlotsEmpty(did: Bytes32, index: number): Promise<boolean>;
  tryReserve(did: Bytes32, index: number): Promise<{ reservationId: string; finalizedBlockHash: Bytes32 } | undefined>;
}

export interface SeedBuildResult {
  readonly reservation: DidReservation;
  readonly seed: SeedPlaintext;
  readonly didLeaf: Bytes32;
}

export interface CredentialBuildInput extends CredentialRoute {
  readonly attributes: readonly [bigint, bigint, bigint, bigint];
  readonly privateSalt: Bytes32;
  readonly expiresAt: bigint;
}

export interface CredentialCommitmentInput {
  readonly chainId?: number;
  readonly anchor: Address;
  readonly regimeHash: Bytes32;
  readonly did: Bytes32;
  readonly ikId: Bytes32;
  readonly attributes: readonly [bigint, bigint, bigint, bigint];
  readonly privateSalt: Bytes32;
  readonly expiresAt: bigint;
}

export function computeSaltCommitment(hasher: Poseidon2, privateSalt: bigint): bigint {
  assertField(privateSalt, "privateSalt");
  return hasher.hash2(privateSalt, 0n);
}

export function computeOneLeafRoot(hasher: Poseidon2, leaf: bigint, index: number, depth: number): bigint {
  assertField(leaf, "leaf");
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** depth) throw new Error("tree index out of range");
  let node = leaf;
  let empty = 0n;
  for (let level = 0; level < depth; level += 1) {
    node = ((index >> level) & 1) === 0 ? hasher.hash2(node, empty) : hasher.hash2(empty, node);
    empty = hasher.hash2(empty, empty);
  }
  return node;
}

export function computeCredentialLeaf(
  hasher: Poseidon2,
  input: CredentialCommitmentInput,
): Bytes32 {
  assertBytes(input.anchor, 20, "anchor");
  assertBytes(input.regimeHash, 32, "regimeHash");
  assertBytes(input.did, 32, "did");
  assertBytes(input.ikId, 32, "ikId");
  assertBytes(input.privateSalt, 32, "privateSalt");
  const fields = [fromHex(input.regimeHash), fromHex(input.did), fromHex(input.ikId), fromHex(input.privateSalt)];
  fields.forEach((field, index) => assertField(field, `credential field ${index}`));
  if (input.attributes.some((attribute) => attribute < 0n || attribute > 0xffffffffffffffffn)) throw new Error("credential attribute exceeds uint64");
  if (input.expiresAt <= 0n || input.expiresAt >= 1n << 64n) throw new Error("credential expiry must be finite uint64");
  const attributesHash = hasher.hash4(
    input.attributes[0], input.attributes[1], input.attributes[2], input.attributes[3],
  );
  return toBytes32(foldHash(hasher, [
    CRED_TAG,
    addressToField(input.anchor),
    fromHex(input.regimeHash),
    fromHex(input.did),
    attributesHash,
    fromHex(input.privateSalt),
    fromHex(input.ikId),
    input.expiresAt,
  ]));
}

export class CredentialBuilder {
  constructor(
    private readonly hasher: Poseidon2,
    private readonly random: (size: number) => Uint8Array = randomBytes,
  ) {}

  buildCredential(input: CredentialBuildInput): CredentialPreimage {
    // The demo lane's fixed pair, now with the two reserved slots pinned to zero: a reserved index
    // that is allowed to carry anything is not reserved.
    if (
      input.attributes[0] !== 1n || input.attributes[1] !== 1n
      || input.attributes[2] !== 0n || input.attributes[3] !== 0n
    ) {
      throw new Error("demo issuer attributes must be exactly [1,1,0,0]");
    }
    return { ...input, commitment: computeCredentialLeaf(this.hasher, input) };
  }

  /**
   * Identity path. Distinct from `buildCredential` by construction, so the
   * fund-only [1,1] guard is unreachable from here and cannot be widened by
   * accident. Provenance of `attributes` is enforced in the worker against the
   * verified provider decision: this is only leaf construction.
   */
  buildIdentityCredentialWithAttributes(
    input: Omit<CredentialBuildInput, "attributes">,
    now: bigint,
    attributes: readonly [bigint, bigint, bigint, bigint],
  ): CredentialPreimage {
    if (input.expiresAt <= now || input.expiresAt - now > 24n * 60n * 60n) throw new Error("identity credential exceeds 24-hour demo lifetime");
    const built = { ...input, attributes };
    // computeCredentialLeaf still enforces the uint64 attribute bound and finite expiry.
    return { ...built, commitment: computeCredentialLeaf(this.hasher, built) };
  }

  buildIdentityCredential(input: Omit<CredentialBuildInput, "attributes">, now: bigint): CredentialPreimage {
    return this.buildIdentityCredentialWithAttributes(input, now, [1n, 1n, 0n, 0n]);
  }

  buildFundCredential(input: Omit<CredentialBuildInput, "attributes">, now: bigint): CredentialPreimage {
    if (input.expiresAt <= now || input.expiresAt - now > 60n * 60n) throw new Error("fund credential exceeds one-hour demo lifetime");
    return this.buildCredential({ ...input, attributes: [1n, 1n, 0n, 0n] });
  }

  async reserveSeed(wallet: Address, reservations: DidReservationPort, maxAttempts = 128): Promise<SeedBuildResult> {
    assertBytes(wallet, 20, "wallet");
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const didValue = sampleField(this.random);
      const saltValue = sampleField(this.random);
      const index = Number(didValue & 0xffffn);
      const stored = await this.tryIndex(reservations, toBytes32(didValue), index);
      if (stored) return this.finalize(wallet, didValue, saltValue, index, stored);
    }
    throw new Error("unable to reserve an empty DID/credential index");
  }

  /**
   * Reserve a slot for a DID that is already fixed (one human = one DID).
   *
   * The random-DID loop above resamples on slot collision. A deterministic
   * per-person DID must never be resampled: with 16-bit slots the birthday
   * bound puts collisions at a few hundred persons, so resampling would
   * silently mint a *different* DID for the same person. Hold the DID and probe
   * forward instead, refusing at the bound.
   */
  async reserveSeedForDid(
    did: Bytes32,
    wallet: Address,
    reservations: DidReservationPort,
    maxProbes = 128,
  ): Promise<SeedBuildResult> {
    assertBytes(wallet, 20, "wallet");
    assertBytes(did, 32, "did");
    const didValue = fromHex(did);
    assertField(didValue, "did");
    if (didValue === 0n) throw new Error("person DID must be nonzero");
    const saltValue = sampleField(this.random);
    const base = Number(didValue & 0xffffn);
    for (let probe = 0; probe < maxProbes; probe += 1) {
      const index = (base + probe) % 0x10000;
      const stored = await this.tryIndex(reservations, did, index);
      if (stored) return this.finalize(wallet, didValue, saltValue, index, stored);
    }
    throw new Error("unable to reserve a credential index for this person DID");
  }

  private async tryIndex(reservations: DidReservationPort, did: Bytes32, index: number) {
    if (!(await reservations.areAllSlotsEmpty(did, index))) return undefined;
    return reservations.tryReserve(did, index);
  }

  private finalize(
    wallet: Address,
    didValue: bigint,
    saltValue: bigint,
    index: number,
    stored: { reservationId: string; finalizedBlockHash: Bytes32 },
  ): SeedBuildResult {
    const did = toBytes32(didValue);
    const privateSalt = toBytes32(saltValue);
    const saltCommitment = computeSaltCommitment(this.hasher, saltValue);
    const spendingLeaf = this.hasher.hash2(addressToField(wallet), 0n);
    const spendingRoot = computeOneLeafRoot(this.hasher, spendingLeaf, Number(addressToField(wallet) & 0xffn), 8);
    const didLeaf = this.hasher.hash2(this.hasher.hash2(didValue, saltCommitment), spendingRoot);
    return {
      reservation: { did, privateSalt, index, ...stored },
      didLeaf: toBytes32(didLeaf),
      seed: {
        did,
        privateSalt,
        saltCommitment: toBytes32(saltCommitment),
        boundAccount: wallet,
        expectedSpendingRoot: toBytes32(spendingRoot),
        reservedDidIndex: index,
        governanceKeys: [wallet],
      },
    };
  }
}
