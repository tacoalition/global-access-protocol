import assert from "node:assert/strict";
import test from "node:test";
import { CredentialBuilder, computeCredentialLeaf, computeOneLeafRoot, computeSaltCommitment } from "../src/credential-builder";
import { createPoseidon2, sampleField, toBytes32 } from "../src/field";

const anchor = `0x${"11".repeat(20)}` as const;
const regimeHash = `0x${"22".repeat(32)}` as const;
const did = `0x${"03".padStart(64, "0")}` as const;
const ikId = `0x${"04".padStart(64, "0")}` as const;
const privateSalt = `0x${"05".padStart(64, "0")}` as const;
const wallet = anchor;

test("Poseidon encodings are frozen for salt, one-wallet root, and GAP credential leaf", async () => {
  const hasher = await createPoseidon2();
  assert.equal(computeSaltCommitment(hasher, 5n), 14715744141351469745078640018556777045717071602313402267792898687731436145768n);
  const spendingRoot = computeOneLeafRoot(hasher, hasher.hash2(BigInt(wallet), 0n), Number(BigInt(wallet) & 0xffn), 8);
  assert.equal(spendingRoot, 10001926210470195301387826813605747044700066675788870751069966564815637867936n);
  // REGENERATED for GAP_ATTR_CRED_V3. The leaf moved on purpose: the domain tag changed and
  // `attrsHash` went from Poseidon(2) over two attributes to Poseidon(4) over four. Note the two
  // encodings ABOVE did not move: this test isolating one of the three is the reason to keep it.
  // The V2 value was 0x038105d106f66cc280130f0e486566c9466fd5aef4ded95823721126ab1c30ad.
  assert.equal(computeCredentialLeaf(hasher, {
    chainId: 84532, anchor, regimeHash, did, ikId, attributes: [1n, 1n, 0n, 0n], privateSalt, expiresAt: 1_800_000_000n,
  }), "0x06222102e9c2d7c08eb14a06c1c0a471b4d910555e1c6934d9c22559df0ddb52");
});

test("builder enforces slot lifetimes and exact approved attributes", async () => {
  const hasher = await createPoseidon2();
  const builder = new CredentialBuilder(hasher);
  const route = { chainId: 84532 as const, anchor, regimeHash, did, ikId, privateSalt };
  assert.equal(builder.buildIdentityCredential({ ...route, expiresAt: 1_086_400n }, 1_000_000n).attributes[0], 1n);
  assert.equal(builder.buildFundCredential({ ...route, expiresAt: 1_003_600n }, 1_000_000n).attributes[1], 1n);
  assert.throws(() => builder.buildIdentityCredential({ ...route, expiresAt: 1_086_401n }, 1_000_000n), /24-hour/);
  assert.throws(() => builder.buildFundCredential({ ...route, expiresAt: 1_003_601n }, 1_000_000n), /one-hour/);
  assert.throws(() => builder.buildCredential({ ...route, attributes: [1n, 0n, 0n, 0n], expiresAt: 2n }), /exactly/);
});

test("seed builder samples fields, retries occupied indices, and reserves all three trees atomically", async () => {
  const hasher = await createPoseidon2();
  let randomCall = 0;
  const random = () => {
    randomCall += 1;
    const bytes = new Uint8Array(32);
    bytes[31] = randomCall;
    return bytes;
  };
  const checked: number[] = [];
  const builder = new CredentialBuilder(hasher, random);
  const result = await builder.reserveSeed(wallet, {
    async areAllSlotsEmpty(_did, index) { checked.push(index); return index !== 1; },
    async tryReserve(_did, index) { return { reservationId: `reservation-${index}`, finalizedBlockHash: `0x${"aa".repeat(32)}` }; },
  });
  assert.deepEqual(checked, [1, 3]);
  assert.equal(result.reservation.index, 3);
  assert.equal(result.seed.reservedDidIndex, 3);
  assert.deepEqual(result.seed.governanceKeys, [wallet]);
  assert.equal(result.seed.privateSalt, toBytes32(4n));
  assert.match(result.didLeaf, /^0x[0-9a-f]{64}$/);
});

test("field sampling rejects out-of-field, zero, and short random values", () => {
  let calls = 0;
  const value = sampleField(() => {
    calls += 1;
    if (calls === 1) return new Uint8Array(32).fill(0xff);
    const bytes = new Uint8Array(32);
    if (calls === 3) bytes[31] = 1;
    return bytes;
  });
  assert.equal(value, 1n);
  assert.equal(calls, 3);
  assert.throws(() => sampleField(() => new Uint8Array(31)), /exactly 32 bytes/);
});
