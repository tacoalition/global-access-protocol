// Shared GAP v2 offchain crypto: Poseidon (field), sparse-tree witnesses, leaf builders.
// Mirrors contracts/src/v2/{PoseidonSparseTree,GapLib} and circuits/src/v2/session.circom.
const { buildPoseidon } = require("circomlibjs");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let _poseidon = null;
async function poseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

// H2(a,b) returning a bigint in the field.
async function h2(a, b) {
  const p = await poseidon();
  return p.F.toObject(p([toBig(a), toBig(b)]));
}
// H4(a,b,c,d) returning a bigint in the field. This is a genuine Poseidon(4): the per-regime
// attribute fold under GAP_ATTR_CRED_V3, and is NOT `chain([a,b,c,d])`, which is three Poseidon(2)
// applications. Mirrors `AttrsHash()` in circuits/src/v2/lib/policy.circom.
// Poseidon over THREE inputs: the circuit's `Poseidon(3)`, not a chain of 2-ary hashes. Used for
// ikRefCommitment, which is blinded; a chain would be a different function and the proof would not
// verify against it.
async function h3(a, b, c) {
  const p = await poseidon();
  return p.F.toObject(p([toBig(a), toBig(b), toBig(c)]));
}

async function h4(a, b, c, d) {
  const p = await poseidon();
  return p.F.toObject(p([toBig(a), toBig(b), toBig(c), toBig(d)]));
}
async function chain(items) {
  let acc = 0n;
  for (let i = 0; i < items.length; i++) {
    acc = i === 0 ? toBig(items[0]) : await h2(acc, items[i]);
  }
  return acc;
}
function toBig(x) {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") return BigInt(x);
  if (typeof x === "string") return x.startsWith("0x") ? BigInt(x) : BigInt(x);
  return BigInt(x);
}
function keccakToField(hexOrBig) {
  return toBig(hexOrBig) % P;
}

// Sparse Poseidon tree (dense-storage) matching PoseidonSparseTree.sol.
class SparseTree {
  constructor(depth) {
    this.depth = depth;
    this.leaves = new Map(); // index -> bigint
    this.slots = new Map();  // key (bigint) -> allocated index
    this.nextIndex = 0;
    this.zeros = null;
    this.p = null;
  }
  async init() {
    this.p = await poseidon();
    this.zeros = [0n];
    for (let i = 1; i <= this.depth; i++) {
      this.zeros.push(this.p.F.toObject(this.p([this.zeros[i - 1], this.zeros[i - 1]])));
    }
  }
  // ALLOCATION-ORDERED, mirroring PoseidonSparseTree.sol exactly: first key in takes slot 0, and a
  // key keeps its slot. The index used to be the low `depth` bits of the key, which collides on the
  // birthday bound, 50% by the 302nd key into a depth-16 tree, and a collision on chain is a hard
  // revert. The circuit takes pathIndices as a WITNESS and the leaf binds the key, so position never
  // carried meaning and this costs nothing in constraints.
  //
  // These two implementations must allocate in the SAME ORDER or the witness will not match the
  // on-chain root. That is not a silent failure: the proof simply will not verify.
  indexOf(key) {
    const k = toBig(key);
    const existing = this.slots.get(k);
    if (existing !== undefined) return existing;
    if (this.nextIndex >= 2 ** this.depth) throw new Error("SparseTree: tree full");
    const index = this.nextIndex++;
    this.slots.set(k, index);
    return index;
  }
  /** The slot this key holds, or undefined. Never allocates, for callers that must not. */
  slotOf(key) { return this.slots.get(toBig(key)); }
  set(index, value) { this.leaves.set(index, toBig(value)); }
  setByKey(key, value) { this.set(this.indexOf(key), value); }
  _nodeAt(level, index, cache) {
    const k = level + ":" + index;
    if (cache.has(k)) return cache.get(k);
    let v;
    if (level === 0) v = this.leaves.get(index) ?? 0n;
    else {
      const l = this._nodeAt(level - 1, index * 2, cache);
      const r = this._nodeAt(level - 1, index * 2 + 1, cache);
      v = (l === 0n && r === 0n) ? this.zeros[level] : this.p.F.toObject(this.p([l, r]));
    }
    cache.set(k, v);
    return v;
  }
  root() { return this._nodeAt(this.depth, 0, new Map()); }
  // Returns { siblings[], pathIndices[] } for the leaf at `index`.
  proof(index) {
    const cache = new Map();
    const siblings = [];
    const pathIndices = [];
    let idx = index;
    // Build a full cache by computing root once
    this._nodeAt(this.depth, 0, cache);
    for (let level = 0; level < this.depth; level++) {
      const sib = idx ^ 1;
      siblings.push(this._nodeAt(level, sib, cache));
      pathIndices.push(idx & 1);
      idx = idx >> 1;
    }
    return { siblings, pathIndices };
  }
}

// Indexed Merkle tree (sorted linked list) matching IndexedMerkleTree.sol, full-key
// NON-membership (GAP-H1). Leaves H2(key, nextKey) at allocation-ordered slots;
// genesis {0,0} at slot 0. lowLeafFor(key) builds the circuit witness.
class IndexedTree {
  constructor(depth) {
    this.t = new SparseTree(depth);
    this.nodes = [{ key: 0n, nextKey: 0n }]; // genesis sentinel
    this.keyIndex = new Map();               // key -> slot (genesis key 0 excluded)
    this.freeSlots = [];                     // reclaimed slots (LIFO, mirrors the contract)
  }
  async init() {
    await this.t.init();
    this.t.set(0, await h2(0n, 0n));
  }
  predecessorIndex(key) {
    key = toBig(key);
    let idx = 0, n = this.nodes[0];
    while (n.nextKey !== 0n && n.nextKey < key) {
      idx = this.keyIndex.get(n.nextKey);
      n = this.nodes[idx];
    }
    return idx;
  }
  async insert(key) {
    key = toBig(key);
    if (key === 0n || key >= P || this.keyIndex.has(key)) throw new Error("IndexedTree: bad/duplicate key");
    const predIdx = this.predecessorIndex(key);
    const pred = this.nodes[predIdx];
    const slot = this.freeSlots.length > 0 ? this.freeSlots.pop() : this.nodes.length;
    if (slot >= 2 ** this.t.depth) throw new Error("IndexedTree: full"); // mirrors IMT: full
    this.nodes[slot] = { key, nextKey: pred.nextKey };
    pred.nextKey = key;
    this.keyIndex.set(key, slot);
    this.t.set(predIdx, await h2(pred.key, key));
    this.t.set(slot, await h2(key, this.nodes[slot].nextKey));
  }
  async remove(key) {
    key = toBig(key);
    const slot = this.keyIndex.get(key);
    if (slot === undefined) throw new Error("IndexedTree: key absent");
    const predIdx = this.predecessorIndex(key);
    const pred = this.nodes[predIdx];
    pred.nextKey = this.nodes[slot].nextKey;
    this.nodes[slot] = { key: 0n, nextKey: 0n }; // dead slot: leaf zeroed, slot reclaimed
    this.keyIndex.delete(key);
    this.freeSlots.push(slot);
    this.t.set(predIdx, await h2(pred.key, pred.nextKey));
    this.t.set(slot, 0n);
  }
  root() { return this.t.root(); }
  // Non-membership witness: the low leaf bracketing `key` + its membership path.
  lowLeafFor(key) {
    const index = this.predecessorIndex(toBig(key));
    const n = this.nodes[index];
    const { siblings, pathIndices } = this.t.proof(index);
    return { index, lowKey: n.key, nextKey: n.nextKey, siblings, pathIndices };
  }
}

module.exports = { P, poseidon, h2, h3, h4, chain, toBig, keccakToField, SparseTree, IndexedTree };
