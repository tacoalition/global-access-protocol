import { LOCAL_CIRCUIT_METADATA, assertCircuitMetadata, type CircuitMetadata } from "./metadata";
import { bigIntToBytes, bytesToHex, concatBytes, sampleField, type RandomBytes } from "./random";
import { tmSessionContextForWitness } from "./tm-envelope";
import { SPENDING_BLIND_TAG, type TmEncryptionPlaintext } from "./types";
import type {
  Clause,
  Holder,
  ProverConfig,
  SessionInput,
  SessionScenario,
  SpendingKeyWitness,
  TmEncryptionContext,
  WitnessData,
} from "./types";

type CryptoModule = ProverConfig["crypto"];

function bits(index: number, depth: number): string[] {
  return Array.from({ length: depth }, (_, i) => String((index >> i) & 1));
}

function assertIndex(label: string, index: number, depth: number): void {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** depth) {
    throw new Error(`GAP SDK: invalid ${label} index`);
  }
}

function assertSiblings(label: string, siblings: bigint[], depth: number): void {
  if (siblings.length !== depth) {
    throw new Error(`GAP SDK: ${label} requires ${depth} siblings, got ${siblings.length}`);
  }
}

function assertSpendingWitness(witness: SpendingKeyWitness, depth: number): void {
  assertSiblings("spending-key proof", witness.siblings, depth);
  if (witness.pathIndices.length !== depth) {
    throw new Error(
      `GAP SDK: spending-key proof requires ${depth} path indices, got ${witness.pathIndices.length}`,
    );
  }
  if (witness.pathIndices.some((value) => value !== 0 && value !== 1)) {
    throw new Error("GAP SDK: spending-key path indices must be binary");
  }
}

function assertWitness(w: WitnessData, metadata: CircuitMetadata): void {
  assertCircuitMetadata(metadata);
  const d = metadata.depths;
  assertSiblings("DID proof", w.didSiblings, d.did);
  assertSiblings("credential-0 proof", w.cred0Siblings, d.credential);
  assertSiblings("credential-1 proof", w.cred1Siblings, d.credential);
  assertSiblings("risk proof", w.rdb.siblings, d.risk);
  assertIndex("DID", w.didIndex, d.did);
  assertIndex("credential-0", w.cred0Index, d.credential);
  assertIndex("credential-1", w.cred1Index, d.credential);
  assertIndex("risk", w.rdb.index, d.risk);
  if (w.spendingKeyWitness) {
    assertSpendingWitness(w.spendingKeyWitness, d.spendingKey);
  } else if (metadata.profile !== "gap-v2-local") {
    throw new Error("GAP SDK: Base Fund profile requires an explicit spending-key witness");
  }
  if (w.clauses.length !== 6) throw new Error("GAP SDK: circuit requires exactly six clauses");
  if (w.ita0 === w.ita1) {
    // Allowed by the local reference profile only; the public integration requires two trust roots.
    if (metadata.profile !== "gap-v2-local") {
      throw new Error("GAP SDK: Base Fund profiles require distinct identity anchors");
    }
  }
}

/** The predicate fold, pub[3]. Exported: the relayer re-derives it to check a proof it did
 * not build, and a second copy of this loop is how pub[3] would come to mean two things. */
export async function clausesHash(gc: CryptoModule, clauses: Clause[]): Promise<bigint> {
  const items: bigint[] = [0n];
  for (const clause of clauses) {
    const meta =
      BigInt(clause.enabled) |
      (BigInt(clause.groupId) << 8n) |
      (BigInt(clause.attrIndex) << 16n) |
      (BigInt(clause.op) << 24n);
    items.push(meta, clause.value);
  }
  return gc.chain(items);
}

function localCipher(
  plaintext: TmEncryptionPlaintext,
): `0x${string}` {
  return bytesToHex(
    concatBytes(
      bigIntToBytes(plaintext.pseudonym),
      bigIntToBytes(plaintext.blindingR),
      bigIntToBytes(plaintext.ita0),
      bigIntToBytes(plaintext.ikId0),
      // The fifth field, which this path was missing after `ikBlind` was added. Without it the
      // envelope is one element short and a monitor cannot reopen ikRefCommitment: a cleartext
      // stand-in that is also WRONG is worse than one that is merely insecure.
      bigIntToBytes(plaintext.ikBlind),
    ),
  );
}

/**
 * The blind that stops the published `spendingKeyRoot` being a preimage of the holder's wallets.
 *
 * MIRRORS `gap-identity-keeper-v2` `spendingBlindFor` and the circuit's `spendingBlind` component
 * (`circuits/src/v2/lib/gap_session.circom`). All three must agree or a proof built here does not
 * verify against a root built there, which is exactly how this was found: the leaf was blinded in
 * the circuit and the keeper, this file was not, and the joined lane failed with "spending-key
 * proof does not match its root".
 */
/**
 * The blind for a tree that holds no holder's wallets.
 *
 * NAMED, and never a default. A fixture or a one-wallet scenario that genuinely has no salt-derived
 * set passes this, and the choice is then visible at the call site instead of being the value a
 * forgotten argument happens to take.
 */
export const EMPTY_SPENDING_BLIND = 0n;

export function spendingBlindFor(gc: CryptoModule, privateSalt: bigint): Promise<bigint> {
  return gc.h2(privateSalt, SPENDING_BLIND_TAG);
}

/**
 * A one-wallet spending set's root and this wallet's membership proof.
 *
 * THE BLIND IS REQUIRED, not defaulted. A default of zero would silently rebuild the OLD
 * unblinded leaf: the very shape that made the published root computable from the address in
 * eight hashes, and the caller would get a root that verifies against nothing. Callers holding
 * no set of their own pass `EMPTY_SPENDING_BLIND` explicitly, so "this tree is unblinded" is a
 * statement somebody made rather than a parameter nobody filled in.
 */
export async function spendingKeyRootFor(
  gc: CryptoModule,
  depth: number,
  account: bigint,
  spendingBlind: bigint,
): Promise<{ root: bigint; siblings: bigint[]; pathIndices: number[] }> {
  if (typeof spendingBlind !== "bigint") {
    throw new Error(
      "GAP SDK: a spending-key root needs its blind, pass spendingBlindFor(gc, privateSalt),"
      + " or EMPTY_SPENDING_BLIND for a tree that holds no leaves",
    );
  }
  const tree = new gc.SparseTree(depth);
  await tree.init();
  tree.setByKey(account, await gc.h2(account, spendingBlind));
  const proof = tree.proof(tree.indexOf(account));
  return { root: tree.root(), ...proof };
}

async function spendingWitnessFor(
  gc: CryptoModule,
  metadata: CircuitMetadata,
  account: bigint,
  spendingBlind: bigint,
  explicit?: SpendingKeyWitness,
): Promise<SpendingKeyWitness> {
  if (!explicit) {
    return spendingKeyRootFor(gc, metadata.depths.spendingKey, account, spendingBlind);
  }
  // The SAME leaf the circuit constrains. Recomputing it unblinded here would accept a witness
  // the circuit rejects: a proof that fails at the verifier instead of at the builder.
  let node = await gc.h2(account, spendingBlind);
  for (let level = 0; level < explicit.siblings.length; level += 1) {
    node = explicit.pathIndices[level] === 0
      ? await gc.h2(node, explicit.siblings[level])
      : await gc.h2(explicit.siblings[level], node);
  }
  if (node !== explicit.root) {
    throw new Error("GAP SDK: spending-key proof does not match its root");
  }
  return explicit;
}

/**
 * The person's spending-wallet-set root, as pinned in their DID document.
 *
 * A holder that carries an explicit root is a PERSON with a wallet set (possibly
 * many wallets); the singleton fallback exists only for one-wallet fixtures that
 * predate the wallet set, and it must never silently paper over a person whose
 * DID document pins a multi-wallet root, hence the paired witness requirement.
 */
function holderSpendingRoot(
  gc: CryptoModule, depth: number, holder: Holder, spendingBlind: bigint,
): Promise<bigint> {
  if (holder.spendingKeyRoot === undefined) {
    return spendingKeyRootFor(gc, depth, holder.account, spendingBlind).then((s) => s.root);
  }
  return Promise.resolve(holder.spendingKeyRoot);
}

function assertHolderSpendingSet(holder: Holder): void {
  if (holder.spendingKeyRoot !== undefined && !holder.spendingKeyWitness) {
    throw new Error(
      "GAP SDK: a holder pinning a spending-wallet-set root must supply this wallet's membership proof",
    );
  }
  if (
    holder.spendingKeyRoot !== undefined &&
    holder.spendingKeyWitness &&
    holder.spendingKeyWitness.root !== holder.spendingKeyRoot
  ) {
    throw new Error("GAP SDK: holder spending-wallet witness is for a different wallet-set root");
  }
}

async function didLeafFor(
  gc: CryptoModule,
  depth: number,
  holder: Holder,
): Promise<bigint> {
  // The holder's OWN blind, derived from their salt exactly as the circuit derives it. A holder
  // pinning an explicit root never reaches the singleton path, so this only matters for the
  // one-wallet fixtures, and for those the leaf must still match what the circuit constrains.
  const root = await holderSpendingRoot(
    gc, depth, holder, await spendingBlindFor(gc, holder.privateSalt),
  );
  const saltCommitment = await gc.h2(holder.privateSalt, 0n);
  return gc.h2(await gc.h2(holder.did, saltCommitment), root);
}

async function encrypt(
  cfg: ProverConfig,
  w: WitnessData,
  plaintext: TmEncryptionPlaintext,
  commitments: { pseudonymCommitment: bigint; ikRefCommitment: bigint },
): Promise<`0x${string}`> {
  // Built by the one shared constructor the transaction monitor also calls, so the associated
  // data the monitor authenticates against cannot drift from the one sealed here.
  const context: TmEncryptionContext = tmSessionContextForWitness(w, commitments);
  if (cfg.tmCipher) return cfg.tmCipher.encrypt(plaintext, context);
  const metadata = cfg.metadata ?? LOCAL_CIRCUIT_METADATA;
  // The cleartext envelope survives for ONE caller: the pure-local `make demo` reference CLI,
  // whose own deployment publishes a placeholder monitor key and therefore has nothing real to
  // encrypt to. It is not a "local mode": the joined lane runs the authenticated cipher on
  // chain 31337 exactly as it does on a public chain. Reaching it takes an explicit opt-in AND
  // the local reference profile AND chain 31337; the Base Fund profile can no longer get here
  // at all, because that is the lane whose pseudonyms must never be readable.
  if (
    cfg.allowInsecureLocalCipher &&
    w.chainId === 31337n &&
    metadata.profile === "gap-v2-local"
  ) {
    return localCipher(plaintext);
  }
  throw new Error("GAP SDK: authenticated TM cipher is required");
}

export async function inputFromWitness(
  cfg: ProverConfig,
  w: WitnessData,
): Promise<SessionInput> {
  const gc = cfg.crypto;
  const metadata = cfg.metadata ?? LOCAL_CIRCUIT_METADATA;
  assertWitness(w, metadata);
  const spending = await spendingWitnessFor(
    gc, metadata, w.account, await spendingBlindFor(gc, w.privateSalt), w.spendingKeyWitness,
  );
  const pseudonym = await gc.h2(
    await gc.h2(await gc.h2(w.did, w.privateSalt), w.regime0),
    w.gatedContract,
  );
  const blindingR = sampleField(cfg.randomBytes as RandomBytes | undefined);
  const pseudonymCommitment = await gc.h2(pseudonym, blindingR);
  // A SEPARATE blinding factor for the IK reference. Both of pub[17]'s other preimages are public, 
  // `ita0` is an address, `ikId0` is emitted by `IKRegistered`, so unblinded it inverted by table
  // lookup and named the Identity Keeper to anyone reading the chain.
  const ikBlind = sampleField(cfg.randomBytes as RandomBytes | undefined);
  const ikRefCommitment = await gc.h3(w.ita0, w.ikId0, ikBlind);
  const predicate = await clausesHash(gc, w.clauses);
  // The AAD the envelope is sealed under, returned alongside it. A monitor must authenticate against
  // the SAME context or the open fails, so handing it back beats having each caller rebuild twelve
  // fields and discover a mismatch as an AEAD error.
  const tmContext = tmSessionContextForWitness(w, { pseudonymCommitment, ikRefCommitment });
  const ciphertext = await encrypt(
    cfg,
    w,
    { pseudonym, blindingR, ita0: w.ita0, ikId0: w.ikId0, ikBlind },
    { pseudonymCommitment, ikRefCommitment },
  );
  const d = metadata.depths;
  const input: Record<string, unknown> = {
    account: String(w.account),
    chainId: String(w.chainId),
    sessionManager: String(w.sessionManager),
    clausesHash: String(predicate),
    validUntil: String(w.validUntil),
    accountNonce: String(w.accountNonce),
    didRoot: String(w.didRoot),
    ita0: String(w.ita0),
    regimeHash0: String(w.regime0),
    credRoot0: String(w.credRoot0),
    ita1: String(w.ita1),
    regimeHash1: String(w.regime1),
    credRoot1: String(w.credRoot1),
    ordbId: String(w.ordbId),
    riskRoot: String(w.rdb.root),
    gatedContract: String(w.gatedContract),
    pseudonymCommitment: String(pseudonymCommitment),
    ikRefCommitment: String(ikRefCommitment),
    monitorKeyId: String(w.monitorKeyId),
    did: String(w.did),
    privateSalt: String(w.privateSalt),
    ikBlind: String(ikBlind),
    spendingKeyRoot: String(spending.root),
    didSiblings: w.didSiblings.map(String),
    didPathIndices: bits(w.didIndex, d.did),
    skSiblings: spending.siblings.map(String),
    skPathIndices: spending.pathIndices.map(String),
    attrs: w.attrs.map(String),
    ikId0: String(w.ikId0),
    ikId1: String(w.ikId1),
    cred0ExpiresAt: String(w.credExpiresAt[0]),
    cred1ExpiresAt: String(w.credExpiresAt[1]),
    cred0Siblings: w.cred0Siblings.map(String),
    cred0PathIndices: bits(w.cred0Index, d.credential),
    cred1Siblings: w.cred1Siblings.map(String),
    cred1PathIndices: bits(w.cred1Index, d.credential),
    rdbLowKey: String(w.rdb.lowKey),
    rdbNextKey: String(w.rdb.nextKey),
    rdbSiblings: w.rdb.siblings.map(String),
    rdbPathIndices: bits(w.rdb.index, d.risk),
    blindingR: String(blindingR),
    clEnabled: w.clauses.map((c) => String(c.enabled)),
    clGroupId: w.clauses.map((c) => String(c.groupId)),
    clAttrIndex: w.clauses.map((c) => String(c.attrIndex)),
    clOp: w.clauses.map((c) => String(c.op)),
    clValue: w.clauses.map((c) => String(c.value)),
  };
  return {
    input,
    ciphertext,
    tmContext,
    pseudonym,
    roots: {
      didRoot: w.didRoot,
      credRoot0: w.credRoot0,
      credRoot1: w.credRoot1,
      riskRoot: w.rdb.root,
    },
  };
}

export async function inputFromScenario(
  cfg: ProverConfig,
  scenario: SessionScenario,
): Promise<SessionInput> {
  const metadata = cfg.metadata ?? LOCAL_CIRCUIT_METADATA;
  if (metadata.profile !== "gap-v2-local") {
    throw new Error("GAP SDK: holder-mirror scenarios are local-reference only");
  }
  const gc = cfg.crypto;
  const didTree = new gc.SparseTree(metadata.depths.did);
  const cred0 = new gc.SparseTree(metadata.depths.credential);
  const cred1 = new gc.SparseTree(metadata.depths.credential);
  await Promise.all([didTree.init(), cred0.init(), cred1.init()]);
  // ORDER IS NOW LOAD-BEARING. Slots are allocation-ordered on both sides, so `allHolders` must be
  // in the same order the chain registered them, and credential leaves in the order they were issued.
  // Truncated indices used to make this irrelevant; they also collided on the birthday bound, which
  // is why they are gone (see PoseidonSparseTree.sol).
  //
  // A mismatch is NOT silent: the mirror's root will differ from the chain's, the public input will
  // not match, and the proof will fail to verify. That is the right failure mode for this, but if
  // you are debugging a root mismatch, this ordering is the first thing to check.
  for (const holder of scenario.allHolders) {
    assertHolderSpendingSet(holder);
    didTree.setByKey(
      holder.did,
      await didLeafFor(gc, metadata.depths.spendingKey, holder),
    );
    if (holder.credLeaves[0] !== 0n) cred0.setByKey(holder.did, holder.credLeaves[0]);
    if (holder.credLeaves[1] !== 0n) cred1.setByKey(holder.did, holder.credLeaves[1]);
  }
  const holder = scenario.holder;
  assertHolderSpendingSet(holder);
  const didProof = didTree.proof(didTree.indexOf(holder.did));
  const proof0 = cred0.proof(cred0.indexOf(holder.did));
  const proof1 = cred1.proof(cred1.indexOf(holder.did));
  return inputFromWitness(cfg, {
    ...scenario,
    did: holder.did,
    privateSalt: holder.privateSalt,
    account: holder.account,
    // Carried through so the acting wallet proves membership in the SAME root the
    // DID leaf above was folded from; without it the fallback would rebuild a
    // singleton tree and the two roots would disagree.
    ...(holder.spendingKeyWitness ? { spendingKeyWitness: holder.spendingKeyWitness } : {}),
    credExpiresAt: holder.credExpiresAt,
    didRoot: didTree.root(),
    credRoot0: cred0.root(),
    credRoot1: cred1.root(),
    didSiblings: didProof.siblings,
    didIndex: didTree.indexOf(holder.did),
    cred0Siblings: proof0.siblings,
    cred0Index: cred0.indexOf(holder.did),
    cred1Siblings: proof1.siblings,
    cred1Index: cred1.indexOf(holder.did),
  });
}
