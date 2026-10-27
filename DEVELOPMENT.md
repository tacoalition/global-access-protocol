# Working on this

The things that are not obvious from reading the code, each of which has cost someone real time.
Ordinary setup lives in the [README](README.md); this is the part that bites.

## Run this before you push

```bash
pnpm install  # first time in a clone
make build    # first time, and after changing the circuit  (~50s)
make parity   # the cross-file invariants      (~1s)
make test     # the circuit, the contracts and every package, incl. a REAL proof
make repro    # the verifier rebuilds byte-for-byte from the circuit  (~45s)
make demo     # the whole story, on a fresh chain  (~160s)
```

All four are cheap. `make demo` is the one people skip and the one that catches what the others
cannot: unit tests pass happily while the thing a reader actually runs is broken.

## One file you must never edit

`contracts/src/v2/SessionVerifier.sol` is **generated**. `make repro` rebuilds it byte-for-byte from
the committed circuit and fails on any difference, so editing it, even the comments, even the licence
header, is a build failure rather than a change. It is also GPL-3.0-or-later (© 2021 0KIMS association), one
of several copyleft parts that [NOTICE](NOTICE) lists, which is why its header matters.

If you need it to differ, change the circuit and rebuild.

## If you touch the circuit, rebuild in this order

```
circuit  →  trusted setup  →  verifier  →  contracts  →  fixtures
```

`make build` does all of it. The order is not a style preference: the test suite asserts a **real**
Groth16 proof against the **deployed** verifier, so a proof from one build and a verifier from another
fail in a way that looks like a cryptography bug and is actually a staleness bug.

Then run `make repro`, which is the only check that catches a *substituted* zkey. `make artifact-check`
alone does not, it re-derives everything **from** the committed zkey, so it would happily bless a
swapped one.

And run `make circuit-test`, which asserts what the circuit **refuses** to prove: 41 cases that
mutate one field of the committed witness and require the rejection to come from the constraint
that names it. Every Foundry suite injects a verifier that returns `true` unconditionally, so they
describe what the SessionManager does with an accepted proof and cannot see a weakened circuit at
all. The expected constraint lines are resolved from the circom at runtime, so moving a constraint
moves the assertion with it, but **deleting** one makes a case fail, which is the point.

It needs `make build` first, because the witness calculator lives under the gitignored
`circuits/build/`. When it is missing the suite fails rather than skipping: a skipped circuit suite
reports green and is indistinguishable from a passing one.

## Two places where punctuation is load-bearing

`circuits/src/**` and `scripts/v2/lib/dev-beacon.sh` are excluded from prose conventions, including
the house rule against em dashes, because their **bytes are hashed**:

- the artifact manifest pins `circuitSourceSha256` over the transitive closure of local circuit
  includes, so editing a comment in a `.circom` file makes `make artifact-check` declare the
  committed proving artifacts incoherent with the source. That is the check working: the claim is
  that this verifier came from this exact source. Nothing in `circuits/src/` can be reformatted
  without a rebuild, and that includes adding a note saying so, which is why this note is here.
- `dev-beacon.sh` documents its closing value as `sha256("...")` of a string containing an em dash,
  and `DEV_BEACON_NAME` is recorded into the zkey's contribution metadata. Either byte changes the
  key and therefore the committed verifier.

A repository-wide style pass rewrote both. `setup-determinism.test.mjs` caught the beacon and
`make artifact-check` caught the circuit, which is the only reason this is a note and not a defect.

## `make build` leaves the tree dirty, and that is expected

Two files change on every build and neither is a mistake:

- `contracts/test/fixtures/v2/proof.json`: a fresh Groth16 proof, with fresh randomness. Two proofs of
  the same statement are different by construction.
- `circuits/keys/v2/local-artifact-manifest.json`'s `deployedBytecodeSha256`, solc embeds metadata
  that varies by environment, so this moves between machines. It is a note, not a pin; nothing
  reachable reads it.

Everything else in that manifest is a digest that must NOT move, and `make repro` is what says so.

## The mirrors, and the one that fails silently

Several numbers live in files that cannot see each other. `make parity` asserts them, and you should
run it after touching any of them:

| What | Mirrored across |
|---|---|
| The **19-slot public-input layout** | `gap-sdk/metadata.ts` ↔ `SessionManager.sol` ↔ `SessionVerifier.sol` ↔ `session.circom` |
| The depth tuple `(did, spendingKey, credential, risk)` | `session.circom` ↔ the SDK's local profile ↔ `DeployV2.s.sol` |
| `MAX_CLAUSES` | `session.circom` ↔ `UserPolicyRegistry.sol` |
| The 8-attribute vocabulary | `gap_session.circom` ↔ `UserPolicyRegistry.sol` |

**The layout is the dangerous one.** The SDK maps signals to bindings **by index**. A layout that
disagrees does not fail to verify: it verifies, against the wrong binding. That is a correctness bug
that looks like everything working.

## Three Poseidons have to agree

The hash exists three times: in the circuit, as deployed bytecode, and as `circomlibjs` off-chain. They
must produce identical output or proofs stop verifying for reasons that are very hard to read.
`test_RootParityWithJsMirror` pins the on-chain tree against the JS mirror; don't delete it.

And a specific trap: **`attrsHash` is a genuine `Poseidon(4)`**, not a chain of 2-ary hashes over four
inputs. They are different functions. The circuit writes it once as `AttrsHash()` and the off-chain
mirror is `gap_crypto.js`'s `h4`.

## The constraint budget is a hard ceiling, not a guideline

The trusted setup uses a **2^16** powers-of-tau: **65,536 constraints**. The session circuit measures
**59,143**. That headroom is the budget for every feature you might add to the circuit.

`MAX_CLAUSES = 6` is a *measured* limit, not a preference: eight clauses compiles to **66,715**
constraints at production depth, which busts the ceiling by 1,179. Marginals, if you are planning:
**+1,230 per clause**, **+718** for the whole attribute widening.

Exceeding it means a new ceremony, not a bigger number.

## Powers-of-tau: the digests are upstream's, the mirror is ours

Upstream's hosts, Google Storage, Hermez S3, PSE: **all return 403**. The file is mirrored as this
repository's own `ptau-hez-16` release asset, and `fetch-ptau.sh` tries that first.

Mirroring is only safe because of the digest pins, which are **iden3's published values**, not ours.
`verify_ptau` refuses the file unless both match and deletes it on mismatch, so a mirror is checked,
never trusted. **Add sources freely; do not touch the digests.**

## The demo's two environment variables are refusals, not conveniences

`make demo` sets `GAP_DEMO_ALLOW_PUBLIC_SALT=1` and `GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1`. Both exist
because the system refuses something on purpose:

- Without the first, `person.ts` refuses the published demo salt: a checked-in salt de-anonymises
  every pseudonym derived from it.
- Without the second, the Identity Keeper refuses to mint a credential unless `attrs[0..3]` come from
  a verified provider decision and `attrs[4..7]` from a signed suitability attestation. That refusal
  **is the system working**: "we KYC'd them, so they're accredited" is precisely the conflation this
  design exists to end.

If a change makes either flag unnecessary, something has probably stopped refusing. Check before
celebrating.

## The demo onboards a fixed identity

`make demo` always starts a fresh chain, which is what makes it repeatable. If you run the story
against a chain that already has it, registration stops at `DID: exists`: the registry correctly
refusing a duplicate, not a bug. `make demo-story` is the raw runner if you want it on a chain you
control.

## Privacy properties you can break without noticing

These hold because of specific decisions. A plausible-looking change can quietly undo one:

- **The DID is public; the wallet↔DID link is the claim.** The 19 public signals carry `didRoot`, the
  account and commitments: no DID. Adding one would collapse the whole claim.
- **The flagged-pseudonym set is public on purpose.** A clean holder proves NON-membership by
  bracketing their key between adjacent entries of a sorted list, so the list must be readable.
  "Encrypt it to the Monitor" removes the only way the innocent can clear themselves.
- **The blinding factor must not be persisted OFF chain**, not into a ledger row, not into an API
  response. Note the qualifier: `revokeSession` puts it in public calldata on purpose, which is a
  disclosure, not an oversight. It is bounded, `blindingR` is fresh per session and the pseudonym is
  per-contract, so one revocation reopens one commitment on one venue, but it is permanent. See
  `docs/ON_CHAIN_DISCLOSURE.md`. Do not widen it by caching the value anywhere else.
- **A session's grounds bind to that session.** Revocation requires a flagged pseudonym that reopens
  *this* session's commitment; without the binding, any flagged pseudonym would justify closing any
  account.

[`docs/ON_CHAIN_DISCLOSURE.md`](docs/ON_CHAIN_DISCLOSURE.md) is the full account of what is visible.

## The contracts cite a spec that is not in this repository

NatSpec across the v2 contracts cites `handoff/03` (and a few siblings) as the normative authority, 
"per handoff/03 §9", "P0-6", "P1-14". **Those documents live in the full stack and are not distributed
here.** There are seventeen such citations, and they are the structural weakness of this tree: a
reference implementation that defers to an undistributed spec is asking you to trust rather than
check, which is the opposite of what `make repro` is for.

Treat them as provenance: the reason a decision was made, recorded where it was made, not as
something you can look up. Everything you can actually verify is in `docs/` and in the checks. Where a
comment pointed at a document that is genuinely absent, it now says so in place rather than dangling.

One family is worth decoding rather than tolerating, because it appears about fifty times and names
properties this tree really does enforce. `GAP-H*` are hardening items from that spec:

| tag | what it names | where you can check it |
|---|---|---|
| GAP-H1 | ORDB full-key **non**-membership over an indexed Merkle tree: a low leaf brackets the pseudonym, so "not flagged" is proven rather than asserted | `IndexedNonMembership` in the circuit; `circuits/test/session-witness.test.mjs` |
| GAP-H2 | credential expiry is folded into the credential **leaf** (`0` means no expiry), so a session cannot outlive the credential behind it | `cred0ExpiresAt` / `cred1ExpiresAt` in `gap_session.circom` |
| GAP-H3 | the Transaction Monitor pre-attests: a granted session is installed **unattested** and unusable until the Monitor opens the envelope and reopens the proven commitments | `SessionManager.attestSession`; `make cli ARGS='session --grant-only'` then `make cli ARGS=attest` |
| GAP-H4 | revoking an Identity Keeper also invalidates the credentials it already issued, via the anchor's purge | `IdentityAnchor` tests |
| GAP-H5 | **still open.** The keeper reference binds the issuer of credential 0 only, not whichever credential the predicate actually selected | the note in `gap_session.circom`, kept deliberately |
| GAP-H6 | transfers are gated on **both** sides: the recipient needs its own receiving session | `TransactionFilterV2`; the demo's blocked third act |

`P1-*` and `P0-*` are numbered requirements from the same spec and have no equivalent decoding, so
they stay as provenance only.

## Where the design decisions are written down

Not in the code comments alone. [`docs/`](docs/) carries the reasoning: the attribute encoding and
what adding an index costs, why a venue may not author its own predicate, what happens when a certified
contract is upgraded, how this measures against the white paper, and what a deployer has to own.
Read the relevant one before changing behaviour it describes.
