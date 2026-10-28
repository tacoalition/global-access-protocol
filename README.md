# Global Access Protocol

A reference implementation of privacy-preserving compliance for regulated digital assets.

The protocol is published by the Digital Securities Initiative at the Tokenized Asset Coalition:
[lite paper](https://www.tacoalition.org/global-access-protocol/lite-paper) ·
[tacoalition.org](https://www.tacoalition.org). This repository implements it and measures itself
against it, section by section, in
[docs/WHITEPAPER_CONFORMANCE.md](docs/WHITEPAPER_CONFORMANCE.md).

A holder proves, in zero knowledge, that they hold a valid credential, that their per-contract
pseudonym is correctly derived, and that they are not flagged, without revealing who they are. The
transfer gate checks **both** sides. Everything here runs on a local Anvil chain.

This repository was extracted from a larger private codebase, called **the full stack** throughout the
docs. The full stack adds the authority services (Control, and the Identity Keeper, Transfer Agent and
Transaction Monitor services) and the operator consoles. Wherever a document cites a file that lives
there, it says so; [What is not here yet](#what-is-not-here-yet) lists what was held back.

> **Not audited, and not for production.** This is a reference implementation with no external
> security audit and no cryptographic review. A local build closes its proving keys with a
> *published* beacon, so proofs against it are forgeable by anyone, and the demo runs under a
> published custody salt. Read [SECURITY.md](SECURITY.md) before doing anything else with it, and
> [docs/DEPLOYMENT_RISKS.md](docs/DEPLOYMENT_RISKS.md) for what a deployer would have to own.

```bash
make demo
```

That is the whole thing: it builds the proving artifacts if they are missing, starts a fresh local
chain, deploys the stack and the permissioned pool, and runs the story. **Running it twice is the same
as running it once**: it always starts from a fresh chain, so there is no state to clean up and no
order to remember.

First run takes a few minutes, because no proving artifacts are shipped (see below) and it fetches
a 72 MB powers-of-tau file, plus circom unless 2.2.2 is already installed. After that it is quick.

Prefer to drive it yourself:

```bash
pnpm install                         # first time only
make build                           # first time only: the proving artifacts (~50s)
make up                              # fresh chain + the stack
make dex-up                          # add the permissioned AMM (for the pool act)
make cli ARGS=onboard                # 1. the sender
make cli ARGS=session                # 2. the sender's session
make cli ARGS='transfer 100'         # 3. fails, "RT: recipient not compliant", and make reports
                                     #    an error: both expected, that is the point
make cli ARGS=onboard-recipient      # 4. the recipient
make cli ARGS=receiving-session      # 5. the recipient's receiving session
make cli ARGS='transfer 100'         # 6. now it settles
make cli ARGS=pool-story             # the permissioned-AMM act
make cli ARGS=flag                   # 7. the Monitor flags the sender
make cli ARGS=status
make down                            # stop the chain
```

`make help` lists everything.

## What the demo shows

```
1.  onboard the sender                     DID registered, credential issued
2.  sender opens a session                 Groth16 proof against LIVE on-chain roots
                                           the Transaction Monitor reopens the commitments
3.  transfer 100 → BLOCKED                 the recipient has no receiving session
4.  recipient onboards
5.  recipient opens a receiving session
6.  the same transfer → SETTLES            999900 / 100
6b. the sender's SECOND wallet opens a     one person, many wallets, one DID,
    session under the same DID             one pseudonym: no second onboarding
```

Then a **permissioned AMM** over a tokenized equity (`make demo` deploys it; driving the steps
yourself, `make dex-up` does):

```
P1a. a session for the EQUITY               a third scope: the fund session does not reach it
P1b. a session for the POOL                 nor does the equity session reach the venue
P2.  seed the pool                          the pool holds the equity under a Compliant DEX
                                            Classification Credential, not a user session
P3.  an unsessioned trader swaps → REFUSED  at the pool's own filter, default-DENY
P4.  the holder swaps with no pool session   → REFUSED, then both sessions are opened
P5.  the swap SETTLES                       the POOL is the sender of a gated equity
P6.  the pool's OWN monitor flags the holder the fund sessions are untouched
6c.  a venue authors a one-person predicate → REFUSED at registration
7.   the Monitor flags the sender's pseudonym  e.g. a sanctions hit
     the Identity Keeper resolves the flagged pseudonym to a DID
8.   the sender proves again → REJECTED     no ORDB non-membership witness exists
                                            for a flagged pseudonym
     then: what the chain saw, and what it never saw
```

P5 is the point. A contract cannot hold a GAP user session: the grant path needs a spending-set
membership proof it has no DID or salt to make, so the pool holds a **Contract Session** from a
Classification Credential. Without that route no AMM of any design could settle a gated security.

P4's swap also proves a **threshold**, not an equality: evidence tier ≥ 3, and the value is never
revealed.

The closing beats are the two halves people usually ask about. The Monitor flags a pseudonym and
genuinely cannot say whose it is: it holds no salt. The **Identity Keeper** can, by recomputing
candidate pseudonyms over its own book, which is whitepaper §5.4 and the answer to "so how do you ever
catch anyone?", **when the keeper holds the salt**, which is what this demo configures. Under
client-held custody it cannot recompute anything, and the paper's route for that case (compelling the
holder to reveal their salt) is not built here; `docs/WHITEPAPER_CONFORMANCE.md` carries it as a gap.
Then the ledger, which is deliberately unflattering: it says out loud that the SET of
wallets holding a session is publicly enumerable. What GAP removes is the *link* and the *collection*,
not the gate.

Step 3 is the point. A compliant sender is not enough: the gate checks the receiving side too, so
compliance is a property of the *transfer*, not of a party.

Step 8 is the other point. The flag does not reach into the existing session: that runs to expiry.
It removes the holder's ability to prove non-membership, so no *new* session can be minted.

The commands under "Prefer to drive it yourself" run the main steps one at a time; `make cli` with no
arguments lists the rest (`session-second-wallet`, `policy-floor`, `unmask`, `disclosure`). `make down`
stops the chain.

## Requirements

| Tool | Version | Notes |
|---|---|---|
| [Foundry](https://book.getfoundry.sh/) (`anvil`, `forge`, `cast`) | 1.4.3, what CI pins | `foundryup --install v1.4.3` |
| Node | 24, what CI runs | `package.json` declares ≥ 20.9, which nothing tests |
| pnpm | 9.15.9 | pinned in `package.json`; `corepack enable` picks it up |
| git, curl, python3, jq | any recent | the spin-up uses python3, `make repro` uses jq |
| [circom](https://docs.circom.io/) | 2.2.2 | used from your PATH if it is 2.2.2, otherwise fetched and digest-checked on first build, for Linux x86_64 and macOS (Apple Silicon runs it under Rosetta). Linux aarch64 has no upstream build: install 2.2.2 yourself |

Clone with the contract dependencies, which are git submodules:

```bash
git clone --recurse-submodules https://github.com/tacoalition/global-access-protocol.git
```

`make demo` runs `pnpm install` for you when `node_modules` is missing, and on first run fetches a 72 MB
powers-of-tau file, plus circom unless 2.2.2 is already on your PATH. If you drive the steps yourself, run `pnpm install` first: the circuit
compiles against circomlib from `node_modules`.

## No proving artifacts are shipped

`make build` produces the circuit, the proving key and the Solidity verifier from the committed
circuit source. The proving key is never committed, so **what you prove with is what this repository
describes**: you are not trusting a binary somebody else made. What is committed, the verification
key, the Solidity verifier and a test proof, is checked against a fresh build rather than trusted.

A build does rewrite two tracked files: the test proof, which is fresh randomness every time, and
the digests in the artifact manifest that describe it and the compiled verifier. That is expected, not
drift; [DEVELOPMENT.md](DEVELOPMENT.md) explains both.

`make repro` is the check that makes this enforceable: it rebuilds the whole chain in a scratch tree
and fails unless the verifier matches byte for byte. `make artifact-check` alone does **not** catch a
substituted proving key, because it re-derives everything *from* that key.

> **The local setup is not a ceremony.** The phase-2 close is a deterministic beacon on a published
> constant, so it is reproducible, and its trapdoor is therefore recoverable. It is labelled
> local-development-only in the artifact manifest. Do not deploy this verifier to a public network.

## Three acknowledgements the demo makes explicit

`make demo` sets two variables, and both are refusals the system makes on purpose. The third is a key
it publishes, below them.

- **`GAP_DEMO_ALLOW_PUBLIC_SALT=1`**: the demo runs under a published demo-custody salt. A
  checked-in salt de-anonymises every pseudonym derived from it, so the code refuses it unless you
  say so. Artifacts are stamped `IK_CUSTODY_DEMO`.
- **`GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1`**: the Identity Keeper will not mint a credential unless
  `attrs[0..3]` come from a verified provider decision and `attrs[4..7]` from a signed suitability
  attestation. "We KYC'd them, so they're accredited" is exactly the conflation the design exists to
  end. With no provider and no suitability desk running, the demo acknowledges the gap rather than
  pretending the gate was satisfied.

Neither is a workaround. They are the shape of the real controls, made visible.

**The Transaction Monitor's private scalar is published** in `packages/gap-cli/src/monitor-key.ts`.
The session envelope is sealed with the real cipher, BabyJubJub ECDH into XChaCha20-Poly1305,
authenticated against the session's own context, but anyone can open it, because the key is in version
control. The mechanism is the production one; the secret is not. It used to be neither: the local
deployment published a placeholder key that nothing could encrypt to, so the envelope was cleartext and
two wallets of one holder were publicly linkable.

## Layout

```
contracts/src/v2/      SessionManager, the registries and anchors, the transfer filter,
                       the regulated token and venue, the Groth16 verifier
circuits/src/v2/       the session circuit, 59,143 constraints, 19 public signals
contracts/src/applications/dex/
                       the permissioned pool, the allowlist checker, the cash leg
docs/                  the attribute vocabulary, policy authorship, the AMM, on-chain
                       disclosure, what happens when a certified contract is upgraded, and
                       what a DEPLOYER has to own that this stack cannot do for them
packages/gap-cli/      the reference client: onboarding, proving, transfers, flags
packages/gap-sdk/      proving primitives, ABIs and types for integrators
packages/gap-identity-keeper-v2/
                       the Identity Keeper's library: credential building, provider and
                       suitability attestations, the DID derivation (not the service)
scripts/v2/            build, spin-up, artifact coherence, reproducibility
```

## What is not here yet

**One test is present but reached by no target.** `scripts/v2/verifier-binding.test.mjs` diagnoses a
*live* deployment whose verifier has drifted from the committed build: a problem the full stack has and
this repository does not, because nothing here runs a long-lived chain. `make repro` is the binding
check that matters here. It is kept as reference.

They are not the only unreached code. What remains: the well-formedness circuits and their build
script, which have their own ceremony, so `make test` reports the 11 SDK tests that need them as
skipped; several CLI modules (`sidecar.ts`, `venue.ts`, `referral.ts`,
`witness.ts`); `ORDBFactory`, which the deploy scripts bypass by constructing risk databases
directly; and `DIDSuccessionRegistry`, which **is** deployed into the demo topology and written into
the manifest, but called by nothing here.

An authority-service package of 75 source files used to sit in this list, reached by a single
`import type` that erased at runtime. It was reference material from the full stack rather than
anything this repository ran, so it is gone, and the three-value custody vocabulary that import
wanted now lives with the Identity Keeper that records it.

The pattern is worth naming rather than just fixing: code that is deployed, tested, or named after a
protocol role reads as load-bearing whether or not anything calls it.

This is the **light** stack: contracts, circuit, one client and the Identity Keeper's library. The
authority services, Control, and the Identity Keeper, Transfer Agent and Transaction Monitor
*services*, and the operator consoles that read them are not in this repository yet. `packages/gap-cli/src/identity-gate.ts` is where the client meets the
Identity Keeper: it detects an armed provider gate exactly as the service does, and REFUSES to stand
in for one.

The Uniswap v4 conformance tree is also held back. `GapAllowlistChecker` implements the interface a
v4 Permissioned Pool queries, and in the full stack an isolated `contracts-v4/` (solc 0.8.26 +
cancun) drives it from a real `PoolManager`. That is a second toolchain, so here the checker is
exercised only by its own suite: the shape is right; no conformance test in this repository proves
the integration. See [docs/PERMISSIONED_AMM.md](docs/PERMISSIONED_AMM.md).

## Working on it

[CONTRIBUTING.md](CONTRIBUTING.md) is the four commands that gate a change and why one of them is not
negotiable. [DEVELOPMENT.md](DEVELOPMENT.md) is the part that bites: the file you must never edit, the
rebuild order, the mirrors that fail silently, the constraint budget, and the privacy properties a
plausible-looking change can quietly undo.

## How this measures against the white paper

[docs/WHITEPAPER_CONFORMANCE.md](docs/WHITEPAPER_CONFORMANCE.md) walks the paper section by section
against the code. The protocol core is implemented and faithful, including the Sybil rule, the
pseudonym derivation, both session types, the filter's argument-position check, and the paper's own
closing example, a swap across three contracts each carrying its own filter, monitor and risk database.

Three divergences are deliberate and explained there. What is genuinely absent: the ZK proof does not
prove the ciphertext is well formed (a Transaction Monitor attests instead, because the constraint
budget has 1,193 spare and the proof needs ~3,000), there is no version interface for mutable
contracts, and factories, certifier delegation, portable Keeper identity and anchor forking are not
built.

## Before you deploy this anywhere real

[docs/DEPLOYMENT_RISKS.md](docs/DEPLOYMENT_RISKS.md) is the short list of things the stack cannot do
for you, each with what breaks if nobody owns it: a certification window that expires after 30 days
and needs a renewal owner, pool token assumptions that are documented and not enforced, a curator that
is a single key, an eligible-wallet set that is public permanently, and a liquidity provider who
cannot withdraw once their session lapses. None of it shows up in the demo, because the demo
redeploys everything on every run.

## Licence

Apache 2.0, © 2026 Tokenized Asset Coalition. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

**The proving stack is not Apache, and it is not a detail.** The zero-knowledge parts come from the iden3
toolchain, which is copyleft:

| Path | Origin | Licence |
|---|---|---|
| `contracts/src/v2/SessionVerifier.sol` | generated by snarkjs (© 2021 0KIMS association) | GPL-3.0-or-later |
| `contracts/bytecode/Poseidon2.bytecode` | generated by circomlibjs | GPL-3.0 |
| `circuits/src/v2/` and the verification key | includes circomlib templates (poseidon, comparators, bitify, mux, …) | GPL-3.0-or-later |
| `packages/`, `circuits/scripts/` | import circomlibjs and snarkjs at runtime | GPL-3.0 |

The verifier is reproduced verbatim and cannot be edited, `make repro` rebuilds it byte-for-byte, so an
edit is a build failure, not a patch. [NOTICE](NOTICE) has the detail. Anyone adopting this as a reference
implementation should take their own view on what these mean for their distribution before they rely on
the Apache grant covering the whole tree.
