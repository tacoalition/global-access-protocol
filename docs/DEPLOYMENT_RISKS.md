# What a deployer has to own

Not a list of weaknesses: a list of things this stack cannot do for you, each with what breaks if
nobody owns it. Several are stated in the design docs; what was missing is the owner and the
consequence, which is the part that gets forgotten between a demo and a deployment.

The demo redeploys everything on every run, so none of these is visible there. That is exactly why
they are written down.

## 0. The demo setup is forgeable. Replace all of it.

What `make up` deploys is a demonstration, and three parts of it are broken on purpose so that it
runs anywhere with no secrets:

- **The verifier accepts forged proofs.** `SessionVerifier` comes from a setup closed on a beacon
  published in this repository (`LOCAL_DEVELOPMENT_ARTIFACT`, and `setupClosure` in the artifact
  manifest), so anyone can recover the trapdoor and prove anything.
- **The monitor's private key is published.** `DEMO_MONITOR_PK_X/Y` in `DeployV2` mirror
  `packages/gap-cli/src/monitor-key.ts`, so every session envelope can be opened by anyone, and every
  pseudonym linked to its wallet.
- **The deployer holds every role**: ITA and CTA admin, IK and CC control, Transaction Monitor,
  governance and curator. The two-party controls in 3 and 3b are one party here.

`DeployV2` and `DeployDexV2` refuse any chain but a local Anvil (31337) for exactly this reason.

**Owner:** whoever deploys anywhere else. That means a real ceremony for the proving key, a monitor key
generated and held by the monitor, and every role assigned to a distinct holder. **If nobody owns it:**
a "testnet" deployment of the demo is a system anyone can mint sessions on and deanonymise.

## 1. The certification window expires. Someone must renew it.

`ContractRequirement.maxAge` is **30 days** in `DeployDexV2`. After that the pool's Classification
Credential is stale and the pool stops being a lawful holder: swaps and liquidity both revert with
`RT: sender not compliant` or `RT: recipient not compliant`.

That is deliberate. An unbounded certification was the real defect, because the chain cannot detect
that a certified contract was upgraded, see `CONTRACT_UPGRADES.md`. A bounded window IS the control.

**Owner:** whoever runs the Contract Trust Anchor. Renewal is `revokeClassification` on the old index,
then `addClassification` again (a new index) followed by `registerContractSession`. Each CTA has its own
list of at most 16 Contract Sessions per target, and a full list drops its revoked entries on the next
registration, so renewals do not run out. **If nobody owns it:** the venue silently stops trading on day
31, and the failure looks like a compliance bug rather than an expired certificate.

**Pick the number deliberately.** Shorter means less exposure to an undetected upgrade and more
operational load. 30 days is a demo-scale default, not a recommendation.

## 2. The pool's token assumptions are not enforced

`GapCompliantDex` tracks reserves internally and must be paired with plain ERC-20s on both legs: no
transfer callbacks, no fee on transfer, no rebasing.

`nonReentrant` covers the callback case. **Nothing covers fee-on-transfer or rebasing**: the contract
credits `amountIn` to its reserves while receiving less than that, so the internal accounting drifts
from the real balances and every subsequent price is wrong. The constructor accepts any two addresses
and cannot tell.

**Owner:** whoever deploys a pool. **If nobody owns it:** losses accrue quietly through mispricing
rather than through a revert, which is the worst shape of failure to notice.

## 3. The curator is one key

`UserPolicyRegistry.curator` approves the predicates a venue may carry: the control that stops a
venue authoring a rule narrow enough to identify its holders (`POLICY_AUTHORSHIP.md`). In the local
deploy that is the deployer's key, with no timelock and no multi-party step.

A captured curator can approve a one-person predicate. The floor is then no floor.

**Owner:** governance. **If nobody owns it:** the strongest privacy claim in the system rests on a
single hot key. A production deployment wants a timelock and a published approval trail: the events
are already emitted (`PredicateApproved` carries the clauses in the clear), so the audit surface
exists; the delay does not.

## 3b. A lost monitor key makes flags permanent

Clearing a flag is a two-party act: the Transaction Monitor raises the appeal (`proposeUnflag`,
`onlyTM`) and governance acts on it (`unflagPseudonym`, `onlyGovernance`, which now consumes a matching
proposal). Neither role can do both: that is the point, because a role that can raise and clear can be
leaned on to quietly undo a flag, and the flag set is the only public record of monitoring activity
there is.

The cost: **a monitor whose key is lost can no longer raise appeals, and governance cannot clear a flag
without one.** Every false positive under that monitor becomes permanent until the key is replaced.

**Owner:** whoever holds the monitor key. `rotateMonitorKey` exists and is the remedy. **If nobody owns
it:** a holder flagged in error has no route back, and the system has no way to say so, the appeal
cannot even be recorded.

## 3c. The trees have ceilings, and one of them is small

Hard protocol limits, set by the depth tuple in `gap-sdk/src/metadata.ts` and matched by the deploy:

| | depth | capacity |
|---|---|---|
| DIDs | 16 | 65,536 |
| Credentials, per regime per anchor | 16 | 65,536 |
| Concurrently flagged keys per ORDB | 14 | 16,384 |
| **Wallets per DID** | **4** | **16** |

The last one is the one to notice. The demo's step 6b is "one person, many wallets, one DID", and
*many* stops at sixteen. Nothing in the tour says so.

Raising any of them is a circuit parameter change: a new trusted setup, not a bigger number, so these
are decisions to make before a deployment rather than after.

**Owner:** whoever sizes the deployment. **If nobody owns it:** the ceiling is discovered by the
holder who hits it, and for the wallet set that could be an ordinary user with a hardware wallet, a hot
wallet and a few per-venue addresses.

## 4. The set of eligible wallets is public, permanently

`SessionGranted` is public and keyed by the account, so anyone can enumerate which addresses may
trade a given security. GAP hides the LINK between wallet and person and removes the COLLECTION of
documents. It does not hide eligibility. See `ON_CHAIN_DISCLOSURE.md`.

**Owner:** whoever writes the marketing. **If nobody owns it:** someone claims "fully private", a
reader greps the event logs in five minutes, and every other claim in the system loses its
credibility along with that one. The demo's closing ledger says this out loud for precisely this
reason.

## 5. A liquidity provider whose session lapses cannot withdraw

`removeLiquidity` is gated like everything else, so a provider who is flagged or whose session expires
cannot pull their position. `RegulatedVenueV2` answers this with `operatorTransfer` to a compliance
escrow; this reference pool has no such escape hatch.

**Owner:** whoever designs the venue. **If nobody owns it:** an honest provider whose credential
lapses is indistinguishable from a sanctioned one, and their funds are stuck until they re-session.

## 6. Know which claims are tested and which are shaped

`GapAllowlistChecker` implements the interface a Uniswap v4 Permissioned Pool queries. **In THIS
repository nothing drives it from a real `PoolManager`**: the conformance tree needs solc 0.8.26 and
cancun, a second toolchain held back from the light stack, so the checker is exercised only by its own
suite.

So: the interface SHAPE is right and no conformance test here proves the integration. See
`PERMISSIONED_AMM.md`, and read it before anyone says "GAP is integrated with Uniswap".

## 7. A proof is valid only against the current DID root

`SessionManager` requires a proof's DID root to be `DIDRegistryV2.root()` **exactly**, with no
history of recent roots. Every DID registration, and every `updateSpendingKeyRoot`, moves the root,
so a proof built before any of them fails with `SM: stale DID root` and has to be rebuilt.

On the demo chain nothing else is registering, so this never shows. On a shared chain ordinary
registration traffic will fail some grants, and registration is permissionless (the deploy sets
`registrationFee` to 0), so anyone can do it on purpose: watch for a pending `grantSession` and land a registration first.

It is not fixed here because the obvious fix has a cost. Accepting a short history of roots, as
Tornado Cash and Semaphore do, is safe when leaves never change, and a DID leaf does: it folds in the
spending-key root, which is how a lost or compromised wallet is removed from a DID. Accepting an
older root would let a removed wallet keep proving for as long as that root stays acceptable.

**Owner:** whoever deploys onto a shared chain. The options are a bounded root history (by time, not
by count, so a quiet period cannot stretch it) with the wallet-removal window stated as a property,
a nonzero `registrationFee` (already supported) or a rate limit, or both. **If nobody owns it:** grants fail intermittently under
load, and a griefer can deny sessions to a chosen holder at the cost of gas.
