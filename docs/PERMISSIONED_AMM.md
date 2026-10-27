# The permissioned AMM

What this is: a constant-product pool over a gated security where eligibility is proven in zero
knowledge instead of looked up in a register. It exists because the regulated object now has a
shape, and because GAP's own whitepaper already specified how a contract holds a security.

## Why permissioned, and not general

The SEC issued the **Innovation Exemption** on 2026-09-17 (Release 34-106402, File 4-927): two
five-year conditional exemptions, one from the definition of "exchange" for a Tokenized Securities
Venue, one from "dealer" for liquidity providers supplying Tokenized NMS Stock. The Commission's own
framing is **"permissioned trading … through automated market makers and liquidity pools"**, and a
TSV must establish standards governing access to its pools.

So a general permissionless AMM is not the thing the exemption authorizes. A permissioned,
GAP-gated pool is the regulated object, and it is the more honest thing to demonstrate. Uniswap
shipped the market standard for it on 2026-07-23, v4 Permissioned Pools, with a `PermissionsAdapter`
and a pluggable `IAllowlistChecker`, with Superstate, Securitize and Dowgo as launch partners.

## The interface is a question, not a register

`checkAllowlist(account, token) → flags` asks: may this account trade this token? Every permissioned
venue must answer it. The fight is over **how**.

| | Wallet allowlist | GAP |
|---|---|---|
| Set of eligible addresses | public or issuer-held | **public** |
| Identity behind each address | **known to the issuer** | nobody |
| KYC documents | **held by the issuer** | held once, by the IK |
| A breach exposes | the wallet↔identity map | nothing |

The naive implementation of that interface is `mapping(address => bool)`, maintained by an issuer
that collected documents and knows which human each wallet is. That register is the data haystack an
attribute-credential scheme exists to delete. `GapAllowlistChecker` answers the identical question
from `hasValidSession`: the wallet holds an unexpired, TM-attested session it obtained by proving in
zero knowledge that its attributes satisfy a published policy.

**Be precise about the claim.** GAP does not remove the permitted-wallet *set*: session grants are
public and keyed by the account, so the eligible addresses are enumerable
(`ON_CHAIN_DISCLOSURE.md`). What it removes is the *link* and the *collection*. The gate stays; the
register goes.

## How a contract holds a security

This was the blocker, and it was not a Uniswap problem. `TransactionFilterV2.check()` had a
contract-session route only for its `counterparty` argument, and `RegulatedTokenV2` passes
`address(0)` there, so **no contract could pass the sender side**, and no AMM of any design could
settle a gated security.

The whitepaper §7 states the intended behaviour outright:

> "The AMM then performs two token transfers: in each token transfer the Transaction Filter checks
> that the 'to' and 'from' addresses have the appropriate session. The user has already started their
> User Session, and **the AMM already has an active Contract Session via their 'Compliant DEX'
> Classification Credential**."

And §4.1 names the failure mode as the *reason* contract classification exists at all:

> "If this token is deposited into an ERC-20 contract or something similar, these controls no longer
> apply to the wrapper."

So the pool holds a **Contract Session from a Classification Credential**, not a user session it
could never produce: the grant path needs a spending-set membership proof, and a pool has no DID or
salt. `ClassificationContract` and `SessionManager.registerContractSession` already implemented this;
they were simply unreachable from the sender side. The sender side now tries the same two routes the
recipient side already tried, in the same order, **opt-in per selector**, `_contractCfg` is empty
until an admin calls `setContractConfig`, so nothing changes for a selector that does not configure
it. Before this work, `setContractConfig` had no caller anywhere in the tree.

## What is built

| Contract | Role |
|---|---|
| `GapCompliantDex` | constant-product pool over one gated security and one cash token |
| `GapAllowlistChecker` | the Uniswap-shaped eligibility view, backed by sessions |
| `IAllowlistChecker` / `PermissionFlags` | the interface and its `SWAP_ALLOWED` / `LIQUIDITY_ALLOWED` bits |
| `DemoCashToken` | the ungated cash leg (deliberately not the subject) |
| `DeployDexV2.s.sol` | additive deployment: reads `31337-v2.json`, writes `31337-dex.json` |

Four design decisions worth stating, because each closes a specific hole:

- **The entry points ARE the trade**, so `msg.sender` is the trader. On a shared singleton a hook
  sees the router, not the person, and `beforeSwap`'s `sender` cannot be trusted as an identity;
  passing the trader in unauthenticated hook data invites impersonation. There is no router here.
- **The DEX carries its OWN Transaction Filter and ORDB.** The whitepaper is explicit that the DEX
  needs one, because it screens market integrity, wash trading, sandwich attacks, which is a
  different job from the tokens' AML/CFT. A pool flag therefore stops new *pool* sessions and leaves
  the holder's token sessions alone. That is what per-contract pseudonyms buy.
- **LP positions are non-transferable balances, not a token.** A transferable LP receipt IS the
  unregistered wrapper §4.1 warns about: an ineligible party could buy the receipt and hold the
  security's economics without ever touching the gated token. With no wrapper, there is nothing to
  look through.
- **Swap output settles to `msg.sender`**, with no recipient argument. The token's recipient gate
  would catch a non-compliant destination anyway, but refusing to accept one removes the question
  rather than relying on a second gate to answer it.

## Running it

```bash
make up          # the token topology
make dex-up      # ADD the pool (additive; the token story runs without it)
make demo        # every act
make pool-story  # just the AMM act
```

The act, and what each beat proves:

1. **A pool session**: a second, separate scope. The holder's token session does not reach the venue.
2. **Liquidity added**: the pool receives the security under its Classification Credential.
3. **An unsessioned trader's swap is refused** at the pool's own filter (default-DENY, not default-open).
4. **A pool session alone still cannot settle.** Buying makes the holder a RECIPIENT of the security,
   and the token gates every recipient independently (GAP-H6), so a token receiving session is also
   required. Three refusals in order: no pool session, then no place to land, then settlement.
5. **The swap settles**: the pool is the sender of a gated security, which only its Contract Session
   permits.
6. **The pool's own monitor flags the holder**, and the token sessions are untouched.

The act must run BEFORE the token flag: `cmdFlag` blocks any NEW token session, and beat 4 needs one.

## Limits, stated rather than implied

What a DEPLOYER has to own, rather than what the design cannot do, is in `DEPLOYMENT_RISKS.md`.

- **The Uniswap v4 conformance tree is NOT in this repository.** In the full stack an isolated
  `contracts-v4/` (solc 0.8.26 + cancun, v4-core pinned at `v4.0.0`) deploys a real `PoolManager` and
  proves this checker gates it: six cases, each negative asserting the exact ERC-7751 envelope v4
  wraps a hook revert in, and the session lookup stubbed because `SessionManager` is pinned at solc
  0.8.20 and cannot target cancun. That is a second toolchain, so it is held back from the light
  stack. HERE, `GapAllowlistChecker` is exercised only by its own suite: the interface shape is right
  and no conformance test in THIS repository drives it. Do not claim otherwise.
- **The router-identity problem is named, not solved.** `beforeSwap`'s `sender` is the router, so
  a v4 hook must read the trader from `hookData` and trust an allowlisted router to have put it there.
  That allowlist is a trusted-computing-base decision: each router must itself bind the address it
  passes to its own caller. The isolated pool (`GapCompliantDex`) avoids the question entirely by
  being the entry point; a hook on a shared singleton cannot.
- **An LP whose session lapses cannot withdraw.** `removeLiquidity` is gated, so a provider who is
  flagged or expired cannot pull the security back out. This is the frozen-holder problem
  `RegulatedVenueV2` answers with `operatorTransfer`; this reference venue has no such escape hatch.
- **Pooling is inherently commingled.** Per-unit holder compliance cannot be tracked inside a shared
  reserve. Safety rests on the pool being a lawful holder of record and the claim on it being
  non-transferable, which is an omnibus account with a restricted participation list, a structure
  securities law has run for decades.
- **No price oracle, no flash accounting, no multi-hop routing.** Reserves are tracked internally, so
  a direct transfer into the contract is ignored rather than counted. This is a reference venue for
  demonstrating compliant settlement, not a production exchange.
