# Security

## Status: not audited, not for production

This is a **reference implementation**. It has had no external security audit, no cryptographic
review, and no formal verification. It exists to show how a compliance protocol can be built so
that eligibility is proven rather than listed, and to let a reader check that claim against running
code.

Do not deploy it to a public network or put real assets behind it. Several specific reasons, each
written up rather than summarised:

- the proving keys in a local build are closed with a **published** beacon, so anyone can forge a
  proof against them (`setupClosure` in `circuits/keys/v2/local-artifact-manifest.json`, and the
  NatSpec on `contracts/src/v2/SessionVerifier.sol`)
- the demo runs under a **published** custody salt and an acknowledged local-fixture escape hatch,
  both of which exist so the refusals they bypass stay visible
- `docs/DEPLOYMENT_RISKS.md` lists what a deployer would have to own, with what breaks if nobody
  does: a 30-day certification window with no renewal owner, a single-key curator, a permanently
  public eligible set, and more
- the README names what is deployed or tested here but reached by no production composition, so a
  demo should not be read as promising it

## Reporting a vulnerability

Please report privately rather than opening a public issue.

Use GitHub's [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security → Report a vulnerability). That routes to the maintainers without
disclosing the issue first.

Please include what you need to make the finding checkable: the commit, the command you ran, and
what you expected instead. A proof-of-concept against a local chain is ideal, since everything here
runs on Anvil.

There is no bug bounty, and no service-level commitment on response times. This is a reference
implementation maintained alongside other work; expect a considered reply rather than a fast one.

## What is in scope

A defect in this repository's circuits, contracts, SDK or scripts, in particular anything that
would let a holder prove a statement that is not true, link a pseudonym to a wallet without the
keys the design says that requires, or bypass a gate the documentation claims is enforced.

Out of scope: the deliberate local-development weaknesses listed above, which are documented rather
than hidden, and anything in the undistributed full stack this tree was extracted from.
