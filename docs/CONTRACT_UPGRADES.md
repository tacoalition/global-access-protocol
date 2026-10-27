# A certified contract that gets upgraded

The honest version of a problem the protocol cannot solve, the controls that do exist, and the exact
shape of what remains uncovered. Read this before certifying anything upgradeable.

## The problem

A Contract Session lets a contract hold a gated security. `GapCompliantDex` has one; without it no AMM
could settle a security at all, because a contract cannot produce the spending-set membership proof a
user session needs.

The session is backed by a Classification Credential: an audit firm's statement that this contract is
safe to hold the asset. `ClassificationContract` captures the target's `EXTCODEHASH` at certification
and a venue can require it still match (`requireCodeMatch`).

**That does not catch an upgrade.** `EXTCODEHASH` is the bytecode *at the target's own address*. For a
proxy, that bytecode is the proxy, and it does not change when the implementation behind it does. So
a pool could be certified, hold the security, then have its logic replaced with something that drains
it, and still present a valid Contract Session.

## Why the chain cannot fix this

Three fixes suggest themselves. None works.

**Refuse to certify proxies.** You cannot reliably detect one. EIP-1967 is a convention; a bespoke
proxy puts its pointer wherever it likes. A check would be a speed bump, not a guarantee, and a
guarantee is what the word "certified" implies.

**Read the implementation slot.** You can't. `SLOAD` operates on the storage of the *executing*
contract. There is no EVM opcode to read another account's storage, so this contract cannot inspect a
proxy's pointer. It can only call something the proxy exposes, and a malicious proxy returns whatever
it likes.

**The version interface.** The whitepaper describes letting mutable contracts report a version, with
the Contract Session pinned to it (§4.3). That works against an *honest* upgrade: a developer who
bumps the version invalidates the session, as intended. It does nothing against a developer who
upgrades and does not bump, because the version is self-reported like everything else.

So: no on-chain mechanism prevents a malicious upgrade of a certified contract. Anything claiming
otherwise is mistaken about what `EXTCODEHASH` covers.

## The controls that do exist

**The certifier asserts it, on-chain.** `addClassification` takes `codeIsImmutable`: the certifier's
statement that the target has no upgrade path: no proxy, no delegatecall to mutable code, no
selfdestruct-and-recreate. It is an assertion, not a measurement, and it is recorded so it can be
pointed at afterwards. This is the ordinary GAP pattern: an authority states something, the chain binds
it, and the authority is accountable for it.

**A venue demands it.** `ContractRequirement.requireImmutableCode` refuses a classification whose
certifier would not make that assertion. A venue admitting a contract as a lawful holder of a security
should set it. `test_AVenueMayRefuseAContractTheCertifierWillNotCallImmutable` is that control, and the
test fails if the check is removed.

**`maxAge` bounds every assertion.** A certification that never expires is the only thing between a
venue and a contract upgraded after certification, and since the chain cannot see that upgrade, a
bounded re-certification window *is* the control. `DeployDexV2` sets **30 days**. It was previously 0,
meaning never, which was the real defect: not that the mechanism was weak, but that nothing bounded it.

**`revokeClassification`** is the response once an upgrade is noticed off-chain. Immediate, and it
invalidates every session resting on that classification.

## What is still uncovered, precisely

A contract whose certifier **falsely** asserts immutability, inside the `maxAge` window, before anyone
notices. The exposure is bounded by `maxAge` and ended by revocation, and the recourse is against the
certifier, who made a recorded false statement. That is a liability model, not a cryptographic one, and
it is worth being clear that the two are different.

If you are deploying this: set a finite `maxAge`, set `requireImmutableCode`, and prefer certifying
contracts that genuinely cannot be upgraded, for which `certifiedCodeHash` is a complete behavioural
commitment and none of the above is load-bearing.
