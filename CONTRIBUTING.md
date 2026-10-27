# Contributing

## What will reject your change

Four commands, all cheap. Run them before you open a PR.

CI runs all four on every pull request and every push to `main`, in three jobs: `make repro`,
`make build && make test` (which includes `parity`), and `make demo` twice. Every job is one of these
targets, so a red job is reproduced by typing what it typed. Run them first anyway. A red terminal is a
minute; a red PR is six.

**CI blocks.** `main` takes changes only through a pull request, squash-merged, and only once the three
CI jobs, the PR-title check and the DCO sign-off check are green. There is no bypass, for maintainers
either.

```bash
pnpm install  # first time in a clone
make build    # first time, and after changing the circuit: test and parity read its output
make parity   # the cross-file invariants
make test     # the circuit, the contracts and every package, incl. a REAL proof
make repro    # the verifier rebuilds byte-for-byte from the committed circuit
make demo     # the whole story, on a fresh chain (run it twice: it must be repeatable)
```

`make repro` is the one that is not negotiable. It is the only check that catches a **substituted
proving key**, `make artifact-check` re-derives everything *from* the committed zkey, so it cannot. If
it fails, the committed verifier does not come from the committed circuit, and nothing else about the
change matters until that is true again.

[DEVELOPMENT.md](DEVELOPMENT.md) covers the traps these four commands exist to catch. The short version:
you cannot edit `SessionVerifier.sol`, circuit changes need a full rebuild in order, and the 19-slot
public-input layout is mapped **by index**: a layout that disagrees still verifies, against the wrong
binding.

## Before you add to the circuit

Check the budget. The 2^16 ceremony allows **65,536** constraints and the session circuit uses
**59,143**. Exceeding it is not a bigger number, it is a new ceremony. `MAX_CLAUSES = 6` is a measured
limit for the same reason, eight clauses compiles to 66,715 at PRODUCTION depth, which is the
binding case because that profile is what ships. At this repository's local depth eight clauses land
near 61,600, inside the ceiling, so the limit exists to stop one build being configured past what
the other can prove.

## Commit messages and PR titles

[Conventional Commits](https://www.conventionalcommits.org/), checked by
`scripts/git/check-commit-message.mjs`. Enable it locally once:

```bash
make hooks     # points core.hooksPath at .githooks
```

Git does not share hooks through a clone, so this is opt-in. CI applies the same rule to the pull
request title, and the title is what lands: squash is the only merge method, and the squash
subject is set to the PR title, never a lone commit's. So the hook is the early warning and the
title check is what guards the history. It cannot see the commits on your branch,
which is why the one command is still worth running.

```
type(optional scope)!: subject
```

Types: `feat` `fix` `docs` `test` `refactor` `perf` `build` `ci` `revert` `chore`. A wrong or
misleading **document is a `fix`**, not a `docs`, `docs` is for prose that was merely absent. `chore`
is the one that becomes a dumping ground; most commits labelled that way are really `build`, `ci`,
`refactor` or `docs`.

Scope is a directory or a package when one is obviously responsible, `circuit`, `contracts`, `cli`,
`sdk`, `ik`, `build`, and omitted when the change is genuinely cross-cutting. Do not invent a
taxonomy; the scope exists to make `git log --grep` useful, not to classify.

**The checker is deliberately permissive.** It enforces the shape and gets out of the way: beyond the
type and scope it fails only a subject under 10 characters or one ending in a full stop, and a long
subject is a warning rather than a failure. A linter that rejects a good message on a technicality just
teaches people to pass `--no-verify`.

**`make build` leaves two tracked files modified**, `contracts/test/fixtures/v2/proof.json` and the
manifest's `deployedBytecodeSha256`. That is expected; do not commit them unless your change is to the
circuit ([DEVELOPMENT.md](DEVELOPMENT.md) says why). Stage files by name rather than `git commit -a`.

`make hooks` sets `core.hooksPath` to `.githooks`, which also means git stops running anything in your
own `.git/hooks` for this clone.

### What counts as BREAKING here

Not what you would expect from a typical repository, so it is worth stating. Mark a change `!` (or add
a `BREAKING CHANGE:` footer) when it:

- **changes the 19-slot public-input layout**, consumers map signals to bindings *by index*, so a
  reorder silently binds the wrong value;
- **changes the depth tuple or `MAX_CLAUSES`**: these need a new trusted setup, so every existing
  proving key and verifier is dead;
- **changes the credential leaf or an attribute index**, existing credentials must be re-minted;
- **changes a deployed contract's ABI** in a way an integrator cannot absorb.

A new Solidity function is not breaking. A reordered public signal is, even though nothing fails to
compile, which is exactly why it needs the marker.

## Documentation claims are checked

`make parity` runs a drift check over the prose and the comments. It does not try to read your
arguments: it extracts claims that have a *syntax* and verifies them:

- a cited file path that is not in the tree
- a `make` target the Makefile does not define
- a constraint count that disagrees with `build.sh`
- "asserted by `X`" where `X` has no caller outside a test

If a citation genuinely lives in the full stack, say so, `` `foo.ts` (full stack, not in this
repository) ``, and the check accepts it.

This exists because documentation contradicting code was **half of everything five independent
reviews found here**, and the same shapes kept recurring: a number corrected in prose and not in
JSON, a claim fixed in one file and missed in its neighbour, a comment promising a check that had no
call site. A review finds an instance; only a check prevents the class.

## Explain why, not what

The diff shows what changed. What is worth writing down is the reasoning that will not survive in
anyone's head: what you tried that did not work, what the failure mode was, what you are trading away.
Several files here exist because a design decision was non-obvious enough to need an argument, and that
argument is the valuable part.

The same applies to commit messages. Conventional Commits governs the **subject line only**, it says
nothing about the body, and the body is where this repository's value is. A perfectly-formatted subject
over an empty body is a worse commit than a badly-formatted one that explains the reasoning. The
history here is written to be read.

## Claims need evidence

If a change adds a control, add the test that fails without it, then **remove the control and watch
that test fail**, so you know it is load-bearing rather than merely present. A test that passes either
way is worse than no test, because it reads as coverage.

If you cannot verify something, say so in the change rather than implying it holds. A documented gap is
a contribution; a silent one is a liability. `docs/` contains several, on purpose.

## Licensing and sign-off

This project is licensed under **Apache 2.0** (© 2026 Tokenized Asset Coalition), see [LICENSE](LICENSE)
and [NOTICE](NOTICE). Contributions are accepted under the same licence: you keep the copyright in what
you write and license it to everyone under Apache 2.0, as its section 5 says.

**Every commit must be signed off** under the [Developer Certificate of Origin](https://developercertificate.org/),
your statement that you wrote the change or otherwise have the right to submit it under this licence.
`git commit -s` adds the line, which must name the commit's author:

```
Signed-off-by: Your Name <you@example.com>
```

CI checks every commit in a PR, and `make hooks` checks each one locally. To sign off commits already on
a branch, `git rebase --signoff main` and force-push.

The exceptions to the Apache licence are the proving stack, which comes from the copyleft iden3
toolchain: `contracts/src/v2/SessionVerifier.sol` (generated by snarkjs, GPL-3.0-or-later),
`contracts/bytecode/Poseidon2.bytecode` (generated by circomlibjs, GPL-3.0), the circomlib templates the
circuits include (GPL-3.0-or-later), and circomlibjs and snarkjs, which the TypeScript packages import at runtime
(GPL-3.0). [NOTICE](NOTICE) lists them. The verifier is reproduced verbatim and cannot be edited, since
`make repro` rebuilds it byte-for-byte. Do not relicense any of them, and **do not add a new copyleft
dependency**; if you think one is unavoidable, open an issue first.

## Security

If you find something exploitable, do not open a public issue. Report it privately, as
[SECURITY.md](SECURITY.md) describes.
