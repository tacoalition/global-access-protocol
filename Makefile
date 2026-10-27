# Global Access Protocol, local reference implementation.
#
# Everything here runs against a local Anvil chain. Nothing reaches a public network, and no
# proving artifacts are shipped: `make build` produces them from the committed circuit, so what you
# prove with is what this repository describes.
.DEFAULT_GOAL := help
.PHONY: help build up dex-up demo demo-story parity hooks pool-story disclosure policy-floor cli test typecheck artifact-check artifact-test circuit-test proof-selftest repro down

help: ## Show this help
	@printf "\n\033[1mGlobal Access Protocol\033[0m, local reference implementation\n\n"
	@printf "  \033[1mmake demo\033[0m   ★ start here. Everything, from a cold clone. Repeatable.\n\n"
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'
	@printf "\n"

build: ## Compile the circuit, run the local setup, emit the verifier, build the contracts
	@bash scripts/v2/build.sh

up: ## Fresh local chain + deploy the whole stack
	@bash scripts/v2/spinup.sh

# TWO ACKNOWLEDGEMENTS, BOTH DELIBERATE, BOTH LOCAL-ONLY.
#
# GAP_DEMO_ALLOW_PUBLIC_SALT=1: the demo runs under the published demo-custody salt. person.ts
# refuses it otherwise, because a checked-in salt de-anonymises every pseudonym derived from it.
# Artifacts are stamped IK_CUSTODY_DEMO so the custody story stays visible.
#
# GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1: the Identity Keeper refuses to mint a credential unless
# attrs[0..3] come from a verified provider decision and attrs[4..7] from a signed suitability
# attestation. That refusal is the system working: "we KYC'd them, so they're accredited" is the
# conflation the design exists to end. With no provider and no suitability desk running, the demo
# acknowledges it explicitly rather than pretending the gate was satisfied.
DEMO_ENV = GAP_DEMO_ALLOW_PUBLIC_SALT=1 GAP_ALLOW_INSECURE_LOCAL_FIXTURES=1

# THE GOLDEN PATH, and the only command a reader needs. It builds the proving artifacts if they are
# missing, starts a FRESH chain, deploys the stack and the pool, and runs the story, so running it
# twice is the same as running it once. `demo-story` is the raw runner for an existing chain.
demo: ## ★ START HERE: everything, from a cold clone to the whole story. Repeatable.
	@bash scripts/v2/golden-path.sh

demo-story: ## Just the story, against a chain that is already up
	@cd packages/gap-cli && $(DEMO_ENV) npx tsx src/cli.ts demo

# ADDITIVE: the permissioned AMM. Kept separate because the token story does not need it, the DEX
# introduces its own filter, ORDB and policies, and a reader should be able to see exactly which
# contracts the pool adds. Run after `make up`.
dex-up: ## Add the permissioned AMM (a tokenized equity, a pool, and the allowlist checker)
	@set -a; . ./.env.anvil; set +a; \
		export USER_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8; \
		. scripts/v2/lib/broadcast.sh; \
		broadcast deploy-dex script/v2/DeployDexV2.s.sol:DeployDexV2 --rpc-url "$$RPC_URL" \
		&& echo "✅ permissioned pool live → contracts/deployments/31337-dex.json"

pool-story: ## Just the permissioned-AMM act (needs make dex-up)
	@cd packages/gap-cli && $(DEMO_ENV) npx tsx src/cli.ts pool-story

disclosure: ## What the chain saw about the holder, and what it never saw
	@cd packages/gap-cli && $(DEMO_ENV) npx tsx src/cli.ts disclosure

policy-floor: ## Watch a one-person predicate be refused at registration
	@cd packages/gap-cli && $(DEMO_ENV) npx tsx src/cli.ts policy-floor

cli: ## Run one command, e.g. make cli ARGS='transfer 100'
	@cd packages/gap-cli && $(DEMO_ENV) npx tsx src/cli.ts $(ARGS)

test: typecheck artifact-test parity circuit-test artifact-check ## Everything: types, parity, artifacts, the circuit, contracts, and every package
	@cd contracts && forge test --match-path 'test/v2/*' -vv
	@# 324 passing tests in four packages used to be run by no documented command, which is how they
	@# rot. A review counted them; the honest fix is to gate them rather than to footnote them.
	@pnpm -r --no-bail test

# tsx runs TypeScript without checking it, so every package suite can pass over a type error. A
# package once imported viem without declaring it and had never typechecked in a clean install.
typecheck: ## Typecheck every package
	@pnpm -r --filter './packages/*' exec tsc --noEmit -p tsconfig.json

# THE CIRCUIT ITSELF, which until this target was tested by nothing. Every Foundry suite injects a
# MockVerifier that returns true, so they describe what the SessionManager does with an accepted
# proof and say nothing about what the circuit accepts. Needs `make build` first: the witness
# calculator lives under the gitignored circuits/build, and the suite FAILS rather than skips when
# it is absent, because a skipped circuit suite is indistinguishable from a passing one.
circuit-test: ## Assert what the session circuit refuses to prove (needs make build)
	@node --test circuits/test/session-witness.test.mjs

artifact-check: ## Fail unless the proving and verifier artifacts form one coherent bundle
	@node scripts/v2/check-artifacts.mjs

artifact-test: ## Regression tests for artifact mismatch detection, setup determinism and the ptau pin
	@# Three of these were run by no target until a review counted them. The comment below has argued
	@# since it was written that tests nothing runs will rot; these are the ones it was missing.
	@node --test scripts/v2/check-artifacts.test.mjs scripts/v2/setup-determinism.test.mjs \
		scripts/v2/ptau-integrity.test.mjs scripts/v2/anvil-lifecycle.test.mjs \
		scripts/v2/wf-ceremony-transcript.test.mjs

# The numbers that have to agree across files which cannot see each other: the 19-slot public-input
# layout, the depth tuple, MAX_CLAUSES, the attribute width. Every one fails silently and late when it
# drifts, so this asserts them the way a human would and reliably forgets to.
parity: ## Assert the cross-file invariants and that the docs still match the code
	@npx tsx --test scripts/v2/invariant-parity.test.mjs
	@# Documentation that contradicts the code was half of everything five reviews found. These are
	@# the four shapes those findings took, each reduced to something a machine decides.
	@node --test scripts/v2/doc-drift.test.mjs
	@# 51 ABI entries in the CLI are written by hand, so the compiler never checks them against the
	@# Solidity. One had already drifted and decoded a truncated struct in silence.
	@npx tsx --test scripts/v2/abi-parity.test.mjs

hooks: ## Enable the commit-message check locally (git does not share hooks through a clone)
	@git config core.hooksPath .githooks
	@echo "✅ commit-msg hook enabled: Conventional Commits and the DCO sign-off are checked locally."

# artifact-check re-derives the verifier FROM the committed zkey, so a wholesale zkey substitution
# passes it. This rebuilds the chain from the committed circuit in a scratch tree instead.
repro: ## Fail unless the verifier rebuilds byte-for-byte from the committed circuit
	@bash scripts/v2/repro-check.sh

# Into circuits/build/, NOT the committed fixtures: a Groth16 proof is randomised, so a fresh one
# no longer matches the manifest's proofFixtureSha256, and writing it over the fixture broke every
# later `make up` and `make demo` until a full `make build`.
proof-selftest: ## Regenerate a proof with your local zkey and verify it off-chain
	@cd circuits && node scripts/v2/prove_session.js selftest build/selftest

down: ## Stop only the Anvil this repo started
	@bash scripts/v2/anvil-stop.sh
