#!/usr/bin/env bash
#
# THE DEVELOPMENT BUILD'S CLOSING VALUE — deterministic on purpose, and worthless on purpose.
#
# WHY NOT `zkey contribute`. Measured on this repo: `groth16 setup` is byte-deterministic, and
# `zkey beacon` with a fixed hex is byte-deterministic, but `zkey contribute` is NOT — it reseeds
# from OS entropy even when fed a fixed seed on stdin. Two runs of the same script over the same
# source produced two different zkeys, so `SessionVerifier.sol` could not be regenerated from the
# committed circuit by anyone: not CI, not a second engineer, not an auditor. That is the entire
# reason the "circuit -> setup -> verifier -> contracts -> fixtures, one build" rule was an
# honour system rather than a gate.
#
# WHAT THIS VALUE IS NOT. It is a published constant in a public repository. A development key
# closed on it is exactly as forgeable as one closed on a typed passphrase — anyone can reproduce
# the setup and recover the trapdoor. That is fine and intended: these are DEVELOPMENT artifacts,
# they are marked as such in the generated verifier, and the production path is
# `scripts/v2/wf-ceremony.sh`, which takes real contributions and closes on real public
# randomness. Reproducibility is the goal here; soundness is the ceremony's job.
#
# NEVER use this in the ceremony path. `wf-ceremony.sh` deliberately does not source this file.
# The value is not arbitrary and not cherry-picked: it is
#   sha256("gap-v2 development build — NOT a ceremony")   (UTF-8, no trailing newline)
# so any reader can recompute it and confirm nobody chose a hex string for its effect on the
# resulting key. `scripts/v2/setup-determinism.test.mjs` recomputes it on every run.
DEV_BEACON_HEX="cdcbd5a596e1808885ad7531e146b402ff5073ce24ccc4c6a93457fa7a4a84db"
DEV_BEACON_ITERATIONS=10
DEV_BEACON_NAME="development build — deterministic, NOT a ceremony"
