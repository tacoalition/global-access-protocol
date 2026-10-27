pragma circom 2.0.0;

// GAP v2 local-development wrapper. The statement lives in lib/gap_session.circom so the
// production-depth Base demo cannot silently overwrite this verifier or its artifacts.
include "./lib/gap_session.circom";

component main {public [
    account, chainId, sessionManager, clausesHash, validUntil, accountNonce,
    didRoot,
    ita0, regimeHash0, credRoot0,
    ita1, regimeHash1, credRoot1,
    ordbId, riskRoot, gatedContract,
    pseudonymCommitment, ikRefCommitment, monitorKeyId
]} = GapSession(16, 4, 16, 14, 6);

