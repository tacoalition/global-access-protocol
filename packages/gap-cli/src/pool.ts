// Permissioned-AMM flows (GapCompliantDex). The pool is a SEPARATE gating scope from the token:
// GAP whitepaper §7 has a swap needing a session per contract, each with its own Transaction
// Filter, Monitor and Onchain Risk Database, because the AMM screens for market integrity while the
// token screens for AML/CFT. So a holder's token session does NOT admit them to the pool: they
// prove a second session scoped to the DEX, which is what makes the pseudonyms per-contract.
import {
  abis, contracts, publicClient, requireDexDeployment, wallet, toHex32,
  DemoIdentity, DEPLOYER_PK,
} from "./state";
import { pseudonymFor } from "./prover";
import { cmdSession, SessionTarget } from "./cli";
import { txWait } from "./tx";
import { getContract } from "viem";

/**
 * MUST equal the clause array in contracts/script/v2/DeployDexV2.s.sol `_wire`, in order: the
 * circuit recomputes clausesHash from these private witnesses and the Session Manager pins the
 * on-chain value, so a divergence fails in-circuit with no useful diagnostic.
 */
export const DEX_CLAUSES = [
  { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },    // not sanctioned
  { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n },  // residency == US
  // op 6 = GTE. A THRESHOLD, not an equality: evidence tier 3 or better, value never revealed.
  { enabled: 1, groupId: 0, attrIndex: 6, op: 6, value: 3n },
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
  { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
];

export function dexTarget(): SessionTarget {
  const dx = requireDexDeployment();
  return { gatedContract: dx.gapCompliantDex, ordbAddress: dx.dexOrdb, clauses: DEX_CLAUSES };
}

/**
 * The EQUITY's own scope. The pool trades a tokenized listed equity, not the fund token, and that
 * equity carries its own TransactionFilter, so holding the fund admits nobody here. This is what
 * per-security scope means in practice: a third name for the same person.
 */
export function equityTarget(): SessionTarget {
  const dx = requireDexDeployment();
  return { gatedContract: dx.security, ordbAddress: dx.equityOrdb, clauses: DEX_CLAUSES };
}

/** Open + TM-attest the equity holder session (one policy serves both directions). */
export async function equitySession(id: DemoIdentity, step: string) {
  const dx = requireDexDeployment();
  await cmdSession(id, dx.dexEquityPolicy, step, "equity holder session", equityTarget());
}

function dexContracts() {
  const dx = requireDexDeployment();
  const pc = publicClient();
  return {
    dx,
    dex: getContract({ address: dx.gapCompliantDex as `0x${string}`, abi: abis.dex, client: pc }),
    cash: getContract({ address: dx.cashToken as `0x${string}`, abi: abis.cash, client: pc }),
    checker: getContract({ address: dx.gapAllowlistChecker as `0x${string}`, abi: abis.checker, client: pc }),
  };
}

/** Open + TM-attest a DEX-scoped session. `kind` picks the swap or the liquidity policy. */
export async function poolSession(id: DemoIdentity, kind: "swap" | "liquidity", step: string) {
  const dx = requireDexDeployment();
  const policyId = kind === "swap" ? dx.dexSwapPolicy : dx.dexLiquidityPolicy;
  await cmdSession(id, policyId, step, `pool ${kind} session`, dexTarget());
}

/** Operator funds the cash leg and the holder approves the pool for both tokens. */
export async function poolFund(id: DemoIdentity, cashAmount: bigint) {
  const { d } = contracts();
  const { dx } = dexContracts();
  const op = wallet(DEPLOYER_PK);
  await txWait(await op.writeContract({
    address: dx.cashToken as `0x${string}`, abi: abis.cash, functionName: "mint",
    args: [id.address, cashAmount],
  }));
  const holder = wallet(id.pk);
  await txWait(await holder.writeContract({
    address: dx.cashToken as `0x${string}`, abi: abis.cash, functionName: "approve",
    args: [dx.gapCompliantDex as `0x${string}`, cashAmount],
  }));
  // The EQUITY is what the pool trades, not the fund token.
  await txWait(await holder.writeContract({
    address: dx.security as `0x${string}`, abi: abis.token, functionName: "approve",
    args: [dx.gapCompliantDex as `0x${string}`, (1n << 255n)],
  }));
}

export async function poolAddLiquidity(id: DemoIdentity, securityIn: bigint, cashIn: bigint) {
  const { dx, dex } = dexContracts();
  if (!(await dex.read.mayProvideLiquidity([id.address]))) {
    return { outcome: "blocked" as const, reason: "no liquidity session for this pool" };
  }
  const holder = wallet(id.pk);
  const r = await txWait(await holder.writeContract({
    address: dx.gapCompliantDex as `0x${string}`, abi: abis.dex, functionName: "addLiquidity",
    args: [securityIn, cashIn],
  }));
  return { outcome: "added" as const, gasUsed: r.gasUsed, shares: await dex.read.shares([id.address]) };
}

/**
 * @param securityIn true sells the security for cash, false buys it. Buying is the interesting
 *   direction: the POOL becomes the sender of a gated security, which only its Contract Session
 *   permits.
 */
export async function poolSwap(id: DemoIdentity, securityIn: boolean, amountIn: bigint) {
  const { dx, dex } = dexContracts();
  if (!(await dex.read.maySwap([id.address]))) {
    return { outcome: "blocked" as const, reason: "no swap session for this pool" };
  }
  const expected = await dex.read.quote([securityIn, amountIn]);
  const holder = wallet(id.pk);
  const r = await txWait(await holder.writeContract({
    address: dx.gapCompliantDex as `0x${string}`, abi: abis.dex, functionName: "swap",
    args: [securityIn, amountIn, 0n],
  }));
  return { outcome: "swapped" as const, gasUsed: r.gasUsed, amountOut: expected };
}

export async function poolStatus(id: DemoIdentity) {
  const { dex, cash, checker, dx } = dexContracts();
  const token = getContract({ address: dx.security as `0x${string}`, abi: abis.token, client: publicClient() });
  const [sec, csh, shares, flags, holderCash, holderSec] = await Promise.all([
    dex.read.securityReserve(), dex.read.cashReserve(), dex.read.shares([id.address]),
    checker.read.checkAllowlist([id.address, dx.security as `0x${string}`]),
    cash.read.balanceOf([id.address]), token.read.balanceOf([id.address]),
  ]);
  return { securityReserve: sec, cashReserve: csh, shares, checkerFlags: Number(flags), holderCash, holderSec };
}

/**
 * The DEX's OWN Transaction Monitor flags the holder's POOL pseudonym. Independent of the token's
 * ORDB by construction: the pseudonym is scoped to the DEX, so flagging here stops new POOL sessions
 * and leaves the holder's token sessions entirely alone. That separation is what per-contract
 * pseudonyms buy, and this makes it visible rather than asserted.
 */
export async function poolFlag(id: DemoIdentity) {
  const dx = requireDexDeployment();
  const { d } = contracts();
  const pseud = await pseudonymFor(BigInt(d.idRegime), BigInt(dx.gapCompliantDex), id);
  const tm = wallet(DEPLOYER_PK);
  const FLAG_MARKET_ABUSE = 1n << 4n;
  await txWait(await tm.writeContract({
    address: dx.dexOrdb as `0x${string}`, abi: abis.ordb, functionName: "flagPseudonym",
    args: [toHex32(pseud), FLAG_MARKET_ABUSE],
  }));
  return pseud;
}
