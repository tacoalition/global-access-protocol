// Shared state, clients, ABIs, and the demo identity for the GAP v2 CLI.
import * as fs from "fs";
import * as path from "path";
import { createPublicClient, createWalletClient, http, getContract } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { derivePersonIdentity, runScopedAccountLinkId } from "./person";

export const ROOT = path.resolve(__dirname, "../../..");
export const RPC = process.env.RPC_URL || "http://127.0.0.1:8545";
export const CHAIN_ID = 31337;
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Depths, MUST match circuits/src/v2/session.circom and DeployV2.s.sol.
export const DID_DEPTH = 16, SK_DEPTH = 4, CRED_DEPTH = 16, RDB_DEPTH = 14;
export const CRED_TAG = 7398619034839472060957547841361825911550539606183619483712186628328937676175n; // keccak("GAP_ATTR_CRED_V3") mod P

// Anvil default accounts.
export const DEPLOYER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const USER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // acct1
export const USER_PK_B = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"; // acct3
export const RECIPIENT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"; // acct2
export const RECIPIENT_PK = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"; // acct2

// GOVERNANCE KEYS, DELIBERATELY OUTSIDE EVERY SPENDING SET.
//
// The DID registry stores governance keys in the clear and `registerDID` requires the caller to be
// one of them. Registering from a spending wallet therefore publishes `DID -> that wallet` to anyone
// with no keys at all, which is the exact link the demo's closing panel calls "the privacy claim,
// and it is not on chain". A reviewer read it straight off the chain with one `cast call`.
//
// So the DID is registered from a key that holds nothing and transacts nowhere. It is the
// identity-control key the white paper §3.2 describes; the spending wallets stay unlinked, which is
// what makes the paper's address-rotation property true rather than aspirational.
export const USER_GOV_PK = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"; // acct4
export const USER_GOV = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65" as const;              // acct4
export const RECEIVER_GOV_PK = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"; // acct5
export const RECEIVER_GOV = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc" as const;           // acct5

/** One wallet a person owns. Many of these map to ONE DemoIdentity. */
export interface DemoWallet {
  address: `0x${string}`;
  pk: string;
}

/**
 * A demo PERSON, acting from one of their wallets.
 *
 * `did`/`privateSalt`/`accounts` are properties of the person; `address`/`pk` are
 * the wallet this value is currently acting from. `walletOf()` produces the same
 * person acting from a different one of their own wallets, same DID, same salt,
 * same pseudonym, same credential.
 */
export interface DemoIdentity {
  label: string;
  /** The onboarding platform's customer-link id. The ONLY per-person input to the DID and salt derivations. */
  accountLinkId: string;
  did: bigint;
  privateSalt: bigint;
  /** Every wallet this person owns: the spending wallet set the DID document pins. */
  accounts: DemoWallet[];
  /**
   * The key that registers and controls the DID. NOT a member of `accounts`: a governance key is
   * public in the registry, so using a spending wallet here would publish the wallet↔DID link.
   */
  governance: DemoWallet;
  address: `0x${string}`;
  pk: string;
}

// Base account links for the two demo people. A run scope (GAP_DEMO_RUN_ID) maps each
// onto its own person so a PERSISTENT deployment can host the lane repeatedly: the DID
// is a function of the link, and both the DID registry and the credential issuers refuse
// a second write for a DID that already exists.
const SENDER_LINK = runScopedAccountLinkId(
  process.env.GAP_DEMO_SENDER_ACCOUNT_LINK_ID ?? "8f1d6c2a-1b3e-4a7c-9d21-5c0e2f7a41b8",
  process.env.GAP_DEMO_RUN_ID,
);
const RECIPIENT_LINK = runScopedAccountLinkId(
  process.env.GAP_DEMO_RECIPIENT_ACCOUNT_LINK_ID ?? "2c9a4e70-63d5-4f18-8b6a-77e1c3d0951f",
  process.env.GAP_DEMO_RUN_ID,
);

// did/privateSalt are DERIVED PER PERSON from the account link (see person.ts), never from
// the transacting wallet. Placeholder 0n until initIdentities() runs; every flow awaits it.
export const USER: DemoIdentity = {
  label: "sender (acct1)", accountLinkId: SENDER_LINK, did: 0n, privateSalt: 0n,
  accounts: [
    { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", pk: USER_PK },
    // The SAME person's second account wallet. It transacts under the same DID
    // because it is a member of the wallet set that DID document pins.
    { address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906", pk: USER_PK_B },
  ],
  governance: { address: USER_GOV, pk: USER_GOV_PK },
  address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", pk: USER_PK,
};
// GAP-H6: the receiving party is a DIFFERENT person, own DID + salt, and must hold a
// "receiving session".
export const RECEIVER: DemoIdentity = {
  label: "recipient (acct2)", accountLinkId: RECIPIENT_LINK, did: 0n, privateSalt: 0n,
  accounts: [{ address: RECIPIENT as `0x${string}`, pk: RECIPIENT_PK }],
  governance: { address: RECEIVER_GOV, pk: RECEIVER_GOV_PK },
  address: RECIPIENT as `0x${string}`, pk: RECIPIENT_PK,
};

/** The person's wallet addresses, in slot-assignment order. */
export const accountsOf = (id: DemoIdentity): string[] => id.accounts.map((w) => w.address);

/**
 * The same person acting from another of their own wallets. Refuses a wallet the
 * person does not own: that wallet has no membership proof to offer, so letting it
 * through would only fail later, inside the prover, with a worse message.
 */
export function walletOf(id: DemoIdentity, address: string): DemoIdentity {
  const wallet = id.accounts.find((w) => w.address.toLowerCase() === address.toLowerCase());
  if (!wallet) throw new Error(`${address} is not one of ${id.label}'s wallets`);
  return { ...id, label: `${id.label} via ${wallet.address.slice(0, 10)}…`, ...wallet };
}

let _identitiesReady = false;
/**
 * Populate USER/RECEIVER did+salt from their PER-PERSON derivations (once).
 * Call before any flow. No chain read and no wallet signature is involved: the
 * identity exists before, and independently of, any wallet the person holds.
 */
export async function initIdentities(): Promise<void> {
  if (_identitiesReady) return;
  for (const id of [USER, RECEIVER]) {
    const person = derivePersonIdentity(id.accountLinkId);
    id.did = person.did;
    id.privateSalt = person.privateSalt;
  }
  _identitiesReady = true;
}

export const chain = { id: CHAIN_ID, name: "anvil", nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } } as const;

export function loadDeployment(): Record<string, string> {
  const f = path.join(ROOT, "contracts/deployments/31337-v2.json");
  if (!fs.existsSync(f)) throw new Error("no deployment, run `make up` first");
  return JSON.parse(fs.readFileSync(f, "utf8"));
}

/**
 * The permissioned-AMM layer is ADDITIVE: `make up` deploys the token topology without it, and
 * `make dex-up` adds it. So this returns null rather than throwing, and every pool verb says so
 * plainly instead of failing deep inside a contract read.
 */
export function loadDexDeployment(): Record<string, string> | null {
  const f = path.join(ROOT, "contracts/deployments/31337-dex.json");
  if (!fs.existsSync(f)) return null;
  return JSON.parse(fs.readFileSync(f, "utf8"));
}

export function requireDexDeployment(): Record<string, string> {
  const dx = loadDexDeployment();
  if (!dx) throw new Error("no permissioned-pool deployment, run `make dex-up` first");
  return dx;
}

/**
 * The pool deployment, but only when its contracts are on THIS chain.
 *
 * `loadDexDeployment` reads a FILE, and a file is not a chain. `v2-up` starts a fresh Anvil and
 * does NOT deploy the pool, so the `31337-dex.json` left by an earlier `v2-dex-up` survives with
 * addresses that no longer have code. The pool acts then ran anyway and died deep inside a session
 * build with `getMonitorKey returned no data ("0x")`, which reads as a contract bug and is really
 * a stale artifact. Every address in the file is checked, so a key added later is covered without
 * anyone remembering to add it here.
 */
export async function dexDeploymentIfLive(): Promise<
  { deployment: Record<string, string> } | { stale: true } | null
> {
  const dx = loadDexDeployment();
  if (!dx) return null;
  const pc = publicClient();
  const addresses = Object.entries(dx)
    .filter(([, v]) => typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v));
  for (const [, address] of addresses) {
    const code = await pc.getCode({ address: address as `0x${string}` });
    if (!code || code === "0x") return { stale: true };
  }
  return { deployment: dx };
}

export function publicClient() {
  return createPublicClient({ chain, transport: http(RPC) });
}
export function wallet(pk: string) {
  return createWalletClient({ account: privateKeyToAccount(pk as `0x${string}`), chain, transport: http(RPC) });
}

export const toHex32 = (x: bigint): `0x${string}` => ("0x" + x.toString(16).padStart(64, "0")) as `0x${string}`;

// ---- minimal ABIs (only what the CLI calls) ----
export const abis = {
  did: [
    { type: "function", name: "registerDID", stateMutability: "payable", inputs: [{ name: "did", type: "bytes32" }, { name: "psc", type: "bytes32" }, { name: "skr", type: "bytes32" }, { name: "gov", type: "address[]" }], outputs: [] },
    // Registration is COMMIT-THEN-REVEAL: a pending registerDID used to broadcast the DID in the
    // clear, and a front-runner could take it and substitute their own governance key. The reveal
    // must land in a strictly later block than its commitment.
    { type: "function", name: "commitRegistration", stateMutability: "nonpayable", inputs: [{ name: "commitment", type: "bytes32" }], outputs: [] },
    { type: "function", name: "registrationCommitment", stateMutability: "pure", inputs: [{ name: "did", type: "bytes32" }, { name: "psc", type: "bytes32" }, { name: "skr", type: "bytes32" }, { name: "gov", type: "address[]" }, { name: "registrant", type: "address" }], outputs: [{ name: "", type: "bytes32" }] },
    { type: "function", name: "root", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "isRegistered", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "getMerkleProof", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ name: "siblings", type: "bytes32[]" }, { name: "index", type: "uint256" }] },
  ],
  ita: [
    { type: "function", name: "issueCredential", stateMutability: "nonpayable", inputs: [{ name: "regime", type: "bytes32" }, { name: "did", type: "bytes32" }, { name: "commitment", type: "bytes32" }, { name: "expiresAt", type: "uint256" }, { name: "ikId", type: "bytes32" }, { name: "metadata", type: "bytes32" }], outputs: [] },
    { type: "function", name: "getAttributeRegimeRoot", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "isCredentialValid", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "bytes32" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "getCredential", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "bytes32" }], outputs: [{ type: "tuple", components: [{ name: "commitment", type: "bytes32" }, { name: "issuerIKId", type: "bytes32" }, { name: "issuedAt", type: "uint256" }, { name: "expiresAt", type: "uint256" }, { name: "revoked", type: "bool" }, { name: "metadata", type: "bytes32" }] }] },
    { type: "function", name: "getCredentialProof", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "bytes32" }], outputs: [{ name: "siblings", type: "bytes32[]" }, { name: "index", type: "uint256" }] },
  ],
  ordb: [
    { type: "function", name: "root", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "isFlagged", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "flagPseudonym", stateMutability: "nonpayable", inputs: [{ name: "p", type: "bytes32" }, { name: "flags", type: "uint256" }], outputs: [] },
    { type: "function", name: "getNonMembershipWitness", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ name: "lowIndex", type: "uint256" }, { name: "lowKey", type: "bytes32" }, { name: "nextKey", type: "bytes32" }, { name: "siblings", type: "bytes32[]" }, { name: "root_", type: "bytes32" }] },
    { type: "function", name: "getMonitorKey", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }, { type: "uint256" }, { type: "bytes32" }] },
    { type: "function", name: "monitoredContract", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  ],
  policy: [
    { type: "function", name: "latestVersion", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "uint32" }] },
    { type: "function", name: "getPolicyVersion", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "uint32" }], outputs: [
      { name: "identityRoots", type: "tuple[2]", components: [{ name: "regimeHash", type: "bytes32" }, { name: "ita", type: "address" }] },
      { name: "requiredORDB", type: "address" },
      { name: "clauses", type: "tuple[6]", components: [{ name: "enabled", type: "bool" }, { name: "groupId", type: "uint8" }, { name: "attrIndex", type: "uint8" }, { name: "op", type: "uint8" }, { name: "value", type: "uint256" }] },
      { name: "clausesHash", type: "bytes32" },
      { name: "maxSessionValidity", type: "uint64" },
    ] },
    { type: "function", name: "predicateApproved", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "predicateName", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "string" }] },
    { type: "function", name: "registerPolicy", stateMutability: "nonpayable", inputs: [
      { name: "name", type: "string" },
      { name: "identityRoots", type: "tuple[2]", components: [{ name: "regimeHash", type: "bytes32" }, { name: "ita", type: "address" }] },
      { name: "requiredORDB", type: "address" },
      { name: "clauses", type: "tuple[6]", components: [{ name: "enabled", type: "bool" }, { name: "groupId", type: "uint8" }, { name: "attrIndex", type: "uint8" }, { name: "op", type: "uint8" }, { name: "value", type: "uint256" }] },
      { name: "maxSessionValidity", type: "uint64" },
    ], outputs: [{ type: "bytes32" }] },
  ],
  sm: [
    { type: "function", name: "sessionNonce", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "hasValidSession", stateMutability: "view", inputs: [{ type: "address" }, { type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "getSession", stateMutability: "view", inputs: [{ type: "address" }, { type: "bytes32" }], outputs: [{ type: "tuple", components: [{ name: "validUntil", type: "uint64" }, { name: "policyId", type: "bytes32" }, { name: "policyVersion", type: "uint32" }, { name: "gatedContract", type: "address" }, { name: "ordb", type: "address" }, { name: "attested", type: "bool" }, { name: "encryptedPseudonym", type: "bytes" }] }] },
    // The STAGING slot. A re-grant while the live session is still attested and unexpired is
    // staged rather than written over it (SessionManager._install), and `sessionDigestOf` then
    // names the STAGED session. Without this read nothing in this package can see the session the
    // contract is actually talking about, resolve slots via @tac-gap/sdk `inspectNamedSession`.
    { type: "function", name: "getPendingSession", stateMutability: "view", inputs: [{ type: "address" }, { type: "bytes32" }], outputs: [{ type: "tuple", components: [{ name: "validUntil", type: "uint64" }, { name: "policyId", type: "bytes32" }, { name: "policyVersion", type: "uint32" }, { name: "gatedContract", type: "address" }, { name: "ordb", type: "address" }, { name: "attested", type: "bool" }, { name: "encryptedPseudonym", type: "bytes" }] }] },
    { type: "function", name: "sessionDigestOf", stateMutability: "view", inputs: [{ type: "address" }, { type: "bytes32" }], outputs: [{ type: "bytes32" }] },
    { type: "function", name: "attestSession", stateMutability: "nonpayable", inputs: [{ name: "account", type: "address" }, { name: "policyId", type: "bytes32" }, { name: "sessionDigest", type: "bytes32" }], outputs: [] },
    { type: "function", name: "grantSession", stateMutability: "nonpayable", inputs: [
      { name: "policyId", type: "bytes32" }, { name: "policyVersion", type: "uint32" }, { name: "validUntil", type: "uint64" },
      { name: "pA", type: "uint256[2]" }, { name: "pB", type: "uint256[2][2]" }, { name: "pC", type: "uint256[2]" },
      { name: "pub", type: "uint256[19]" }, { name: "ciphertext", type: "bytes" },
    ], outputs: [] },
  ],
  token: [
    { type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
    { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  ],
  dex: [
    { type: "function", name: "swap", stateMutability: "nonpayable", inputs: [{ name: "securityIn", type: "bool" }, { name: "amountIn", type: "uint256" }, { name: "minAmountOut", type: "uint256" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "addLiquidity", stateMutability: "nonpayable", inputs: [{ name: "securityIn", type: "uint256" }, { name: "cashIn", type: "uint256" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "removeLiquidity", stateMutability: "nonpayable", inputs: [{ name: "sharesIn", type: "uint256" }], outputs: [{ type: "uint256" }, { type: "uint256" }] },
    { type: "function", name: "quote", stateMutability: "view", inputs: [{ type: "bool" }, { type: "uint256" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "maySwap", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "mayProvideLiquidity", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "securityReserve", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
    { type: "function", name: "cashReserve", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
    { type: "function", name: "shares", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  ],
  cash: [
    { type: "function", name: "mint", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
    { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  ],
  checker: [
    { type: "function", name: "checkAllowlist", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "uint8" }] },
  ],
  venue: [
    { type: "function", name: "issue", stateMutability: "nonpayable", inputs: [{ name: "assetId", type: "bytes32" }, { name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] },
    { type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "assetId", type: "bytes32" }, { name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] },
    { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ name: "assetId", type: "bytes32" }, { name: "holder", type: "address" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "preflight", stateMutability: "view", inputs: [{ name: "assetId", type: "bytes32" }, { name: "from", type: "address" }, { name: "to", type: "address" }], outputs: [{ name: "senderOk", type: "bool" }, { name: "recipientOk", type: "bool" }] },
    { type: "function", name: "getAsset", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "tuple", components: [{ name: "zoneId", type: "bytes32" }, { name: "symbol", type: "string" }, { name: "exists", type: "bool" }] }] },
  ],
} as const;

// Any ORDB by address (the token ORDB or a venue ORDB), same interface.
export function ordbAt(address: string) {
  return getContract({ address: address as `0x${string}`, abi: abis.ordb, client: publicClient() });
}

export function contracts() {
  const d = loadDeployment();
  const pc = publicClient();
  return {
    d,
    did: getContract({ address: d.didRegistry as `0x${string}`, abi: abis.did, client: pc }),
    ita: getContract({ address: d.identityAnchor as `0x${string}`, abi: abis.ita, client: pc }),
    ordb: getContract({ address: d.ordb as `0x${string}`, abi: abis.ordb, client: pc }),
    policy: getContract({ address: d.userPolicyRegistry as `0x${string}`, abi: abis.policy, client: pc }),
    sm: getContract({ address: d.sessionManager as `0x${string}`, abi: abis.sm, client: pc }),
    token: getContract({ address: d.regulatedToken as `0x${string}`, abi: abis.token, client: pc }),
    venue: getContract({ address: d.venue as `0x${string}`, abi: abis.venue, client: pc }),
    venueOrdb: getContract({ address: d.venueOrdb as `0x${string}`, abi: abis.ordb, client: pc }),
  };
}

// The venue's Regulated Zones the demo user's existing credentials satisfy. Each zone is a
// (transfer, receiving) policy pair; the DNF clause template must match the deploy (matched by
// the circuit's clausesHash). Under GAP_ATTR_CRED_V3 the attrs order is
// regime 0: [residency, sanctioned, citizenship, reserved]
// regime 1: [accredited, qualifiedPurchaser, reserved, reserved]
// i.e. attrs[0] is RESIDENCY (not citizenship, citizenship is attrs[2]), accredited is attrs[4]
// and qualified purchaser is attrs[5]. Mirrors _zonePolicy in contracts/script/v2/DeployV2.s.sol.
export type ZoneId = "general" | "reg-d";
export interface ZoneCfg {
  label: string;
  assetId: string;      // deployment key (assetFUNDG / assetPRIVD)
  assetSymbol: string;
  transferKey: string;  // deployment key for the transfer policyId
  receivingKey: string; // deployment key for the receiving policyId
  clauses: { enabled: number; groupId: number; attrIndex: number; op: number; value: bigint }[];
}
export const ZONES: Record<ZoneId, ZoneCfg> = {
  general: {
    label: "General Securities", assetSymbol: "dFUND-G", assetId: "assetFUNDG",
    transferKey: "genTransferPolicy", receivingKey: "genReceivingPolicy",
    clauses: [
      { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },    // sanctioned == 0
      { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n },  // residency == US
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    ],
  },
  "reg-d": {
    label: "Reg D (accredited)", assetSymbol: "PRIV-D", assetId: "assetPRIVD",
    transferKey: "regdTransferPolicy", receivingKey: "regdReceivingPolicy",
    clauses: [
      { enabled: 1, groupId: 0, attrIndex: 1, op: 1, value: 0n },    // sanctioned == 0
      { enabled: 1, groupId: 0, attrIndex: 0, op: 1, value: 840n },  // residency == US
      { enabled: 1, groupId: 0, attrIndex: 4, op: 1, value: 1n },    // accredited == 1
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
      { enabled: 0, groupId: 0, attrIndex: 0, op: 0, value: 0n },
    ],
  },
};
