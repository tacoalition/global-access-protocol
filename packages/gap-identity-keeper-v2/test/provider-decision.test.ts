import assert from "node:assert/strict";
import test from "node:test";
import { derivePersonDid } from "../src/person-did";
import type { ProviderAttestationEnvelope } from "../src/provider-attestation";
import {
  InMemoryProviderDecisionStore,
  ProviderBackedDecisionPort,
  type IdentityCaseBinding,
  type LiveProviderStatus,
} from "../src/provider-decision-port";
import {
  APPLICANT_ID, LINK_A, LINK_B, NOW, PERSON_DID_KEY,
  createProviderKey, decisionSlots, liveFrom, policyFor, signAttestation, storedFrom,
} from "./provider-fixture";

const SUBJECT = "subject-demo-person";
const WALLET = `0x${"33".repeat(20)}` as const;
const key = createProviderKey();

const binding: IdentityCaseBinding = {
  subjectId: SUBJECT, accountLinkId: LINK_A, applicantId: APPLICANT_ID, wallet: WALLET,
};

interface Wiring {
  readonly stored?: ProviderAttestationEnvelope;
  readonly live?: ProviderAttestationEnvelope;
  readonly liveOverrides?: Partial<LiveProviderStatus>;
  readonly liveThrows?: boolean;
  readonly storedNonce?: string;
  readonly caseBinding?: IdentityCaseBinding | undefined;
}

function port(wiring: Wiring) {
  const store = new InMemoryProviderDecisionStore();
  if (wiring.stored) {
    void store.write(LINK_A, storedFrom(wiring.stored, wiring.storedNonce));
  }
  const instance = new ProviderBackedDecisionPort({
    policy: policyFor(key),
    directory: { async lookup() { return "caseBinding" in wiring ? wiring.caseBinding : binding; } },
    store,
    live: {
      async readStatus() {
        if (wiring.liveThrows) throw new Error("connection reset");
        return liveFrom(wiring.live, wiring.liveOverrides ?? {});
      },
    },
    personDidKey: PERSON_DID_KEY,
    now: () => NOW,
  });
  return { port: instance, store };
}

const green = () => signAttestation(key, decisionSlots());

test("no verified provider decision means no credential", async () => {
  const { port: p } = port({ live: green() });
  await assert.rejects(
    p.readDecision("IDENTITY", SUBJECT),
    /identity issuance requires a verified provider decision/,
  );
});

test("a decision for a different subject is refused", async () => {
  const foreign = signAttestation(key, decisionSlots({ subject: LINK_B }));
  const { port: p } = port({ stored: foreign, live: foreign });
  await assert.rejects(
    p.readDecision("IDENTITY", SUBJECT),
    /attestation subject does not match the account link id/,
  );
  // ...and a live read bound to someone else's externalUserId is refused too.
  const ok = green();
  const { port: q } = port({
    stored: ok, live: ok, liveOverrides: { externalUserId: LINK_B },
  });
  await assert.rejects(q.readDecision("IDENTITY", SUBJECT), /bound to a different applicant\/subject/);
});

test("stale, expired, and replayed decisions are refused", async () => {
  const expired = signAttestation(key, decisionSlots({
    observedAt: new Date(Number(NOW - 7200n) * 1000).toISOString(),
    expiresAt: String(NOW - 60n),
  }));
  await assert.rejects(
    port({ stored: expired, live: expired }).port.readDecision("IDENTITY", SUBJECT),
    /provider decision has expired/,
  );

  const staleScreen = signAttestation(key, decisionSlots({
    screenedAt: new Date(Number(NOW - 90_000n) * 1000).toISOString(),
  }));
  await assert.rejects(
    port({ stored: staleScreen, live: staleScreen }).port.readDecision("IDENTITY", SUBJECT),
    /sanctions screening is stale/,
  );

  // Replay: the live channel is behind the durable decision of record.
  const current = signAttestation(key, decisionSlots({ decisionRevision: "4" }));
  const replayed = signAttestation(key, decisionSlots({ decisionRevision: "3" }));
  await assert.rejects(
    port({ stored: current, live: replayed }).port.readDecision("IDENTITY", SUBJECT),
    /live provider decision is behind the stored decision/,
  );

  // Equivocation: same revision, different signed bytes across the two channels.
  const forked = signAttestation(key, decisionSlots({ country: "USA" }));
  await assert.rejects(
    port({ stored: green(), live: forked }).port.readDecision("IDENTITY", SUBJECT),
    /equivocates between webhook and live read/,
  );

  // The nonce binds the stored decision to the exact webhook delivery.
  await assert.rejects(
    port({ stored: green(), live: green(), storedNonce: `0x${"ee".repeat(32)}` }).port
      .readDecision("IDENTITY", SUBJECT),
    /not bound to the recorded webhook delivery/,
  );
});

test("an unavailable or unsigned live re-read refuses issuance", async () => {
  await assert.rejects(
    port({ stored: green(), liveThrows: true }).port.readDecision("IDENTITY", SUBJECT),
    /live provider status re-read is unavailable/,
  );
  await assert.rejects(
    port({ stored: green(), live: undefined }).port.readDecision("IDENTITY", SUBJECT),
    /carries no provider attestation/,
  );
  // A live read whose state is not APPROVED blocks even with a valid signature.
  await assert.rejects(
    port({ stored: green(), live: green(), liveOverrides: { reviewStatus: "onHold" } }).port
      .readDecision("IDENTITY", SUBJECT),
    /live provider state SUSPENDED does not permit issuance/,
  );
});

test("a GB approval yields country 826 and a clean sanctions attribute", async () => {
  const envelope = green();
  const { port: p } = port({ stored: envelope, live: envelope });
  const decision = await p.readDecision("IDENTITY", SUBJECT);
  assert.deepEqual(decision.attributes, [826n, 0n, 826n, 0n]);
  assert.equal(decision.approved, true);
  assert.equal(decision.subjectId, SUBJECT);
  assert.equal(decision.wallet, WALLET);
  assert.equal(decision.did, derivePersonDid({
    personDidKey: PERSON_DID_KEY, environment: "sandbox", accountLinkId: LINK_A,
  }));
  assert.equal(decision.expiresAt, NOW + 3600n);
  assert.match(decision.evidenceDigest, /^0x[0-9a-f]{64}$/);

  const us = signAttestation(key, decisionSlots({ country: "USA" }));
  const usDecision = await port({ stored: us, live: us }).port.readDecision("IDENTITY", SUBJECT);
  assert.deepEqual(usDecision.attributes, [840n, 0n, 840n, 0n]);
});

test("a sanctioned, rejected, or unknown-jurisdiction applicant gets no credential", async () => {
  const hit = signAttestation(key, decisionSlots({ screeningResult: "HIT" }));
  await assert.rejects(
    port({ stored: hit, live: hit }).port.readDecision("IDENTITY", SUBJECT),
    /unresolved hit; no credential is issued/,
  );

  const red = signAttestation(key, decisionSlots({ reviewAnswer: "RED", reviewRejectType: "FINAL" }));
  await assert.rejects(
    port({ stored: red, live: red }).port.readDecision("IDENTITY", SUBJECT),
    /review answer is not GREEN/,
  );

  // No sentinel numeric for an unknown jurisdiction, refusal is the only default.
  const unknown = signAttestation(key, decisionSlots({ country: "XXX" }));
  await assert.rejects(
    port({ stored: unknown, live: unknown }).port.readDecision("IDENTITY", SUBJECT),
    /not in the reviewed ISO 3166-1 table/,
  );
});

test("a forged or foreign-keyed attestation cannot pass verification", async () => {
  const foreign = createProviderKey();
  const forged = signAttestation(foreign, decisionSlots());
  await assert.rejects(
    port({ stored: forged, live: forged }).port.readDecision("IDENTITY", SUBJECT),
    /signature is invalid/,
  );
  const unpinned = signAttestation(key, decisionSlots(), "rogue-key");
  await assert.rejects(
    port({ stored: unpinned, live: unpinned }).port.readDecision("IDENTITY", SUBJECT),
    /is not pinned/,
  );
  // Tampering with the payload after signing breaks the signature over the bytes.
  const envelope = green();
  const tampered = {
    ...envelope,
    payload: Buffer.from(JSON.stringify(decisionSlots({ country: "USA" })), "utf8").toString("base64url"),
  };
  await assert.rejects(
    port({ stored: tampered, live: tampered }).port.readDecision("IDENTITY", SUBJECT),
    /signature is invalid/,
  );
});

test("a newer live revision becomes the durable record before issuance proceeds", async () => {
  const older = signAttestation(key, decisionSlots({ decisionRevision: "1" }));
  const newer = signAttestation(key, decisionSlots({ decisionRevision: "2", country: "USA" }));
  const { port: p, store } = port({ stored: older, live: newer });
  const decision = await p.readDecision("IDENTITY", SUBJECT);
  assert.equal(decision.revision, 2n);
  assert.deepEqual(decision.attributes, [840n, 0n, 840n, 0n]);
  assert.equal((await store.read(LINK_A))?.payload, newer.payload);
});

test("an unknown case, a non-UUID link id, and an absent fund source all refuse", async () => {
  await assert.rejects(
    port({ stored: green(), live: green(), caseBinding: undefined }).port.readDecision("IDENTITY", SUBJECT),
    /no identity case is known for this subject/,
  );
  await assert.rejects(
    port({
      stored: green(), live: green(),
      caseBinding: { ...binding, accountLinkId: "gap-link-person-a" },
    }).port.readDecision("IDENTITY", SUBJECT),
    /canonical lowercase UUIDv4/,
  );
  await assert.rejects(
    port({ stored: green(), live: green() }).port.readDecision("FUND", SUBJECT),
    /no fund decision source is configured/,
  );
});
