import { assertBytes, assertField } from "./field";
import type { Address, Bytes32 } from "./types";
import type { RevokeReason } from "./command-schema";

export type AnchorMutation =
  | {
      readonly functionName: "issueCredential";
      readonly anchor: Address;
      readonly regimeHash: Bytes32;
      readonly did: Bytes32;
      readonly commitment: Bytes32;
      readonly expiresAt: bigint;
      readonly ikId: Bytes32;
      /**
       * Issuer-set, opaque, PUBLIC and in no proof. OPTIONAL, omitted means `0x00..00`, "none",
       * which is what every lane in this repository issues. See the warning on
       * IdentityAnchor.Credential.metadata before putting anything derived from PII here.
       */
      readonly metadata?: Bytes32;
    }
  | {
      readonly functionName: "revokeCredential";
      readonly anchor: Address;
      readonly regimeHash: Bytes32;
      readonly did: Bytes32;
      readonly reason: RevokeReason;
      readonly ikId: Bytes32;
    };

export interface IkSigningPort {
  readonly address: Address;
  sendCredentialMutation(mutation: AnchorMutation): Promise<Bytes32>;
}

export class SchemaRestrictedSigner {
  constructor(
    private readonly signer: IkSigningPort,
    private readonly expectedAnchor: Address,
    private readonly expectedIkId: Bytes32,
  ) {
    assertBytes(expectedAnchor, 20, "expectedAnchor");
    assertBytes(expectedIkId, 32, "expectedIkId");
  }

  get address(): Address {
    return this.signer.address;
  }

  async submit(mutation: AnchorMutation): Promise<Bytes32> {
    if (mutation.anchor.toLowerCase() !== this.expectedAnchor.toLowerCase()) throw new Error("signer target anchor is not allowlisted");
    if (mutation.ikId.toLowerCase() !== this.expectedIkId.toLowerCase()) throw new Error("signer IK route is not allowlisted");
    assertBytes(mutation.regimeHash, 32, "regimeHash");
    assertBytes(mutation.did, 32, "did");
    assertField(BigInt(mutation.did), "did");
    if (mutation.functionName === "issueCredential") {
      assertBytes(mutation.commitment, 32, "commitment");
      assertField(BigInt(mutation.commitment), "commitment");
      if (mutation.expiresAt <= 0n || mutation.expiresAt >= 1n << 64n) throw new Error("expiry is not finite uint64");
    }
    return this.signer.sendCredentialMutation(mutation);
  }
}
