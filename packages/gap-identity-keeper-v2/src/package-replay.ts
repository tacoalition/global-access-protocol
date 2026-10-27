import type { Address, Bytes32 } from "./types";

export interface PackageReplayClaim {
  readonly wallet: Address;
  readonly packageId: Bytes32;
  readonly sequence: bigint;
  readonly envelopeDigest: Bytes32;
}

export interface PackageReplayPort {
  claim(input: PackageReplayClaim): Promise<"ACCEPTED" | "DUPLICATE">;
}

interface AcceptedPackage extends PackageReplayClaim {}

/** Test/demo implementation. Production callers inject the same semantics over durable storage. */
export class InMemoryPackageReplayStore implements PackageReplayPort {
  private readonly byWallet = new Map<string, AcceptedPackage>();
  private readonly byPackageId = new Map<string, AcceptedPackage>();

  async claim(input: PackageReplayClaim): Promise<"ACCEPTED" | "DUPLICATE"> {
    const walletKey = input.wallet.toLowerCase();
    const packageKey = input.packageId.toLowerCase();
    const priorPackage = this.byPackageId.get(packageKey);
    if (priorPackage) {
      if (
        priorPackage.wallet.toLowerCase() === walletKey &&
        priorPackage.sequence === input.sequence &&
        priorPackage.envelopeDigest.toLowerCase() === input.envelopeDigest.toLowerCase()
      ) {
        return "DUPLICATE";
      }
      throw new Error("package ID was already claimed with different bindings");
    }

    const priorWallet = this.byWallet.get(walletKey);
    if (priorWallet && input.sequence <= priorWallet.sequence) {
      throw new Error("package sequence is stale or conflicts with accepted bytes");
    }
    const accepted = { ...input };
    this.byWallet.set(walletKey, accepted);
    this.byPackageId.set(packageKey, accepted);
    return "ACCEPTED";
  }
}
