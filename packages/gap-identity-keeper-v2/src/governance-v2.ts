import { assertBytes } from "./field";
import type { Address } from "./types";

export function assertStableGovernanceControllers(
  controllers: readonly Address[],
  spendingWallets: readonly Address[],
): void {
  if (controllers.length < 1 || controllers.length > 5) {
    throw new Error("V2 DID governance requires 1..5 stable controllers");
  }
  const normalizedControllers = new Set<string>();
  for (const controller of controllers) {
    assertBytes(controller, 20, "governance controller");
    const normalized = controller.toLowerCase();
    if (BigInt(normalized) === 0n) {
      throw new Error("V2 DID governance controllers must be nonzero");
    }
    if (normalizedControllers.has(normalized)) {
      throw new Error("V2 DID governance controllers must be unique");
    }
    normalizedControllers.add(normalized);
  }
  for (const wallet of spendingWallets) {
    assertBytes(wallet, 20, "spending wallet");
    if (normalizedControllers.has(wallet.toLowerCase())) {
      throw new Error("V2 DID governance controllers must be separate from spending wallets");
    }
  }
}

export function sameControllerSet(
  left: readonly Address[],
  right: readonly Address[],
): boolean {
  if (left.length !== right.length) return false;
  const normalizedLeft = new Set(left.map((address) => address.toLowerCase()));
  const normalizedRight = new Set(right.map((address) => address.toLowerCase()));
  if (normalizedLeft.size !== left.length || normalizedRight.size !== right.length) return false;
  return [...normalizedRight].every((address) => normalizedLeft.has(address));
}
