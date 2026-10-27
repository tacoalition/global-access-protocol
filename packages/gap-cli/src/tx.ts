// Await a transaction receipt and refuse to continue on a revert. Shared by every
// write path in this lane so no caller can accidentally treat a reverted tx as done.
import { publicClient } from "./state";

export async function txWait(hash: `0x${string}`) {
  const pc = publicClient();
  const r = await pc.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error("tx reverted: " + hash);
  return r;
}
