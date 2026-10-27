/** Serializes complete read-witness → prove → submit → canonical-receipt tasks per account. */
export class GrantQueue {
  private tails = new Map<string, Promise<void>>();

  enqueue<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const run = previous.then(task, task);
    const tail = run.then(
      () => undefined,
      () => undefined,
    );
    this.tails.set(key, tail);
    void tail.then(() => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    });
    return run;
  }

  get size(): number {
    return this.tails.size;
  }
}

export interface GrantLockKey {
  chainId: bigint | number;
  sessionManager: `0x${string}`;
  account: `0x${string}`;
}

export function grantLockName(key: GrantLockKey): string {
  return [
    "dsi-gap-grant-v1",
    String(key.chainId),
    key.sessionManager.toLowerCase(),
    key.account.toLowerCase(),
  ].join(":");
}

interface BrowserLockManager {
  request<T>(
    name: string,
    options: { mode: "exclusive" },
    callback: () => Promise<T>,
  ): Promise<T>;
}

export class StaleWitnessError extends Error {
  constructor(message = "GAP SDK: stale witness") {
    super(message);
    this.name = "StaleWitnessError";
  }
}

/**
 * Uses Web Locks across tabs when available and a leak-free in-realm queue otherwise. The task must
 * encompass every live read, witness build, proof, submission, and canonical receipt check.
 */
export class GrantCoordinator {
  private readonly local = new GrantQueue();

  constructor(
    private readonly locks: BrowserLockManager | undefined =
      typeof navigator === "undefined"
        ? undefined
        : (navigator as Navigator & { locks?: BrowserLockManager }).locks,
  ) {}

  run<T>(key: GrantLockKey, task: () => Promise<T>): Promise<T> {
    const name = grantLockName(key);
    if (this.locks) return this.locks.request(name, { mode: "exclusive" }, task);
    return this.local.enqueue(name, task);
  }

  /**
   * A stale nonce/root retry always invokes the complete task again, so the discarded proof and all
   * chain-derived inputs are rebuilt. Non-stale failures are never retried here.
   */
  runWithStaleRetry<T>(
    key: GrantLockKey,
    task: () => Promise<T>,
    maxStaleRetries = 1,
  ): Promise<T> {
    return this.run(key, async () => {
      for (let attempt = 0; ; attempt += 1) {
        try {
          return await task();
        } catch (error) {
          if (!(error instanceof StaleWitnessError) || attempt >= maxStaleRetries) throw error;
        }
      }
    });
  }
}

export interface GapSigner {
  address: `0x${string}`;
  // Wallet clients and smart-account adapters intentionally share this narrow port.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  writeContract(args: {
    address: `0x${string}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: any;
    functionName: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    args: any[];
  }): Promise<`0x${string}`>;
  waitForReceipt(hash: `0x${string}`): Promise<void>;
}

