import assert from "node:assert/strict";
import test from "node:test";
import { assertStableGovernanceControllers } from "../src/governance-v2";
import type { Address } from "../src/types";

const address = (value: bigint): Address =>
  `0x${value.toString(16).padStart(40, "0")}`;

test("V2 governance rejects the zero controller", () => {
  assert.throws(
    () => assertStableGovernanceControllers([address(0n)], [address(0x1001n)]),
    /controllers must be nonzero/,
  );
});

test("V2 governance rejects duplicate controllers", () => {
  const controller = address(0xc011n);
  assert.throws(
    () => assertStableGovernanceControllers([controller, controller], [address(0x1001n)]),
    /controllers must be unique/,
  );
});

test("V2 governance accepts unique nonzero controllers separate from wallets", () => {
  assert.doesNotThrow(() => assertStableGovernanceControllers(
    [address(0xc011n), address(0xc012n)],
    [address(0x1001n), address(0x1101n)],
  ));
});
