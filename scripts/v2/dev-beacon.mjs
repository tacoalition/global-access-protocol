// The development closing value has ONE definition, in the shell library the builds source. Node
// callers that need to record it: the manifest writer, its checker, read that file rather than
// keeping a second copy, because a manifest that records a beacon the build did not use is worse
// than one that records nothing.
import { readFile } from "node:fs/promises";
import path from "node:path";

export const DEV_BEACON_SHELL = "scripts/v2/lib/dev-beacon.sh";

function assignment(source, name, pattern) {
  const match = source.match(new RegExp(`^${name}=(?:"([^"]*)"|(\\S+))\\s*$`, "m"));
  const value = match?.[1] ?? match?.[2];
  if (value === undefined || !pattern.test(value)) {
    throw new Error(
      `${DEV_BEACON_SHELL} does not define ${name} in the expected form; the manifest cannot ` +
        `record a closing value it is not certain the build used.`,
    );
  }
  return value;
}

export async function readDevelopmentBeacon(root) {
  const source = await readFile(path.join(root, DEV_BEACON_SHELL), "utf8");
  return {
    hex: assignment(source, "DEV_BEACON_HEX", /^[0-9a-f]{64}$/),
    iterations: assignment(source, "DEV_BEACON_ITERATIONS", /^\d+$/),
  };
}
