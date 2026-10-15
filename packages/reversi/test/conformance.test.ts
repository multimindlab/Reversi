import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("committed conformance fixtures match the TypeScript implementation", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  expect(() => execFileSync("node", [join(root, "scripts", "gen-fixtures.mjs"), "--check"], { stdio: "pipe" })).not.toThrow();
});
