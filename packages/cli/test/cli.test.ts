import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SealedScope, loadRegistry, openLocal } from "@multimindlab/reversi";
import { main } from "../src/cli.js";

const MANIFESTS = `
- tool: create_order
  effect: reversible
  permission: orders:write
  compensation:
    tool: cancel_order
    argument_map: { id: $result.id }
- tool: cancel_order
  effect: idempotent
  permission: orders:write
- tool: send_email
  effect: irreversible
  permission: mail:send
`;

let dir: string;
let mpath: string;
let data: string;
beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "reversi-cli-"));
  mpath = join(dir, "tools.yaml");
  data = join(dir, "data");
  writeFileSync(mpath, MANIFESTS);
  const rv = openLocal(data, loadRegistry(mpath), () => true);
  const run = rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["orders:write", "mail:send"]) });
  await run.call({ tool: "create_order", reason: "order", execute: () => ({ id: 11 }) });
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function cli(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, { out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

describe("validate", () => {
  it("accepts good manifests", async () => {
    expect(await cli("validate", mpath)).toMatchObject({ code: 0, out: "ok: 3 tool manifests valid" });
  });
  it("reports every problem and exits 1", async () => {
    const bad = join(dir, "bad.yaml");
    writeFileSync(bad, "- tool: x\n  effect: reversible\n  permission: p\n- tool: y\n  effect: nope\n  permission: p\n");
    const r = await cli("validate", bad);
    expect(r.code).toBe(1);
    expect(r.err.split("\n").length).toBeGreaterThanOrEqual(2);
  });
  it("fails on a missing path", async () => {
    expect((await cli("validate", join(dir, "nope"))).code).toBe(1);
  });
  it("loads a directory", async () => {
    expect((await cli("validate", dir)).out).toContain("valid");
  });
});

describe("verify / export", () => {
  it("verifies an untouched ledger", async () => {
    const r = await cli("verify", join(data, "ledger.jsonl"));
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/^ok: 3 records, head [0-9a-f]{64}$/);
  });
  it("flags tampering with exit 1", async () => {
    const f = join(data, "ledger.jsonl");
    writeFileSync(f, readFileSync(f, "utf8").replace("create_order", "refund_all"));
    const r = await cli("verify", f);
    expect(r.code).toBe(1);
    expect(r.err).toContain("TAMPERED");
  });
  it("exports one run as JSONL that still verifies", async () => {
    const r = await cli("export", "-d", data, "--run", "r1");
    const lines = r.out.split("\n");
    expect(lines).toHaveLength(3);
    const copy = join(dir, "copy.jsonl");
    writeFileSync(copy, r.out + "\n");
    expect((await cli("verify", copy)).code).toBe(0);
  });
});

describe("runs / plan", () => {
  it("lists runs", async () => {
    const r = await cli("runs", "-m", mpath, "-d", data);
    expect(r.out).toContain("r1  actor=agent  mode=enforce  steps=1");
  });
  it("prints a plan and does not change anything", async () => {
    const before = readFileSync(join(data, "ledger.jsonl"), "utf8");
    const r = await cli("plan", "r1", "-m", mpath, "-d", data);
    expect(r.code).toBe(0);
    expect(r.out).toContain("step 0  create_order  compensate  -> cancel_order");
    expect(readFileSync(join(data, "ledger.jsonl"), "utf8")).toBe(before);
  });
  it("exits 2 when not fully reversible", async () => {
    const rv = openLocal(data, loadRegistry(mpath), () => true);
    await rv.openRun("r1").call({ tool: "send_email", reason: "mail", execute: () => "sent" });
    expect((await cli("plan", "r1", "-m", mpath, "-d", data)).code).toBe(2);
  });
  it("errors for an unknown run", async () => {
    expect((await cli("plan", "ghost", "-m", mpath, "-d", data)).code).toBe(1);
  });
});

describe("rollback", () => {
  it("feeds the compensation call to the operator command on stdin", async () => {
    const sink = join(dir, "seen.json");
    const r = await cli("rollback", "r1", "-m", mpath, "-d", data, "--compensator-cmd", `cat > ${sink}`);
    expect(r.code).toBe(0);
    expect(r.out).toContain("rollback complete");
    const call = JSON.parse(readFileSync(sink, "utf8"));
    expect(call).toMatchObject({ tool: "cancel_order", args: { id: 11 }, step: 0 });
    expect((await cli("verify", join(data, "ledger.jsonl"))).code).toBe(0);
  });
  it("reports a failing compensator and exits 2", async () => {
    const r = await cli("rollback", "r1", "-m", mpath, "-d", data, "--compensator-cmd", "echo nope >&2; exit 3");
    expect(r.code).toBe(2);
    expect(r.out).toContain("FAILED step 0");
    expect(r.out).toContain("rollback INCOMPLETE");
    const retry = await cli("rollback", "r1", "-m", mpath, "-d", data, "--compensator-cmd", "true");
    expect(retry.code).toBe(0);
  });
  it("requires an explicit compensator", async () => {
    expect((await cli("rollback", "r1", "-m", mpath, "-d", data)).code).toBe(64);
  });
});
