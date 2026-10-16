import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { serve } from "@hono/node-server";
import { Approvals, Ledger, ManifestRegistry, Policy, PolicyVersions, Registry, Reversi } from "@multimindlab/reversi";
import { createApp } from "@multimindlab/reversi-server";
import { main } from "../src/cli.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "reversi-apply-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function cli(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, { out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

const desiredDir = () => join(dir, "desired");
function write(name: string, text: string) {
  mkdirSync(join(desiredDir(), "manifests"), { recursive: true });
  writeFileSync(join(desiredDir(), "manifests", name), text);
}
const A = "tool: shop.read\neffect: read_only\npermission: shop:read\n";
const B = "tool: shop.write\neffect: idempotent\npermission: shop:write\n";
const POLICY = "version: 1\nrules:\n  - id: r\n    match: { tool: 'shop.write' }\n    action: deny\ntests:\n  - name: denied\n    input: { tool: shop.write, args: {} }\n    expect: deny\n";

describe("reversi apply", () => {
  it("creates, is idempotent, updates, and prunes by deprecating", async () => {
    const reg = join(dir, "registry");
    const pol = join(dir, "policy");
    write("a.yaml", A);
    write("b.yaml", B);
    writeFileSync(join(desiredDir(), "policy.yaml"), POLICY);
    const base = ["apply", desiredDir(), "--registry", reg, "--policy-dir", pol, "--by", "ci"];

    const dry = await cli(...base, "--dry-run", "--detailed-exitcode");
    expect(dry.out).toContain("+ manifest shop.read");
    expect(dry.out).toContain("3 changes (dry run: nothing applied)");
    expect(dry.code).toBe(2);
    expect(readdirSync(dir)).not.toContain("registry");

    const first = await cli(...base);
    expect(first.code).toBe(0);
    expect(first.out).toContain("applied shop.read v1 (approved)");
    expect(first.out).toContain("applied policy v1");
    const registry = new ManifestRegistry(reg);
    expect(registry.history("shop.write").at(-1)?.status).toBe("approved");
    expect(new PolicyVersions(pol).activeVersion()).toBe(1);

    const again = await cli(...base, "--dry-run", "--detailed-exitcode");
    expect(again.out).toContain("up to date");
    expect(again.code).toBe(0);

    write("b.yaml", "tool: shop.write\neffect: idempotent\npermission: shop:write\nowner: team@example.com\n");
    const upd = await cli(...base);
    expect(upd.out).toContain("~ manifest shop.write");
    expect(registry.history("shop.write")).toHaveLength(2);
    expect(registry.history("shop.read")).toHaveLength(1); // untouched

    rmSync(join(desiredDir(), "manifests", "a.yaml"));
    expect((await cli(...base)).out).toContain("up to date"); // no prune: nothing removed
    const pruned = await cli(...base, "--prune");
    expect(pruned.out).toContain("- manifest shop.read");
    expect(registry.history("shop.read").at(-1)?.status).toBe("deprecated");
  });

  it("refuses an invalid directory and a registry that is just loose files", async () => {
    write("bad.yaml", "tool: x\neffect: nonsense\npermission: p\n");
    const bad = await cli("apply", desiredDir(), "--registry", join(dir, "r"));
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("invalid manifest");
    rmSync(desiredDir(), { recursive: true });
    write("a.yaml", A);
    const loose = join(dir, "loose");
    mkdirSync(loose);
    writeFileSync(join(loose, "x.yaml"), A);
    const r = await cli("apply", desiredDir(), "--registry", loose);
    expect(r.code).toBe(1);
    expect(r.err).toContain("not a registry");
  });
});

describe("reversi apply --server", () => {
  it("applies to a running server with an admin key, and refuses a lesser key", async () => {
    const approvals = new Approvals();
    const reversi = new Reversi({ registry: new Registry(), ledger: new Ledger(), approver: approvals.asApprover(), policy: Policy.from({ rules: [] }) });
    const app = createApp({ reversi, approvals, keys: [{ name: "root", role: "admin", key: "k-root" }, { name: "ops", role: "operator", key: "k-ops" }], registry_dir: join(dir, "sreg"), policy_dir: join(dir, "spol") });
    const server = await new Promise<ReturnType<typeof serve>>((r) => {
      const s = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, () => r(s));
    });
    try {
      const port = (server.address() as { port: number }).port;
      write("a.yaml", A);
      writeFileSync(join(desiredDir(), "policy.yaml"), POLICY);
      const url = `http://127.0.0.1:${port}`;
      const denied = await cli("apply", desiredDir(), "--server", url, "--token", "k-ops");
      expect(denied.code).toBe(1);
      const ok = await cli("apply", desiredDir(), "--server", url, "--token", "k-root");
      expect(ok.out).toContain("applied shop.read v1 (approved)");
      expect(new ManifestRegistry(join(dir, "sreg")).history("shop.read")).toHaveLength(1);
      expect((await cli("apply", desiredDir(), "--server", url, "--token", "k-root", "--dry-run")).out).toContain("up to date");
    } finally {
      server.close();
    }
  });
});

describe("suggest-manifest", () => {
  const fs = resolve(__dirname, "../../connectors/dist/main.js");
  it("drafts manifests from a real MCP server and writes them out", async () => {
    const sandbox = join(dir, "sb");
    mkdirSync(sandbox);
    const out = join(dir, "drafts");
    const r = await cli("suggest-manifest", "--upstream-cmd", "node", "--upstream-arg", fs, "--upstream-arg", "serve", "--upstream-arg", "fs", "--upstream-arg", "--root", "--upstream-arg", sandbox, "-o", out);
    expect(r.code).toBe(0);
    const files = readdirSync(out);
    expect(files).toContain("fs.write_file.yaml");
    expect(readFileSync(join(out, "fs.write_file.yaml"), "utf8")).toContain("DRAFT");
    expect(r.err).toContain("drafted");
  });
});

describe("rollback read-back and approvals through the engine", () => {
  it("--reader-cmd runs a manifest's declared verification; without it the step is reported unverified", async () => {
    const m = join(dir, "m.yaml");
    writeFileSync(m, `- tool: shop.cancel\n  effect: idempotent\n  permission: s:w\n- tool: shop.get\n  effect: read_only\n  permission: s:r\n- tool: shop.create\n  effect: reversible\n  permission: s:w\n  compensation:\n    tool: shop.cancel\n    argument_map: { id: $result.id }\n    verification:\n      tool: shop.get\n      arguments: { id: $result.id }\n      expect: { status: canceled }\n      retries: 1\n      backoff_ms: 1\n`);
    const data = join(dir, "d");
    const { Reversi, Ledger, JsonlLedgerStore, FileRunStore, SealedScope, loadRegistry } = await import("@multimindlab/reversi");
    const rv = new Reversi({ registry: loadRegistry(m), ledger: new Ledger(new JsonlLedgerStore(join(data, "ledger.jsonl"))), runs: new FileRunStore(join(data, "runs")) });
    const run = rv.startRun({ run_id: "v1", actor: "a", scope: SealedScope.seal(["s:w", "s:r"]) });
    await run.call({ tool: "shop.create", reason: "x", execute: () => ({ id: "o9" }) });
    const base = ["rollback", "v1", "-m", m, "-d", data, "--compensator-cmd", "cat > /dev/null"];
    const no = await cli(...base);
    expect(no.code).toBe(2);
    expect(no.out).toContain("not verified");
    const ok = await cli(...base, "--reader-cmd", `cat > /dev/null; echo '{"status":"canceled"}'`);
    expect(ok.out).toContain("rollback complete");
  });

  it("an approval decided from the CLI is journaled in the ledger", async () => {
    const data = join(dir, "d2");
    const m = join(dir, "m2.yaml");
    writeFileSync(m, "- tool: shop.pay\n  effect: idempotent\n  permission: s:w\n  approval: always\n");
    const { Reversi, Ledger, JsonlLedgerStore, FileRunStore, FileApprovalStore, Approvals, SealedScope, loadRegistry } = await import("@multimindlab/reversi");
    const approvals = new Approvals(new FileApprovalStore(join(data, "approvals.json")));
    const rv = new Reversi({ registry: loadRegistry(m), ledger: new Ledger(new JsonlLedgerStore(join(data, "ledger.jsonl"))), runs: new FileRunStore(join(data, "runs")), approver: approvals.asApprover() });
    const run = rv.startRun({ run_id: "p1", actor: "a", scope: SealedScope.seal(["s:w"]) });
    await run.call({ tool: "shop.pay", reason: "x", execute: () => 1 });
    const id = approvals.list({ status: "pending" })[0]!.id;
    const r = await cli("approvals", "approve", id, "-d", data, "--as", "dana", "--note", "ok");
    expect(r.out).toBe(`${id} approved by dana`);
    expect(readFileSync(join(data, "ledger.jsonl"), "utf8")).toContain(`approval ${id} approved by dana`);
  });
});

describe("commands that read manifests accept a registry folder", () => {
  it("validate and lint work on it", async () => {
    const reg = join(dir, "r");
    new ManifestRegistry(reg).publish({ tool: "shop.read", effect: "read_only", permission: "s:r" }, { by: "t", status: "approved" });
    expect((await cli("validate", reg)).code).toBe(0);
    const lint = await cli("lint", reg);
    expect(lint.code).toBe(0);
  });
});
