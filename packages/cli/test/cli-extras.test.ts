import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Approvals, FileApprovalStore, Policy, Registry, Reversi, SealedScope, Ledger, JsonlLedgerStore, FileRunStore, loadRegistry } from "@multimindlab/reversi";
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
- tool: refund
  effect: idempotent
  permission: orders:write
  approval: always
`;
const POLICY = `
version: 1
rules:
  - id: big-orders
    match: { tool: create_order }
    when: [{ path: $args.qty, op: gt, value: 100 }]
    action: require_approval
tests:
  - name: small order passes
    input: { tool: create_order, args: { qty: 1 } }
    expect: allow
  - name: big order needs approval
    input: { tool: create_order, args: { qty: 500 } }
    expect: require_approval
    rule: big-orders
`;

let dir: string, mpath: string, data: string;
beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "reversi-cli2-"));
  mpath = join(dir, "tools.yaml");
  data = join(dir, "data");
  writeFileSync(mpath, MANIFESTS);
  const approvals = new Approvals(new FileApprovalStore(join(data, "approvals.json")));
  const rv = new Reversi({
    registry: loadRegistry(mpath),
    ledger: new Ledger(new JsonlLedgerStore(join(data, "ledger.jsonl"))),
    runs: new FileRunStore(join(data, "runs")),
    approver: approvals.asApprover(),
  });
  const run = rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["orders:write"]) });
  await run.call({ tool: "create_order", reason: "order", execute: () => ({ id: 11 }) });
  await run.call({ tool: "refund", reason: "needs approval", execute: () => 1 }); // blocked: queues an approval
  const b = await run.begin({ tool: "create_order", reason: "second" });
  if (b.decision === "allow") run.complete(b.step, { status: "uncertain", error: "timeout" });
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function cli(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, { out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

describe("approvals", () => {
  it("lists, approves and denies requests stored by another process", async () => {
    const list = await cli("approvals", "list", "-d", data);
    expect(list.out).toMatch(/apr_\S+  pending  run=r1  call  refund  args=\[\]/);
    const id = /(apr_\S+)/.exec(list.out)?.[1] as string;
    expect((await cli("approvals", "approve", id, "-d", data, "--as", "alice", "--note", "ok")).out).toBe(`${id} approved by alice`);
    expect((await cli("approvals", "approve", id, "-d", data)).code).toBe(1); // no longer pending
    expect((await cli("approvals", "list", "-d", data, "--status", "pending")).out).toBe("no approvals");
    expect((await cli("approvals", "deny", "apr_nope", "-d", data)).err).toContain("not found");
  });
});

describe("resolve and rollback", () => {
  it("resolves the uncertain step with a note and a result, then rolls it back with retries and verification", async () => {
    expect((await cli("resolve", "r1", "1", "-m", mpath, "-d", data, "--status", "succeeded", "--note", "  ")).code).toBe(1);
    const r = await cli("resolve", "r1", "1", "-m", mpath, "-d", data, "--status", "succeeded", "--result", '{"id":12}', "--note", "found in admin UI", "--actor", "dana");
    expect(r.out).toBe("step 1 is now succeeded");
    const ledger = readFileSync(join(data, "ledger.jsonl"), "utf8");
    expect(ledger).toContain("resolved by dana: found in admin UI");

    const seen = join(dir, "seen.log");
    const flaky = join(dir, "flaky");
    const cmd = `if [ ! -f ${flaky} ]; then touch ${flaky}; exit 1; fi; cat >> ${seen}; echo >> ${seen}`;
    const rb = await cli("rollback", "r1", "-m", mpath, "-d", data, "--compensator-cmd", cmd, "--retries", "2", "--verify-cmd", "true");
    expect(rb.out).toContain("compensated: 1, 0");
    expect(rb.out).toContain("rollback complete");
    expect(readFileSync(seen, "utf8")).toContain('"args":{"id":12}');

    const bad = await cli("rollback", "r1", "-m", mpath, "-d", data, "--compensator-cmd", "true", "--retries", "99");
    expect(bad.code).toBe(1);
  });

  it("a failing verify command fails the compensation", async () => {
    await cli("resolve", "r1", "1", "-m", mpath, "-d", data, "--status", "failed", "--note", "never created");
    const rb = await cli("rollback", "r1", "-m", mpath, "-d", data, "--compensator-cmd", "true", "--verify-cmd", "false");
    expect(rb.code).toBe(2);
    expect(rb.out).toContain("verification failed");
  });

  it("--approve-compensations pre-approves compensations that need it", async () => {
    // The requirement is snapshotted when a step runs, so create this run under a manifest that asks for approval.
    const m2 = join(dir, "m2.yaml");
    writeFileSync(m2, MANIFESTS.replace("tool: cancel_order\n    argument_map", "tool: cancel_order\n    requires_approval: true\n    argument_map"));
    const d2 = join(dir, "d2");
    const rv = new Reversi({
      registry: loadRegistry(m2),
      ledger: new Ledger(new JsonlLedgerStore(join(d2, "ledger.jsonl"))),
      runs: new FileRunStore(join(d2, "runs")),
    });
    await rv.startRun({ run_id: "a1", actor: "agent", scope: SealedScope.seal(["orders:write"]) }).call({ tool: "create_order", reason: "x", execute: () => ({ id: 5 }) });
    const without = await cli("rollback", "a1", "-m", m2, "-d", d2, "--compensator-cmd", "true");
    expect(without.code).toBe(2);
    expect(without.out).toContain("awaiting approval: 0");
    const withFlag = await cli("rollback", "a1", "-m", m2, "-d", d2, "--compensator-cmd", "true", "--approve-compensations");
    expect(withFlag.out).toContain("rollback complete");
  });
});

describe("policy", () => {
  it("runs inline tests and reports failures", async () => {
    const p = join(dir, "policy.yaml");
    writeFileSync(p, POLICY);
    const ok = await cli("policy", "test", p);
    expect(ok).toMatchObject({ code: 0 });
    expect(ok.out).toContain("ok   big order needs approval");
    expect(ok.out).toContain("2 passed");
    const extra = join(dir, "more.yaml");
    writeFileSync(extra, "- name: wrong\n  input: { tool: create_order, args: { qty: 500 } }\n  expect: allow\n");
    const bad = await cli("policy", "test", p, extra);
    expect(bad.code).toBe(1);
    expect(bad.out).toContain("FAIL wrong: expected allow, got require_approval");
    expect((await cli("policy", "check", p)).out).toBe("ok: 1 rules, 0 limits, default allow");
    writeFileSync(p, "rules: [{ id: a, action: nope }]");
    expect((await cli("policy", "check", p)).code).toBe(1);
  });
});

describe("kill switch", () => {
  it("creates and removes the file that engines watch", async () => {
    const f = join(dir, "STOP");
    await cli("kill-switch", "on", f);
    expect(existsSync(f)).toBe(true);
    const rv = new Reversi({ registry: Registry.from([{ tool: "t", effect: "read_only", permission: "p" }]), ledger: new Ledger(), kill_switch_file: f });
    const run = rv.startRun({ actor: "a", scope: SealedScope.seal(["p"]) });
    expect((await run.call({ tool: "t", reason: "x", execute: () => 1 })).status).toBe("blocked");
    await cli("kill-switch", "off", f);
    expect((await run.call({ tool: "t", reason: "x", execute: () => 1 })).status).toBe("executed");
    expect((await cli("kill-switch", "maybe", f)).code).toBe(1);
  });
});

describe("evidence", () => {
  it("keygen, bundle, verify-bundle (with a trusted key and after tampering), report", async () => {
    const prefix = join(dir, "sign");
    expect((await cli("keygen", prefix)).out).toMatch(/key id [0-9a-f]{16}/);
    expect((await cli("keygen", prefix)).code).toBe(1); // never overwrites
    expect(readFileSync(`${prefix}.key`, "utf8")).toContain("PRIVATE KEY");

    const out = join(dir, "bundle.json");
    expect((await cli("bundle", "-d", data, "--key", `${prefix}.key`, "--out", out)).out).toContain("wrote");
    const v = await cli("verify-bundle", out);
    expect(v.out).toContain("hash chain verified");
    expect(v.out).toContain("NOT checked against a trusted key");
    expect((await cli("verify-bundle", out, "--pub", `${prefix}.pub`)).out).toContain("(trusted)");

    const runBundle = join(dir, "run.json");
    await cli("bundle", "-d", data, "--key", `${prefix}.key`, "--out", runBundle, "--run", "r1");
    expect((await cli("verify-bundle", runBundle)).out).toContain("single run");
    expect((await cli("bundle", "-d", data, "--key", `${prefix}.key`, "--out", out, "--run", "ghost")).code).toBe(1);

    writeFileSync(out, readFileSync(out, "utf8").replace('"create_order"', '"delete_all"'));
    const bad = await cli("verify-bundle", out);
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("INVALID");

    const html = join(dir, "r.html");
    await cli("report", "r1", "-m", mpath, "-d", data, "--out", html);
    expect(readFileSync(html, "utf8")).toContain("Run r1");
  });
});

describe("sqlite store", () => {
  it("runs, plans, exports and verifies from a SQLite store", async () => {
    const { openSqliteStores } = await import("@multimindlab/reversi/sqlite");
    const d2 = join(dir, "sq");
    const s = openSqliteStores(join(d2, "reversi.db"));
    const rv = new Reversi({ registry: loadRegistry(mpath), ledger: new Ledger(s.ledger), runs: s.runs });
    await rv.startRun({ run_id: "s1", actor: "agent", scope: SealedScope.seal(["orders:write"]) }).call({ tool: "create_order", reason: "x", execute: () => ({ id: 3 }) });
    s.db.close();
    const common = ["-m", mpath, "-d", d2, "--store", "sqlite"];
    expect((await cli("runs", ...common)).out).toContain("s1  actor=agent");
    expect((await cli("plan", "s1", ...common)).out).toContain("cancel_order");
    expect((await cli("export", "-d", d2, "--store", "sqlite")).out.split("\n")).toHaveLength(3);
    expect((await cli("verify", "-d", d2, "--store", "sqlite")).out).toMatch(/^ok: 3 records/);
    expect((await cli("runs", "-m", mpath, "-d", d2, "--store", "bogus")).code).toBe(1);
    expect((await cli("runs", "-m", mpath, "-d", d2, "--store", "postgres")).err).toContain("connection URL");
  });
});
