import { describe, expect, it } from "vitest";
import {
  Approvals,
  FileApprovalStore,
  Ledger,
  MemoryApprovalStore,
  OidcVerifier,
  Policy,
  Registry,
  Reversi,
  SealedScope,
  KeyRing,
} from "../src/index.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, createSign, type JsonWebKey } from "node:crypto";

const MANIFESTS = [{ tool: "refund", effect: "idempotent", permission: "o:w", approval: "always" }];
const ok = () => 1;

function make(approvals: Approvals) {
  const rv = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: approvals.asApprover() });
  return { rv, run: rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["o:w"]) }) };
}

describe("arguments that cannot be hashed", () => {
  it("are blocked, and an approval granted for one such call never covers another", async () => {
    const approvals = new Approvals();
    const { run } = make(approvals);
    // JSON.parse('1e999') is Infinity: the canonical form does not exist, so every such call used to share one hash.
    const a = JSON.parse('{"note":"hi","x":1e999}');
    const b = JSON.parse('{"to":"attacker","amount":9999,"x":1e999}');
    const first = await run.call({ tool: "refund", args: a, reason: "x", execute: ok });
    expect(first).toMatchObject({ status: "blocked", reasons: [expect.stringContaining("cannot be canonicalized")] });
    const pending = approvals.list({ status: "pending" })[0];
    if (pending) approvals.approve(pending.id, "alice");
    expect((await run.call({ tool: "refund", args: b, reason: "x", execute: ok })).status).toBe("blocked");
    expect((await run.call({ tool: "refund", args: a, reason: "x", execute: ok })).status).toBe("blocked");
  });
});

describe("approval store atomicity", () => {
  it("a pre-approval can be consumed exactly once, even by interleaved callers", () => {
    const a = new Approvals(new MemoryApprovalStore());
    a.add("r1", "call", "refund");
    const results = [0, 1, 2, 3].map(() => a.asApprover()({ run_id: "r1", step: null, tool: "refund", reason: "x", kind: "call" }));
    expect(results.filter((r) => r === true)).toHaveLength(1);
  });

  it("transition refuses a stale expectation, in memory and in files", () => {
    const dir = mkdtempSync(join(tmpdir(), "rv-trans-"));
    try {
      for (const store of [new MemoryApprovalStore(), new FileApprovalStore(join(dir, "a.json"))]) {
        const a = new Approvals(store);
        a.add("r1", "call", "refund");
        const rec = a.list()[0];
        expect(store.transition(rec!.id, "approved", { status: "consumed" })).toBe(true);
        expect(store.transition(rec!.id, "approved", { status: "consumed" })).toBe(false);
        expect(store.transition("missing", "approved", { status: "consumed" })).toBe(false);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a second decision on the same request fails and does not overwrite the first", () => {
    const a = new Approvals();
    a.asApprover()({ run_id: "r1", step: null, tool: "refund", reason: "x", kind: "call", args_hash: "h" });
    const id = a.list()[0]!.id;
    a.approve(id, "alice");
    expect(() => a.deny(id, "bob")).toThrow(/not pending/);
    expect(a.get(id)).toMatchObject({ status: "approved", decided_by: "alice" });
  });

  it("decisions are reported to a callback (the ledger, in the engine factory) with who decided", () => {
    const seen: string[] = [];
    const a = new Approvals(undefined, { on_decision: (r, d) => seen.push(`${d}:${r.decided_by}:${r.tool}`) });
    a.asApprover()({ run_id: "r1", step: null, tool: "refund", reason: "x", kind: "call", args_hash: "h" });
    a.approve(a.list()[0]!.id, "alice", "ok");
    expect(seen).toEqual(["approved:alice:refund"]);
    const broken = new Approvals(undefined, { on_decision: () => { throw new Error("ledger down"); } });
    broken.asApprover()({ run_id: "r1", step: null, tool: "refund", reason: "x", kind: "call", args_hash: "h" });
    expect(broken.approve(broken.list()[0]!.id, "alice").status).toBe("approved"); // the decision stands
  });

  it("redacts credentials in the stored reason and decision note", () => {
    const a = new Approvals();
    a.asApprover()({ run_id: "r1", step: null, tool: "refund", reason: "token AKIAABCDEFGHIJKLMNOP", kind: "call", args_hash: "h" });
    const rec = a.approve(a.list()[0]!.id, "alice", "see password=hunter2hunter2");
    expect(JSON.stringify(rec)).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(JSON.stringify(rec)).not.toContain("hunter2hunter2");
  });
});

describe("oidc hardening", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...(rsa.publicKey.export({ format: "jwk" }) as JsonWebKey), kid: "k1", use: "sig", alg: "RS256" };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const token = (claims: Record<string, unknown>) => {
    const data = `${b64({ alg: "RS256", kid: "k1" })}.${b64({ iss: "i", aud: "a", sub: "s", exp: 2_000_000_000, ...claims })}`;
    return `${data}.${createSign("sha256").update(data).sign(rsa.privateKey).toString("base64url")}`;
  };

  it("ignores role values that are inherited object properties", async () => {
    const v = new OidcVerifier({ issuer: "i", audience: "a", role_map: { admin: "admin" }, now: () => 1_900_000_000_000, fetch: (async () => Response.json({ jwks_uri: "x", keys: [jwk] })) as typeof fetch });
    expect(await v.authenticate(token({ roles: ["constructor", "__proto__", "toString"] }))).toBeNull();
    expect(await v.authenticate(token({ roles: ["constructor", "admin"] }))).toMatchObject({ roles: ["admin"] });
  });

  it("stops trusting a key the issuer withdrew, and exposes the token's expiry", async () => {
    let t = 1_900_000_000_000;
    let keys: unknown[] = [jwk];
    const v = new OidcVerifier({ issuer: "i", audience: "a", role_map: { r: "agent" }, now: () => t, fetch: (async () => Response.json({ jwks_uri: "x", keys })) as typeof fetch });
    expect(await v.authenticate(token({ roles: ["r"] }))).toMatchObject({ exp_ms: 2_000_000_000_000 });
    keys = []; // withdrawn
    expect(await v.authenticate(token({ roles: ["r"] }))).not.toBeNull(); // still inside the cache window
    t += 11 * 60_000;
    expect(await v.authenticate(token({ roles: ["r"] }))).toBeNull();
  });

  it("shares one key-set fetch between concurrent callers", async () => {
    let fetches = 0;
    const v = new OidcVerifier({ issuer: "i", audience: "a", role_map: { r: "agent" }, now: () => 1_900_000_000_000, fetch: (async () => { fetches++; await new Promise((r) => setTimeout(r, 20)); return Response.json({ jwks_uri: "x", keys: [jwk] }); }) as typeof fetch });
    const out = await Promise.all([1, 2, 3, 4].map(() => v.authenticate(token({ roles: ["r"] }))));
    expect(out.every((p) => p !== null)).toBe(true);
    expect(fetches).toBeLessThanOrEqual(2); // discovery + jwks, once
  });
});

describe("key ring fingerprints", () => {
  it("finds a live key by fingerprint and forgets it when the key is disabled or removed", () => {
    const ring = new KeyRing([{ name: "a", role: "operator", key: "k1" }]);
    const fp = ring.authenticate("k1")!.fingerprint!;
    expect(ring.byFingerprint(fp)).toMatchObject({ name: "a", roles: ["operator"] });
    ring.replace([{ name: "a", role: "operator", key: "k1", disabled: true }]);
    expect(ring.byFingerprint(fp)).toBeNull();
    ring.replace([{ name: "a", role: "auditor", key: "k1" }]);
    expect(ring.byFingerprint(fp)).toMatchObject({ roles: ["auditor"] }); // demotion shows up
    expect(ring.byFingerprint("nope")).toBeNull();
  });
});

describe("policy limits and rules are unaffected by hardening", () => {
  it("still allows ordinary calls", async () => {
    const policy = Policy.from({ rules: [] });
    expect(policy.evaluate({ tool: "x", effect: null, permission: null, actor: "a", run_id: "r", environment: "dev", args: { n: "5" } }).action).toBe("allow");
  });
});

describe("error text in run state", () => {
  it("is redacted like ledger text", async () => {
    const { run } = make(new Approvals());
    const b = await run.begin({ tool: "refund", reason: "x" });
    // approval is required, so use a manifest-free path: complete a step via a permissive run instead
    expect(b.decision).toBe("block");
    const rv = new Reversi({ registry: Registry.from([{ tool: "t", effect: "idempotent", permission: "p" }]), ledger: new Ledger() });
    const r = rv.startRun({ actor: "a", scope: SealedScope.seal(["p"]) });
    await r.call({ tool: "t", reason: "x", execute: () => { throw new Error("boom token=ghp_" + "a".repeat(36)); } }).catch(() => {});
    expect(JSON.stringify(r.state())).not.toContain("ghp_");
  });
});
