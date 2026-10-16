import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  ManifestRegistry,
  PolicyVersions,
  ProjectConfigError,
  findProjectConfig,
  generateSigningKey,
  loadProjectConfig,
  openEngine,
  readAnchors,
  SealedScope,
  starterConfig,
  type EngineHandle,
} from "../src/index.js";

const dirs: string[] = [];
const open: EngineHandle[] = [];
afterEach(async () => {
  while (open.length) await (open.pop() as EngineHandle).close();
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "rv-cfg-"));
  dirs.push(d);
  return d;
};
const log = () => {
  const lines: string[] = [];
  return { lines, fn: (l: string, m: string) => lines.push(`${l}: ${m}`) };
};

const MANIFESTS = [
  { tool: "orders.create", effect: "reversible", permission: "p", compensation: { tool: "orders.cancel", argument_map: { id: "$result.id" } } },
  { tool: "orders.cancel", effect: "idempotent", permission: "p" },
  { tool: "mail.send", effect: "irreversible", permission: "p" },
];
const scope = () => SealedScope.seal(["p"]);

function folder(manifests = MANIFESTS) {
  const dir = tmp();
  writeFileSync(join(dir, "tools.json"), JSON.stringify(manifests));
  return dir;
}

describe("openEngine: sources", () => {
  it("loads a folder, a signed registry and a versioned policy", async () => {
    const dir = tmp();
    const key = generateSigningKey();
    const reg = new ManifestRegistry(join(dir, "registry"));
    for (const m of MANIFESTS) reg.publish(m, { by: "ci", status: "approved", key });
    writeFileSync(join(dir, "pub.pem"), key.public_pem);
    const pv = new PolicyVersions(join(dir, "policy"));
    pv.publish("version: 1\nrules:\n  - id: no-mail\n    match: { tool: mail.send }\n    action: deny\n", { by: "ci" });
    const h = await openEngine({ manifests: join(dir, "registry"), manifest_public_key: join(dir, "pub.pem"), policy: join(dir, "policy"), data: { dir: join(dir, "data") }, log: () => {} });
    open.push(h);
    expect(h.registry.size).toBe(3);
    const run = h.reversi.startRun({ actor: "a", scope: scope() });
    expect((await run.call({ tool: "mail.send", reason: "x", execute: () => 1 })).status).toBe("blocked");
    // an unsigned manifest slipped into the registry is refused at start
    new ManifestRegistry(join(dir, "registry")).publish({ tool: "evil", effect: "read_only", permission: "p" }, { by: "mallory", status: "approved" });
    await expect(openEngine({ manifests: join(dir, "registry"), manifest_public_key: join(dir, "pub.pem"), data: { dir: join(dir, "d2") }, log: () => {} })).rejects.toThrow(/not signed by the trusted key/);
  });

  it("loads from a URL through the egress rules", async () => {
    const dir = tmp();
    const reg = new ManifestRegistry(join(dir, "registry"));
    for (const m of MANIFESTS) reg.publish(m, { by: "ci", status: "approved" });
    const server = createServer((req, res) => {
      try {
        res.writeHead(200).end(readFileSync(join(dir, "registry", decodeURIComponent((req.url ?? "").slice(1))), "utf8"));
      } catch {
        res.writeHead(404).end();
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const h = await openEngine({ manifests: url, data: { dir: join(dir, "data") }, log: () => {} });
      open.push(h);
      expect(h.registry.size).toBe(3);
      await expect(openEngine({ manifests: url, egress: { allow: ["*.example.com"] }, data: { dir: join(dir, "d2") }, log: () => {} })).rejects.toThrow(/allowlist/);
    } finally {
      server.close();
    }
  });

  it("starts with no manifests only when asked (the observe-first gateway)", async () => {
    const dir = tmp();
    await expect(openEngine({ manifests: "", data: { dir } })).rejects.toThrow(/no manifests/);
    const h = await openEngine({ manifests: "", allow_empty_manifests: true, data: { dir }, log: () => {} });
    open.push(h);
    expect(h.registry.size).toBe(0);
  });
});

describe("hot reload", () => {
  it("picks up changed manifests and policy, records it, and keeps the old ones when the new ones are broken", async () => {
    const dir = folder();
    const manifests = join(dir, "manifests");
    mkdirSync(manifests);
    writeFileSync(join(manifests, "tools.json"), readFileSync(join(dir, "tools.json")));
    const policy = join(dir, "policy.yaml");
    writeFileSync(policy, "version: 1\nrules: []\n");
    const l = log();
    const h = await openEngine({ manifests, policy, data: { dir: join(dir, "data") }, log: l.fn });
    open.push(h);
    const run = h.reversi.startRun({ actor: "a", scope: scope() });
    expect((await run.call({ tool: "orders.cancel", reason: "x", execute: () => 1 })).status).toBe("executed");
    expect(await h.reload()).toMatchObject({ changed: false, tools: 3 });

    writeFileSync(policy, "version: 1\nrules:\n  - id: freeze-cancel\n    match: { tool: orders.cancel }\n    action: deny\n");
    expect(await h.reload("alice")).toMatchObject({ changed: true });
    expect((await run.call({ tool: "orders.cancel", reason: "x", execute: () => 1 })).status).toBe("blocked");
    const ev = h.reversi.ledger.records().filter((r) => r.event === "reloaded");
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ actor: "alice", run_id: "-" });
    expect(ev[0]?.detail).toMatch(/^3 manifests; policy [0-9a-f]{8}$/);

    // a broken edit changes nothing and says why
    writeFileSync(policy, "rules: [{ id: a, action: nope }]");
    const bad = await h.reload();
    expect(bad.changed).toBe(false);
    expect(bad.error).toContain("action must be");
    expect((await run.call({ tool: "orders.cancel", reason: "x", execute: () => 1 })).status).toBe("blocked"); // still the previous policy
    expect(l.lines.some((x) => x.startsWith("error: reload failed, keeping the previous"))).toBe(true);

    // manifests too
    writeFileSync(join(manifests, "tools.json"), JSON.stringify([...MANIFESTS, { tool: "extra", effect: "read_only", permission: "p" }]));
    writeFileSync(policy, "version: 1\nrules: []\n");
    expect(await h.reload()).toMatchObject({ changed: true, tools: 4 });
    expect(h.reversi.registry.has("extra")).toBe(true);
  });

  it("watch() reloads by itself when a file changes", async () => {
    const dir = folder();
    const h = await openEngine({ manifests: dir, data: { dir: join(dir, "data") }, log: () => {} });
    open.push(h);
    h.watch(30);
    await new Promise((r) => setTimeout(r, 80));
    writeFileSync(join(dir, "tools.json"), JSON.stringify([...MANIFESTS, { tool: "watched", effect: "read_only", permission: "p" }]));
    for (let i = 0; i < 50 && !h.reversi.registry.has("watched"); i++) await new Promise((r) => setTimeout(r, 40));
    expect(h.reversi.registry.has("watched")).toBe(true);
  });
});

describe("openEngine: wiring", () => {
  it("sends approval notifications through configured channels, and capture and anchors work", async () => {
    const dir = folder();
    const posts: any[] = [];
    const server = createServer((req, res) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        posts.push({ url: req.url, body: JSON.parse(b) });
        res.end("ok");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const key = generateSigningKey();
      writeFileSync(join(dir, "sign.key"), key.private_pem);
      const h = await openEngine({
        manifests: dir,
        data: { dir: join(dir, "data"), store: "sqlite" },
        console_url: "https://r.example.com",
        signing_key: join(dir, "sign.key"),
        capture: { enabled: true },
        notifications: { channels: [{ type: "webhook", name: "ops", url: `${base}/ops` }], routes: [{ events: ["approval_requested", "approval_decided", "rollback_failed"], channels: ["ops"] }] },
        anchor: { sinks: [{ type: "file", path: join(dir, "anchors.jsonl") }], interval_ms: 3_600_000 },
        log: () => {},
      });
      open.push(h);
      h.start();
      const run = h.reversi.startRun({ actor: "agent", scope: scope() });
      await run.call({ tool: "mail.send", args: { to: "ada@example.com" }, reason: "x", execute: () => 1 }); // needs approval
      const pending = h.approvals.list({ status: "pending" })[0]!;
      h.approvals.approve(pending.id, "alice");
      await new Promise((r) => setTimeout(r, 100));
      expect(posts.map((p) => p.body.event)).toEqual(["approval_requested", "approval_decided"]);
      expect(posts[0].body.link).toBe("https://r.example.com/console/approvals");
      expect(JSON.stringify(posts)).not.toContain("ada@example.com");
      expect(h.capture?.list({ run_id: run.run_id })[0]).toMatchObject({ tool: "mail.send", args: { to: "[PII:email]" }, decision: "block" });
      await new Promise((r) => setTimeout(r, 100));
      expect(readAnchors(join(dir, "anchors.jsonl"))[0]).toMatchObject({ format: "reversi-anchor", key_id: expect.any(String) });
      expect(h.signing_key?.public_pem).toBe(key.public_pem);
    } finally {
      server.close();
    }
  });
});

describe("project config file", () => {
  it("is found by walking up, expands environment variables, resolves paths against the file, and rejects mistakes", () => {
    const root = tmp();
    mkdirSync(join(root, "a", "b"), { recursive: true });
    writeFileSync(
      join(root, "reversi.config.yaml"),
      `manifests: ./manifests
policy: https://example.com/policy.yaml
data: { dir: ./data, store: sqlite }
approval: { ttl: 30m, webhook: "\${HOOK}" }
capture: { enabled: true, ttl: 2d }
notifications:
  channels: [{ type: webhook, name: w, url: "\${HOOK}" }]
anchor: { sinks: [{ type: file, path: ./anchors.jsonl }], interval: 1h }
console: { mode: open, role: operator }
`,
    );
    expect(findProjectConfig(join(root, "a", "b"), undefined, {})).toBe(join(root, "reversi.config.yaml"));
    expect(findProjectConfig(tmp(), undefined, {})).toBeUndefined();
    const c = loadProjectConfig(join(root, "reversi.config.yaml"), { HOOK: "https://hooks.example.com/x" });
    expect(c).toMatchObject({
      manifests: join(root, "manifests"),
      policy: "https://example.com/policy.yaml",
      data: { dir: join(root, "data"), store: "sqlite" },
      approval: { ttl_ms: 1_800_000, webhook: "https://hooks.example.com/x" },
      capture: { enabled: true, ttl_ms: 172_800_000 },
      anchor: { sinks: [{ type: "file", path: join(root, "anchors.jsonl") }], interval_ms: 3_600_000 },
      console: { mode: "open", role: "operator" },
    });
    expect(c.notifications?.routes[0]).toMatchObject({ events: ["*"], channels: ["w"] }); // no routes given: everything goes to every channel
    expect(() => loadProjectConfig(join(root, "reversi.config.yaml"), {})).toThrow(/environment variable HOOK is not set/);
  });

  it("reports every mistake", () => {
    const f = join(tmp(), "reversi.config.yaml");
    writeFileSync(f, "mystery: 1\ndata: { store: oracle }\nconsole: { mode: open, role: admin }\ncapture: { ttl: soon }\nanchor: { sinks: [] }\n");
    try {
      loadProjectConfig(f, {});
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ProjectConfigError);
      const m = (e as ProjectConfigError).errors.join("\n");
      expect(m).toContain("unknown setting `mystery`");
      expect(m).toContain("data.store must be files, sqlite or postgres");
      expect(m).toContain("never admin");
      expect(m).toContain("capture.ttl must be a duration");
      expect(m).toContain("anchor needs a list of sinks");
    }
    expect(() => findProjectConfig(tmp(), "/nonexistent/reversi.config.yaml", {})).toThrow(/not found/);
  });

  it("the starter config from `reversi init` is itself valid", () => {
    const f = join(tmp(), "reversi.config.yaml");
    writeFileSync(f, starterConfig({ store: "sqlite" }));
    expect(loadProjectConfig(f, {})).toMatchObject({ data: { store: "sqlite" }, environment: "dev" });
  });
});
