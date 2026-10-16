/**
 * `reversi apply <dir>`: make a registry (and policy) match a directory in git. A directory holds manifests (`manifests/*.yaml`,
 * or yaml/json files at the top) and optionally `policy.yaml`. It is compared with the target, a local registry or a running
 * server, and only what differs is published. Nothing is deleted: `--prune` deprecates tools that left the directory.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import type { Command } from "commander";
import { ManifestRegistry, PolicyVersions, canonicalize, sha256Hex, validateManifest, type SigningKey } from "@multimindlab/reversi";
import { Fail, type Ctx } from "../context.js";
import { readManifests } from "./manifests.js";

interface Current {
  manifests: Map<string, { version: number; status: string; manifest: Record<string, unknown> }>;
  policy_checksum: string | null;
}
interface Target {
  read(): Promise<Current>;
  publish(manifest: Record<string, unknown>, status: "draft" | "approved", note: string | undefined): Promise<number>;
  deprecate(tool: string): Promise<void>;
  publishPolicy(text: string, note: string | undefined): Promise<number>;
}

export interface ApplyChange {
  kind: "manifest" | "policy";
  action: "create" | "update" | "deprecate" | "unchanged";
  name: string;
  detail?: string;
}

const me = () => {
  try {
    return userInfo().username;
  } catch {
    return "cli";
  }
};

/** Content that matters when comparing: everything except the registry-assigned version and status. */
const essence = (m: Record<string, unknown>): string => {
  const r = validateManifest(m); // both sides in normalized form, so defaults do not show up as differences
  const { version: _v, status: _s, ...rest } = (r.ok ? r.manifest : m) as unknown as Record<string, unknown>;
  return canonicalize(rest);
};

export function readDesired(dir: string): { manifests: Record<string, unknown>[]; policy?: string } {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Fail(`not a directory: ${dir}`);
  const mdir = existsSync(join(dir, "manifests")) ? join(dir, "manifests") : dir;
  const files = mdir === dir ? readManifestsTop(dir) : readManifests(mdir);
  const manifests: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  for (const raw of files) {
    const r = validateManifest(raw);
    if (!r.ok) throw new Fail(`invalid manifest ${(raw as { tool?: string }).tool ?? "?"}: ${r.errors.join("; ")}`);
    if (seen.has(r.manifest.tool)) throw new Fail(`duplicate manifest for \`${r.manifest.tool}\` in ${dir}`);
    seen.add(r.manifest.tool);
    manifests.push(raw as Record<string, unknown>);
  }
  const pf = ["policy.yaml", "policy.yml", "policy.json"].map((f) => join(dir, f)).find((f) => existsSync(f));
  return { manifests, ...(pf ? { policy: readFileSync(pf, "utf8") } : {}) };
}

/** A directory that is itself the manifest folder: policy.* files are not manifests. */
function readManifestsTop(dir: string): unknown[] {
  const all = readManifests(dir) as Array<Record<string, unknown>>;
  return all.filter((m) => typeof m === "object" && m !== null && "tool" in m);
}

export function plan(desired: ReturnType<typeof readDesired>, current: Current, o: { prune: boolean }): ApplyChange[] {
  const out: ApplyChange[] = [];
  for (const raw of desired.manifests) {
    const tool = (raw as { tool: string }).tool;
    const have = current.manifests.get(tool);
    if (!have) out.push({ kind: "manifest", action: "create", name: tool });
    else if (have.status === "deprecated" && (raw as { status?: string }).status !== "deprecated") out.push({ kind: "manifest", action: "update", name: tool, detail: `was deprecated at v${have.version}` });
    else if (essence(have.manifest) !== essence(raw)) out.push({ kind: "manifest", action: "update", name: tool, detail: `v${have.version} differs` });
    else out.push({ kind: "manifest", action: "unchanged", name: tool });
  }
  if (o.prune) {
    const wanted = new Set(desired.manifests.map((m) => (m as { tool: string }).tool));
    for (const [tool, have] of current.manifests) if (!wanted.has(tool) && have.status !== "deprecated") out.push({ kind: "manifest", action: "deprecate", name: tool, detail: "not in the directory" });
  }
  if (desired.policy !== undefined) {
    const sum = sha256Hex(desired.policy);
    out.push({ kind: "policy", action: current.policy_checksum === null ? "create" : current.policy_checksum === sum ? "unchanged" : "update", name: "policy" });
  }
  return out;
}

function localTarget(registryDir: string, policyDir: string | undefined, by: string, key: SigningKey | undefined): Target {
  const reg = new ManifestRegistry(registryDir);
  return {
    async read() {
      const manifests: Current["manifests"] = new Map();
      if (ManifestRegistry.isRegistry(registryDir)) {
        for (const t of reg.tools()) {
          const cur = reg.history(t).at(-1);
          if (cur) manifests.set(t, { version: cur.version, status: cur.status, manifest: reg.get(t, cur.version) as unknown as Record<string, unknown> });
        }
      }
      let policy_checksum: string | null = null;
      if (policyDir) {
        const pv = new PolicyVersions(policyDir);
        const a = pv.activeVersion();
        policy_checksum = a === null ? null : (pv.history().find((h) => h.version === a)?.checksum ?? null);
      }
      return { manifests, policy_checksum };
    },
    async publish(m, status, note) {
      return reg.publish(m, { by, note, status, key }).version;
    },
    async deprecate(tool) {
      reg.deprecate(tool, { by, key });
    },
    async publishPolicy(text, note) {
      if (!policyDir) throw new Fail("no policy folder: pass --policy-dir, or leave policy.yaml out of the directory");
      return new PolicyVersions(policyDir).publish(text, { by, note, activate: true }).version;
    },
  };
}

function remoteTarget(url: string, token: string): Target {
  const base = url.replace(/\/$/, "");
  const call = async (method: string, path: string, body?: unknown): Promise<any> => {
    const res = await fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json: any;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { error: text };
    }
    if (!res.ok) throw new Fail(`${method} ${path}: ${res.status} ${json.error ?? text}`);
    return json;
  };
  return {
    async read() {
      const j = await call("GET", "/v1/registry");
      const manifests: Current["manifests"] = new Map();
      for (const m of j.manifests as Array<{ tool: string; version: number; status: string; manifest: Record<string, unknown> }>) manifests.set(m.tool, m);
      return { manifests, policy_checksum: j.policy?.checksum ?? null };
    },
    async publish(manifest, status, note) {
      return (await call("POST", "/v1/registry/manifests", { manifest, status, note })).version;
    },
    async deprecate(tool) {
      await call("POST", `/v1/registry/manifests/${encodeURIComponent(tool)}/deprecate`, {});
    },
    async publishPolicy(text, note) {
      return (await call("POST", "/v1/registry/policy", { text, note, activate: true })).version;
    },
  };
}

export function registerApplyCommand(program: Command, ctx: Ctx): void {
  const { io } = ctx;
  program
    .command("apply <dir>")
    .description("make a registry (and policy) match a directory kept in git; only differences are published. Nothing is ever deleted")
    .option("--registry <dir>", "the local registry folder (default: `manifests:` in the config)")
    .option("--policy-dir <dir>", "the local policy versions folder (default: `policy:` in the config)")
    .option("--server <url>", "apply to a running Reversi server instead (needs --token)")
    .option("--token <key>", "admin API key for --server (default: REVERSI_TOKEN)")
    .option("--status <status>", "approved (default: the directory is the reviewed source of truth) | draft", "approved")
    .option("--prune", "deprecate tools that are in the target but not in the directory")
    .option("--dry-run", "show what would change and change nothing")
    .option("--detailed-exitcode", "exit 2 when there are changes (with --dry-run: for CI drift checks)")
    .option("--by <name>", "who is applying (default: your user name)")
    .option("--key <file>", "signing key for the new versions")
    .option("--note <text>", "recorded with each new version")
    .action(async (dir: string, o) => {
      if (o.status !== "draft" && o.status !== "approved") throw new Fail("--status must be draft or approved");
      const desired = readDesired(dir);
      let target: Target;
      if (o.server) {
        const token = o.token ?? process.env.REVERSI_TOKEN;
        if (!token) throw new Fail("--server needs --token (or REVERSI_TOKEN)");
        target = remoteTarget(o.server, token);
      } else {
        const p = ctx.project();
        const registryDir = o.registry ?? p?.manifests;
        if (!registryDir) throw new Fail("no registry folder: pass --registry <dir> or --server <url>, or set `manifests:` in reversi.config.yaml");
        if (existsSync(registryDir) && !ManifestRegistry.isRegistry(registryDir) && statSync(registryDir).isDirectory() && readdirSync(registryDir).length > 0) {
          throw new Fail(`${registryDir} holds manifest files but is not a registry: apply into an empty or registry folder`);
        }
        const policyDir = o.policyDir ?? (p?.policy && existsSync(p.policy) && statSync(p.policy).isDirectory() ? p.policy : undefined);
        const key = o.key ? (() => { const private_pem = readFileSync(o.key, "utf8"); return { private_pem, public_pem: createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString() }; })() : undefined;
        target = localTarget(registryDir, policyDir, o.by ?? me(), key);
      }
      const changes = plan(desired, await target.read(), { prune: o.prune === true });
      const pending = changes.filter((c) => c.action !== "unchanged");
      const sign = { create: "+", update: "~", deprecate: "-", unchanged: " " } as const;
      for (const c of changes) io.out(`${sign[c.action]} ${c.kind.padEnd(8)} ${c.name}${c.detail ? `  (${c.detail})` : ""}${c.action === "unchanged" ? "  unchanged" : ""}`);
      io.out(pending.length ? `${pending.length} change${pending.length === 1 ? "" : "s"}${o.dryRun ? " (dry run: nothing applied)" : ""}` : "up to date");
      if (!o.dryRun) {
        for (const c of pending) {
          if (c.kind === "policy") {
            const v = await target.publishPolicy(desired.policy as string, o.note);
            io.out(`applied policy v${v}`);
          } else if (c.action === "deprecate") {
            await target.deprecate(c.name);
            io.out(`deprecated ${c.name}`);
          } else {
            const m = desired.manifests.find((x) => (x as { tool: string }).tool === c.name) as Record<string, unknown>;
            const v = await target.publish(m, o.status, o.note);
            io.out(`applied ${c.name} v${v} (${o.status})`);
          }
        }
      }
      if (o.detailedExitcode && pending.length && o.dryRun) ctx.code = 2;
    });
}
