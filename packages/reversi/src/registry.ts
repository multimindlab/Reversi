/**
 * A versioned manifest registry on disk (or served over HTTP as static files).
 *
 *   <dir>/index.json                      the list of tools and their versions, each with a checksum
 *   <dir>/tools/<tool>/v<N>.json          the manifest at that version
 *
 * Every publish makes a new immutable version. Versions start as `draft` and are enforceable only once approved; a
 * deprecated tool keeps its history and still rolls back. Each version's checksum (and, if a signing key is used, an
 * Ed25519 signature over it) is checked when the registry is loaded, so a manifest changed outside the workflow is refused.
 */
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, sha256Hex } from "./canonical.js";
import { renderDiff } from "./diff.js";
import { guardedFetch, type EgressConfig } from "./egress.js";
import { keyId, type SigningKey } from "./evidence.js";
import { Registry, validateManifest, type ManifestStatus, type ToolManifest } from "./manifest.js";

export interface RegistryVersion {
  version: number;
  checksum: string;
  status: ManifestStatus;
  created_ms: number;
  by: string;
  note?: string;
  approved_by?: string;
  signature?: string;
  key_id?: string;
}

interface IndexFile {
  format: "reversi-registry";
  version: 1;
  tools: Record<string, { versions: RegistryVersion[] }>;
}

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

const fileFor = (dir: string, tool: string, v: number) => join(dir, "tools", encodeURIComponent(tool), `v${v}.json`);
const signedText = (tool: string, version: number, checksum: string) => `reversi-manifest:${tool}@${version}:${checksum}`;
const checksumOf = (m: unknown) => sha256Hex(canonicalize(m));

export interface RegistryOptions {
  now?: () => number;
  /** If set, every version must carry a valid signature from this key. */
  trusted_public_pem?: string;
}

export class ManifestRegistry {
  private readonly now: () => number;
  constructor(
    readonly dir: string,
    private readonly opts: RegistryOptions = {},
  ) {
    this.now = opts.now ?? Date.now;
  }

  static isRegistry(dir: string): boolean {
    try {
      return existsSync(join(dir, "index.json")) && (JSON.parse(readFileSync(join(dir, "index.json"), "utf8")) as IndexFile).format === "reversi-registry";
    } catch {
      return false;
    }
  }

  private readIndex(): IndexFile {
    const p = join(this.dir, "index.json");
    if (!existsSync(p)) return { format: "reversi-registry", version: 1, tools: {} };
    return JSON.parse(readFileSync(p, "utf8")) as IndexFile;
  }

  private writeIndex(ix: IndexFile): void {
    mkdirSync(this.dir, { recursive: true });
    const tmp = join(this.dir, `index.json.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(ix, null, 2));
    renameSync(tmp, join(this.dir, "index.json"));
  }

  tools(): string[] {
    return Object.keys(this.readIndex().tools).sort();
  }

  history(tool: string): RegistryVersion[] {
    const t = this.readIndex().tools[tool];
    if (!t) throw new RegistryError(`no tool \`${tool}\` in the registry`);
    return t.versions;
  }

  get(tool: string, version: number): ToolManifest {
    const v = this.history(tool).find((x) => x.version === version);
    if (!v) throw new RegistryError(`\`${tool}\` has no version ${version}`);
    const raw = JSON.parse(readFileSync(fileFor(this.dir, tool, version), "utf8")) as unknown;
    this.check(tool, v, raw);
    const r = validateManifest(raw);
    if (!r.ok) throw new RegistryError(`\`${tool}\` v${version} is not a valid manifest: ${r.errors.join("; ")}`);
    return r.manifest;
  }

  /** Verify a version's checksum, and its signature when a trusted key is configured. */
  private check(tool: string, v: RegistryVersion, raw: unknown): void {
    if (checksumOf(raw) !== v.checksum) throw new RegistryError(`\`${tool}\` v${v.version} was changed outside the registry: its checksum does not match the index`);
    if (this.opts.trusted_public_pem) {
      let ok = false;
      try {
        ok = !!v.signature && verify(null, Buffer.from(signedText(tool, v.version, v.checksum)), createPublicKey(this.opts.trusted_public_pem), Buffer.from(v.signature, "base64"));
      } catch {
        ok = false;
      }
      if (!ok) throw new RegistryError(`\`${tool}\` v${v.version} is not signed by the trusted key`);
    }
  }

  /** Add a new version. It is a draft unless `status` says otherwise. */
  publish(manifest: unknown, o: { by: string; note?: string; status?: ManifestStatus; key?: SigningKey }): { tool: string; version: number; checksum: string } {
    const first = validateManifest(manifest);
    if (!first.ok) throw new RegistryError(first.errors.join("; "));
    const tool = first.manifest.tool;
    const ix = this.readIndex();
    const versions = (ix.tools[tool] ??= { versions: [] }).versions;
    const version = (versions.at(-1)?.version ?? 0) + 1;
    const status = o.status ?? "draft";
    const body = { ...(manifest as Record<string, unknown>), version, status };
    const again = validateManifest(body);
    if (!again.ok) throw new RegistryError(again.errors.join("; "));
    const checksum = checksumOf(body);
    const rec: RegistryVersion = { version, checksum, status, created_ms: this.now(), by: o.by, ...(o.note ? { note: o.note } : {}) };
    if (o.key) {
      rec.signature = sign(null, Buffer.from(signedText(tool, version, checksum)), createPrivateKey(o.key.private_pem)).toString("base64");
      rec.key_id = keyId(o.key.public_pem);
    }
    mkdirSync(join(this.dir, "tools", encodeURIComponent(tool)), { recursive: true });
    writeFileSync(fileFor(this.dir, tool, version), JSON.stringify(body, null, 2));
    versions.push(rec);
    this.writeIndex(ix);
    return { tool, version, checksum };
  }

  /**
   * Promote a draft to approved. It republishes the manifest as a new `approved` version, so the approval is itself a
   * versioned, signed event, and the approver is recorded. With `require_other` the approver may not be the author.
   */
  approve(tool: string, o: { by: string; version?: number; note?: string; key?: SigningKey; require_other?: boolean }): { tool: string; version: number } {
    const hist = this.history(tool);
    const target = hist.find((v) => v.version === (o.version ?? hist.at(-1)?.version));
    if (!target) throw new RegistryError(`\`${tool}\` has no version ${o.version}`);
    if (target.status !== "draft") throw new RegistryError(`\`${tool}\` v${target.version} is ${target.status}, not a draft`);
    if (o.require_other && target.by === o.by) throw new RegistryError("the author of a draft cannot approve it: ask someone else");
    const m = this.get(tool, target.version);
    const out = this.publish({ ...m }, { by: target.by, note: o.note ?? `approved from v${target.version}`, status: "approved", key: o.key });
    const ix = this.readIndex();
    const rec = (ix.tools[tool]?.versions ?? []).find((v) => v.version === out.version);
    if (rec) {
      rec.approved_by = o.by;
      this.writeIndex(ix);
    }
    return { tool, version: out.version };
  }

  /** Mark a tool deprecated (new calls are noted; rollback keeps working), optionally pointing at its replacement. */
  deprecate(tool: string, o: { by: string; replaced_by?: string; note?: string; key?: SigningKey }): { tool: string; version: number } {
    const cur = this.current(tool);
    if (!cur) throw new RegistryError(`\`${tool}\` has no approved version to deprecate`);
    const out = this.publish({ ...cur, status: "deprecated", ...(o.replaced_by ? { replaced_by: o.replaced_by } : {}) }, { by: o.by, note: o.note ?? "deprecated", status: "deprecated", key: o.key });
    return { tool, version: out.version };
  }

  /** Publish an old version again as the newest one (a rollback of the manifest, with history intact). */
  rollbackTo(tool: string, version: number, o: { by: string; key?: SigningKey; note?: string }): { tool: string; version: number } {
    const m = this.get(tool, version);
    const out = this.publish({ ...m }, { by: o.by, note: o.note ?? `restored v${version}`, status: m.status === "draft" ? "draft" : "approved", key: o.key });
    return { tool, version: out.version };
  }

  /** The newest approved or deprecated version of a tool (drafts are not enforceable). */
  current(tool: string, includeDrafts = false): ToolManifest | undefined {
    const t = this.readIndex().tools[tool];
    const v = [...(t?.versions ?? [])].reverse().find((x) => includeDrafts || x.status !== "draft");
    return v ? this.get(tool, v.version) : undefined;
  }

  diff(tool: string, a: number, b: number): string {
    const pretty = (v: number) => JSON.stringify(this.get(tool, v), null, 2);
    return renderDiff(pretty(a), pretty(b), 3);
  }

  /** Everything enforceable, checksum- and signature-verified. */
  load(o: { drafts?: boolean } = {}): Registry {
    const reg = new Registry();
    for (const t of this.tools()) {
      const m = this.current(t, o.drafts);
      if (m) reg.register(m);
    }
    reg.assertValid();
    return reg;
  }

  /** Check every version of every tool; returns problems instead of throwing at the first. */
  verifyAll(): string[] {
    const problems: string[] = [];
    for (const t of this.tools()) {
      let expected = 1;
      for (const v of this.history(t)) {
        if (v.version !== expected++) problems.push(`\`${t}\`: version numbers are not continuous at v${v.version}`);
        try {
          this.get(t, v.version);
        } catch (e) {
          problems.push(e instanceof Error ? e.message : String(e));
        }
      }
    }
    return problems;
  }
}

/** Load a registry served as static files: `<url>/index.json` and `<url>/tools/<tool>/v<N>.json`. */
export async function loadRemoteRegistry(url: string, o: { trusted_public_pem?: string; egress?: EgressConfig; fetch?: typeof fetch; headers?: Record<string, string> } = {}): Promise<Registry> {
  const f = guardedFetch(o.egress, o.fetch);
  const base = url.replace(/\/$/, "");
  const get = async (path: string) => {
    const res = await f(`${base}/${path}`, { headers: o.headers, signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new RegistryError(`${base}/${path} answered ${res.status}`);
    return (await res.json()) as unknown;
  };
  const ix = (await get("index.json")) as IndexFile;
  if (ix?.format !== "reversi-registry") throw new RegistryError(`${base}/index.json is not a Reversi registry`);
  const reg = new Registry();
  for (const [tool, t] of Object.entries(ix.tools)) {
    const v = [...t.versions].reverse().find((x) => x.status !== "draft");
    if (!v) continue;
    const raw = await get(`tools/${encodeURIComponent(tool)}/v${v.version}.json`);
    if (checksumOf(raw) !== v.checksum) throw new RegistryError(`\`${tool}\` v${v.version} does not match its checksum in the index`);
    if (o.trusted_public_pem) {
      let ok = false;
      try {
        ok = !!v.signature && verify(null, Buffer.from(signedText(tool, v.version, v.checksum)), createPublicKey(o.trusted_public_pem), Buffer.from(v.signature, "base64"));
      } catch {
        ok = false;
      }
      if (!ok) throw new RegistryError(`\`${tool}\` v${v.version} is not signed by the trusted key`);
    }
    reg.register(raw);
  }
  reg.assertValid();
  return reg;
}
