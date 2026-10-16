/**
 * Versioned policy files. Publishing validates the policy and runs its own tests (a policy whose tests fail is refused);
 * activating a version makes it the one the engine loads; rollback re-activates an older one. Everything keeps its
 * history, checksum and author.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { sha256Hex } from "./canonical.js";
import { renderDiff } from "./diff.js";
import { parsePolicy, runPolicyTests, type PolicyDoc } from "./policy.js";

export interface PolicyVersion {
  version: number;
  checksum: string;
  created_ms: number;
  by: string;
  note?: string;
  tests_passed: number;
}
interface PolicyIndex {
  format: "reversi-policy-versions";
  version: 1;
  active: number | null;
  versions: PolicyVersion[];
}

export class PolicyVersionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyVersionError";
  }
}

export class PolicyVersions {
  constructor(
    readonly dir: string,
    private readonly now: () => number = Date.now,
  ) {}

  static isVersioned(dir: string): boolean {
    try {
      return (JSON.parse(readFileSync(join(dir, "policy-index.json"), "utf8")) as PolicyIndex).format === "reversi-policy-versions";
    } catch {
      return false;
    }
  }

  private read(): PolicyIndex {
    const p = join(this.dir, "policy-index.json");
    return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as PolicyIndex) : { format: "reversi-policy-versions", version: 1, active: null, versions: [] };
  }
  private write(ix: PolicyIndex): void {
    mkdirSync(this.dir, { recursive: true });
    const tmp = join(this.dir, `policy-index.json.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(ix, null, 2));
    renameSync(tmp, join(this.dir, "policy-index.json"));
  }
  private file(v: number) {
    return join(this.dir, `policy-v${v}.yaml`);
  }

  history(): PolicyVersion[] {
    return this.read().versions;
  }
  activeVersion(): number | null {
    return this.read().active;
  }

  text(version: number): string {
    const v = this.read().versions.find((x) => x.version === version);
    if (!v) throw new PolicyVersionError(`there is no policy version ${version}`);
    const text = readFileSync(this.file(version), "utf8");
    if (sha256Hex(text) !== v.checksum) throw new PolicyVersionError(`policy v${version} was changed outside the version history: its checksum does not match`);
    return text;
  }

  activeText(): string | undefined {
    const a = this.read().active;
    return a === null ? undefined : this.text(a);
  }

  doc(version: number): PolicyDoc {
    return parsePolicy(parseYaml(this.text(version)));
  }

  /** Validate, run the policy's own tests, store as a new version, and (by default) make it active. */
  publish(text: string, o: { by: string; note?: string; activate?: boolean; allow_failing_tests?: boolean }): PolicyVersion {
    const doc = parsePolicy(parseYaml(text));
    const results = runPolicyTests(doc);
    const failed = results.filter((r) => !r.ok);
    if (failed.length && !o.allow_failing_tests) throw new PolicyVersionError(`${failed.length} of the policy's own tests fail: ${failed.map((f) => f.name).join(", ")}`);
    const ix = this.read();
    const version = (ix.versions.at(-1)?.version ?? 0) + 1;
    mkdirSync(this.dir, { recursive: true });
    writeFileSync(this.file(version), text);
    const rec: PolicyVersion = { version, checksum: sha256Hex(text), created_ms: this.now(), by: o.by, ...(o.note ? { note: o.note } : {}), tests_passed: results.length - failed.length };
    ix.versions.push(rec);
    if (o.activate !== false) ix.active = version;
    this.write(ix);
    return rec;
  }

  activate(version: number): void {
    const ix = this.read();
    if (!ix.versions.some((v) => v.version === version)) throw new PolicyVersionError(`there is no policy version ${version}`);
    this.text(version); // refuses a tampered file
    ix.active = version;
    this.write(ix);
  }

  diff(a: number, b: number): string {
    return renderDiff(this.text(a), this.text(b), 3);
  }
}
