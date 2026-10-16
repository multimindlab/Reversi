/** The manifest registry and versioned policies: publish, approve, deprecate, history, diff, roll back, verify. */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { userInfo } from "node:os";
import { extname, join } from "node:path";
import type { Command } from "commander";
import { parse as parseYaml } from "yaml";
import { ManifestRegistry, PolicyVersions, RegistryError, loadRegistry, type SigningKey } from "@multimindlab/reversi";
import { Fail, type Ctx } from "../context.js";

const me = () => {
  try {
    return userInfo().username;
  } catch {
    return "cli";
  }
};

function loadKey(path: string | undefined): SigningKey | undefined {
  if (!path) return undefined;
  const private_pem = readFileSync(path, "utf8");
  return { private_pem, public_pem: createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString() };
}

export function manifestFiles(path: string): string[] {
  const st = statSync(path);
  if (st.isFile()) return [path];
  return readdirSync(path)
    .filter((f) => /\.(ya?ml|json)$/i.test(f))
    .sort()
    .map((f) => join(path, f));
}

export function readManifests(path: string): unknown[] {
  return manifestFiles(path).flatMap((f) => {
    const text = readFileSync(f, "utf8");
    const doc = extname(f).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
    return Array.isArray(doc) ? doc : [doc];
  });
}

export function registerManifestCommands(program: Command, ctx: Ctx): void {
  const { io } = ctx;
  const registryDir = (o: { registry?: string }): string => {
    const dir = o.registry ?? ctx.project()?.manifests;
    if (!dir) throw new Fail("no registry folder: pass --registry <dir>, or set `manifests:` to a registry folder in reversi.config.yaml");
    if (existsSync(dir) && statSync(dir).isDirectory() && readdirSync(dir).length > 0 && !ManifestRegistry.isRegistry(dir)) {
      throw new Fail(`${dir} holds manifest files but is not a registry: publish them with \`reversi manifests publish\` into an empty or registry folder`);
    }
    return dir;
  };
  const opened = (o: { registry?: string; trust?: string }) =>
    new ManifestRegistry(registryDir(o), { trusted_public_pem: o.trust ? readFileSync(o.trust, "utf8") : undefined });
  const common = (c: Command) =>
    c.option("--registry <dir>", "the registry folder (default: `manifests:` in the config)").option("--by <name>", "who is doing this (default: your user name)").option("--key <file>", "signing key (from `reversi keygen`) to sign the new version").option("--note <text>", "why");

  const group = program.command("manifests").description("a versioned, signable registry of manifests");

  common(group.command("publish <path>").description("add manifests (a file or folder) to the registry as new versions").option("--status <status>", "draft | approved (default draft: someone else approves)", "draft")).action((path: string, o: { registry?: string; by?: string; key?: string; note?: string; status: string }) => {
    if (o.status !== "draft" && o.status !== "approved") throw new Fail("--status must be draft or approved");
    const reg = opened(o);
    const key = loadKey(o.key);
    for (const m of readManifests(path)) {
      const r = reg.publish(m, { by: o.by ?? me(), note: o.note, status: o.status, key });
      io.out(`${r.tool}  v${r.version}  ${o.status}  ${r.checksum.slice(0, 12)}`);
    }
  });

  common(group.command("approve <tool>").description("promote a draft to approved (a new, signed version)").option("--version <n>", "the draft version (default: the latest)").option("--four-eyes", "the author may not approve their own draft")).action((tool: string, o: { registry?: string; by?: string; key?: string; note?: string; version?: string; fourEyes?: boolean }) => {
    const r = opened(o).approve(tool, { by: o.by ?? me(), version: o.version ? Number(o.version) : undefined, note: o.note, key: loadKey(o.key), require_other: o.fourEyes });
    io.out(`${r.tool}  v${r.version}  approved by ${o.by ?? me()}`);
  });

  common(group.command("deprecate <tool>").description("keep a tool working and rolling back, but flag new calls and point to its replacement").option("--replaced-by <tool>")).action((tool: string, o: { registry?: string; by?: string; key?: string; note?: string; replacedBy?: string }) => {
    const r = opened(o).deprecate(tool, { by: o.by ?? me(), replaced_by: o.replacedBy, note: o.note, key: loadKey(o.key) });
    io.out(`${r.tool}  v${r.version}  deprecated${o.replacedBy ? `; use ${o.replacedBy}` : ""}`);
  });

  common(group.command("rollback <tool> <version>").description("publish an old version again as the newest")).action((tool: string, version: string, o: { registry?: string; by?: string; key?: string; note?: string }) => {
    const r = opened(o).rollbackTo(tool, Number(version), { by: o.by ?? me(), key: loadKey(o.key), note: o.note });
    io.out(`${r.tool}  v${r.version}  (restored from v${version})`);
  });

  group
    .command("history <tool>")
    .option("--registry <dir>")
    .description("every version of a tool")
    .action((tool: string, o: { registry?: string }) => {
      for (const v of opened(o).history(tool)) io.out(`v${v.version}  ${v.status.padEnd(10)}  ${new Date(v.created_ms).toISOString().slice(0, 19)}Z  by ${v.by}${v.approved_by ? `, approved by ${v.approved_by}` : ""}  ${v.checksum.slice(0, 12)}${v.signature ? "  signed" : ""}${v.note ? `  - ${v.note}` : ""}`);
    });

  group
    .command("diff <tool> <from> <to>")
    .option("--registry <dir>")
    .description("what changed between two versions")
    .action((tool: string, a: string, b: string, o: { registry?: string }) => {
      const d = opened(o).diff(tool, Number(a), Number(b));
      io.out(d || "(no differences)");
    });

  group
    .command("list")
    .option("--registry <dir>")
    .description("the tools in the registry and their current versions")
    .action((o: { registry?: string }) => {
      const r = opened(o);
      for (const t of r.tools()) {
        const h = r.history(t);
        const last = h[h.length - 1];
        io.out(`${t.padEnd(40)} v${last?.version}  ${last?.status}`);
      }
      if (r.tools().length === 0) io.out("(empty)");
    });

  group
    .command("verify")
    .option("--registry <dir>")
    .option("--trust <pem>", "public key every version must be signed by")
    .description("check every version's checksum (and signature, with --trust)")
    .action((o: { registry?: string; trust?: string }) => {
      const problems = opened(o).verifyAll();
      if (problems.length) {
        for (const p of problems) io.err(`BAD ${p}`);
        ctx.code = 1;
      } else io.out(`ok: ${opened(o).tools().length} tools, every version verifies`);
    });

  group
    .command("check <path>")
    .description("validate manifests in a file or folder (same as `reversi validate`)")
    .action((path: string) => {
      const reg = loadRegistry(path);
      io.out(`ok: ${reg.size} tool manifests valid`);
    });

  // ---- policy versions, added to the existing `policy` group ----
  const policy = program.commands.find((c) => c.name() === "policy") ?? program.command("policy").description("policy as code");
  const pdir = (o: { dir?: string }) => {
    const p = o.dir ?? ctx.project()?.policy;
    if (!p) throw new Fail("no policy folder: pass --dir <folder>, or point `policy:` at a folder in reversi.config.yaml");
    if (existsSync(p) && statSync(p).isFile()) throw new Fail(`${p} is a single policy file; versions live in a folder`);
    return new PolicyVersions(p);
  };
  policy
    .command("publish <file>")
    .description("validate a policy and its tests, store it as a new version, and activate it")
    .option("--dir <folder>", "the policy versions folder (default: `policy:` in the config)")
    .option("--by <name>")
    .option("--note <text>")
    .option("--no-activate", "store it without making it the active policy")
    .action((file: string, o: { dir?: string; by?: string; note?: string; activate: boolean }) => {
      const v = pdir(o).publish(readFileSync(file, "utf8"), { by: o.by ?? me(), note: o.note, activate: o.activate });
      io.out(`policy v${v.version}  ${v.tests_passed} tests passed${o.activate ? "  active" : ""}  ${v.checksum.slice(0, 12)}`);
    });
  policy
    .command("history")
    .option("--dir <folder>")
    .description("every policy version")
    .action((o: { dir?: string }) => {
      const pv = pdir(o);
      for (const v of pv.history()) io.out(`v${v.version}${pv.activeVersion() === v.version ? "  *active*" : "          "}  ${new Date(v.created_ms).toISOString().slice(0, 19)}Z  by ${v.by}  ${v.tests_passed} tests  ${v.checksum.slice(0, 12)}${v.note ? `  - ${v.note}` : ""}`);
    });
  policy
    .command("diff <from> <to>")
    .option("--dir <folder>")
    .description("what changed between two policy versions")
    .action((a: string, b: string, o: { dir?: string }) => io.out(pdir(o).diff(Number(a), Number(b)) || "(no differences)"));
  policy
    .command("activate <version>")
    .option("--dir <folder>")
    .description("make a version the active policy (this is also how you roll back)")
    .action((v: string, o: { dir?: string }) => {
      pdir(o).activate(Number(v));
      io.out(`policy v${v} is now active`);
    });
}

export { RegistryError };
