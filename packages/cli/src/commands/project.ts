/** init, doctor, lint, test: getting a project set up and keeping its manifests honest. */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { Command } from "commander";
import { stringify } from "yaml";
import {
  ManifestRegistry,
  Notifier,
  PolicyVersions,
  createChannel,
  checkUrl,
  hasErrors,
  lintManifests,
  loadPolicyFile,
  loadRegistry,
  openData,
  runManifestTests,
  runPolicyTests,
  starterConfig,
  type ManifestTestCase,
  type StoreKind,
} from "@multimindlab/reversi";
import { Fail, type Ctx, type EngineFlags } from "../context.js";
import { fetchUpstreamTools, hasUpstream, upstreamOpts, type UpstreamFlags } from "./upstream.js";

const EXAMPLE_MANIFESTS = `# One manifest per tool: how reversible it is, what undoes it, who may use it.
# Replace these two with your own (reversi suggest-manifest drafts them from an MCP server).
- tool: notes.read
  description: Read a note.
  effect: read_only
  permission: notes:read

- tool: notes.write
  description: Create or overwrite a note. The previous text is kept so it can be restored.
  effect: reversible
  permission: notes:write
  owner: you@example.com
  risk: { data_class: internal, blast_radius: low }
  timeout_ms: 30s
  compensation:
    tool: notes.restore
    kind: inverse
    argument_map:
      name: $args.name
      backup: $result.backup_id
    verification:
      tool: notes.read
      arguments: { name: $args.name }
      expect: { restored: true }

- tool: notes.restore
  description: Put a note back the way a backup says it was.
  effect: idempotent
  permission: notes:write
`;

const EXAMPLE_POLICY = `version: 1
# Rules add restrictions on top of the manifests; nothing here can grant a permission the run's scope lacks.
rules:
  - id: no-destructive-names
    description: anything called drop, wipe or purge needs a person
    match: { tool: ["*.drop*", "*.wipe*", "*.purge*"] }
    action: require_approval
    reason: destructive name
limits:
  - id: runaway-guard
    match: {}
    max_calls: 200
    window_seconds: 60
    per: run
content:
  secrets: flag
  encoded_payloads: require_approval
  injection: require_approval
tests:
  - { name: ordinary tools are allowed, input: { tool: notes.write }, expect: allow }
  - { name: drop needs approval, input: { tool: db.drop_table }, expect: require_approval, rule: no-destructive-names }
`;

const EXAMPLE_TESTS = `# Contract tests for manifests: run with \`reversi test\`.
- name: writing a note can be undone, and the undo is read back
  tool: notes.write
  args: { name: todo }
  result: { backup_id: b1 }
  expect_plan: compensate
  expect_handle: { name: todo, backup: b1 }
  verify_with: { restored: true }
  expect_verified: true
- name: a failed write leaves nothing to undo
  tool: notes.write
  args: { name: todo }
  fail: disk full
`;

type Check = { level: "ok" | "warn" | "fail" | "info"; text: string };

export function registerProjectCommands(program: Command, ctx: Ctx): void {
  const { io } = ctx;

  program
    .command("init [dir]")
    .description("create a Reversi project: config, example manifests, a starter policy, tests and a data store")
    .option("--store <kind>", "files | sqlite", "sqlite")
    .option("--force", "overwrite files that already exist")
    .action(async (dir: string | undefined, o: { store: string; force?: boolean }) => {
      const root = resolve(dir ?? ".");
      if (!["files", "sqlite"].includes(o.store)) throw new Fail("--store must be files or sqlite (use postgres by editing reversi.config.yaml)");
      mkdirSync(root, { recursive: true });
      const made: string[] = [];
      const put = (rel: string, text: string) => {
        const f = join(root, rel);
        if (existsSync(f) && !o.force) {
          io.out(`kept     ${rel} (exists; --force to overwrite)`);
          return;
        }
        mkdirSync(dirname(f), { recursive: true });
        writeFileSync(f, text);
        made.push(rel);
        io.out(`created  ${rel}`);
      };
      put("reversi.config.yaml", starterConfig({ store: o.store as StoreKind }));
      put("manifests/example.yaml", EXAMPLE_MANIFESTS);
      put("policy.yaml", EXAMPLE_POLICY);
      put("tests/manifests.test.yaml", EXAMPLE_TESTS);
      const ignore = join(root, ".gitignore");
      const line = "reversi-data/\n";
      if (!existsSync(ignore) || !readFileSync(ignore, "utf8").includes("reversi-data")) {
        writeFileSync(ignore, (existsSync(ignore) ? readFileSync(ignore, "utf8").replace(/\n?$/, "\n") : "") + line);
        io.out("updated  .gitignore (reversi-data/)");
      }
      const data = await openData({ dir: join(root, "reversi-data"), store: o.store as StoreKind });
      data.close();
      io.out(`created  reversi-data/ (${o.store} store)`);
      loadRegistry(join(root, "manifests"));
      io.out("");
      io.out("Next:");
      io.out("  reversi doctor                         check the setup");
      io.out("  reversi test                           run the example contract and policy tests");
      io.out("  reversi suggest-manifest --upstream-cmd <your MCP server>   draft manifests from a real server");
      io.out("  reversi gateway --upstream-cmd <your MCP server> --mode observe   see what an agent does before enforcing anything");
    });

  upstreamOpts(
    ctx.dataOpts(
      program
        .command("doctor")
        .description("check the setup: config, manifests, policy, data store, keys, notifications, network rules and (optionally) an upstream")
        .option("--policy <file>", "policy file or folder")
        .option("--send-test", "send a test message through every configured notification channel"),
    ),
  ).action(async (o: EngineFlags & UpstreamFlags & { sendTest?: boolean }) => {
    const checks: Check[] = [];
    const add = (level: Check["level"], text: string) => checks.push({ level, text });
    const [maj, min] = process.versions.node.split(".").map(Number) as [number, number];
    if (maj > 22 || (maj === 22 && (min ?? 0) >= 13)) add("ok", `Node ${process.versions.node}`);
    else add("fail", `Node ${process.versions.node}: Reversi needs 22.13 or newer`);

    let project;
    try {
      project = ctx.project(o);
      add(project ? "ok" : "info", project ? `config ${project.file}` : "no reversi.config.yaml (defaults and environment variables are used; `reversi init` creates one)");
    } catch (e) {
      add("fail", `config: ${e instanceof Error ? e.message : String(e)}`);
    }

    let registryTools = 0;
    try {
      const path = ctx.manifestsPath(o);
      if (!/^https?:\/\//.test(path)) {
        if (!existsSync(path)) throw new Error(`${path} does not exist`);
        if (statSync(path).isDirectory() && ManifestRegistry.isRegistry(path)) {
          const problems = new ManifestRegistry(path).verifyAll();
          add(problems.length ? "fail" : "ok", problems.length ? `manifest registry: ${problems.join("; ")}` : `manifest registry ${path}: every version verifies`);
        }
      }
      const reg = ctx.engineConfigOf(o).manifests;
      void reg;
      await ctx.withEngine(o, (e) => {
        registryTools = e.registry.size;
        const findings = lintManifests(e.registry);
        add("ok", `${e.registry.size} manifests load`);
        const errs = findings.filter((f) => f.level === "error").length;
        const warns = findings.filter((f) => f.level === "warning").length;
        if (errs) add("fail", `lint: ${errs} errors (reversi lint)`);
        else if (warns) add("warn", `lint: ${warns} warnings (reversi lint)`);
        else add("ok", "lint: clean");
        add("ok", `data store (${e.data.kind}) opens`);
        const v = e.reversi.ledger.verify();
        add(v.ok ? "ok" : "fail", v.ok ? `ledger: ${v.records} records, chain intact` : `ledger: TAMPERED or corrupt at record ${v.seq}: ${v.error}`);
        const un = e.reversi.runIds().filter((id) => e.reversi.openRun(id).unresolved().length);
        if (un.length) add("warn", `${un.length} runs have steps with an unknown outcome (reversi runs list --status needs_attention)`);
        const halted = e.reversi.halted();
        if (halted) add("warn", `new calls are halted: ${halted}`);
        if (e.signing_key) add("ok", "signing key loads");
        else add("info", "no signing key: signed evidence bundles and anchors are off");
        if (e.config.policy) {
          try {
            const f = existsSync(e.config.policy) && statSync(e.config.policy).isDirectory() ? undefined : loadPolicyFile(e.config.policy);
            if (f) {
              const results = runPolicyTests(f.doc);
              const bad = results.filter((r) => !r.ok).length;
              add(bad ? "fail" : "ok", `policy: ${f.doc.rules.length} rules, ${results.length} tests${bad ? `, ${bad} failing` : ""}`);
            } else add("ok", `policy versions in ${e.config.policy}`);
          } catch (err) {
            add("fail", `policy: ${err instanceof Error ? err.message : String(err)}`);
          }
        } else add("info", "no policy file: only manifests and scopes restrict calls");
        if (e.notifier) add("ok", `notifications: ${e.notifier.channelNames().join(", ")}`);
        else add("info", "no notification channels configured");
        if (e.capture) add("ok", "capture is on (redacted arguments are kept for replay and simulation)");
        return undefined;
      });
    } catch (e) {
      add("fail", `engine: ${e instanceof Error ? e.message : String(e)}`);
    }

    // data directory writable
    try {
      const d = ctx.dataOptionsOf(o);
      if (d.store !== "postgres") {
        mkdirSync(d.dir, { recursive: true });
        const probe = join(d.dir, `.doctor-${process.pid}`);
        writeFileSync(probe, "");
        (await import("node:fs")).unlinkSync(probe);
        add("ok", `data directory ${d.dir} is writable`);
      }
    } catch (e) {
      add("fail", `data directory: ${e instanceof Error ? e.message : String(e)}`);
    }

    // network destinations
    const proj = project;
    const urls = [...(proj?.notifications?.channels ?? []).flatMap((c) => ("url" in c && c.url ? [c.url] : [])), proj?.otel?.endpoint, proj?.approval?.webhook].filter((u): u is string => !!u);
    for (const u of urls) {
      try {
        await checkUrl(proj?.egress, u);
        add("ok", `egress allows ${new URL(u).host}`);
      } catch (e) {
        add("fail", `egress: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    if (o.sendTest && proj?.notifications?.channels.length) {
      const n = new Notifier(proj.notifications.channels.map((c) => createChannel(c, { egress: proj.egress })), [{ events: ["*"], channels: proj.notifications.channels.map((c) => c.name) }]);
      const r = await n.notify({ event: "doctor_test", severity: "info", title: "Reversi test notification", text: "If you can read this, the channel works." });
      add(r.failed.length ? "fail" : "ok", `test message: sent to ${r.sent.join(", ") || "nobody"}${r.failed.length ? `; failed: ${r.failed.join(", ")}` : ""}`);
    }

    if (hasUpstream(o)) {
      try {
        const { tools } = await fetchUpstreamTools(o);
        add("ok", `upstream answers: ${tools.length} tools`);
        if (registryTools) {
          const reg = loadRegistry(ctx.manifestsPath(o));
          const missing = tools.filter((t) => !reg.has(t.name)).length;
          add(missing ? "warn" : "ok", missing ? `${missing} upstream tools have no manifest (reversi suggest-manifest)` : "every upstream tool has a manifest");
        }
      } catch (e) {
        add("fail", `upstream: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    const sym = { ok: "ok  ", warn: "warn", fail: "FAIL", info: "info" } as const;
    for (const c of checks) io.out(`${sym[c.level]}  ${c.text}`);
    const fails = checks.filter((c) => c.level === "fail").length;
    const warns = checks.filter((c) => c.level === "warn").length;
    io.out(fails ? `${fails} problem${fails === 1 ? "" : "s"} to fix` : warns ? `ok, with ${warns} warning${warns === 1 ? "" : "s"}` : "everything checks out");
    if (fails) ctx.code = 1;
  });

  upstreamOpts(
    program
      .command("lint [path]")
      .description("find unsafe, incomplete or contradictory manifests; with an upstream, also check them against its real tools")
      .option("--strict", "exit 1 on warnings too")
      .option("--json", "machine-readable findings"),
  ).action(async (path: string | undefined, o: UpstreamFlags & { strict?: boolean; json?: boolean }) => {
    const reg = loadRegistry(path ?? ctx.manifestsPath({}));
    const tools = hasUpstream(o) ? (await fetchUpstreamTools(o)).tools : undefined;
    const findings = lintManifests(reg, { tools });
    if (o.json) io.out(JSON.stringify(findings, null, 2));
    else {
      for (const f of findings) io.out(`${f.level.padEnd(7)} ${f.code}  ${f.tool}: ${f.message}`);
      const n = (l: string) => findings.filter((f) => f.level === l).length;
      io.out(findings.length ? `${n("error")} errors, ${n("warning")} warnings, ${n("info")} notes` : `ok: ${reg.size} manifests, no findings`);
    }
    if (hasErrors(findings) || (o.strict && findings.some((f) => f.level === "warning"))) ctx.code = 1;
  });

  ctx
    .dataOpts(program.command("test [fixtures...]").description("run contract tests for manifests, and the policy's own tests, without touching any system").option("--policy <file>", "policy file"))
    .action(async (fixtures: string[], o: EngineFlags) => {
      const reg = loadRegistry(ctx.manifestsPath(o));
      const root = ctx.project(o)?.root ?? process.cwd();
      let files = fixtures;
      if (files.length === 0) {
        const dir = join(root, "tests");
        files = existsSync(dir) ? readdirSync(dir).filter((f) => /\.(test\.)?(ya?ml|json)$/.test(f)).map((f) => join(dir, f)) : [];
      }
      const cases: ManifestTestCase[] = [];
      for (const f of files) {
        const doc = ctx.readDoc(f);
        const list = Array.isArray(doc) ? doc : (doc as { manifests?: unknown[] })?.manifests;
        if (!Array.isArray(list)) throw new Fail(`${f}: expected a list of test cases`);
        cases.push(...(list as ManifestTestCase[]));
      }
      let failed = 0;
      let policyDoc;
      const polPath = o.policy ?? ctx.project(o)?.policy;
      if (polPath && existsSync(polPath) && !statSync(polPath).isDirectory()) policyDoc = loadPolicyFile(polPath).doc;
      else if (polPath && existsSync(polPath) && PolicyVersions.isVersioned(polPath)) policyDoc = new PolicyVersions(polPath).doc(new PolicyVersions(polPath).activeVersion() as number);
      const { results, untested } = await runManifestTests(reg, cases, { policy: policyDoc, environment: ctx.project(o)?.environment });
      for (const r of results) {
        io.out(`${r.ok ? "ok  " : "FAIL"} ${r.name}`);
        for (const p of r.problems) io.out(`       ${p}`);
        if (!r.ok) failed++;
      }
      if (policyDoc) {
        const pr = runPolicyTests(policyDoc);
        for (const r of pr) {
          io.out(`${r.ok ? "ok  " : "FAIL"} policy: ${r.name}${r.ok ? "" : `: expected ${r.expected}, got ${r.got}`}`);
          if (!r.ok) failed++;
        }
        results.push(...pr.map((r) => ({ name: r.name, tool: "", ok: r.ok, problems: [] })));
      }
      if (results.length === 0) io.out("no tests found: add files under tests/ or pass them as arguments");
      if (untested.length) io.out(`not covered by any test: ${untested.join(", ")}`);
      io.out(failed ? `${failed} of ${results.length} failed` : `${results.length} passed`);
      if (failed) ctx.code = 1;
    });

  program
    .command("show-config")
    .description("print the project configuration Reversi found, with defaults filled in")
    .action(() => {
      const p = ctx.project({});
      io.out(p ? stringify(p) : "no reversi.config.yaml found");
    });
}
