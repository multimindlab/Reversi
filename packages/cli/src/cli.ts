import { spawn } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { extname } from "node:path";
import { Command, CommanderError } from "commander";
import { parse as parseYaml } from "yaml";
import {
  ApprovalError,
  Approvals,
  Ledger,
  loadRegistry,
  ManifestError,
  PolicyError,
  createBundle,
  dataOptionsFromEnv,
  generateSigningKey,
  keyId,
  loadPolicyFile,
  openData,
  openEngine,
  parseJsonl,
  parsePolicy,
  renderReport,
  runPolicyTests,
  storeKindFrom,
  toJsonl,
  verifyBundle,
  verifyRecords,
  type CompensationCall,
  type EngineHandle,
  type RollbackPlan,
} from "@multimindlab/reversi";

export interface IO {
  out: (s: string) => void;
  err: (s: string) => void;
}

const DEFAULT_IO: IO = {
  out: (s) => process.stdout.write(s + "\n"),
  err: (s) => process.stderr.write(s + "\n"),
};

class Fail extends Error {}

/** Run a shell command with the compensation call as JSON on stdin. Exit 0 means the undo succeeded. */
function runCompensator(cmd: string, call: CompensationCall, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, { shell: true, stdio: ["pipe", "pipe", "pipe"], timeout: timeoutMs });
    let stderr = "";
    child.stderr.on("data", (d) => {
      if (stderr.length < 500) stderr += String(d);
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`compensator ${signal ? `killed by ${signal}` : `exited ${code}`}${stderr ? `: ${stderr.trim()}` : ""}`));
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(call));
  });
}

function formatPlan(p: RollbackPlan): string[] {
  const lines = [`rollback plan for ${p.run_id}`];
  if (p.actions.length === 0) lines.push("  nothing to undo");
  for (const a of p.actions) {
    const extra =
      a.kind === "compensate"
        ? `-> ${a.compensation_tool}${a.needs_approval ? " (needs approval)" : ""}`
        : a.kind === "defer"
          ? `waits for step ${a.blocked_by?.join(", ")}`
          : (a.note ?? "");
    lines.push(`  step ${a.step}  ${a.tool}  ${a.kind}  ${extra}`.trimEnd());
  }
  lines.push(p.fully_reversible ? "fully reversible (assuming each compensation succeeds)" : "NOT fully reversible: see above");
  return lines;
}

export async function main(argv: string[], io: IO = DEFAULT_IO): Promise<number> {
  const program = new Command();
  let code = 0;
  program
    .name("reversi")
    .description("Reversibility, approvals and tamper-evident evidence for AI agent tool calls")
    .exitOverride()
    .configureOutput({ writeOut: (s) => io.out(s.replace(/\n$/, "")), writeErr: (s) => io.err(s.replace(/\n$/, "")) });

  const storeOpts = (c: Command) =>
    c
      .option("-d, --data <dir>", "data directory", "./reversi-data")
      .option("--store <kind>", "files | sqlite | postgres (default: REVERSI_STORE or files)")
      .option("--database-url <url>", "PostgreSQL URL (default: REVERSI_DATABASE_URL)");
  const dataOpts = (c: Command) => storeOpts(c.requiredOption("-m, --manifests <path>", "manifest file or directory (.json, .yaml)"));

  interface StoreFlags {
    data: string;
    store?: string;
    databaseUrl?: string;
  }
  const dataOptionsOf = (o: StoreFlags) => {
    const env = dataOptionsFromEnv();
    return {
      dir: o.data,
      store: o.store ? storeKindFrom(o.store) : env.store,
      postgres_url: o.databaseUrl ?? env.postgres_url,
    };
  };
  const dataExists = (o: StoreFlags) => {
    const d = dataOptionsOf(o);
    if (d.store === "files" && !existsSync(o.data)) throw new Fail(`data directory not found: ${o.data}`);
  };
  /** Open the engine; the caller closes the store. Policy only matters for new calls, which the CLI never makes. */
  const engine = async (o: StoreFlags & { manifests: string }): Promise<EngineHandle> => {
    dataExists(o);
    return openEngine({ manifests: o.manifests, data: dataOptionsOf(o) });
  };
  const withEngine = async <T>(o: Parameters<typeof engine>[0], fn: (e: EngineHandle) => Promise<T> | T): Promise<T> => {
    const e = await engine(o);
    try {
      return await fn(e);
    } finally {
      e.data.close();
    }
  };
  const readDoc = (path: string): unknown => {
    const text = readFileSync(path, "utf8");
    return extname(path).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
  };

  program
    .command("validate <path>")
    .description("check manifests, including that every compensation and required tool exists")
    .action((path: string) => {
      const reg = loadRegistry(path);
      io.out(`ok: ${reg.size} tool manifest${reg.size === 1 ? "" : "s"} valid`);
    });

  storeOpts(
    program
      .command("verify [ledger]")
      .description("verify the hash chain of a ledger file (JSON Lines), or of the ledger in the data store"),
  ).action(async (file: string | undefined, o) => {
    let records;
    if (file) {
      if (!existsSync(file)) throw new Fail(`ledger not found: ${file}`);
      records = parseJsonl(readFileSync(file, "utf8"));
    } else {
      dataExists(o);
      const d = await openData(dataOptionsOf(o));
      try {
        records = [...d.ledger.all()];
      } finally {
        d.close();
      }
    }
    const v = verifyRecords(records);
    if (v.ok) io.out(`ok: ${v.records} records, head ${v.head}`);
    else {
      io.err(`TAMPERED or corrupt at record ${v.seq}: ${v.error}`);
      code = 1;
    }
  });

  dataOpts(program.command("runs").description("list runs and their step counts")).action((o) =>
    withEngine(o, (rv) => {
      for (const id of rv.reversi.runIds()) {
        const run = rv.reversi.openRun(id);
        const s = run.state();
        const un = run.unresolved();
        io.out(`${id}  actor=${s.actor}  mode=${s.mode}  steps=${s.steps.length}${un.length ? `  UNRESOLVED=${un.join(",")}` : ""}`);
      }
    }),
  );

  dataOpts(program.command("plan <run_id>").description("show what a rollback would do; executes nothing"))
    .option("--json", "machine-readable output")
    .action((run_id: string, o) =>
      withEngine(o, (rv) => {
        const p = rv.reversi.openRun(run_id).plan();
        if (o.json) io.out(JSON.stringify(p, null, 2));
        else for (const l of formatPlan(p)) io.out(l);
        if (!p.fully_reversible) code = 2;
      }),
    );

  dataOpts(program.command("rollback <run_id>").description("undo a run with an operator-supplied compensator command"))
    .requiredOption("--compensator-cmd <cmd>", "shell command; receives the compensation call as JSON on stdin; exit 0 = undone")
    .option("--verify-cmd <cmd>", "shell command run after each compensation with the same JSON; exit 0 = the undo is confirmed")
    .option("--approve-compensations", "approve compensations that require approval (operator decision)")
    .option("--retries <n>", "attempts per compensation, with exponential backoff and the same idempotency key", "1")
    .option("--timeout-ms <n>", "per-compensation timeout", "30000")
    .option("--json", "machine-readable report")
    .action(async (run_id: string, o) => {
      const timeout = Number(o.timeoutMs);
      if (!Number.isFinite(timeout) || timeout <= 0) throw new Fail("--timeout-ms must be a positive number");
      const attempts = Number(o.retries);
      if (!Number.isInteger(attempts) || attempts < 1 || attempts > 10) throw new Fail("--retries must be 1..10");
      await withEngine(o, async (rv) => {
        const run = rv.reversi.openRun(run_id);
        if (o.approveCompensations) {
          for (const a of run.plan().actions) {
            if (a.kind === "compensate" && a.needs_approval && a.compensation_tool) rv.approvals.add(run_id, "compensation", a.compensation_tool, 1, "cli");
          }
        }
        const report = await run.rollback({
          actor: "cli",
          retry: { attempts },
          compensate: (c) => runCompensator(o.compensatorCmd, c, timeout),
          verify: o.verifyCmd ? (c) => runCompensator(o.verifyCmd, c, timeout).then(() => true, () => false) : undefined,
        });
        if (o.json) io.out(JSON.stringify(report, null, 2));
        else {
          io.out(`compensated: ${report.compensated.join(", ") || "-"}`);
          io.out(`skipped (no undo needed): ${report.skipped.join(", ") || "-"}`);
          for (const f of report.failed) io.out(`FAILED step ${f.step}: ${f.error}`);
          if (report.unrecoverable.length) io.out(`cannot be undone: ${report.unrecoverable.join(", ")}`);
          if (report.unresolved.length) io.out(`outcome unknown, reconcile manually (reversi resolve): ${report.unresolved.join(", ")}`);
          if (report.unmanifested.length) io.out(`no manifest: ${report.unmanifested.join(", ")}`);
          for (const d of report.deferred) io.out(`deferred step ${d.step}: waits for ${d.blocked_by.join(", ")}`);
          if (report.awaiting_approval.length) io.out(`awaiting approval: ${report.awaiting_approval.join(", ")}`);
          io.out(report.complete ? "rollback complete" : "rollback INCOMPLETE");
        }
        if (!report.complete) code = 2;
      });
    });

  dataOpts(program.command("resolve <run_id> <step>").description("settle a step whose outcome was unknown, after checking the downstream system"))
    .requiredOption("--status <status>", "succeeded | failed")
    .requiredOption("--note <text>", "how you established the outcome (recorded in the ledger)")
    .option("--result <json>", "the tool's result, as JSON, so the step can be rolled back")
    .option("--actor <name>", "who is resolving it", "cli")
    .action((run_id: string, step: string, o) =>
      withEngine(o, (rv) => {
        if (o.status !== "succeeded" && o.status !== "failed") throw new Fail("--status must be succeeded or failed");
        const n = Number(step);
        if (!Number.isInteger(n) || n < 0) throw new Fail("step must be a non-negative integer");
        let result: unknown;
        if (o.result !== undefined) {
          try {
            result = JSON.parse(o.result);
          } catch {
            throw new Fail("--result must be valid JSON");
          }
        }
        const r = rv.reversi.openRun(run_id).resolve(n, o.status === "succeeded" ? { status: "succeeded", result } : { status: "failed" }, { actor: o.actor, note: o.note });
        io.out(`step ${r.step} is now ${r.status}`);
      }),
    );

  const approvals = program.command("approvals").description("list and decide approval requests (shared with the gateway and server through the data store)");
  storeOpts(approvals.command("list").description("show approval requests").option("--status <status>", "pending | approved | denied | consumed | expired")).action(async (o) => {
    dataExists(o);
    const d = await openData(dataOptionsOf(o));
    try {
      const list = new Approvals(d.approvals).list({ status: o.status });
      if (list.length === 0) io.out("no approvals");
      for (const a of list) {
        io.out(`${a.id}  ${a.status}  run=${a.run_id}  ${a.kind}  ${a.tool}  args=[${a.arg_keys.join(",")}]  why: ${a.triggers.join("; ")}`);
      }
    } finally {
      d.close();
    }
  });
  for (const decision of ["approve", "deny"] as const) {
    storeOpts(approvals.command(`${decision} <id>`).description(`${decision} a pending request`).option("--note <text>", "recorded with the decision").option("--as <name>", "who is deciding", "cli")).action(async (id: string, o) => {
      dataExists(o);
      const d = await openData(dataOptionsOf(o));
      try {
          const a = new Approvals(d.approvals);
        const r = decision === "approve" ? a.approve(id, o.as, o.note) : a.deny(id, o.as, o.note);
        io.out(`${r.id} ${r.status} by ${r.decided_by}`);
      } finally {
        d.close();
      }
    });
  }

  storeOpts(program.command("export").description("print ledger records as JSON Lines (optionally one run)").option("--run <run_id>", "only this run")).action(async (o) => {
    dataExists(o);
    const d = await openData(dataOptionsOf(o));
    try {
      const ledger = new Ledger(d.ledger);
      const text = toJsonl(o.run ? ledger.forRun(o.run) : ledger.records());
      if (text) io.out(text.replace(/\n$/, ""));
    } finally {
      d.close();
    }
  });

  // ---- policy ----
  const policy = program.command("policy").description("policy as code");
  policy
    .command("test <policy> [tests]")
    .description("run a policy's test cases (inline `tests:` and/or a separate file with a list of cases)")
    .action((file: string, tests?: string) => {
      const doc = parsePolicy(readDoc(file));
      const extra = tests ? (readDoc(tests) as never) : [];
      if (!Array.isArray(extra)) throw new Fail("the tests file must hold a list of cases");
      const results = runPolicyTests(doc, extra);
      if (results.length === 0) throw new Fail("no test cases found: add `tests:` to the policy or pass a tests file");
      for (const r of results) io.out(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `: expected ${r.expected}, got ${r.got}${r.message ? ` (${r.message})` : ""}`}`);
      const bad = results.filter((r) => !r.ok).length;
      io.out(bad ? `${bad} of ${results.length} failed` : `${results.length} passed`);
      if (bad) code = 1;
    });
  policy
    .command("check <policy>")
    .description("validate a policy file")
    .action((file: string) => {
      const d = loadPolicyFile(file).doc;
      io.out(`ok: ${d.rules.length} rules, ${d.limits.length} limits, default ${d.default}${d.content ? ", content checks configured" : ""}`);
    });

  // ---- kill switch ----
  program
    .command("kill-switch <on|off> <file>")
    .description("create or remove the kill-switch file; while it exists, every gateway and server using it blocks new calls")
    .action((state: string, file: string) => {
      if (state === "on") {
        writeFileSync(file, `halted ${new Date().toISOString()}\n`);
        io.out(`kill switch ON: ${file}`);
      } else if (state === "off") {
        rmSync(file, { force: true });
        io.out(`kill switch OFF: ${file}`);
      } else throw new Fail("use `on` or `off`");
    });

  // ---- evidence ----
  program
    .command("keygen <prefix>")
    .description("create an Ed25519 signing key pair: <prefix>.key (keep private) and <prefix>.pub")
    .action((prefix: string) => {
      if (existsSync(`${prefix}.key`) || existsSync(`${prefix}.pub`)) throw new Fail(`${prefix}.key or ${prefix}.pub already exists; refusing to overwrite`);
      const k = generateSigningKey();
      writeFileSync(`${prefix}.key`, k.private_pem, { mode: 0o600 });
      writeFileSync(`${prefix}.pub`, k.public_pem);
      io.out(`wrote ${prefix}.key and ${prefix}.pub (key id ${keyId(k.public_pem)})`);
    });

  storeOpts(
    program
      .command("bundle")
      .description("write a signed evidence bundle of the whole ledger, or one run")
      .requiredOption("--key <file>", "private key from `reversi keygen`")
      .requiredOption("--out <file>", "output file")
      .option("--run <run_id>", "only this run"),
  ).action(async (o) => {
    dataExists(o);
    const private_pem = readFileSync(o.key, "utf8");
    const { createPrivateKey, createPublicKey } = await import("node:crypto");
    const public_pem = createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString();
    const d = await openData(dataOptionsOf(o));
    try {
      const ledger = new Ledger(d.ledger);
      const records = o.run ? ledger.forRun(o.run) : ledger.records();
      if (o.run && records.length === 0) throw new Fail(`no records for run ${o.run}`);
      const b = createBundle({ records, ledger_head: ledger.head(), run_id: o.run ?? null, key: { private_pem, public_pem } });
      writeFileSync(o.out, JSON.stringify(b, null, 2));
      io.out(`wrote ${o.out}: ${b.record_count} records, key ${b.signature.key_id}`);
    } finally {
      d.close();
    }
  });

  program
    .command("verify-bundle <file>")
    .description("verify a signed evidence bundle; pass --pub to check it against a key you trust")
    .option("--pub <file>", "trusted public key (PEM). Without it the signature only proves the bundle is self-consistent")
    .action((file: string, o) => {
      const r = verifyBundle(JSON.parse(readFileSync(file, "utf8")), { trusted_public_pem: o.pub ? readFileSync(o.pub, "utf8") : undefined });
      if (!r.ok) {
        io.err(`INVALID: ${r.error}`);
        code = 1;
        return;
      }
      io.out(`ok: ${r.records} records, ${r.chain === "full" ? "hash chain verified" : "record hashes verified (single run)"}, key ${r.key_id}${r.trusted_key ? " (trusted)" : " (NOT checked against a trusted key)"}`);
    });

  dataOpts(program.command("report <run_id>").description("write a self-contained HTML report for auditors").requiredOption("--out <file>", "output file")).action((run_id: string, o) =>
    withEngine(o, (rv) => {
      const run = rv.reversi.openRun(run_id);
      writeFileSync(o.out, renderReport({ run: run.state(), records: rv.reversi.ledger.forRun(run_id), plan: run.plan(), ledger_head: rv.reversi.ledger.head() }));
      io.out(`wrote ${o.out}`);
    }),
  );

  try {
    await program.parseAsync(argv, { from: "user" });
    return code;
  } catch (e) {
    if (e instanceof CommanderError) return e.exitCode === 0 ? 0 : 64;
    if (e instanceof ManifestError || e instanceof PolicyError) {
      for (const m of e.errors) io.err(`error: ${m}`);
      return 1;
    }
    if (e instanceof ApprovalError) {
      io.err(`error: ${e.message}`);
      return 1;
    }
    io.err(`error: ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  }
}
