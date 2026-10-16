import { EffectUncertainError, Registry } from "@multimindlab/reversi";
import { expect } from "vitest";
import {
  CHECK_IDS,
  compensatorFor,
  connectorSchemaHashes,
  detectManifestDrift,
  type Certification,
  type CheckId,
  type CheckResult,
  type Connector,
} from "../src/index.js";
import { engine, type Call, type FakeReply } from "./helpers.js";

/**
 * The shared certification helper. `certifyConnector(subject, scenarios)` drives every tool of a connector against a
 * fake backend and records pass / fail / not_applicable, with a reason, for each of the twelve checks.
 */

export type Args = Record<string, unknown>;

export type Fault =
  | { kind: "status"; status: number; body?: FakeReply; on?: "any" | "mutating" }
  | { kind: "throw"; message: string; on?: "any" | "mutating" }
  | { kind: "hang"; on?: "any" | "mutating" };

export interface Backend {
  /** The active fault; set by the checks. */
  fault: Fault | null;
  /** Every request the connector made, including ones a fault swallowed. */
  calls: Call[];
  /** A JSON snapshot of everything the fake service holds. */
  state(): unknown;
  isMutating(c: Call): boolean;
  /** False for backends with no transport to break (the local filesystem). */
  supportsFaults: boolean;
}

export interface HttpBackend extends Backend {
  fetch: typeof fetch;
}

/** A fake HTTP service with fault injection. `handle` answers requests; `state` snapshots what it holds. */
export function httpBackend(o: {
  handle: (c: Call) => FakeReply | Promise<FakeReply>;
  state: () => unknown;
  isMutating?: (c: Call) => boolean;
}): HttpBackend {
  const calls: Call[] = [];
  const isMutating = o.isMutating ?? ((c: Call) => c.method !== "GET" && c.method !== "HEAD");
  const b: HttpBackend = {
    fault: null,
    calls,
    state: o.state,
    isMutating,
    supportsFaults: true,
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
      let body = "";
      if (init?.body instanceof Uint8Array) body = Buffer.from(init.body).toString("latin1");
      else if (init?.body !== undefined && init?.body !== null) body = String(init.body);
      const call: Call = { url: String(url), method: init?.method ?? "GET", headers, body };
      calls.push(call);
      const f = b.fault;
      if (f && (f.on !== "mutating" || isMutating(call))) {
        if (f.kind === "throw") throw new TypeError(f.message);
        if (f.kind === "hang") {
          return new Promise<Response>((_, reject) => {
            const s = init?.signal;
            if (s?.aborted) reject(s.reason);
            s?.addEventListener("abort", () => reject(s.reason), { once: true });
          });
        }
        return toResponse({ status: f.status, ...(f.body ?? { json: { message: `fault ${f.status}` } }) });
      }
      return toResponse(await o.handle(call));
    }) as typeof fetch,
  };
  return b;
}

export function toResponse(r: FakeReply & { bytes?: Uint8Array; headers?: Record<string, string> }): Response {
  const status = r.status ?? 200;
  const body = (r as { bytes?: Uint8Array }).bytes ?? r.text ?? (r.json === undefined ? "" : JSON.stringify(r.json));
  return new Response(status === 204 || status === 304 ? null : body, {
    status,
    headers: (r as { headers?: Record<string, string> }).headers,
  });
}

export interface Subject {
  name: string;
  /** Every credential that must never leak. */
  secrets: string[];
  /** A fresh connector wired to a fresh fake backend. `timeoutMs` is passed through to the connector. */
  make(opts?: { timeoutMs?: number }): { connector: Connector; backend: Backend };
  /** How a backend error with this HTTP status must read in the error message. Default: the number itself. */
  statusPattern?: (status: number) => RegExp;
  /** An error body in the service's own format that echoes `secret`, so redaction is exercised. */
  faultBody?: (status: number, secret: string) => FakeReply;
  /** Checks that cannot apply to this connector, with the reason. */
  notApplicable?: Partial<Record<CheckId, string>>;
}

export interface Scenario {
  /** Short tool name, such as `post_message`. */
  tool: string;
  args: Args;
  /** Seed the fake backend so `args` refer to things that exist. */
  setup?: (b: Backend) => void | Promise<void>;
  /** Assertions on a successful result. */
  expect?: (result: unknown, b: Backend) => void;
  /** Make the tool fail definitively without a transport fault (for the filesystem). */
  fail?: (b: Backend) => void;
  /** For tools that pass the idempotency key to the service: does this request carry `key`? */
  usesKey?: (c: Call, key: string) => boolean;
  /** The call changes nothing observable even when it succeeds. */
  noEffect?: boolean;
  fingerprint?: (b: Backend) => unknown;
  /** Compare the state before the call with the state after rollback. Default: equal. */
  restored?: (before: unknown, after: unknown, b: Backend) => void;
  /** Make the undo fail / heal it again. Default: a 500 fault on every request. */
  breakCompensation?: (b: Backend) => void;
  healCompensation?: (b: Backend) => void;
}

type Manifest = { tool: string; effect: string; compensation?: { tool: string; argument_map: Record<string, string> }; requires?: string[] };

const manifestsOf = (c: Connector): Manifest[] => c.manifests as Manifest[];

function shortName(c: Connector, full: string): string {
  return full.startsWith(`${c.name}.`) ? full.slice(c.name.length + 1) : full;
}

function leaks(text: string, secrets: string[]): string | undefined {
  return secrets.find((s) => s && text.includes(s));
}

function noLeak(what: string, text: string, secrets: string[]): void {
  const s = leaks(text, secrets);
  if (s) throw new Error(`${what} contains the credential`);
}

const mutatingFault = (mutating: boolean): "any" | "mutating" => (mutating ? "mutating" : "any");

export async function certifyConnector(subject: Subject, scenarios: Scenario[]): Promise<Certification> {
  const probeMade = subject.make();
  const probe = probeMade.connector;
  const supportsFaults = probeMade.backend.supportsFaults;
  const manifests = manifestsOf(probe);
  const manifestFor = (sc: Scenario) => {
    const m = manifests.find((x) => x.tool === `${probe.name}.${sc.tool}`);
    if (!m) throw new Error(`scenario names unknown tool \`${sc.tool}\``);
    return m;
  };
  const statusRe = subject.statusPattern ?? ((s: number) => new RegExp(`\\b${s}\\b`));
  const bodyFor = (status: number, secret: string): FakeReply =>
    subject.faultBody?.(status, secret) ?? { json: { message: `rejected: ${secret}`, error: { message: `rejected: ${secret}` } } };
  const secret0 = subject.secrets[0] ?? "";

  const fp = (sc: Scenario, b: Backend) => JSON.parse(JSON.stringify(sc.fingerprint ? sc.fingerprint(b) : b.state() ?? null));
  const prepare = async (sc: Scenario, timeoutMs?: number) => {
    const { connector, backend } = subject.make(timeoutMs ? { timeoutMs } : undefined);
    await sc.setup?.(backend);
    const tool = connector.tools[`${connector.name}.${sc.tool}`];
    if (!tool) throw new Error(`connector has no tool \`${sc.tool}\``);
    return { connector, backend, tool, before: fp(sc, backend) };
  };
  const errorOf = async (p: Promise<unknown>): Promise<Error> => {
    try {
      await p;
    } catch (e) {
      if (e instanceof Error) return e;
      throw new Error(`a non-Error was thrown: ${String(e)}`);
    }
    throw new Error("expected the call to fail, but it succeeded");
  };

  async function each(
    id: CheckId,
    list: Scenario[],
    body: (sc: Scenario, m: Manifest) => Promise<void>,
    naReason: string,
  ): Promise<CheckResult> {
    const declared = subject.notApplicable?.[id];
    if (declared) return { check: id, status: "not_applicable", reason: declared, tools: [] };
    if (list.length === 0) return { check: id, status: "not_applicable", reason: naReason, tools: [] };
    const failures: string[] = [];
    for (const sc of list) {
      try {
        await body(sc, manifestFor(sc));
      } catch (e) {
        failures.push(`${sc.tool}: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
      }
    }
    return {
      check: id,
      status: failures.length ? "fail" : "pass",
      ...(failures.length ? { reason: failures.join("; ") } : {}),
      tools: list.map((s) => s.tool),
    };
  }

  const mutatingOf = (m: Manifest) => m.effect !== "read_only";
  const compensable = scenarios.filter((s) => manifestFor(s).compensation);
  const results: CheckResult[] = [];

  // 1. forward success
  {
    const r = await each(
      "forward_success",
      scenarios,
      async (sc, m) => {
        const { backend, tool, before } = await prepare(sc);
        const mark = backend.calls.length;
        const result = await tool(sc.args, {});
        JSON.stringify(result ?? null);
        sc.expect?.(result, backend);
        const after = fp(sc, backend);
        if (m.effect === "read_only") {
          expect(after).toEqual(before);
          if (backend.supportsFaults) {
            const writes = backend.calls.slice(mark).filter((c) => backend.isMutating(c));
            expect(writes, "a read-only tool made a mutating request").toEqual([]);
          }
        } else if (!sc.noEffect) {
          expect(after, "the tool reported success but the backend did not change").not.toEqual(before);
        }
      },
      "no scenarios",
    );
    const known = new Set(scenarios.map((s) => `${probe.name}.${s.tool}`));
    const missing = manifests.map((m) => m.tool).filter((t) => !known.has(t));
    if (missing.length) {
      r.status = "fail";
      r.reason = [r.reason, `no scenario for: ${missing.join(", ")}`].filter(Boolean).join("; ");
    }
    results.push(r);
  }

  // 2. forward failure
  results.push(
    await each(
      "forward_failure",
      scenarios.filter((s) => s.fail || supportsFaults),
      async (sc) => {
        const { backend, tool, before: seeded } = await prepare(sc);
        let before = seeded;
        if (sc.fail) {
          sc.fail(backend);
          before = fp(sc, backend); // the hook itself sets the scene; the call must not change it further
        } else backend.fault = { kind: "status", status: 422, body: bodyFor(422, secret0) };
        const err = await errorOf(Promise.resolve().then(() => tool(sc.args, {})));
        expect(err).not.toBeInstanceOf(EffectUncertainError);
        noLeak("the error message", err.message, subject.secrets);
        if (!sc.fail) expect(err.message).toMatch(statusRe(422));
        backend.fault = null;
        expect(fp(sc, backend), "a failed call changed the backend").toEqual(before);
      },
      "no scenarios",
    ),
  );

  // 3. duplicate call
  results.push(
    await each(
      "duplicate_call",
      scenarios.filter((s) => manifestFor(s).effect === "idempotent" || s.usesKey),
      async (sc) => {
        const { backend, tool } = await prepare(sc);
        const key = "idem-0123456789abcdef";
        const mark = backend.calls.length;
        await tool(sc.args, { idempotency_key: key });
        const first = fp(sc, backend);
        const mid = backend.calls.length;
        await tool(sc.args, { idempotency_key: key });
        expect(fp(sc, backend), "the repeat had a second effect").toEqual(first);
        if (sc.usesKey) {
          for (const c of backend.calls.slice(mark).filter((x) => backend.isMutating(x))) {
            expect(sc.usesKey(c, key), `a write did not carry the idempotency key: ${c.method} ${c.url}`).toBe(true);
          }
          expect(backend.calls.length).toBeGreaterThan(mid);
        }
      },
      "no tool takes an idempotency key and none is naturally idempotent",
    ),
  );

  // 4. retry
  results.push(
    await each(
      "retry",
      scenarios,
      async (sc, m) => {
        const mutating = mutatingOf(m);
        for (const mode of ["transport", "5xx"] as const) {
          const { backend, tool, before } = await prepare(sc);
          const on = mutatingFault(mutating);
          backend.fault =
            mode === "transport"
              ? { kind: "throw", message: `socket hang up ${secret0}`, on }
              : { kind: "status", status: 503, body: bodyFor(503, secret0), on };
          const err = await errorOf(Promise.resolve().then(() => tool(sc.args, {})));
          if (mode === "transport") {
            if (mutating) expect(err, "a lost connection on a write must be uncertain").toBeInstanceOf(EffectUncertainError);
            else expect(err).not.toBeInstanceOf(EffectUncertainError);
          } else if (!(err instanceof EffectUncertainError)) {
            expect(err.message).toMatch(statusRe(503));
          }
          noLeak("the error message", err.message, subject.secrets);
          expect(fp(sc, backend), "the failed attempt changed the backend").toEqual(before);
          backend.fault = null;
          await tool(sc.args, {});
          if (mutating && !sc.noEffect) expect(fp(sc, backend), "the re-run did not take effect").not.toEqual(before);
        }
      },
      "no scenarios",
    ),
  );

  /** Forward-run one scenario through a real engine, first running the scenarios of any tools it `requires`. */
  const rollbackDrive = async (sc: Scenario, m: Manifest) => {
    const { connector, backend } = subject.make();
    const prereqs = (m.requires ?? []).map((r) => {
      const found = scenarios.find((s) => `${probe.name}.${s.tool}` === r);
      if (!found) throw new Error(`no scenario for required tool ${r}`);
      return found;
    });
    for (const p of prereqs) await p.setup?.(backend);
    await sc.setup?.(backend);
    const before = fp(sc, backend);
    const eng = engine([connector]);
    for (const p of prereqs) expect((await eng.call(`${connector.name}.${p.tool}`, p.args)).status).toBe("executed");
    const step = await eng.call(`${connector.name}.${sc.tool}`, sc.args);
    expect(step.status).toBe("executed");
    if (!sc.noEffect) expect(fp(sc, backend)).not.toEqual(before);
    return { connector, backend, before, eng, comp: compensatorFor([connector]), steps: prereqs.length + 1 };
  };
  const assertRestored = (sc: Scenario, before: unknown, b: Backend) => {
    const after = fp(sc, b);
    if (sc.restored) sc.restored(before, after, b);
    else expect(after, "the backend is not back in its prior state").toEqual(before);
  };
  const standing = (eng: ReturnType<typeof engine>, status: string) =>
    eng.run.state().steps.filter((s) => s.status === status).length;

  // 5. compensation success
  results.push(
    await each(
      "compensation_success",
      compensable,
      async (sc, m) => {
        const { connector, backend, before, eng, comp, steps } = await rollbackDrive(sc, m);
        // the compensation is a registered idempotent tool that accepts exactly what the argument_map produces
        const reg = Registry.from(connector.manifests);
        const ct = reg.get(m.compensation!.tool)!;
        expect(ct.effect, "the compensation tool must be idempotent").toBe("idempotent");
        const schema = connector.inputSchemas[ct.tool] as { properties: object; required: string[] };
        const mapped = Object.keys(m.compensation!.argument_map);
        for (const k of mapped) expect(Object.keys(schema.properties), `argument_map key \`${k}\` is not an argument of ${ct.tool}`).toContain(k);
        for (const k of schema.required) expect(mapped, `${ct.tool} requires \`${k}\` but argument_map does not provide it`).toContain(k);
        const report = await eng.run.rollback({ compensate: comp });
        expect(report.complete, JSON.stringify(report)).toBe(true);
        expect(report.compensated).toHaveLength(steps);
        assertRestored(sc, before, backend);
      },
      "no tool declares a compensation",
    ),
  );

  // 6. compensation failure
  results.push(
    await each(
      "compensation_failure",
      compensable,
      async (sc, m) => {
        const { backend, before, eng, comp } = await rollbackDrive(sc, m);
        if (sc.breakCompensation) sc.breakCompensation(backend);
        else backend.fault = { kind: "status", status: 500, body: bodyFor(500, secret0) };
        const report = await eng.run.rollback({ compensate: comp });
        expect(report.complete, "a failed compensation must never report complete").toBe(false);
        expect(report.failed).toHaveLength(1);
        expect(report.compensated).toEqual([]);
        expect(standing(eng, "compensation_failed")).toBe(1);
        noLeak("the rollback report", JSON.stringify(report), subject.secrets);
        if (sc.healCompensation) sc.healCompensation(backend);
        else backend.fault = null;
        const again = await eng.run.rollback({ compensate: comp });
        expect(again.complete, JSON.stringify(again)).toBe(true);
        assertRestored(sc, before, backend);
      },
      "no tool declares a compensation",
    ),
  );

  // 7. verification failure
  results.push(
    await each(
      "verification_failure",
      compensable,
      async (sc, m) => {
        const { backend, before, eng, comp } = await rollbackDrive(sc, m);
        const report = await eng.run.rollback({ compensate: comp, verify: () => false });
        expect(report.complete).toBe(false);
        expect(report.compensated, "an unverified undo must not be reported as compensated").toEqual([]);
        expect(report.failed).toHaveLength(1);
        expect(report.failed[0]!.error).toContain("verification failed");
        expect(standing(eng, "compensated")).toBe(0);
        const again = await eng.run.rollback({ compensate: comp, verify: () => true });
        expect(again.complete, JSON.stringify(again)).toBe(true);
        assertRestored(sc, before, backend);
      },
      "no tool declares a compensation",
    ),
  );

  // 8. permission denial
  results.push(
    await each(
      "permission_denial",
      supportsFaults ? scenarios : [],
      async (sc) => {
        for (const status of [401, 403]) {
          const { backend, tool, before } = await prepare(sc);
          backend.fault = { kind: "status", status, body: bodyFor(status, secret0) };
          const err = await errorOf(Promise.resolve().then(() => tool(sc.args, {})));
          expect(err).not.toBeInstanceOf(EffectUncertainError);
          expect(err.message).toMatch(statusRe(status));
          noLeak("the error message", err.message, subject.secrets);
          backend.fault = null;
          expect(fp(sc, backend), "a denied call changed the backend").toEqual(before);
        }
      },
      "no scenarios",
    ),
  );

  // 9. timeout
  results.push(
    await each(
      "timeout",
      scenarios,
      async (sc, m) => {
        const mutating = mutatingOf(m);
        const { backend, tool } = await prepare(sc, 40);
        backend.fault = { kind: "hang", on: mutatingFault(mutating) };
        const deadline = new Promise<never>((_, reject) => {
          const t = setTimeout(() => reject(new Error("the call never returned: the connector applies no timeout")), 2000);
          t.unref();
        });
        const err = await errorOf(Promise.race([Promise.resolve().then(() => tool(sc.args, {})), deadline]));
        if (mutating) expect(err, "a write that never answers must be uncertain").toBeInstanceOf(EffectUncertainError);
        else expect(err, "a read that never answers is a plain error").not.toBeInstanceOf(EffectUncertainError);
        noLeak("the error message", err.message, subject.secrets);
      },
      "no scenarios",
    ),
  );

  // 10. redaction
  results.push(
    await each(
      "redaction",
      scenarios,
      async (sc, m) => {
        const mutating = mutatingOf(m);
        {
          const { backend, tool } = await prepare(sc);
          const result = await tool(sc.args, {});
          noLeak("the returned JSON", JSON.stringify(result ?? null), subject.secrets);
          for (const c of backend.calls) noLeak(`the request ${c.method} ${c.url} (URL or body)`, `${c.url}\n${c.body}`, subject.secrets);
        }
        for (const fault of [
          { kind: "throw", message: `ECONNRESET talking to host with ${secret0}` },
          { kind: "status", status: 500, body: bodyFor(500, secret0) },
        ] as Fault[]) {
          const { backend, tool } = await prepare(sc);
          backend.fault = { ...fault, on: mutatingFault(mutating) } as Fault;
          const err = await errorOf(Promise.resolve().then(() => tool(sc.args, {})));
          noLeak("the error message", err.message, subject.secrets);
        }
      },
      "no scenarios",
    ),
  );

  // 11. dependency block
  {
    const edges = manifests.flatMap((m) => (m.requires ?? []).map((req) => ({ later: m.tool, earlier: req })));
    const usable = edges.filter(
      (e) => scenarios.some((s) => `${probe.name}.${s.tool}` === e.later) && scenarios.some((s) => `${probe.name}.${s.tool}` === e.earlier),
    );
    const declared = subject.notApplicable?.dependency_block;
    if (declared) results.push({ check: "dependency_block", status: "not_applicable", reason: declared, tools: [] });
    else if (edges.length === 0) {
      results.push({ check: "dependency_block", status: "not_applicable", reason: "no tool manifest declares `requires`", tools: [] });
    } else {
      const failures: string[] = [];
      if (usable.length === 0) failures.push("a `requires` edge has no scenario for both tools");
      for (const e of usable) {
        try {
          const first = scenarios.find((s) => `${probe.name}.${s.tool}` === e.earlier)!;
          const second = scenarios.find((s) => `${probe.name}.${s.tool}` === e.later)!;
          const { connector, backend } = subject.make();
          await first.setup?.(backend);
          await second.setup?.(backend);
          const eng = engine([connector]);
          const a = await eng.call(e.earlier, first.args);
          const b = await eng.call(e.later, second.args);
          expect([a.status, b.status]).toEqual(["executed", "executed"]);
          backend.fault = { kind: "status", status: 500 };
          const report = await eng.run.rollback({ compensate: compensatorFor([connector]) });
          expect(report.complete).toBe(false);
          expect(report.deferred, "the earlier step must be deferred while the later one stands").not.toEqual([]);
          const stepA = (a as { step: number }).step;
          const stepB = (b as { step: number }).step;
          expect(report.deferred.find((d) => d.step === stepA)?.blocked_by).toContain(stepB);
        } catch (err) {
          failures.push(`${e.later} requires ${e.earlier}: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
        }
      }
      results.push({
        check: "dependency_block",
        status: failures.length ? "fail" : "pass",
        ...(failures.length ? { reason: failures.join("; ") } : {}),
        tools: usable.map((e) => e.later),
      });
    }
  }

  // 12. manifest drift
  {
    const declared = subject.notApplicable?.manifest_drift;
    if (declared) results.push({ check: "manifest_drift", status: "not_applicable", reason: declared, tools: [] });
    else {
      let reason: string | undefined;
      try {
        const c = subject.make().connector;
        Registry.from(c.manifests);
        const names = manifestsOf(c).map((m) => m.tool);
        expect(Object.keys(c.inputSchemas).sort(), "every manifest needs an input schema").toEqual([...names].sort());
        const baseline = connectorSchemaHashes(c);
        expect(Object.keys(baseline).sort()).toEqual([...names].sort());
        expect(detectManifestDrift(c.manifests, c.inputSchemas, baseline)).toEqual({ added: [], removed: [], changed: [] });
        const victim = names[0]!;
        const changed = { ...c.inputSchemas, [victim]: { ...(c.inputSchemas[victim] as object), properties: { extra: { type: "string" } } } };
        expect(detectManifestDrift(c.manifests, changed, baseline).changed).toEqual([victim]);
        const smaller = { ...c.inputSchemas };
        delete smaller[victim];
        const dropped = detectManifestDrift(
          c.manifests.filter((m) => (m as { tool: string }).tool !== victim),
          smaller,
          baseline,
        );
        expect(dropped.removed).toEqual([victim]);
        const added = detectManifestDrift(c.manifests, c.inputSchemas, Object.fromEntries(Object.entries(baseline).filter(([k]) => k !== victim)));
        expect(added.added).toEqual([victim]);
      } catch (e) {
        reason = e instanceof Error ? e.message.split("\n")[0] : String(e);
      }
      results.push({ check: "manifest_drift", status: reason ? "fail" : "pass", ...(reason ? { reason } : {}), tools: manifests.map((m) => shortName(probe, m.tool)) });
    }
  }

  results.sort((a, b) => CHECK_IDS.indexOf(a.check) - CHECK_IDS.indexOf(b.check));
  return { connector: probe.name, results };
}
