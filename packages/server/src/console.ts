/**
 * Server-rendered operator console. No client-side JavaScript: every action is a form POST guarded by a CSRF token, and
 * every value is HTML-escaped under a strict Content-Security-Policy.
 *
 * Modes (set by the server, `off` by default):
 *   off    nothing is served under /console
 *   open   no login. Only requests addressed to localhost from the same origin are answered, and the console acts with a
 *          fixed role (operator by default, never admin). For your own machine.
 *   login  an API key or OIDC token is exchanged for a signed, HttpOnly, SameSite=Strict cookie that is re-checked
 *          against the key ring on every request.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Context, Hono } from "hono";
import {
  can,
  evaluateAlerts,
  previewImpact,
  type ApprovalRecord,
  type Capability,
  type LedgerRecord,
  type Principal,
  type Role,
} from "@multimindlab/reversi";
import { mountAdminPages } from "./console-admin.js";
import { mountEditorPages } from "./console-editors.js";
import { P, esc, layout, time, type ConsoleDeps, type ConsoleMode, type Kit, type Session } from "./console-kit.js";

export type { ConsoleDeps, ConsoleMode } from "./console-kit.js";

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const hostnameOf = (host: string) => (host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : (host.split(":")[0] ?? "")).toLowerCase();
const isLoopbackName = (h: string) => LOOPBACK.has(h) || /^127(\.\d{1,3}){3}$/.test(h);

export function mountConsole(app: Hono, deps: ConsoleDeps): void {
  if (deps.mode === "off") {
    app.all("/console", (c) => c.text("The console is off. Start Reversi with REVERSI_CONSOLE=open (on your own machine, no login) or REVERSI_CONSOLE=login.", 404));
    app.all("/console/*", (c) => c.text("The console is off. Start Reversi with REVERSI_CONSOLE=open (on your own machine, no login) or REVERSI_CONSOLE=login.", 404));
    return;
  }
  const { reversi, approvals } = deps;
  const open = deps.mode === "open";
  const sign = (data: string) => createHmac("sha256", deps.session_secret).update(data).digest("base64url");
  const csrfFor = (s: Session) => sign(`csrf:${s.sid}`);

  const secure = (c: Context) => {
    c.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "no-referrer");
  };

  // Open mode: refuse anything that is not plainly the user's own browser talking to localhost.
  if (open) {
    app.use("/console/*", async (c, next) => {
      const host = c.req.header("host") ?? "";
      const origin = c.req.header("origin");
      const fetchSite = c.req.header("sec-fetch-site");
      const bad = !isLoopbackName(hostnameOf(host)) || (origin !== undefined && new URL(origin).host !== host) || (fetchSite !== undefined && !["same-origin", "none"].includes(fetchSite));
      if (bad) {
        secure(c);
        return c.html(layout({ title: "Not allowed", session: null, mode: deps.mode, can: () => false, body: "<p>The console in open mode only answers requests made from this machine to <code>localhost</code>. Use <code>REVERSI_CONSOLE=login</code> to serve it to other people.</p>" }), 403);
      }
      await next();
    });
  }
  app.use("/console/*", async (c, next) => {
    // the login form is reachable without credentials: keep its body small
    if (c.req.method === "POST") {
      const len = Number(c.req.header("content-length") ?? 0);
      if (len > 262_144) return c.text("body too large", 413);
    }
    await next();
  });

  const openSession = (): Session => ({ name: "local-console", roles: [deps.open_role], exp: Number.MAX_SAFE_INTEGER, sid: "open", open: true });

  /** Sessions ended by logout. The cookie is stateless, so remember them until they would have expired anyway. */
  const revoked = new Map<string, number>();

  const readSession = (c: Context): Session | null => {
    if (open) return openSession();
    const raw = /(?:^|;\s*)rv_session=([^;]+)/.exec(c.req.header("cookie") ?? "")?.[1];
    if (!raw) return null;
    const [payload, mac] = raw.split(".");
    if (!payload || !mac) return null;
    const want = Buffer.from(sign(payload));
    const got = Buffer.from(mac);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
    try {
      const s = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Session;
      if (s.exp <= deps.now() || revoked.has(s.sid)) return null;
      if (s.fp) {
        const live = deps.byFingerprint(s.fp);
        if (!live) return null; // the key was disabled, expired or removed
        return { ...s, name: live.name, roles: live.roles, groups: live.groups ?? [] }; // and roles follow the key's current roles
      }
      return s;
    } catch {
      return null;
    }
  };

  const principalOf = (s: Session): Principal => ({ name: s.name, roles: s.roles as Role[], via: "api_key" });
  const allowed = (s: Session, cap: Capability) => can(principalOf(s), cap);
  const nav = () => ({ pending: approvals.list({ status: "pending" }).length, critical: evaluateAlerts(reversi, approvals, { now: deps.now() }).filter((a) => a.severity === "critical").length });
  const html = (c: Context, status: number, body: string) => {
    secure(c);
    return c.html(body, status as 200);
  };

  const render: Kit["render"] = (c, s, title, body, status = 200) =>
    html(c, status, layout({ title, session: s, body, nav: nav(), csrf: csrfFor(s), halted: reversi.halted(), mode: deps.mode, can: (cap) => allowed(s, cap) }));

  const guarded: Kit["guarded"] = (opts, fn) => async (c) => {
    const s = readSession(c);
    if (!s || (s.roles.includes("agent") && s.roles.length === 1)) {
      if (opts.post) return html(c, 401, layout({ title: "Signed out", session: null, mode: deps.mode, can: () => false, body: `<p>Your session ended. <a href="/console/login">Sign in again</a>.</p>` }));
      return c.redirect("/console/login");
    }
    let form: FormData | null = null;
    if (opts.post) {
      form = await c.req.formData().catch(() => null);
      const t = String(form?.get("csrf") ?? "");
      const want = Buffer.from(csrfFor(s));
      if (t.length !== want.length || !timingSafeEqual(Buffer.from(t), want)) return render(c, s, "Forbidden", "<p>Invalid or missing CSRF token. Go back, reload the page and try again.</p>", 403);
    }
    if (opts.cap && !allowed(s, opts.cap)) return render(c, s, "Forbidden", `<p>Your role does not allow this.</p>`, 403);
    secure(c);
    return fn(c, s, form);
  };

  const form: Kit["form"] = (s, action, fields, label, cls = "") =>
    `<form class="inline" method="post" action="${esc(action)}"><input type="hidden" name="csrf" value="${esc(csrfFor(s))}">${fields}<button class="${cls}">${esc(label)}</button></form>`;
  const statusBadge = (st: string) => `<span class="badge ${["succeeded", "compensated", "no_action", "approved", "consumed", "verified"].includes(st) ? "ok" : ["failed", "compensation_failed", "unrecoverable", "uncertain", "intended", "denied", "verification_failed"].includes(st) ? "bad" : "warn"}">${esc(st)}</span>`;

  const kit: Kit = {
    app,
    deps,
    rv: reversi,
    engine: deps.opts.engine,
    guarded,
    render,
    form,
    csrf: csrfFor,
    principal: principalOf,
    allowed,
    statusBadge,
    redirect: (c, to) => c.redirect(to, 303),
  };

  // ---- login (login mode only) ----
  if (open) {
    app.get("/console/login", (c) => c.redirect("/console/runs"));
    app.post("/console/logout", (c) => c.redirect("/console/runs", 303));
  } else {
    app.get("/console/login", (c) =>
      html(c, 200, layout({ title: "Sign in", session: null, mode: deps.mode, can: () => false, body: `<form method="post" action="/console/login"><p>Paste an API key or an OIDC access token for an auditor, approver, operator or admin.</p><p><input type="password" name="key" size="48" autocomplete="off" autofocus> <button>Sign in</button></p></form>` })),
    );
    app.post("/console/login", async (c) => {
      const f = await c.req.formData().catch(() => null);
      const p = await deps.authenticate(String(f?.get("key") ?? ""));
      if (!p || (p.roles.length === 1 && p.roles[0] === "agent")) {
        return html(c, 401, layout({ title: "Sign in", session: null, mode: deps.mode, can: () => false, body: `<p><strong>That credential was not accepted, or it has no console role.</strong></p><p><a href="/console/login">Try again</a></p>` }));
      }
      // An OIDC session never outlives the token it came from.
      const exp = Math.min(deps.now() + deps.session_ttl_ms, p.exp_ms ?? Infinity);
      const s: Session = { name: p.name, roles: p.roles, groups: p.groups ?? [], exp, sid: randomBytes(12).toString("hex"), ...(p.fingerprint ? { fp: p.fingerprint } : {}) };
      const payload = Buffer.from(JSON.stringify(s)).toString("base64url");
      c.header("Set-Cookie", `rv_session=${payload}.${sign(payload)}; Path=/console; HttpOnly; SameSite=Strict; Max-Age=${Math.max(0, Math.floor((exp - deps.now()) / 1000))}${deps.secure_cookies ? "; Secure" : ""}`);
      return c.redirect("/console/runs", 303);
    });
    app.post(
      "/console/logout",
      guarded({ post: true }, (c, s) => {
        revoked.set(s.sid, s.exp);
        for (const [sid, exp] of revoked) if (exp <= deps.now()) revoked.delete(sid);
        c.header("Set-Cookie", "rv_session=; Path=/console; HttpOnly; SameSite=Strict; Max-Age=0");
        return c.redirect("/console/login", 303);
      }),
    );
  }
  app.get("/console", (c) => c.redirect("/console/runs"));

  // ---- runs ----
  const needsAttention = (r: { steps: Array<{ status: string }> }, unresolved: number[]) => unresolved.length > 0 || r.steps.some((s) => ["compensation_failed", "unrecoverable", "uncertain"].includes(s.status));

  app.get(
    "/console/runs",
    guarded({ cap: "read" }, (c, s) => {
      const actor = c.req.query("actor") ?? "";
      const tenant = c.req.query("tenant") ?? "";
      const tool = c.req.query("tool") ?? "";
      const only = c.req.query("filter") ?? "";
      const rows = reversi
        .runIds()
        .map((id) => {
          const run = reversi.openRun(id);
          return { st: run.state(), unresolved: run.unresolved() };
        })
        .filter((r) => (!actor || r.st.actor === actor) && (!tenant || r.st.tenant === tenant) && (!tool || r.st.steps.some((x) => x.tool === tool)) && (only !== "attention" || needsAttention(r.st, r.unresolved)))
        .sort((a, b) => b.st.created_ms - a.st.created_ms);
      const body = `<form method="get"><input type="text" name="actor" placeholder="actor" value="${esc(actor)}"> <input type="text" name="tenant" placeholder="tenant" value="${esc(tenant)}"> <input type="text" name="tool" placeholder="tool" value="${esc(tool)}"> <select name="filter"><option value="">all runs</option><option value="attention"${only === "attention" ? " selected" : ""}>needs attention</option></select> <button>Filter</button></form>
<table><tr><th>Run</th><th>Actor</th><th>Tenant</th><th>Mode</th><th>Started</th><th>Steps</th><th>Attention</th></tr>${
        rows
          .map(({ st, unresolved }) => `<tr><td><a href="/console/runs/${encodeURIComponent(st.run_id)}">${esc(st.run_id)}</a></td><td>${esc(st.actor)}</td><td>${esc(st.tenant ?? "")}</td><td>${esc(st.mode)}</td><td>${time(st.created_ms)}</td><td>${st.steps.length}</td><td>${needsAttention(st, unresolved) ? `<span class="badge bad">needs attention</span>` : ""}</td></tr>`)
          .join("") || `<tr><td colspan="7" class="muted">No runs.</td></tr>`
      }</table><p><a href="/console/compare">Compare two runs</a></p>`;
      return render(c, s, "Runs", body);
    }),
  );

  const approvalTable = (s: Session, list: ApprovalRecord[], canDecide: boolean, impact = false) =>
    `<table><tr><th>Requested</th><th>Run</th><th>Tool</th><th>Kind</th><th>Why approval is needed</th><th>Who may decide</th><th>Arguments</th><th>Status</th><th></th></tr>${
      list
        .map((a) => {
          const progress = (a.quorum ?? 1) > 1 ? ` (${(a.decisions ?? []).filter((d) => d.decision === "approve").length}/${a.quorum})` : "";
          const imp = impact ? `<br><a href="/console/impact?tool=${encodeURIComponent(a.tool)}&actor=${encodeURIComponent(a.requested_by ?? "")}">impact preview</a>` : "";
          return `<tr><td>${time(a.requested_ms)}<br><span class="muted">expires ${time(a.expires_ms)}</span></td><td><a href="/console/runs/${encodeURIComponent(a.run_id)}">${esc(a.run_id)}</a></td><td><code>${esc(a.tool)}</code>${imp}</td><td>${esc(a.kind)}</td><td>${esc(a.triggers.join("; "))}<br><span class="muted">${esc(a.reason)}</span></td><td>${a.required_roles?.length ? esc(a.required_roles.join(" or ")) : "any approver"}${progress}${a.escalated ? ' <span class="badge warn">escalated</span>' : ""}</td><td>${a.arg_keys.map((k) => `<code>${esc(k)}</code>`).join(" ")}${a.args_hash ? `<br><span class="muted">hash ${esc(a.args_hash.slice(0, 10))}</span>` : ""}</td><td>${statusBadge(a.status)}${a.decided_by ? `<br><span class="muted">${esc(a.decided_by)}${a.decision_note ? `: ${esc(a.decision_note)}` : ""}</span>` : ""}${a.break_glass ? `<br><span class="badge bad">break-glass</span>` : ""}</td><td>${
            canDecide && a.status === "pending"
              ? form(s, `/console/approvals/${encodeURIComponent(a.id)}/approve`, `<input type="text" name="note" placeholder="note (optional)">`, "Approve", "ok") + " " + form(s, `/console/approvals/${encodeURIComponent(a.id)}/deny`, `<input type="text" name="note" placeholder="reason">`, "Deny") + (allowed(s, "halt") ? "<br>" + form(s, `/console/approvals/${encodeURIComponent(a.id)}/break-glass`, `<input type="text" name="reason" placeholder="why (10+ characters)" required> <input type="text" name="evidence" placeholder="ticket / incident" required>`, "Break-glass", "bad") : "") : ""
          }</td></tr>`;
        })
        .join("") || `<tr><td colspan="9" class="muted">None.</td></tr>`
    }</table>`;

  const stepVerifications = (recs: LedgerRecord[]) => recs.filter((r) => ["verified", "verification_failed", "unverified"].includes(r.event));

  app.get(
    "/console/runs/:id",
    guarded({ cap: "read" }, async (c, s) => {
      const id = P(c, "id");
      let run;
      try {
        run = reversi.openRun(id);
      } catch {
        return render(c, s, "Run not found", `<p>No run <code>${esc(id)}</code>.</p>`, 404);
      }
      const st = run.state();
      const plan = run.plan();
      const unresolved = run.unresolved();
      const recs = reversi.ledger.forRun(id) as LedgerRecord[];
      const pend = approvals.list({ run_id: id, status: "pending" });
      const canRollback = allowed(s, "rollback");
      const canApprove = allowed(s, "approve");
      const job = deps.extras.rollbackStatus(id);
      const ver = stepVerifications(recs);
      const failedComp = st.steps.some((x) => x.status === "compensation_failed");
      const refresh = job?.running ? `<meta http-equiv="refresh" content="2">` : "";
      const cap = deps.opts.engine?.capture;
      const body = `${refresh}<p>Actor <strong>${esc(st.actor)}</strong> · mode <strong>${esc(st.mode)}</strong>${st.tenant ? ` · tenant <strong>${esc(st.tenant)}</strong>` : ""} · started ${time(st.created_ms)} · scope <code>${esc(st.scope.permissions.join(" "))}</code></p>
<p><a href="/console/runs/${encodeURIComponent(id)}/report">Auditor report (HTML)</a> · <a href="/console/runs/${encodeURIComponent(id)}/report.pdf">PDF</a>${deps.signing_available ? ` · <a href="/console/runs/${encodeURIComponent(id)}/bundle">Signed evidence bundle</a>` : ""}${cap ? ` · <a href="/console/replay/${encodeURIComponent(id)}">Replay with a change</a>` : ""}</p>
${pend.length ? `<h2>Pending approvals</h2>${approvalTable(s, pend, canApprove, true)}` : ""}
<h2>Steps</h2><table><tr><th>#</th><th>Tool</th><th>Effect</th><th>Status</th><th>Risk</th><th>Error</th><th></th></tr>${st.steps
        .map(
          (x) =>
            `<tr><td>${x.step}</td><td><code>${esc(x.tool)}</code></td><td>${esc(x.effect ?? "no manifest")}</td><td>${statusBadge(x.status)}</td><td>${x.risk_score ?? ""}</td><td>${esc(x.error ?? "")}</td><td>${
              canRollback && (x.status === "intended" || x.status === "uncertain")
                ? form(s, `/console/runs/${encodeURIComponent(id)}/steps/${x.step}/resolve`, `<select name="status"><option>succeeded</option><option>failed</option></select> <input type="text" name="note" placeholder="how you checked" required>`, "Resolve")
                : ""
            }</td></tr>`,
        )
        .join("") || `<tr><td colspan="7" class="muted">No steps.</td></tr>`}</table>
<h2>Rollback plan <span class="muted">(dry run, nothing executed)</span></h2>
<p>${plan.fully_reversible ? `<span class="badge ok">fully reversible</span> assuming each compensation succeeds` : `<span class="badge bad">not fully reversible</span>`}</p>
<table><tr><th>Step</th><th>Tool</th><th>Action</th><th>Detail</th><th>Residue</th><th>Verified</th></tr>${plan.actions
        .map((a) => `<tr><td>${a.step}</td><td><code>${esc(a.tool)}</code></td><td>${esc(a.kind)}</td><td>${esc(a.kind === "compensate" ? `${a.compensation_tool}${a.needs_approval ? " (needs approval)" : ""}` : a.kind === "defer" ? `waits for step ${a.blocked_by?.join(", ")}` : (a.note ?? ""))}</td><td>${esc((a.residue ?? []).join("; "))}</td><td>${a.verified ? "read back after the undo" : ""}</td></tr>`)
        .join("") || `<tr><td colspan="6" class="muted">Nothing to undo.</td></tr>`}</table>
${
  deps.opts.compensator && canRollback
    ? `<div class="card"><strong>Run the rollback</strong>${job ? `<p>${job.running ? `Running since ${time(job.started_ms)} by ${esc(job.by)}… this page refreshes.` : job.error ? `Last attempt failed: ${esc(job.error)}` : job.report ? `Last attempt ${job.report.complete ? "completed" : "was INCOMPLETE"}: compensated ${esc(job.report.compensated.join(", ") || "-")}${job.report.failed.length ? `; failed ${esc(job.report.failed.map((f) => `${f.step} (${f.error})`).join("; "))}` : ""}${job.report.unverified.length ? `; unverified ${esc(job.report.unverified.join(", "))}` : ""}` : ""}</p>` : ""}${
        job?.running
          ? ""
          : form(s, `/console/runs/${encodeURIComponent(id)}/rollback`, `<label><input type="checkbox" name="approve_compensations" value="1"> also approve compensations that need approval</label> `, failedComp || job ? "Retry the rollback" : "Execute the rollback", "bad")
      }</div>`
    : `<p class="muted">The console shows the plan. ${deps.opts.compensator ? "" : "To execute it, start the server with a compensator (REVERSI_COMPENSATOR_CMD) or use the gateway's operator tools, "}<code>reversi rollback ${esc(id)}</code> or the operator API.${unresolved.length ? ` Unresolved steps: ${unresolved.join(", ")}.` : ""}</p>`
}
${canRollback && (failedComp || st.steps.some((x) => x.status === "unrecoverable")) ? form(s, `/console/runs/${encodeURIComponent(id)}/escalate`, `<input type="text" name="note" placeholder="what the on-call needs to know">`, "Escalate to on-call") : ""}
${ver.length ? `<h2>Verification of the undo</h2><table><tr><th>Time</th><th>Step</th><th>Result</th><th>Detail</th></tr>${ver.map((r) => `<tr><td>${time(r.ts_ms)}</td><td>${r.step ?? ""}</td><td>${statusBadge(r.event)}</td><td>${esc(r.detail)}</td></tr>`).join("")}</table>` : ""}
<h2>Event trail</h2><table><tr><th>seq</th><th>Time</th><th>Step</th><th>Event</th><th>Tool</th><th>Actor</th><th>Reason</th><th>Detail</th></tr>${recs
        .map((r) => `<tr><td>${r.seq}</td><td>${time(r.ts_ms)}</td><td>${r.step ?? ""}</td><td>${esc(r.event)}</td><td><code>${esc(r.tool)}</code></td><td>${esc(r.actor)}</td><td>${esc(r.reason)}</td><td>${esc(r.detail)}</td></tr>`)
        .join("")}</table>`;
      return render(c, s, `Run ${id}`, body);
    }),
  );

  app.get("/console/runs/:id/report", guarded({ cap: "read" }, (c) => {
    try {
      return c.html(deps.report(P(c, "id")));
    } catch {
      return c.text("run not found", 404);
    }
  }));
  app.get("/console/runs/:id/report.pdf", guarded({ cap: "read" }, async (c) => {
    const { renderReportPdf } = await import("@multimindlab/reversi");
    try {
      const run = reversi.openRun(P(c, "id"));
      const pdf = renderReportPdf({ run: run.state(), records: reversi.ledger.forRun(P(c, "id")), plan: run.plan(), ledger_head: reversi.ledger.head(), region: deps.opts.engine?.egress.region });
      return c.body(new Uint8Array(pdf), 200, { "Content-Type": "application/pdf", "Content-Disposition": `inline; filename="reversi-${P(c, "id")}.pdf"` });
    } catch {
      return c.text("run not found", 404);
    }
  }));

  const download = (c: Context, run_id: string | null) => {
    try {
      const body = JSON.stringify(deps.bundle(run_id), null, 2);
      return c.body(body, 200, { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="reversi-evidence-${run_id ?? "ledger"}.json"` });
    } catch (e) {
      return c.text(e instanceof Error ? e.message : "bundle unavailable", 404);
    }
  };
  app.get("/console/runs/:id/bundle", guarded({ cap: "read" }, (c) => download(c, P(c, "id"))));
  app.get("/console/bundle", guarded({ cap: "read" }, (c) => download(c, null)));

  app.post(
    "/console/runs/:id/steps/:n/resolve",
    guarded({ cap: "rollback", post: true }, (c, s, f) => {
      const status = String(f?.get("status"));
      const note = String(f?.get("note") ?? "").trim();
      try {
        if (status !== "succeeded" && status !== "failed") throw new Error("status must be succeeded or failed");
        reversi.openRun(P(c, "id")).resolve(Number(P(c, "n")), { status }, { actor: s.name, note });
      } catch (e) {
        return render(c, s, "Could not resolve", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
      }
      return c.redirect(`/console/runs/${encodeURIComponent(P(c, "id"))}`, 303);
    }),
  );

  app.post(
    "/console/runs/:id/rollback",
    guarded({ cap: "rollback", post: true }, (c, s, f) => {
      try {
        deps.extras.startRollback(P(c, "id"), s.name, { approve_compensations: f?.get("approve_compensations") === "1" && allowed(s, "approve") });
      } catch (e) {
        return render(c, s, "Could not start the rollback", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
      }
      return c.redirect(`/console/runs/${encodeURIComponent(P(c, "id"))}`, 303);
    }),
  );

  app.post(
    "/console/runs/:id/escalate",
    guarded({ cap: "rollback", post: true }, async (c, s, f) => {
      const id = P(c, "id");
      const note = String(f?.get("note") ?? "").trim();
      reversi.ledger.append({ ts_ms: deps.now(), run_id: id, actor: s.name, tool: "-", reason: note || "escalated by an operator", event: "escalated", detail: `escalated to on-call by ${s.name}` });
      await deps.opts.engine?.notifier?.notify({ event: "alert", severity: "critical", title: `Escalation: run ${id}`, text: `${s.name} escalated run ${id} to on-call.${note ? ` ${note}` : ""}`, dedup_key: `escalation:${id}` });
      return c.redirect(`/console/runs/${encodeURIComponent(id)}`, 303);
    }),
  );

  // ---- approvals ----
  app.get(
    "/console/approvals",
    guarded({ cap: "read" }, (c, s) => {
      const ok = allowed(s, "approve");
      const recent = approvals.list().filter((a) => a.status !== "pending").sort((a, b) => b.requested_ms - a.requested_ms).slice(0, 50);
      const dg = deps.opts.engine?.delegations;
      return render(
        c,
        s,
        "Approvals",
        `<h2>Pending</h2>${approvalTable(s, approvals.list({ status: "pending" }), ok, true)}<h2>Recent decisions</h2>${approvalTable(s, recent, false)}${
          dg && ok
            ? `<h2>Delegation</h2><p class="muted">Hand your approval authority to someone for a while. They approve as themselves, on your behalf, and you cannot also vote on the same request.</p>${form(s, "/console/delegations", `<input type="text" name="to" placeholder="delegate to" required> <input type="number" name="hours" value="24" min="1" max="2160" style="width:5em"> hours <input type="text" name="reason" placeholder="why" required>`, "Delegate")}<table><tr><th>From</th><th>To</th><th>Until</th><th>Reason</th><th></th></tr>${dg.list().filter((d) => !d.revoked && d.until_ms > deps.now()).map((d) => `<tr><td>${esc(d.from)}</td><td>${esc(d.to)}</td><td>${time(d.until_ms)}</td><td>${esc(d.reason)}</td><td>${d.from === s.name || allowed(s, "halt") ? form(s, `/console/delegations/${encodeURIComponent(d.id)}/revoke`, "", "Revoke") : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">None in force.</td></tr>'}</table>`
            : ""
        }`,
      );
    }),
  );
  const identityOf = (s: Session) => ({ roles: s.roles, groups: [] as string[] });
  const groupsOf = (s: Session): string[] => s.groups ?? [];
  for (const decision of ["approve", "deny"] as const) {
    app.post(
      `/console/approvals/:id/${decision}`,
      guarded({ cap: "approve", post: true }, (c, s, f) => {
        try {
          const note = String(f?.get("note") ?? "").trim() || undefined;
          const who = { ...identityOf(s), groups: groupsOf(s) };
          if (decision === "approve") approvals.approve(P(c, "id"), s.name, note, who);
          else approvals.deny(P(c, "id"), s.name, note, who);
        } catch (e) {
          return render(c, s, "Could not decide", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
        }
        return c.redirect("/console/approvals", 303);
      }),
    );
  }
  app.post(
    "/console/approvals/:id/break-glass",
    guarded({ cap: "halt", post: true }, (c, s, f) => {
      try {
        approvals.breakGlass(P(c, "id"), s.name, { reason: String(f?.get("reason") ?? ""), evidence: String(f?.get("evidence") ?? "") }, { ...identityOf(s), groups: groupsOf(s) });
      } catch (e) {
        return render(c, s, "Could not break glass", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
      }
      return c.redirect("/console/approvals", 303);
    }),
  );
  app.post(
    "/console/delegations",
    guarded({ cap: "approve", post: true }, (c, s, f) => {
      const dg = deps.opts.engine?.delegations;
      try {
        if (!dg) throw new Error("delegation is not enabled");
        dg.grant({ from: s.name, to: String(f?.get("to") ?? "").trim(), until_ms: deps.now() + Number(f?.get("hours")) * 3_600_000, reason: String(f?.get("reason") ?? "") });
      } catch (e) {
        return render(c, s, "Could not delegate", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 400);
      }
      return c.redirect("/console/approvals", 303);
    }),
  );
  app.post(
    "/console/delegations/:id/revoke",
    guarded({ cap: "approve", post: true }, (c, s) => {
      deps.opts.engine?.delegations.revoke(P(c, "id"));
      return c.redirect("/console/approvals", 303);
    }),
  );

  // ---- evidence and kill switches ----
  app.get(
    "/console/evidence",
    guarded({ cap: "read" }, (c, s) => {
      const v = reversi.ledger.verify();
      const admin = allowed(s, "halt");
      const halts = reversi.halts();
      const file = reversi.halted();
      const body = `<div class="card">Ledger: ${v.ok ? `<span class="badge ok">chain verified</span> ${v.records} records, head <code>${esc(v.head)}</code>` : `<span class="badge bad">TAMPERED or corrupt at record ${v.seq}</span> ${esc(v.error)}`}</div>
<p>${deps.signing_available ? `<a href="/console/bundle">Download signed bundle of the whole ledger</a>` : `<span class="muted">Signed bundles are off: start the server with a signing key.</span>`}</p>
<h2>Kill switches</h2>
<table><tr><th>Reason</th><th>Scope</th><th>By</th><th>Since</th><th></th></tr>${halts.map((h) => `<tr><td>${esc(h.reason)}</td><td>${Object.keys(h.scope).length ? esc(Object.entries(h.scope).map(([k, x]) => `${k}=${x}`).join(", ")) : "everything"}</td><td>${esc(h.by)}</td><td>${time(h.ts_ms)}</td><td>${admin ? form(s, "/console/resume", `<input type="hidden" name="id" value="${esc(h.id)}">`, "Lift") : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">None. A kill-switch file may still be active.</td></tr>'}</table>
${file && !halts.length ? `<p>Active: ${esc(file)}</p>` : ""}
${admin ? form(s, "/console/halt", `<input type="text" name="reason" placeholder="reason" required> <input type="text" name="tool" placeholder="tool glob (optional)"> <input type="text" name="actor" placeholder="actor (optional)"> <input type="text" name="tenant" placeholder="tenant (optional)"> <input type="text" name="environment" placeholder="environment (optional)">`, "Block new calls", "bad") : `<p class="muted">Admin role needed to change kill switches.</p>`}`;
      return render(c, s, "Evidence", body);
    }),
  );
  app.post(
    "/console/halt",
    guarded({ cap: "halt", post: true }, (c, s, f) => {
      const scope: Record<string, string> = {};
      for (const k of ["tool", "actor", "tenant", "environment"]) {
        const v = String(f?.get(k) ?? "").trim();
        if (v) scope[k] = v;
      }
      reversi.halt(`${String(f?.get("reason") ?? "").trim() || "halted"} (by ${s.name})`, scope as never, s.name);
      return c.redirect("/console/evidence", 303);
    }),
  );
  app.post(
    "/console/resume",
    guarded({ cap: "halt", post: true }, (c, _s, f) => {
      const id = String(f?.get("id") ?? "");
      reversi.resume(id || undefined);
      return c.redirect("/console/evidence", 303);
    }),
  );

  mountEditorPages(kit);
  mountAdminPages(kit);
  void previewImpact;
}
