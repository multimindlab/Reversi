/**
 * Server-rendered operator console. No client-side JavaScript: every action is a form POST guarded
 * by a session cookie (HttpOnly, SameSite=Strict) and a per-session CSRF token. All values are
 * HTML-escaped; a strict Content-Security-Policy backs that up.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Context, Hono } from "hono";
import { can, type Approvals, type ApprovalRecord, type LedgerRecord, type Principal, type Reversi, type Role, type RunState } from "@multimindlab/reversi";

const esc = (v: unknown) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
const P = (c: Context, name: string): string => c.req.param(name) ?? "";
const time = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 19) + "Z";

export interface ConsoleDeps {
  reversi: Reversi;
  approvals: Approvals;
  authenticate: (token: string) => Promise<Principal | null>;
  session_secret: string;
  secure_cookies: boolean;
  session_ttl_ms: number;
  signing_available: boolean;
  report: (run_id: string) => string;
  bundle: (run_id: string | null) => unknown;
  now: () => number;
}

interface Session {
  name: string;
  roles: Role[];
  exp: number;
  sid: string;
}

const CSS = `body{font:14px/1.5 system-ui,sans-serif;margin:0;color:#1b1b1f;background:#fafafa}header{background:#1F5FD6;color:#fff;padding:.6rem 1.2rem;display:flex;gap:1.2rem;align-items:center;flex-wrap:wrap}header a{color:#fff;text-decoration:none}header .sp{flex:1}main{max-width:1150px;margin:1.2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;background:#fff;margin:.6rem 0 1.4rem}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f0f2f6}code{background:#eef;padding:0 3px;border-radius:3px}.badge{display:inline-block;padding:0 7px;border-radius:9px;background:#ddd;font-size:12px}.bad{background:#fbb}.ok{background:#bfb}.warn{background:#fe9}form.inline{display:inline}button{cursor:pointer;padding:3px 10px}.card{background:#fff;border:1px solid #ddd;padding:.8rem 1rem;margin:.6rem 0 1.2rem}input[type=text],input[type=password],select{padding:3px 6px}.muted{color:#666}`;

function page(title: string, s: Session | null, body: string, pending = 0, csrf = "", d?: ConsoleDeps): string {
  const nav = s
    ? `<a href="/console/runs">Runs</a><a href="/console/approvals">Approvals${pending ? ` <span class="badge warn">${pending}</span>` : ""}</a><a href="/console/tools">Tools</a><a href="/console/evidence">Evidence</a><span class="sp"></span><span>${esc(s.name)} (${esc(s.roles.join(", "))})</span><form class="inline" method="post" action="/console/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button>Log out</button></form>`
    : "";
  const halted = d?.reversi.halted();
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Reversi Console</title><style>${CSS}</style></head><body><header><strong>Reversi Console</strong>${nav}</header><main>${halted ? `<div class="card" style="border-color:#c33"><strong>Kill switch active:</strong> ${esc(halted)}. New tool calls are blocked.</div>` : ""}<h1>${esc(title)}</h1>${body}</main></body></html>`;
}

const statusBadge = (st: string) =>
  `<span class="badge ${["succeeded", "compensated", "no_action"].includes(st) ? "ok" : ["failed", "compensation_failed", "unrecoverable", "uncertain", "intended"].includes(st) ? "bad" : ""}">${esc(st)}</span>`;

export function mountConsole(app: Hono, deps: ConsoleDeps): void {
  const { reversi, approvals } = deps;
  const sign = (data: string) => createHmac("sha256", deps.session_secret).update(data).digest("base64url");
  const csrfFor = (s: Session) => sign(`csrf:${s.sid}`);

  const secure = (c: Context) => {
    c.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "no-referrer");
  };

  const readSession = (c: Context): Session | null => {
    const raw = /(?:^|;\s*)rv_session=([^;]+)/.exec(c.req.header("cookie") ?? "")?.[1];
    if (!raw) return null;
    const [payload, mac] = raw.split(".");
    if (!payload || !mac) return null;
    const want = Buffer.from(sign(payload));
    const got = Buffer.from(mac);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
    try {
      const s = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Session;
      return s.exp > deps.now() ? s : null;
    } catch {
      return null;
    }
  };

  const principalOf = (s: Session): Principal => ({ name: s.name, roles: s.roles, via: "api_key" });
  const html = (c: Context, status: number, body: string) => {
    secure(c);
    return c.html(body, status as 200);
  };

  /** Run a handler with a valid session (and, for POST, a valid CSRF token). */
  const guarded =
    (opts: { cap?: Parameters<typeof can>[1]; post?: boolean }, fn: (c: Context, s: Session, form: FormData | null) => Promise<Response> | Response) =>
    async (c: Context) => {
      const s = readSession(c);
      if (!s || s.roles.includes("agent") && s.roles.length === 1) {
        if (opts.post) return html(c, 401, page("Signed out", null, `<p>Your session ended. <a href="/console/login">Sign in again</a>.</p>`));
        return c.redirect("/console/login");
      }
      let form: FormData | null = null;
      if (opts.post) {
        form = await c.req.formData().catch(() => null);
        const t = String(form?.get("csrf") ?? "");
        const want = Buffer.from(csrfFor(s));
        if (t.length !== want.length || !timingSafeEqual(Buffer.from(t), want)) return html(c, 403, page("Forbidden", s, "<p>Invalid or missing CSRF token. Go back, reload the page and try again.</p>", 0, csrfFor(s), deps));
      }
      if (opts.cap && !can(principalOf(s), opts.cap)) return html(c, 403, page("Forbidden", s, `<p>Your role does not allow this.</p>`, 0, csrfFor(s), deps));
      secure(c);
      return fn(c, s, form);
    };

  const render = (c: Context, s: Session, title: string, body: string, status = 200) =>
    html(c, status, page(title, s, body, approvals.list({ status: "pending" }).length, csrfFor(s), deps));

  const form = (s: Session, action: string, fields: string, label: string, cls = "") =>
    `<form class="inline" method="post" action="${esc(action)}"><input type="hidden" name="csrf" value="${esc(csrfFor(s))}">${fields}<button class="${cls}">${esc(label)}</button></form>`;

  // ---- login ----
  app.get("/console/login", (c) =>
    html(c, 200, page("Sign in", null, `<form method="post" action="/console/login"><p>Paste an API key or an OIDC access token for an auditor, approver, operator or admin.</p><p><input type="password" name="key" size="48" autocomplete="off" autofocus> <button>Sign in</button></p></form>`)),
  );
  app.post("/console/login", async (c) => {
    const f = await c.req.formData().catch(() => null);
    const p = await deps.authenticate(String(f?.get("key") ?? ""));
    if (!p || (p.roles.length === 1 && p.roles[0] === "agent")) {
      return html(c, 401, page("Sign in", null, `<p><strong>That credential was not accepted, or it has no console role.</strong></p><p><a href="/console/login">Try again</a></p>`));
    }
    const s: Session = { name: p.name, roles: p.roles, exp: deps.now() + deps.session_ttl_ms, sid: randomBytes(12).toString("hex") };
    const payload = Buffer.from(JSON.stringify(s)).toString("base64url");
    c.header(
      "Set-Cookie",
      `rv_session=${payload}.${sign(payload)}; Path=/console; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(deps.session_ttl_ms / 1000)}${deps.secure_cookies ? "; Secure" : ""}`,
    );
    return c.redirect("/console/runs", 303);
  });
  app.post(
    "/console/logout",
    guarded({ post: true }, (c) => {
      c.header("Set-Cookie", "rv_session=; Path=/console; HttpOnly; SameSite=Strict; Max-Age=0");
      return c.redirect("/console/login", 303);
    }),
  );
  app.get("/console", (c) => c.redirect("/console/runs"));

  // ---- runs ----
  const needsAttention = (r: RunState, unresolved: number[]) =>
    unresolved.length > 0 || r.steps.some((s) => ["compensation_failed", "unrecoverable", "uncertain"].includes(s.status));

  app.get(
    "/console/runs",
    guarded({ cap: "read" }, (c, s) => {
      const actor = c.req.query("actor") ?? "";
      const only = c.req.query("filter") ?? "";
      const rows = reversi
        .runIds()
        .map((id) => {
          const run = reversi.openRun(id);
          const st = run.state();
          return { st, unresolved: run.unresolved() };
        })
        .filter((r) => (!actor || r.st.actor === actor) && (only !== "attention" || needsAttention(r.st, r.unresolved)))
        .sort((a, b) => b.st.created_ms - a.st.created_ms);
      const body = `<form method="get"><input type="text" name="actor" placeholder="actor" value="${esc(actor)}"> <select name="filter"><option value="">all runs</option><option value="attention"${only === "attention" ? " selected" : ""}>needs attention</option></select> <button>Filter</button></form>
<table><tr><th>Run</th><th>Actor</th><th>Mode</th><th>Started</th><th>Steps</th><th>Attention</th></tr>${
        rows
          .map(
            ({ st, unresolved }) =>
              `<tr><td><a href="/console/runs/${encodeURIComponent(st.run_id)}">${esc(st.run_id)}</a></td><td>${esc(st.actor)}</td><td>${esc(st.mode)}</td><td>${time(st.created_ms)}</td><td>${st.steps.length}</td><td>${needsAttention(st, unresolved) ? `<span class="badge bad">needs attention</span>` : ""}</td></tr>`,
          )
          .join("") || `<tr><td colspan="6" class="muted">No runs.</td></tr>`
      }</table>`;
      return render(c, s, "Runs", body);
    }),
  );

  app.get(
    "/console/runs/:id",
    guarded({ cap: "read" }, (c, s) => {
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
      const recs: LedgerRecord[] = reversi.ledger.forRun(id) as LedgerRecord[];
      const pend = approvals.list({ run_id: id, status: "pending" });
      const canRollback = can(principalOf(s), "rollback");
      const canApprove = can(principalOf(s), "approve");
      const body = `<p>Actor <strong>${esc(st.actor)}</strong> · mode <strong>${esc(st.mode)}</strong> · started ${time(st.created_ms)} · scope <code>${esc(st.scope.permissions.join(" "))}</code></p>
<p><a href="/console/runs/${encodeURIComponent(id)}/report">Auditor report (HTML)</a>${deps.signing_available ? ` · <a href="/console/runs/${encodeURIComponent(id)}/bundle">Signed evidence bundle</a>` : ""}</p>
${pend.length ? `<h2>Pending approvals</h2>${approvalTable(s, pend, canApprove)}` : ""}
<h2>Steps</h2><table><tr><th>#</th><th>Tool</th><th>Effect</th><th>Status</th><th>Error</th><th></th></tr>${st.steps
        .map(
          (x) =>
            `<tr><td>${x.step}</td><td><code>${esc(x.tool)}</code></td><td>${esc(x.effect ?? "no manifest")}</td><td>${statusBadge(x.status)}</td><td>${esc(x.error ?? "")}</td><td>${
              canRollback && (x.status === "intended" || x.status === "uncertain")
                ? form(s, `/console/runs/${encodeURIComponent(id)}/steps/${x.step}/resolve`, `<select name="status"><option>succeeded</option><option>failed</option></select> <input type="text" name="note" placeholder="how you checked" required>`, "Resolve")
                : ""
            }</td></tr>`,
        )
        .join("") || `<tr><td colspan="6" class="muted">No steps.</td></tr>`}</table>
<h2>Rollback plan <span class="muted">(dry run, nothing executed)</span></h2>
<p>${plan.fully_reversible ? `<span class="badge ok">fully reversible</span> assuming each compensation succeeds` : `<span class="badge bad">not fully reversible</span>`}</p>
<table><tr><th>Step</th><th>Tool</th><th>Action</th><th>Detail</th></tr>${plan.actions
        .map((a) => `<tr><td>${a.step}</td><td><code>${esc(a.tool)}</code></td><td>${esc(a.kind)}</td><td>${esc(a.kind === "compensate" ? `${a.compensation_tool}${a.needs_approval ? " (needs approval)" : ""}` : a.kind === "defer" ? `waits for step ${a.blocked_by?.join(", ")}` : (a.note ?? ""))}</td></tr>`)
        .join("") || `<tr><td colspan="4" class="muted">Nothing to undo.</td></tr>`}</table>
<p class="muted">Execute with <code>reversi rollback ${esc(id)} --compensator-cmd …</code> or the operator API; the console never runs compensations itself.${unresolved.length ? ` Unresolved steps: ${unresolved.join(", ")}.` : ""}</p>
<h2>Event trail</h2><table><tr><th>seq</th><th>Time</th><th>Step</th><th>Event</th><th>Tool</th><th>Actor</th><th>Reason</th><th>Detail</th></tr>${recs
        .map((r) => `<tr><td>${r.seq}</td><td>${time(r.ts_ms)}</td><td>${r.step ?? ""}</td><td>${esc(r.event)}</td><td><code>${esc(r.tool)}</code></td><td>${esc(r.actor)}</td><td>${esc(r.reason)}</td><td>${esc(r.detail)}</td></tr>`)
        .join("")}</table>`;
      return render(c, s, `Run ${id}`, body);
    }),
  );

  app.get(
    "/console/runs/:id/report",
    guarded({ cap: "read" }, (c) => {
      try {
        return c.html(deps.report(P(c, "id")));
      } catch {
        return c.text("run not found", 404);
      }
    }),
  );

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

  // ---- approvals ----
  const approvalTable = (s: Session, list: ApprovalRecord[], canDecide: boolean) =>
    `<table><tr><th>Requested</th><th>Run</th><th>Tool</th><th>Kind</th><th>Why approval is needed</th><th>Arguments</th><th>Status</th><th></th></tr>${
      list
        .map(
          (a) =>
            `<tr><td>${time(a.requested_ms)}</td><td><a href="/console/runs/${encodeURIComponent(a.run_id)}">${esc(a.run_id)}</a></td><td><code>${esc(a.tool)}</code></td><td>${esc(a.kind)}</td><td>${esc(a.triggers.join("; "))}<br><span class="muted">${esc(a.reason)}</span></td><td>${a.arg_keys.map((k) => `<code>${esc(k)}</code>`).join(" ")}${a.args_hash ? `<br><span class="muted">hash ${esc(a.args_hash.slice(0, 10))}</span>` : ""}</td><td>${statusBadge(a.status)}${a.decided_by ? `<br><span class="muted">${esc(a.decided_by)}${a.decision_note ? `: ${esc(a.decision_note)}` : ""}</span>` : ""}</td><td>${
              canDecide && a.status === "pending"
                ? form(s, `/console/approvals/${encodeURIComponent(a.id)}/approve`, `<input type="text" name="note" placeholder="note (optional)">`, "Approve", "ok") + " " + form(s, `/console/approvals/${encodeURIComponent(a.id)}/deny`, `<input type="text" name="note" placeholder="reason">`, "Deny")
                : ""
            }</td></tr>`,
        )
        .join("") || `<tr><td colspan="8" class="muted">None.</td></tr>`
    }</table>`;

  app.get(
    "/console/approvals",
    guarded({ cap: "read" }, (c, s) => {
      const ok = can(principalOf(s), "approve");
      const recent = approvals.list().filter((a) => a.status !== "pending").sort((a, b) => b.requested_ms - a.requested_ms).slice(0, 50);
      return render(c, s, "Approvals", `<h2>Pending</h2>${approvalTable(s, approvals.list({ status: "pending" }), ok)}<h2>Recent decisions</h2>${approvalTable(s, recent, false)}`);
    }),
  );
  for (const decision of ["approve", "deny"] as const) {
    app.post(
      `/console/approvals/:id/${decision}`,
      guarded({ cap: "approve", post: true }, (c, s, f) => {
        try {
          const note = String(f?.get("note") ?? "").trim() || undefined;
          if (decision === "approve") approvals.approve(P(c, "id"), s.name, note);
          else approvals.deny(P(c, "id"), s.name, note);
        } catch (e) {
          return render(c, s, "Could not decide", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
        }
        return c.redirect("/console/approvals", 303);
      }),
    );
  }

  // ---- tools inventory ----
  app.get(
    "/console/tools",
    guarded({ cap: "read" }, (c, s) => {
      const known = new Set(reversi.registry.list().map((m) => m.tool));
      const unmanifested = new Set<string>();
      for (const id of reversi.runIds()) for (const st of reversi.openRun(id).state().steps) if (!known.has(st.tool)) unmanifested.add(st.tool);
      const rows = reversi.registry
        .list()
        .map(
          (m) =>
            `<tr><td><code>${esc(m.tool)}</code></td><td>${esc(m.effect)}${m.effect === "irreversible" ? ` <span class="badge bad">irreversible</span>` : ""}</td><td><code>${esc(m.permission)}</code></td><td>${esc(m.approval)}</td><td>${m.compensation ? `<code>${esc(m.compensation.tool)}</code>${m.compensation.requires_approval ? " (approval)" : ""}` : `<span class="muted">none</span>`}</td></tr>`,
        )
        .join("");
      return render(
        c,
        s,
        "Tools",
        `<p>${reversi.registry.size} manifests. Environment <code>${esc(reversi.environment)}</code>.</p><table><tr><th>Tool</th><th>Effect</th><th>Permission</th><th>Approval</th><th>Compensation</th></tr>${rows}</table>
<h2>Called without a manifest</h2>${unmanifested.size ? `<p>${[...unmanifested].map((t) => `<code>${esc(t)}</code>`).join(" ")}</p>` : `<p class="muted">None seen.</p>`}`,
      );
    }),
  );

  // ---- evidence and kill switch ----
  app.get(
    "/console/evidence",
    guarded({ cap: "read" }, (c, s) => {
      const v = reversi.ledger.verify();
      const admin = can(principalOf(s), "halt");
      const halted = reversi.halted();
      const body = `<div class="card">Ledger: ${v.ok ? `<span class="badge ok">chain verified</span> ${v.records} records, head <code>${esc(v.head)}</code>` : `<span class="badge bad">TAMPERED or corrupt at record ${v.seq}</span> ${esc(v.error)}`}</div>
<p>${deps.signing_available ? `<a href="/console/bundle">Download signed bundle of the whole ledger</a>` : `<span class="muted">Signed bundles are off: start the server with a signing key.</span>`}</p>
<h2>Kill switch</h2>${
        admin
          ? halted
            ? `<p>Active: ${esc(halted)}</p>${form(s, "/console/resume", "", "Resume new calls", "ok")}`
            : form(s, "/console/halt", `<input type="text" name="reason" placeholder="reason" required>`, "Block all new calls", "bad")
          : `<p class="muted">${halted ? `Active: ${esc(halted)}` : "Not active."} Admin role needed to change it.</p>`
      }`;
      return render(c, s, "Evidence", body);
    }),
  );
  app.post(
    "/console/halt",
    guarded({ cap: "halt", post: true }, (c, s, f) => {
      reversi.halt(`${String(f?.get("reason") ?? "").trim() || "halted"} (by ${s.name})`);
      return c.redirect("/console/evidence", 303);
    }),
  );
  app.post(
    "/console/resume",
    guarded({ cap: "halt", post: true }, (c) => {
      reversi.resume();
      return c.redirect("/console/evidence", 303);
    }),
  );
}
