/** Console pages for operating Reversi: alerts, connectors, tool inventory, run comparison, and settings (keys, roles, holds, retention, channels). */
import { ROLES, applyRetention, evaluateAlerts, planRetention, searchRuns, type Role } from "@multimindlab/reversi";
import { P, esc, time, type Kit } from "./console-kit.js";

const CAP_TABLE: Array<[Role, string]> = [
  ["agent", "open and use its own runs"],
  ["auditor", "read runs, evidence and reports"],
  ["approver", "read, and approve or deny calls"],
  ["operator", "read, approve, and roll back"],
  ["admin", "everything, including kill switches, publishing, keys and holds"],
];

export function mountAdminPages(k: Kit): void {
  const { app, guarded, render, form, deps } = k;
  const engine = () => deps.opts.engine;
  const sev = (s: string) => (s === "critical" ? "bad" : s === "warning" ? "warn" : "");

  app.get(
    "/console/alerts",
    guarded({ cap: "read" }, async (c, s) => {
      const health = deps.opts.health ? await deps.opts.health().catch(() => undefined) : undefined;
      const alerts = evaluateAlerts(k.rv, deps.approvals, { now: deps.now(), health, ...(engine()?.config.alerts?.denial_spike ? { denial_spike: engine()?.config.alerts?.denial_spike } : {}) });
      const rows = alerts
        .map((a) => `<tr><td><span class="badge ${sev(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.title)}</td><td>${esc(a.detail)}</td><td>${time(a.ts_ms)}</td><td>${a.run_id ? `<a href="/console/runs/${encodeURIComponent(a.run_id)}">${esc(a.run_id)}</a>` : ""}</td></tr>`)
        .join("");
      return render(c, s, "Alerts", `<p>Computed live from the ledger, approvals and upstream health. ${engine()?.alerts ? "Each alert is also sent once to the notification channels, with reminders while it lasts." : "Notifications are not configured."}</p><table><tr><th>Severity</th><th>What</th><th>Detail</th><th>Since</th><th>Run</th></tr>${rows || '<tr><td colspan="5" class="muted">Nothing needs attention.</td></tr>'}</table>`);
    }),
  );

  app.get(
    "/console/connectors",
    guarded({ cap: "read" }, async (c, s) => {
      const list = deps.opts.connectors ? await deps.opts.connectors().catch(() => []) : [];
      const rows = list
        .map((x) => `<tr><td><code>${esc(x.name)}</code></td><td>${esc(x.kind)}</td><td><span class="badge ${x.healthy ? "ok" : "bad"}">${x.healthy ? "healthy" : "unreachable"}</span></td><td>${x.tools}</td><td>${x.classified}</td><td>${x.unclassified ? `<span class="badge warn">${x.unclassified}</span>` : 0}</td><td>${esc(x.credential ?? "")}</td><td>${esc(x.detail ?? "")}</td></tr>`)
        .join("");
      return render(c, s, "Connectors", `<p>The systems whose tools Reversi governs. Unclassified tools have no manifest: they are blocked in enforce mode and only observed in observe mode.</p><table><tr><th>Name</th><th>Kind</th><th>Health</th><th>Tools</th><th>With manifest</th><th>Unclassified</th><th>Credential</th><th>Detail</th></tr>${rows || '<tr><td colspan="8" class="muted">No connectors are reported. The gateway supplies this list.</td></tr>'}</table>`);
    }),
  );

  app.get(
    "/console/tools",
    guarded({ cap: "read" }, async (c, s) => {
      const manifested = new Set(k.rv.registry.list().map((m) => m.tool));
      let upstream: Array<{ name: string }> = [];
      try {
        upstream = deps.opts.upstream_tools ? await deps.opts.upstream_tools() : [];
      } catch {
        /* upstream unreachable: show the manifests only */
      }
      const used = new Map<string, number>();
      for (const r of searchRuns(k.rv, { limit: 500 }).runs) for (const t of r.tools) used.set(t, (used.get(t) ?? 0) + 1);
      const unclassified = upstream.filter((t) => !manifested.has(t.name));
      const names = [...new Set([...manifested, ...upstream.map((t) => t.name), ...used.keys()])].sort();
      const rows = names
        .map((n) => {
          const m = k.rv.registry.get(n);
          return `<tr><td><code>${esc(n)}</code></td><td>${m ? esc(m.effect) : '<span class="badge warn">unclassified</span>'}</td><td>${m ? k.statusBadge(m.status) : ""}</td><td>${upstream.some((t) => t.name === n) ? "yes" : upstream.length ? "no" : ""}</td><td>${used.get(n) ?? 0}</td><td>${m ? `<a href="/console/manifests/${encodeURIComponent(n)}">manifest</a>` : k.allowed(s, "rollback") ? '<a href="/console/manifests/import">draft one</a>' : ""}</td></tr>`;
        })
        .join("");
      return render(c, s, "Tool inventory", `<p>${manifested.size} classified, ${unclassified.length} unclassified${upstream.length ? ` of ${upstream.length} offered by the upstream` : ""}. Use counts come from the 500 most recent runs.</p><table><tr><th>Tool</th><th>Effect</th><th>Status</th><th>Offered now</th><th>Runs</th><th></th></tr>${rows || '<tr><td colspan="6" class="muted">No tools yet.</td></tr>'}</table>`);
    }),
  );

  app.get(
    "/console/compare",
    guarded({ cap: "read" }, (c, s) => {
      const a = c.req.query("a") ?? "";
      const b = c.req.query("b") ?? "";
      const side = (id: string) => {
        const st = id ? k.rv.runs.get(id) : undefined;
        if (!st) return id ? `<p>No run <code>${esc(id)}</code>.</p>` : "";
        return `<table><tr><th>#</th><th>Tool</th><th>Effect</th><th>Status</th></tr>${st.steps.map((x) => `<tr><td>${x.step}</td><td><code>${esc(x.tool)}</code></td><td>${esc(x.effect)}</td><td>${esc(x.status)}</td></tr>`).join("")}</table><p class="muted">${esc(st.actor)} · ${st.mode} · ${time(st.created_ms)}</p>`;
      };
      return render(c, s, "Compare runs", `<form method="get" action="/console/compare"><input type="text" name="a" value="${esc(a)}" placeholder="run id" size="30"> <input type="text" name="b" value="${esc(b)}" placeholder="run id" size="30"> <button>Compare</button></form><div class="cols"><div>${side(a)}</div><div>${side(b)}</div></div>`);
    }),
  );

  // ================= settings =================
  app.get(
    "/console/settings",
    guarded({ cap: "read" }, (c, s) => {
      const e = engine();
      const admin = k.allowed(s, "halt");
      const keys = deps.extras.keys;
      const keyRows = keys.enabled()
        ? keys
            .list()
            .map((x) => `<tr><td>${esc(x.name)}</td><td>${esc(x.roles.join(", "))}</td><td>${esc(x.groups.join(", "))}</td><td>${esc(x.tenant ?? "")}</td><td>${x.expires_at ? esc(typeof x.expires_at === "number" ? time(x.expires_at) : x.expires_at) : ""}</td><td><code>${esc(x.fingerprint.slice(0, 12))}</code></td><td>${x.disabled ? '<span class="badge bad">disabled</span>' : '<span class="badge ok">active</span>'}</td><td>${admin ? form(s, `/console/settings/keys/${x.index}/${x.disabled ? "enable" : "disable"}`, "", x.disabled ? "Enable" : "Disable") + " " + form(s, `/console/settings/keys/${x.index}/remove`, "", "Remove", "bad") : ""}</td></tr>`)
            .join("")
        : "";
      const holds = e?.holds.list() ?? [];
      const cfg = k.rv.policy?.doc.retention;
      const plan = cfg && e ? planRetention(k.rv, cfg, e.holds, deps.now()) : [];
      const due = plan.filter((p) => p.due && !p.held).length;
      const channels = e?.notifier?.channelNames() ?? [];
      const body = `
<h2>Environment</h2><div class="card">Environment <strong>${esc(k.rv.environment ?? "(not set)")}</strong> · console mode <strong>${esc(deps.mode)}</strong>${deps.mode === "open" ? ` as <strong>${esc(deps.open_role)}</strong>` : ""} · ledger head ${esc(String(k.rv.ledger.head()).slice(0, 16))}${e?.config.capture?.enabled ? " · capture on" : " · capture off"}${e?.config.egress ? " · egress guard on" : ""}</div>
<h2>Roles</h2><table><tr><th>Role</th><th>May</th></tr>${CAP_TABLE.map(([r, d]) => `<tr><td>${r}</td><td>${esc(d)}</td></tr>`).join("")}</table>
<h2>Users and API keys</h2>${keys.enabled() ? `<table><tr><th>Name</th><th>Roles</th><th>Groups</th><th>Tenant</th><th>Expires</th><th>Fingerprint</th><th>State</th><th></th></tr>${keyRows}</table>${admin ? `<form method="post" action="/console/settings/keys"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><label>Name <input type="text" name="name" required></label> <label>Role <select name="role">${ROLES.map((r) => `<option>${r}</option>`).join("")}</select></label> <label>Groups <input type="text" name="groups" size="14" placeholder="finance, risk"></label> <label>Tenant <input type="text" name="tenant" size="8"></label> <label>Expires in days <input type="number" name="days" style="width:5em"></label> <button>Create a key</button></p></form>` : ""}` : '<p class="muted">Keys are managed outside the server (no keys file is configured), or sign-in uses OIDC.</p>'}
<h2>Legal holds</h2>${e ? `<table><tr><th>Id</th><th>Scope</th><th>Reason</th><th>By</th><th>Since</th><th></th></tr>${holds.map((h) => `<tr><td><code>${esc(h.id)}</code></td><td>${esc(JSON.stringify(h.scope))}</td><td>${esc(h.reason)}</td><td>${esc(h.by)}</td><td>${time(h.ts_ms)}</td><td>${admin ? form(s, `/console/settings/holds/${encodeURIComponent(h.id)}/release`, "", "Release") : ""}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">No holds.</td></tr>'}</table>${admin ? `<form method="post" action="/console/settings/holds"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><label>Run <input type="text" name="run_id" size="20"></label> <label>Tenant <input type="text" name="tenant" size="8"></label> <label>Actor <input type="text" name="actor" size="8"></label> <label>Tool <input type="text" name="tool" size="12"></label> <label>Reason <input type="text" name="reason" size="24" required></label> <button>Place a hold</button></p></form>` : ""}` : '<p class="muted">Needs the engine services.</p>'}
<h2>Retention</h2>${cfg ? `<p>Default ${cfg.default_days} days. ${plan.length} runs tracked, ${due} due for deletion now (holds respected).</p>${admin ? `${form(s, "/console/settings/retention", '<input type="hidden" name="dry" value="1">', "Dry run")} ${form(s, "/console/settings/retention", "", "Apply now (deletes runs)", "bad")}` : ""}` : '<p class="muted">No <code>retention:</code> section in the policy: nothing is ever deleted.</p>'}
<h2>Notification channels</h2>${channels.length ? `<p>${channels.map((n) => `<code>${esc(n)}</code>`).join(", ")}</p>${admin ? form(s, "/console/settings/notify-test", "", "Send a test notification") : ""}` : '<p class="muted">None configured (<code>notifications:</code> in the project file).</p>'}
<h2>Integrations</h2><ul><li>Slack approvals: ${deps.opts.slack ? "enabled" : "off"}</li><li>OpenTelemetry traces: ${e?.otel ? "on" : "off"}</li><li>Anchoring: ${e?.config.anchor ? `${e.config.anchor.sinks.length} sink(s)` : "off"}</li><li>Evidence signing: ${deps.signing_available ? "on" : "off"}</li><li>Data residency: ${e?.config.egress ? "outbound addresses are checked against the egress rules" : "no egress rules; set <code>egress:</code> to restrict where data can be sent"}</li></ul>`;
      return render(c, s, "Settings", body);
    }),
  );

  const back = (c: Parameters<Kit["redirect"]>[0]) => k.redirect(c, "/console/settings");
  const fail = (c: Parameters<Kit["redirect"]>[0], s: Parameters<Kit["render"]>[1], e: unknown) => render(c, s, "Could not do that", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);

  app.post(
    "/console/settings/keys",
    guarded({ cap: "halt", post: true }, (c, s, f) => {
      try {
        const g = (n: string) => String(f?.get(n) ?? "").trim();
        const role = g("role") as Role;
        if (!ROLES.includes(role)) throw new Error("unknown role");
        const key = deps.extras.keys.create({ name: g("name"), roles: [role], groups: g("groups").split(/[,\s]+/).filter(Boolean), tenant: g("tenant") || undefined, expires_in_days: g("days") ? Number(g("days")) : undefined });
        return render(c, s, "Key created", `<div class="card"><p>Copy this key now. It is not stored and cannot be shown again.</p><pre>${esc(key)}</pre></div><p><a href="/console/settings">Back to settings</a></p>`);
      } catch (e) {
        return fail(c, s, e);
      }
    }),
  );
  for (const act of ["disable", "enable", "remove"] as const) {
    app.post(
      `/console/settings/keys/:i/${act}`,
      guarded({ cap: "halt", post: true }, (c, s) => {
        try {
          const i = Number(P(c, "i"));
          if (act === "remove") deps.extras.keys.remove(i);
          else deps.extras.keys.disable(i, act === "disable");
          return back(c);
        } catch (e) {
          return fail(c, s, e);
        }
      }),
    );
  }
  app.post(
    "/console/settings/holds",
    guarded({ cap: "halt", post: true }, (c, s, f) => {
      try {
        const g = (n: string) => String(f?.get(n) ?? "").trim() || undefined;
        engine()?.holds.add({ run_id: g("run_id"), tenant: g("tenant"), actor: g("actor"), tool: g("tool") }, g("reason") ?? "", s.name);
        return back(c);
      } catch (e) {
        return fail(c, s, e);
      }
    }),
  );
  app.post(
    "/console/settings/holds/:id/release",
    guarded({ cap: "halt", post: true }, (c, s) => {
      engine()?.holds.release(P(c, "id"));
      return back(c);
    }),
  );
  app.post(
    "/console/settings/retention",
    guarded({ cap: "halt", post: true }, (c, s, f) => {
      const e = engine();
      const cfg = k.rv.policy?.doc.retention;
      if (!e || !cfg) return fail(c, s, "no retention settings");
      const rep = applyRetention(k.rv, cfg, { holds: e.holds, approvals: e.approvals, capture: e.capture, dry_run: f?.get("dry") === "1", key: e.signing_key, now: deps.now(), actor: s.name });
      return render(c, s, "Retention", `<p>${rep.dry_run ? "Dry run: nothing deleted. Would delete" : "Deleted"} ${rep.purged.length} runs; skipped ${rep.skipped.length}.</p><ul>${rep.skipped.map((x) => `<li>${esc(x.run_id)}: ${esc(x.reason)}</li>`).join("")}</ul><p><a href="/console/settings">Back</a></p>`);
    }),
  );
  app.post(
    "/console/settings/notify-test",
    guarded({ cap: "halt", post: true }, async (c, s) => {
      const r = await engine()?.notifier?.notify({ event: "test", severity: "info", title: "Reversi test notification", text: `Sent from the console by ${s.name}.` });
      return render(c, s, "Test notification", `<p>Sent to: ${esc((r?.sent ?? []).join(", ") || "nobody")}. Failed: ${esc((r?.failed ?? []).join(", ") || "none")}.</p><p><a href="/console/settings">Back</a></p>`);
    }),
  );
}
