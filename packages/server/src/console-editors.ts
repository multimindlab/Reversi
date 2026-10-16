/** Console pages for editing: manifests (form, YAML, diff, publish workflow, import), policy (editor, builder, versions, simulation), and impact previews. */
import { readFileSync } from "node:fs";
import { parse as parseYaml, stringify } from "yaml";
import {
  ManifestRegistry,
  PolicyVersions,
  Registry,
  authorForm,
  lintManifests,
  parsePolicy,
  previewImpact,
  replayRun,
  renderDiff,
  runManifestTests,
  runPolicyTests,
  simulatePolicy,
  suggestManifests,
  validateManifest,
  type ArgChange,
  type McpToolInfo,
  type PolicyDoc,
} from "@multimindlab/reversi";
import { P, esc, time, type Kit } from "./console-kit.js";

const YAML_OPTS = { lineWidth: 100 } as const;

function dumpManifest(m: unknown): string {
  return stringify(typeof m === "object" && m !== null && "approval_rules" in m ? authorForm(m as never) : m, YAML_OPTS);
}

/** Parse a manifest from the editor: YAML or JSON, one manifest. */
function readManifestText(text: string): { manifest?: Record<string, unknown>; errors: string[] } {
  try {
    const doc = parseYaml(text) as unknown;
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return { errors: ["the text must be one manifest (a mapping)"] };
    const v = validateManifest(doc);
    return v.ok ? { manifest: doc as Record<string, unknown>, errors: [] } : { errors: v.errors };
  } catch (e) {
    return { errors: [`cannot read it as YAML: ${e instanceof Error ? e.message : String(e)}`] };
  }
}

const TEMPLATE = `tool: service.do_thing
description: What this tool does, in a sentence.
effect: reversible          # read_only | idempotent | reversible | compensable | irreversible
permission: service:write
owner: team@example.com
risk: { data_class: internal, blast_radius: low }
timeout_ms: 30s
compensation:
  tool: service.undo_thing
  kind: inverse              # inverse = restores exact state; compensation = may leave residue
  argument_map:
    id: $result.id
`;

export function mountEditorPages(k: Kit): void {
  const { app, guarded, render, form, deps } = k;
  const reg = (): ManifestRegistry | undefined => (deps.opts.registry_dir ? new ManifestRegistry(deps.opts.registry_dir) : undefined);
  const pver = (): PolicyVersions | undefined => (deps.opts.policy_dir ? new PolicyVersions(deps.opts.policy_dir) : undefined);
  const findings = (r: Registry) => lintManifests(r);
  const reload = async (by: string) => (await deps.opts.engine?.reload(by))?.error;

  // ================= manifests =================
  app.get(
    "/console/manifests",
    guarded({ cap: "read" }, (c, s) => {
      const live = k.rv.registry.list();
      const lint = findings(k.rv.registry);
      const r = reg();
      const rows = live
        .map((m) => {
          const f = lint.filter((x) => x.tool === m.tool);
          const errs = f.filter((x) => x.level === "error").length;
          const warns = f.filter((x) => x.level === "warning").length;
          return `<tr><td><a href="/console/manifests/${encodeURIComponent(m.tool)}"><code>${esc(m.tool)}</code></a></td><td>${esc(m.effect)}</td><td>${k.statusBadge(m.status)}</td><td>v${m.version}</td><td>${esc(m.owner ?? "")}</td><td>${esc(m.risk?.data_class ?? "")}</td><td>${m.compensation ? `<code>${esc(m.compensation.tool)}</code>${m.compensation.verification ? " (verified)" : ""}` : '<span class="muted">none</span>'}</td><td>${errs ? `<span class="badge bad">${errs} errors</span> ` : ""}${warns ? `<span class="badge warn">${warns} warnings</span>` : ""}</td></tr>`;
        })
        .join("");
      const drafts = r ? r.tools().filter((t) => r.history(t).at(-1)?.status === "draft") : [];
      return render(
        c,
        s,
        "Manifests",
        `<p>${live.length} enforced manifests. ${r ? `Registry: <code>${esc(deps.opts.registry_dir)}</code>.` : '<span class="muted">The manifests are plain files, so the console shows them but cannot change them. Publish them into a registry folder (<code>reversi manifests publish</code>) and point the server at it to edit them here.</span>'}</p>
<p>${r && k.allowed(s, "rollback") ? '<a href="/console/manifests/new">New manifest</a> · <a href="/console/manifests/import">Draft from an MCP server\'s tools</a> · ' : ""}<a href="/console/tools">Tool inventory</a></p>
${drafts.length ? `<div class="card"><strong>Drafts waiting for approval:</strong> ${drafts.map((t) => `<a href="/console/manifests/${encodeURIComponent(t)}"><code>${esc(t)}</code></a>`).join(", ")}</div>` : ""}
<table><tr><th>Tool</th><th>Effect</th><th>Status</th><th>Version</th><th>Owner</th><th>Data class</th><th>Undo</th><th>Lint</th></tr>${rows || '<tr><td colspan="8" class="muted">No manifests.</td></tr>'}</table>`,
      );
    }),
  );

  // Form-mode builder: a form that produces the YAML.
  const builderForm = (s: Parameters<Kit["form"]>[0], seed: Record<string, string> = {}) => {
    const v = (n: string) => esc(seed[n] ?? "");
    const rows = [0, 1, 2, 3].map((i) => `<tr><td><input type="text" name="map_name${i}" value="${v(`map_name${i}`)}" placeholder="undo argument"></td><td><select name="map_src${i}"><option value="$result"${seed[`map_src${i}`] === "$result" ? " selected" : ""}>from the result</option><option value="$args"${seed[`map_src${i}`] === "$args" ? " selected" : ""}>from the call's arguments</option></select></td><td><input type="text" name="map_path${i}" value="${v(`map_path${i}`)}" placeholder="path, e.g. id"></td></tr>`).join("");
    return `<form method="post" action="/console/manifests/build"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}">
<div class="cols"><div><p><label>Tool name <input type="text" name="tool" value="${v("tool")}" required></label></p>
<p><label>Description <input type="text" name="description" value="${v("description")}" size="50"></label></p>
<p><label>Effect <select name="effect">${["read_only", "idempotent", "reversible", "compensable", "irreversible"].map((e) => `<option${seed.effect === e ? " selected" : ""}>${e}</option>`).join("")}</select></label>
 <label>Permission <input type="text" name="permission" value="${v("permission")}" required></label></p>
<p><label>Owner <input type="text" name="owner" value="${v("owner")}"></label> <label>Data class <input type="text" name="data_class" value="${v("data_class")}"></label> <label>Blast radius <select name="blast_radius"><option value=""></option>${["low", "medium", "high", "critical"].map((e) => `<option${seed.blast_radius === e ? " selected" : ""}>${e}</option>`).join("")}</select></label></p>
<p><label>Timeout <input type="text" name="timeout" value="${v("timeout")}" placeholder="30s" size="6"></label> <label>Approval <select name="approval"><option value="">never (unless irreversible)</option><option value="always"${seed.approval === "always" ? " selected" : ""}>always</option></select></label> <label>Approver groups <input type="text" name="approvers" value="${v("approvers")}" placeholder="finance, risk" size="14"></label> <label>Quorum <input type="number" name="quorum" value="${v("quorum") || "1"}" min="1" max="10" style="width:4em"></label></p></div>
<div><p><strong>Undo</strong> (reversible and compensable tools)</p>
<p><label>Undo tool <input type="text" name="comp_tool" value="${v("comp_tool")}"></label> <label>Kind <select name="comp_kind"><option value="compensation">compensation (may leave residue)</option><option value="inverse"${seed.comp_kind === "inverse" ? " selected" : ""}>inverse (exact)</option></select></label></p>
<p><label>Residue, one per line<br><textarea name="residue" rows="2">${v("residue")}</textarea></label></p>
<table><tr><th>Undo argument</th><th>Where it comes from</th><th>Path</th></tr>${rows}</table>
<p><strong>Verify the undo</strong> (optional)</p>
<p><label>Read-back tool <input type="text" name="ver_tool" value="${v("ver_tool")}"></label> <label>Argument <input type="text" name="ver_arg" value="${v("ver_arg")}" size="8" placeholder="id"> = <input type="text" name="ver_ref" value="${v("ver_ref")}" size="12" placeholder="$result.id"></label> <label>Expect <input type="text" name="ver_expect" value="${v("ver_expect")}" size="14" placeholder="status=canceled"></label></p></div></div>
<button>Build the YAML</button></form>`;
  };

  const editor = (s: Parameters<Kit["form"]>[0], o: { action: string; text: string; title?: string; extra?: string; messages?: string }) => `${o.messages ?? ""}
<form method="post" action="${esc(o.action)}"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}">
<p><textarea name="text" rows="22" spellcheck="false">${esc(o.text)}</textarea></p>
<p><button name="do" value="validate">Validate</button> ${k.allowed(s, "rollback") && reg() ? '<button name="do" value="draft" class="ok">Save as draft</button>' : ""} ${k.allowed(s, "halt") && reg() ? '<button name="do" value="approved" class="bad">Publish as approved</button>' : ""} <input type="text" name="note" placeholder="note (why)"></p>${o.extra ?? ""}</form>`;

  const validation = (text: string, currentText?: string): string => {
    const r = readManifestText(text);
    if (!r.manifest) return `<div class="card" style="border-color:#c33"><strong>Not valid:</strong><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`;
    let lint = "";
    try {
      const m = r.manifest;
      const trial = new Registry();
      for (const x of k.rv.registry.list()) if (x.tool !== m.tool) trial.register(x);
      trial.register(m);
      const f = lintManifests(trial).filter((x) => x.tool === m.tool);
      lint = f.length ? `<ul>${f.map((x) => `<li>${esc(x.level)} ${esc(x.code)}: ${esc(x.message)}</li>`).join("")}</ul>` : "no findings";
      const problems = trial.validate();
      if (problems.length) lint += `<p class="badge bad">references: ${esc(problems.join("; "))}</p>`;
    } catch (e) {
      lint = `<span class="badge bad">${esc(e instanceof Error ? e.message : e)}</span>`;
    }
    const diff = currentText && currentText.trim() !== text.trim() ? `<pre>${esc(renderDiff(currentText, text, 3))}</pre>` : currentText ? '<p class="muted">no change from the current version</p>' : "";
    return `<div class="card" style="border-color:#3a3"><strong>Valid.</strong> Lint: ${lint}${diff ? `<br><strong>Changes</strong>${diff}` : ""}</div>`;
  };

  app.get(
    "/console/manifests/new",
    guarded({ cap: "rollback" }, (c, s) => render(c, s, "New manifest", `<p>Fill in the form, or write the YAML directly.</p>${builderForm(s)}<h2>Or write the YAML</h2>${editor(s, { action: "/console/manifests/save", text: TEMPLATE })}`)),
  );

  app.post(
    "/console/manifests/build",
    guarded({ cap: "rollback", post: true }, (c, s, f) => {
      const g = (n: string) => String(f?.get(n) ?? "").trim();
      const seed: Record<string, string> = {};
      for (const n of ["tool", "description", "effect", "permission", "owner", "data_class", "blast_radius", "timeout", "approval", "approvers", "quorum", "comp_tool", "comp_kind", "residue", "ver_tool", "ver_arg", "ver_ref", "ver_expect"]) seed[n] = g(n);
      const m: Record<string, unknown> = { tool: g("tool"), ...(g("description") ? { description: g("description") } : {}), effect: g("effect"), permission: g("permission") };
      if (g("owner")) m.owner = g("owner");
      if (g("data_class") || g("blast_radius")) m.risk = { ...(g("data_class") ? { data_class: g("data_class") } : {}), ...(g("blast_radius") ? { blast_radius: g("blast_radius") } : {}) };
      if (g("timeout")) m.timeout_ms = g("timeout");
      if (g("approvers")) m.approval = { roles: g("approvers").split(/[,\s]+/).filter(Boolean), quorum: Number(g("quorum") || 1) };
      else if (g("approval") === "always") m.approval = "always";
      if (g("comp_tool")) {
        const argument_map: Record<string, string> = {};
        for (let i = 0; i < 4; i++) {
          const n = g(`map_name${i}`);
          const p = g(`map_path${i}`);
          seed[`map_name${i}`] = n;
          seed[`map_path${i}`] = p;
          seed[`map_src${i}`] = g(`map_src${i}`);
          if (n && p) argument_map[n] = `${g(`map_src${i}`) || "$result"}.${p}`;
        }
        const comp: Record<string, unknown> = { tool: g("comp_tool"), kind: g("comp_kind") || "compensation", argument_map };
        const residue = g("residue").split("\n").map((x) => x.trim()).filter(Boolean);
        if (residue.length) comp.residue = residue;
        if (g("ver_tool") && g("ver_expect")) {
          const expect: Record<string, string> = {};
          for (const part of g("ver_expect").split(",")) {
            const [pa, ...va] = part.split("=");
            if (pa?.trim()) expect[pa.trim()] = va.join("=").trim();
          }
          comp.verification = { tool: g("ver_tool"), arguments: g("ver_arg") && g("ver_ref") ? { [g("ver_arg")]: g("ver_ref") } : {}, expect };
        }
        m.compensation = comp;
      }
      const text = dumpManifest(m);
      return render(c, s, "New manifest", `${builderForm(s, seed)}<h2>The YAML</h2>${editor(s, { action: "/console/manifests/save", text, messages: validation(text) })}`);
    }),
  );

  app.post(
    "/console/manifests/save",
    guarded({ cap: "rollback", post: true }, async (c, s, f) => {
      const text = String(f?.get("text") ?? "");
      const action = String(f?.get("do") ?? "validate");
      const parsed = readManifestText(text);
      const back = (msgs: string, status = 200) => render(c, s, "Manifest", editor(s, { action: "/console/manifests/save", text, messages: msgs }), status);
      if (action === "validate" || !parsed.manifest) return back(validation(text));
      const r = reg();
      if (!r) return back('<div class="card">No registry folder is configured, so this cannot be saved.</div>', 409);
      if (action === "approved" && !k.allowed(s, "halt")) return back('<div class="card">Publishing as approved needs the admin role. Save it as a draft for an admin to approve.</div>', 403);
      try {
        const out = r.publish(parsed.manifest, { by: s.name, note: String(f?.get("note") ?? "").trim() || undefined, status: action === "approved" ? "approved" : "draft", key: deps.opts.engine?.signing_key });
        if (action === "approved") {
          const err = await reload(s.name);
          if (err) return back(`<div class="card" style="border-color:#c33">Saved v${out.version}, but the new configuration did not load: ${esc(err)}</div>`, 409);
        }
        return c.redirect(`/console/manifests/${encodeURIComponent(out.tool)}`, 303);
      } catch (e) {
        return back(`<div class="card" style="border-color:#c33">${esc(e instanceof Error ? e.message : e)}</div>`, 400);
      }
    }),
  );

  app.get(
    "/console/manifests/import",
    guarded({ cap: "rollback" }, async (c, s) => {
      let fetched = "";
      let note = "";
      if (deps.opts.upstream_tools) {
        try {
          fetched = JSON.stringify(await deps.opts.upstream_tools(), null, 2);
          note = "These are the tools the connected upstream offers right now.";
        } catch (e) {
          note = `Could not fetch them: ${e instanceof Error ? e.message : e}`;
        }
      }
      return render(c, s, "Draft manifests from MCP tools", `<p>Paste the <code>tools</code> array from an MCP <code>tools/list</code> response. Reversi drafts a manifest for each tool from its name, schema and annotations. Annotations are the server's own claims: they only ever produce drafts that a person approves. ${esc(note)}</p>
<form method="post" action="/console/manifests/import"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><textarea name="tools" rows="14" spellcheck="false">${esc(fetched)}</textarea></p><p><label>Server name <input type="text" name="server" value="upstream"></label> <button>Draft manifests</button></p></form>`);
    }),
  );
  app.post(
    "/console/manifests/import",
    guarded({ cap: "rollback", post: true }, (c, s, f) => {
      let tools: McpToolInfo[];
      try {
        const raw = JSON.parse(String(f?.get("tools") ?? "[]")) as unknown;
        tools = (Array.isArray(raw) ? raw : (raw as { tools?: McpToolInfo[] }).tools) as McpToolInfo[];
        if (!Array.isArray(tools)) throw new Error("expected an array of tools");
      } catch (e) {
        return render(c, s, "Draft manifests", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 400);
      }
      const r = suggestManifests(tools, { server: String(f?.get("server") ?? "upstream"), existing: k.rv.registry });
      const body = r.suggestions
        .map((sg) => {
          const text = dumpManifest(sg.manifest);
          return `<div class="card"><strong><code>${esc(String(sg.manifest.tool))}</code></strong> <span class="badge ${sg.confidence === "high" ? "ok" : sg.confidence === "medium" ? "warn" : "bad"}">${sg.confidence} confidence</span><ul>${sg.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>${editor(s, { action: "/console/manifests/save", text })}</div>`;
        })
        .join("");
      return render(c, s, "Draft manifests", `<p>${r.suggestions.length} drafted, ${r.skipped.length} skipped because they already have manifests.</p>${body}`);
    }),
  );

  app.get(
    "/console/manifests/:tool",
    guarded({ cap: "read" }, (c, s) => {
      const tool = P(c, "tool");
      const r = reg();
      const live = k.rv.registry.get(tool);
      const hist = r && r.tools().includes(tool) ? r.history(tool) : [];
      const current = r && hist.length ? r.current(tool, true) : live;
      if (!current) return render(c, s, "Manifest not found", `<p>No manifest for <code>${esc(tool)}</code>.</p>`, 404);
      const text = dumpManifest(current);
      const f = lintManifests(k.rv.registry).filter((x) => x.tool === tool);
      const testText = `- name: forward success maps the undo\n  tool: ${tool}\n  args: {}\n  expect_plan: ${current.compensation ? "compensate" : "skip"}\n`;
      return render(
        c,
        s,
        `Manifest ${tool}`,
        `<p>${k.statusBadge(current.status)} v${current.version} · effect <strong>${esc(current.effect)}</strong>${current.owner ? ` · owner ${esc(current.owner)}` : ""} · <a href="/console/impact?tool=${encodeURIComponent(tool)}">impact preview</a></p>
${f.length ? `<div class="card"><strong>Lint</strong><ul>${f.map((x) => `<li>${esc(x.level)} ${esc(x.code)}: ${esc(x.message)}</li>`).join("")}</ul></div>` : ""}
<h2>Edit</h2>${r ? editor(s, { action: "/console/manifests/save", text }) : `<pre>${esc(text)}</pre><p class="muted">Read-only: the manifests are plain files.</p>`}
${
  r && hist.length
    ? `<h2>History</h2><table><tr><th>Version</th><th>Status</th><th>When</th><th>By</th><th>Note</th><th></th></tr>${hist
        .map((h, i) => `<tr><td>v${h.version}</td><td>${k.statusBadge(h.status)}</td><td>${time(h.created_ms)}</td><td>${esc(h.by)}${h.approved_by ? `, approved by ${esc(h.approved_by)}` : ""}${h.signature ? " (signed)" : ""}</td><td>${esc(h.note ?? "")}</td><td>${i > 0 ? `<a href="/console/manifests/${encodeURIComponent(tool)}/diff?a=${hist[i - 1]?.version}&b=${h.version}">diff</a> ` : ""}${k.allowed(s, "halt") ? form(s, `/console/manifests/${encodeURIComponent(tool)}/restore`, `<input type="hidden" name="version" value="${h.version}">`, "Restore") : ""}</td></tr>`)
        .join("")}</table>
${hist.at(-1)?.status === "draft" && k.allowed(s, "halt") ? form(s, `/console/manifests/${encodeURIComponent(tool)}/approve`, `<label><input type="checkbox" name="four_eyes" value="1" checked> the author may not approve it</label> `, "Approve the latest draft", "ok") : ""}
${current.status === "approved" && k.allowed(s, "halt") ? form(s, `/console/manifests/${encodeURIComponent(tool)}/deprecate`, `<input type="text" name="replaced_by" placeholder="replaced by (optional)">`, "Deprecate") : ""}`
    : ""
}
<h2>Contract tests</h2><p class="muted">Run these without touching any system. The YAML is the same format as <code>reversi test</code>.</p>
<form method="post" action="/console/manifests/${encodeURIComponent(tool)}/test"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><textarea name="tests" rows="8" spellcheck="false">${esc(testText)}</textarea></p><button>Run the tests</button></form>`,
      );
    }),
  );

  app.get(
    "/console/manifests/:tool/diff",
    guarded({ cap: "read" }, (c, s) => {
      const r = reg();
      if (!r) return render(c, s, "Diff", "<p>No registry.</p>", 404);
      try {
        const d = r.diff(P(c, "tool"), Number(c.req.query("a")), Number(c.req.query("b")));
        return render(c, s, `${P(c, "tool")}: v${c.req.query("a")} to v${c.req.query("b")}`, `<pre>${esc(d || "(no differences)")}</pre>`);
      } catch (e) {
        return render(c, s, "Diff", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 404);
      }
    }),
  );
  for (const action of ["approve", "deprecate", "restore"] as const) {
    app.post(
      `/console/manifests/:tool/${action}`,
      guarded({ cap: "halt", post: true }, async (c, s, f) => {
        const r = reg();
        const tool = P(c, "tool");
        try {
          if (!r) throw new Error("no registry folder is configured");
          const key = deps.opts.engine?.signing_key;
          if (action === "approve") r.approve(tool, { by: s.name, key, require_other: f?.get("four_eyes") === "1" });
          else if (action === "deprecate") r.deprecate(tool, { by: s.name, key, replaced_by: String(f?.get("replaced_by") ?? "").trim() || undefined });
          else r.rollbackTo(tool, Number(f?.get("version")), { by: s.name, key });
          const err = await reload(s.name);
          if (err) throw new Error(`saved, but the new configuration did not load: ${err}`);
        } catch (e) {
          return render(c, s, "Could not do that", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
        }
        return c.redirect(`/console/manifests/${encodeURIComponent(tool)}`, 303);
      }),
    );
  }
  app.post(
    "/console/manifests/:tool/test",
    guarded({ cap: "read", post: true }, async (c, s, f) => {
      let cases;
      try {
        cases = parseYaml(String(f?.get("tests") ?? "")) as never[];
        if (!Array.isArray(cases)) throw new Error("expected a list of test cases");
      } catch (e) {
        return render(c, s, "Contract tests", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 400);
      }
      const { results } = await runManifestTests(k.rv.registry, cases, { policy: k.rv.policy?.doc, environment: k.rv.environment });
      return render(c, s, "Contract test results", `<table><tr><th>Test</th><th>Result</th></tr>${results.map((x) => `<tr><td>${esc(x.name)}</td><td>${x.ok ? '<span class="badge ok">pass</span>' : `<span class="badge bad">fail</span><ul>${x.problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>`}</td></tr>`).join("")}</table><p><a href="/console/manifests/${encodeURIComponent(P(c, "tool"))}">Back</a></p>`);
    }),
  );

  // ================= policy =================
  app.get(
    "/console/policy",
    guarded({ cap: "read" }, (c, s) => {
      const pv = pver();
      const doc = k.rv.policy?.doc;
      let text = "";
      let active: number | null = null;
      if (pv) {
        active = pv.activeVersion();
        text = active === null ? "version: 1\nrules: []\n" : pv.text(active);
      } else if (deps.opts.engine?.config.policy) {
        try {
          text = readFileSync(deps.opts.engine.config.policy, "utf8");
        } catch {
          text = "";
        }
      }
      const tests = doc ? runPolicyTests(doc) : [];
      const hist = pv ? pv.history() : [];
      const body = `<p>${doc ? `${doc.rules.length} rules, ${doc.limits.length} limits, ${doc.budgets.length} budgets, ${doc.freezes.length} freezes, default <strong>${esc(doc.default)}</strong>${doc.risk ? ", risk scoring on" : ""}.` : "No policy is loaded: only manifests and scopes restrict calls."} ${pv ? `Versions folder: <code>${esc(deps.opts.policy_dir)}</code>, active ${active === null ? "none" : `v${active}`}.` : '<span class="muted">The policy is a plain file, so the console shows it but cannot change it. Point <code>policy:</code> at a folder (<code>reversi policy publish</code>) to edit it here.</span>'}</p>
${tests.length ? `<p>${tests.filter((t) => t.ok).length} of ${tests.length} of the policy's own tests pass.</p>` : ""}
<h2>Rule builder</h2>
<form method="post" action="/console/policy/rule"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><input type="hidden" name="text" value="${esc(text)}">
<p><label>Rule id <input type="text" name="id" required size="16"></label> <label>Action <select name="action"><option>deny</option><option>require_approval</option><option>allow</option></select></label> <label>Reason <input type="text" name="reason" size="30"></label></p>
<p>When the call matches: <label>tool <input type="text" name="tool" placeholder="pay.*" size="12"></label> <label>effect <select name="effect"><option value=""></option>${["read_only", "idempotent", "reversible", "compensable", "irreversible"].map((e) => `<option>${e}</option>`).join("")}</select></label> <label>environment <input type="text" name="environment" size="8"></label> <label>tenant <input type="text" name="tenant" size="8"></label> <label>data class <input type="text" name="data_class" size="8"></label></p>
<p>and, optionally: <label>argument <input type="text" name="path" placeholder="$args.amount" size="14"></label> <select name="op">${["gt", "gte", "lt", "lte", "eq", "ne", "in", "not_in", "matches", "contains", "exists"].map((o) => `<option>${o}</option>`).join("")}</select> <input type="text" name="value" size="10" placeholder="1000"></p>
<p>for approvals: <label>approver groups <input type="text" name="approvers" size="14" placeholder="finance, risk"></label> <label>quorum <input type="number" name="quorum" value="1" min="1" max="10" style="width:4em"></label></p>
<button>Add the rule to the editor</button></form>
<h2>Policy</h2>
<form method="post" action="/console/policy/save"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><textarea name="text" rows="26" spellcheck="false">${esc(text)}</textarea></p>
<p><button name="do" value="validate">Validate and run its tests</button> <button name="do" value="simulate">Simulate against captured history</button> ${pv && k.allowed(s, "halt") ? '<button name="do" value="publish" class="bad">Publish and activate</button> <button name="do" value="publish-inactive">Publish without activating</button>' : ""} <input type="text" name="note" placeholder="note (why)"></p></form>
${hist.length ? `<h2>Versions</h2><table><tr><th>Version</th><th>When</th><th>By</th><th>Tests</th><th>Note</th><th></th></tr>${hist.map((h, i) => `<tr><td>v${h.version}${h.version === active ? ' <span class="badge ok">active</span>' : ""}</td><td>${time(h.created_ms)}</td><td>${esc(h.by)}</td><td>${h.tests_passed}</td><td>${esc(h.note ?? "")}</td><td>${i > 0 ? `<a href="/console/policy/diff?a=${hist[i - 1]?.version}&b=${h.version}">diff</a> ` : ""}${k.allowed(s, "halt") && h.version !== active ? form(s, "/console/policy/activate", `<input type="hidden" name="version" value="${h.version}">`, "Activate") : ""}</td></tr>`).join("")}</table>` : ""}`;
      return render(c, s, "Policy", body);
    }),
  );

  app.post(
    "/console/policy/rule",
    guarded({ cap: "read", post: true }, (c, s, f) => {
      const g = (n: string) => String(f?.get(n) ?? "").trim();
      let doc: Record<string, unknown>;
      try {
        doc = (parseYaml(g("text")) as Record<string, unknown>) ?? { version: 1 };
      } catch {
        doc = { version: 1 };
      }
      const rule: Record<string, unknown> = { id: g("id"), match: {}, action: g("action") };
      const match = rule.match as Record<string, unknown>;
      for (const n of ["tool", "effect", "environment", "tenant", "data_class"]) if (g(n)) match[n] = g(n);
      if (g("path")) {
        let value: unknown = g("value");
        try {
          value = JSON.parse(g("value"));
        } catch {
          /* a plain string */
        }
        rule.when = [{ path: g("path"), op: g("op"), ...(g("op") === "exists" ? {} : { value }) }];
      }
      if (g("reason")) rule.reason = g("reason");
      if (g("action") === "require_approval" && g("approvers")) {
        rule.approvers = g("approvers").split(/[,\s]+/).filter(Boolean);
        rule.quorum = Number(g("quorum") || 1);
      }
      doc.rules = [...((doc.rules as unknown[]) ?? []), rule];
      const text = stringify(doc, YAML_OPTS);
      return render(c, s, "Policy", `<p>Rule added below. Validate it, then publish.</p><form method="post" action="/console/policy/save"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><textarea name="text" rows="26" spellcheck="false">${esc(text)}</textarea></p><p><button name="do" value="validate">Validate and run its tests</button> ${pver() && k.allowed(s, "halt") ? '<button name="do" value="publish" class="bad">Publish and activate</button>' : ""} <input type="text" name="note" placeholder="note"></p></form>`);
    }),
  );

  app.post(
    "/console/policy/save",
    guarded({ cap: "read", post: true }, async (c, s, f) => {
      const text = String(f?.get("text") ?? "");
      const action = String(f?.get("do") ?? "validate");
      const again = (msgs: string, status = 200) =>
        render(c, s, "Policy", `${msgs}<form method="post" action="/console/policy/save"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><textarea name="text" rows="26" spellcheck="false">${esc(text)}</textarea></p><p><button name="do" value="validate">Validate and run its tests</button> <button name="do" value="simulate">Simulate against captured history</button> ${pver() && k.allowed(s, "halt") ? '<button name="do" value="publish" class="bad">Publish and activate</button>' : ""} <input type="text" name="note" placeholder="note"></p></form>`, status);
      let doc: PolicyDoc;
      try {
        doc = parsePolicy(parseYaml(text));
      } catch (e) {
        const errs = (e as { errors?: string[] }).errors ?? [e instanceof Error ? e.message : String(e)];
        return again(`<div class="card" style="border-color:#c33"><strong>Not valid:</strong><ul>${errs.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`);
      }
      const results = runPolicyTests(doc);
      const bad = results.filter((r) => !r.ok);
      const testHtml = `<div class="card" style="border-color:${bad.length ? "#c33" : "#3a3"}"><strong>${bad.length ? `${bad.length} of ${results.length} tests fail` : `Valid. ${results.length} tests pass`}.</strong><ul>${results.map((r) => `<li>${r.ok ? "ok" : "FAIL"}: ${esc(r.name)}${r.ok ? "" : ` (expected ${esc(r.expected)}, got ${esc(r.got)})`}</li>`).join("")}</ul></div>`;
      const pv = pver();
      const activeText = pv && pv.activeVersion() !== null ? pv.text(pv.activeVersion() as number) : undefined;
      const diff = activeText !== undefined && activeText !== text ? `<div class="card"><strong>Changes from the active version</strong><pre>${esc(renderDiff(activeText, text, 3))}</pre></div>` : "";
      if (action === "validate") return again(testHtml + diff);
      if (action === "simulate") {
        const cap = deps.opts.engine?.capture;
        if (!cap) return again(`${testHtml}<div class="card">Capture is off, so there is no history to simulate against. Turn it on (<code>capture: enabled: true</code>) to keep redacted arguments for a limited time.</div>`);
        const rep = await simulatePolicy(cap.list({ since_ms: deps.now() - 7 * 86_400_000 }), { registry: k.rv.registry, policy: doc, environment: k.rv.environment });
        const row = (title: string, l: typeof rep.newly_blocked) => (l.length ? `<h3>${title} (${l.length})</h3><table><tr><th>Run</th><th>Tool</th><th>Change</th><th>Why</th></tr>${l.slice(0, 100).map((x) => `<tr><td>${esc(x.run)}</td><td><code>${esc(x.tool)}</code></td><td>${esc(x.before)} to ${esc(x.after)}</td><td>${esc(x.reasons[0] ?? "")}</td></tr>`).join("")}</table>` : "");
        return again(`${testHtml}<div class="card"><strong>Last 7 days of captured calls:</strong> ${rep.calls} calls in ${rep.runs} runs, ${rep.unchanged} unchanged.${row("Newly blocked", rep.newly_blocked)}${row("Newly needing approval", rep.newly_needs_approval)}${row("Newly allowed", rep.newly_allowed)}${rep.notes.map((n) => `<p class="muted">${esc(n)}</p>`).join("")}</div>`);
      }
      if (!pv || !k.allowed(s, "halt")) return again(`${testHtml}<div class="card">Publishing needs a policy versions folder and the admin role.</div>`, 403);
      try {
        pv.publish(text, { by: s.name, note: String(f?.get("note") ?? "").trim() || undefined, activate: action === "publish" });
        const err = action === "publish" ? await reload(s.name) : undefined;
        if (err) return again(`<div class="card" style="border-color:#c33">Saved, but the new policy did not load: ${esc(err)}</div>`, 409);
      } catch (e) {
        return again(`${testHtml}<div class="card" style="border-color:#c33">${esc(e instanceof Error ? e.message : e)}</div>`, 400);
      }
      return c.redirect("/console/policy", 303);
    }),
  );
  app.get(
    "/console/policy/diff",
    guarded({ cap: "read" }, (c, s) => {
      const pv = pver();
      if (!pv) return render(c, s, "Policy diff", "<p>No policy versions folder.</p>", 404);
      try {
        return render(c, s, `Policy v${c.req.query("a")} to v${c.req.query("b")}`, `<pre>${esc(pv.diff(Number(c.req.query("a")), Number(c.req.query("b"))) || "(no differences)")}</pre>`);
      } catch (e) {
        return render(c, s, "Policy diff", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 404);
      }
    }),
  );
  app.post(
    "/console/policy/activate",
    guarded({ cap: "halt", post: true }, async (c, s, f) => {
      try {
        pver()?.activate(Number(f?.get("version")));
        const err = await reload(s.name);
        if (err) throw new Error(err);
      } catch (e) {
        return render(c, s, "Could not activate", `<p>${esc(e instanceof Error ? e.message : e)}</p>`, 409);
      }
      return c.redirect("/console/policy", 303);
    }),
  );

  // ================= impact, replay =================
  app.get(
    "/console/impact",
    guarded({ cap: "read" }, async (c, s) => {
      const tool = c.req.query("tool") ?? "";
      const argsText = c.req.query("args") ?? "";
      let result = "";
      if (tool) {
        let args: unknown;
        let bad = "";
        if (argsText) {
          try {
            args = JSON.parse(argsText);
          } catch {
            bad = "The arguments are not valid JSON.";
          }
        }
        if (bad) result = `<div class="card" style="border-color:#c33">${bad}</div>`;
        else {
          const p = await previewImpact({ registry: k.rv.registry, policy: k.rv.policy?.doc, environment: k.rv.environment }, { tool, args, actor: c.req.query("actor") || undefined });
          result = `<div class="card"><p><strong>${esc(p.tool)}</strong>: ${p.known ? esc(p.effect) : "no manifest"}${p.status && p.status !== "approved" ? ` (${esc(p.status)})` : ""}. Decision now: <strong>${esc(p.verdict)}</strong>${p.reasons.length ? ` (${esc(p.reasons[0])})` : ""}</p>
${p.risk_score ? `<p>Risk score <strong>${p.risk_score.score}</strong>: ${esc(p.risk_score.factors.join(", ") || "no factors")}</p>` : ""}
${p.risk ? `<p>Data class ${esc(p.risk.data_class ?? "?")}, blast radius ${esc(p.risk.blast_radius ?? "?")}${p.owner ? `, owner ${esc(p.owner)}` : ""}</p>` : ""}
${p.requires.length ? `<p>Needs first: ${p.requires.map((r) => `<code>${esc(r)}</code>`).join(", ")}</p>` : ""}
${p.approval ? `<p>Approvers: ${esc(p.approval.roles.join(" or ") || "any")}, ${p.approval.quorum} needed</p>` : ""}
<p><strong>If approved, rollback outlook:</strong></p><ul>${p.rollback_outlook.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
${p.warnings.length ? `<ul>${p.warnings.map((w) => `<li class="badge warn">${esc(w)}</li>`).join("")}</ul>` : ""}</div>`;
        }
      }
      const names = k.rv.registry.list().map((m) => `<option value="${esc(m.tool)}">`).join("");
      return render(c, s, "Impact preview", `<form method="get" action="/console/impact"><datalist id="tools">${names}</datalist><input type="text" name="tool" list="tools" value="${esc(tool)}" placeholder="tool" size="30" required> <input type="text" name="args" value="${esc(argsText)}" placeholder='arguments as JSON, e.g. {"amount": 500}' size="40"> <input type="text" name="actor" placeholder="actor (optional)"> <button>Preview</button></form>${result}`);
    }),
  );

  app.get(
    "/console/replay/:id",
    guarded({ cap: "rollback" }, (c, s) => render(c, s, `Replay ${P(c, "id")}`, `<p>Replays the captured calls of this run in a sandbox, nothing is executed anywhere. Change an argument and see which decisions differ.</p><form method="post" action="/console/replay/${encodeURIComponent(P(c, "id"))}"><input type="hidden" name="csrf" value="${esc(k.csrf(s))}"><p><label>Step (blank = every matching call) <input type="number" name="step" style="width:5em"></label> <label>Tool (optional) <input type="text" name="tool"></label> <label>Argument path <input type="text" name="path" placeholder="amount" required></label> <label>New value (JSON) <input type="text" name="value" placeholder="9000" required></label> <button>Replay</button></p></form>`)),
  );
  app.post(
    "/console/replay/:id",
    guarded({ cap: "rollback", post: true }, async (c, s, f) => {
      const cap = deps.opts.engine?.capture;
      const records = cap?.list({ run_id: P(c, "id") }) ?? [];
      if (!records.length) return render(c, s, "Replay", "<p>Nothing is captured for that run (capture must be on, and captures expire).</p>", 404);
      let value: unknown = String(f?.get("value") ?? "");
      try {
        value = JSON.parse(String(f?.get("value")));
      } catch {
        /* a plain string */
      }
      const change: ArgChange = { path: String(f?.get("path") ?? ""), value, ...(String(f?.get("step") ?? "") !== "" ? { step: Number(f?.get("step")) } : {}), ...(String(f?.get("tool") ?? "") ? { tool: String(f?.get("tool")) } : {}) };
      const rep = await replayRun(records, { registry: k.rv.registry, policy: k.rv.policy?.doc, environment: k.rv.environment }, [change]);
      return render(c, s, `Replay ${P(c, "id")}`, `<table><tr><th>#</th><th>Tool</th><th>As recorded</th><th>With your change</th><th>Why</th></tr>${rep.variant.map((v, i) => `<tr><td>${i}</td><td><code>${esc(v.tool)}</code></td><td>${esc(rep.baseline[i]?.verdict ?? "")}</td><td>${rep.baseline[i]?.verdict !== v.verdict ? `<strong>${esc(v.verdict)}</strong>` : esc(v.verdict)}</td><td>${esc(v.reasons[0] ?? "")}</td></tr>`).join("")}</table><p>${rep.differences.length} decision${rep.differences.length === 1 ? "" : "s"} would change. Rollback as recorded: ${rep.baseline_plan?.fully_reversible ? "fully reversible" : "not fully reversible"}; with your change: ${rep.variant_plan?.fully_reversible ? "fully reversible" : "not fully reversible"}.</p>`);
    }),
  );
}
