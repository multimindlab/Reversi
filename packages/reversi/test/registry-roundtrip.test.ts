import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ManifestRegistry, authorForm, validateManifest } from "../src/index.js";

const M = { tool: "pay.refund", effect: "idempotent", permission: "pay:w", approval: { roles: ["finance"], quorum: 2, timeout: "15m", on_timeout: "escalate", escalate_to: ["cfo"] } };

describe("a manifest with an approval object survives the registry", () => {
  it("approve, deprecate and restore keep the rules", () => {
    const reg = new ManifestRegistry(mkdtempSync(join(tmpdir(), "rv-reg-")));
    reg.publish(M, { by: "a", status: "draft" });
    reg.approve("pay.refund", { by: "b" });
    const cur = reg.current("pay.refund");
    expect(cur?.approval_rules).toMatchObject({ roles: ["finance"], quorum: 2, timeout_ms: 900_000, on_timeout: "escalate", escalate_to: ["cfo"] });
    reg.deprecate("pay.refund", { by: "b" });
    reg.rollbackTo("pay.refund", 2, { by: "b" });
    expect(reg.current("pay.refund")?.approval_rules?.quorum).toBe(2);
    expect(reg.verifyAll()).toEqual([]);
  });

  it("authorForm output validates to the same manifest", () => {
    const v = validateManifest(M);
    if (!v.ok) throw new Error("setup");
    const again = validateManifest(authorForm(v.manifest));
    expect(again.ok && again.manifest).toEqual(v.manifest);
  });
});

describe("loading a registry that holds an approval object", () => {
  it("load() and a hand-written normalized manifest both validate", () => {
    const reg = new ManifestRegistry(mkdtempSync(join(tmpdir(), "rv-reg-")));
    reg.publish(M, { by: "a", status: "approved" });
    const loaded = reg.load();
    expect(loaded.get("pay.refund")?.approval_rules?.quorum).toBe(2);
    const v = validateManifest(loaded.get("pay.refund"));
    expect(v.ok).toBe(true);
  });
});
