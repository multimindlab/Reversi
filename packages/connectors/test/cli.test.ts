import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { CHECK_IDS } from "../src/index.js";

const main = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "main.js");
const run = (args: string[], env: Record<string, string> = {}, input?: string) =>
  spawnSync(process.execPath, [main, ...args], { input, encoding: "utf8", env: { PATH: process.env.PATH ?? "", ...env } });
const built = existsSync(main);

describe("reversi-connectors CLI for the new connectors", () => {
  it.skipIf(!built).each([
    ["gitlab", "GITLAB_TOKEN"],
    ["teams", "TEAMS_TOKEN"],
    ["linear", "LINEAR_API_KEY"],
    ["jira", "JIRA_BASE_URL"],
    ["gcalendar", "GOOGLE_CALENDAR_TOKEN"],
    ["postgres", "POSTGRES_URL"],
    ["aws", "AWS_ACCESS_KEY_ID"],
    ["gcp", "GCP_ACCESS_TOKEN"],
    ["azure", "AZURE_STORAGE_TOKEN"],
    ["kubernetes", "KUBE_API_SERVER"],
  ])("serve %s needs %s in the environment, not a flag", (name, variable) => {
    const r = run(["serve", name]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(`${variable} is not set`);
    expect(run(["serve", name, "--token", "abc"]).status).toBe(1);
  });

  it.skipIf(!built)("prints valid manifests for each new connector without any credentials", () => {
    for (const name of ["gitlab", "teams", "linear", "jira", "gcalendar", "postgres", "aws", "gcp", "azure", "kubernetes"]) {
      const out = JSON.parse(run(["manifests", name, "--format", "json"]).stdout) as Array<{ tool: string }>;
      expect(out.length).toBeGreaterThan(2);
      expect(out.every((m) => m.tool.startsWith(`${name}.`))).toBe(true);
      Registry.from(out);
    }
  });

  it.skipIf(!built)("compensate enables a connector from its environment variables and runs its compensation", () => {
    // no network: the Kubernetes API server is an unroutable name, so the compensation fails with a clear, redacted error
    const call = { run_id: "r", step: 0, tool: "kubernetes.restore_replicas", original_tool: "kubernetes.scale_deployment", args: { namespace: "prod", name: "web", replicas: 3 }, idempotency_key: "k" };
    const r = run(["compensate", "--root", "."], { KUBE_API_SERVER: "http://127.0.0.1:1", KUBE_TOKEN: "SECRET-KUBE-TOKEN" }, JSON.stringify(call));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Kubernetes PATCH");
    expect(r.stderr).not.toContain("SECRET-KUBE-TOKEN");
    const without = run(["compensate", "--root", "."], {}, JSON.stringify(call));
    expect(without.stderr).toContain("no connector provides");
  });

  it.skipIf(!built)("certify prints the twelve checks and says where they are enforced", () => {
    const all = run(["certify", "all"]);
    expect(all.status).toBe(0);
    for (const id of CHECK_IDS) expect(all.stdout).toContain(id);
    expect(all.stdout).toContain("fake backends");
    expect(all.stdout).toContain("certify.test.ts");
    expect(run(["certify", "gitlab"]).status).toBe(0);
    const bad = run(["certify", "nope"]);
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("certify needs one of");
  });
});
