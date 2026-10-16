import { mkdtempSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { caFetch, compensatorFor, createKubernetesConnector } from "../src/index.js";
import { SEED_UID, SERVER, TOKEN, fakeKube } from "./fixtures/kubernetes.js";
import { engine } from "./helpers.js";

const make = () => {
  const b = fakeKube();
  const c = createKubernetesConnector({ apiServer: SERVER, token: TOKEN, fetch: b.fetch });
  return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`kubernetes.${n}`]!(a, {}) };
};

describe("kubernetes manifests", () => {
  it("validate; the two destructive tools are irreversible and always need approval", () => {
    const { c } = make();
    const reg = Registry.from(c.manifests);
    expect(reg.size).toBe(8);
    for (const tool of ["kubernetes.rollout_restart", "kubernetes.delete_pod"]) {
      expect(reg.get(tool)).toMatchObject({ effect: "irreversible", approval: "always" });
      expect(reg.get(tool)?.compensation).toBeUndefined();
    }
    expect(reg.get("kubernetes.scale_deployment")?.compensation?.tool).toBe("kubernetes.restore_replicas");
    expect(reg.get("kubernetes.create_configmap")?.compensation).toMatchObject({
      tool: "kubernetes.delete_configmap",
      argument_map: { namespace: "$args.namespace", name: "$args.name", uid: "$result.uid" },
    });
    expect(reg.get("kubernetes.get_deployment")?.effect).toBe("read_only");
    expect(reg.get("kubernetes.list_pods")?.effect).toBe("read_only");
  });
});

describe("kubernetes tools", () => {
  it("scale reads the current replicas through the scale subresource, then merge-patches", async () => {
    const { b, t } = make();
    b.deployments.set("prod/web", { replicas: 3, restarts: 0 });
    const r = await t("scale_deployment", { namespace: "prod", name: "web", replicas: 5 });
    expect(r).toEqual({ namespace: "prod", name: "web", previous_replicas: 3, replicas: 5 });
    expect(b.calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      "GET /apis/apps/v1/namespaces/prod/deployments/web/scale",
      "PATCH /apis/apps/v1/namespaces/prod/deployments/web/scale",
    ]);
    expect(b.calls[1]!.headers["content-type"]).toBe("application/merge-patch+json");
    expect(JSON.parse(b.calls[1]!.body)).toEqual({ spec: { replicas: 5 } });
    expect(b.calls[0]!.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("scaling to zero and back through a real engine", async () => {
    const { b, c } = make();
    b.deployments.set("prod/web", { replicas: 3, restarts: 0 });
    const { call, run } = engine([c]);
    await call("kubernetes.scale_deployment", { namespace: "prod", name: "web", replicas: 0 });
    expect(b.deployments.get("prod/web")!.replicas).toBe(0);
    const report = await run.rollback({ compensate: compensatorFor([c]) });
    expect(report.complete).toBe(true);
    expect(b.deployments.get("prod/web")!.replicas).toBe(3);
  });

  it("deletes a created ConfigMap only if its UID still matches", async () => {
    const { b, c, t } = make();
    const { call, run } = engine([c]);
    const made = await call("kubernetes.create_configmap", { namespace: "prod", name: "settings", data: { a: "b" } });
    const uid = (made as { result: { uid: string } }).result.uid;
    // someone deletes it and creates a different one with the same name
    b.configmaps.set("prod/settings", { uid: SEED_UID, data: { theirs: "1" } });
    const report = await run.rollback({ compensate: compensatorFor([c]) });
    expect(report.complete).toBe(true);
    expect(b.configmaps.get("prod/settings")).toEqual({ uid: SEED_UID, data: { theirs: "1" } });
    const del = b.calls.at(-1)!;
    expect(del.method).toBe("DELETE");
    expect(JSON.parse(del.body)).toEqual({ apiVersion: "v1", kind: "DeleteOptions", preconditions: { uid } });
    expect(await t("delete_configmap", { namespace: "prod", name: "settings", uid: SEED_UID })).toMatchObject({ deleted: true });
  });

  it("create_configmap refuses to overwrite an existing one", async () => {
    const { b, t } = make();
    b.configmaps.set("prod/settings", { uid: SEED_UID, data: {} });
    const err = await t("create_configmap", { namespace: "prod", name: "settings", data: { a: "b" } }).catch((e) => e);
    expect(err.message).toContain("status 409");
    expect(err.message).toContain("already exists");
  });

  it("rollout_restart patches the pod template annotation; delete_pod can pass a grace period", async () => {
    const { b, t } = make();
    b.deployments.set("prod/web", { replicas: 3, restarts: 0 });
    b.pods.set("prod/web-1", { labels: {}, phase: "Running" });
    const r = (await t("rollout_restart", { namespace: "prod", name: "web" })) as { restarted_at: string };
    expect(JSON.parse(b.calls[0]!.body)).toEqual({ spec: { template: { metadata: { annotations: { "kubectl.kubernetes.io/restartedAt": r.restarted_at } } } } });
    await t("delete_pod", { namespace: "prod", name: "web-1", grace_period_seconds: 0 });
    expect(JSON.parse(b.calls[1]!.body)).toEqual({ apiVersion: "v1", kind: "DeleteOptions", gracePeriodSeconds: 0 });
    await expect(t("delete_pod", { namespace: "prod", name: "web-1" })).rejects.toThrow("status 404");
  });

  it("rollback reports an irreversible step as unrecoverable and never complete", async () => {
    const { b, c } = make();
    b.deployments.set("prod/web", { replicas: 3, restarts: 0 });
    const { call, run } = engine([c]); // the test engine approves everything
    await call("kubernetes.rollout_restart", { namespace: "prod", name: "web" });
    const report = await run.rollback({ compensate: compensatorFor([c]) });
    expect(report.unrecoverable).toHaveLength(1);
    expect(report.complete).toBe(false);
  });

  it("lists pods by label selector", async () => {
    const { b, t } = make();
    b.pods.set("prod/web-1", { labels: { app: "web" }, phase: "Running" });
    b.pods.set("prod/db-1", { labels: { app: "db" }, phase: "Pending" });
    const r = (await t("list_pods", { namespace: "prod", label_selector: "app=db" })) as { pods: Array<{ name: string; phase: string; restarts: number }> };
    expect(r.pods).toEqual([{ name: "db-1", phase: "Pending", node_name: "node-1", ready: true, restarts: 2 }]);
    expect(b.calls[0]!.url).toContain("labelSelector=app%3Ddb");
  });

  it("validates namespaces and names as DNS-1123 before any request", async () => {
    const { b, t } = make();
    for (const bad of ["Prod", "pr_od", "-prod", "prod-", "a/b", "..", "", "x".repeat(64), "pro d", "prod%2Fother"]) {
      await expect(t("get_deployment", { namespace: bad, name: "web" })).rejects.toThrow("namespace");
    }
    for (const bad of ["Web", "we_b", ".web", "web.", "a/b", "../x", "x".repeat(254)]) {
      await expect(t("get_deployment", { namespace: "prod", name: bad })).rejects.toThrow("name");
    }
    await expect(t("scale_deployment", { namespace: "prod", name: "web", replicas: -1 })).rejects.toThrow("non-negative");
    await expect(t("scale_deployment", { namespace: "prod", name: "web", replicas: 1.5 })).rejects.toThrow("non-negative");
    await expect(t("scale_deployment", { namespace: "prod", name: "web", replicas: 10001 })).rejects.toThrow("at most");
    await expect(t("create_configmap", { namespace: "prod", name: "x", data: { "bad key!": "v" } })).rejects.toThrow("invalid key");
    await expect(t("create_configmap", { namespace: "prod", name: "x", data: { k: 1 } })).rejects.toThrow("must be a string");
    await expect(t("delete_configmap", { namespace: "prod", name: "x", uid: "not a uid!" })).rejects.toThrow("uid");
    await expect(t("list_pods", { namespace: "prod", label_selector: "app=$(rm -rf)" })).rejects.toThrow("label selector");
    expect(b.calls).toHaveLength(0);
    await t("get_deployment", { namespace: "a", name: "a.b-c" }).catch(() => undefined);
    expect(b.calls[0]!.url).toBe(`${SERVER}/apis/apps/v1/namespaces/a/deployments/a.b-c`);
  });

  it("maps Kubernetes Status errors to HTTP errors without the token", async () => {
    const { t } = make();
    const err = await t("get_deployment", { namespace: "prod", name: "missing" }).catch((e) => e);
    expect(err.status).toBe(404);
    expect(err.message).toContain("not found");
    const c = createKubernetesConnector({ apiServer: SERVER, token: TOKEN, fetch: (async () => new Response(JSON.stringify({ kind: "Status", message: `forbidden: ${TOKEN}`, code: 403 }), { status: 403 })) as typeof fetch });
    const e2 = await c.tools["kubernetes.get_deployment"]!({ namespace: "prod", name: "web" }, {}).catch((e) => e);
    expect(e2.message).toContain("status 403");
    expect(e2.message).not.toContain(TOKEN);
  });
});

describe("kubernetes transport with a private CA", () => {
  it("caFetch speaks plain http/https requests and maps responses, headers, bodies and 204s", async () => {
    const seen: Array<{ method: string; url: string; auth: string | undefined; body: string }> = [];
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ method: req.method!, url: req.url!, auth: req.headers.authorization, body: Buffer.concat(chunks).toString() });
        if (req.url!.endsWith("/gone")) return void res.writeHead(204).end();
        if (req.url!.endsWith("/slow")) return; // never answers
        res.writeHead(req.url!.endsWith("/missing") ? 404 : 200, { "content-type": "application/json", "x-multi": ["a", "b"] }).end(JSON.stringify({ echoed: Buffer.concat(chunks).toString() }));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const f = caFetch("-----BEGIN CERTIFICATE-----\nunused for http\n-----END CERTIFICATE-----");
      const ok = await f(`${base}/echo`, { method: "PATCH", headers: { Authorization: "Bearer t", "Content-Type": "application/merge-patch+json" }, body: '{"a":1}' });
      expect(ok.status).toBe(200);
      expect(await ok.json()).toEqual({ echoed: '{"a":1}' });
      expect(ok.headers.get("x-multi")).toBe("a, b");
      expect((await f(`${base}/gone`, { method: "DELETE" })).status).toBe(204);
      expect((await f(`${base}/missing`)).status).toBe(404);
      expect(seen[0]).toEqual({ method: "PATCH", url: "/echo", auth: "Bearer t", body: '{"a":1}' });
      await expect(f(`${base}/slow`, { signal: AbortSignal.timeout(50) })).rejects.toThrow();
      await expect(f(`${base}/echo`, { signal: AbortSignal.abort() })).rejects.toThrow();
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });

  it("with KUBE_CA_CERT the connector uses the CA transport; a timeout on a write is uncertain", async () => {
    const server = http.createServer(() => undefined); // accepts and never answers
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    const ca = path.join(mkdtempSync(path.join(tmpdir(), "rv-ca-")), "ca.pem");
    writeFileSync(ca, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n");
    try {
      const c = createKubernetesConnector({ apiServer: `http://127.0.0.1:${port}`, token: TOKEN, caCertPath: ca, timeoutMs: 80 });
      const err = await c.tools["kubernetes.restore_replicas"]!({ namespace: "prod", name: "web", replicas: 1 }, {}).catch((e) => e);
      expect(err.name).toBe("EffectUncertainError");
      expect(err.message).not.toContain(TOKEN);
      expect(() => createKubernetesConnector({ apiServer: SERVER, token: TOKEN, caCertPath: "/nonexistent/ca.pem" })).toThrow();
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });
});
