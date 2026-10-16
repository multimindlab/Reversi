import { expect } from "vitest";
import { createKubernetesConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";
import type { FakeReply } from "../helpers.js";

export const TOKEN = "eyJhbGciOi.SECRET-KUBE-SERVICE-ACCOUNT-TOKEN.sig";
export const SEED_UID = "11111111-0000-4000-8000-000000000001";
export const SERVER = "https://kube.example:6443";

const status = (code: number, reason: string, message: string): FakeReply => ({ status: code, json: { kind: "Status", status: "Failure", message, reason, code } });

export function fakeKube() {
  const deployments = new Map<string, { replicas: number; restarts: number }>();
  const configmaps = new Map<string, { uid: string; data: Record<string, string> }>();
  const pods = new Map<string, { labels: Record<string, string>; phase: string }>();
  let n = 0;
  const b = httpBackend({
    state: () => ({ deployments: [...deployments], configmaps: [...configmaps], pods: [...pods] }),
    handle: (c) => {
      if (c.headers.authorization !== `Bearer ${TOKEN}`) return status(401, "Unauthorized", "Unauthorized");
      const p = new URL(c.url).pathname;
      const q = new URL(c.url).searchParams;
      const body = c.body ? JSON.parse(c.body) : {};
      let m: RegExpMatchArray | null;
      if ((m = p.match(/^\/apis\/apps\/v1\/namespaces\/([^/]+)\/deployments\/([^/]+)(\/scale)?$/))) {
        const d = deployments.get(`${m[1]}/${m[2]}`);
        if (!d) return status(404, "NotFound", `deployments.apps "${m[2]}" not found`);
        if (c.method === "GET" && m[3]) return { json: { kind: "Scale", spec: { replicas: d.replicas } } };
        if (c.method === "GET") {
          return {
            json: {
              metadata: { generation: 4 },
              spec: { replicas: d.replicas, template: { spec: { containers: [{ image: "web:1.0" }] } } },
              status: { readyReplicas: d.replicas, updatedReplicas: d.replicas, availableReplicas: d.replicas },
            },
          };
        }
        if (c.method === "PATCH") {
          if (c.headers["content-type"] !== "application/merge-patch+json") return status(415, "UnsupportedMediaType", "bad patch type");
          if (m[3]) d.replicas = body.spec.replicas;
          else if (body.spec?.template?.metadata?.annotations?.["kubectl.kubernetes.io/restartedAt"]) d.restarts++;
          return { json: {} };
        }
      }
      if (c.method === "POST" && (m = p.match(/^\/api\/v1\/namespaces\/([^/]+)\/configmaps$/))) {
        const key = `${m[1]}/${body.metadata.name}`;
        if (configmaps.has(key)) return status(409, "AlreadyExists", `configmaps "${body.metadata.name}" already exists`);
        const uid = `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;
        configmaps.set(key, { uid, data: body.data });
        return { status: 201, json: { metadata: { name: body.metadata.name, uid, resourceVersion: "1" } } };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/api\/v1\/namespaces\/([^/]+)\/configmaps\/([^/]+)$/))) {
        const cm = configmaps.get(`${m[1]}/${m[2]}`);
        if (!cm) return status(404, "NotFound", "not found");
        if (body.preconditions?.uid && body.preconditions.uid !== cm.uid) return status(409, "Conflict", "Precondition failed: UID in precondition does not match");
        configmaps.delete(`${m[1]}/${m[2]}`);
        return { json: { kind: "Status", status: "Success" } };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/api\/v1\/namespaces\/([^/]+)\/pods\/([^/]+)$/))) {
        return pods.delete(`${m[1]}/${m[2]}`) ? { json: { kind: "Pod" } } : status(404, "NotFound", "pod not found");
      }
      if (c.method === "GET" && (m = p.match(/^\/api\/v1\/namespaces\/([^/]+)\/pods$/))) {
        const sel = q.get("labelSelector");
        const items = [...pods]
          .filter(([k]) => k.startsWith(`${m![1]}/`))
          .filter(([, v]) => !sel || sel.split(",").every((kv) => v.labels[kv.split("=")[0]!] === kv.split("=")[1]))
          .map(([k, v]) => ({
            metadata: { name: k.split("/")[1] },
            spec: { nodeName: "node-1" },
            status: { phase: v.phase, containerStatuses: [{ ready: true, restartCount: 2 }] },
          }));
        return { json: { items, metadata: {} } };
      }
      return status(500, "InternalError", `unexpected ${c.method} ${c.url}`);
    },
  });
  return Object.assign(b, { deployments, configmaps, pods });
}
export type FakeKube = ReturnType<typeof fakeKube>;
const k = (b: Backend) => b as FakeKube;
const seedDeploy = (b: Backend) => void k(b).deployments.set("prod/web", { replicas: 3, restarts: 0 });
const seedPods = (b: Backend) => {
  k(b).pods.set("prod/web-1", { labels: { app: "web" }, phase: "Running" });
  k(b).pods.set("prod/web-2", { labels: { app: "web" }, phase: "Running" });
  k(b).pods.set("prod/db-1", { labels: { app: "db" }, phase: "Running" });
};

export const subject: Subject = {
  name: "kubernetes",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeKube();
    return { backend, connector: createKubernetesConnector({ apiServer: SERVER, token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (code, secret) => status(code, "Forbidden", `forbidden for token ${secret}`),
};

export const scenarios: Scenario[] = [
  { tool: "get_deployment", args: { namespace: "prod", name: "web" }, setup: seedDeploy, expect: (r) => expect(r).toMatchObject({ replicas: 3, ready_replicas: 3, images: ["web:1.0"] }) },
  { tool: "list_pods", args: { namespace: "prod", label_selector: "app=web", limit: 50 }, setup: seedPods, expect: (r) => expect((r as { pods: Array<{ name: string }> }).pods.map((p) => p.name)).toEqual(["web-1", "web-2"]) },
  { tool: "scale_deployment", args: { namespace: "prod", name: "web", replicas: 0 }, setup: seedDeploy, expect: (r) => expect(r).toMatchObject({ previous_replicas: 3, replicas: 0 }) },
  { tool: "restore_replicas", args: { namespace: "prod", name: "web", replicas: 3 }, setup: (b) => void k(b).deployments.set("prod/web", { replicas: 0, restarts: 0 }) },
  { tool: "create_configmap", args: { namespace: "prod", name: "settings", data: { "app.properties": "a=b" } }, expect: (r) => expect(r).toMatchObject({ uid: "00000000-0000-4000-8000-000000000001" }) },
  { tool: "delete_configmap", args: { namespace: "prod", name: "settings", uid: SEED_UID }, setup: (b) => void k(b).configmaps.set("prod/settings", { uid: SEED_UID, data: {} }) },
  { tool: "rollout_restart", args: { namespace: "prod", name: "web" }, setup: seedDeploy },
  { tool: "delete_pod", args: { namespace: "prod", name: "web-1", grace_period_seconds: 5 }, setup: seedPods },
];
