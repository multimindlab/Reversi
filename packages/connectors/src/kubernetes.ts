import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  nonNegInt,
  optMatches,
  optPosInt,
  send,
  snippet,
  type Connector,
  type Fetch,
  type Sent,
} from "./common.js";

export interface KubernetesConfig {
  /** API server URL such as https://10.0.0.1:6443 */
  apiServer: string;
  /** A bearer token (service account token). */
  token: string;
  /** Path to the cluster CA certificate (PEM). When set and no `fetch` is injected, requests use node:https with this CA. */
  caCertPath?: string;
  fetch?: Fetch;
  timeoutMs?: number;
}

const NAMESPACE = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const NAME = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/;
const UID = /^[0-9a-fA-F-]{8,64}$/;
const SELECTOR = /^[A-Za-z0-9_./=!,() -]{1,512}$/;
const DATA_KEY = /^[-._a-zA-Z0-9]{1,253}$/;
const MAX_CONFIGMAP_BYTES = 900 * 1024;
const MAX_REPLICAS = 10000;

/** A fetch built on node:http(s) that trusts the given CA, for clusters with a private certificate authority. */
export function caFetch(ca: string | Buffer): Fetch {
  return ((input: string | URL | Request, init?: RequestInit) =>
    new Promise<Response>((resolve, reject) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
      const tls = url.protocol === "https:";
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
      const signal = init?.signal;
      if (signal?.aborted) return reject(signal.reason instanceof Error ? signal.reason : new Error("aborted"));
      const req = (tls ? https : http).request(
        url,
        { method: init?.method ?? "GET", headers, ...(tls ? { ca } : {}) },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("error", reject);
          res.on("end", () => {
            const h = new Headers();
            for (const [k, v] of Object.entries(res.headers)) {
              if (Array.isArray(v)) for (const x of v) h.append(k, x);
              else if (v !== undefined) h.set(k, v);
            }
            const status = res.statusCode ?? 0;
            resolve(new Response(status === 204 || status === 304 ? null : Buffer.concat(chunks), { status, headers: h }));
          });
        },
      );
      req.on("error", reject);
      signal?.addEventListener("abort", () => req.destroy(signal.reason instanceof Error ? signal.reason : new Error("aborted")), {
        once: true,
      });
      if (init?.body !== undefined && init.body !== null) req.write(typeof init.body === "string" ? init.body : Buffer.from(init.body as Uint8Array));
      req.end();
    })) as Fetch;
}

export function createKubernetesConnector(cfg: KubernetesConfig): Connector {
  if (!cfg.apiServer) throw new Error("kubernetes connector needs an `apiServer`");
  if (!cfg.token) throw new Error("kubernetes connector needs a `token`");
  const f = cfg.fetch ?? (cfg.caCertPath ? caFetch(readFileSync(cfg.caCertPath)) : fetch);
  const base = cfg.apiServer.replace(/\/+$/, "");
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    p: string,
    opts: { body?: unknown; query?: Array<[string, string]>; tolerate?: number[] } = {},
  ): Promise<Sent & { object: Record<string, unknown> }> {
    const label = `Kubernetes ${method} ${p}`;
    const q = new URLSearchParams(opts.query ?? []).toString();
    const res = await send(
      f,
      `${base}${p}${q ? `?${q}` : ""}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          Accept: "application/json",
          ...(opts.body !== undefined
            ? { "Content-Type": method === "PATCH" ? "application/merge-patch+json" : "application/json" }
            : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      },
      { label, mutating: method !== "GET", secrets, timeoutMs },
    );
    if (!res.ok && !(opts.tolerate ?? []).includes(res.status)) {
      throw new HttpError(`${label} failed with status ${res.status}: ${snippet(res, secrets)}`, res.status);
    }
    return { ...res, object: asRecord(res.json) };
  }

  const ns = (args: Record<string, unknown>) => matches(args, "namespace", NAMESPACE, "namespace (DNS-1123 label)");
  const nm = (args: Record<string, unknown>) => matches(args, "name", NAME, "name (DNS-1123 subdomain)");
  const deployPath = (namespace: string, name: string) => `/apis/apps/v1/namespaces/${namespace}/deployments/${name}`;

  const target = {
    namespace: { type: "string", description: "Namespace (DNS-1123 label)" },
    name: { type: "string", description: "Object name (DNS-1123 subdomain)" },
  };
  const replicasProp = { type: "integer", minimum: 0, maximum: MAX_REPLICAS };
  const replicasArg = (args: Record<string, unknown>) => {
    const n = nonNegInt(args, "replicas");
    if (n > MAX_REPLICAS) throw new Error(`\`replicas\` must be at most ${MAX_REPLICAS}`);
    return n;
  };

  return defineConnector("kubernetes", [
    {
      name: "get_deployment",
      description: "Read a deployment's replica counts and images. RBAC: get on deployments.apps.",
      effect: "read_only",
      permission: "kubernetes:deployments:read",
      properties: target,
      required: ["namespace", "name"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const d = (await api("GET", deployPath(namespace, name))).object;
        const spec = asRecord(d.spec);
        const status = asRecord(d.status);
        const containers = asRecord(asRecord(spec.template).spec).containers;
        return {
          namespace,
          name,
          replicas: spec.replicas ?? 1,
          ready_replicas: status.readyReplicas ?? 0,
          updated_replicas: status.updatedReplicas ?? 0,
          available_replicas: status.availableReplicas ?? 0,
          generation: asRecord(d.metadata).generation ?? null,
          images: (Array.isArray(containers) ? containers : []).map((c) => asRecord(c).image),
        };
      },
    },
    {
      name: "list_pods",
      description: "List pods in a namespace, optionally by label selector. RBAC: list on pods.",
      effect: "read_only",
      permission: "kubernetes:pods:read",
      properties: {
        namespace: target.namespace,
        label_selector: { type: "string", description: "Such as app=web,tier!=cache" },
        limit: { type: "integer", minimum: 1, maximum: 500 },
      },
      required: ["namespace"],
      handler: async (args) => {
        const namespace = ns(args);
        const selector = optMatches(args, "label_selector", SELECTOR, "label selector");
        const limit = optPosInt(args, "limit");
        if (limit !== undefined && limit > 500) throw new Error("`limit` must be at most 500");
        const query: Array<[string, string]> = [];
        if (selector) query.push(["labelSelector", selector]);
        if (limit) query.push(["limit", String(limit)]);
        const j = (await api("GET", `/api/v1/namespaces/${namespace}/pods`, { query })).object;
        const pods = (Array.isArray(j.items) ? j.items : []).map((i) => {
          const r = asRecord(i);
          const statuses = (Array.isArray(asRecord(r.status).containerStatuses) ? (asRecord(r.status).containerStatuses as unknown[]) : []).map(asRecord);
          return {
            name: asRecord(r.metadata).name,
            phase: asRecord(r.status).phase ?? null,
            node_name: asRecord(r.spec).nodeName ?? null,
            ready: statuses.length > 0 && statuses.every((s) => s.ready === true),
            restarts: statuses.reduce((n, s) => n + (typeof s.restartCount === "number" ? s.restartCount : 0), 0),
          };
        });
        const next = asRecord(j.metadata).continue;
        return { pods, continue: typeof next === "string" && next ? next : null };
      },
    },
    {
      name: "scale_deployment",
      description:
        "Set a deployment's replica count through the scale subresource. The current count is read first and returned as previous_replicas; rollback scales back to it. RBAC: get and patch on deployments/scale.",
      effect: "reversible",
      permission: "kubernetes:deployments:scale",
      compensation: {
        tool: "restore_replicas",
        argument_map: { namespace: "$args.namespace", name: "$args.name", replicas: "$result.previous_replicas" },
      },
      properties: { ...target, replicas: replicasProp },
      required: ["namespace", "name", "replicas"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const replicas = replicasArg(args);
        const p = `${deployPath(namespace, name)}/scale`;
        const current = asRecord((await api("GET", p)).object.spec).replicas;
        if (typeof current !== "number") throw new Error("Kubernetes scale response had no spec.replicas");
        await api("PATCH", p, { body: { spec: { replicas } } });
        return { namespace, name, previous_replicas: current, replicas };
      },
    },
    {
      name: "restore_replicas",
      description: "Set a deployment's replica count back to a saved value. Safe to repeat. Used to undo scale_deployment.",
      effect: "idempotent",
      permission: "kubernetes:deployments:scale",
      properties: { ...target, replicas: replicasProp },
      required: ["namespace", "name", "replicas"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const replicas = replicasArg(args);
        await api("PATCH", `${deployPath(namespace, name)}/scale`, { body: { spec: { replicas } } });
        return { namespace, name, replicas };
      },
    },
    {
      name: "create_configmap",
      description:
        "Create a ConfigMap. Fails if it already exists. Rollback deletes it, guarded by its UID so a different object with the same name is never deleted. RBAC: create on configmaps.",
      effect: "reversible",
      permission: "kubernetes:configmaps:write",
      compensation: {
        tool: "delete_configmap",
        argument_map: { namespace: "$args.namespace", name: "$args.name", uid: "$result.uid" },
      },
      properties: { ...target, data: { type: "object", additionalProperties: { type: "string" } } },
      required: ["namespace", "name", "data"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const raw = args.data;
        if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error("`data` must be an object of strings");
        const data: Record<string, string> = {};
        let size = 0;
        for (const [k, v] of Object.entries(raw)) {
          if (!DATA_KEY.test(k)) throw new Error(`\`data\` has an invalid key \`${k.slice(0, 64)}\``);
          if (typeof v !== "string") throw new Error(`\`data.${k}\` must be a string`);
          size += Buffer.byteLength(k) + Buffer.byteLength(v);
          data[k] = v;
        }
        if (size > MAX_CONFIGMAP_BYTES) throw new Error("`data` is larger than a ConfigMap may be");
        const { object } = await api("POST", `/api/v1/namespaces/${namespace}/configmaps`, {
          body: { apiVersion: "v1", kind: "ConfigMap", metadata: { name }, data },
        });
        const uid = asRecord(object.metadata).uid;
        if (typeof uid !== "string") throw new Error("Kubernetes response had no uid");
        return { namespace, name, uid, resource_version: asRecord(object.metadata).resourceVersion ?? null };
      },
    },
    {
      name: "delete_configmap",
      description:
        "Delete a ConfigMap. With `uid`, only the object with that UID is deleted. A ConfigMap that is already gone, or was replaced by another with a different UID, counts as success. RBAC: delete on configmaps; the agent should not hold it.",
      effect: "idempotent",
      permission: "kubernetes:configmaps:delete",
      properties: { ...target, uid: { type: "string" } },
      required: ["namespace", "name"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const uid = optMatches(args, "uid", UID, "uid");
        const r = await api("DELETE", `/api/v1/namespaces/${namespace}/configmaps/${name}`, {
          body: uid ? { apiVersion: "v1", kind: "DeleteOptions", preconditions: { uid } } : undefined,
          tolerate: uid ? [404, 409] : [404],
        });
        return { namespace, name, deleted: r.status !== 404 && r.status !== 409 };
      },
    },
    {
      name: "rollout_restart",
      description:
        "Restart a deployment's pods by stamping the pod template (what `kubectl rollout restart` does). Pods are replaced and the old ones are gone, so it is irreversible and always needs approval. RBAC: patch on deployments.apps.",
      effect: "irreversible",
      approval: "always",
      permission: "kubernetes:deployments:restart",
      properties: target,
      required: ["namespace", "name"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const restarted_at = new Date().toISOString();
        await api("PATCH", deployPath(namespace, name), {
          body: { spec: { template: { metadata: { annotations: { "kubectl.kubernetes.io/restartedAt": restarted_at } } } } },
        });
        return { namespace, name, restarted_at };
      },
    },
    {
      name: "delete_pod",
      description:
        "Delete a pod. Its state is gone for good, so it is irreversible and always needs approval. RBAC: delete on pods.",
      effect: "irreversible",
      approval: "always",
      permission: "kubernetes:pods:delete",
      properties: { ...target, grace_period_seconds: { type: "integer", minimum: 0, maximum: 3600 } },
      required: ["namespace", "name"],
      handler: async (args) => {
        const namespace = ns(args);
        const name = nm(args);
        const grace = args.grace_period_seconds === undefined ? undefined : nonNegInt(args, "grace_period_seconds");
        if (grace !== undefined && grace > 3600) throw new Error("`grace_period_seconds` must be at most 3600");
        await api("DELETE", `/api/v1/namespaces/${namespace}/pods/${name}`, {
          body: grace === undefined ? undefined : { apiVersion: "v1", kind: "DeleteOptions", gracePeriodSeconds: grace },
        });
        return { namespace, name, deleted: true };
      },
    },
  ]);
}
