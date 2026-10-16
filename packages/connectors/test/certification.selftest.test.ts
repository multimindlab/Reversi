import { describe, expect, it } from "vitest";
import { HttpError, defineConnector, matches, send, snippet, str, type Connector } from "../src/common.js";
import { connectorSchemaHashes, createSlackConnector, detectManifestDrift } from "../src/index.js";
import { certifyConnector, httpBackend, type Scenario, type Subject } from "./certification.js";

const TOKEN = "kv-SECRET-TOKEN-9999";

function kvBackend() {
  const kv = new Map<string, string>();
  return Object.assign(
    httpBackend({
      state: () => [...kv].sort(),
      handle: (c) => {
        const u = new URL(c.url);
        const k = decodeURIComponent(u.pathname.replace("/kv/", ""));
        if (c.method === "POST" && u.pathname === "/kv") {
          const b = JSON.parse(c.body) as { k: string; v: string };
          kv.set(b.k, b.v);
          return { status: 201, json: { k: b.k } };
        }
        if (c.method === "DELETE") return kv.delete(k) ? { status: 204 } : { status: 404, json: { message: "no" } };
        if (c.method === "GET") return kv.has(k) ? { json: { k, v: kv.get(k) } } : { status: 404, json: { message: "no" } };
        return { status: 500 };
      },
    }),
    { kv },
  );
}

/** A correct connector over the key-value fake, optionally with `requires` edges. */
function goodKv(f: typeof fetch, timeoutMs = 30000): Connector {
  const secrets = [TOKEN];
  const call = async (method: string, p: string, body?: unknown, tolerate: number[] = []) => {
    const r = await send(
      f,
      `https://kv.example${p}`,
      { method, headers: { Authorization: `Bearer ${TOKEN}` }, body: body === undefined ? undefined : JSON.stringify(body) },
      { label: `KV ${method} ${p}`, mutating: method !== "GET", secrets, timeoutMs },
    );
    if (!r.ok && !tolerate.includes(r.status)) throw new HttpError(`KV ${method} ${p} failed with status ${r.status}: ${snippet(r, secrets)}`, r.status);
    return r;
  };
  const props = { key: { type: "string" }, value: { type: "string" } };
  const c = defineConnector("kv", [
    {
      name: "open",
      description: "Create a key.",
      effect: "reversible",
      permission: "kv:write",
      compensation: { tool: "close", argument_map: { key: "$args.key" } },
      properties: props,
      required: ["key", "value"],
      handler: async (a) => {
        await call("POST", "/kv", { k: str(a, "key"), v: str(a, "value") });
        return { key: a.key };
      },
    },
    {
      name: "close",
      description: "Delete a key.",
      effect: "idempotent",
      permission: "kv:write",
      properties: { key: props.key },
      required: ["key"],
      handler: async (a) => {
        const r = await call("DELETE", `/kv/${encodeURIComponent(matches(a, "key", /^[a-z0-9]+$/, "key"))}`, undefined, [404]);
        return { deleted: r.status !== 404 };
      },
    },
    {
      name: "annotate",
      description: "Create a second key that depends on the first.",
      effect: "reversible",
      permission: "kv:write",
      compensation: { tool: "close", argument_map: { key: "$args.key" } },
      properties: props,
      required: ["key", "value"],
      handler: async (a) => {
        await call("POST", "/kv", { k: str(a, "key"), v: str(a, "value") });
        return { key: a.key };
      },
    },
  ]);
  return c;
}

function subjectOf(make: (f: typeof fetch, t?: number) => Connector, extra: Partial<Subject> = {}): Subject {
  return {
    name: "kv",
    secrets: [TOKEN],
    make: (o) => {
      const backend = kvBackend();
      return { backend, connector: make(backend.fetch, o?.timeoutMs) };
    },
    ...extra,
  };
}

const kvScenarios: Scenario[] = [
  { tool: "open", args: { key: "alpha", value: "1" } },
  { tool: "close", args: { key: "alpha" }, setup: (b) => void (b as ReturnType<typeof kvBackend>).kv.set("alpha", "1") },
  { tool: "annotate", args: { key: "beta", value: "2" } },
];

describe("certification suite", () => {
  it("passes a correct connector", async () => {
    const cert = await certifyConnector(subjectOf(goodKv), kvScenarios);
    expect(cert.results.filter((r) => r.status === "fail")).toEqual([]);
    expect(cert.results.find((r) => r.check === "dependency_block")?.status).toBe("not_applicable");
  });

  it("runs the dependency block check when a manifest declares requires, and passes", async () => {
    const make = (f: typeof fetch, t?: number) => {
      const c = goodKv(f, t);
      (c.manifests.find((m) => (m as { tool: string }).tool === "kv.annotate") as { requires?: string[] }).requires = ["kv.open"];
      return c;
    };
    const cert = await certifyConnector(subjectOf(make), kvScenarios);
    const r = cert.results.find((x) => x.check === "dependency_block")!;
    expect(r.status, r.reason).toBe("pass");
    expect(r.tools).toEqual(["kv.annotate"]);
    expect(cert.results.filter((x) => x.status === "fail")).toEqual([]);
  });

  it("fails a connector that leaks the credential, loses uncertainty, and does not undo", async () => {
    const bad = (f: typeof fetch): Connector => {
      const c = defineConnector("kv", [
        {
          name: "open",
          description: "Create a key.",
          effect: "reversible",
          permission: "kv:write",
          compensation: { tool: "close", argument_map: { key: "$args.key", extra: "$args.value" } },
          properties: { key: { type: "string" }, value: { type: "string" } },
          required: ["key", "value"],
          handler: async (a) => {
            let r: Response;
            try {
              r = await f("https://kv.example/kv", { method: "POST", headers: { Authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ k: a.key, v: a.value }) });
            } catch (e) {
              throw new Error(`transport: ${(e as Error).message}`); // plain Error: should have been EffectUncertainError
            }
            if (!r.ok) throw new Error(`failed ${r.status}: ${await r.text()} (token ${TOKEN})`); // leaks the credential
            return { key: a.key, echo: `auth was ${TOKEN}` };
          },
        },
        {
          name: "close",
          description: "Pretend to delete.",
          effect: "idempotent",
          permission: "kv:write",
          properties: { key: { type: "string" } },
          required: ["key"],
          handler: async () => ({ deleted: true }), // does nothing
        },
      ]);
      return c;
    };
    const cert = await certifyConnector(subjectOf((f) => bad(f)), [
      { tool: "open", args: { key: "alpha", value: "1" } },
      { tool: "close", args: { key: "alpha" }, setup: (b) => void (b as ReturnType<typeof kvBackend>).kv.set("alpha", "1") },
    ]);
    const failed = (id: string) => cert.results.find((r) => r.check === id)?.status === "fail";
    expect(failed("forward_failure")).toBe(true);
    expect(failed("retry")).toBe(true);
    expect(failed("compensation_success")).toBe(true);
    expect(failed("redaction")).toBe(true);
    expect(failed("timeout")).toBe(true); // it never applies a timeout, so the call hangs until the suite gives up
    expect(failed("forward_success")).toBe(true); // `close` changed nothing although it reported success
  });

  it("fails a scenario list that does not cover every tool", async () => {
    const cert = await certifyConnector(subjectOf(goodKv), kvScenarios.slice(0, 1));
    const r = cert.results.find((x) => x.check === "forward_success")!;
    expect(r.status).toBe("fail");
    expect(r.reason).toContain("no scenario for");
  });

  it("requires a reason for every not_applicable result", async () => {
    const cert = await certifyConnector(subjectOf(goodKv, { notApplicable: { timeout: "declared by the subject" } }), kvScenarios);
    expect(cert.results.find((r) => r.check === "timeout")).toMatchObject({ status: "not_applicable", reason: "declared by the subject" });
    for (const r of cert.results) if (r.status === "not_applicable") expect(r.reason).toBeTruthy();
  });
});

describe("manifest drift", () => {
  const slack = createSlackConnector({ token: "t" });
  const baseline = connectorSchemaHashes(slack);

  it("hashes every tool and reports no drift against itself", () => {
    expect(Object.keys(baseline).sort()).toEqual(Object.keys(slack.tools).sort());
    for (const h of Object.values(baseline)) expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(detectManifestDrift(slack.manifests, slack.inputSchemas, baseline)).toEqual({ added: [], removed: [], changed: [] });
  });

  it("detects a changed input schema", () => {
    const schemas = structuredClone(slack.inputSchemas) as Record<string, { properties: Record<string, unknown> }>;
    schemas["slack.post_message"]!.properties.blocks = { type: "array" };
    expect(detectManifestDrift(slack.manifests, schemas, baseline)).toEqual({ added: [], removed: [], changed: ["slack.post_message"] });
  });

  it("detects added and removed tools", () => {
    const fewer = { ...baseline };
    delete fewer["slack.add_reaction"];
    expect(detectManifestDrift(slack.manifests, slack.inputSchemas, fewer).added).toEqual(["slack.add_reaction"]);
    const more = { ...baseline, "slack.gone": "0".repeat(64) };
    expect(detectManifestDrift(slack.manifests, slack.inputSchemas, more).removed).toEqual(["slack.gone"]);
  });

  it("reads a schema_hash on the manifests when no baseline is passed", () => {
    const stamped = slack.manifests.map((m) => ({ ...(m as object), schema_hash: baseline[(m as { tool: string }).tool] }));
    expect(detectManifestDrift(stamped, slack.inputSchemas)).toEqual({ added: [], removed: [], changed: [] });
    expect(detectManifestDrift(slack.manifests, slack.inputSchemas).added).toHaveLength(slack.manifests.length);
  });

  it("is stable across key order", () => {
    const a = { inputSchemas: { t: { type: "object", properties: { a: 1, b: 2 } } } };
    const b = { inputSchemas: { t: { properties: { b: 2, a: 1 }, type: "object" } } };
    expect(connectorSchemaHashes(a)).toEqual(connectorSchemaHashes(b));
  });
});
