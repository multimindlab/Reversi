import { expect } from "vitest";
import { createGcpConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";
import type { FakeReply } from "../helpers.js";

export const TOKEN = "ya29.SECRET-GCP-ACCESS-TOKEN";
export const BUCKET = "my-bucket";
export const BK = ".reversi-backups/00000000-0000-4000-8000-000000000002";

type Reply = FakeReply & { bytes?: Uint8Array; headers?: Record<string, string> };
const err = (status: number, message: string): Reply => ({ status, json: { error: { code: status, message } } });

export function fakeGcs() {
  const objects = new Map<string, { bytes: Buffer; type: string; generation: number }>();
  let gen = 1000;
  const b = httpBackend({
    state: () => ({ objects: [...objects].map(([k, v]) => [k, v.bytes.toString("base64"), v.type]).sort() }),
    handle: (c): Reply => {
      if (c.headers.authorization !== `Bearer ${TOKEN}`) return err(401, "Invalid Credentials");
      const u = new URL(c.url);
      const p = u.pathname;
      const q = u.searchParams;
      let m: RegExpMatchArray | null;
      if (c.method === "POST" && p === `/upload/storage/v1/b/${BUCKET}/o`) {
        const name = q.get("name")!;
        const want = q.get("ifGenerationMatch");
        const have = objects.get(name)?.generation ?? 0;
        if (want !== null && Number(want) !== have) return err(412, "Precondition Failed");
        objects.set(name, { bytes: Buffer.from(c.body, "latin1"), type: c.headers["content-type"] ?? "", generation: ++gen });
        return { json: { name, generation: String(gen) } };
      }
      if (c.method === "GET" && p === `/storage/v1/b/${BUCKET}/o`) {
        const prefix = q.get("prefix") ?? "";
        const items = [...objects].filter(([k]) => k.startsWith(prefix)).sort(([a], [x]) => (a < x ? -1 : 1)).map(([name, v]) => ({ name, size: String(v.bytes.length), updated: "2026-01-01T00:00:00Z", contentType: v.type }));
        return { json: { items } };
      }
      if ((m = p.match(new RegExp(`^/storage/v1/b/${BUCKET}/o/([^/]+)/rewriteTo/b/${BUCKET}/o/([^/]+)$`))) && c.method === "POST") {
        const src = objects.get(decodeURIComponent(m[1]!));
        if (!src) return err(404, "No such object");
        const want = q.get("sourceGeneration");
        if (want !== null && Number(want) !== src.generation) return err(412, "source generation changed");
        if (q.get("rewriteToken") !== "round-2") return { json: { done: false, rewriteToken: "round-2" } };
        objects.set(decodeURIComponent(m[2]!), { bytes: Buffer.from(src.bytes), type: src.type, generation: ++gen });
        return { json: { done: true } };
      }
      if ((m = p.match(new RegExp(`^/storage/v1/b/${BUCKET}/o/([^/]+)$`)))) {
        const name = decodeURIComponent(m[1]!);
        const o = objects.get(name);
        if (c.method === "DELETE") {
          if (!o) return err(404, "No such object");
          const want = q.get("ifGenerationMatch");
          if (want !== null && Number(want) !== o.generation) return err(412, "Precondition Failed");
          objects.delete(name);
          return { status: 204 };
        }
        if (c.method === "GET") {
          if (!o) return err(404, "No such object");
          if (q.get("alt") !== "media") return { json: { generation: String(o.generation) } };
          const range = /^bytes=0-(\d+)$/.exec(c.headers.range ?? "");
          const part = o.bytes.subarray(0, range ? Number(range[1]) + 1 : o.bytes.length);
          return { status: part.length < o.bytes.length ? 206 : 200, bytes: part, headers: { "content-type": o.type, "content-range": `bytes 0-${part.length - 1}/${o.bytes.length}` } };
        }
      }
      return err(500, `unexpected ${c.method} ${c.url}`);
    },
  });
  return Object.assign(b, { objects });
}
export type FakeGcs = ReturnType<typeof fakeGcs>;
const gcs = (b: Backend) => b as FakeGcs;
const put = (b: Backend, key: string, content: string) => void gcs(b).objects.set(key, { bytes: Buffer.from(content), type: "text/plain", generation: 5 });
const seed = (b: Backend) => put(b, "docs/a.txt", "v1");
const visible = (b: Backend) => (gcs(b).state() as { objects: string[][] }).objects.filter(([k]) => !k!.startsWith(".reversi-backups/"));
const backups = (b: Backend) => [...gcs(b).objects.keys()].filter((k) => k.startsWith(".reversi-backups/"));

export const subject: Subject = {
  name: "gcp",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeGcs();
    return { backend, connector: createGcpConnector({ accessToken: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (status, secret) => ({ json: { error: { code: status, message: `denied ${secret}` } } }),
};

const base = { fingerprint: visible };
export const scenarios: Scenario[] = [
  { tool: "get_object", args: { bucket: BUCKET, key: "docs/a.txt" }, setup: seed, expect: (r) => expect(r).toMatchObject({ content: "v1", encoding: "utf8", size: 2 }) },
  {
    tool: "list_objects",
    args: { bucket: BUCKET, prefix: "docs/" },
    setup: (b) => (seed(b), put(b, BK, "hidden")),
    expect: (r) => expect((r as { objects: Array<{ key: string }> }).objects.map((o) => o.key)).toEqual(["docs/a.txt"]),
  },
  { tool: "put_object", args: { bucket: BUCKET, key: "docs/new.txt", content: "aGk=", encoding: "base64" }, ...base, expect: (r) => expect(r).toMatchObject({ existed: false, backup_key: null }) },
  { tool: "put_object", args: { bucket: BUCKET, key: "docs/a.txt", content: "v2" }, setup: seed, ...base, expect: (r, b) => (expect(r).toMatchObject({ existed: true }), expect(backups(b)).toHaveLength(1)) },
  { tool: "delete_object", args: { bucket: BUCKET, key: "docs/a.txt" }, setup: seed, ...base, expect: (_r, b) => expect(backups(b)).toHaveLength(1) },
  {
    tool: "restore_object",
    args: { bucket: BUCKET, key: "docs/a.txt", backup_key: BK },
    setup: (b) => (put(b, "docs/a.txt", "v2"), put(b, BK, "v1")),
    ...base,
    expect: (_r, b) => expect(gcs(b).objects.get("docs/a.txt")!.bytes.toString()).toBe("v1"),
  },
  { tool: "restore_object", args: { bucket: BUCKET, key: "docs/new.txt", backup_key: null }, setup: (b) => put(b, "docs/new.txt", "x"), ...base },
];
