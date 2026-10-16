import { expect } from "vitest";
import { createAzureConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";
import type { FakeReply } from "../helpers.js";

export const TOKEN = "eyJ0eXAi.SECRET-AZURE-STORAGE-TOKEN.sig";
export const ACCOUNT = "myaccount";
export const CONTAINER = "docs";
export const BK = ".reversi-backups/00000000-0000-4000-8000-000000000003";

type Reply = FakeReply & { bytes?: Uint8Array; headers?: Record<string, string> };
const xmlErr = (status: number, code: string, message = code): Reply => ({
  status,
  headers: { "x-ms-error-code": code },
  text: `<?xml version="1.0"?><Error><Code>${code}</Code><Message>${message}\nRequestId:abc</Message></Error>`,
});
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

export function fakeBlob() {
  const blobs = new Map<string, { bytes: Buffer; type: string; etag: string }>();
  let n = 0;
  const b = httpBackend({
    state: () => ({ blobs: [...blobs].map(([k, v]) => [k, v.bytes.toString("base64"), v.type]).sort() }),
    handle: (c): Reply => {
      if (c.headers.authorization !== `Bearer ${TOKEN}`) return xmlErr(401, "AuthenticationFailed");
      if (!c.headers["x-ms-version"]) return xmlErr(400, "MissingRequiredHeader");
      const u = new URL(c.url);
      if (u.host !== `${ACCOUNT}.blob.core.windows.net`) return xmlErr(404, "ResourceNotFound");
      const parts = u.pathname.slice(1).split("/");
      const container = parts.shift();
      const name = decodeURIComponent(parts.join("/"));
      if (container !== CONTAINER) return xmlErr(404, "ContainerNotFound");
      if (c.method === "GET" && name === "") {
        const prefix = u.searchParams.get("prefix") ?? "";
        const rows = [...blobs].filter(([k]) => k.startsWith(prefix)).sort(([a], [x]) => (a < x ? -1 : 1));
        return {
          text:
            `<EnumerationResults><Blobs>` +
            rows.map(([k, v]) => `<Blob><Name>${esc(k)}</Name><Properties><Last-Modified>Wed, 01 Jan 2026 00:00:00 GMT</Last-Modified><Etag>${v.etag}</Etag><Content-Length>${v.bytes.length}</Content-Length></Properties></Blob>`).join("") +
            `</Blobs><NextMarker /></EnumerationResults>`,
        };
      }
      const cur = blobs.get(name);
      const copySource = c.headers["x-ms-copy-source"];
      if (c.method === "PUT" && copySource) {
        if (c.headers["x-ms-requires-sync"] !== "true") return xmlErr(400, "InvalidHeaderValue", "copy must be synchronous");
        if (c.headers["x-ms-copy-source-authorization"] !== `Bearer ${TOKEN}`) return xmlErr(403, "CannotVerifyCopySource");
        const srcName = decodeURIComponent(new URL(copySource).pathname.slice(1).split("/").slice(1).join("/"));
        const src = blobs.get(srcName);
        if (!src) return xmlErr(404, "BlobNotFound");
        const want = c.headers["x-ms-source-if-match"];
        if (want && want !== src.etag) return xmlErr(412, "SourceConditionNotMet");
        blobs.set(name, { bytes: Buffer.from(src.bytes), type: src.type, etag: `"0x${++n}"` });
        return { status: 202, headers: { "x-ms-copy-status": "success", etag: `"0x${n}"` } };
      }
      if (c.method === "PUT") {
        if (c.headers["x-ms-blob-type"] !== "BlockBlob") return xmlErr(400, "MissingRequiredHeader");
        const ifMatch = c.headers["if-match"];
        if (ifMatch && (!cur || cur.etag !== ifMatch)) return xmlErr(412, "ConditionNotMet");
        if (c.headers["if-none-match"] === "*" && cur) return xmlErr(409, "BlobAlreadyExists");
        const etag = `"0x${++n}"`;
        blobs.set(name, { bytes: Buffer.from(c.body, "latin1"), type: c.headers["content-type"] ?? "", etag });
        return { status: 201, headers: { etag } };
      }
      if (c.method === "DELETE") {
        if (!cur) return xmlErr(404, "BlobNotFound");
        const ifMatch = c.headers["if-match"];
        if (ifMatch && cur.etag !== ifMatch) return xmlErr(412, "ConditionNotMet");
        blobs.delete(name);
        return { status: 202 };
      }
      if (!cur) return c.method === "HEAD" ? { status: 404, headers: { "x-ms-error-code": "BlobNotFound" } } : xmlErr(404, "BlobNotFound");
      if (c.method === "HEAD") return { headers: { etag: cur.etag, "content-length": String(cur.bytes.length) } };
      const range = /^bytes=0-(\d+)$/.exec(c.headers.range ?? "");
      const part = cur.bytes.subarray(0, range ? Number(range[1]) + 1 : cur.bytes.length);
      return { status: part.length < cur.bytes.length ? 206 : 200, bytes: part, headers: { "content-type": cur.type, etag: cur.etag, "content-range": `bytes 0-${part.length - 1}/${cur.bytes.length}` } };
    },
  });
  return Object.assign(b, { blobs });
}
export type FakeBlob = ReturnType<typeof fakeBlob>;
const az = (b: Backend) => b as FakeBlob;
const put = (b: Backend, key: string, content: string) => void az(b).blobs.set(key, { bytes: Buffer.from(content), type: "text/plain", etag: '"0x0"' });
const seed = (b: Backend) => put(b, "a/b.txt", "v1");
const visible = (b: Backend) => (az(b).state() as { blobs: string[][] }).blobs.filter(([k]) => !k!.startsWith(".reversi-backups/"));
const backups = (b: Backend) => [...az(b).blobs.keys()].filter((k) => k.startsWith(".reversi-backups/"));

export const subject: Subject = {
  name: "azure",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeBlob();
    return { backend, connector: createAzureConnector({ account: ACCOUNT, token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (status, secret) => ({ text: `<Error><Code>AuthorizationFailure</Code><Message>status ${status} ${secret}</Message></Error>`, headers: { "x-ms-error-code": "AuthorizationFailure" } } as FakeReply),
};

const base = { fingerprint: visible };
export const scenarios: Scenario[] = [
  { tool: "get_blob", args: { container: CONTAINER, blob: "a/b.txt" }, setup: seed, expect: (r) => expect(r).toMatchObject({ content: "v1", encoding: "utf8", size: 2 }) },
  {
    tool: "list_blobs",
    args: { container: CONTAINER, prefix: "a/" },
    setup: (b) => (seed(b), put(b, BK, "hidden")),
    expect: (r) => expect((r as { blobs: Array<{ blob: string }> }).blobs.map((x) => x.blob)).toEqual(["a/b.txt"]),
  },
  { tool: "put_blob", args: { container: CONTAINER, blob: "a/new.txt", content: "hello" }, ...base, expect: (r) => expect(r).toMatchObject({ existed: false, backup_blob: null }) },
  { tool: "put_blob", args: { container: CONTAINER, blob: "a/b.txt", content: "v2" }, setup: seed, ...base, expect: (r, b) => (expect(r).toMatchObject({ existed: true }), expect(backups(b)).toHaveLength(1)) },
  { tool: "delete_blob", args: { container: CONTAINER, blob: "a/b.txt" }, setup: seed, ...base, expect: (_r, b) => expect(backups(b)).toHaveLength(1) },
  {
    tool: "restore_blob",
    args: { container: CONTAINER, blob: "a/b.txt", backup_blob: BK },
    setup: (b) => (put(b, "a/b.txt", "v2"), put(b, BK, "v1")),
    ...base,
    expect: (_r, b) => expect(az(b).blobs.get("a/b.txt")!.bytes.toString()).toBe("v1"),
  },
  { tool: "restore_blob", args: { container: CONTAINER, blob: "a/new.txt", backup_blob: null }, setup: (b) => put(b, "a/new.txt", "x"), ...base },
];
