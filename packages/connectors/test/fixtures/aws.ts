import { expect } from "vitest";
import { createAwsConnector, signV4 } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";
import type { Call, FakeReply } from "../helpers.js";

export const ACCESS_KEY_ID = "AKIAEXAMPLEKEYID1234";
export const SECRET = "SECRETACCESSKEY/abcdefghij0123456789+xyz";
export const SESSION = "FwoGZXIvYXdzSESSIONTOKENexample";
export const BUCKET = "my-bucket";
export const REGION = "us-east-1";
export const NOW = new Date("2026-05-01T12:00:00Z");
export const BK = ".reversi-backups/00000000-0000-4000-8000-000000000001";

type Reply = FakeReply & { bytes?: Uint8Array; headers?: Record<string, string> };

const xmlError = (status: number, code: string, message = code): Reply => ({
  status,
  text: `<?xml version="1.0"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`,
});
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

/** Recompute the signature the way S3 would, from the request as it arrived. */
export function verifySignature(c: Call): string | undefined {
  const auth = c.headers.authorization ?? "";
  const m = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/s3\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(auth);
  if (!m) return "malformed Authorization header";
  if (m[1] !== ACCESS_KEY_ID) return "unknown access key";
  const u = new URL(c.url);
  const headers: Record<string, string> = {};
  for (const name of m[4]!.split(";")) {
    if (name === "host") headers.host = u.host;
    else if (c.headers[name] === undefined) return `signed header ${name} was not sent`;
    else headers[name] = c.headers[name]!;
  }
  delete headers["x-amz-security-token"];
  const query = [...u.searchParams.entries()] as Array<[string, string]>;
  const signed = signV4({
    method: c.method,
    canonicalUri: u.pathname,
    query,
    headers,
    payloadHash: c.headers["x-amz-content-sha256"] ?? "",
    region: REGION,
    service: "s3",
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET,
    sessionToken: c.headers["x-amz-security-token"],
    amzDate: c.headers["x-amz-date"] ?? "",
  });
  return signed.signature === m[5] ? undefined : "signature mismatch";
}

export function fakeS3() {
  const objects = new Map<string, { bytes: Buffer; type: string }>();
  let n = 0;
  const b = httpBackend({
    state: () => ({ objects: [...objects].map(([k, v]) => [k, v.bytes.toString("base64"), v.type]).sort() }),
    handle: (c): Reply => {
      const bad = verifySignature(c);
      if (bad) return xmlError(403, "SignatureDoesNotMatch", bad);
      const u = new URL(c.url);
      if (u.host !== `${BUCKET}.s3.${REGION}.amazonaws.com`) return xmlError(404, "NoSuchBucket");
      const key = decodeURIComponent(u.pathname.slice(1));
      if (c.method === "GET" && key === "") {
        const prefix = u.searchParams.get("prefix") ?? "";
        const rows = [...objects].filter(([k]) => k.startsWith(prefix)).sort(([a], [b2]) => (a < b2 ? -1 : 1));
        return {
          text:
            `<ListBucketResult><IsTruncated>false</IsTruncated>` +
            rows.map(([k, v]) => `<Contents><Key>${esc(k)}</Key><Size>${v.bytes.length}</Size><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>"e"</ETag></Contents>`).join("") +
            `</ListBucketResult>`,
        };
      }
      const copySource = c.headers["x-amz-copy-source"];
      if (c.method === "PUT" && copySource) {
        const src = objects.get(decodeURIComponent(copySource.replace(new RegExp(`^/${BUCKET}/`), "")));
        if (!src) return xmlError(404, "NoSuchKey", "The specified key does not exist.");
        objects.set(key, { bytes: Buffer.from(src.bytes), type: src.type });
        return { text: `<CopyObjectResult><ETag>"c${++n}"</ETag></CopyObjectResult>` };
      }
      if (c.method === "PUT") {
        objects.set(key, { bytes: Buffer.from(c.body, "latin1"), type: c.headers["content-type"] ?? "" });
        return { headers: { etag: `"p${++n}"` } };
      }
      if (c.method === "DELETE") {
        objects.delete(key);
        return { status: 204 };
      }
      const o = objects.get(key);
      if (!o) return c.method === "HEAD" ? { status: 404 } : xmlError(404, "NoSuchKey", "The specified key does not exist.");
      if (c.method === "HEAD") return { headers: { etag: '"h"', "content-length": String(o.bytes.length) } };
      const range = /^bytes=0-(\d+)$/.exec(c.headers.range ?? "");
      const end = range ? Number(range[1]) + 1 : o.bytes.length;
      const part = o.bytes.subarray(0, end);
      return {
        status: range && part.length < o.bytes.length ? 206 : 200,
        bytes: part,
        headers: { "content-type": o.type || "application/octet-stream", etag: '"g"', "content-range": `bytes 0-${part.length - 1}/${o.bytes.length}` },
      };
    },
  });
  return Object.assign(b, { objects });
}
export type FakeS3 = ReturnType<typeof fakeS3>;
const s3 = (b: Backend) => b as FakeS3;
const put = (b: Backend, key: string, content: string, type = "text/plain") => void s3(b).objects.set(key, { bytes: Buffer.from(content), type });
const seed = (b: Backend) => put(b, "docs/a.txt", "v1");
const visible = (b: Backend) => (s3(b).state() as { objects: string[][] }).objects.filter(([k]) => !k!.startsWith(".reversi-backups/"));
const backups = (b: Backend) => [...s3(b).objects.keys()].filter((k) => k.startsWith(".reversi-backups/"));

export const subject: Subject = {
  name: "aws",
  secrets: [SECRET, SESSION],
  make: (o) => {
    const backend = fakeS3();
    return {
      backend,
      connector: createAwsConnector({
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: SECRET,
        sessionToken: SESSION,
        region: REGION,
        fetch: backend.fetch,
        now: () => NOW,
        timeoutMs: o?.timeoutMs,
      }),
    };
  },
  faultBody: (status, secret) => ({ text: `<Error><Code>AccessDenied</Code><Message>status ${status} denied ${secret}</Message></Error>` }),
};

const base = { fingerprint: visible };
export const scenarios: Scenario[] = [
  { tool: "get_object", args: { bucket: BUCKET, key: "docs/a.txt" }, setup: seed, expect: (r) => expect(r).toMatchObject({ content: "v1", encoding: "utf8", size: 2, truncated: false }) },
  {
    tool: "list_objects",
    args: { bucket: BUCKET, prefix: "docs/", max_keys: 10 },
    setup: (b) => {
      seed(b);
      put(b, BK, "hidden");
      put(b, "other/b.txt", "x");
    },
    expect: (r) => expect((r as { objects: Array<{ key: string }> }).objects.map((o) => o.key)).toEqual(["docs/a.txt"]),
  },
  {
    tool: "put_object",
    args: { bucket: BUCKET, key: "docs/new file.txt", content: "hello" },
    ...base,
    expect: (r, b) => {
      expect(r).toMatchObject({ existed: false, backup_key: null });
      expect(backups(b)).toEqual([]);
    },
  },
  {
    tool: "put_object",
    args: { bucket: BUCKET, key: "docs/a.txt", content: "v2", content_type: "text/plain" },
    setup: seed,
    ...base,
    expect: (r, b) => {
      expect(r).toMatchObject({ existed: true });
      expect(backups(b)).toHaveLength(1);
    },
  },
  { tool: "delete_object", args: { bucket: BUCKET, key: "docs/a.txt" }, setup: seed, ...base, expect: (r, b) => (expect(r).toMatchObject({ existed: true }), expect(backups(b)).toHaveLength(1)) },
  {
    tool: "restore_object",
    args: { bucket: BUCKET, key: "docs/a.txt", backup_key: BK },
    setup: (b) => (put(b, "docs/a.txt", "v2"), put(b, BK, "v1")),
    ...base,
    expect: (_r, b) => expect(s3(b).objects.get("docs/a.txt")!.bytes.toString()).toBe("v1"),
  },
  {
    tool: "restore_object",
    args: { bucket: BUCKET, key: "docs/new.txt", backup_key: null },
    setup: (b) => put(b, "docs/new.txt", "x"),
    ...base,
  },
];
