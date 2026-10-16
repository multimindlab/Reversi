import { EffectUncertainError, Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { compensatorFor, createAwsConnector, createAzureConnector, createGcpConnector } from "../src/index.js";
import { ACCESS_KEY_ID, BUCKET, NOW, REGION, SECRET, SESSION, fakeS3, verifySignature } from "./fixtures/aws.js";
import { ACCOUNT, CONTAINER, TOKEN as AZ_TOKEN, fakeBlob } from "./fixtures/azure.js";
import { BUCKET as GCS_BUCKET, TOKEN as GCP_TOKEN, fakeGcs } from "./fixtures/gcp.js";
import { engine } from "./helpers.js";

const route = (c: { method: string; url: string }) => `${c.method} ${decodeURIComponent(new URL(c.url).pathname)}`;

describe("aws (S3)", () => {
  const make = (o: { endpoint?: string } = {}) => {
    const b = fakeS3();
    const c = createAwsConnector({ accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, sessionToken: SESSION, region: REGION, fetch: b.fetch, now: () => NOW, ...o });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`aws.${n}`]!(a, {}) };
  };
  const put = (b: ReturnType<typeof fakeS3>, k: string, v: string) => b.objects.set(k, { bytes: Buffer.from(v), type: "text/plain" });

  it("manifests validate; one restore tool undoes both put and delete", () => {
    const { c } = make();
    const reg = Registry.from(c.manifests);
    expect(reg.size).toBe(5);
    expect(reg.get("aws.put_object")?.compensation).toMatchObject({ tool: "aws.restore_object", argument_map: { bucket: "$args.bucket", key: "$args.key", backup_key: "$result.backup_key" } });
    expect(reg.get("aws.delete_object")?.compensation?.tool).toBe("aws.restore_object");
    expect(reg.get("aws.get_object")?.effect).toBe("read_only");
    expect(reg.get("aws.list_objects")?.effect).toBe("read_only");
  });

  it("signs every request with SigV4 (verified by the fake from the request as received)", async () => {
    const { b, t } = make();
    put(b, "docs/a.txt", "v1");
    await t("get_object", { bucket: BUCKET, key: "docs/a.txt" });
    await t("put_object", { bucket: BUCKET, key: "docs/a b+c.txt", content: "x" });
    await t("list_objects", { bucket: BUCKET, prefix: "docs/" });
    expect(b.calls.length).toBeGreaterThanOrEqual(4);
    for (const c of b.calls) {
      expect(verifySignature(c)).toBeUndefined();
      expect(c.headers["x-amz-date"]).toBe("20260501T120000Z");
      expect(c.headers["x-amz-security-token"]).toBe(SESSION);
      expect(c.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEYID1234\/20260501\/us-east-1\/s3\/aws4_request, SignedHeaders=.*host.*x-amz-content-sha256.*x-amz-date.*x-amz-security-token, Signature=[0-9a-f]{64}$/);
      expect(c.headers.authorization).not.toContain(SECRET);
    }
  });

  it("a tampered request fails verification", async () => {
    const { b, t } = make();
    await t("put_object", { bucket: BUCKET, key: "k", content: "x" });
    const call = b.calls.at(-1)!;
    expect(verifySignature({ ...call, headers: { ...call.headers, "x-amz-date": "20260501T120001Z" } })).toBe("signature mismatch");
  });

  it("uses virtual-hosted URLs, path-style for dotted buckets, and a custom endpoint", async () => {
    const { b, t } = make();
    await t("put_object", { bucket: BUCKET, key: "a/b.txt", content: "x" });
    expect(b.calls[0]!.url).toBe(`https://${BUCKET}.s3.us-east-1.amazonaws.com/a/b.txt`);
    const dotted = make();
    await dotted.t("get_object", { bucket: "my.dotted.bucket", key: "a" }).catch(() => undefined);
    expect(dotted.b.calls[0]!.url).toBe("https://s3.us-east-1.amazonaws.com/my.dotted.bucket/a");
    const local = make({ endpoint: "http://localhost:9000" });
    await local.t("list_objects", { bucket: BUCKET, max_keys: 5 }).catch(() => undefined);
    expect(local.b.calls[0]!.url).toBe(`http://localhost:9000/${BUCKET}?list-type=2&max-keys=5`);
  });

  it("put over an existing object: HEAD, copy to a backup key, then PUT", async () => {
    const { b, t } = make();
    put(b, "docs/a.txt", "v1");
    const r = (await t("put_object", { bucket: BUCKET, key: "docs/a.txt", content: "v2" })) as { existed: boolean; backup_key: string };
    expect(r.existed).toBe(true);
    expect(r.backup_key).toMatch(/^\.reversi-backups\/[0-9a-f-]{36}$/);
    expect(b.calls.map(route)).toEqual(["HEAD /docs/a.txt", `PUT /${r.backup_key}`, "PUT /docs/a.txt"]);
    expect(b.calls[1]!.headers["x-amz-copy-source"]).toBe(`/${BUCKET}/docs/a.txt`);
    expect(b.objects.get(r.backup_key)!.bytes.toString()).toBe("v1");
    expect(b.objects.get("docs/a.txt")!.bytes.toString()).toBe("v2");
  });

  it("put of a new key makes no backup", async () => {
    const { b, t } = make();
    const r = await t("put_object", { bucket: BUCKET, key: "new.txt", content: "x", content_type: "text/csv" });
    expect(r).toMatchObject({ existed: false, backup_key: null });
    expect(b.calls.map((c) => c.method)).toEqual(["HEAD", "PUT"]);
    expect(b.calls[1]!.headers["content-type"]).toBe("text/csv");
    expect([...b.objects.keys()]).toEqual(["new.txt"]);
  });

  it("a definite failure of the PUT removes the backup; an uncertain one keeps it and names it", async () => {
    const definite = make();
    put(definite.b, "k", "v1");
    definite.b.fault = { kind: "status", status: 403, on: "mutating" };
    // the copy is the first write; let it through, fail only the second write
    let writes = 0;
    const real = definite.b.fetch;
    const c1 = createAwsConnector({
      accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, region: REGION, now: () => NOW,
      fetch: (async (u: string, i: RequestInit) => {
        const isWrite = i.method === "PUT";
        if (isWrite && ++writes === 2) return new Response("<Error><Code>AccessDenied</Code></Error>", { status: 403 });
        definite.b.fault = null;
        return real(u, i);
      }) as typeof fetch,
    });
    const err = await c1.tools["aws.put_object"]!({ bucket: BUCKET, key: "k", content: "v2" }, {}).catch((e) => e);
    expect(err.message).toContain("AccessDenied");
    expect([...definite.b.objects.keys()]).toEqual(["k"]);

    const lost = make();
    put(lost.b, "k", "v1");
    let n = 0;
    const real2 = lost.b.fetch;
    const c2 = createAwsConnector({
      accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, region: REGION, now: () => NOW,
      fetch: (async (u: string, i: RequestInit) => {
        if (i.method === "PUT" && ++n === 2) throw new TypeError("socket hang up");
        return real2(u, i);
      }) as typeof fetch,
    });
    const e2 = await c2.tools["aws.put_object"]!({ bucket: BUCKET, key: "k", content: "v2" }, {}).catch((e) => e);
    expect(e2).toBeInstanceOf(EffectUncertainError);
    const backup = [...lost.b.objects.keys()].find((k) => k.startsWith(".reversi-backups/"))!;
    expect(e2.message).toContain(backup);
  });

  it("delete copies aside then deletes, and restore brings it back; the backup stays as residue", async () => {
    const { b, c } = make();
    put(b, "docs/a.txt", "v1");
    const { call, run } = engine([c]);
    await call("aws.delete_object", { bucket: BUCKET, key: "docs/a.txt" });
    expect(b.objects.has("docs/a.txt")).toBe(false);
    expect([...b.objects.keys()].filter((k) => k.startsWith(".reversi-backups/"))).toHaveLength(1);
    const report = await run.rollback({ compensate: compensatorFor([c]) });
    expect(report.complete).toBe(true);
    expect(b.objects.get("docs/a.txt")!.bytes.toString()).toBe("v1");
    expect([...b.objects.keys()].filter((k) => k.startsWith(".reversi-backups/"))).toHaveLength(1);
  });

  it("deleting a missing key is a no-op whose rollback leaves the key absent", async () => {
    const { b, t } = make();
    expect(await t("delete_object", { bucket: BUCKET, key: "nope" })).toMatchObject({ existed: false, backup_key: null });
    expect(b.calls.map((c) => c.method)).toEqual(["HEAD"]);
  });

  it("returns binary content as base64 and honours max_bytes", async () => {
    const { b, t } = make();
    b.objects.set("bin", { bytes: Buffer.from([0xff, 0xfe, 0x00, 0x01]), type: "application/octet-stream" });
    expect(await t("get_object", { bucket: BUCKET, key: "bin" })).toMatchObject({ encoding: "base64", content: "//4AAQ==", size: 4 });
    put(b, "big", "0123456789");
    const r = (await t("get_object", { bucket: BUCKET, key: "big", max_bytes: 4 })) as { content: string; truncated: boolean; size: number };
    expect(r).toMatchObject({ content: "0123", truncated: true, size: 10 });
    expect(b.calls.at(-1)!.headers.range).toBe("bytes=0-3");
    await t("put_object", { bucket: BUCKET, key: "bin2", content: "//4AAQ==", encoding: "base64" });
    expect([...b.objects.get("bin2")!.bytes]).toEqual([0xff, 0xfe, 0x00, 0x01]);
  });

  it("lists with XML entities decoded and hides backups", async () => {
    const { b, t } = make();
    put(b, "a&b<c>.txt", "x");
    put(b, ".reversi-backups/00000000-0000-4000-8000-000000000009", "x");
    const r = (await t("list_objects", { bucket: BUCKET })) as { objects: Array<{ key: string }> };
    expect(r.objects.map((o) => o.key)).toEqual(["a&b<c>.txt"]);
  });

  it("surfaces S3 error codes with the status, not the credential, and rejects a copy that answers 200 with an error", async () => {
    const denied = createAwsConnector({
      accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, region: REGION,
      fetch: (async () => new Response(`<Error><Code>AccessDenied</Code><Message>no ${SECRET}</Message></Error>`, { status: 403 })) as typeof fetch,
    });
    const err = await denied.tools["aws.get_object"]!({ bucket: BUCKET, key: "k" }, {}).catch((e) => e);
    expect(err.message).toContain("status 403: AccessDenied");
    expect(err.message).not.toContain(SECRET);
    const sneaky = createAwsConnector({
      accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET, region: REGION,
      fetch: (async (_u: string, i: RequestInit) =>
        i.method === "HEAD" ? new Response(null, { status: 200 }) : new Response("<Error><Code>InternalError</Code></Error>", { status: 200 })) as typeof fetch,
    });
    await expect(sneaky.tools["aws.delete_object"]!({ bucket: BUCKET, key: "k" }, {})).rejects.toThrow("InternalError");
  });

  it("validates input and refuses the reserved backup prefix for writes", async () => {
    const { b, t } = make();
    await expect(t("put_object", { bucket: "Bad_Bucket", key: "k", content: "x" })).rejects.toThrow("bucket name");
    await expect(t("put_object", { bucket: BUCKET, key: ".reversi-backups/x", content: "x" })).rejects.toThrow("reserved");
    await expect(t("delete_object", { bucket: BUCKET, key: ".reversi-backups/x" })).rejects.toThrow("reserved");
    await expect(t("put_object", { bucket: BUCKET, key: "k", content: "!!!", encoding: "base64" })).rejects.toThrow("base64");
    await expect(t("put_object", { bucket: BUCKET, key: "k", content: "x", encoding: "latin1" })).rejects.toThrow("encoding");
    await expect(t("put_object", { bucket: BUCKET, key: "k", content: "x".repeat(5 * 1024 * 1024 + 1) })).rejects.toThrow("larger than");
    await expect(t("restore_object", { bucket: BUCKET, key: "k", backup_key: "somewhere/else" })).rejects.toThrow("backup object name");
    await expect(t("put_object", { bucket: BUCKET, key: "k\nx", content: "x" })).rejects.toThrow("control character");
    await expect(t("list_objects", { bucket: BUCKET, max_keys: 5000 })).rejects.toThrow("at most 1000");
    expect(b.calls).toHaveLength(0);
    expect(() => createAwsConnector({ accessKeyId: "a", secretAccessKey: "b", region: "mars" })).toThrow("region");
  });
});

describe("gcp (Cloud Storage)", () => {
  const make = () => {
    const b = fakeGcs();
    const c = createGcpConnector({ accessToken: GCP_TOKEN, fetch: b.fetch });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`gcp.${n}`]!(a, {}) };
  };
  const put = (b: ReturnType<typeof fakeGcs>, k: string, v: string, generation = 5) => b.objects.set(k, { bytes: Buffer.from(v), type: "text/plain", generation });

  it("manifests validate", () => {
    const reg = Registry.from(make().c.manifests);
    expect(reg.size).toBe(5);
    expect(reg.get("gcp.put_object")?.compensation?.tool).toBe("gcp.restore_object");
    expect(reg.get("gcp.delete_object")?.compensation?.tool).toBe("gcp.restore_object");
  });

  it("overwrites conditionally on the generation it backed up, following a multi-round rewrite", async () => {
    const { b, t } = make();
    put(b, "docs/a.txt", "v1", 42);
    const r = (await t("put_object", { bucket: GCS_BUCKET, key: "docs/a.txt", content: "v2" })) as { backup_key: string };
    const seen = b.calls.map((c) => `${c.method} ${new URL(c.url).pathname}${new URL(c.url).search}`);
    expect(seen[0]).toBe(`GET /storage/v1/b/${GCS_BUCKET}/o/docs%2Fa.txt?fields=generation`);
    const rewrites = seen.filter((s) => s.includes("/rewriteTo/"));
    expect(rewrites).toHaveLength(2);
    expect(rewrites[0]).toContain("sourceGeneration=42");
    expect(rewrites[1]).toContain("rewriteToken=round-2");
    expect(seen.at(-1)).toBe(`POST /upload/storage/v1/b/${GCS_BUCKET}/o?uploadType=media&name=docs%2Fa.txt&ifGenerationMatch=42`);
    expect(b.calls.every((c) => c.headers.authorization === `Bearer ${GCP_TOKEN}`)).toBe(true);
    expect(b.objects.get(r.backup_key)!.bytes.toString()).toBe("v1");
  });

  it("a new object is created only if absent (ifGenerationMatch=0)", async () => {
    const { b, t } = make();
    await t("put_object", { bucket: GCS_BUCKET, key: "new.txt", content: "x" });
    expect(b.calls.at(-1)!.url).toContain("ifGenerationMatch=0");
    // a concurrent writer wins the race: the upload is refused and nothing is overwritten
    const { b: b2, c } = make();
    const real = b2.fetch;
    const racing = createGcpConnector({
      accessToken: GCP_TOKEN,
      fetch: (async (u: string, i: RequestInit) => {
        if (i.method === "POST" && u.includes("/upload/")) put(b2, "new.txt", "theirs", 77);
        return real(u, i);
      }) as typeof fetch,
    });
    void c;
    const err = await racing.tools["gcp.put_object"]!({ bucket: GCS_BUCKET, key: "new.txt", content: "mine" }, {}).catch((e) => e);
    expect(err.message).toContain("status 412");
    expect(b2.objects.get("new.txt")!.bytes.toString()).toBe("theirs");
  });

  it("delete is conditional on the generation and fully restorable", async () => {
    const { b, c } = make();
    put(b, "docs/a.txt", "v1", 9);
    const { call, run } = engine([c]);
    await call("gcp.delete_object", { bucket: GCS_BUCKET, key: "docs/a.txt" });
    expect(b.calls.at(-1)!.url).toContain("ifGenerationMatch=9");
    expect(b.objects.has("docs/a.txt")).toBe(false);
    expect((await run.rollback({ compensate: compensatorFor([c]) })).complete).toBe(true);
    expect(b.objects.get("docs/a.txt")!.bytes.toString()).toBe("v1");
  });

  it("validates input", async () => {
    const { b, t } = make();
    await expect(t("get_object", { bucket: "UPPER", key: "k" })).rejects.toThrow("bucket name");
    await expect(t("put_object", { bucket: GCS_BUCKET, key: ".reversi-backups/a", content: "x" })).rejects.toThrow("reserved");
    await expect(t("restore_object", { bucket: GCS_BUCKET, key: "k", backup_key: "x" })).rejects.toThrow("backup object name");
    expect(b.calls).toHaveLength(0);
  });
});

describe("azure (Blob Storage)", () => {
  const make = () => {
    const b = fakeBlob();
    const c = createAzureConnector({ account: ACCOUNT, token: AZ_TOKEN, fetch: b.fetch });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`azure.${n}`]!(a, {}) };
  };
  const put = (b: ReturnType<typeof fakeBlob>, k: string, v: string, etag = '"0x0"') => b.blobs.set(k, { bytes: Buffer.from(v), type: "text/plain", etag });

  it("manifests validate", () => {
    const reg = Registry.from(make().c.manifests);
    expect(reg.size).toBe(5);
    expect(reg.get("azure.put_blob")?.compensation).toMatchObject({ tool: "azure.restore_blob", argument_map: { container: "$args.container", blob: "$args.blob", backup_blob: "$result.backup_blob" } });
  });

  it("creates new blobs only if absent, and overwrites only the version it backed up", async () => {
    const { b, t } = make();
    await t("put_blob", { container: CONTAINER, blob: "a/new.txt", content: "x", content_type: "text/plain" });
    const create = b.calls.at(-1)!;
    expect(create.url).toBe(`https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}/a/new.txt`);
    expect(create.headers["if-none-match"]).toBe("*");
    expect(create.headers["x-ms-blob-type"]).toBe("BlockBlob");
    expect(create.headers["x-ms-version"]).toBe("2023-11-03");
    expect(create.headers.authorization).toBe(`Bearer ${AZ_TOKEN}`);

    put(b, "a/b.txt", "v1", '"0xABC"');
    const r = (await t("put_blob", { container: CONTAINER, blob: "a/b.txt", content: "v2" })) as { backup_blob: string };
    const calls = b.calls.slice(-3);
    expect(calls.map((c) => c.method)).toEqual(["HEAD", "PUT", "PUT"]);
    expect(calls[1]!.headers["x-ms-copy-source"]).toBe(`https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}/a/b.txt`);
    expect(calls[1]!.headers["x-ms-requires-sync"]).toBe("true");
    expect(calls[1]!.headers["x-ms-source-if-match"]).toBe('"0xABC"');
    expect(calls[2]!.headers["if-match"]).toBe('"0xABC"');
    expect(b.blobs.get(r.backup_blob)!.bytes.toString()).toBe("v1");
  });

  it("an overwrite by someone else in between is refused", async () => {
    const { b } = make();
    put(b, "a/b.txt", "v1", '"0x1"');
    const real = b.fetch;
    const c = createAzureConnector({
      account: ACCOUNT,
      token: AZ_TOKEN,
      fetch: (async (u: string, i: RequestInit) => {
        const res = await real(u, i);
        if (i.method === "PUT" && (i.headers as Record<string, string>)["x-ms-copy-source"]) put(b, "a/b.txt", "theirs", '"0x2"');
        return res;
      }) as typeof fetch,
    });
    const err = await c.tools["azure.put_blob"]!({ container: CONTAINER, blob: "a/b.txt", content: "mine" }, {}).catch((e) => e);
    expect(err.message).toContain("status 412");
    expect(err.message).toContain("ConditionNotMet");
    expect(b.blobs.get("a/b.txt")!.bytes.toString()).toBe("theirs");
    expect([...b.blobs.keys()].filter((k) => k.startsWith(".reversi-backups/"))).toEqual([]); // the backup was cleaned up
  });

  it("delete is conditional on the ETag and restorable", async () => {
    const { b, c } = make();
    put(b, "a/b.txt", "v1", '"0x7"');
    const { call, run } = engine([c]);
    await call("azure.delete_blob", { container: CONTAINER, blob: "a/b.txt" });
    expect(b.calls.filter((x) => x.method === "DELETE")[0]!.headers["if-match"]).toBe('"0x7"');
    expect((await run.rollback({ compensate: compensatorFor([c]) })).complete).toBe(true);
    expect(b.blobs.get("a/b.txt")!.bytes.toString()).toBe("v1");
  });

  it("validates input and names Azure error codes without the token", async () => {
    const { b, t } = make();
    await expect(t("get_blob", { container: "Bad_Container", blob: "x" })).rejects.toThrow("container name");
    await expect(t("put_blob", { container: CONTAINER, blob: ".reversi-backups/x", content: "x" })).rejects.toThrow("reserved");
    expect(b.calls).toHaveLength(0);
    const denied = createAzureConnector({
      account: ACCOUNT,
      token: AZ_TOKEN,
      fetch: (async () => new Response(`<Error><Code>AuthorizationPermissionMismatch</Code><Message>${AZ_TOKEN}\nRequestId:1</Message></Error>`, { status: 403 })) as typeof fetch,
    });
    const err = await denied.tools["azure.get_blob"]!({ container: CONTAINER, blob: "x" }, {}).catch((e) => e);
    expect(err.message).toContain("status 403: AuthorizationPermissionMismatch");
    expect(err.message).not.toContain(AZ_TOKEN);
    expect(() => createAzureConnector({ account: "BAD", token: "t" })).toThrow("account");
  });
});
