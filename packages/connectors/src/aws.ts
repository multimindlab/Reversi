import { EffectUncertainError } from "@multimindlab/reversi";
import {
  HttpError,
  defineConnector,
  matches,
  optPosInt,
  optStr,
  redact,
  send,
  xmlBlocks,
  xmlText,
  BACKUP_PREFIX,
  type Connector,
  type Fetch,
  type Sent,
} from "./common.js";
import {
  backupName,
  contentBytes,
  contentOut,
  contentProps,
  isBackupName,
  maxBytes,
  mediaType,
  newBackupName,
  objectName,
} from "./objects.js";
import { amzDateOf, canonicalQueryString, sha256Hex, signV4, uriEncode } from "./sigv4.js";

export interface AwsConfig {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region: string;
  fetch?: Fetch;
  /** An S3-compatible endpoint (MinIO, LocalStack). Requests then use path-style URLs. */
  endpoint?: string;
  timeoutMs?: number;
  /** Clock for the signature; tests pin it. */
  now?: () => Date;
}

const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;
const EMPTY_HASH = sha256Hex("");

export function createAwsConnector(cfg: AwsConfig): Connector {
  if (!cfg.accessKeyId) throw new Error("aws connector needs an `accessKeyId`");
  if (!cfg.secretAccessKey) throw new Error("aws connector needs a `secretAccessKey`");
  if (!cfg.region || !REGION.test(cfg.region)) throw new Error("aws connector needs a `region` such as us-east-1");
  const f = cfg.fetch ?? fetch;
  const secrets = [cfg.secretAccessKey, cfg.sessionToken ?? ""].filter(Boolean);
  const timeoutMs = cfg.timeoutMs ?? 30000;
  const now = cfg.now ?? (() => new Date());
  const endpoint = cfg.endpoint ? new URL(cfg.endpoint.replace(/\/+$/, "")) : undefined;

  function location(bucket: string, key: string): { origin: string; host: string; path: string } {
    if (endpoint) {
      const prefix = endpoint.pathname.replace(/\/+$/, "");
      return {
        origin: endpoint.origin,
        host: endpoint.host,
        path: `${prefix}/${bucket}${key ? "/" + uriEncode(key, true) : ""}`,
      };
    }
    if (bucket.includes(".")) {
      const host = `s3.${cfg.region}.amazonaws.com`;
      return { origin: `https://${host}`, host, path: `/${bucket}${key ? "/" + uriEncode(key, true) : ""}` };
    }
    const host = `${bucket}.s3.${cfg.region}.amazonaws.com`;
    return { origin: `https://${host}`, host, path: `/${key ? uriEncode(key, true) : ""}` };
  }

  /** A signed S3 request. XML error bodies become HttpError unless the status is tolerated. */
  async function s3(
    method: "GET" | "HEAD" | "PUT" | "DELETE",
    bucket: string,
    key: string,
    o: {
      query?: Array<[string, string]>;
      headers?: Record<string, string>;
      body?: Uint8Array;
      binary?: boolean;
      tolerate?: number[];
    } = {},
  ): Promise<Sent> {
    const loc = location(bucket, key);
    const body = o.body;
    const headers: Record<string, string> = {
      host: loc.host,
      "x-amz-date": amzDateOf(now()),
      "x-amz-content-sha256": body ? sha256Hex(body) : EMPTY_HASH,
      ...(o.headers ?? {}),
    };
    const signed = signV4({
      method,
      canonicalUri: loc.path || "/",
      query: o.query,
      headers,
      payloadHash: headers["x-amz-content-sha256"]!,
      region: cfg.region,
      service: "s3",
      accessKeyId: cfg.accessKeyId,
      secretAccessKey: cfg.secretAccessKey,
      sessionToken: cfg.sessionToken,
      amzDate: headers["x-amz-date"]!,
    });
    const { host: _host, ...wire } = signed.headers;
    void _host;
    const qs = o.query && o.query.length ? `?${canonicalQueryString(o.query)}` : "";
    const label = `S3 ${method} ${bucket}/${key}`.trim();
    const res = await send(
      f,
      `${loc.origin}${loc.path || "/"}${qs}`,
      { method, headers: { ...wire, Authorization: signed.authorization }, body },
      { label, mutating: method === "PUT" || method === "DELETE", secrets, timeoutMs, binary: o.binary },
    );
    if (!res.ok && !(o.tolerate ?? []).includes(res.status)) {
      const code = xmlText(res.text, "Code");
      const msg = xmlText(res.text, "Message");
      const detail = code || msg ? `${code ?? ""}${code && msg ? ": " : ""}${msg ?? ""}` : "";
      throw new HttpError(`${label} failed with status ${res.status}${detail ? `: ${redact(detail, secrets).slice(0, 200)}` : ""}`, res.status);
    }
    return res;
  }

  /** CopyObject can answer 200 with an <Error> body. */
  async function copy(bucket: string, from: string, to: string): Promise<void> {
    const r = await s3("PUT", bucket, to, {
      headers: { "x-amz-copy-source": `/${bucket}/${uriEncode(from, true)}` },
    });
    if (/<Error>/.test(r.text)) {
      const code = xmlText(r.text, "Code") ?? "unknown";
      throw new HttpError(`S3 copy ${from} to ${to} failed: ${code}`, 500);
    }
  }

  const bucketProp = { type: "string", description: "Bucket name" };
  const keyProp = { type: "string", description: "Object key" };
  const bucketOf = (args: Record<string, unknown>) => {
    const b = matches(args, "bucket", BUCKET, "bucket name");
    if (b.includes("..")) throw new Error("`bucket` is not a valid bucket name");
    return b;
  };

  /** HEAD, then copy the current object aside. Returns the backup name, or null if the key did not exist. */
  async function backUp(bucket: string, key: string): Promise<{ existed: boolean; backup_key: string | null }> {
    const head = await s3("HEAD", bucket, key, { tolerate: [404] });
    if (head.status === 404) return { existed: false, backup_key: null };
    const backup_key = newBackupName();
    await copy(bucket, key, backup_key);
    return { existed: true, backup_key };
  }

  async function dropBackup(bucket: string, backup_key: string | null): Promise<void> {
    if (backup_key) await s3("DELETE", bucket, backup_key).catch(() => undefined);
  }

  const restoreMap = { bucket: "$args.bucket", key: "$args.key", backup_key: "$result.backup_key" };

  return defineConnector("aws", [
    {
      name: "get_object",
      description: "Read an object (at most max_bytes, default 5 MiB). Needs s3:GetObject.",
      effect: "read_only",
      permission: "aws:s3:read",
      properties: { bucket: bucketProp, key: keyProp, max_bytes: { type: "integer", minimum: 1 } },
      required: ["bucket", "key"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key", { allowBackup: true });
        const max = maxBytes(args);
        const r = await s3("GET", bucket, key, { headers: { range: `bytes=0-${max - 1}` }, binary: true });
        const bytes = r.bytes ?? new Uint8Array();
        const total = /\/(\d+)$/.exec(r.headers.get("content-range") ?? "")?.[1];
        const size = total ? Number(total) : bytes.byteLength;
        return {
          bucket,
          key,
          ...contentOut(bytes),
          size,
          truncated: size > bytes.byteLength,
          content_type: r.headers.get("content-type"),
          etag: r.headers.get("etag"),
        };
      },
    },
    {
      name: "list_objects",
      description: "List objects (ListObjectsV2). Needs s3:ListBucket. Backup objects are hidden.",
      effect: "read_only",
      permission: "aws:s3:read",
      properties: {
        bucket: bucketProp,
        prefix: { type: "string" },
        max_keys: { type: "integer", minimum: 1, maximum: 1000 },
        continuation_token: { type: "string" },
      },
      required: ["bucket"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const query: Array<[string, string]> = [["list-type", "2"]];
        const prefix = optStr(args, "prefix", { max: 1024 });
        const max = optPosInt(args, "max_keys");
        if (max !== undefined && max > 1000) throw new Error("`max_keys` must be at most 1000");
        const token = optStr(args, "continuation_token", { max: 2048 });
        if (prefix) query.push(["prefix", prefix]);
        if (max) query.push(["max-keys", String(max)]);
        if (token) query.push(["continuation-token", token]);
        const r = await s3("GET", bucket, "", { query });
        const objects = xmlBlocks(r.text, "Contents")
          .map((c) => ({
            key: xmlText(c, "Key") ?? "",
            size: Number(xmlText(c, "Size") ?? 0),
            last_modified: xmlText(c, "LastModified") ?? null,
            etag: xmlText(c, "ETag") ?? null,
          }))
          .filter((o) => o.key && !isBackupName(o.key));
        return {
          objects,
          truncated: xmlText(r.text, "IsTruncated") === "true",
          next_continuation_token: xmlText(r.text, "NextContinuationToken") ?? null,
        };
      },
    },
    {
      name: "put_object",
      description: `Write an object. If one exists it is first copied to ${BACKUP_PREFIX}<uuid> in the same bucket, so rollback restores it (or deletes the new object). Needs s3:GetObject, s3:PutObject and s3:ListBucket.`,
      effect: "reversible",
      permission: "aws:s3:write",
      compensation: { tool: "restore_object", argument_map: restoreMap },
      properties: { bucket: bucketProp, key: keyProp, ...contentProps },
      required: ["bucket", "key", "content"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key");
        const body = contentBytes(args);
        const type = mediaType(args);
        const { existed, backup_key } = await backUp(bucket, key);
        try {
          const r = await s3("PUT", bucket, key, { body, headers: { "content-type": type } });
          return { bucket, key, existed, backup_key, etag: r.headers.get("etag") };
        } catch (e) {
          if (e instanceof EffectUncertainError && backup_key) {
            throw new EffectUncertainError(`${e.message}; the previous version is saved at ${backup_key}`);
          }
          if (!(e instanceof EffectUncertainError)) await dropBackup(bucket, backup_key);
          throw e;
        }
      },
    },
    {
      name: "delete_object",
      description: `Delete an object. It is first copied to ${BACKUP_PREFIX}<uuid> so rollback can restore it. Needs s3:GetObject, s3:DeleteObject and s3:ListBucket.`,
      effect: "reversible",
      permission: "aws:s3:write",
      compensation: { tool: "restore_object", argument_map: restoreMap },
      properties: { bucket: bucketProp, key: keyProp },
      required: ["bucket", "key"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key");
        const { existed, backup_key } = await backUp(bucket, key);
        if (!existed) return { bucket, key, existed, backup_key };
        try {
          await s3("DELETE", bucket, key);
        } catch (e) {
          if (e instanceof EffectUncertainError) {
            throw new EffectUncertainError(`${e.message}; the previous version is saved at ${backup_key}`);
          }
          await dropBackup(bucket, backup_key);
          throw e;
        }
        return { bucket, key, existed, backup_key };
      },
    },
    {
      name: "restore_object",
      description:
        "Undo put_object or delete_object: copy the saved backup back over the key, or delete the key when there was no previous object (backup_key null). Safe to repeat. The backup object is kept.",
      effect: "idempotent",
      permission: "aws:s3:write",
      properties: {
        bucket: bucketProp,
        key: keyProp,
        backup_key: { type: ["string", "null"], description: "Backup object name, or null if the key did not exist" },
      },
      required: ["bucket", "key", "backup_key"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key");
        const backup = backupName(args, "backup_key");
        if (backup === null) {
          await s3("DELETE", bucket, key);
          return { bucket, key, restored: true, action: "deleted" };
        }
        try {
          await copy(bucket, backup, key);
        } catch (e) {
          if (e instanceof HttpError && e.status === 404) throw new Error(`backup ${backup} was not found`);
          throw e;
        }
        return { bucket, key, restored: true, action: "restored" };
      },
    },
  ]);
}
