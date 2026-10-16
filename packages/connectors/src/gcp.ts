import { EffectUncertainError } from "@multimindlab/reversi";
import {
  BACKUP_PREFIX,
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optPosInt,
  optStr,
  send,
  snippet,
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

export interface GcpConfig {
  /** An OAuth 2.0 access token with a Cloud Storage scope. */
  accessToken: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const BUCKET = /^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$/;
const MAX_REWRITE_ROUNDS = 1000;

export function createGcpConnector(cfg: GcpConfig): Connector {
  if (!cfg.accessToken) throw new Error("gcp connector needs an `accessToken`");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? "https://storage.googleapis.com").replace(/\/+$/, "");
  const secrets = [cfg.accessToken];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST" | "DELETE",
    p: string,
    o: {
      query?: Array<[string, string]>;
      body?: Uint8Array | string;
      contentType?: string;
      headers?: Record<string, string>;
      binary?: boolean;
      tolerate?: number[];
    } = {},
  ): Promise<Sent> {
    const q = new URLSearchParams(o.query ?? []).toString();
    const label = `GCS ${method} ${p}`;
    const res = await send(
      f,
      `${base}${p}${q ? `?${q}` : ""}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${cfg.accessToken}`,
          ...(o.contentType ? { "Content-Type": o.contentType } : {}),
          ...(o.headers ?? {}),
        },
        body: o.body,
      },
      { label, mutating: method !== "GET", secrets, timeoutMs, binary: o.binary },
    );
    if (!res.ok && !(o.tolerate ?? []).includes(res.status)) {
      throw new HttpError(`${label} failed with status ${res.status}: ${snippet(res, secrets)}`, res.status);
    }
    return res;
  }

  const objPath = (bucket: string, name: string) => `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;

  /** Current generation of an object, or null if it does not exist. */
  async function generationOf(bucket: string, name: string): Promise<string | null> {
    const r = await api("GET", objPath(bucket, name), { query: [["fields", "generation"]], tolerate: [404] });
    if (r.status === 404) return null;
    const g = asRecord(r.json).generation;
    if (typeof g !== "string" && typeof g !== "number") throw new Error("Cloud Storage response had no generation");
    return String(g);
  }

  /** Server-side copy that survives large objects: rewrite until `done`. */
  async function rewrite(bucket: string, from: string, to: string, sourceGeneration?: string): Promise<void> {
    let token: string | undefined;
    for (let i = 0; i < MAX_REWRITE_ROUNDS; i++) {
      const query: Array<[string, string]> = [];
      if (sourceGeneration) query.push(["sourceGeneration", sourceGeneration]);
      if (token) query.push(["rewriteToken", token]);
      const r = await api("POST", `${objPath(bucket, from)}/rewriteTo/b/${bucket}/o/${encodeURIComponent(to)}`, {
        query,
        body: "{}",
        contentType: "application/json",
      });
      const j = asRecord(r.json);
      if (j.done === true) return;
      if (typeof j.rewriteToken !== "string") throw new Error("Cloud Storage rewrite did not finish and gave no token");
      token = j.rewriteToken;
    }
    throw new Error("Cloud Storage rewrite did not finish");
  }

  const bucketProp = { type: "string", description: "Bucket name" };
  const keyProp = { type: "string", description: "Object name" };
  const bucketOf = (args: Record<string, unknown>) => matches(args, "bucket", BUCKET, "bucket name");
  const restoreMap = { bucket: "$args.bucket", key: "$args.key", backup_key: "$result.backup_key" };

  async function dropBackup(bucket: string, backup_key: string | null): Promise<void> {
    if (backup_key) await api("DELETE", objPath(bucket, backup_key), { tolerate: [404] }).catch(() => undefined);
  }

  return defineConnector("gcp", [
    {
      name: "get_object",
      description: "Read an object (at most max_bytes, default 5 MiB). Needs storage.objects.get.",
      effect: "read_only",
      permission: "gcp:storage:read",
      properties: { bucket: bucketProp, key: keyProp, max_bytes: { type: "integer", minimum: 1 } },
      required: ["bucket", "key"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key", { allowBackup: true });
        const max = maxBytes(args);
        const r = await api("GET", objPath(bucket, key), {
          query: [["alt", "media"]],
          headers: { Range: `bytes=0-${max - 1}` },
          binary: true,
        });
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
        };
      },
    },
    {
      name: "list_objects",
      description: "List objects. Needs storage.objects.list. Backup objects are hidden.",
      effect: "read_only",
      permission: "gcp:storage:read",
      properties: {
        bucket: bucketProp,
        prefix: { type: "string" },
        max_results: { type: "integer", minimum: 1, maximum: 1000 },
        page_token: { type: "string" },
      },
      required: ["bucket"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const query: Array<[string, string]> = [["fields", "items(name,size,updated,contentType),nextPageToken"]];
        const prefix = optStr(args, "prefix", { max: 1024 });
        const max = optPosInt(args, "max_results");
        if (max !== undefined && max > 1000) throw new Error("`max_results` must be at most 1000");
        const token = optStr(args, "page_token", { max: 2048 });
        if (prefix) query.push(["prefix", prefix]);
        if (max) query.push(["maxResults", String(max)]);
        if (token) query.push(["pageToken", token]);
        const j = asRecord((await api("GET", `/storage/v1/b/${bucket}/o`, { query })).json);
        const objects = (Array.isArray(j.items) ? j.items : [])
          .map(asRecord)
          .filter((o) => typeof o.name === "string" && !isBackupName(o.name))
          .map((o) => ({ key: o.name, size: Number(o.size ?? 0), updated: o.updated ?? null, content_type: o.contentType ?? null }));
        return { objects, next_page_token: typeof j.nextPageToken === "string" ? j.nextPageToken : null };
      },
    },
    {
      name: "put_object",
      description: `Write an object. If one exists it is first copied to ${BACKUP_PREFIX}<uuid> in the same bucket and the upload is conditional on that generation, so rollback restores exactly what was overwritten (or deletes the new object). Needs storage.objects.get, create, delete and list.`,
      effect: "reversible",
      permission: "gcp:storage:write",
      compensation: { tool: "restore_object", argument_map: restoreMap },
      properties: { bucket: bucketProp, key: keyProp, ...contentProps },
      required: ["bucket", "key", "content"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key");
        const body = contentBytes(args);
        const type = mediaType(args);
        const generation = await generationOf(bucket, key);
        const existed = generation !== null;
        const backup_key = existed ? newBackupName() : null;
        if (backup_key) await rewrite(bucket, key, backup_key, generation!);
        try {
          const r = await api("POST", `/upload/storage/v1/b/${bucket}/o`, {
            query: [
              ["uploadType", "media"],
              ["name", key],
              ["ifGenerationMatch", generation ?? "0"],
            ],
            body,
            contentType: type,
          });
          return { bucket, key, existed, backup_key, generation: asRecord(r.json).generation ?? null };
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
      description: `Delete an object. It is first copied to ${BACKUP_PREFIX}<uuid> and the delete is conditional on that generation, so rollback restores what was deleted. Needs storage.objects.get, create, delete and list.`,
      effect: "reversible",
      permission: "gcp:storage:write",
      compensation: { tool: "restore_object", argument_map: restoreMap },
      properties: { bucket: bucketProp, key: keyProp },
      required: ["bucket", "key"],
      handler: async (args) => {
        const bucket = bucketOf(args);
        const key = objectName(args, "key");
        const generation = await generationOf(bucket, key);
        if (generation === null) return { bucket, key, existed: false, backup_key: null };
        const backup_key = newBackupName();
        await rewrite(bucket, key, backup_key, generation);
        try {
          await api("DELETE", objPath(bucket, key), { query: [["ifGenerationMatch", generation]] });
        } catch (e) {
          if (e instanceof EffectUncertainError) {
            throw new EffectUncertainError(`${e.message}; the previous version is saved at ${backup_key}`);
          }
          await dropBackup(bucket, backup_key);
          throw e;
        }
        return { bucket, key, existed: true, backup_key };
      },
    },
    {
      name: "restore_object",
      description:
        "Undo put_object or delete_object: copy the saved backup back over the key, or delete the key when there was no previous object (backup_key null). Safe to repeat. The backup object is kept.",
      effect: "idempotent",
      permission: "gcp:storage:write",
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
          await api("DELETE", objPath(bucket, key), { tolerate: [404] });
          return { bucket, key, restored: true, action: "deleted" };
        }
        try {
          await rewrite(bucket, backup, key);
        } catch (e) {
          if (e instanceof HttpError && e.status === 404) throw new Error(`backup ${backup} was not found`);
          throw e;
        }
        return { bucket, key, restored: true, action: "restored" };
      },
    },
  ]);
}
