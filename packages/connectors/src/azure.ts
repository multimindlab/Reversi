import { EffectUncertainError } from "@multimindlab/reversi";
import {
  BACKUP_PREFIX,
  HttpError,
  defineConnector,
  matches,
  optPosInt,
  optStr,
  redact,
  send,
  xmlBlocks,
  xmlText,
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

export interface AzureConfig {
  /** Storage account name. */
  account: string;
  /** A Microsoft Entra bearer token for https://storage.azure.com/. */
  token: string;
  fetch?: Fetch;
  /** Override the endpoint, e.g. for Azurite. Default https://<account>.blob.core.windows.net */
  baseUrl?: string;
  timeoutMs?: number;
}

const ACCOUNT = /^[a-z0-9]{3,24}$/;
const CONTAINER = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62}$/;
const API_VERSION = "2023-11-03";

export function createAzureConnector(cfg: AzureConfig): Connector {
  if (!cfg.token) throw new Error("azure connector needs a `token`");
  if (!cfg.account || !ACCOUNT.test(cfg.account)) throw new Error("azure connector needs a storage `account` name");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? `https://${cfg.account}.blob.core.windows.net`).replace(/\/+$/, "");
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  const encode = (name: string) => name.split("/").map(encodeURIComponent).join("/");
  const blobUrl = (container: string, name: string) => `${base}/${container}/${encode(name)}`;

  async function blobApi(
    method: "GET" | "HEAD" | "PUT" | "DELETE",
    url: string,
    o: {
      query?: Array<[string, string]>;
      headers?: Record<string, string>;
      body?: Uint8Array;
      binary?: boolean;
      tolerate?: number[];
    } = {},
  ): Promise<Sent> {
    const q = new URLSearchParams(o.query ?? []).toString();
    const label = `Blob ${method} ${url.slice(base.length)}`;
    const res = await send(
      f,
      `${url}${q ? `?${q}` : ""}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          "x-ms-version": API_VERSION,
          "x-ms-date": new Date().toUTCString(),
          ...(o.headers ?? {}),
        },
        body: o.body,
      },
      { label, mutating: method === "PUT" || method === "DELETE", secrets, timeoutMs, binary: o.binary },
    );
    if (!res.ok && !(o.tolerate ?? []).includes(res.status)) {
      const code = xmlText(res.text, "Code") ?? res.headers.get("x-ms-error-code") ?? "";
      const msg = xmlText(res.text, "Message") ?? "";
      const detail = [code, msg.split("\n")[0]].filter(Boolean).join(": ");
      throw new HttpError(`${label} failed with status ${res.status}${detail ? `: ${redact(detail, secrets).slice(0, 200)}` : ""}`, res.status);
    }
    return res;
  }

  /** Copy a blob within the account, synchronously, optionally only if the source still has `etag`. */
  async function copy(container: string, from: string, to: string, etag?: string): Promise<void> {
    const r = await blobApi("PUT", blobUrl(container, to), {
      headers: {
        "x-ms-copy-source": blobUrl(container, from),
        "x-ms-requires-sync": "true",
        "x-ms-copy-source-authorization": `Bearer ${cfg.token}`,
        ...(etag ? { "x-ms-source-if-match": etag } : {}),
      },
    });
    const status = r.headers.get("x-ms-copy-status");
    if (status && status !== "success") throw new Error(`Blob copy of ${from} ended with status ${status}`);
  }

  async function dropBackup(container: string, backup: string | null): Promise<void> {
    if (backup) await blobApi("DELETE", blobUrl(container, backup), { tolerate: [404] }).catch(() => undefined);
  }

  const containerProp = { type: "string", description: "Container name" };
  const blobProp = { type: "string", description: "Blob name" };
  const containerOf = (args: Record<string, unknown>) => matches(args, "container", CONTAINER, "container name");
  const restoreMap = { container: "$args.container", blob: "$args.blob", backup_blob: "$result.backup_blob" };

  /** HEAD the blob; if it exists, copy it aside bound to its ETag. */
  async function backUp(container: string, blob: string) {
    const head = await blobApi("HEAD", blobUrl(container, blob), { tolerate: [404] });
    if (head.status === 404) return { existed: false, etag: null, backup_blob: null as string | null };
    const etag = head.headers.get("etag");
    if (!etag) throw new Error("Blob storage returned no ETag");
    const backup_blob = newBackupName();
    await copy(container, blob, backup_blob, etag);
    return { existed: true, etag, backup_blob: backup_blob as string | null };
  }

  return defineConnector("azure", [
    {
      name: "get_blob",
      description: "Read a blob (at most max_bytes, default 5 MiB). Needs Storage Blob Data Reader.",
      effect: "read_only",
      permission: "azure:blob:read",
      properties: { container: containerProp, blob: blobProp, max_bytes: { type: "integer", minimum: 1 } },
      required: ["container", "blob"],
      handler: async (args) => {
        const container = containerOf(args);
        const blob = objectName(args, "blob", { allowBackup: true });
        const max = maxBytes(args);
        const r = await blobApi("GET", blobUrl(container, blob), { headers: { Range: `bytes=0-${max - 1}` }, binary: true });
        const bytes = r.bytes ?? new Uint8Array();
        const total = /\/(\d+)$/.exec(r.headers.get("content-range") ?? "")?.[1];
        const size = total ? Number(total) : bytes.byteLength;
        return {
          container,
          blob,
          ...contentOut(bytes),
          size,
          truncated: size > bytes.byteLength,
          content_type: r.headers.get("content-type"),
          etag: r.headers.get("etag"),
        };
      },
    },
    {
      name: "list_blobs",
      description: "List blobs in a container. Needs Storage Blob Data Reader. Backup blobs are hidden.",
      effect: "read_only",
      permission: "azure:blob:read",
      properties: {
        container: containerProp,
        prefix: { type: "string" },
        max_results: { type: "integer", minimum: 1, maximum: 5000 },
        marker: { type: "string" },
      },
      required: ["container"],
      handler: async (args) => {
        const container = containerOf(args);
        const query: Array<[string, string]> = [
          ["restype", "container"],
          ["comp", "list"],
        ];
        const prefix = optStr(args, "prefix", { max: 1024 });
        const max = optPosInt(args, "max_results");
        if (max !== undefined && max > 5000) throw new Error("`max_results` must be at most 5000");
        const marker = optStr(args, "marker", { max: 2048 });
        if (prefix) query.push(["prefix", prefix]);
        if (max) query.push(["maxresults", String(max)]);
        if (marker) query.push(["marker", marker]);
        const r = await blobApi("GET", `${base}/${container}`, { query });
        const blobs = xmlBlocks(r.text, "Blob")
          .map((b) => ({
            blob: xmlText(b, "Name") ?? "",
            size: Number(xmlText(b, "Content-Length") ?? 0),
            last_modified: xmlText(b, "Last-Modified") ?? null,
            etag: xmlText(b, "Etag") ?? null,
          }))
          .filter((b) => b.blob && !isBackupName(b.blob));
        return { blobs, next_marker: xmlText(r.text, "NextMarker") || null };
      },
    },
    {
      name: "put_blob",
      description: `Write a block blob. If one exists it is first copied to ${BACKUP_PREFIX}<uuid> in the same container and the write is conditional on its ETag, so rollback restores exactly what was overwritten (or deletes the new blob). Needs Storage Blob Data Contributor.`,
      effect: "reversible",
      permission: "azure:blob:write",
      compensation: { tool: "restore_blob", argument_map: restoreMap },
      properties: { container: containerProp, blob: blobProp, ...contentProps },
      required: ["container", "blob", "content"],
      handler: async (args) => {
        const container = containerOf(args);
        const blob = objectName(args, "blob");
        const body = contentBytes(args);
        const type = mediaType(args);
        const { existed, etag, backup_blob } = await backUp(container, blob);
        try {
          const r = await blobApi("PUT", blobUrl(container, blob), {
            body,
            headers: {
              "x-ms-blob-type": "BlockBlob",
              "Content-Type": type,
              ...(etag ? { "If-Match": etag } : { "If-None-Match": "*" }),
            },
          });
          return { container, blob, existed, backup_blob, etag: r.headers.get("etag") };
        } catch (e) {
          if (e instanceof EffectUncertainError && backup_blob) {
            throw new EffectUncertainError(`${e.message}; the previous version is saved at ${backup_blob}`);
          }
          if (!(e instanceof EffectUncertainError)) await dropBackup(container, backup_blob);
          throw e;
        }
      },
    },
    {
      name: "delete_blob",
      description: `Delete a blob. It is first copied to ${BACKUP_PREFIX}<uuid> and the delete is conditional on its ETag, so rollback restores what was deleted. Needs Storage Blob Data Contributor.`,
      effect: "reversible",
      permission: "azure:blob:write",
      compensation: { tool: "restore_blob", argument_map: restoreMap },
      properties: { container: containerProp, blob: blobProp },
      required: ["container", "blob"],
      handler: async (args) => {
        const container = containerOf(args);
        const blob = objectName(args, "blob");
        const { existed, etag, backup_blob } = await backUp(container, blob);
        if (!existed) return { container, blob, existed, backup_blob };
        try {
          await blobApi("DELETE", blobUrl(container, blob), { headers: { "If-Match": etag! } });
        } catch (e) {
          if (e instanceof EffectUncertainError) {
            throw new EffectUncertainError(`${e.message}; the previous version is saved at ${backup_blob}`);
          }
          await dropBackup(container, backup_blob);
          throw e;
        }
        return { container, blob, existed, backup_blob };
      },
    },
    {
      name: "restore_blob",
      description:
        "Undo put_blob or delete_blob: copy the saved backup back over the blob, or delete the blob when there was no previous one (backup_blob null). Safe to repeat. The backup blob is kept.",
      effect: "idempotent",
      permission: "azure:blob:write",
      properties: {
        container: containerProp,
        blob: blobProp,
        backup_blob: { type: ["string", "null"], description: "Backup blob name, or null if the blob did not exist" },
      },
      required: ["container", "blob", "backup_blob"],
      handler: async (args) => {
        const container = containerOf(args);
        const blob = objectName(args, "blob");
        const backup = backupName(args, "backup_blob");
        if (backup === null) {
          await blobApi("DELETE", blobUrl(container, blob), { tolerate: [404] });
          return { container, blob, restored: true, action: "deleted" };
        }
        try {
          await copy(container, backup, blob);
        } catch (e) {
          if (e instanceof HttpError && e.status === 404) throw new Error(`backup ${backup} was not found`);
          throw e;
        }
        return { container, blob, restored: true, action: "restored" };
      },
    },
  ]);
}
