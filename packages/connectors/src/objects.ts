import { randomUUID } from "node:crypto";
import { BACKUP_PREFIX, assertNotBackupKey, str } from "./common.js";

/** Shared argument handling for the object-store connectors (S3, Cloud Storage, Blob Storage). */

export const MAX_OBJECT_BYTES = 5 * 1024 * 1024;
const BACKUP_KEY = new RegExp(`^${BACKUP_PREFIX.replace(/[.\\/]/g, "\\$&")}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`);

type Args = Record<string, unknown>;

/** An object name: 1-1024 bytes, no control characters, and not inside the reserved backup prefix. */
export function objectName(args: Args, key: string, opts: { allowBackup?: boolean } = {}): string {
  const v = str(args, key, { max: 1024 });
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw new Error(`\`${key}\` contains a control character`);
  if (Buffer.byteLength(v, "utf8") > 1024) throw new Error(`\`${key}\` is too long`);
  if (!opts.allowBackup) assertNotBackupKey(v, key);
  return v;
}

/** The backup object name returned by put/delete, or null when the object did not exist before. */
export function backupName(args: Args, key: string): string | null {
  const v = args[key];
  if (v === null) return null;
  if (typeof v !== "string" || !BACKUP_KEY.test(v)) throw new Error(`\`${key}\` is not a backup object name`);
  return v;
}

export function newBackupName(): string {
  return BACKUP_PREFIX + randomUUID();
}

/** `content` as bytes: UTF-8 text by default, or base64 with `encoding: "base64"`. */
export function contentBytes(args: Args): Uint8Array {
  const content = args.content;
  if (typeof content !== "string") throw new Error("`content` must be a string");
  const enc = args.encoding ?? "utf8";
  if (enc !== "utf8" && enc !== "base64") throw new Error("`encoding` must be utf8 or base64");
  let bytes: Uint8Array;
  if (enc === "base64") {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(content) || content.length % 4 !== 0) throw new Error("`content` is not valid base64");
    bytes = Buffer.from(content, "base64");
  } else {
    bytes = Buffer.from(content, "utf8");
  }
  if (bytes.byteLength > MAX_OBJECT_BYTES) throw new Error(`\`content\` is larger than ${MAX_OBJECT_BYTES} bytes`);
  return bytes;
}

/** Bytes as UTF-8 text when they are valid UTF-8, otherwise base64. */
export function contentOut(bytes: Uint8Array): { content: string; encoding: "utf8" | "base64" } {
  try {
    return { content: new TextDecoder("utf-8", { fatal: true }).decode(bytes), encoding: "utf8" };
  } catch {
    return { content: Buffer.from(bytes).toString("base64"), encoding: "base64" };
  }
}

export function maxBytes(args: Args): number {
  const v = args.max_bytes;
  if (v === undefined) return MAX_OBJECT_BYTES;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 1 || v > MAX_OBJECT_BYTES) {
    throw new Error(`\`max_bytes\` must be an integer from 1 to ${MAX_OBJECT_BYTES}`);
  }
  return v;
}

export const contentProps = {
  content: { type: "string" },
  encoding: { type: "string", enum: ["utf8", "base64"], description: "How `content` is encoded; default utf8" },
  content_type: { type: "string", description: "Media type; default application/octet-stream" },
};

const MEDIA_TYPE = /^[A-Za-z0-9!#$&^_.+-]{1,127}\/[A-Za-z0-9!#$&^_.+-]{1,127}(;\s?[A-Za-z0-9=._-]+)*$/;
export function mediaType(args: Args): string {
  const v = args.content_type;
  if (v === undefined) return "application/octet-stream";
  if (typeof v !== "string" || !MEDIA_TYPE.test(v)) throw new Error("`content_type` is not a valid media type");
  return v;
}

export function isBackupName(name: string): boolean {
  return name.startsWith(BACKUP_PREFIX);
}
