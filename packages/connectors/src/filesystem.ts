import { randomUUID } from "node:crypto";
import { promises as fsp, type Stats } from "node:fs";
import path from "node:path";
import { defineConnector, optStr, str, type Connector } from "./common.js";

export interface FilesystemConfig {
  /** Every path the tools accept is relative to this directory and cannot leave it. */
  root: string;
  /** Where previous contents are kept. Default `<root>/.reversi-backups`. Created on demand. */
  backupDir?: string;
}

const MAX_READ_BYTES = 5 * 1024 * 1024;
const BACKUP_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface BackupMeta {
  path: string;
  existed: boolean;
  restored: boolean;
}

function code(e: unknown): string | undefined {
  return typeof e === "object" && e !== null && "code" in e ? String((e as { code: unknown }).code) : undefined;
}

async function lstatOrNull(p: string): Promise<Stats | null> {
  try {
    return await fsp.lstat(p);
  } catch (e) {
    if (code(e) === "ENOENT" || code(e) === "ENOTDIR") return null;
    throw e;
  }
}

export function createFilesystemConnector(cfg: FilesystemConfig): Connector {
  if (typeof cfg.root !== "string" || !cfg.root) throw new Error("filesystem connector needs a `root` directory");
  const rootAbs = path.resolve(cfg.root);
  const backupAbs = path.resolve(cfg.backupDir ?? path.join(rootAbs, ".reversi-backups"));

  const inside = (base: string, p: string) => p === base || p.startsWith(base + path.sep);

  async function realRoot(): Promise<string> {
    try {
      return await fsp.realpath(rootAbs);
    } catch {
      throw new Error("the filesystem root does not exist");
    }
  }

  /** Lexical checks only; see {@link guard} for the symlink check. */
  function resolveRel(raw: unknown, key: string, allowRoot = false): { abs: string; rel: string } {
    if (typeof raw !== "string" || raw.length === 0) throw new Error(`\`${key}\` must be a non-empty relative path`);
    if (raw.includes("\0")) throw new Error(`\`${key}\` contains a NUL byte`);
    if (raw.startsWith("/") || raw.startsWith("\\") || /^[A-Za-z]:/.test(raw) || path.isAbsolute(raw)) {
      throw new Error(`\`${key}\` must be relative to the root, not absolute`);
    }
    const segs = raw.split(/[\\/]+/);
    if (segs.includes("..")) throw new Error(`\`${key}\` must not contain \`..\``);
    const clean = segs.filter((s) => s !== "" && s !== ".");
    if (clean.length === 0 && !allowRoot) throw new Error(`\`${key}\` must name something inside the root`);
    const abs = path.join(rootAbs, ...clean);
    if (inside(backupAbs, abs) && backupAbs !== rootAbs) {
      throw new Error(`\`${key}\` points into the backup directory, which is reserved`);
    }
    return { abs, rel: clean.join("/") };
  }

  /** Reject anything whose real location (parent, and the target when it is followed) is outside the root. */
  async function guard(abs: string, key: string, followTarget: boolean): Promise<void> {
    const root = await realRoot();
    if (abs === rootAbs) return;
    let probe = path.dirname(abs);
    for (;;) {
      try {
        const real = await fsp.realpath(probe);
        if (!inside(root, real)) throw new Error(`\`${key}\` resolves outside the root through a symlink`);
        break;
      } catch (e) {
        if (code(e) !== "ENOENT" && code(e) !== "ENOTDIR") throw e;
        const up = path.dirname(probe);
        if (up === probe) throw new Error(`\`${key}\` cannot be resolved`);
        probe = up;
      }
    }
    if (followTarget) {
      const st = await lstatOrNull(abs);
      if (st?.isSymbolicLink()) {
        let real: string;
        try {
          real = await fsp.realpath(abs);
        } catch {
          throw new Error(`\`${key}\` is a dangling symlink`);
        }
        if (!inside(root, real)) throw new Error(`\`${key}\` is a symlink that points outside the root`);
      }
    }
  }

  async function target(raw: unknown, key: string, follow: boolean, allowRoot = false) {
    const r = resolveRel(raw, key, allowRoot);
    await guard(r.abs, key, follow);
    return r;
  }

  async function newBackup(meta: Omit<BackupMeta, "restored">, source?: string): Promise<string> {
    const id = randomUUID();
    const dir = path.join(backupAbs, id);
    await fsp.mkdir(dir, { recursive: true });
    if (source) await fsp.copyFile(source, path.join(dir, "content"));
    const full: BackupMeta = { ...meta, restored: false };
    await fsp.writeFile(path.join(dir, "meta.json"), JSON.stringify(full));
    return id;
  }

  async function readBackup(id: string, rel: string): Promise<{ dir: string; meta: BackupMeta }> {
    if (!BACKUP_ID.test(id)) throw new Error("`backup_id` is not a valid backup id");
    const dir = path.join(backupAbs, id);
    let meta: BackupMeta;
    try {
      meta = JSON.parse(await fsp.readFile(path.join(dir, "meta.json"), "utf8")) as BackupMeta;
    } catch (e) {
      if (code(e) === "ENOENT") throw new Error(`backup \`${id}\` not found`);
      throw new Error(`backup \`${id}\` is unreadable`);
    }
    if (meta.path !== rel) throw new Error(`backup \`${id}\` belongs to a different path`);
    return { dir, meta };
  }

  const pathProp = { type: "string", description: "Path relative to the connector root" };

  return defineConnector("fs", [
    {
      name: "read_file",
      description: "Read a UTF-8 text file under the root.",
      effect: "read_only",
      permission: "fs:read",
      properties: { path: pathProp },
      required: ["path"],
      handler: async (args) => {
        const { abs, rel } = await target(args.path, "path", true);
        const st = await lstatOrNull(abs);
        if (!st) throw new Error(`file not found: ${rel}`);
        const real = await fsp.stat(abs);
        if (!real.isFile()) throw new Error(`not a regular file: ${rel}`);
        if (real.size > MAX_READ_BYTES) throw new Error(`file is larger than ${MAX_READ_BYTES} bytes: ${rel}`);
        return { path: rel, content: await fsp.readFile(abs, "utf8"), size: real.size };
      },
    },
    {
      name: "list_dir",
      description: "List a directory under the root (default: the root itself).",
      effect: "read_only",
      permission: "fs:read",
      properties: { path: pathProp },
      handler: async (args) => {
        const { abs, rel } = await target(optStr(args, "path") ?? ".", "path", true, true);
        const st = await lstatOrNull(abs);
        if (!st) throw new Error(`directory not found: ${rel || "."}`);
        if (!(await fsp.stat(abs)).isDirectory()) throw new Error(`not a directory: ${rel}`);
        const entries = await fsp.readdir(abs, { withFileTypes: true });
        const out = entries
          .filter((d) => path.join(abs, d.name) !== backupAbs)
          .map((d) => ({
            name: d.name,
            type: d.isSymbolicLink() ? "symlink" : d.isDirectory() ? "dir" : d.isFile() ? "file" : "other",
          }))
          .sort((a, b) => a.name.localeCompare(b.name));
        return { path: rel, entries: out };
      },
    },
    {
      name: "write_file",
      description: "Create or overwrite a text file. The previous content is saved so rollback can restore it.",
      effect: "reversible",
      permission: "fs:write",
      compensation: {
        tool: "restore_file",
        argument_map: { path: "$args.path", backup_id: "$result.backup_id" },
      },
      properties: { path: pathProp, content: { type: "string" } },
      required: ["path", "content"],
      handler: async (args) => {
        const { abs, rel } = await target(args.path, "path", true);
        if (typeof args.content !== "string") throw new Error("`content` must be a string");
        const st = await lstatOrNull(abs);
        if (st && !(await fsp.stat(abs)).isFile()) throw new Error(`not a regular file: ${rel}`);
        const backup_id = await newBackup({ path: rel, existed: st !== null }, st ? abs : undefined);
        await fsp.writeFile(abs, args.content, "utf8");
        return { path: rel, backup_id, existed: st !== null };
      },
    },
    {
      name: "delete_file",
      description: "Delete a file. It is moved into the backup directory so rollback can restore it.",
      effect: "reversible",
      permission: "fs:write",
      compensation: {
        tool: "restore_file",
        argument_map: { path: "$args.path", backup_id: "$result.backup_id" },
      },
      properties: { path: pathProp },
      required: ["path"],
      handler: async (args) => {
        const { abs, rel } = await target(args.path, "path", false);
        const st = await lstatOrNull(abs);
        if (!st) throw new Error(`file not found: ${rel}`);
        if (!st.isFile()) throw new Error(`not a regular file: ${rel}`);
        const backup_id = await newBackup({ path: rel, existed: true }, abs);
        await fsp.unlink(abs);
        return { path: rel, backup_id };
      },
    },
    {
      name: "restore_file",
      description:
        "Undo write_file or delete_file from a backup: restores the prior content, or deletes the file if it did not exist. Safe to repeat.",
      effect: "idempotent",
      permission: "fs:write",
      properties: { path: pathProp, backup_id: { type: "string" } },
      required: ["path", "backup_id"],
      handler: async (args) => {
        const { abs, rel } = await target(args.path, "path", false);
        const { dir, meta } = await readBackup(str(args, "backup_id", { max: 64 }), rel);
        if (meta.restored) return { path: rel, restored: false, already_restored: true };
        const st = await lstatOrNull(abs);
        let action: "restored" | "deleted";
        if (meta.existed) {
          if (st && !st.isFile() && !st.isSymbolicLink()) throw new Error(`cannot restore over a non-file: ${rel}`);
          if (st?.isSymbolicLink()) await fsp.unlink(abs);
          await fsp.copyFile(path.join(dir, "content"), abs);
          action = "restored";
        } else {
          if (st && !st.isFile() && !st.isSymbolicLink()) throw new Error(`cannot delete a non-file: ${rel}`);
          if (st) await fsp.unlink(abs);
          action = "deleted";
        }
        await fsp.writeFile(path.join(dir, "meta.json"), JSON.stringify({ ...meta, restored: true }));
        return { path: rel, restored: true, action };
      },
    },
    {
      name: "make_dir",
      description: "Create a directory whose parent exists. Fails if it already exists.",
      effect: "reversible",
      permission: "fs:write",
      compensation: { tool: "remove_dir", argument_map: { path: "$args.path" } },
      properties: { path: pathProp },
      required: ["path"],
      handler: async (args) => {
        const { abs, rel } = await target(args.path, "path", false);
        try {
          await fsp.mkdir(abs);
        } catch (e) {
          if (code(e) === "EEXIST") throw new Error(`already exists: ${rel}`);
          if (code(e) === "ENOENT") throw new Error(`parent directory does not exist: ${rel}`);
          throw e;
        }
        return { path: rel };
      },
    },
    {
      name: "remove_dir",
      description:
        "Remove an EMPTY directory. A missing directory counts as success. Used to undo make_dir; as a forward tool it only ever removes an empty directory, so no data is lost.",
      effect: "idempotent",
      permission: "fs:write",
      properties: { path: pathProp },
      required: ["path"],
      handler: async (args) => {
        const { abs, rel } = await target(args.path, "path", false);
        const st = await lstatOrNull(abs);
        if (!st) return { path: rel, removed: false };
        if (!st.isDirectory()) throw new Error(`not a directory: ${rel}`);
        try {
          await fsp.rmdir(abs);
        } catch (e) {
          if (code(e) === "ENOTEMPTY" || code(e) === "EEXIST") throw new Error(`directory is not empty: ${rel}`);
          throw e;
        }
        return { path: rel, removed: true };
      },
    },
    {
      name: "move_file",
      description: "Move a file to a new path inside the root. Fails if the destination exists.",
      effect: "reversible",
      permission: "fs:write",
      compensation: { tool: "unmove_file", argument_map: { from: "$args.from", to: "$args.to" } },
      properties: { from: pathProp, to: pathProp },
      required: ["from", "to"],
      handler: async (args) => {
        const src = await target(args.from, "from", false);
        const dst = await target(args.to, "to", false);
        const st = await lstatOrNull(src.abs);
        if (!st) throw new Error(`file not found: ${src.rel}`);
        if (!st.isFile()) throw new Error(`not a regular file: ${src.rel}`);
        if (await lstatOrNull(dst.abs)) throw new Error(`destination already exists: ${dst.rel}`);
        await fsp.rename(src.abs, dst.abs);
        return { from: src.rel, to: dst.rel };
      },
    },
    {
      name: "unmove_file",
      description:
        "Undo move_file: move the file at `to` back to `from`. If it is already back, nothing happens. Safe to repeat.",
      effect: "idempotent",
      permission: "fs:write",
      properties: { from: pathProp, to: pathProp },
      required: ["from", "to"],
      handler: async (args) => {
        const src = await target(args.from, "from", false);
        const dst = await target(args.to, "to", false);
        const moved = await lstatOrNull(dst.abs);
        const original = await lstatOrNull(src.abs);
        if (!moved) {
          if (original) return { from: src.rel, to: dst.rel, moved: false };
          throw new Error(`neither ${src.rel} nor ${dst.rel} exists`);
        }
        if (original) throw new Error(`cannot move back: ${src.rel} exists again`);
        await fsp.rename(dst.abs, src.abs);
        return { from: src.rel, to: dst.rel, moved: true };
      },
    },
  ]);
}
