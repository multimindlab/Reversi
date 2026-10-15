import { mkdtempSync, mkdirSync, readFileSync, existsSync, symlinkSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Registry } from "@multimindlab/reversi";
import { beforeEach, describe, expect, it } from "vitest";
import { compensatorFor, createFilesystemConnector, type Connector } from "../src/index.js";
import { engine } from "./helpers.js";

let root: string;
let outside: string;
let fsc: Connector;
const t = (name: string, args: Record<string, unknown>, ctx = {}) => fsc.tools[`fs.${name}`]!(args, ctx);

beforeEach(() => {
  const base = mkdtempSync(path.join(tmpdir(), "rv-fs-"));
  root = path.join(base, "root");
  outside = path.join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  fsc = createFilesystemConnector({ root });
});

describe("filesystem manifests", () => {
  it("validate, with compensation tools registered", () => {
    const reg = Registry.from(fsc.manifests);
    expect(reg.size).toBe(9);
    expect(reg.get("fs.write_file")?.compensation?.tool).toBe("fs.restore_file");
    expect(reg.get("fs.restore_file")?.effect).toBe("idempotent");
    expect(Object.keys(fsc.tools).sort()).toEqual(reg.list().map((m) => m.tool).sort());
    expect(Object.keys(fsc.inputSchemas).sort()).toEqual(Object.keys(fsc.tools).sort());
  });
});

describe("filesystem tools", () => {
  it("writes, reads and lists", async () => {
    const w = (await t("write_file", { path: "a.txt", content: "one" })) as Record<string, unknown>;
    expect(w).toMatchObject({ path: "a.txt", existed: false });
    expect(await t("read_file", { path: "a.txt" })).toMatchObject({ content: "one", size: 3 });
    const list = (await t("list_dir", {})) as { entries: Array<{ name: string }> };
    expect(list.entries.map((e) => e.name)).toEqual(["a.txt"]); // backups are hidden
  });

  it("fails clearly on bad input", async () => {
    await expect(t("read_file", { path: "missing.txt" })).rejects.toThrow("file not found");
    await expect(t("write_file", { path: "x" })).rejects.toThrow("`content` must be a string");
    await expect(t("write_file", { path: "x", content: "y", extra: 1 })).rejects.toThrow("unknown argument `extra`");
    await expect(t("make_dir", { path: "d" })).resolves.toBeTruthy();
    await expect(t("make_dir", { path: "d" })).rejects.toThrow("already exists");
    await expect(t("make_dir", { path: "p/q" })).rejects.toThrow("parent directory does not exist");
    await expect(t("restore_file", { path: "a", backup_id: "nope" })).rejects.toThrow("not a valid backup id");
    await expect(
      t("restore_file", { path: "a", backup_id: "00000000-0000-4000-8000-000000000000" }),
    ).rejects.toThrow("not found");
  });

  it("denies paths that escape the root", async () => {
    writeFileSync(path.join(outside, "secret.txt"), "s3cret");
    for (const p of ["../outside/secret.txt", "a/../../outside/secret.txt", "/etc/passwd", path.join(outside, "secret.txt")]) {
      await expect(t("read_file", { path: p })).rejects.toThrow(/\.\.|absolute/);
      await expect(t("write_file", { path: p, content: "x" })).rejects.toThrow(/\.\.|absolute/);
    }
    expect(readFileSync(path.join(outside, "secret.txt"), "utf8")).toBe("s3cret");
  });

  it("denies symlink escapes through a directory and through a file", async () => {
    writeFileSync(path.join(outside, "secret.txt"), "s3cret");
    symlinkSync(outside, path.join(root, "linkdir"));
    symlinkSync(path.join(outside, "secret.txt"), path.join(root, "linkfile"));
    await expect(t("read_file", { path: "linkdir/secret.txt" })).rejects.toThrow("outside the root");
    await expect(t("write_file", { path: "linkdir/new.txt", content: "x" })).rejects.toThrow("outside the root");
    await expect(t("read_file", { path: "linkfile" })).rejects.toThrow("outside the root");
    await expect(t("write_file", { path: "linkfile", content: "x" })).rejects.toThrow("outside the root");
    await expect(t("make_dir", { path: "linkdir/sub/deeper" })).rejects.toThrow("outside the root");
    expect(existsSync(path.join(outside, "new.txt"))).toBe(false);
    expect(readFileSync(path.join(outside, "secret.txt"), "utf8")).toBe("s3cret");
  });

  it("keeps the backup directory off limits", async () => {
    await t("write_file", { path: "a.txt", content: "one" });
    await expect(t("read_file", { path: ".reversi-backups" })).rejects.toThrow("reserved");
    await expect(t("write_file", { path: ".reversi-backups/x/meta.json", content: "{}" })).rejects.toThrow("reserved");
  });

  it("restore_file brings back overwritten content and is safe to repeat", async () => {
    await t("write_file", { path: "a.txt", content: "v1" });
    const w2 = (await t("write_file", { path: "a.txt", content: "v2" })) as { backup_id: string; existed: boolean };
    expect(w2.existed).toBe(true);
    await t("restore_file", { path: "a.txt", backup_id: w2.backup_id });
    expect(readFileSync(path.join(root, "a.txt"), "utf8")).toBe("v1");
    writeFileSync(path.join(root, "a.txt"), "later edit");
    const again = await t("restore_file", { path: "a.txt", backup_id: w2.backup_id });
    expect(again).toMatchObject({ already_restored: true });
    expect(readFileSync(path.join(root, "a.txt"), "utf8")).toBe("later edit");
  });

  it("restore_file deletes a file that did not exist, and tolerates it being gone", async () => {
    const w = (await t("write_file", { path: "n.txt", content: "new" })) as { backup_id: string };
    await t("restore_file", { path: "n.txt", backup_id: w.backup_id });
    expect(existsSync(path.join(root, "n.txt"))).toBe(false);
    await expect(t("restore_file", { path: "n.txt", backup_id: w.backup_id })).resolves.toBeTruthy();
  });

  it("refuses a backup that belongs to another path", async () => {
    const w = (await t("write_file", { path: "n.txt", content: "new" })) as { backup_id: string };
    await expect(t("restore_file", { path: "other.txt", backup_id: w.backup_id })).rejects.toThrow("different path");
  });

  it("delete_file moves the file into backups and restore_file returns it", async () => {
    writeFileSync(path.join(root, "d.txt"), "keep me");
    const d = (await t("delete_file", { path: "d.txt" })) as { backup_id: string };
    expect(existsSync(path.join(root, "d.txt"))).toBe(false);
    await t("restore_file", { path: "d.txt", backup_id: d.backup_id });
    expect(readFileSync(path.join(root, "d.txt"), "utf8")).toBe("keep me");
    await expect(t("delete_file", { path: "gone.txt" })).rejects.toThrow("file not found");
  });

  it("remove_dir only removes empty directories and is idempotent", async () => {
    mkdirSync(path.join(root, "full"));
    writeFileSync(path.join(root, "full", "f"), "x");
    await expect(t("remove_dir", { path: "full" })).rejects.toThrow("not empty");
    expect(existsSync(path.join(root, "full", "f"))).toBe(true);
    mkdirSync(path.join(root, "empty"));
    expect(await t("remove_dir", { path: "empty" })).toMatchObject({ removed: true });
    expect(await t("remove_dir", { path: "empty" })).toMatchObject({ removed: false });
    await expect(t("remove_dir", { path: "." })).rejects.toThrow("inside the root");
  });

  it("move_file refuses to overwrite, and unmove_file is idempotent", async () => {
    writeFileSync(path.join(root, "a"), "A");
    writeFileSync(path.join(root, "b"), "B");
    await expect(t("move_file", { from: "a", to: "b" })).rejects.toThrow("destination already exists");
    await t("move_file", { from: "a", to: "c" });
    expect(existsSync(path.join(root, "a"))).toBe(false);
    await t("unmove_file", { from: "a", to: "c" });
    expect(readFileSync(path.join(root, "a"), "utf8")).toBe("A");
    expect(await t("unmove_file", { from: "a", to: "c" })).toMatchObject({ moved: false });
    await expect(t("unmove_file", { from: "x", to: "y" })).rejects.toThrow("neither");
  });

  it("uses a custom backup directory outside the root", async () => {
    const backupDir = path.join(path.dirname(root), "bk");
    const c = createFilesystemConnector({ root, backupDir });
    await c.tools["fs.write_file"]!({ path: "a.txt", content: "x" }, {});
    expect(readdirSync(backupDir)).toHaveLength(1);
    expect(existsSync(path.join(root, ".reversi-backups"))).toBe(false);
  });
});

describe("filesystem end to end", () => {
  it("rolls back writes, overwrites, deletes, moves and mkdirs through a real engine", async () => {
    writeFileSync(path.join(root, "keep.txt"), "original");
    writeFileSync(path.join(root, "gone.txt"), "precious");
    writeFileSync(path.join(root, "mv.txt"), "movable");
    const { call, run } = engine([fsc]);

    await call("fs.write_file", { path: "keep.txt", content: "changed" });
    await call("fs.write_file", { path: "fresh.txt", content: "fresh" });
    await call("fs.delete_file", { path: "gone.txt" });
    await call("fs.make_dir", { path: "newdir" });
    await call("fs.move_file", { from: "mv.txt", to: "newdir/mv.txt" });
    await call("fs.read_file", { path: "fresh.txt" });

    const report = await run.rollback({ compensate: compensatorFor([fsc]) });
    expect(report.complete).toBe(true);
    expect(report.compensated).toHaveLength(5);
    expect(readFileSync(path.join(root, "keep.txt"), "utf8")).toBe("original");
    expect(readFileSync(path.join(root, "gone.txt"), "utf8")).toBe("precious");
    expect(readFileSync(path.join(root, "mv.txt"), "utf8")).toBe("movable");
    expect(existsSync(path.join(root, "fresh.txt"))).toBe(false);
    expect(existsSync(path.join(root, "newdir"))).toBe(false);

    const again = await run.rollback({ compensate: compensatorFor([fsc]) });
    expect(again.complete).toBe(true);
  });

  it("compensating twice with the same call is a no-op the second time", async () => {
    const { call, run } = engine([fsc]);
    const r = await call("fs.write_file", { path: "z.txt", content: "z" });
    const comp = compensatorFor([fsc]);
    const handle = run.state().steps[r.status === "executed" ? r.step : 0]!.partial_handle;
    const result = r.status === "executed" ? (r.result as { backup_id: string }) : { backup_id: "" };
    const callArgs = { run_id: run.run_id, step: 0, tool: "fs.restore_file", original_tool: "fs.write_file", idempotency_key: "k", args: { ...handle, backup_id: result.backup_id } };
    await comp(callArgs);
    await comp(callArgs);
    expect(existsSync(path.join(root, "z.txt"))).toBe(false);
  });

  it("reports a compensation failure and leaves the run incomplete", async () => {
    const { call, run } = engine([fsc]);
    await call("fs.make_dir", { path: "d" });
    writeFileSync(path.join(root, "d", "intruder"), "x"); // someone put a file in after the fact
    const report = await run.rollback({ compensate: compensatorFor([fsc]) });
    expect(report.complete).toBe(false);
    expect(report.failed[0]?.error).toContain("not empty");
    expect(existsSync(path.join(root, "d", "intruder"))).toBe(true);
  });

  it("the compensator rejects an unknown tool", async () => {
    await expect(
      compensatorFor([fsc])({ run_id: "r", step: 0, tool: "fs.nope", original_tool: "x", args: {}, idempotency_key: "k" }),
    ).rejects.toThrow("no connector provides");
  });
});
