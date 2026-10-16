import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect } from "vitest";
import { createFilesystemConnector } from "../../src/index.js";
import type { Backend, Scenario, Subject } from "../certification.js";

const dirs: string[] = [];
export function cleanup(): void {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
}

const BACKUP = "00000000-0000-4000-8000-0000000000aa";

function tree(root: string, rel = ""): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const name of readdirSync(path.join(root, rel)).sort()) {
    const r = rel ? `${rel}/${name}` : name;
    if (r === ".reversi-backups") continue;
    if (statSync(path.join(root, r)).isDirectory()) {
      out[r + "/"] = null;
      Object.assign(out, tree(root, r));
    } else out[r] = readFileSync(path.join(root, r), "utf8");
  }
  return out;
}

export function fakeFs() {
  const root = mkdtempSync(path.join(tmpdir(), "rv-cert-fs-"));
  dirs.push(root);
  const p = (rel: string) => path.join(root, rel);
  const b: Backend & { root: string; p: (rel: string) => string } = {
    fault: null,
    calls: [],
    supportsFaults: false,
    isMutating: () => false,
    state: () => tree(root),
    root,
    p,
  };
  return b;
}
type FakeFs = ReturnType<typeof fakeFs>;
const fx = (b: Backend) => b as FakeFs;
const file = (b: Backend, rel: string, content: string) => {
  mkdirSync(path.dirname(fx(b).p(rel)), { recursive: true });
  writeFileSync(fx(b).p(rel), content);
};
const seedBackup = (b: Backend, rel: string, content: string | null) => {
  const dir = path.join(fx(b).root, ".reversi-backups", BACKUP);
  mkdirSync(dir, { recursive: true });
  if (content !== null) writeFileSync(path.join(dir, "content"), content);
  writeFileSync(path.join(dir, "meta.json"), JSON.stringify({ path: rel, existed: content !== null, restored: false }));
};
/** Swap a file for a directory (and back) so the undo has something it must refuse to overwrite. */
const blockWithDir = (rel: string) => (b: Backend) => {
  rmSync(fx(b).p(rel), { force: true });
  mkdirSync(fx(b).p(rel));
};
const unblock = (rel: string) => (b: Backend) => rmdirSync(fx(b).p(rel));

export const subject: Subject = {
  name: "fs",
  secrets: [],
  make: () => {
    const backend = fakeFs();
    return { backend, connector: createFilesystemConnector({ root: backend.root }) };
  },
  notApplicable: {
    retry: "the local filesystem has no network transport that can fail transiently; errors are definite",
    permission_denial: "access control is the operating system's; the connector confines paths to its root instead (covered in filesystem.test.ts)",
    timeout: "local file operations have no network wait to time out",
    redaction: "the connector holds no credential",
  },
};

export const scenarios: Scenario[] = [
  { tool: "read_file", args: { path: "a.txt" }, setup: (b) => file(b, "a.txt", "one"), fail: (b) => unlinkSync(fx(b).p("a.txt")), expect: (r) => expect(r).toMatchObject({ content: "one", size: 3 }) },
  {
    tool: "list_dir",
    args: { path: "d" },
    setup: (b) => file(b, "d/a.txt", "one"),
    fail: (b) => (rmSync(fx(b).p("d"), { recursive: true }), writeFileSync(fx(b).p("d"), "now a file")),
    expect: (r) => expect(r).toMatchObject({ entries: [{ name: "a.txt", type: "file" }] }),
  },
  {
    tool: "write_file",
    args: { path: "new.txt", content: "hello" },
    fail: (b) => mkdirSync(fx(b).p("new.txt")),
    breakCompensation: blockWithDir("new.txt"),
    healCompensation: unblock("new.txt"),
  },
  {
    tool: "write_file",
    args: { path: "a.txt", content: "two" },
    setup: (b) => file(b, "a.txt", "one"),
    fail: (b) => (unlinkSync(fx(b).p("a.txt")), mkdirSync(fx(b).p("a.txt"))),
    breakCompensation: blockWithDir("a.txt"),
    healCompensation: unblock("a.txt"),
  },
  {
    tool: "delete_file",
    args: { path: "a.txt" },
    setup: (b) => file(b, "a.txt", "one"),
    fail: (b) => unlinkSync(fx(b).p("a.txt")),
    breakCompensation: (b) => mkdirSync(fx(b).p("a.txt")),
    healCompensation: unblock("a.txt"),
  },
  {
    tool: "restore_file",
    args: { path: "a.txt", backup_id: BACKUP },
    setup: (b) => (file(b, "a.txt", "two"), seedBackup(b, "a.txt", "one")),
    fail: (b) => rmSync(path.join(fx(b).root, ".reversi-backups"), { recursive: true, force: true }),
    expect: (_r, b) => expect(readFileSync(fx(b).p("a.txt"), "utf8")).toBe("one"),
  },
  {
    tool: "make_dir",
    args: { path: "d" },
    fail: (b) => mkdirSync(fx(b).p("d")),
    breakCompensation: (b) => writeFileSync(fx(b).p("d/inside.txt"), "x"),
    healCompensation: (b) => unlinkSync(fx(b).p("d/inside.txt")),
  },
  { tool: "remove_dir", args: { path: "d" }, setup: (b) => mkdirSync(fx(b).p("d")), fail: (b) => writeFileSync(fx(b).p("d/inside.txt"), "x") },
  {
    tool: "move_file",
    args: { from: "a.txt", to: "b.txt" },
    setup: (b) => file(b, "a.txt", "one"),
    fail: (b) => unlinkSync(fx(b).p("a.txt")),
    breakCompensation: (b) => writeFileSync(fx(b).p("a.txt"), "intruder"),
    healCompensation: (b) => unlinkSync(fx(b).p("a.txt")),
  },
  { tool: "unmove_file", args: { from: "a.txt", to: "b.txt" }, setup: (b) => file(b, "b.txt", "one"), fail: (b) => unlinkSync(fx(b).p("b.txt")) },
];
