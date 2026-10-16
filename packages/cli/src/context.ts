/** Shared plumbing for CLI commands: option handling, project config defaults, opening the engine. */
import { existsSync, readFileSync } from "node:fs";
import { extname } from "node:path";
import type { Command } from "commander";
import { parse as parseYaml } from "yaml";
import {
  dataOptionsFromEnv,
  findProjectConfig,
  loadProjectConfig,
  openEngine,
  storeKindFrom,
  type DataOptions,
  type EngineConfig,
  type EngineHandle,
  type ProjectConfig,
} from "@multimindlab/reversi";

export interface IO {
  out: (s: string) => void;
  err: (s: string) => void;
}

/** An error whose message is for the user, not a stack trace. */
export class Fail extends Error {}

export interface StoreFlags {
  data?: string;
  store?: string;
  databaseUrl?: string;
  config?: string;
}
export type EngineFlags = StoreFlags & { manifests?: string; policy?: string };

export interface Ctx {
  io: IO;
  /** Exit code the command wants (0 ok, 1 error, 2 incomplete). */
  code: number;
  program: Command;
  project(flags?: StoreFlags): ProjectConfig | undefined;
  storeOpts(c: Command): Command;
  /** Adds the storage options plus `-m, --manifests` (optional when the project config names them). */
  dataOpts(c: Command): Command;
  dataOptionsOf(o: StoreFlags): DataOptions;
  dataExists(o: StoreFlags): void;
  engineConfigOf(o: EngineFlags, extra?: Partial<EngineConfig>): EngineConfig;
  engine(o: EngineFlags, extra?: Partial<EngineConfig>): Promise<EngineHandle>;
  withEngine<T>(o: EngineFlags, fn: (e: EngineHandle) => Promise<T> | T, extra?: Partial<EngineConfig>): Promise<T>;
  readDoc(path: string): unknown;
  manifestsPath(o: EngineFlags): string;
}

export function makeContext(program: Command, io: IO): Ctx {
  let cached: { key: string; value: ProjectConfig | undefined } | undefined;

  const ctx: Ctx = {
    io,
    code: 0,
    program,

    project(flags = {}) {
      const explicit = flags.config ?? (program.opts() as { config?: string }).config;
      const key = explicit ?? process.cwd();
      if (cached?.key === key) return cached.value;
      const file = findProjectConfig(process.cwd(), explicit);
      cached = { key, value: file ? loadProjectConfig(file) : undefined };
      return cached.value;
    },

    storeOpts(c) {
      return c
        .option("-d, --data <dir>", "data directory (default: reversi.config.yaml, REVERSI_DATA or ./reversi-data)")
        .option("--store <kind>", "files | sqlite | postgres (default: the config file, REVERSI_STORE or files)")
        .option("--database-url <url>", "PostgreSQL URL (default: REVERSI_DATABASE_URL)");
    },

    dataOpts(c) {
      return ctx.storeOpts(c.option("-m, --manifests <path>", "manifests: a file, a folder, a registry folder or an https URL (default: the config file or REVERSI_MANIFESTS)"));
    },

    dataOptionsOf(o) {
      const env = dataOptionsFromEnv();
      const p = ctx.project(o)?.data;
      return {
        dir: o.data ?? process.env.REVERSI_DATA ?? p?.dir ?? "./reversi-data",
        store: o.store ? storeKindFrom(o.store) : process.env.REVERSI_STORE ? env.store : (p?.store ?? env.store),
        postgres_url: o.databaseUrl ?? env.postgres_url ?? p?.database_url,
      };
    },

    dataExists(o) {
      const d = ctx.dataOptionsOf(o);
      if (d.store === "files" && !existsSync(d.dir)) throw new Fail(`data directory not found: ${d.dir} (run \`reversi init\`, or pass -d)`);
    },

    manifestsPath(o) {
      const m = o.manifests ?? process.env.REVERSI_MANIFESTS ?? ctx.project(o)?.manifests;
      if (!m) throw new Fail("no manifests: pass -m <path>, set REVERSI_MANIFESTS, or add `manifests:` to reversi.config.yaml");
      return m;
    },

    engineConfigOf(o, extra = {}) {
      const p = ctx.project(o);
      return {
        manifests: ctx.manifestsPath(o),
        data: ctx.dataOptionsOf(o),
        policy: o.policy ?? process.env.REVERSI_POLICY ?? p?.policy,
        environment: process.env.REVERSI_ENV ?? p?.environment,
        manifest_public_key: process.env.REVERSI_MANIFEST_PUBLIC_KEY ?? p?.manifest_public_key,
        signing_key: process.env.REVERSI_SIGNING_KEY ?? p?.signing_key,
        egress: p?.egress,
        capture: p?.capture,
        ...extra,
      };
    },

    async engine(o, extra) {
      ctx.dataExists(o);
      return openEngine(ctx.engineConfigOf(o, { log: () => {}, ...extra }));
    },

    async withEngine(o, fn, extra) {
      const e = await ctx.engine(o, extra);
      try {
        return await fn(e);
      } finally {
        await e.close();
      }
    },

    readDoc(path) {
      const text = readFileSync(path, "utf8");
      return extname(path).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
    },
  };
  return ctx;
}
