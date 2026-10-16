/**
 * Local file helpers shared by the CLI and the server: load manifests from JSON/YAML files and
 * open a data directory (`ledger.jsonl` + `runs/`).
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { JsonlLedgerStore, Ledger } from "./ledger.js";
import { ManifestError, Registry } from "./manifest.js";
import { ManifestRegistry } from "./registry.js";
import { Reversi, type Approver } from "./engine.js";
import { FileRunStore } from "./store.js";

const EXTS = new Set([".json", ".yaml", ".yml"]);

function filesIn(path: string): string[] {
  const st = statSync(path);
  if (st.isFile()) return [path];
  return readdirSync(path)
    .filter((f) => EXTS.has(extname(f).toLowerCase()))
    .sort()
    .map((f) => join(path, f));
}

/** Load manifests from a file or a directory of `.json`/`.yaml`/`.yml` files. Each file holds one manifest or an array. */
export function loadRegistry(path: string): Registry {
  if (!existsSync(path)) throw new ManifestError([`manifest path not found: ${path}`]);
  if (statSync(path).isDirectory() && ManifestRegistry.isRegistry(path)) return new ManifestRegistry(path).load(); // a versioned registry: its current versions
  const reg = new Registry();
  const errors: string[] = [];
  for (const file of filesIn(path)) {
    let doc: unknown;
    try {
      const text = readFileSync(file, "utf8");
      doc = extname(file).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
    } catch (e) {
      errors.push(`${file}: cannot parse: ${e instanceof Error ? e.message : String(e)}`);
      continue;
    }
    for (const m of Array.isArray(doc) ? doc : [doc]) {
      try {
        reg.register(m);
      } catch (e) {
        errors.push(`${file}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }
  errors.push(...reg.validate());
  if (errors.length) throw new ManifestError(errors);
  return reg;
}

export interface DataDir {
  ledgerPath: string;
  runsDir: string;
}
export function dataDirPaths(dir: string): DataDir {
  return { ledgerPath: join(dir, "ledger.jsonl"), runsDir: join(dir, "runs") };
}

/** Open (creating if needed) a file-backed engine in `dir`. */
export function openLocal(dir: string, registry: Registry, approver?: Approver): Reversi {
  const p = dataDirPaths(dir);
  return new Reversi({
    registry,
    ledger: new Ledger(new JsonlLedgerStore(p.ledgerPath)),
    runs: new FileRunStore(p.runsDir),
    approver,
  });
}
