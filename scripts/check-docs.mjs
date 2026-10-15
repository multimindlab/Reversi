// Compiles every docs/*.mdx page with the MDX compiler and checks docs.json navigation and internal links.
// Mintlify refuses to deploy a docs tree with a syntax error, so CI runs this on every push.
import { compile } from "@mdx-js/mdx";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../docs/", import.meta.url).pathname;
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const files = walk(root).filter((f) => f.endsWith(".mdx"));
let bad = 0;
const fail = (m) => {
  bad++;
  console.error(m);
};

for (const f of files) {
  try {
    await compile(readFileSync(f, "utf8"));
  } catch (e) {
    fail(`${f.replace(root, "docs/")}: ${e.reason ?? e.message} (line ${e.line ?? "?"}). In MDX use [text](url), not <url>, and escape { and <.`);
  }
}

const nav = JSON.parse(readFileSync(join(root, "docs.json"), "utf8")).navigation.groups.flatMap((g) => g.pages);
for (const p of nav) if (!existsSync(join(root, `${p}.mdx`))) fail(`docs.json lists "${p}" but docs/${p}.mdx does not exist`);
const listed = new Set(nav);
for (const f of files) {
  const p = f.replace(root, "").replace(/\.mdx$/, "");
  if (!listed.has(p)) fail(`docs/${p}.mdx is not in the docs.json navigation`);
  for (const m of readFileSync(f, "utf8").matchAll(/\]\((\/[^)#\s]*)|href="(\/[^"#]*)/g)) {
    const link = (m[1] ?? m[2]).replace(/^\//, "");
    if (link && !listed.has(link)) fail(`docs/${p}.mdx links to /${link}, which is not a page`);
  }
}
if (bad) process.exit(1);
console.log(`docs ok: ${files.length} pages compile, navigation and links resolve`);
