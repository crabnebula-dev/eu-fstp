// The asset packer of the `/app/` shell (ADR-014 "Shell, assets and
// headers", M4 design section 3.9).
//
// Build and run, from the repository root:
//
//   web/node_modules/.bin/tsc -p web/tsconfig.json
//   web/node_modules/.bin/tsc -p web/build
//   node web/dist/build/pack.js web/dist web/src web/dist/app shell/main.js
//
// `fstp-web` serves every asset at `/app/assets/{sha256}.js`, a flat and
// content-addressed path. A module that tsc wrote imports its neighbours
// by relative path, such as `../core/dom.js`, which would not resolve
// there. So the packer rewrites each relative import specifier to the
// content address of the module it names, `./{sha256}.js`, starting
// from the modules that import nothing. A module's address is the
// SHA-256 of its rewritten bytes, so it covers every module below it.
//
// The packer writes, below the output directory:
//
// - each module reachable from the entry, rewritten, at its tsc path;
// - each stylesheet of the source directory's feature folders that the
//   shell links, copied byte for byte;
// - `asset-manifest.json`, the manifest that `fstp_web_assets::load_dir`
//   verifies at cell start: `schema`, `entry` and `assets`, each path
//   mapped to the SHA-256 of the file written there.
//
// Interim readings, pending Daniel:
//
// - Only modules reachable from the entry are packed, so the stand-alone
//   entries of the auth and vault pages never reach `/app/`.
// - The shell links the stylesheets of `STYLE_FOLDERS` only. The auth
//   stylesheet styles the M3 pages and stays with them.
// - The packer reads tsc's own output, which writes one import or export
//   declaration per statement and starts each at the first column. It
//   refuses any specifier that is not a relative `.js` path inside the
//   output, any dynamic `import(`, any import cycle and any module that
//   still names a relative `.js` path after the rewrite. So a module it
//   cannot read refuses the whole build instead of loading broken.

import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** The manifest file name and schema of `fstp-web-assets`. */
const MANIFEST_FILE = "asset-manifest.json";
const SCHEMA = "fstp.web-assets/1";

/** The feature folders whose stylesheets the `/app/` shell links. */
const STYLE_FOLDERS: readonly string[] = ["applicant"];

/** A failure that stops the build, with a message that names the module. */
class PackError extends Error {
  override readonly name = "PackError";
}

/** The lowercase hex SHA-256 of `bytes`. */
function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** `spec` resolved against the directory `base`, as POSIX segments, or null when it climbs above the root. */
function normalise(base: string, spec: string): string | null {
  const out = base === "" ? [] : base.split("/");
  for (const seg of spec.split("/")) {
    if (seg === "" || seg === ".") {
      continue;
    }
    if (seg === "..") {
      if (out.length === 0) {
        return null;
      }
      out.pop();
      continue;
    }
    out.push(seg);
  }
  return out.join("/");
}

/** The directory part of a POSIX module path. */
function dirOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i);
}

/** One import or export declaration of a module. */
interface Declaration {
  /** The specifier text between the quotes. */
  readonly spec: string;
  /** The quote character around it. */
  readonly quote: string;
  /** The module path it resolves to. */
  readonly target: string;
}

/** A module read from the tsc output. */
interface Module {
  readonly path: string;
  readonly lines: readonly string[];
  /** For each line index that ends a declaration, its specifier. */
  readonly declarations: ReadonlyMap<number, Declaration>;
}

const FROM = /\bfrom\s*(["'])([^"'\\]+)\1\s*;\s*$/;
const BARE_IMPORT = /^import\s*(["'])([^"'\\]+)\1\s*;\s*$/;

/**
 * Reads the declarations of one tsc module. A declaration starts at the
 * first column with `import` or with `export {` or `export *`, and ends
 * on the first line that ends with `;`.
 */
function readModule(path: string, text: string, known: ReadonlySet<string>): Module {
  const lines = text.split("\n");
  const code = (l: string): boolean => !/^\s*(\/\/|\/\*|\*)/.test(l);
  if (lines.some((l) => code(l) && /\bimport\s*\(/.test(l))) {
    throw new PackError(`${path}: a dynamic import is not packed`);
  }
  const declarations = new Map<number, Declaration>();
  let open: string | null = null;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    if (open === null) {
      if (!/^(import\b|export\s*\{|export\s*\*)/.test(line)) {
        continue;
      }
      open = line;
    } else {
      open = `${open}\n${line}`;
    }
    if (!/;\s*$/.test(line)) {
      continue;
    }
    const statement = open;
    open = null;
    const m = FROM.exec(statement) ?? BARE_IMPORT.exec(statement);
    if (m === null) {
      continue;
    }
    const quote = m[1] ?? "\"";
    const spec = m[2] ?? "";
    if (!(spec.startsWith("./") || spec.startsWith("../")) || !spec.endsWith(".js")) {
      throw new PackError(`${path}: the specifier ${JSON.stringify(spec)} is not a relative .js path`);
    }
    const target = normalise(dirOf(path), spec);
    if (target === null || !known.has(target)) {
      throw new PackError(`${path}: ${JSON.stringify(spec)} names no module of the build`);
    }
    declarations.set(i, { spec, quote, target });
  }
  if (open !== null) {
    throw new PackError(`${path}: a declaration does not end`);
  }
  return { path, lines, declarations };
}

/** Every `.js` file below `dir`, as POSIX paths relative to it, skipping `skip` at the top. */
function listModules(dir: string, skip: ReadonlySet<string>, prefix = ""): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    if (prefix === "" && skip.has(name)) {
      continue;
    }
    const full = join(dir, name);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) {
      throw new PackError(`${prefix}${name}: a symbolic link is not packed`);
    }
    if (st.isDirectory()) {
      out.push(...listModules(full, skip, `${prefix}${name}/`));
    } else if (st.isFile() && name.endsWith(".js")) {
      out.push(`${prefix}${name}`);
    }
  }
  return out;
}

/** What one run wrote. */
interface Packed {
  readonly assets: ReadonlyMap<string, string>;
  readonly entry: string;
}

/** Packs the modules reachable from `entry` and the linked stylesheets into `out`. */
function pack(dist: string, src: string, out: string, entry: string): Packed {
  const outName = out.startsWith(`${dist}/`) ? out.slice(dist.length + 1).split("/")[0] ?? "" : "";
  const skip = new Set(["build", "test-build", outName].filter((s) => s !== ""));
  const all = listModules(dist, skip);
  const known = new Set(all);
  if (!known.has(entry)) {
    throw new PackError(`the entry ${entry} is not in ${dist}`);
  }
  const modules = new Map<string, Module>();
  const read = (path: string): Module => {
    let m = modules.get(path);
    if (m === undefined) {
      m = readModule(path, readFileSync(join(dist, path), "utf8"), known);
      modules.set(path, m);
    }
    return m;
  };

  // Post-order over the import graph from the entry: a module is
  // rewritten only after every module it names has its address.
  const address = new Map<string, string>();
  const rewritten = new Map<string, string>();
  const onPath = new Set<string>();
  const visit = (path: string, trail: readonly string[]): void => {
    if (address.has(path)) {
      return;
    }
    if (onPath.has(path)) {
      throw new PackError(`an import cycle: ${[...trail, path].join(" -> ")}`);
    }
    onPath.add(path);
    const m = read(path);
    for (const d of m.declarations.values()) {
      visit(d.target, [...trail, path]);
    }
    const lines = m.lines.map((line, i) => {
      const d = m.declarations.get(i);
      if (d === undefined) {
        return line;
      }
      const to = address.get(d.target);
      if (to === undefined) {
        throw new PackError(`${path}: ${d.target} has no address`);
      }
      const quoted = `${d.quote}${d.spec}${d.quote}`;
      const at = line.lastIndexOf(quoted);
      if (at < 0) {
        throw new PackError(`${path}: the specifier ${d.spec} is not on its closing line`);
      }
      return `${line.slice(0, at)}${d.quote}./${to}.js${d.quote}${line.slice(at + quoted.length)}`;
    });
    const text = lines.join("\n");
    if (/(?:from|import)\s*["']\.\.?\/(?![0-9a-f]{64}\.js["'])/.test(text)) {
      throw new PackError(`${path}: a relative specifier is left after the rewrite`);
    }
    onPath.delete(path);
    rewritten.set(path, text);
    address.set(path, sha256(text));
  };
  visit(entry, []);

  rmSync(out, { recursive: true, force: true });
  const assets = new Map<string, string>();
  for (const [path, text] of rewritten) {
    const full = join(out, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
    assets.set(path, sha256(text));
  }
  for (const folder of STYLE_FOLDERS) {
    for (const name of readdirSync(join(src, folder)).sort()) {
      if (!name.endsWith(".css")) {
        continue;
      }
      const bytes = readFileSync(join(src, folder, name));
      const path = `${folder}/${name}`;
      mkdirSync(join(out, folder), { recursive: true });
      writeFileSync(join(out, path), bytes);
      assets.set(path, sha256(bytes));
    }
  }
  const members = [...assets.keys()].sort().map((p) => `${JSON.stringify(p)}:${JSON.stringify(assets.get(p))}`);
  const manifest = `{"assets":{${members.join(",")}},"entry":${JSON.stringify(entry)},"schema":${JSON.stringify(SCHEMA)}}`;
  writeFileSync(join(out, MANIFEST_FILE), manifest);
  return { assets, entry };
}

function main(argv: readonly string[]): number {
  const [dist, src, out, entry] = argv;
  if (dist === undefined || src === undefined || out === undefined || entry === undefined || argv.length !== 4) {
    process.stderr.write("usage: pack.js <tsc out dir> <src dir> <pack out dir> <entry module>\n");
    return 64;
  }
  try {
    const p = pack(dist, src, out, entry);
    process.stdout.write(`packed ${p.assets.size} assets, entry ${p.entry}, into ${out}\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
}

process.exitCode = main(process.argv.slice(2));
