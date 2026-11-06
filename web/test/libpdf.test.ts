// ADR-016: the vendored LibPDF and the signing Worker of web/src/sign.
//
// Provenance: every vendored file has the git blob hash of the pinned
// upstream file, or is declared in web/vendor/libpdf/CHANGED-FILES, and
// the upstream manifest hashes to the pinned src/ tree. Build: no shipped
// module imports a bare package or an unbuilt module. Behaviour: the
// preparation emits only the appended bytes of one increment, its
// /ByteRange covers every byte except /Contents, and the parser refuses
// encrypted files, object streams and xref streams.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

import { readExpectations, runTarget } from "../fuzz/harness.js";
import * as pdfDocument from "../fuzz/pdf_document.fuzz.js";
import {
  contractRevision,
  deepRevision,
  encryptedRevision,
  flateObjectStreamRevision,
  fromBytes,
  objectStreamRevision,
  prevLoopRevision,
  toBytes,
  xrefStreamRevision,
} from "../fuzz/pdf_fixture.js";
import { refCheckIncrement } from "../fuzz/pdf_increment_ref.js";
import { parseModule, prepareModule } from "../fuzz/pdf_load.js";
import * as pdfPrepare from "../fuzz/pdf_prepare.fuzz.js";
import * as pdfDifferential from "../fuzz/pdf_prepare_differential.fuzz.js";
import * as pdfToken from "../fuzz/pdf_token.fuzz.js";
import * as pdfXref from "../fuzz/pdf_xref.fuzz.js";
import { NotImplemented, assert, eq, show, test } from "./support/harness.js";
import { WEB_DIR } from "./support/paths.js";

const VENDOR = join(WEB_DIR, "vendor", "libpdf");
const SIGNER_DIST = join(WEB_DIR, "dist", "signer");

/** ADR-016 "Source and pin". */
const PIN = {
  commit: "6bb53b8c7574c1a91992812bcfca8121a11eace8",
  srcTree: "2d817a095f34f4177b1b50f92392336ac5200cb1",
  licenseBlob: "03e95b9d30aa4957489f78f576a66d241e08b368",
  noticeBlob: "4da75301eaf795d26cd31b56c86937c70d084978",
};

/** ADR-016 "Parts used": vendored but not built. A shipped module never lives here. */
const UNBUILT: readonly string[] = [
  "src/fontbox/",
  "src/fonts/",
  "src/drawing/",
  "src/text/",
  "src/svg/",
  "src/images/",
  "src/layers/",
  "src/attachments/",
  "src/annotations/",
  "src/security/",
  "src/filters/",
  "src/parser/brute-force-parser.ts",
];

/** ADR-016 "Parts used": built and shipped. A shipped module lives below one of these. */
const BUILT: readonly string[] = [
  "src/io/",
  "src/objects/",
  "src/parser/",
  "src/writer/",
  "src/document/",
  "src/api/",
  "src/signatures/placeholder.ts",
  "src/helpers/",
];

/** Whether an upstream path is a test file, which the import leaves out. */
function isUpstreamTest(path: string): boolean {
  return (
    path.endsWith(".test.ts") ||
    path === "src/test-utils.ts" ||
    path.startsWith("src/integration/") ||
    path === "src/signatures/formats/test-helpers.ts"
  );
}

function sha1Hex(parts: readonly (string | Uint8Array)[]): string {
  const h = createHash("sha1");
  for (const p of parts) {
    h.update(p);
  }
  return h.digest("hex");
}

/** The git blob hash of `bytes`. */
function blobHash(bytes: Uint8Array): string {
  return sha1Hex([`blob ${bytes.length}\u0000`, bytes]);
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

interface TreeNode {
  readonly blobs: Map<string, string>;
  readonly trees: Map<string, TreeNode>;
}

/** The git tree hash of `node`, as git orders tree entries. */
function treeHash(node: TreeNode): string {
  const names = [...[...node.blobs.keys()].map((n) => ({ n, key: n })), ...[...node.trees.keys()].map((n) => ({ n, key: `${n}/` }))];
  names.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  for (const { n } of names) {
    const blob = node.blobs.get(n);
    const sub = node.trees.get(n);
    const mode = blob === undefined ? "40000" : "100644";
    const sha = blob ?? (sub === undefined ? "" : treeHash(sub));
    parts.push(enc.encode(`${mode} ${n}\u0000`), hexBytes(sha));
  }
  const body = concat(parts);
  return sha1Hex([`tree ${body.length}\u0000`, body]);
}

/** The upstream manifest: path to blob hash. */
function upstreamTree(): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of readFileSync(join(VENDOR, "UPSTREAM-TREE"), "utf8").split("\n")) {
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const m = /^100644 blob ([0-9a-f]{40})\t(.+)$/.exec(line);
    assert(m !== null, `UPSTREAM-TREE line ${show(line)}`);
    out.set(m[2] ?? "", m[1] ?? "");
  }
  return out;
}

/** The declared local changes: path to `modified` or `added`. */
function changedFiles(): Map<string, string> {
  const out = new Map<string, string>();
  const path = join(VENDOR, "CHANGED-FILES");
  if (!existsSync(path)) {
    return out;
  }
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const m = /^(modified|added) (src\/\S+)$/.exec(line);
    assert(m !== null, `CHANGED-FILES line ${show(line)}`);
    assert(!out.has(m[2] ?? ""), `CHANGED-FILES names ${m[2] ?? ""} twice`);
    out.set(m[2] ?? "", m[1] ?? "");
  }
  return out;
}

/** Every file below `dir`, as POSIX paths relative to `base`. */
function listFiles(base: string, dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(base, dir)).sort()) {
    const rel = dir === "" ? name : `${dir}/${name}`;
    if (statSync(join(base, rel)).isDirectory()) {
      out.push(...listFiles(base, rel));
    } else {
      out.push(rel);
    }
  }
  return out;
}

/** ADR-016 "Source and pin": the manifest is the pinned upstream src/ tree and licence. */
test("adr016_provenance_upstream_manifest_is_the_pinned_tree", () => {
  const tree = upstreamTree();
  const root: TreeNode = { blobs: new Map(), trees: new Map() };
  for (const [path, sha] of tree) {
    if (!path.startsWith("src/")) {
      continue;
    }
    const segs = path.slice(4).split("/");
    let node = root;
    for (const seg of segs.slice(0, -1)) {
      let next = node.trees.get(seg);
      if (next === undefined) {
        next = { blobs: new Map(), trees: new Map() };
        node.trees.set(seg, next);
      }
      node = next;
    }
    node.blobs.set(segs[segs.length - 1] ?? "", sha);
  }
  eq(treeHash(root), PIN.srcTree, "the src/ tree hash of UPSTREAM-TREE");
  eq(tree.get("LICENSE.md"), PIN.licenseBlob, "the LICENSE.md blob of UPSTREAM-TREE");
  const upstream = readFileSync(join(VENDOR, "UPSTREAM"), "utf8");
  assert(upstream.includes(`commit: ${PIN.commit}`) && upstream.includes(`src-tree: ${PIN.srcTree}`), "UPSTREAM names the pin");
});

/**
 * ADR-016 "Location and build", review plan item 1: every vendored file
 * has the blob hash of its upstream file, or is declared changed. Every
 * declaration is true, every upstream file outside the tests is present,
 * and the fontbox NOTICE is the pinned PDFBox NOTICE.txt.
 */
test("adr016_provenance_every_vendored_file_matches_its_upstream_blob_or_is_declared", () => {
  const tree = upstreamTree();
  const changed = changedFiles();
  const vendored = new Set(["LICENSE.md", ...listFiles(VENDOR, "src")]);
  eq(blobHash(readFileSync(join(VENDOR, "LICENSE.md"))), PIN.licenseBlob, "LICENSE.md is upstream's, byte for byte");
  eq(blobHash(readFileSync(join(VENDOR, "src", "fontbox", "NOTICE"))), PIN.noticeBlob, "src/fontbox/NOTICE is PDFBox's NOTICE.txt");
  const bad: string[] = [];
  for (const [path, sha] of tree) {
    if (isUpstreamTest(path)) {
      if (vendored.has(path)) {
        bad.push(`${path}: an upstream test file is vendored`);
      }
      continue;
    }
    if (!vendored.has(path)) {
      bad.push(`${path}: missing`);
      continue;
    }
    const same = blobHash(readFileSync(join(VENDOR, path))) === sha;
    const kind = changed.get(path);
    if (kind === undefined && !same) {
      bad.push(`${path}: differs from upstream and is not declared in CHANGED-FILES`);
    } else if (kind === "modified" && same) {
      bad.push(`${path}: declared modified but equals upstream`);
    } else if (kind === "added") {
      bad.push(`${path}: declared added but is an upstream file`);
    }
  }
  for (const path of vendored) {
    if (tree.has(path) || path === "src/fontbox/NOTICE") {
      continue;
    }
    if (changed.get(path) !== "added") {
      bad.push(`${path}: not upstream and not declared added`);
    }
  }
  for (const path of changed.keys()) {
    if (!vendored.has(path)) {
      bad.push(`${path}: declared in CHANGED-FILES but absent`);
    }
  }
  eq(bad, [], "provenance findings");
});

interface Shipped {
  readonly files: readonly string[];
}

function shippedSet(): Shipped {
  const cfg: unknown = JSON.parse(readFileSync(join(VENDOR, "tsconfig.json"), "utf8"));
  const files = (cfg as { files?: unknown }).files;
  assert(Array.isArray(files) && files.every((f) => typeof f === "string"), "web/vendor/libpdf/tsconfig.json lists its modules in `files`");
  assert((cfg as { include?: unknown }).include === undefined, "the vendored project names its modules in `files` only");
  return { files: files as string[] };
}

/** The specifiers of the import and export declarations of a module. */
function specifiers(text: string): string[] {
  const out: string[] = [];
  const decl = /^(?:import|export)\b[^;]*?\bfrom\s*(["'])([^"']*)\1/gm;
  const bare = /^import\s*(["'])([^"']*)\1/gm;
  for (const re of [decl, bare]) {
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      out.push(m[2] ?? "");
    }
  }
  return out;
}

/** `spec` resolved against the directory of `from`, both POSIX paths below web/vendor/libpdf. */
function resolveSpec(from: string, spec: string): string | null {
  const out = dirname(from) === "." ? [] : dirname(from).split("/");
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

/** ADR-016 "Runtime dependencies": no shipped vendored module imports a bare package specifier. */
test("adr016_no_shipped_vendored_module_imports_a_bare_package", () => {
  const bad: string[] = [];
  for (const f of shippedSet().files) {
    const text = readFileSync(join(VENDOR, f), "utf8");
    for (const spec of specifiers(text)) {
      if (!(spec.startsWith("./") || spec.startsWith("../")) || !spec.endsWith(".js")) {
        bad.push(`${f}: ${spec}`);
      }
    }
    const code = text.split("\n").filter((l) => !/^\s*(\/\/|\/\*|\*)/.test(l));
    for (const l of code) {
      if (/\bimport\s*\(|\brequire\s*\(|\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(/.test(l)) {
        bad.push(`${f}: ${l.trim()}`);
      }
    }
  }
  eq(bad, [], "bare specifiers, dynamic imports, eval or Function in shipped modules");
});

/**
 * ADR-016 "Parts used": the shipped set lies inside the built parts, and
 * no shipped module, nor web/src/sign, imports a module outside it. tsc's
 * output holds no other module.
 */
test("adr016_no_shipped_module_imports_an_unbuilt_module", () => {
  const files = shippedSet().files;
  const shipped = new Set(files);
  const bad: string[] = [];
  for (const f of files) {
    if (UNBUILT.some((u) => f.startsWith(u)) || f.startsWith("src/signatures/") && f !== "src/signatures/placeholder.ts") {
      bad.push(`${f}: an unbuilt part is in the build`);
    }
    if (!BUILT.some((b) => f.startsWith(b)) && changedFiles().get(f) !== "added") {
      bad.push(`${f}: outside the built parts of ADR-016`);
    }
    for (const spec of specifiers(readFileSync(join(VENDOR, f), "utf8"))) {
      const target = resolveSpec(f, spec)?.replace(/\.js$/, ".ts") ?? null;
      if (target === null || !shipped.has(target)) {
        bad.push(`${f}: imports ${spec}, which is not shipped`);
      }
    }
  }
  for (const f of listFiles(join(WEB_DIR, "src"), "sign").filter((p) => p.endsWith(".ts"))) {
    for (const spec of specifiers(readFileSync(join(WEB_DIR, "src", f), "utf8"))) {
      const fromWeb = resolveSpec(`src/${f}`, spec);
      if (fromWeb !== null && fromWeb.startsWith("vendor/libpdf/")) {
        const target = fromWeb.slice("vendor/libpdf/".length).replace(/\.js$/, ".ts");
        if (!shipped.has(target)) {
          bad.push(`web/src/${f}: imports ${spec}, which is not shipped`);
        }
      } else if (fromWeb === null || !fromWeb.startsWith("src/sign/")) {
        bad.push(`web/src/${f}: imports ${spec}, outside web/src/sign and the shipped vendored modules`);
      }
    }
  }
  eq(bad, [], "build findings");
  const out = join(SIGNER_DIST, "vendor", "libpdf");
  if (!existsSync(out)) {
    throw new NotImplemented("web/dist/signer is not built (tsc -b web/src/sign)");
  }
  const emitted = listFiles(out, "src").filter((p) => p.endsWith(".js"));
  const extra = emitted.filter((p) => !shipped.has(p.replace(/\.js$/, ".ts")));
  eq(extra, [], "modules in tsc's output that the vendored tsconfig does not list");
});

async function prepared(revision: string, field: string): Promise<{ increment: string; byteRange: readonly number[] }> {
  const prep = await prepareModule();
  const bytes = toBytes(revision);
  const out = prep.prepareSignature(bytes, { field, contentsBytes: pdfPrepare.CONTENTS_BYTES });
  assert(out.ok, `prepareSignature refused ${field}: ${out.ok ? "" : `${out.code}: ${out.message}`}`);
  eq(fromBytes(bytes), revision, "the input buffer is unchanged");
  return { increment: fromBytes(out.increment), byteRange: out.byteRange };
}

/** ADR-016 "Division of work", M5 design 3.1 step 3: the output is only the appended bytes, after the input bytes exactly. */
test("adr016_pdf_prepare_output_starts_with_the_input_bytes", async () => {
  const parse = await parseModule();
  const rev0 = contractRevision();
  const one = await prepared(rev0, "party-1");
  assert(!one.increment.startsWith("%PDF"), "the increment is not a whole file");
  pdfPrepare.checkPrepared(parse, rev0, toBytes(one.increment), one.byteRange, "party-1");
  eq(refCheckIncrement(rev0, one.increment, "party-1"), null, "the reference increment check");
  // The second party signs revision 1: the increment follows the /Prev chain.
  const rev1 = rev0 + one.increment;
  const two = await prepared(rev1, "party-2");
  pdfPrepare.checkPrepared(parse, rev1, toBytes(two.increment), two.byteRange, "party-2");
  eq(refCheckIncrement(rev1, two.increment, "party-2"), null, "the reference increment check on revision 1");
});

/** ADR-016 review plan item 4: /ByteRange covers every byte except the /Contents hex string, with no gap or overlap. */
test("adr016_pdf_prepare_byte_range_covers_every_byte_except_contents", async () => {
  const rev0 = contractRevision();
  const { increment, byteRange } = await prepared(rev0, "party-2");
  const full = rev0 + increment;
  const [o1, l1, o2, l2] = byteRange as [number, number, number, number];
  const lt = full.indexOf("<", full.lastIndexOf("/Contents"));
  const gt = full.indexOf(">", lt);
  eq([o1, l1, o2, o2 + l2], [0, lt, gt + 1, full.length], "/ByteRange against the /Contents string");
  eq(gt + 1 - lt, 2 + 2 * pdfPrepare.CONTENTS_BYTES, "the /Contents string holds the placeholder only");
});

/** ADR-016 review plan item 4: a field outside the party's own, or one already signed, is refused. */
test("adr016_pdf_prepare_refuses_an_unknown_or_signed_field", async () => {
  const prep = await prepareModule();
  const rev0 = contractRevision();
  const unknown = prep.prepareSignature(toBytes(rev0), { field: "party-3", contentsBytes: pdfPrepare.CONTENTS_BYTES });
  eq(unknown.ok ? "ok" : unknown.code, "no-field", "an unknown field");
  const { increment } = await prepared(rev0, "party-1");
  const again = prep.prepareSignature(toBytes(rev0 + increment), { field: "party-1", contentsBytes: pdfPrepare.CONTENTS_BYTES });
  eq(again.ok ? "ok" : again.code, "field-signed", "a field already signed");
  const small = prep.prepareSignature(toBytes(rev0), { field: "party-1", contentsBytes: prep.CONTENTS_BYTES_MIN - 1 });
  eq(small.ok ? "ok" : small.code, "request", "a placeholder below the minimum");
  const large = prep.prepareSignature(toBytes(rev0), { field: "party-1", contentsBytes: prep.CONTENTS_BYTES_MAX + 1 });
  eq(large.ok ? "ok" : large.code, "request", "a placeholder above the maximum");
});

/** ADR-016 "Runtime dependencies", fuzz target pdf_document: encrypted files are refused with a typed error. */
test("adr016_parser_refuses_encrypted_files", async () => {
  const parse = await parseModule();
  const prep = await prepareModule();
  const out = parse.parseDocumentBytes(toBytes(encryptedRevision()));
  eq(out.ok ? "ok" : out.code, "encrypted", "an encrypted revision");
  const p = prep.prepareSignature(toBytes(encryptedRevision()), { field: "party-1", contentsBytes: pdfPrepare.CONTENTS_BYTES });
  eq(p.ok ? "ok" : p.code, "encrypted", "preparing on an encrypted revision");
});

/** ADR-016 "Runtime dependencies": object streams, also FlateDecode ones, are refused with a typed error. */
test("adr016_parser_refuses_object_streams", async () => {
  const parse = await parseModule();
  for (const rev of [objectStreamRevision(), flateObjectStreamRevision()]) {
    const out = parse.parseDocumentBytes(toBytes(rev));
    eq(out.ok ? "ok" : out.code, "object-stream", "an object stream");
  }
});

/** ADR-016 "Runtime dependencies": xref streams are refused with a typed error. */
test("adr016_parser_refuses_xref_streams", async () => {
  const parse = await parseModule();
  eq((o => (o.ok ? "ok" : o.code))(parse.parseDocumentBytes(toBytes(xrefStreamRevision()))), "xref-stream", "a document");
  eq((o => (o.ok ? "ok" : o.code))(parse.parseXRefBytes(toBytes(xrefStreamRevision()))), "xref-stream", "the xref chain");
});

/** ADR-016 review plan item 3: a /Prev loop, deep nesting and input above the size limit are refused. */
test("adr016_parser_hard_limits_refuse_loops_depth_and_size", async () => {
  const parse = await parseModule();
  const code = (o: { ok: boolean; code?: string }): string => (o.ok ? "ok" : o.code ?? "");
  eq(code(parse.parseXRefBytes(toBytes(prevLoopRevision()))), "malformed", "a /Prev loop");
  eq(code(parse.parseDocumentBytes(toBytes(deepRevision(parse.LIMITS.maxDepth - 4)))), "ok", "nesting within the limit");
  eq(code(parse.parseDocumentBytes(toBytes(deepRevision(parse.LIMITS.maxDepth + 1)))), "limit", "nesting beyond the limit");
  eq(code(parse.parseObjectBytes(toBytes(`(${"a".repeat(parse.LIMITS.maxStringBytes + 1)})`))), "limit", "a string beyond the limit");
  eq(code(parse.parseDocumentBytes(new Uint8Array(parse.LIMITS.maxFileBytes + 1))), "limit", "a file beyond the size limit");
});

/** ADR-016 "Location and build": the Worker answers a request with only the increment, and refuses a malformed message. */
test("adr016_sign_worker_message_contract", async () => {
  const url = new URL("../../signer/src/sign/prepare.js", import.meta.url);
  if (!existsSync(join(SIGNER_DIST, "src", "sign", "prepare.js"))) {
    throw new NotImplemented("web/dist/signer is not built (tsc -b web/src/sign)");
  }
  const mod = (await import(url.href)) as { handleMessage?: (data: unknown) => unknown };
  const handle = mod.handleMessage;
  assert(typeof handle === "function", "prepare.ts exports handleMessage");
  const rev0 = toBytes(contractRevision());
  const reply = handle({ revision: rev0.buffer, field: "party-1", contentsBytes: pdfPrepare.CONTENTS_BYTES }) as Record<string, unknown>;
  eq(Object.keys(reply).sort(), ["byteRange", "increment", "ok"], "reply members");
  assert(reply["ok"] === true && reply["increment"] instanceof ArrayBuffer, `reply ${show(reply)}`);
  for (const bad of [null, {}, { revision: "x", field: "party-1", contentsBytes: 2048 }, { revision: rev0.buffer, field: 1, contentsBytes: 2048 }, { revision: rev0.buffer, field: "party-1", contentsBytes: 2048, extra: 1 }]) {
    const r = handle(bad) as Record<string, unknown>;
    eq([r["ok"], r["code"]], [false, "request"], `a malformed message ${show(bad)}`);
  }
});

/** TH-26, ADR-016: each PDF corpus line gets its verdict. */
test("th26_adr016_pdf_corpora_get_their_verdicts", async () => {
  const parse = await parseModule();
  pdfToken.checkCorpus(parse);
  pdfXref.checkCorpus(parse);
  pdfDocument.checkCorpus(parse);
  pdfPrepare.checkCorpus(await prepareModule());
  pdfDifferential.checkCorpus(await prepareModule());
  for (const name of ["pdf_token", "pdf_xref", "pdf_document", "pdf_prepare", "pdf_prepare_differential"]) {
    assert(readExpectations(name).length > 0, `${name} has an expect.tsv corpus`);
  }
});

const SMOKE_SEED = 20261106;
const SMOKE_RUNS = 300;

/** TH-26, ADR-016: every PDF fuzz target holds on a seeded run under the in-house harness. */
test("th26_adr016_pdf_targets_hold", async () => {
  for (const t of [pdfToken.target, pdfXref.target, pdfDocument.target, pdfPrepare.target, pdfDifferential.target]) {
    const out = await runTarget(t, SMOKE_SEED, SMOKE_RUNS);
    assert(out.ok, `${t.name} failed at iteration ${out.ok ? 0 : out.iteration} on ${out.ok ? "" : show(out.input.slice(0, 300))}: ${out.ok ? "" : out.message}`);
  }
});

/** TH-26, ADR-016 teeth: the reference increment check refuses an extra object and a shifted /ByteRange. */
test("th26_adr016_reference_increment_check_has_teeth", async () => {
  const rev0 = contractRevision();
  const { increment } = await prepared(rev0, "party-1");
  eq(refCheckIncrement(rev0, increment, "party-1"), null, "the prepared increment");
  const extra = increment.replace("xref\n", "99 0 obj\nnull\nendobj\nxref\n");
  assert(refCheckIncrement(rev0, extra, "party-1") !== null, "an increment with a third object");
  const shifted = increment.replace(/\/ByteRange \[0 (\d+)/, (_m, n: string) => `/ByteRange [0 ${String(Number(n) - 1).padEnd(n.length, " ")}`);
  assert(shifted !== increment && refCheckIncrement(rev0, shifted, "party-1") !== null, "a /ByteRange with a gap");
  assert(refCheckIncrement(rev0, increment, "party-2") !== null, "the increment of another party's field");
});
