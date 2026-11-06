// Fuzz target `route_tree` for `readRouteTree` in web/src/journey/svg.ts
// (ADR-015 amendment of 2026-11-06, ADR-014, TH-26, I-68, I-70, H-05;
// lane j4).
//
// The progress page reads the server's checked map tree from the wire
// and builds it with `createElementNS`. The reader is an in-house parser
// of wire data. Checks, for any input:
// - the input is read as JSON when it parses, and as a string otherwise;
// - the reader never throws and never touches the document;
// - an accepted tree is inside the closed SVG subset of the reference
//   below, and the reader agrees with the reference on every input and
//   with the verdicts of web/fuzz/seeds/route_tree/expect.tsv.
//
// The reference reading of the subset, written apart from the reader
// from `crates/fstp-html/src/subset.rs` and the ADR-015 amendment:
// - an element is an object with exactly `tag`, `attrs` and `children`;
//   an attribute exactly `name` and `value`, both strings; a text node
//   exactly `text`, a non-empty string. No two texts stand side by side;
// - the root is `svg`, and each child stands below the parents of the
//   checker's SVG table. Only `title`, `desc`, `text` and `tspan` hold
//   text, and only `text` holds an element (`tspan`) beside text. No `a`
//   stands inside another `a`. At most 32 elements deep, the root at 1;
// - attribute names come from the checker's SVG table, plus `id`,
//   `class`, `role`, `tabindex`, `lang`, `dir` and `aria-` with lower-case
//   letters, each name once per element;
// - `href` is `{page}#node-` and an upper-case state name of A-Z, 0-9
//   and `_`; `fill` and `stroke` are `currentColor` or `none`;
//   `font-size` is a whole number from 1 to 99 with no leading zero;
//   `marker-start` and `marker-end` are `url(#name)` with a name of
//   letters, digits, `-` and `_`; `lang` is a language tag;
// - every text and value holds plain characters only: tab, line feed, or
//   a scalar value from U+0020 up that is not DEL, a C1 control or a
//   noncharacter. A lone surrogate is refused.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { assert, show } from "../test/support/harness.js";
import { REPO_DIR } from "../test/support/paths.js";
import { readRouteTree } from "../src/journey/svg.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

/** The page the fuzzed trees are read for. */
export const PAGE = "/app/proposals/1001/progress";

/** The deepest element the reference accepts, the root at 1. */
export const MAX_TREE_DEPTH = 32;

/** The reader this target drives. */
export type TreeReader = (v: unknown, page: string) => unknown;

const ELEMENT_ATTRS: Readonly<Record<string, readonly string[]>> = {
  svg: ["viewbox"],
  title: [],
  desc: [],
  defs: [],
  marker: ["viewbox", "refx", "refy", "markerwidth", "markerheight", "orient"],
  g: [],
  a: ["href"],
  path: ["d", "marker-start", "marker-end", "fill", "stroke"],
  line: ["x1", "y1", "x2", "y2", "marker-start", "marker-end", "stroke"],
  rect: ["x", "y", "width", "height", "rx", "ry", "fill", "stroke"],
  circle: ["cx", "cy", "r", "fill", "stroke"],
  text: ["x", "y", "dx", "dy", "text-anchor", "fill", "font-size"],
  tspan: ["x", "y", "dx", "dy"],
};

const CHILDREN: Readonly<Record<string, readonly string[]>> = {
  svg: ["title", "desc", "defs", "g", "a", "path", "line", "rect", "circle", "text"],
  g: ["title", "desc", "g", "a", "path", "line", "rect", "circle", "text"],
  a: ["title", "desc", "g", "path", "line", "rect", "circle", "text"],
  defs: ["marker"],
  marker: ["path"],
  text: ["tspan"],
};

const HOLDS_TEXT = new Set(["title", "desc", "text", "tspan"]);
const GLOBAL = new Set(["id", "class", "role", "tabindex", "lang", "dir"]);

function own(o: object, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function exactly(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const k = Object.keys(o);
  return k.length === keys.length && keys.every((x) => own(o, x));
}

/** Whether every code point of `s` is plain, with no lone surrogate. */
export function refPlain(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const u = s.charCodeAt(i);
    let c = u;
    if (u >= 0xd800 && u <= 0xdbff) {
      const lo = s.charCodeAt(i + 1);
      if (!(lo >= 0xdc00 && lo <= 0xdfff)) {
        return false;
      }
      c = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
      i += 1;
    } else if (u >= 0xdc00 && u <= 0xdfff) {
      return false;
    }
    if (c === 0x09 || c === 0x0a) {
      continue;
    }
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) {
      return false;
    }
    if ((c >= 0xfdd0 && c <= 0xfdef) || (c & 0xfffe) === 0xfffe) {
      return false;
    }
  }
  return true;
}

/** Whether `s` is a whole number from 1 to 99, with no sign, unit or leading zero. */
function wholeUpTo99(s: string): boolean {
  if (s === "" || s.length > 2 || s.startsWith("0")) {
    return false;
  }
  for (const ch of s) {
    if (ch < "0" || ch > "9") {
      return false;
    }
  }
  return true;
}

function langTag(s: string): boolean {
  return /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/.test(s);
}

function valueOk(name: string, value: string, page: string): boolean {
  switch (name) {
    case "href": {
      if (!value.startsWith(`${page}#node-`)) {
        return false;
      }
      return /^[A-Z0-9_]+$/.test(value.slice(page.length + "#node-".length));
    }
    case "fill":
    case "stroke":
      return value === "currentColor" || value === "none";
    case "font-size":
      return wholeUpTo99(value);
    case "marker-start":
    case "marker-end":
      return /^url\(#[A-Za-z0-9_-]+\)$/.test(value);
    case "lang":
      return langTag(value);
    default:
      return true;
  }
}

function elementOk(v: unknown, parent: string | null, inLink: boolean, depth: number, page: string): boolean {
  if (depth > MAX_TREE_DEPTH || !isRecord(v) || !exactly(v, ["tag", "attrs", "children"])) {
    return false;
  }
  const tag = v["tag"];
  const attrs = v["attrs"];
  const children = v["children"];
  if (typeof tag !== "string" || !Array.isArray(attrs) || !Array.isArray(children)) {
    return false;
  }
  const allowed = own(ELEMENT_ATTRS, tag) ? ELEMENT_ATTRS[tag] : undefined;
  if (allowed === undefined) {
    return false;
  }
  if (parent === null ? tag !== "svg" : !(CHILDREN[parent] ?? []).includes(tag)) {
    return false;
  }
  if (tag === "a" && inLink) {
    return false;
  }
  const seen = new Set<string>();
  for (const a of attrs as unknown[]) {
    if (!isRecord(a) || !exactly(a, ["name", "value"])) {
      return false;
    }
    const n = a["name"];
    const x = a["value"];
    if (typeof n !== "string" || typeof x !== "string" || seen.has(n)) {
      return false;
    }
    seen.add(n);
    const aria = /^aria-[a-z]+$/.test(n);
    if (!(GLOBAL.has(n) || allowed.includes(n) || aria) || !refPlain(x) || !valueOk(n, x, page)) {
      return false;
    }
  }
  let lastText = false;
  for (const c of children as unknown[]) {
    if (isRecord(c) && own(c, "text")) {
      const t = c["text"];
      if (!exactly(c, ["text"]) || typeof t !== "string" || t === "" || !refPlain(t) || !HOLDS_TEXT.has(tag) || lastText) {
        return false;
      }
      lastText = true;
      continue;
    }
    lastText = false;
    if (!elementOk(c, tag, inLink || tag === "a", depth + 1, page)) {
      return false;
    }
  }
  return true;
}

/** The reference verdict on the wire value `v` for the page `page`. */
export function refAccepts(v: unknown, page: string): boolean {
  return elementOk(v, null, false, 1, page);
}

/** The wire value of a fuzz input: its JSON parse, or the string itself. */
export function wireOf(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    return input;
  }
}

/** The checker over any reader. */
export function checkerFor(read: TreeReader): Checker {
  return (input: string) => {
    const v = wireOf(input);
    const g = globalThis as unknown as Record<string, unknown>;
    const before = g["document"];
    let got: unknown;
    try {
      got = read(v, PAGE);
    } catch (e) {
      if (e instanceof Error && e.name === "NotImplemented") {
        throw e;
      }
      throw new Error(`the tree reader threw on ${show(input)}: ${String(e)}`);
    }
    assert(g["document"] === before, "the reader touched the document");
    const accepted = got !== null;
    assert(accepted === refAccepts(v, PAGE), `the reader and the reference disagree on ${show(input)}: accepted ${accepted}`);
  };
}

/** The server's tree of the prototype state, as one seed. */
function serverTree(): string {
  return readFileSync(join(REPO_DIR, "crates", "fstp-html", "testdata", "route_stage2.tree.json"), "utf8").trim();
}

export const target: FuzzTarget = {
  name: "route_tree",
  seeds: () => [...readExpectations("route_tree").map((e) => e.input), serverTree()],
  dictionary: [
    '{"tag":"svg","attrs":[],"children":[]}',
    '{"tag":"script","attrs":[],"children":[]}',
    '{"tag":"foreignObject","attrs":[],"children":[]}',
    '{"text":"<script>alert(1)</script>"}',
    '{"name":"onclick","value":"x"}',
    '{"name":"style","value":"fill:red"}',
    '{"name":"fill","value":"red"}',
    '{"name":"stroke","value":"currentColor"}',
    '{"name":"font-size","value":"10"}',
    '{"name":"href","value":"javascript:alert(1)"}',
    '{"name":"href","value":"/app/proposals/1001/progress#node-DRAFT"}',
    '"__proto__"',
    '"tag"',
    '"attrs"',
    '"children"',
    '"text"',
    "url(#arrow)",
    "currentColor",
    "#node-",
    "\\u0000",
    "\\ud800",
    ",",
    "[",
    "]",
    "{",
    "}",
  ],
  prepare: async () => checkerFor(readRouteTree),
};
