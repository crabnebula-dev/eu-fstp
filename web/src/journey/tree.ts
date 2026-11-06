// The server's checked map tree in the web app (ADR-015 "Rendering" and
// its amendment of 2026-11-06, ADR-014 "DOM"; lane j4).
//
// The closed SVG subset the browser holds a tree to, and the reader and
// builder of the tree the server sends. This module imports nothing from
// `model.ts`, so `model.ts` can read the `proposal.route_map` reply
// through it with no import cycle. `svg.ts` takes the subset from here
// and re-exports the reader and the builder.

/** The SVG namespace. */
export const SVG_NS = "http://www.w3.org/2000/svg";

/** Whether code point `c` is plain (`fstp_html` subset): tab, LF, or no control or noncharacter. */
export function isPlain(c: number): boolean {
  if (c === 0x09 || c === 0x0a) {
    return true;
  }
  if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) {
    return false;
  }
  return !((c >= 0xfdd0 && c <= 0xfdef) || (c & 0xfffe) === 0xfffe);
}

/** The closed SVG subset: each element with the attributes it may carry. */
export const SUBSET: Readonly<Record<string, readonly string[]>> = Object.freeze({
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
});

export const GLOBAL = new Set(["id", "class", "role", "tabindex", "lang", "dir"]);
export const ARIA = /^aria-[a-z]+$/;
/** A `font-size`: a whole number from 1 to 99, with no sign, unit or leading zero. */
export const SMALL_WHOLE = /^[1-9][0-9]?$/;

/** The SVG spelling of the attributes the HTML parser would adjust. */
export const CAMEL: Readonly<Record<string, string>> = Object.freeze({
  viewbox: "viewBox",
  refx: "refX",
  refy: "refY",
  markerwidth: "markerWidth",
  markerheight: "markerHeight",
});

// ---------------------------------------------------------------------------
// The server's checked map tree (ADR-015 amendment, Daniel 2026-11-06)
// ---------------------------------------------------------------------------
//
// The map is laid out and rendered on the server: `proposal.route_map`
// returns the tree of `fstp_html::route::tree`, and the browser only
// validates it against the closed SVG subset and builds it with
// `createElementNS`, because the CSP admits no markup strings. The reader
// is an in-house parser of wire data, with the fuzz target
// `web/fuzz/route_tree.fuzz.ts`. The browser layout of `svg.ts` goes once the
// read is registered and the page draws the server's tree (lane j4
// blocker: the registry row of `proposal.route_map`).
//
// The wire shape:
//
// - an element is `{"tag", "attrs": [{"name", "value"}], "children"}`;
// - a text node is `{"text"}`, the characters before escaping.

/** An attribute of a tree element, as the wire gives it. */
export interface RouteTreeAttr {
  readonly name: string;
  readonly value: string;
}

/** A text node of the tree. */
export interface RouteTreeText {
  readonly text: string;
}

/** An element of the tree. */
export interface RouteTreeEl {
  readonly tag: string;
  readonly attrs: readonly RouteTreeAttr[];
  readonly children: readonly (RouteTreeEl | RouteTreeText)[];
}

declare const checkedTree: unique symbol;

/** A tree `readRouteTree` accepted for the page `page`. Only it makes one. */
export interface RouteTree {
  readonly root: RouteTreeEl;
  readonly page: string;
  readonly [checkedTree]: true;
}

/** The deepest element a tree may hold, the root at 1. */
const MAX_TREE_DEPTH = 32;

/** The children each element of the subset may hold, as the checker's SVG table gives them. */
const TREE_CHILDREN: Readonly<Record<string, readonly string[]>> = Object.freeze({
  svg: ["title", "desc", "defs", "g", "a", "path", "line", "rect", "circle", "text"],
  g: ["title", "desc", "g", "a", "path", "line", "rect", "circle", "text"],
  a: ["title", "desc", "g", "path", "line", "rect", "circle", "text"],
  defs: ["marker"],
  marker: ["path"],
  text: ["tspan"],
});

/** The elements that hold text. */
const HOLDS_TEXT: ReadonlySet<string> = new Set(["title", "desc", "text", "tspan"]);

const LANG_TAG = /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/;
const NODE_STATE = /^[A-Z0-9_]+$/;
const LOCAL_MARKER = /^url\(#[A-Za-z0-9_-]+\)$/;

function hasOwn(o: object, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function isObject(v: unknown): v is Readonly<Record<string, unknown>> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Whether `o` has exactly the own members `keys`. */
function onlyMembers(o: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const k = Object.keys(o);
  return k.length === keys.length && keys.every((x) => hasOwn(o, x));
}

/** Whether every code point of `s` is plain, with no lone surrogate. */
function plainString(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    if ((c >= 0xd800 && c <= 0xdfff) || !isPlain(c)) {
      return false;
    }
  }
  return true;
}

/** Whether attribute `name` may carry `value` on the map of `page`. */
function treeValueAllowed(name: string, value: string, page: string): boolean {
  switch (name) {
    case "href": {
      const prefix = `${page}#node-`;
      return value.startsWith(prefix) && NODE_STATE.test(value.slice(prefix.length));
    }
    case "fill":
    case "stroke":
      return value === "currentColor" || value === "none";
    case "font-size":
      return SMALL_WHOLE.test(value);
    case "marker-start":
    case "marker-end":
      return LOCAL_MARKER.test(value);
    case "lang":
      return LANG_TAG.test(value);
    default:
      return true;
  }
}

/** Reads one wire element below `parent`, or null outside the subset. */
function readTreeEl(v: unknown, parent: string | null, inLink: boolean, depth: number, page: string): RouteTreeEl | null {
  if (depth > MAX_TREE_DEPTH || !isObject(v) || !onlyMembers(v, ["tag", "attrs", "children"])) {
    return null;
  }
  const tag = v["tag"];
  const attrsIn = v["attrs"];
  const childrenIn = v["children"];
  if (typeof tag !== "string" || !Array.isArray(attrsIn) || !Array.isArray(childrenIn)) {
    return null;
  }
  const own = hasOwn(SUBSET, tag) ? SUBSET[tag] : undefined;
  if (own === undefined) {
    return null;
  }
  const placed = parent === null ? tag === "svg" : (hasOwn(TREE_CHILDREN, parent) ? (TREE_CHILDREN[parent] ?? []) : []).includes(tag);
  if (!placed || (tag === "a" && inLink)) {
    return null;
  }
  const seen = new Set<string>();
  const attrs: RouteTreeAttr[] = [];
  for (const a of attrsIn as readonly unknown[]) {
    if (!isObject(a) || !onlyMembers(a, ["name", "value"])) {
      return null;
    }
    const name = a["name"];
    const value = a["value"];
    if (typeof name !== "string" || typeof value !== "string" || seen.has(name)) {
      return null;
    }
    seen.add(name);
    if (!(GLOBAL.has(name) || own.includes(name) || ARIA.test(name))) {
      return null;
    }
    if (!plainString(value) || !treeValueAllowed(name, value, page)) {
      return null;
    }
    attrs.push(Object.freeze({ name, value }));
  }
  const children: (RouteTreeEl | RouteTreeText)[] = [];
  let lastText = false;
  for (const c of childrenIn as readonly unknown[]) {
    if (isObject(c) && hasOwn(c, "text")) {
      const text = c["text"];
      if (!onlyMembers(c, ["text"]) || typeof text !== "string" || text === "" || !plainString(text) || !HOLDS_TEXT.has(tag) || lastText) {
        return null;
      }
      lastText = true;
      children.push(Object.freeze({ text }));
      continue;
    }
    lastText = false;
    const e = readTreeEl(c, tag, inLink || tag === "a", depth + 1, page);
    if (e === null) {
      return null;
    }
    children.push(e);
  }
  return Object.freeze({ tag, attrs: Object.freeze(attrs), children: Object.freeze(children) });
}

/**
 * Reads the wire tree `v` of the map on the page `page`, or null when
 * any part of it is outside the closed SVG subset: an unknown or foreign
 * element, an element below a parent that may not hold it, an attribute
 * the element may not carry, `style` or an event attribute, a link other
 * than `{page}#node-STATE`, a marker outside the document, a `fill`
 * or `stroke` other than `currentColor` or `none`, a `font-size` that is
 * not a whole number from 1 to 99, a text where no text may stand, a
 * character that is not plain, a tree deeper than 32 elements, or a
 * member outside the wire shape. It never throws on wire data and never
 * touches the document. `web/fuzz/route_tree.fuzz.ts` holds the
 * reference it agrees with on every input.
 */
export function readRouteTree(v: unknown, page: string): RouteTree | null {
  let root: RouteTreeEl | null;
  try {
    root = readTreeEl(v, null, false, 1, page);
  } catch {
    // A hostile getter or a proxy is not wire data: refuse it.
    return null;
  }
  return root === null ? null : (Object.freeze({ root, page }) as RouteTree);
}

function buildEl(e: RouteTreeEl): SVGElement {
  const node = document.createElementNS(SVG_NS, e.tag);
  for (const a of e.attrs) {
    node.setAttribute(CAMEL[a.name] ?? a.name, a.value);
  }
  for (const c of e.children) {
    node.appendChild("text" in c ? document.createTextNode(c.text) : buildEl(c));
  }
  return node;
}

/**
 * Builds a checked tree as SVG DOM nodes: `createElementNS` in the SVG
 * namespace, `setAttribute` in the SVG spelling and text nodes only, so
 * no string reaches a parser (ADR-014).
 */
export function buildRouteTree(t: RouteTree): SVGElement {
  return buildEl(t.root);
}
