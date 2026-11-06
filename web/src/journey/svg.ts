// The progress map of the web app (ADR-015 "Rendering", ADR-014 "DOM";
// `docs/design/02-voyager-route-diary.md` "The progress map").
//
// The route SVG renderer is `fstp_html::route`. The `/app/` pages run
// under Trusted Types with no HTML sink, so a page cannot take the
// renderer's markup as a string. This module builds the same tree as
// data, then as DOM nodes through `createElementNS`, `setAttribute` and
// text nodes only. No string reaches a parser.
//
// The tree equals the renderer's output for equal inputs: the layout,
// the classes, the words and the escaping are the renderer's.
// `web/test/journey.test.ts` (`r_jv_05_web_map_equals_the_renderer_snapshot`)
// checks the serialised tree against the renderer's snapshot
// `crates/fstp-html/testdata/route_stage2.svg`, so a drift on either side
// fails a test.
//
// The builder takes only the closed SVG subset of the renderer and the
// checker: no script, no style, no event attribute, no foreign object,
// no colour of its own (`fill` and `stroke` are `currentColor` or
// `none`, `font-size` a whole number), and links through `safeUrl` only.
//
// Interim, pending Daniel: the map is built in the browser from the
// `proposal.journey` read and the proposal definition below, with the
// renderer's layout, since no read returns the renderer's tree.

import { safeUrl } from "../core/dom.js";
import { ARIA, CAMEL, GLOBAL, SMALL_WHOLE, SUBSET, SVG_NS, isPlain } from "./tree.js";
import { type Journey, type Msg, type NodeStatus, type StateName, PROPOSAL_EDGES, ROUTE_ORDER, kindOf, nodeHref, nodeKey, say, statusOf } from "./model.js";

export { PROPOSAL_EDGES } from "./model.js";
export { type RouteTree, type RouteTreeAttr, type RouteTreeEl, type RouteTreeText, buildRouteTree, readRouteTree } from "./tree.js";

/** One element of the map tree. Attribute names are the renderer's lower-case spelling. */
export interface SvgEl {
  readonly tag: string;
  readonly attrs: readonly (readonly [string, string])[];
  readonly children: readonly (SvgEl | string)[];
}

// ---------------------------------------------------------------------------
// Layout (the renderer's, `fstp_html::route`)
// ---------------------------------------------------------------------------

const NODE_W = 104;
const NODE_H = 62;
const MAIN_Y = 139;
const PAUSE_Y = 249;
const OUTCOME_Y = 359;
const BRACKET_Y = 118;
const LABEL_WIDTH = 17;
const LABEL_LINES = 3;
const LABEL_STEP = 12;

interface Place {
  readonly x: number;
  readonly y: number;
}

const PLACES: Readonly<Record<StateName, Place>> = Object.freeze({
  DRAFT: { x: 8, y: MAIN_Y },
  SUBMITTED: { x: 118, y: MAIN_Y },
  STAGE1: { x: 228, y: MAIN_Y },
  STAGE2: { x: 338, y: MAIN_Y },
  RANKED: { x: 448, y: MAIN_Y },
  IRC_REVIEW: { x: 558, y: MAIN_Y },
  NEGOTIATION: { x: 668, y: MAIN_Y },
  GRANTED: { x: 778, y: MAIN_Y },
  IN_EXECUTION: { x: 888, y: MAIN_Y },
  COMPLETED: { x: 998, y: MAIN_Y },
  DEFERRED: { x: 503, y: PAUSE_Y },
  INELIGIBLE: { x: 118, y: OUTCOME_Y },
  NOT_SELECTED: { x: 338, y: OUTCOME_Y },
  DECLINED: { x: 668, y: OUTCOME_Y },
  WITHDRAWN: { x: 338, y: 14 },
  TERMINATED: { x: 888, y: OUTCOME_Y },
});

const cx = (p: Place): number => p.x + NODE_W / 2;
const cy = (p: Place): number => p.y + NODE_H / 2;
const right = (p: Place): number => p.x + NODE_W;
const bottom = (p: Place): number => p.y + NODE_H;

/** The words of a label, filled greedily into lines (`fstp_html::Lines::wrap`). */
export function wrap(text: string, width: number, max: number): string[] {
  const out: string[] = [];
  const len = (s: string): number => Array.from(s).length;
  for (const word of text.split(" ").filter((w) => w !== "")) {
    const last = out[out.length - 1];
    const fits = last !== undefined && len(last) + 1 + len(word) <= width;
    const full = out.length >= Math.max(max, 1);
    if (last !== undefined && (fits || full)) {
      out[out.length - 1] = `${last} ${word}`;
    } else {
      out.push(word);
    }
  }
  return out;
}

function el(tag: string, attrs: readonly (readonly [string, string])[], children: readonly (SvgEl | string)[] = []): SvgEl {
  return Object.freeze({ tag, attrs: Object.freeze(attrs), children: Object.freeze(children) });
}

const GLYPH: Readonly<Record<NodeStatus, string>> = {
  completed: "✓",
  current: "●",
  upcoming: "○",
  pause: "↺",
  positive_end: "★",
  negative_end: "■",
};

const SVG_CLASS: Readonly<Record<NodeStatus, string>> = {
  completed: "svg-complete",
  current: "svg-current",
  upcoming: "svg-upcoming",
  pause: "svg-upcoming",
  positive_end: "svg-positive",
  negative_end: "svg-negative",
};

function m(key: string, args: Readonly<Record<string, string>> = {}): Msg {
  return { key, args };
}

/** The accessible name of node `s`: "{plain label} ({STATE}), {status words}" (I-96, R-JV-01). */
export function nodeName(s: StateName, status: NodeStatus): string {
  return `${say(m(nodeKey(s)))} (${s}), ${say(m(`journey.route.name.${status}`))}`;
}

function rect(cls: string, x: number, y: number, w: number, h: number, rx: string): SvgEl {
  return el("rect", [
    ["class", cls],
    ["x", String(x)],
    ["y", String(y)],
    ["width", String(w)],
    ["height", String(h)],
    ["rx", rx],
  ]);
}

function nodeEl(j: Journey, page: string, s: StateName): SvgEl {
  const p = PLACES[s];
  const status = statusOf(j, s);
  const name = nodeName(s, status);
  const lines = wrap(say(m(nodeKey(s))), LABEL_WIDTH, LABEL_LINES);
  const centre = p.y + 30;
  const first = centre - Math.trunc(((lines.length - 1) * LABEL_STEP) / 2);
  const kids: SvgEl[] = [el("title", [], [name])];
  if (status === "current") {
    kids.push(rect("current-ring", p.x - 6, p.y - 6, NODE_W + 12, NODE_H + 12, "14"));
  }
  kids.push(
    rect("node-shape", p.x, p.y, NODE_W, NODE_H, status === "negative_end" ? "2" : "10"),
    el(
      "text",
      [
        ["class", "node-glyph"],
        ["x", String(p.x + 9)],
        ["y", String(p.y + 13)],
        ["aria-hidden", "true"],
      ],
      [GLYPH[status]],
    ),
    el(
      "text",
      [
        ["class", "node-label"],
        ["text-anchor", "middle"],
      ],
      lines.map((line, i) =>
        el(
          "tspan",
          [
            ["x", String(cx(p))],
            ["y", String(first + i * LABEL_STEP)],
          ],
          [line],
        ),
      ),
    ),
    el(
      "text",
      [
        ["class", "node-formal"],
        ["x", String(cx(p))],
        ["y", String(p.y + 56)],
        ["text-anchor", "middle"],
      ],
      [s],
    ),
  );
  return el(
    "a",
    [
      ["href", nodeHref(page, s)],
      ["aria-label", name],
      ["class", SVG_CLASS[status]],
    ],
    kids,
  );
}

function edgeEl(j: Journey, from: StateName, to: StateName): SvgEl {
  const f = PLACES[from];
  const t = PLACES[to];
  let cls = "edge";
  if (j.legs.some((l) => l.from === from && l.to === to)) {
    cls += " edge--done";
  }
  if (kindOf(to) === "negative_end") {
    cls += " edge--negative";
  }
  const looped = kindOf(from) === "pause";
  if (looped) {
    cls += " edge--loop";
  }
  const marker = looped ? "url(#arrow-loop)" : "url(#arrow)";
  const id = ["edge-T", from, to].join("-");
  if (f.y === MAIN_Y && t.y === MAIN_Y) {
    const [x1, x2] = f.x < t.x ? [right(f), t.x] : [f.x, right(t)];
    return el("line", [
      ["id", id],
      ["class", cls],
      ["x1", String(x1)],
      ["y1", String(cy(f))],
      ["x2", String(x2)],
      ["y2", String(cy(t))],
      ["marker-end", marker],
    ]);
  }
  let d: string;
  if (t.y === OUTCOME_Y) {
    d = `M${cx(f)} ${bottom(f)} L${cx(t)} ${t.y}`;
  } else if (kindOf(to) === "pause") {
    const left = cx(f) < cx(t);
    const [sx, qx, ex] = left ? [cx(f) + 20, cx(f) + 40, t.x] : [cx(f) - 20, cx(f) - 30, right(t)];
    const qy = left ? cy(t) : t.y + 1;
    d = `M${sx} ${bottom(f)} Q ${qx} ${qy} ${ex} ${t.y + 25}`;
  } else if (looped) {
    const left = cx(t) < cx(f);
    const [sx, qx, ex] = left ? [f.x, cx(t) - 10, cx(t) - 20] : [right(f), cx(t) + 10, cx(t) + 20];
    d = `M${sx} ${f.y + 39} Q ${qx} ${f.y + 51} ${ex} ${bottom(t)}`;
  } else {
    d = `M${cx(f)} ${cy(f)} L${cx(t)} ${cy(t)}`;
  }
  return el("path", [
    ["id", id],
    ["class", cls],
    ["d", d],
    ["marker-end", marker],
  ]);
}

function markerEl(id: string): SvgEl {
  return el(
    "marker",
    [
      ["id", id],
      ["viewbox", "0 0 10 10"],
      ["refx", "9"],
      ["refy", "5"],
      ["markerwidth", "7"],
      ["markerheight", "7"],
      ["orient", "auto-start-reverse"],
    ],
    [
      el("path", [
        ["class", "arrow-head"],
        ["d", "M0 0 L10 5 L0 10 z"],
        ["fill", "currentColor"],
      ]),
    ],
  );
}

function bracketEl(j: Journey): SvgEl {
  const left = PLACES.DRAFT.x;
  const r = right(PLACES.NEGOTIATION);
  const target = PLACES.WITHDRAWN;
  let cls = "edge edge--leave";
  if (j.legs.some((l) => l.to === "WITHDRAWN")) {
    cls += " edge--done";
  }
  const top = MAIN_Y - 9;
  return el(
    "g",
    [["class", "leave"]],
    [
      el("path", [
        ["class", cls],
        ["d", `M${left} ${top} L${left} ${BRACKET_Y} L${r} ${BRACKET_Y} L${r} ${top}`],
      ]),
      el("path", [
        ["class", cls],
        ["d", `M${cx(target)} ${BRACKET_Y} L${cx(target)} ${bottom(target)}`],
        ["marker-end", "url(#arrow)"],
      ]),
      el(
        "text",
        [
          ["class", "node-formal"],
          ["x", String(left + 4)],
          ["y", String(BRACKET_Y - 6)],
        ],
        [say(m("journey.route.leave_label"))],
      ),
    ],
  );
}

/**
 * The map of `j` as a tree: the renderer's `fstp_html::route::svg` for
 * the proposal definition, with node links into `page` and the title
 * naming `subject`.
 */
export function mapTree(j: Journey, page: string, subject: string): SvgEl {
  const pause = PLACES.DEFERRED;
  return el(
    "svg",
    [
      ["class", "route-svg"],
      ["viewbox", "0 0 1110 430"],
      ["role", "group"],
      ["aria-labelledby", "route-title route-desc"],
    ],
    [
      el("title", [["id", "route-title"]], [say(m("journey.route.map_title", { subject }))]),
      el(
        "desc",
        [["id", "route-desc"]],
        [say(m("journey.route.current_is")), " ", say(m(nodeKey(j.state))), ` (${j.state}).`],
      ),
      el("defs", [], [markerEl("arrow"), markerEl("arrow-loop")]),
      ...PROPOSAL_EDGES.map(([f, t]) => edgeEl(j, f, t)),
      el(
        "text",
        [
          ["class", "node-formal"],
          ["x", String(cx(pause))],
          ["y", String(bottom(pause) + 17)],
          ["text-anchor", "middle"],
        ],
        [say(m("journey.route.reenter_label"))],
      ),
      bracketEl(j),
      ...ROUTE_ORDER.map((s) => nodeEl(j, page, s)),
    ],
  );
}

// ---------------------------------------------------------------------------
// Serialising (the renderer's escaping) and building
// ---------------------------------------------------------------------------

function escape(s: string): string {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    if (ch === "&") {
      out += "&amp;";
    } else if (ch === "<") {
      out += "&lt;";
    } else if (ch === ">") {
      out += "&gt;";
    } else if (ch === '"') {
      out += "&quot;";
    } else if (ch === "'") {
      out += "&#39;";
    } else {
      out += isPlain(c) ? ch : "�";
    }
  }
  return out;
}

/** The tree as the renderer writes it inside `svg`: quotes are escaped in text too. */
export function serialise(t: SvgEl): string {
  const attrs = t.attrs.map(([k, v]) => ` ${k}="${escape(v)}"`).join("");
  const kids = t.children.map((c) => (typeof c === "string" ? escape(c) : serialise(c))).join("");
  return `<${t.tag}${attrs}>${kids}</${t.tag}>`;
}

/** Why `toDom` refused a tree. */
export class SvgRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SvgRefusal";
  }
}

function valueAllowed(k: string, v: string): boolean {
  if (k === "fill" || k === "stroke") {
    return v === "currentColor" || v === "none";
  }
  if (k === "font-size") {
    return SMALL_WHOLE.test(v);
  }
  if (k === "marker-start" || k === "marker-end") {
    return /^url\(#[A-Za-z0-9_-]+\)$/.test(v);
  }
  if (k === "href") {
    return safeUrl(v) === v;
  }
  return true;
}

/** Builds `t` as SVG DOM nodes with `createElementNS`. Throws `SvgRefusal` outside the subset. */
export function toDom(t: SvgEl): SVGElement {
  const allowed = SUBSET[t.tag];
  if (allowed === undefined) {
    throw new SvgRefusal(`element ${t.tag} is outside the SVG subset`);
  }
  for (const [k, v] of t.attrs) {
    if (!(GLOBAL.has(k) || allowed.includes(k) || ARIA.test(k)) || !valueAllowed(k, v)) {
      throw new SvgRefusal(`attribute ${k} is outside the SVG subset on ${t.tag}`);
    }
  }
  const node = document.createElementNS(SVG_NS, t.tag);
  for (const [k, v] of t.attrs) {
    node.setAttribute(CAMEL[k] ?? k, v);
  }
  for (const c of t.children) {
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : toDom(c));
  }
  return node;
}
