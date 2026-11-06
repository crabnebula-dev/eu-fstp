// The server's checked map tree in the web app (ADR-015 amendment of
// 2026-11-06, ADR-014 "DOM"; `SPEC/12-journey-ui.md` sections 6, 8.1 and
// 8.3; TH-26, I-68, I-70, R-JV-05, NOTE 10, O-58; review J3-R2; lane j4).
//
// Daniel decided on 2026-11-06 that the map is laid out and rendered on
// the server. `proposal.route_map` returns the renderer's checked tree as
// data, and the browser only validates it against the closed SVG subset
// and builds it with `createElementNS`, because the `/app/` CSP admits no
// markup strings. These tests pin the browser side:
//
// - the reader refuses every tree outside the subset and builds nothing;
// - the build of the server's tree of the prototype state
//   (`crates/fstp-html/testdata/route_stage2.tree.json`, which
//   `r_jv_route_tree.rs` pins to `route::tree`) serialises to the Rust
//   golden map `route_stage2.svg`, byte for byte;
// - a canary label stays a text node;
// - the list follows the server's node statuses verbatim;
// - the progress page shows the map, the list and the help panels only
//   when `proposal.journey` gives `map`, the withdrawal only when it
//   gives `withdraw`, and asks no team read of its own.
//
// Lane j4 test author. Red until the implementer builds the reader, the
// builder, the reply reader and the page: the stubs throw
// `NotImplemented`. Every value here is synthetic.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type NodeStatus, ROUTE_ORDER, type StateName, mapItems, readRouteMap } from "../src/journey/model.js";
import { mountProgress } from "../src/journey/pages.js";
import { buildRouteTree, readRouteTree } from "../src/journey/svg.js";
import { FakeElement, FakeNode, FakeText, elementsCreated, fakeDocument, freshDom, sinkUses } from "./support/fakedom.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { REPO_DIR } from "./support/paths.js";
import { type Rng } from "./support/rng.js";

const SVG_NS = "http://www.w3.org/2000/svg";

/** The progress page of the prototype's proposal; the tree's node links go to it. */
const PAGE = "/app/proposals/1001/progress";

const TESTDATA = join(REPO_DIR, "crates", "fstp-html", "testdata");

/** The server's tree of the prototype state, as the wire gives it. */
function wireTree(): Record<string, unknown> {
  return JSON.parse(readFileSync(join(TESTDATA, "route_stage2.tree.json"), "utf8")) as Record<string, unknown>;
}

/** The Rust golden map of the same state, without its final newline. */
function golden(): string {
  return readFileSync(join(TESTDATA, "route_stage2.svg"), "utf8").replace(/\n$/, "");
}

type WireEl = { tag: string; attrs: { name: string; value: string }[]; children: WireNode[] };
type WireNode = WireEl | { text: string };

function isEl(n: WireNode): n is WireEl {
  return "tag" in n;
}

/** Every element of `t`, in document order, the root first. */
function elements(t: WireEl): WireEl[] {
  const out: WireEl[] = [t];
  for (const c of t.children) {
    if (isEl(c)) {
      out.push(...elements(c));
    }
  }
  return out;
}

/** The writer's escaping inside `svg`: quotes are escaped in text too. */
function escape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** The reference serialisation of a built element, as the renderer spells it. */
function serialise(n: FakeNode): string {
  if (n instanceof FakeText) {
    return escape(n.data);
  }
  if (!(n instanceof FakeElement)) {
    throw new Error("a node that is neither element nor text");
  }
  const attrs = [...n.attributes].map(([k, v]) => ` ${k}="${escape(v)}"`).join("");
  return `<${n.localName}${attrs}>${n.childNodes.map(serialise).join("")}</${n.localName}>`;
}

/** Every element below and including `n`. */
function built(n: FakeElement): FakeElement[] {
  return [n, ...n.descendants()];
}

/** One way out of the closed subset, applied to a fresh copy of the server's tree. */
interface Breach {
  readonly what: string;
  apply(t: WireEl): void;
}

function firstOf(t: WireEl, tag: string): WireEl {
  const e = elements(t).find((x) => x.tag === tag);
  if (e === undefined) {
    throw new Error(`the server's tree has no ${tag}`);
  }
  return e;
}

function setAttr(e: WireEl, name: string, value: string): void {
  const a = e.attrs.find((x) => x.name === name);
  if (a === undefined) {
    e.attrs.push({ name, value });
  } else {
    a.value = value;
  }
}

function deep(n: number): WireEl {
  let e: WireEl = { tag: "g", attrs: [], children: [] };
  for (let i = 0; i < n; i += 1) {
    e = { tag: "g", attrs: [], children: [e] };
  }
  return e;
}

/** TH-26, I-68, I-70: the breaches the subset refuses. */
const BREACHES: readonly Breach[] = [
  { what: "a script element", apply: (t) => t.children.push({ tag: "script", attrs: [], children: [{ text: "alert(1)" }] }) },
  { what: "a foreignObject", apply: (t) => t.children.push({ tag: "foreignObject", attrs: [], children: [] }) },
  { what: "a foreignobject", apply: (t) => t.children.push({ tag: "foreignobject", attrs: [], children: [] }) },
  { what: "an unknown tag", apply: (t) => t.children.push({ tag: "blink", attrs: [], children: [] }) },
  { what: "an image", apply: (t) => t.children.push({ tag: "image", attrs: [{ name: "href", value: "/x.png" }], children: [] }) },
  { what: "a use element", apply: (t) => t.children.push({ tag: "use", attrs: [{ name: "href", value: "#arrow" }], children: [] }) },
  { what: "an animation", apply: (t) => firstOf(t, "rect").children.push({ tag: "animate", attrs: [], children: [] }) },
  { what: "a style element", apply: (t) => t.children.push({ tag: "style", attrs: [], children: [{ text: "*{}" }] }) },
  { what: "an onclick attribute", apply: (t) => setAttr(firstOf(t, "a"), "onclick", "alert(1)") },
  { what: "an onload attribute on svg", apply: (t) => setAttr(t, "onload", "alert(1)") },
  { what: "an onClick attribute", apply: (t) => setAttr(firstOf(t, "rect"), "onClick", "alert(1)") },
  { what: "a style attribute", apply: (t) => setAttr(firstOf(t, "rect"), "style", "fill:red") },
  { what: "a namespaced attribute", apply: (t) => setAttr(firstOf(t, "a"), "xlink:href", PAGE + "#node-DRAFT") },
  { what: "an attribute the element may not carry", apply: (t) => setAttr(firstOf(t, "rect"), "href", PAGE + "#node-DRAFT") },
  { what: "a javascript: link", apply: (t) => setAttr(firstOf(t, "a"), "href", "javascript:alert(1)") },
  { what: "an external link", apply: (t) => setAttr(firstOf(t, "a"), "href", `https://evil.example${PAGE}#node-DRAFT`) },
  { what: "a protocol-relative link", apply: (t) => setAttr(firstOf(t, "a"), "href", `//evil.example${PAGE}#node-DRAFT`) },
  { what: "a link to another page", apply: (t) => setAttr(firstOf(t, "a"), "href", "/app/proposals/1002/progress#node-DRAFT") },
  { what: "a link to no node", apply: (t) => setAttr(firstOf(t, "a"), "href", `${PAGE}#main`) },
  { what: "a colour fill", apply: (t) => setAttr(firstOf(t, "path"), "fill", "red") },
  { what: "a url fill", apply: (t) => setAttr(firstOf(t, "path"), "fill", "url(https://evil.example/p#g)") },
  { what: "an external marker", apply: (t) => setAttr(firstOf(t, "line"), "marker-end", "url(https://evil.example/m#a)") },
  { what: "a text in the svg root", apply: (t) => t.children.push({ text: "loose text" }) },
  { what: "a text in a rect", apply: (t) => firstOf(t, "rect").children.push({ text: "x" }) },
  { what: "a link inside a link", apply: (t) => firstOf(t, "a").children.push({ tag: "a", attrs: [{ name: "href", value: `${PAGE}#node-DRAFT` }], children: [] }) },
  { what: "a root that is not svg", apply: (t) => { t.tag = "g"; } },
  { what: "a member outside the shape", apply: (t) => { (t as unknown as Record<string, unknown>)["html"] = "<b>x</b>"; } },
  { what: "an attribute value that is not a string", apply: (t) => { (t.attrs[0] as unknown as Record<string, unknown>)["value"] = 7; } },
  { what: "attrs that are not an array", apply: (t) => { (t as unknown as Record<string, unknown>)["attrs"] = { class: "route-svg" }; } },
  { what: "a text with a member beside it", apply: (t) => firstOf(t, "title").children.push({ text: "x", tag: "b" } as unknown as WireNode) },
  { what: "a tree deeper than the writer's limit", apply: (t) => t.children.push(deep(300)) },
];

/** The server's tree with `b` applied. */
function breached(b: Breach): WireEl {
  const t = wireTree() as unknown as WireEl;
  b.apply(t);
  return t;
}

/**
 * TH-26, I-68, I-70, ADR-015 amendment: the reader accepts the server's
 * tree and refuses each breach of the closed subset, and a refused tree
 * builds nothing.
 */
test("th26_i68_tree_reader_refuses_every_tree_outside_the_subset", () => {
  freshDom();
  assert(readRouteTree(wireTree(), PAGE) !== null, "the reader accepts the server's tree");
  for (const b of BREACHES) {
    freshDom();
    let got: unknown;
    try {
      got = readRouteTree(breached(b), PAGE);
    } catch (e) {
      if (e instanceof Error && e.name === "NotImplemented") {
        throw e;
      }
      throw new Error(`the reader threw on ${b.what}: ${String(e)}`);
    }
    eq(got, null, `the reader refuses ${b.what}`);
    eq(elementsCreated(), 0, `nothing is drawn for ${b.what}`);
  }
});

/** A breach at a random element of the server's tree. */
function randomBreach(r: Rng): { readonly what: string; readonly tree: WireEl } {
  const t = wireTree() as unknown as WireEl;
  const all = elements(t);
  const at = r.pick(all);
  const kinds: readonly [string, () => void][] = [
    ["a script child", () => at.children.push({ tag: "script", attrs: [], children: [] })],
    ["a foreignObject child", () => at.children.push({ tag: "foreignObject", attrs: [], children: [] })],
    ["an on* attribute", () => setAttr(at, `on${r.pick(["click", "load", "mouseover", "focus"])}`, "x")],
    ["a style attribute", () => setAttr(at, "style", "color:red")],
    ["a colour fill", () => setAttr(at, "fill", r.pick(["red", "#fff", "rgb(0,0,0)", "url(#x)"]))],
    ["a javascript: href", () => setAttr(at, "href", r.pick(["javascript:alert(1)", " javascript:x", "JAVASCRIPT:x"]))],
  ];
  const [what, apply] = r.pick(kinds);
  apply();
  return { what: `${what} on ${at.tag}`, tree: t };
}

/** TH-26, I-68: a breach at any element of the tree is refused, and nothing is drawn. */
test("th26_i68_tree_reader_refuses_a_breach_anywhere", () => {
  forAll(
    randomBreach,
    ({ what, tree }) => {
      freshDom();
      eq(readRouteTree(tree, PAGE), null, `the reader refuses ${what}`);
      eq(elementsCreated(), 0, `nothing is drawn for ${what}`);
    },
    { runs: 200 },
  );
});

/**
 * I-70, TH-26, review J4-REV-1: the closed subset takes the paint the
 * public map sets on itself, as the Rust checker does. `fill` and
 * `stroke` take only `currentColor` or `none`, and `font-size` a whole
 * number from 1 to 99 on `text`. Any other paint is refused, and nothing
 * is drawn for it.
 */
test("i70_tree_reader_takes_only_the_text_colour_as_paint", () => {
  const painted = (tag: string, attrs: readonly (readonly [string, string])[]): WireEl => ({
    tag: "svg",
    attrs: [],
    children: [{ tag, attrs: attrs.map(([name, value]) => ({ name, value })), children: tag === "text" ? [{ text: "STAGE2" }] : [] }],
  });
  const accepted: readonly WireEl[] = [
    painted("rect", [["fill", "none"], ["stroke", "currentColor"]]),
    painted("line", [["stroke", "currentColor"]]),
    painted("path", [["fill", "none"], ["stroke", "currentColor"]]),
    painted("text", [["fill", "currentColor"], ["font-size", "9"]]),
  ];
  for (const t of accepted) {
    freshDom();
    assert(readRouteTree(t, PAGE) !== null, `the reader accepts ${show(t)}`);
  }
  const refused: readonly WireEl[] = [
    painted("rect", [["stroke", "red"]]),
    painted("rect", [["stroke", "url(#x)"]]),
    painted("line", [["fill", "none"]]),
    painted("text", [["stroke", "currentColor"]]),
    painted("text", [["font-size", "10px"]]),
    painted("text", [["font-size", "0"]]),
    painted("text", [["font-size", "100"]]),
    painted("rect", [["font-size", "10"]]),
  ];
  for (const t of refused) {
    freshDom();
    eq(readRouteTree(t, PAGE), null, `the reader refuses ${show(t)}`);
    eq(elementsCreated(), 0, `nothing is drawn for ${show(t)}`);
  }
});

/**
 * ADR-015 amendment, R-JV-05, ADR-014: the browser's build of the
 * server's tree of the prototype state serialises to the Rust golden map
 * byte for byte, through `createElementNS` in the SVG namespace and no
 * HTML sink, one element per tree element.
 */
test("adr015_r_jv_05_web_build_of_the_server_tree_serialises_to_the_golden", () => {
  freshDom();
  const wire = wireTree() as unknown as WireEl;
  const t = readRouteTree(wire, PAGE);
  assert(t !== null, "the reader accepts the server's tree");
  const svg = buildRouteTree(t);
  assert(svg instanceof FakeElement, "the build is an element");
  eq(serialise(svg), golden(), "the web build equals fstp_html::route::svg");
  const els = built(svg);
  eq(els.length, elements(wire).length, "one element per tree element");
  eq(elementsCreated(), els.length, "every element came from createElementNS");
  for (const e of els) {
    eq(e.namespaceURI, SVG_NS, `${e.localName} is in the SVG namespace`);
  }
  eq(sinkUses, [], "no HTML sink");
});

/** I-68, TW-2: a canary label in the server's tree builds as one text node, never as markup. */
test("i68_tree_canary_label_stays_a_text_node", () => {
  freshDom();
  const canary = "<script>alert('j4')</script> & \"x\" <img src=x onerror=alert(1)>";
  const wire = wireTree() as unknown as WireEl;
  const title = firstOf(wire, "title");
  title.children = [{ text: canary }];
  const t = readRouteTree(wire, PAGE);
  assert(t !== null, "a canary text is text, so the reader accepts it");
  const svg = buildRouteTree(t);
  assert(svg instanceof FakeElement, "the build is an element");
  const names = built(svg).map((e) => e.localName);
  for (const bad of ["script", "img"]) {
    assert(!names.includes(bad), `I-68: a ${bad} element was built`);
  }
  const shown = built(svg).find((e) => e.localName === "title");
  assert(shown !== undefined, "the title is built");
  eq(shown.childNodes.length, 1, "one text node");
  const only = shown.childNodes[0];
  assert(only instanceof FakeText && only.data === canary, `the canary shows intact: ${show(only)}`);
  assert(serialise(svg).includes("&lt;script&gt;"), "the canary serialises escaped");
  eq(sinkUses, [], "no HTML sink");
});

/** The node statuses of the prototype state, as the server sends them. */
function stage2Nodes(): { state: StateName; status: NodeStatus }[] {
  const done: readonly StateName[] = ["DRAFT", "SUBMITTED", "STAGE1"];
  const negative: readonly StateName[] = ["INELIGIBLE", "NOT_SELECTED", "DECLINED", "WITHDRAWN", "TERMINATED"];
  return ROUTE_ORDER.map((state) => {
    const status: NodeStatus = done.includes(state)
      ? "completed"
      : state === "STAGE2"
        ? "current"
        : state === "COMPLETED"
          ? "positive_end"
          : state === "DEFERRED"
            ? "pause"
            : negative.includes(state)
              ? "negative_end"
              : "upcoming";
    return { state, status };
  });
}

function mapReply(nodes: readonly { state: StateName; status: NodeStatus }[], tree: unknown = wireTree()): Record<string, unknown> {
  return { proposal: "1001", tree, nodes };
}

/** ADR-015 amendment, TH-26: the reply reader takes the server's reply and refuses one whose tree breaches the subset. */
test("adr015_th26_route_map_reader_takes_the_reply_and_refuses_a_breach", () => {
  freshDom();
  assert(readRouteMap(mapReply(stage2Nodes()), PAGE) !== null, "the reply reads");
  const script = BREACHES[0];
  assert(script !== undefined, "a breach");
  eq(readRouteMap(mapReply(stage2Nodes(), breached(script)), PAGE), null, "a script in the tree");
  eq(readRouteMap({ ...mapReply(stage2Nodes()), title: "free text" }, PAGE), null, "a member outside the shape");
  eq(readRouteMap(mapReply([...stage2Nodes(), { state: "DRAFT", status: "completed" }]), PAGE), null, "a node twice");
  eq(readRouteMap(mapReply(stage2Nodes().slice(1)), PAGE), null, "a node missing");
  eq(elementsCreated(), 0, "reading builds nothing");
});

const STATUSES: readonly NodeStatus[] = ["completed", "upcoming", "pause", "positive_end", "negative_end"];

/** Statuses in route order with one current node. */
function nodesOf(r: Rng): { state: StateName; status: NodeStatus }[] {
  const at = r.below(ROUTE_ORDER.length);
  return ROUTE_ORDER.map((state, i) => ({ state, status: i === at ? "current" : r.pick(STATUSES) }));
}

/**
 * R-JV-05, ADR-015 amendment ("never from its own layout"): the list
 * holds every node in route order with the status the server sent,
 * verbatim, whatever the browser would have computed.
 */
test("r_jv_05_list_follows_the_server_node_statuses", () => {
  forAll(nodesOf, (nodes) => {
    const m = readRouteMap(mapReply(nodes), PAGE);
    assert(m !== null, `the reply reads: ${show(nodes)}`);
    const items = mapItems(m, PAGE);
    eq(
      items.map((i) => [i.state, i.status]),
      nodes.map((n) => [n.state, n.status]),
      "the server's statuses",
    );
    for (const i of items) {
      eq(i.href, `${PAGE}#node-${i.state}`, `${i.state} links to its panel`);
    }
  });
});

// ---------------------------------------------------------------------------
// The progress page
// ---------------------------------------------------------------------------

/** The `proposal.journey` reply of the prototype state, with the read flags. */
function journeyReply(flags: { map: boolean; withdraw: boolean; strip: boolean }): Record<string, unknown> {
  return {
    proposal: "1001",
    state: "STAGE2",
    since: "1793750400000000",
    seq: "13",
    legs: [
      { from: "DRAFT", to: "SUBMITTED", at: "1793750400000000", seq: "11" },
      { from: "SUBMITTED", to: "STAGE1", at: "1793750460000000", seq: "12" },
      { from: "STAGE1", to: "STAGE2", at: "1793750520000000", seq: "13" },
    ],
    strip: flags.strip,
    map: flags.map,
    withdraw: flags.withdraw,
    overlay: null,
  };
}

/** Mounts the progress page of 1001 over a fake cell, and gives the paths it asked for. */
async function mounted(flags: { map: boolean; withdraw: boolean; strip: boolean }): Promise<string[]> {
  freshDom();
  const asked: string[] = [];
  const g = globalThis as unknown as Record<string, unknown>;
  g["location"] = { pathname: PAGE, hash: "", search: "", origin: "https://cell-a.e2e.invalid", href: `https://cell-a.e2e.invalid${PAGE}` };
  g["fetch"] = async (input: unknown): Promise<Response> => {
    const path = new URL(String(input), "https://cell-a.e2e.invalid").pathname;
    asked.push(path);
    const json = (v: unknown, status = 200): Response =>
      new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
    if (path.endsWith("/proposals/1001/journey")) {
      return json(journeyReply(flags));
    }
    if (path.endsWith("/proposals/1001/route-map")) {
      return flags.map ? json(mapReply(stage2Nodes())) : json({ code: "refused", rule: "R-AC-01" }, 403);
    }
    return json({ code: "not_found", rule: "Input" }, 404);
  };
  mountProgress("1001");
  for (let i = 0; i < 20; i += 1) {
    await new Promise((r) => setTimeout(r, 0));
  }
  return asked;
}

function byId(id: string): FakeElement | null {
  return fakeDocument.getElementById(id);
}

/**
 * Section 8.1, review J3-R2, ADR-015 amendment: with `map` set, the page
 * builds the server's tree (no layout of its own), the list and the help
 * panels, and asks no team read of its own.
 */
test("adr015_j3r2_progress_page_shows_the_server_map_when_the_flag_is_set", async () => {
  const asked = await mounted({ map: true, withdraw: false, strip: false });
  const section = byId("journey-map");
  assert(section !== null, `the map section shows: asked ${show(asked)}`);
  const svg = section.descendants().find((e) => e.localName === "svg");
  assert(svg !== undefined, "the map is drawn");
  eq(svg.namespaceURI, SVG_NS, "in the SVG namespace");
  eq(serialise(svg), golden(), "the page draws the server's tree");
  assert(byId("journey-list") !== null && byId("journey-help") !== null, "the list and the help panels");
  assert(asked.some((p) => p.endsWith("/proposals/1001/route-map")), "the page reads the route map");
  assert(!asked.some((p) => p.endsWith("/me/proposals")), `J3-R2: no proposal.list_own read: ${show(asked)}`);
  eq(sinkUses, [], "no HTML sink");
});

/** NOTE 10, review J3-R2: the withdrawal shows only when the read gives `withdraw`. */
test("r_sb_03_note10_progress_page_shows_the_withdrawal_only_with_its_flag", async () => {
  await mounted({ map: true, withdraw: true, strip: false });
  assert(byId("journey-map") !== null, "the lead's map");
  assert(byId("journey-withdraw") !== null, "the lead's withdrawal");
  await mounted({ map: true, withdraw: false, strip: false });
  assert(byId("journey-map") !== null, "a team member's map");
  eq(byId("journey-withdraw"), null, "no withdrawal without the flag");
});

/**
 * Section 8.3, O-58, review J3-R2: without `map` the page shows no map,
 * list, help panels or withdrawal, never reads the route map, and shows
 * the strip only when the read gives `strip`.
 */
test("r_jv_03_o58_progress_page_shows_no_map_without_the_flag", async () => {
  for (const strip of [true, false]) {
    const asked = await mounted({ map: false, withdraw: true, strip });
    for (const id of ["journey-map", "journey-list", "journey-help", "journey-withdraw"]) {
      eq(byId(id), null, `no ${id} (strip ${strip})`);
    }
    assert(!asked.some((p) => p.endsWith("/route-map")), `no route map read: ${show(asked)}`);
    assert(!asked.some((p) => p.endsWith("/me/proposals")), `J3-R2: no proposal.list_own read: ${show(asked)}`);
    const svgs = fakeDocument.documentElement.descendants().filter((e) => e.localName === "svg");
    eq(svgs.length, 0, "no map is drawn");
    const strips = fakeDocument.documentElement.descendants().filter((e) => (e.getAttribute("class") ?? "").split(" ").includes("strip"));
    eq(strips.length > 0, strip, `the strip follows the read (strip ${strip})`);
  }
});
