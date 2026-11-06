// The web progress map against the renderer (lane j3, implementer;
// ADR-015 "Rendering", ADR-014 "DOM"; `SPEC/12-journey-ui.md` section 6).
//
// The `/app/` pages cannot take the renderer's SVG markup as a string
// under Trusted Types, so `web/src/journey/svg.ts` builds the same tree
// with `createElementNS`. These tests pin that tree to the renderer:
//
// - r_jv_05_web_map_equals_the_renderer_snapshot: the serialised tree of
//   the design's STAGE2 state equals the snapshot that
//   `crates/fstp-html/tests/r_jv_route_golden.rs` pins for
//   `fstp_html::route::svg`, byte for byte.
// - r_jv_01_web_map_names_every_node: over generated routes, the map has
//   sixteen node links in route order, each named by plain label, formal
//   state and status words (I-96), and one current ring.
// - th26_web_map_stays_in_the_svg_subset: the builder refuses an element
//   or attribute outside the closed SVG subset, and a colour of its own.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { VALIDATORS } from "../src/gen/api.js";
import { type Journey, type StateName, ROUTE_ORDER, readJourney } from "../src/journey/model.js";
import { PROPOSAL_EDGES, type SvgEl, SvgRefusal, mapTree, serialise, toDom } from "../src/journey/svg.js";
import { assert, eq, forAll, test } from "./support/harness.js";
import { REPO_DIR } from "./support/paths.js";
import { type Rng } from "./support/rng.js";

const PAGE = "/app/proposals/1001/progress";

const TERMINAL: readonly StateName[] = ["INELIGIBLE", "NOT_SELECTED", "DECLINED", "WITHDRAWN", "TERMINATED", "COMPLETED"];
const WITHDRAW_FROM: readonly StateName[] = ["DRAFT", "SUBMITTED", "STAGE1", "STAGE2", "RANKED", "IRC_REVIEW", "DEFERRED", "NEGOTIATION"];

function journeyOf(legs: readonly (readonly [StateName, StateName])[], at: StateName): Journey {
  const v = {
    proposal: "1001",
    state: at,
    since: "1793750400000000",
    seq: String(legs.length + 10),
    legs: legs.map(([from, to], i) => ({ from, to, at: String(1793750400000000 + i * 60_000_000), seq: String(i + 11) })),
    strip: false,
    map: false,
    withdraw: false,
    overlay: null,
  };
  const check = VALIDATORS["proposal.journey"];
  assert(check !== undefined && check(v), "the sample fits the generated validator");
  const j = readJourney(v);
  assert(j !== null, "readJourney reads the sample");
  return j;
}

function walk(r: Rng): Journey {
  let at: StateName = "DRAFT";
  const legs: (readonly [StateName, StateName])[] = [];
  const steps = r.between(0, 12);
  for (let i = 0; i < steps && !TERMINAL.includes(at); i += 1) {
    const next: StateName[] = PROPOSAL_EDGES.filter(([f]) => f === at).map(([, t]) => t);
    if (WITHDRAW_FROM.includes(at)) {
      next.push("WITHDRAWN");
    }
    const to = r.pick(next);
    legs.push([at, to]);
    at = to;
  }
  return journeyOf(legs, at);
}

function walkTree(t: SvgEl, f: (e: SvgEl) => void): void {
  f(t);
  for (const c of t.children) {
    if (typeof c !== "string") {
      walkTree(c, f);
    }
  }
}

function attr(e: SvgEl, k: string): string | undefined {
  return e.attrs.find(([n]) => n === k)?.[1];
}

/** ADR-015, R-JV-05: the web map of the prototype state equals the renderer's snapshot. */
test("r_jv_05_web_map_equals_the_renderer_snapshot", () => {
  const j = journeyOf(
    [
      ["DRAFT", "SUBMITTED"],
      ["SUBMITTED", "STAGE1"],
      ["STAGE1", "STAGE2"],
    ],
    "STAGE2",
  );
  const want = readFileSync(join(REPO_DIR, "crates/fstp-html/testdata/route_stage2.svg"), "utf8");
  eq(`${serialise(mapTree(j, PAGE, "CSW-2026-0042"))}\n`, want, "the web map equals fstp_html::route::svg");
});

/** I-96, R-JV-01, R-JV-05: sixteen node links in route order, each named by label, state and status. */
test("r_jv_01_web_map_names_every_node", () => {
  forAll(walk, (j) => {
    const links: SvgEl[] = [];
    let rings = 0;
    walkTree(mapTree(j, PAGE, "1001"), (e) => {
      if (e.tag === "a") {
        links.push(e);
      }
      if ((attr(e, "class") ?? "").split(" ").includes("current-ring")) {
        rings += 1;
      }
    });
    eq(
      links.map((a) => (attr(a, "href") ?? "").replace(`${PAGE}#node-`, "")),
      [...ROUTE_ORDER],
      "route order",
    );
    for (const a of links) {
      const name = attr(a, "aria-label") ?? "";
      assert(/^.+ \([A-Z0-9_]+\), .+$/.test(name), `the node is named: ${name}`);
      const first = a.children[0];
      assert(typeof first !== "string" && first?.tag === "title" && first.children.join("") === name, `the title repeats ${name}`);
    }
    eq(rings, 1, "one current ring");
  });
});

/** TH-26, I-68, I-70: the builder refuses what the closed SVG subset leaves out. */
test("th26_web_map_stays_in_the_svg_subset", () => {
  const bad: SvgEl[] = [
    { tag: "script", attrs: [], children: [] },
    { tag: "foreignObject", attrs: [], children: [] },
    { tag: "rect", attrs: [["onclick", "x"]], children: [] },
    { tag: "rect", attrs: [["style", "fill:red"]], children: [] },
    { tag: "path", attrs: [["fill", "red"]], children: [] },
    { tag: "path", attrs: [["marker-end", "url(https://evil.example/m#a)"]], children: [] },
    { tag: "a", attrs: [["href", "javascript:alert(1)"]], children: [] },
  ];
  for (const t of bad) {
    let refused = false;
    try {
      toDom(t);
    } catch (e) {
      refused = e instanceof SvgRefusal;
    }
    assert(refused, `toDom refuses ${t.tag} ${JSON.stringify(t.attrs)}`);
  }
});
