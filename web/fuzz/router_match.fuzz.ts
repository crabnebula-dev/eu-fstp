// Fuzz target `router_match` for web/src/core/router.ts (M4 design section
// 9, ADR-014, TH-26, H-05).
//
// Checks, for any path against a fixed table:
// - `match` never throws;
// - every path matches at most one route of the table;
// - the router's answer equals the reference matcher's;
// - no match carries a parameter that its segment check did not accept,
//   and each check sees only decoded segments that passed the path rules.

import { assert, eq, show } from "../test/support/harness.js";
import type { RouteDef, RouteMatch, RouterModule } from "../test/support/contract.js";
import { core } from "../test/support/load.js";
import { pathSegments, refMatch, refMatches } from "../test/reference/route_ref.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

const callId = (s: string): boolean => /^c[0-9]{1,6}$/.test(s);
const proposalId = (s: string): boolean => /^p[0-9]{1,6}$/.test(s);
const slug = (s: string): boolean => /^[a-z][a-z0-9-]{0,31}$/.test(s);
const term = (s: string): boolean => s.length > 0 && s.length <= 64;

/** The fixed route table, shaped like the application's pages. */
export const TABLE: readonly RouteDef[] = [
  { name: "home", pattern: "/", segments: {} },
  { name: "calls", pattern: "/calls", segments: {} },
  { name: "call", pattern: "/calls/{call}", segments: { call: callId } },
  { name: "call_guide", pattern: "/calls/{call}/guide", segments: { call: callId } },
  { name: "proposal_new", pattern: "/proposals/new", segments: {} },
  { name: "proposal", pattern: "/proposals/{proposal}", segments: { proposal: proposalId } },
  { name: "draft", pattern: "/programmes/{programme}/draft", segments: { programme: slug } },
  { name: "public_call", pattern: "/p/{slug}/calls/{call}", segments: { slug, call: callId } },
  { name: "search", pattern: "/search/{term}", segments: { term } },
];

/**
 * The table with every check wrapped, so the target sees each segment a
 * check is asked about. `seen` collects them.
 */
function watched(seen: string[]): RouteDef[] {
  return TABLE.map((d) => ({
    name: d.name,
    pattern: d.pattern,
    segments: Object.fromEntries(
      Object.entries(d.segments).map(([k, f]) => [
        k,
        (s: string): boolean => {
          seen.push(s);
          return f(s);
        },
      ]),
    ),
  }));
}

export const target: FuzzTarget = {
  name: "router_match",
  seeds: () => readExpectations("router_match").map((e) => e.input),
  dictionary: [
    "/",
    "calls",
    "c1",
    "guide",
    "proposals",
    "new",
    "p1",
    "programmes",
    "draft",
    "p",
    "supersafe",
    "search",
    "%",
    "%2F",
    "%2e",
    "%C3%A9",
    "%00",
    "%25",
    "%2541",
    "%C2%85",
    "..",
    ".",
    "?",
    "#",
  ],
  prepare: async () => checkerFor(await core("router")),
};

/** The checker over any module of the router contract. */
export function checkerFor(router: RouterModule): Checker {
  const seen: string[] = [];
  const r = router.createRouter(watched(seen));
  return (path: string) => {
    seen.length = 0;
    let got: RouteMatch | null;
    try {
      got = r.match(path);
    } catch (e) {
      throw new Error(`match threw on ${show(path)}: ${String(e)}`);
    }
    const all = refMatches(TABLE, path);
    assert(all.length <= 1, `${show(path)} matches ${all.length} routes of an accepted table`);
    eq(got, refMatch(TABLE, path), `match of ${show(path)}`);
    const decoded = pathSegments(path);
    for (const s of seen) {
      assert(
        decoded !== null && decoded.includes(s),
        `a segment check saw ${show(s)}, which is not a checked segment of ${show(path)}`,
      );
    }
    if (got !== null) {
      const name = got.name;
      const def = TABLE.find((d) => d.name === name);
      assert(def !== undefined, `unknown route ${name}`);
      for (const [k, v] of Object.entries(got.params)) {
        const check = def.segments[k];
        assert(check !== undefined && check(v), `parameter ${k}=${show(v)} of ${name} did not pass its check`);
      }
    }
  };
}
