// router.ts: paths against generated segments (M4 design section 3.9,
// ADR-014). Every path matches at most one route, and no parameter
// reaches a page unchecked.

import { readExpectations } from "../fuzz/harness.js";
import { TABLE } from "../fuzz/router_match.fuzz.js";
import type { RouteDef, RouterModule } from "./support/contract.js";
import { pathish } from "./support/gen.js";
import { assert, eq, forAll, show, test, thrown } from "./support/harness.js";
import { core } from "./support/load.js";
import type { Rng } from "./support/rng.js";
import { refMatch, tableFault } from "./reference/route_ref.js";

const any = (): boolean => true;
const digits = (s: string): boolean => /^[0-9]+$/.test(s);

function refuses(router: RouterModule, defs: readonly RouteDef[], what: string): void {
  const e = thrown(() => router.createRouter(defs), what);
  assert(e instanceof router.RouterError, `${what}: threw ${show(String(e))}, not a RouterError`);
}

/** ADR-014: the shared corpus of paths matches as listed, with decoded parameters. */
test("adr014_router_matches_the_corpus", async () => {
  const router = await core("router");
  const r = router.createRouter(TABLE);
  for (const e of readExpectations("router_match")) {
    const want = e.verdict === "none" ? null : { name: e.verdict, params: JSON.parse(e.extra ?? "{}") as unknown };
    eq(r.match(e.input), want, `line ${e.line}: ${show(e.input)}`);
  }
});

/** ADR-014: a malformed table is refused when the router is built. */
test("adr014_router_refuses_malformed_tables", async () => {
  const router = await core("router");
  const cases: readonly [string, readonly RouteDef[]][] = [
    ["duplicate name", [
      { name: "a", pattern: "/a", segments: {} },
      { name: "a", pattern: "/b", segments: {} },
    ]],
    ["no leading slash", [{ name: "a", pattern: "a", segments: {} }]],
    ["empty pattern", [{ name: "a", pattern: "", segments: {} }]],
    ["empty segment", [{ name: "a", pattern: "/a//b", segments: {} }]],
    ["trailing slash", [{ name: "a", pattern: "/a/", segments: {} }]],
    ["partial-segment brace", [{ name: "a", pattern: "/a{x}", segments: { x: any } }]],
    ["unclosed brace", [{ name: "a", pattern: "/{x", segments: { x: any } }]],
    ["empty parameter", [{ name: "a", pattern: "/{}", segments: {} }]],
    ["parameter twice", [{ name: "a", pattern: "/{x}/{x}", segments: { x: any } }]],
    ["parameter without check", [{ name: "a", pattern: "/{x}", segments: {} }]],
    ["check without parameter", [{ name: "a", pattern: "/x", segments: { x: any } }]],
    ["dot segment", [{ name: "a", pattern: "/a/../b", segments: {} }]],
  ];
  for (const [what, defs] of cases) {
    assert(tableFault(defs) !== null, `the reference refuses the case ${what}`);
    refuses(router, defs, what);
  }
});

/** ADR-014: two routes that can match one path are refused when the router is built. */
test("adr014_router_refuses_ambiguous_tables", async () => {
  const router = await core("router");
  const cases: readonly [string, readonly RouteDef[]][] = [
    ["literal passes the other check", [
      { name: "item", pattern: "/a/{x}", segments: { x: any } },
      { name: "fixed", pattern: "/a/b", segments: {} },
    ]],
    ["two parameters", [
      { name: "one", pattern: "/a/{x}", segments: { x: digits } },
      { name: "two", pattern: "/a/{y}", segments: { y: (s) => /^[a-z]+$/.test(s) } },
    ]],
    ["crossed", [
      { name: "one", pattern: "/a/{x}/c", segments: { x: any } },
      { name: "two", pattern: "/a/b/{y}", segments: { y: any } },
    ]],
    ["same pattern", [
      { name: "one", pattern: "/a", segments: {} },
      { name: "two", pattern: "/a", segments: {} },
    ]],
  ];
  for (const [what, defs] of cases) {
    assert(tableFault(defs) !== null, `the reference refuses the case ${what}`);
    refuses(router, defs, what);
  }
});

/** ADR-014: a literal beside a parameter whose check refuses that literal is not ambiguous. */
test("adr014_router_accepts_literal_beside_param_whose_check_refuses_it", async () => {
  const router = await core("router");
  const defs: readonly RouteDef[] = [
    { name: "proposal_new", pattern: "/proposals/new", segments: {} },
    { name: "proposal", pattern: "/proposals/{proposal}", segments: { proposal: (s) => /^p[0-9]+$/.test(s) } },
  ];
  const r = router.createRouter(defs);
  eq(r.match("/proposals/new"), { name: "proposal_new", params: {} }, "literal route");
  eq(r.match("/proposals/p1"), { name: "proposal", params: { proposal: "p1" } }, "parameter route");
  eq(r.match("/proposals/x"), null, "a segment its check refuses");
});

const LITERALS: readonly string[] = ["a", "b", "c"];

function genTable(r: Rng): RouteDef[] {
  const checks: readonly ((s: string) => boolean)[] = [any, digits, (s) => s === "b", (s) => s !== "b"];
  const n = 1 + r.below(4);
  const defs: RouteDef[] = [];
  for (let i = 0; i < n; i += 1) {
    const len = r.below(3);
    const segs: string[] = [];
    const segments: Record<string, (s: string) => boolean> = {};
    for (let k = 0; k < len; k += 1) {
      if (r.bool()) {
        segs.push(r.pick(LITERALS));
      } else {
        const name = `p${k}`;
        segs.push(`{${name}}`);
        segments[name] = r.pick(checks);
      }
    }
    defs.push({ name: `r${i}`, pattern: `/${segs.join("/")}`, segments });
  }
  return defs;
}

/**
 * ADR-014: over random tables, the router is built exactly when the
 * reference finds no fault, and then every path gets the reference match.
 */
test("adr014_router_table_acceptance_and_matching_follow_the_reference", async () => {
  const router = await core("router");
  forAll(
    (r) => ({ defs: genTable(r), paths: Array.from({ length: 12 }, () => pathish(r, [...LITERALS, "1", "22"])) }),
    ({ defs, paths }) => {
      const fault = tableFault(defs);
      let built;
      try {
        built = router.createRouter(defs);
      } catch (e) {
        assert(e instanceof router.RouterError, `createRouter threw ${show(String(e))}, not a RouterError`);
        assert(fault !== null, `a valid table was refused: ${show(defs.map((d) => d.pattern))}`);
        return;
      }
      assert(fault === null, `a faulty table was built (${String(fault)}): ${show(defs.map((d) => d.pattern))}`);
      for (const p of paths) {
        eq(built.match(p), refMatch(defs, p), `match of ${show(p)} in ${show(defs.map((d) => d.pattern))}`);
      }
    },
    { runs: 800 },
  );
});

/** ADR-014: on generated paths over the application-shaped table, the router gives the reference match. */
test("adr014_router_matches_agree_with_reference_on_generated_paths", async () => {
  const router = await core("router");
  const r = router.createRouter(TABLE);
  const literals = ["calls", "guide", "proposals", "new", "programmes", "draft", "p", "search", "supersafe"];
  forAll(
    (g) => pathish(g, literals),
    (p) => {
      eq(r.match(p), refMatch(TABLE, p), `match of ${show(p)}`);
    },
    { runs: 3000 },
  );
});
