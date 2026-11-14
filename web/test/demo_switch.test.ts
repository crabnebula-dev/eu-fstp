// The demo switcher's reader (lane m4/demo-switch): the shape check of
// `GET /auth/demo-signin/people` and `POST /auth/demo-signin/switch`.
// Test only: the demo modules ship in no cell but `fstp-e2e-cell`
// (layering rule A9). Every person here is synthetic.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { DEMO_EN } from "../src/demo/messages.en.js";
import { MAX_PEOPLE, MAX_TEXT, currentPerson, readScene, readToken } from "../src/demo/people.js";
import type { Rng } from "./support/rng.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { WEB_DIR } from "./support/paths.js";

/** A well-formed person. */
function person(account: string, current = false): Record<string, unknown> {
  return {
    account,
    name: `Committee member R${account}`,
    email: `synthetic-r${account}@e2e.invalid`,
    roles: "Committee member",
    does: "Committee member: 2 review assignments to work on, 2 to declare first.",
    current,
  };
}

/** A well-formed reply. */
function reply(): Record<string, unknown> {
  return { scene: "stage1", people: [person("101", true), person("102"), person("103")] };
}

/** ADR-014, A9, R-NF-03: a well-formed reply reads as it came, in order, with the current person marked. */
test("adr014_demo_switch_reads_the_people_of_the_scene", () => {
  const s = readScene(reply());
  assert(s !== null, "the reply reads");
  eq(s.scene, "stage1", "the scene");
  eq(s.people.map((p) => p.account), ["101", "102", "103"], "the order of the cell");
  eq(currentPerson(s)?.account, "101", "the current person");
  eq(s.people[1], person("102"), "every member");
  const none = readScene({ scene: "", people: [person("7")] });
  assert(none !== null && currentPerson(none) === null, "a scene may name no current person");
});

/** ADR-014, A9: a reply with one member off is refused whole, never read in part. */
test("adr014_demo_switch_refuses_a_malformed_reply", () => {
  const bad: [string, unknown][] = [
    ["null", null],
    ["an array", [reply()]],
    ["no people", { scene: "x" }],
    ["people not a list", { scene: "x", people: {} }],
    ["no scene", { people: [] }],
    ["a scene too long", { scene: "x".repeat(MAX_TEXT + 1), people: [] }],
    ["two current people", { scene: "x", people: [person("1", true), person("2", true)] }],
    ["a repeated account", { scene: "x", people: [person("1"), person("1")] }],
    ["too many people", { scene: "x", people: Array.from({ length: MAX_PEOPLE + 1 }, (_, i) => person(String(i + 1))) }],
  ];
  for (const [field, value] of [
    ["account", 101],
    ["account", "0101"],
    ["account", "-1"],
    ["account", "1e3"],
    ["account", ""],
    ["name", ""],
    ["name", "  "],
    ["roles", undefined],
    ["does", 3],
    ["email", null],
    ["current", "true"],
    ["name", "x".repeat(MAX_TEXT + 1)],
  ] as const) {
    const p = person("5");
    if (value === undefined) {
      delete p[field];
    } else {
      p[field] = value;
    }
    bad.push([`${field} = ${show(value)}`, { scene: "x", people: [person("4"), p] }]);
  }
  for (const [why, body] of bad) {
    eq(readScene(body), null, `refused: ${why}`);
  }
});

/** ADR-014, A9: a switch token is read only in the grammar the cell issues. */
test("adr014_demo_switch_reads_a_token_in_the_cell_grammar", () => {
  const t = "0123456789abcdef0123456789abcdef";
  eq(readToken({ token: t }), t, "a token of the cell");
  for (const body of [null, {}, { token: t.toUpperCase() }, { token: t.slice(1) }, { token: `${t}0` }, { token: 1 }, [t], t]) {
    eq(readToken(body), null, `refused: ${show(body)}`);
  }
});

/** A random JSON-ish value of depth at most `depth`. */
function value(r: Rng, depth: number): unknown {
  const pick = r.below(depth <= 0 ? 6 : 9);
  switch (pick) {
    case 0:
      return null;
    case 1:
      return r.bool();
    case 2:
      return r.between(-5, 500);
    case 3:
      return r.pick(["", "1", "0101", "stage1", "x".repeat(r.below(40)), "0123456789abcdef0123456789abcdef"]);
    case 4:
      return String(r.below(1000));
    case 5:
      return undefined;
    case 6:
      return Array.from({ length: r.below(4) }, () => value(r, depth - 1));
    default: {
      const o: Record<string, unknown> = {};
      for (const k of ["scene", "people", "account", "name", "email", "roles", "does", "current", "token"]) {
        if (r.bool()) {
          o[k] = k === "people" && r.bool() ? [person(String(r.below(9))), value(r, depth - 1)] : value(r, depth - 1);
        }
      }
      return o;
    }
  }
}

/** ADR-014, A9: the reader never throws, and what it accepts keeps every rule of a reply. */
test("adr014_demo_switch_reader_never_throws_on_any_value", () => {
  forAll(
    (r) => value(r, 3),
    (v) => {
      const s = readScene(v);
      if (s !== null) {
        assert(s.people.filter((p) => p.current).length <= 1, "at most one current person");
        assert(new Set(s.people.map((p) => p.account)).size === s.people.length, "no account repeats");
        assert(s.people.every((p) => /^(?:0|[1-9][0-9]*)$/.test(p.account)), "every account is decimal");
      }
      const t = readToken(v);
      assert(t === null || /^[0-9a-f]{32}$/.test(t), "a token is 32 lowercase hex digits");
    },
  );
});

/** R-NF-04: the switcher's strings come from the catalogue, each one sentence under 40 words with no em dash. */
test("r_nf_04_demo_switch_messages_are_short_and_plain", () => {
  for (const [id, m] of Object.entries(DEMO_EN.messages)) {
    assert(!m.includes("—"), `${id} holds no em dash`);
    for (const sentence of m.split(/(?<=\.)\s+/)) {
      assert(sentence.split(/\s+/).length < 40, `${id}: a sentence under 40 words`);
    }
  }
});

/** Every `.ts` file below `dir`. */
function sources(dir: string, out: string[]): void {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      sources(p, out);
    } else if (name.endsWith(".ts")) {
      out.push(p);
    }
  }
}

/**
 * A9: no platform module of `web/src` imports a demo module or names a
 * demo route, so the `/app/` bundle never carries the switcher. Only
 * `web/src/demo` may. The Rust half is `crates/fstp-web/tests/demo_signin_absent.rs`.
 */
test("adr014_demo_switch_absent_from_platform_web_sources", () => {
  const src = join(WEB_DIR, "src");
  const files: string[] = [];
  sources(src, files);
  const demo = join(src, "demo");
  const leaks: string[] = [];
  let scanned = 0;
  for (const f of files) {
    if (f.startsWith(`${demo}/`)) {
      continue;
    }
    scanned += 1;
    const text = readFileSync(f, "utf8");
    for (const n of ["demo-signin", "demo_signin", "/demo/", "demo-switch"]) {
      if (text.includes(n)) {
        leaks.push(`${f.slice(WEB_DIR.length)} names ${n}`);
      }
    }
  }
  assert(scanned > 50, `the platform web sources are scanned (${scanned})`);
  eq(leaks, [], "A9: the demo modules leak into the platform web sources");
});
