// Self-checks of the independent references against the shared corpora.
// They pass without production code. Each corpus line is written by hand
// from the grammar, and the reference is written separately, so a slip in
// either one shows here before it can hide a production fault.

import { readExpectations, readRustSeeds } from "../fuzz/harness.js";
import { RUST_SEEDS as MONEY_RUST_SEEDS } from "../fuzz/money_parse.fuzz.js";
import { TABLE } from "../fuzz/router_match.fuzz.js";
import { assert, eq, show, test } from "./support/harness.js";
import { refParseMessage, refWriteMessage } from "./reference/message_ref.js";
import { refMoney } from "./reference/money_ref.js";
import { refMatch, refMatches, tableFault } from "./reference/route_ref.js";
import { refSafeUrl, sameOriginOrHttps } from "./reference/safe_url_ref.js";
import { SAMPLE_SCHEMAS } from "./reference/models.js";
import { fits } from "./reference/schema_ref.js";

/** ADR-006: the money reference gives every verdict of the shared corpus. */
test("adr006_money_reference_agrees_with_the_corpus", () => {
  for (const e of readExpectations("money_parse")) {
    const v = refMoney(e.input);
    eq(v.ok ? "accept" : `refuse:${v.kind}`, e.verdict, `line ${e.line}: ${show(e.input)}`);
  }
});

/**
 * ADR-006: the money reference agrees with the fstp-money seed corpus, whose
 * file names state the verdict (canonical, max and zero are accepted).
 */
test("adr006_money_reference_agrees_with_the_fstp_money_seeds", () => {
  const seeds = readRustSeeds(MONEY_RUST_SEEDS);
  assert(seeds.length >= 9, `fstp-money seeds found: ${seeds.length}`);
  const accepted = seeds.filter((s) => refMoney(s).ok).sort();
  eq(accepted, ["0.00", "1234.50", "9999999999999999.99"], "accepted fstp-money seeds");
  const over = seeds.find((s) => s.startsWith("10000000000000000"));
  assert(over !== undefined, "the over_max seed exists");
  eq(refMoney(over), { ok: false, kind: "OutOfRange" }, "over_max");
});

/** ADR-014: the safeUrl reference gives every verdict of the shared corpus, within the two allowed shapes. */
test("adr014_safe_url_reference_agrees_with_the_corpus", () => {
  for (const e of readExpectations("safe_url")) {
    const ok = refSafeUrl(e.input);
    eq(ok ? "accept" : "refuse", e.verdict, `line ${e.line}: ${show(e.input)}`);
    if (ok) {
      assert(sameOriginOrHttps(e.input), `line ${e.line}: accepted outside the two shapes`);
    }
  }
});

/** R-NF-04: the message reference gives every verdict of the shared corpus and round-trips. */
test("r_nf_04_message_reference_agrees_with_the_corpus", () => {
  for (const e of readExpectations("message_format")) {
    const got = refParseMessage(e.input);
    eq(got.ok ? "accept" : "refuse", e.verdict, `line ${e.line}: ${show(e.input)}`);
    if (got.ok) {
      const parts = got.parts;
      for (let i = 1; i < parts.length; i += 1) {
        assert(!(parts[i - 1]?.kind === "text" && parts[i]?.kind === "text"), `line ${e.line}: adjacent text parts`);
      }
      assert(parts.every((p) => p.kind !== "text" || p.text !== ""), `line ${e.line}: an empty text part`);
      eq(refParseMessage(refWriteMessage(parts)), got, `line ${e.line}: round trip`);
    }
  }
});

/** ADR-014: the fuzz route table is valid, and the router reference gives every corpus match. */
test("adr014_router_reference_agrees_with_the_corpus", () => {
  eq(tableFault(TABLE), null, "the fuzz table is valid");
  for (const e of readExpectations("router_match")) {
    assert(refMatches(TABLE, e.input).length <= 1, `line ${e.line}: more than one route`);
    const want = e.verdict === "none" ? null : { name: e.verdict, params: JSON.parse(e.extra ?? "{}") as unknown };
    eq(refMatch(TABLE, e.input), want, `line ${e.line}: ${show(e.input)}`);
  }
});

/** ADR-014, ADR-006: the schema reference refuses JSON numbers as amounts and unknown members. */
test("adr014_schema_reference_refuses_numbers_and_unknown_members", () => {
  const s = SAMPLE_SCHEMAS["draft_summary"];
  assert(s !== undefined, "sample schema");
  const good = { id: "p1", title: "t", cap: "400000.00", state: "DRAFT" };
  eq(fits(s, good), true, "a fitting value");
  eq(fits(s, { ...good, note: null }), true, "an optional nullable member");
  eq(fits(s, { ...good, cap: 400000 }), false, "a JSON number as an amount");
  eq(fits(s, { ...good, cap: "400000.0" }), false, "a non-canonical amount");
  eq(fits(s, { ...good, extra: 1 }), false, "an unknown member");
  eq(fits(s, { id: "p1", title: "t", state: "DRAFT" }), false, "a missing member");
  eq(fits(s, { ...good, state: "draft" }), false, "a value outside the enum");
  eq(fits(s, JSON.parse('{"__proto__":{"x":1},"id":"p1","title":"t","cap":"1.00","state":"DRAFT"}')), false, "a __proto__ member");
});
