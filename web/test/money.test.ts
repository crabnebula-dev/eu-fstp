// money.ts: ADR-006 strings only (M4 design section 3.9, W1c "money strings
// only"). The browser never computes money; totals and P-04 checks come
// from the server.

import { readExpectations } from "../fuzz/harness.js";
import type { Currency } from "./support/contract.js";
import { canonicalAmount, moneyish } from "./support/gen.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { core } from "./support/load.js";
import { refMoney } from "./reference/money_ref.js";

/** ADR-006: the canonical EUR spellings of the shared corpus are accepted, byte for byte. */
test("adr006_money_accepts_canonical_eur_strings", async () => {
  const money = await core("money");
  const accepted = readExpectations("money_parse").filter((e) => e.verdict === "accept");
  assert(accepted.length > 0, "the corpus has accepted lines");
  for (const e of accepted) {
    const got = money.parseAmount(e.input, "EUR");
    assert(got.ok, `line ${e.line}: ${show(e.input)} refused: ${show(got)}`);
    eq(got.amount.text, e.input, `line ${e.line}: text`);
    eq(got.amount.currency, "EUR", `line ${e.line}: currency`);
    eq(money.amountText(got.amount), e.input, `line ${e.line}: amountText`);
  }
});

/**
 * ADR-006: every other spelling is rejected, never normalised, with the
 * error kind of `fstp_money::AmountParseErrorKind`. This includes each
 * spelling the ADR lists: "1234.5", "01234.50", "+1234.50", "-1234.50",
 * "1234.500" and "1.23450e3".
 */
test("adr006_money_refuses_every_other_spelling_with_its_kind", async () => {
  const money = await core("money");
  const refused = readExpectations("money_parse").filter((e) => e.verdict.startsWith("refuse:"));
  for (const listed of ["1234.5", "01234.50", "+1234.50", "-1234.50", "1234.500", "1.23450e3"]) {
    assert(refused.some((e) => e.input === listed), `the corpus holds the ADR-006 example ${listed}`);
  }
  for (const e of refused) {
    const got = money.parseAmount(e.input, "EUR");
    assert(!got.ok, `line ${e.line}: ${show(e.input)} accepted`);
    eq(got.kind, e.verdict.slice("refuse:".length), `line ${e.line}: kind of ${show(e.input)}`);
  }
});

/** ADR-006: the JSON number 1234.50, and every other non-string value, is refused. */
test("adr006_money_refuses_json_numbers_and_non_strings", async () => {
  const money = await core("money");
  const values: readonly unknown[] = [
    1234.5,
    1234,
    0,
    -0,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    BigInt(123450),
    null,
    undefined,
    true,
    {},
    [],
    ["1234.50"],
    { text: "1234.50", currency: "EUR" },
    { toString: () => "1234.50" },
    Object("1234.50"),
    JSON.parse("1234.50"),
  ];
  for (const v of values) {
    const got = money.parseAmount(v, "EUR");
    assert(!got.ok, `${show(v)} accepted as an amount`);
    eq(got.kind, "NotAString", `kind for ${show(v)}`);
  }
});

/** ADR-006: only currencies with a fixed scale exist; EUR is the only one, spelt exactly. */
test("adr006_money_refuses_unknown_currency", async () => {
  const money = await core("money");
  for (const c of ["USD", "eur", "EUR ", "", "XTS"]) {
    const got = money.parseAmount("1.00", c as Currency);
    assert(!got.ok, `currency ${show(c)} accepted`);
    eq(got.kind, "UnknownCurrency", `kind for currency ${show(c)}`);
  }
});

/** ADR-006: on strings near the grammar, money.ts gives the reference verdict and never throws. */
test("adr006_money_agrees_with_reference_on_generated_strings", async () => {
  const money = await core("money");
  forAll(
    moneyish,
    (s) => {
      const got = money.parseAmount(s, "EUR");
      const want = refMoney(s);
      eq(got.ok, want.ok, `acceptance of ${show(s)}`);
      if (!got.ok && !want.ok) {
        eq(got.kind, want.kind, `kind of ${show(s)}`);
      }
    },
    { runs: 2000 },
  );
});

/** ADR-006: an accepted amount holds its canonical string and no number, and round-trips. */
test("adr006_money_amount_holds_no_number_and_round_trips", async () => {
  const money = await core("money");
  forAll(
    canonicalAmount,
    (s) => {
      const got = money.parseAmount(s, "EUR");
      assert(got.ok, `${s} refused`);
      eq(money.amountText(got.amount), s, "round trip");
      const json = JSON.stringify(got.amount);
      const back: unknown = JSON.parse(json);
      for (const v of Object.values(back as Record<string, unknown>)) {
        assert(typeof v === "string", `an amount serialises a non-string field: ${json}`);
      }
    },
    { runs: 500 },
  );
});

/** ADR-006, design section 3.9: the browser never computes money, so money.ts exports no arithmetic. */
test("adr006_money_module_offers_no_arithmetic", async () => {
  const money = await core("money");
  const names = Object.keys(money);
  const arithmetic = names.filter((n) =>
    /add|plus|sub(?!mit)|minus|sum|total|mul|times|div|ratio|percent|round|float|number|cents|toMinor|fromMinor/i.test(n),
  );
  eq(arithmetic, [], "arithmetic exports of money.ts");
});
