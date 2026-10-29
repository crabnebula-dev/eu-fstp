// Fuzz target `money_parse` for web/src/core/money.ts (M4 design section 9,
// ADR-006, TH-26, H-05).
//
// Checks, for any string:
// - `parseAmount` never throws;
// - it accepts exactly what the ADR-006 reference accepts, with the same
//   error kind as `fstp_money::AmountParseErrorKind` (differential, on the
//   corpus shared with fstp-money: web/fuzz/seeds/money_parse/expect.tsv
//   and crates/fstp-money/fuzz/seeds/amount_parse);
// - an accepted text is kept byte for byte, as an EUR amount, with no
//   numeric field.

import { assert, eq, show } from "../test/support/harness.js";
import type { MoneyModule } from "../test/support/contract.js";
import { core } from "../test/support/load.js";
import { refMoney } from "../test/reference/money_ref.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations, readRustSeeds } from "./harness.js";

/** The fstp-money seed directory shared with this target. */
export const RUST_SEEDS = "crates/fstp-money/fuzz/seeds/amount_parse";

/** The checker over any module of the money contract. */
export function checkerFor(money: MoneyModule): Checker {
  return (input: string) => {
    let got;
    try {
      got = money.parseAmount(input, "EUR");
    } catch (e) {
      throw new Error(`parseAmount threw on ${show(input)}: ${String(e)}`);
    }
    const want = refMoney(input);
    if (want.ok) {
      assert(got.ok, `refused the canonical amount ${show(input)}: ${show(got)}`);
      eq(got.amount.text, input, "accepted text kept byte for byte");
      eq(got.amount.currency, "EUR", "currency");
      eq(money.amountText(got.amount), input, "amountText round trip");
      for (const v of Object.values(got.amount)) {
        assert(typeof v !== "number" && typeof v !== "bigint", `an amount holds a number: ${show(got.amount)}`);
      }
    } else {
      assert(!got.ok, `accepted the non-canonical ${show(input)}`);
      eq(got.kind, want.kind, `error kind for ${show(input)}`);
    }
  };
}

export const target: FuzzTarget = {
  name: "money_parse",
  seeds: () => [...readExpectations("money_parse").map((e) => e.input), ...readRustSeeds(RUST_SEEDS)],
  dictionary: ["0", "1", "9", ".", ".00", "00", "-", "+", "e", " ", ",", "9999999999999999", "\u0000", "１"],
  prepare: async () => checkerFor(await core("money")),
};
