// Fuzz target `message_format` for `parseMessage` in web/src/core/i18n.ts
// (M4 design section 9, R-NF-04, TH-26, H-05).
//
// Checks, for any string:
// - `parseMessage` never throws;
// - it agrees with the reference grammar on acceptance and on the parts;
// - a refusal's offset lies inside the text;
// - accepted parts written back as text parse to the same parts.
// The corpus web/fuzz/seeds/message_format/expect.tsv is shared with
// `fstp_html::parse_message_format` once lane W1d writes it
// (crates/fstp-html/fuzz/seeds/message_format_parse).

import { assert, eq, show } from "../test/support/harness.js";
import type { I18nModule } from "../test/support/contract.js";
import { core } from "../test/support/load.js";
import { refParseMessage, refWriteMessage } from "../test/reference/message_ref.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations, readRustSeeds } from "./harness.js";

/** The fstp-html seed directory shared with this target. */
export const RUST_SEEDS = "crates/fstp-html/fuzz/seeds/message_format_parse";

/** The checker over any `parseMessage` of the i18n contract. */
export function checkerFor(i18n: Pick<I18nModule, "parseMessage">): Checker {
  return (text: string) => {
    let got;
    try {
      got = i18n.parseMessage(text);
    } catch (e) {
      throw new Error(`parseMessage threw on ${show(text)}: ${String(e)}`);
    }
    const want = refParseMessage(text);
    eq(got.ok, want.ok, `acceptance of ${show(text)}`);
    if (got.ok && want.ok) {
      eq(got.parts, want.parts, `parts of ${show(text)}`);
      const again = i18n.parseMessage(refWriteMessage(got.parts));
      assert(again.ok, `written-back parts of ${show(text)} do not parse`);
      eq(again.parts, got.parts, `round trip of ${show(text)}`);
    }
    if (!got.ok) {
      assert(
        Number.isInteger(got.offset) && got.offset >= 0 && got.offset <= text.length,
        `offset ${show(got.offset)} outside ${show(text)}`,
      );
    }
  };
}

export const target: FuzzTarget = {
  name: "message_format",
  seeds: () => [...readExpectations("message_format").map((e) => e.input), ...readRustSeeds(RUST_SEEDS)],
  dictionary: ["{", "}", "{{", "}}", "{name}", "{x}", "{a_1}", "{A}", "{1}", " ", "\u0000", "\ud800"],
  prepare: async () => checkerFor(await core("i18n")),
};
