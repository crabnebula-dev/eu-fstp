// Fuzz target `safe_url` for `safeUrl` in web/src/core/dom.ts (M4 design
// section 9, ADR-014, TH-26, H-05).
//
// Checks, for any string:
// - `safeUrl` never throws;
// - only same-origin paths and `https:` URLs pass, and an accepted URL is
//   returned unchanged;
// - it agrees with the reference subset on every input. The corpus
//   web/fuzz/seeds/safe_url/expect.tsv is shared with the fstp-oauth URL
//   parser once lane W1e writes it (crates/fstp-oauth/fuzz/seeds/url_parse).

import { assert, show } from "../test/support/harness.js";
import type { DomModule } from "../test/support/contract.js";
import { installFakeDom } from "../test/support/fakedom.js";
import { core } from "../test/support/load.js";
import { refSafeUrl, sameOriginOrHttps } from "../test/reference/safe_url_ref.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations, readRustSeeds } from "./harness.js";

/** The fstp-oauth seed directory shared with this target. */
export const RUST_SEEDS = "crates/fstp-oauth/fuzz/seeds/url_parse";

/** The checker over any `safeUrl` of the dom contract. */
export function checkerFor(dom: Pick<DomModule, "safeUrl">): Checker {
  return (input: string) => {
    let got: string | null;
    try {
      got = dom.safeUrl(input);
    } catch (e) {
      throw new Error(`safeUrl threw on ${show(input)}: ${String(e)}`);
    }
    if (got !== null) {
      assert(got === input, `safeUrl changed ${show(input)} into ${show(got)}`);
      assert(sameOriginOrHttps(got), `safeUrl accepted ${show(input)}, which is neither a same-origin path nor https:`);
    }
    assert((got !== null) === refSafeUrl(input), `safeUrl and the reference disagree on ${show(input)}: got ${show(got)}`);
  };
}

export const target: FuzzTarget = {
  name: "safe_url",
  seeds: () => [...readExpectations("safe_url").map((e) => e.input), ...readRustSeeds(RUST_SEEDS)],
  dictionary: [
    "/",
    "//",
    "https://",
    "http://",
    "javascript:",
    "data:",
    "@",
    ":",
    "%",
    "%2F",
    "%5C",
    "\\",
    "?",
    "#",
    ".",
    "example.org",
    "#main",
    "127.0.0.1",
    ".0x",
    "\t",
    " ",
  ],
  prepare: async () => {
    installFakeDom();
    return checkerFor(await core("dom"));
  },
};
