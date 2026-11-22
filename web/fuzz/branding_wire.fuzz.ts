// Fuzz target `branding_wire` for the decoder of the logos read and the
// file sniffer of web/src/admin/branding/logos.ts (ADR-030, TH-26, H-05,
// I-68).
//
// Checks, for any string:
// - neither the decoder nor the sniffer throws on the string, on the
//   value `JSON.parse` gives, or on the string's bytes;
// - every path an accepted reply holds is a logo path of the server's
//   grammar, so the page never loads an image from anywhere else.

import { assert, show } from "../test/support/harness.js";
import * as logos from "../src/admin/branding/logos.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

const LOGO_PATH = /^\/brand\/[0-9a-f]{64}\.(png|webp)$/;

/** The checker over the production module. */
export function checkerFor(m: typeof logos): Checker {
  return (input: string) => {
    const values: unknown[] = [input];
    try {
      values.push(JSON.parse(input));
    } catch {
      // Not JSON: only the string itself is checked.
    }
    try {
      m.sniff(new TextEncoder().encode(input));
    } catch (e) {
      throw new Error(`the sniffer threw on ${show(input)}: ${String(e)}`);
    }
    for (const v of values) {
      let view: logos.LogosView | null;
      try {
        view = m.decodeLogos(v);
      } catch (e) {
        throw new Error(`the logos decoder threw on ${show(input)}: ${String(e)}`);
      }
      if (view === null) {
        continue;
      }
      const all = [view.tenant, ...view.programmes].flatMap((s) => [s.light, s.dark]);
      for (const l of all) {
        if (l !== null) {
          assert(LOGO_PATH.test(l.path), `an accepted path ${show(l.path)} is no logo path`);
        }
      }
    }
  };
}

export const target: FuzzTarget = {
  name: "branding_wire",
  seeds: () => readExpectations("branding_wire").map((e) => e.input),
  dictionary: ['{"tenant":', '"light":', '"dark":', '"programmes":[', '"path":"/brand/', '.png"', '.webp"', '"format":"png"', '"pdf":true', '"email":false', "null", "[]", "{}", "javascript:"],
  prepare: async () => checkerFor(logos),
};
