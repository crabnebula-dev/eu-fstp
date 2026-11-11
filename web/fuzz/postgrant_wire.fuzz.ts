// Fuzz target `postgrant_wire` for the decoders of web/src/grant/models.ts
// (M5 design sections 5 and 6, TH-26, H-05). The decoders read every read
// body of the post-grant pages.
//
// Checks, for any string:
// - no decoder throws on the string or on the value `JSON.parse` gives;
// - an accepted amount is an ADR-006 string, and an accepted id is a
//   canonical decimal, so no page shows a value outside those spellings.

import { assert, show } from "../test/support/harness.js";
import * as models from "../src/grant/models.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

const DECODERS: readonly ((v: unknown) => unknown)[] = [
  models.decodeOverview,
  models.decodeContract,
  models.decodePayments,
  models.decodeQueue,
  models.decodeReports,
  models.decodeRedirect,
  (v) => models.decodeDrawn(v, "contract"),
];

const AMOUNT = /^(0|[1-9][0-9]*)\.[0-9]{2}$/;
const ID = /^(0|[1-9][0-9]{0,38})$/;

/** The checker over the production models. */
export function checkerFor(m: typeof models): Checker {
  return (input: string) => {
    const values: unknown[] = [input];
    try {
      values.push(JSON.parse(input));
    } catch {
      // Not JSON: only the string itself is checked.
    }
    for (const v of values) {
      for (const d of DECODERS) {
        try {
          d(v);
        } catch (e) {
          throw new Error(`a post-grant decoder threw on ${show(input)}: ${String(e)}`);
        }
      }
      const o = m.decodeOverview(v);
      if (o !== null) {
        assert(ID.test(o.proposal), `overview proposal ${show(o.proposal)} is not an id`);
        assert(AMOUNT.test(o.paid), `overview paid ${show(o.paid)} is not an ADR-006 amount`);
      }
      const rows = m.decodePayments(v);
      if (rows !== null) {
        for (const r of rows) {
          for (const l of r.lines) {
            assert(AMOUNT.test(l.requested), `line requested ${show(l.requested)} is not an ADR-006 amount`);
          }
        }
      }
    }
  };
}

export const target: FuzzTarget = {
  name: "postgrant_wire",
  seeds: () => readExpectations("postgrant_wire").map((e) => e.input),
  dictionary: ['{"proposal":"', '"state":"', '"paid":"', '"lines":[', '"status":"PAID"', '"digest":"', '"request":{', "null", "[]", "{}", "-1", "1,00", "00000000000000000000000000000000000000000000000000000000000000"],
  prepare: async () => checkerFor(models),
};
