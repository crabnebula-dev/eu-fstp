// Fuzz target `validators` for the generated structural validators in
// web/src/gen/api.ts (M4 design section 9, ADR-014, ADR-006, TH-26, H-05).
//
// Checks, for any JSON text:
// - `JSON.parse` either refuses it or gives a value;
// - no validator throws on that value;
// - each validator accepts the value exactly when it fits the generated
//   schema, by the independent reference `fits`, so a JSON number never
//   passes as an amount and an unknown member never passes a closed object.
//
// The generator is lane W3a's (tools/gen-ts). Until it emits `VALIDATORS`
// and `SCHEMAS`, this target is red with NotImplemented.

import { assert, show } from "../test/support/harness.js";
import type { GenApiModule } from "../test/support/contract.js";
import { genApi } from "../test/support/load.js";
import { fits } from "../test/reference/schema_ref.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

/** The checker over any generated validator table. */
export function checkerFor(gen: GenApiModule): Checker {
  const names = Object.keys(gen.VALIDATORS);
  for (const n of names) {
    assert(gen.SCHEMAS[n] !== undefined, `validator ${n} has no schema`);
  }
  return (text: string) => {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      return;
    }
    for (const n of names) {
      const validate = gen.VALIDATORS[n];
      const schema = gen.SCHEMAS[n];
      if (validate === undefined || schema === undefined) {
        continue;
      }
      let got: boolean;
      try {
        got = validate(value);
      } catch (e) {
        throw new Error(`validator ${n} threw on ${show(text)}: ${String(e)}`);
      }
      assert(got === fits(schema, value), `validator ${n} gave ${String(got)} on ${show(text)}`);
    }
  };
}

export const target: FuzzTarget = {
  name: "validators",
  seeds: () => readExpectations("validators").map((e) => e.input),
  dictionary: ["{", "}", "[", "]", ",", ":", '"', "null", "true", "0", "1.5", '"1234.50"', '"amount"', '"id"', '"__proto__"'],
  prepare: async () => checkerFor(await genApi()),
};
