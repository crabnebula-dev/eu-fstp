// Fuzz target `pdf_xref` for the vendored LibPDF xref and trailer parser
// (ADR-016 "Fuzz targets", TH-26, H-05), through web/src/sign/parse.ts
// `parseXRefBytes`, which follows `/Prev` from `startxref`.
//
// Checks, for any bytes:
// - a typed outcome, never another error, and no hang;
// - a `/Prev` loop, an offset past the end and a chain longer than the
//   limit are refused;
// - a success never reports more sections than the limit;
// - each line of web/fuzz/seeds/pdf_xref/expect.tsv gets its verdict.

import { assert, eq, show } from "../test/support/harness.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";
import { PDF_DICTIONARY, timed, typed } from "./pdf_common.js";
import { toBytes } from "./pdf_fixture.js";
import { type ParseModule, parseModule } from "./pdf_load.js";

/** The checker over a parse module. */
export function checkerFor(parse: ParseModule): Checker {
  return (input: string) => {
    const out = timed("parseXRefBytes", input, () => parse.parseXRefBytes(toBytes(input)));
    typed("parseXRefBytes", out);
    if (out.ok) {
      assert(out.value.sections >= 1, `no section on ${show(input)}`);
      assert(out.value.sections <= parse.LIMITS.maxXRefSections, `${out.value.sections} sections on ${show(input)}`);
      assert(out.value.entries <= parse.LIMITS.maxObjects, `${out.value.entries} entries on ${show(input)}`);
    }
  };
}

/** Each corpus line gets its verdict: `ok`, or `refuse:<code>`. */
export function checkCorpus(parse: ParseModule): void {
  for (const e of readExpectations("pdf_xref")) {
    const out = parse.parseXRefBytes(toBytes(e.input));
    eq(out.ok ? "ok" : `refuse:${out.code}`, e.verdict, `pdf_xref line ${e.line}`);
  }
}

export const target: FuzzTarget = {
  name: "pdf_xref",
  seeds: () => readExpectations("pdf_xref").map((e) => e.input),
  dictionary: PDF_DICTIONARY,
  prepare: async () => checkerFor(await parseModule()),
};
