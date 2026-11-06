// Fuzz target `pdf_document` for the vendored LibPDF document parser on
// arbitrary bytes (ADR-016 "Fuzz targets", TH-26, H-05), through
// web/src/sign/parse.ts `parseDocumentBytes`, which loads every in-use
// object.
//
// Checks, for any bytes:
// - a typed outcome, never another error, and no hang;
// - a success stays within the object and section limits;
// - each line of web/fuzz/seeds/pdf_document/expect.tsv gets its verdict,
//   among them the refusals of encrypted files (`refuse:encrypted`),
//   object streams (`refuse:object-stream`) and xref streams
//   (`refuse:xref-stream`).

import { assert, eq, show } from "../test/support/harness.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";
import { PDF_DICTIONARY, timed, typed } from "./pdf_common.js";
import { toBytes } from "./pdf_fixture.js";
import { type ParseModule, parseModule } from "./pdf_load.js";

/** The checker over a parse module. */
export function checkerFor(parse: ParseModule): Checker {
  return (input: string) => {
    const out = timed("parseDocumentBytes", input, () => parse.parseDocumentBytes(toBytes(input)));
    typed("parseDocumentBytes", out);
    if (out.ok) {
      assert(out.value.objects <= parse.LIMITS.maxObjects, `${out.value.objects} objects on ${show(input.slice(0, 200))}`);
      assert(out.value.sections <= parse.LIMITS.maxXRefSections, `${out.value.sections} sections`);
    }
  };
}

/** Each corpus line gets its verdict: `ok`, or `refuse:<code>`. */
export function checkCorpus(parse: ParseModule): void {
  for (const e of readExpectations("pdf_document")) {
    const out = parse.parseDocumentBytes(toBytes(e.input));
    eq(out.ok ? "ok" : `refuse:${out.code}`, e.verdict, `pdf_document line ${e.line}`);
  }
}

export const target: FuzzTarget = {
  name: "pdf_document",
  seeds: () => readExpectations("pdf_document").map((e) => e.input),
  dictionary: PDF_DICTIONARY,
  prepare: async () => checkerFor(await parseModule()),
};
