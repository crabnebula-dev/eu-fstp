// Fuzz target `pdf_token` for the vendored LibPDF token reader and object
// parser (ADR-016 "Fuzz targets", TH-26, H-05), through
// web/src/sign/parse.ts `parseObjectBytes`.
//
// Checks, for any bytes:
// - the parser returns an object or a typed refusal, never another error;
// - it never hangs and never returns an object nested deeper than the
//   depth limit;
// - it gives each line of web/fuzz/seeds/pdf_token/expect.tsv its verdict.

import { assert, eq, show } from "../test/support/harness.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";
import { PDF_DICTIONARY, timed, typed } from "./pdf_common.js";
import { toBytes } from "./pdf_fixture.js";
import { type ParseModule, parseModule } from "./pdf_load.js";

/** The checker over a parse module. */
export function checkerFor(parse: ParseModule): Checker {
  return (input: string) => {
    const out = timed("parseObjectBytes", input, () => parse.parseObjectBytes(toBytes(input)));
    typed("parseObjectBytes", out);
    if (out.ok) {
      assert(out.value.depth <= parse.LIMITS.maxDepth, `depth ${out.value.depth} above the limit on ${show(input)}`);
    }
  };
}

/** The verdict of one corpus line: `object`, or `refuse:<code>`. */
export function verdictOf(parse: ParseModule, input: string): string {
  const out = parse.parseObjectBytes(toBytes(input));
  return out.ok ? "object" : `refuse:${out.code}`;
}

/** Each corpus line gets its verdict. */
export function checkCorpus(parse: ParseModule): void {
  for (const e of readExpectations("pdf_token")) {
    eq(verdictOf(parse, e.input), e.verdict, `pdf_token line ${e.line} on ${show(e.input)}`);
  }
}

export const target: FuzzTarget = {
  name: "pdf_token",
  seeds: () => readExpectations("pdf_token").map((e) => e.input),
  dictionary: PDF_DICTIONARY,
  prepare: async () => checkerFor(await parseModule()),
};
