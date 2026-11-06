// Fuzz target `pdf_prepare` for the signing Worker's preparation
// (ADR-016 "Fuzz targets", M5 design section 3.1 step 3, TH-26, H-05),
// through web/src/sign/prepare.ts `prepareSignature` on mutated revisions.
//
// Checks, for any bytes:
// - a typed outcome, never another error, and no hang;
// - the input buffer is left unchanged, so revision plus increment starts
//   with the input bytes exactly;
// - `/ByteRange` is `[0 a b c]`, where `a` is the offset of the `<` of
//   `/Contents`, `b` the offset after its `>`, and `b + c` the length of
//   revision plus increment: it covers every byte except `/Contents`;
// - revision plus increment parses again, with the party's field signed.

import { assert, eq, show } from "../test/support/harness.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";
import { PDF_DICTIONARY, timed, typed } from "./pdf_common.js";
import { fromBytes, toBytes } from "./pdf_fixture.js";
import { type ParseModule, type PrepareModule, parseModule, prepareModule } from "./pdf_load.js";

/** The field every mutated revision is prepared for. */
export const FIELD = "party-1";
/** The `/Contents` placeholder size the targets ask for, in bytes. */
export const CONTENTS_BYTES = 2048;

/** Checks one prepared increment over `revision`; throws on a broken property. */
export function checkPrepared(
  parse: ParseModule,
  revision: string,
  increment: Uint8Array,
  byteRange: readonly number[],
  field: string,
): void {
  const full = revision + fromBytes(increment);
  assert(increment.length > 0, "an empty increment");
  eq(byteRange.length, 4, "/ByteRange has four numbers");
  const [o1, l1, o2, l2] = byteRange as [number, number, number, number];
  eq(o1, 0, "/ByteRange starts at 0");
  assert(l1 >= revision.length, `/ByteRange's first range ends inside the revision: ${l1} < ${revision.length}`);
  eq(full[l1], "<", "/ByteRange's first range ends at the < of /Contents");
  eq(full[o2 - 1], ">", "/ByteRange's second range starts after the > of /Contents");
  assert(/^[0]+$/.test(full.slice(l1 + 1, o2 - 1)), "the gap holds only the /Contents placeholder");
  eq((o2 - l1 - 2) / 2, CONTENTS_BYTES, "the placeholder size");
  eq(o2 + l2, full.length, "/ByteRange's second range ends at the end of the file");
  const at = full.lastIndexOf("/ByteRange");
  assert(at > revision.length, "the /ByteRange of the increment");
  const patched = /^\/ByteRange \[0 +(\d+) +(\d+) +(\d+) *\]/.exec(full.slice(at));
  eq(patched === null ? null : [Number(patched[1]), Number(patched[2]), Number(patched[3])], [l1, o2, l2], `the patched /ByteRange ${show(full.slice(at, at + 48))}`);
  const again = parse.parseDocumentBytes(toBytes(full));
  assert(again.ok, `revision plus increment does not parse again: ${again.ok ? "" : again.message}`);
  const f = again.value.fields.find((x) => x.name === field);
  assert(f !== undefined && f.signed, `the field ${field} is not signed after the increment`);
}

/** The checker over the prepare and parse modules. */
export function checkerFor(prepare: PrepareModule, parse: ParseModule): Checker {
  return (input: string) => {
    const bytes = toBytes(input);
    const copy = bytes.slice();
    const out = timed("prepareSignature", input, () => prepare.prepareSignature(bytes, { field: FIELD, contentsBytes: CONTENTS_BYTES }));
    typed("prepareSignature", out);
    eq(fromBytes(bytes), fromBytes(copy), "the input buffer changed");
    if (out.ok) {
      checkPrepared(parse, input, out.increment, out.byteRange, FIELD);
    }
  };
}

/** Each corpus line gets its verdict for the field party-1: `ok`, or `refuse:<code>`. */
export function checkCorpus(prepare: PrepareModule): void {
  for (const e of readExpectations("pdf_prepare")) {
    const out = prepare.prepareSignature(toBytes(e.input), { field: FIELD, contentsBytes: CONTENTS_BYTES });
    eq(out.ok ? "ok" : `refuse:${out.code}`, e.verdict, `pdf_prepare line ${e.line}`);
  }
}

export const target: FuzzTarget = {
  name: "pdf_prepare",
  seeds: () => readExpectations("pdf_prepare").map((e) => e.input),
  dictionary: PDF_DICTIONARY,
  prepare: async () => checkerFor(await prepareModule(), await parseModule()),
};
