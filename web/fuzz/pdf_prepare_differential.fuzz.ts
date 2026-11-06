// Fuzz target `pdf_prepare_differential` (ADR-016 "Fuzz targets", M5
// design section 3.1 steps 3 and 4, TH-26, H-05).
//
// Every increment that web/src/sign/prepare.ts emits must be accepted by
// the increment verifier. The corpus
// web/fuzz/seeds/pdf_prepare_differential/expect.tsv is shared with the
// Rust fstp-pdf increment verifier of lane L-PDF: each line is
// `accept<TAB><JSON string revision><TAB><field>`, and the seeds of
// crates/fstp-pdf/fuzz/seeds/increment_verify join it once that lane
// writes them. Until the Rust verifier reads the corpus, the byte-level
// reference of pdf_increment_ref.ts stands in for it.
//
// Checks, for any bytes and each party field:
// - a typed outcome, never another error, and no hang;
// - an increment emitted from a revision in the server shape (a classic
//   trailer with /Size, /Root and a hex-string /ID, then startxref and
//   %%EOF) passes the reference increment check;
// - every corpus revision prepares for its field.

import { assert, show } from "../test/support/harness.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations, readRustSeeds } from "./harness.js";
import { PDF_DICTIONARY, timed, typed } from "./pdf_common.js";
import { fromBytes, toBytes } from "./pdf_fixture.js";
import { refCheckIncrement, refRevisionTail } from "./pdf_increment_ref.js";
import { type PrepareModule, prepareModule } from "./pdf_load.js";
import { CONTENTS_BYTES } from "./pdf_prepare.fuzz.js";

/** The Rust seed directory shared with this target. */
export const RUST_SEEDS = "crates/fstp-pdf/fuzz/seeds/increment_verify";

/** The party fields of the synthetic contracts. */
export const FIELDS: readonly string[] = ["party-1", "party-2"];

/** The increment check: null when accepted, or the reason. */
export type IncrementCheck = (revision: string, increment: string, field: string) => string | null;

/** The checker over a prepare module and an increment check. */
export function checkerFor(prepare: PrepareModule, verify: IncrementCheck = refCheckIncrement): Checker {
  return (input: string) => {
    const serverShaped = typeof refRevisionTail(input) !== "string";
    for (const field of FIELDS) {
      const out = timed("prepareSignature", input, () => prepare.prepareSignature(toBytes(input), { field, contentsBytes: CONTENTS_BYTES }));
      typed("prepareSignature", out);
      if (out.ok && serverShaped) {
        const why = verify(input, fromBytes(out.increment), field);
        assert(why === null, `the verifier refuses the increment for ${field}: ${String(why)} on ${show(input.slice(0, 200))}`);
      }
    }
  };
}

/** Every corpus revision prepares for its field, and the verifier accepts it. */
export function checkCorpus(prepare: PrepareModule, verify: IncrementCheck = refCheckIncrement): void {
  for (const e of readExpectations("pdf_prepare_differential")) {
    assert(e.verdict === "accept" && e.extra !== null, `line ${e.line}: expected accept<TAB>revision<TAB>field`);
    const tail = refRevisionTail(e.input);
    assert(typeof tail !== "string", `line ${e.line}: the revision is not in the server shape: ${String(tail)}`);
    const out = prepare.prepareSignature(toBytes(e.input), { field: e.extra, contentsBytes: CONTENTS_BYTES });
    assert(out.ok, `line ${e.line}: the corpus revision does not prepare: ${out.ok ? "" : `${out.code} ${out.message}`}`);
    const why = verify(e.input, fromBytes(out.increment), e.extra);
    assert(why === null, `line ${e.line}: the verifier refuses: ${String(why)}`);
  }
}

export const target: FuzzTarget = {
  name: "pdf_prepare_differential",
  seeds: () => [...readExpectations("pdf_prepare_differential").map((e) => e.input), ...readRustSeeds(RUST_SEEDS)],
  dictionary: PDF_DICTIONARY,
  prepare: async () => checkerFor(await prepareModule()),
};
