// Shared checks of the ADR-016 fuzz targets (pdf_token, pdf_xref,
// pdf_document, pdf_prepare, pdf_prepare_differential).

import { assert, show } from "../test/support/harness.js";
import { type Outcome, REFUSAL_CODES, type Refusal } from "./pdf_load.js";

/** Upper bound on one call, in milliseconds. A parser that needs longer counts as hung. */
export const MAX_CALL_MS = 2000;

/** Runs `fn` and fails when it throws or runs longer than MAX_CALL_MS. */
export function timed<T>(what: string, input: string, fn: () => T): T {
  const start = Date.now();
  let out: T;
  try {
    out = fn();
  } catch (e) {
    const detail = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
    throw new Error(`${what} threw instead of refusing with a typed error on ${show(input.slice(0, 300))}: ${detail}`);
  }
  const ms = Date.now() - start;
  assert(ms <= MAX_CALL_MS, `${what} took ${ms} ms on ${show(input.slice(0, 300))}`);
  return out;
}

/** Fails unless `out` is a success or a refusal with a known code. */
export function typed<T>(what: string, out: Outcome<T> | Refusal | { readonly ok: true }): void {
  if (out.ok) {
    return;
  }
  assert(REFUSAL_CODES.includes(out.code), `${what} refused with the unknown code ${show(out.code)}`);
  assert(typeof out.message === "string" && out.message.length > 0, `${what} refused without a message`);
}

/** Byte-level tokens of PDF syntax for the token-level mutations. */
export const PDF_DICTIONARY: readonly string[] = [
  "<<",
  ">>",
  "[",
  "]",
  "(",
  ")",
  "<",
  ">",
  "\\",
  "/",
  "%",
  " ",
  "\n",
  "\r\n",
  "1 0 R",
  "0 0 R",
  "999999999 0 R",
  "-1",
  "+.5",
  "1e5",
  "obj",
  "endobj",
  "stream\n",
  "\nendstream",
  "xref\n",
  "0 1\n",
  "0000000000 65535 f\r\n",
  "0000000009 00000 n\r\n",
  "trailer\n",
  "startxref\n",
  "%%EOF",
  "/Prev 0",
  "/Size 999999",
  "/Length 99999",
  "/Encrypt 7 0 R",
  "/Type /ObjStm",
  "/Type /XRef",
  "/XRefStm 0",
  "/Filter /FlateDecode",
  "/FT /Sig",
  "/V 4 0 R",
  "/T (party-1)",
  "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
  "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",
  "((((((((((((((((",
  "#41",
  "#",
  "\u0000",
  "ÿ",
];
