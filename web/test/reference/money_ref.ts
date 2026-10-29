// Independent reference for ADR-006 amount strings, written from the ADR
// text and the error order of `fstp_money::decimal::parse_fixed`. It never
// computes a value: the range is decided by the digit count, as the Rust
// fuzz target `amount_parse` does, since the integer part has no leading
// zero.

import type { MoneyErrorKind } from "../support/contract.js";

/** EUR minor digits (ADR-006). */
export const EUR_SCALE = 2;
/** `fstp_money::Amount::MAX_ABS_MINOR` has 18 digits, all nines. */
export const MAX_DIGITS = 18;

/** What ADR-006 says about one input. */
export type MoneyVerdict = { readonly ok: true } | { readonly ok: false; readonly kind: MoneyErrorKind };

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c.length === 1 && c >= "0" && c <= "9";
}

function digitRun(t: string, from: number): number {
  let i = from;
  while (isDigit(t[i])) {
    i += 1;
  }
  return i - from;
}

/** The verdict for `input` as an EUR amount. */
export function refMoney(input: unknown): MoneyVerdict {
  if (typeof input !== "string") {
    return { ok: false, kind: "NotAString" };
  }
  const t = input;
  if (t.length === 0) {
    return { ok: false, kind: "Empty" };
  }
  if (!isDigit(t[0])) {
    return { ok: false, kind: "UnexpectedByte" };
  }
  const intLen = digitRun(t, 0);
  if (t[0] === "0" && intLen > 1) {
    return { ok: false, kind: "LeadingZero" };
  }
  if (intLen === t.length) {
    return { ok: false, kind: "WrongScale" };
  }
  if (t[intLen] !== ".") {
    return { ok: false, kind: "UnexpectedByte" };
  }
  const fracStart = intLen + 1;
  const fracLen = digitRun(t, fracStart);
  const after = fracStart + fracLen;
  if (fracLen > EUR_SCALE) {
    return { ok: false, kind: "WrongScale" };
  }
  if (fracLen < EUR_SCALE) {
    return { ok: false, kind: after === t.length ? "WrongScale" : "UnexpectedByte" };
  }
  if (after !== t.length) {
    return { ok: false, kind: "UnexpectedByte" };
  }
  if (intLen + EUR_SCALE > MAX_DIGITS) {
    return { ok: false, kind: "OutOfRange" };
  }
  return { ok: true };
}
