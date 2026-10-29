// ADR-006 amount strings in the browser (M4 design section 3.9, ADR-014
// "Money").
//
// The browser never computes money. Totals and P-04 checks come from the
// server. So this module reads and shows canonical strings only, and it
// has no arithmetic. An amount holds its canonical text and no number.
//
// The grammar and the order of the error kinds follow
// `fstp_money::decimal::parse_fixed`, so a text gets the same verdict
// here as from `fstp_money::Amount::parse`. The range is decided by the
// digit count: the integer part has no leading zero, so a text with at
// most 18 digits is at most `Amount::MAX_ABS_MINOR`, which is 18 nines.

/** The currencies ADR-006 fixes a scale for. EUR has two minor digits. */
export type Currency = "EUR";

/**
 * Why a text is not an ADR-006 amount. `Empty`, `UnexpectedByte`,
 * `LeadingZero`, `WrongScale` and `OutOfRange` mirror
 * `fstp_money::AmountParseErrorKind`. `NotAString` covers a JSON number
 * and every other non-string value. `UnknownCurrency` covers a currency
 * with no fixed scale.
 */
export type MoneyErrorKind =
  | "NotAString"
  | "UnknownCurrency"
  | "Empty"
  | "UnexpectedByte"
  | "LeadingZero"
  | "WrongScale"
  | "OutOfRange";

declare const AMOUNT: unique symbol;

/**
 * An ADR-006 amount: the canonical text and its currency, with no number.
 * Only `parseAmount` makes one, so the type marks text that passed the
 * grammar. The mark exists for the compiler only.
 */
export interface Amount {
  readonly currency: Currency;
  readonly text: string;
  readonly [AMOUNT]: true;
}

/** The outcome of reading an amount. It is returned, never thrown. */
export type MoneyResult =
  | { readonly ok: true; readonly amount: Amount }
  | { readonly ok: false; readonly kind: MoneyErrorKind };

/** EUR minor digits (ADR-006). */
const EUR_MINOR_DIGITS = 2;
/** The digit count of `fstp_money::Amount::MAX_ABS_MINOR`. */
const MAX_MINOR_DIGITS = 18;

function refuse(kind: MoneyErrorKind): MoneyResult {
  return Object.freeze({ ok: false, kind });
}

function isDigitAt(t: string, i: number): boolean {
  const c = t.charCodeAt(i);
  return c >= 0x30 && c <= 0x39;
}

/** The length of the run of ASCII digits that starts at `from`. */
function digitRun(t: string, from: number): number {
  let i = from;
  while (i < t.length && isDigitAt(t, i)) {
    i += 1;
  }
  return i - from;
}

/**
 * Reads `input` as an amount in `currency`. Only the canonical spelling
 * passes, such as `"1234.50"` for EUR. Every other spelling is refused
 * and never normalised. A JSON number is refused with `NotAString`. It
 * never throws.
 */
export function parseAmount(input: unknown, currency: Currency): MoneyResult {
  if (currency !== "EUR") {
    return refuse("UnknownCurrency");
  }
  if (typeof input !== "string") {
    return refuse("NotAString");
  }
  const t = input;
  if (t.length === 0) {
    return refuse("Empty");
  }
  if (!isDigitAt(t, 0)) {
    return refuse("UnexpectedByte");
  }
  const intLen = digitRun(t, 0);
  if (t.charCodeAt(0) === 0x30 && intLen > 1) {
    return refuse("LeadingZero");
  }
  if (intLen === t.length) {
    return refuse("WrongScale");
  }
  if (t.charCodeAt(intLen) !== 0x2e) {
    return refuse("UnexpectedByte");
  }
  const fracStart = intLen + 1;
  const fracLen = digitRun(t, fracStart);
  const after = fracStart + fracLen;
  if (fracLen > EUR_MINOR_DIGITS) {
    return refuse("WrongScale");
  }
  if (fracLen < EUR_MINOR_DIGITS) {
    return refuse(after === t.length ? "WrongScale" : "UnexpectedByte");
  }
  if (after !== t.length) {
    return refuse("UnexpectedByte");
  }
  if (intLen + EUR_MINOR_DIGITS > MAX_MINOR_DIGITS) {
    return refuse("OutOfRange");
  }
  const amount = Object.freeze({ currency, text: t }) as Amount;
  return Object.freeze({ ok: true, amount });
}

/** The canonical text of `amount`, byte for byte what was parsed. */
export function amountText(amount: Amount): string {
  return amount.text;
}
