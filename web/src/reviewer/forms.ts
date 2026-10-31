// Page logic of the assigned reviewer's score sheet and ranking summary
// (J6, M4 design section 2.2; lane W4c).
//
// - R-EV-02 and P-01 NOTE 6: every criterion is scored on an integer
//   scale from 0 to N, and a sheet that leaves out a criterion is
//   incomplete. A score is read by comparing digit strings, never as a
//   float.
// - I-23: a correction is a new record and carries its reason.
// - R-EV-08: the ranking summary holds a title, a neutral summary and a
//   rationale.
//
// The module is pure. It reads what the user typed and never rewrites
// it, so a wrong spelling stays visible for the user to correct.

/** A field error of a page form, named by criterion id or field name. */
export interface FieldError {
  readonly field: string;
  readonly reason: string;
}

/** A form read: the value to send, or every field error in form order. */
export type FormRead<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly FieldError[] };

/** What one criterion field reads. */
export type ScoreRead =
  | { readonly ok: true; readonly value: number }
  | { readonly ok: false; readonly reason: "required" | "not_an_integer" | "above_scale" };

/** One P-01 criterion as the score sheet takes it. */
export interface CriterionSpec {
  readonly id: string;
  /** N, a safe integer of at least 1. */
  readonly max: number;
}

/** A ranking summary as `RecordRankingSummary` takes it. */
export interface RankingSummary {
  readonly title: string;
  readonly neutral_summary: string;
  readonly rationale: string;
}

/**
 * The canonical spelling of a score: `0`, or a non-zero ASCII digit and
 * ASCII digits. Interim, pending Daniel: `03`, ` 3` and `3.0` are
 * refused rather than normalised.
 */
const CANONICAL_INTEGER = /^(0|[1-9][0-9]*)$/;

/**
 * Whether the canonical digit string `text` names a larger integer than
 * the canonical digit string `top`. Both have no leading zero, so the
 * longer one is larger, and equal lengths compare digit by digit.
 */
function digitsAbove(text: string, top: string): boolean {
  return text.length > top.length || (text.length === top.length && text > top);
}

/**
 * Reads one criterion field against the scale 0 to `max`.
 *
 * - `""` gives `required`, so an empty field never reads as zero.
 * - Text that is not canonical gives `not_an_integer`.
 * - A canonical integer above `max` gives `above_scale`, however many
 *   digits it has. The comparison is on digit strings, so no long input
 *   is ever rounded.
 */
export function readCriterionScore(text: string, max: number): ScoreRead {
  if (text === "") {
    return { ok: false, reason: "required" };
  }
  if (!CANONICAL_INTEGER.test(text)) {
    return { ok: false, reason: "not_an_integer" };
  }
  if (!Number.isSafeInteger(max) || max < 0 || digitsAbove(text, String(max))) {
    return { ok: false, reason: "above_scale" };
  }
  // The text is canonical and at most `max`, a safe integer, so the
  // conversion is exact.
  return { ok: true, value: Number(text) };
}

/** The text typed for `id`, or `""` when no input names it. */
function inputOf(inputs: Readonly<Record<string, string>>, id: string): string {
  if (!Object.hasOwn(inputs, id)) {
    return "";
  }
  const v = inputs[id];
  return typeof v === "string" ? v : "";
}

/** The values in P-01 order, or the criterion errors in P-01 order. */
function readSheet(
  criteria: readonly CriterionSpec[],
  inputs: Readonly<Record<string, string>>,
): { readonly values: number[]; readonly errors: FieldError[] } {
  const values: number[] = [];
  const errors: FieldError[] = [];
  for (const c of criteria) {
    const s = readCriterionScore(inputOf(inputs, c.id), c.max);
    if (s.ok) {
      values.push(s.value);
    } else {
      errors.push({ field: c.id, reason: s.reason });
    }
  }
  return { values, errors };
}

/**
 * Reads a whole sheet: one value per criterion in P-01 order (NOTE 6:
 * every reviewer scores every criterion). A missing input reads as `""`.
 * Inputs that name no criterion are ignored.
 */
export function readScoreSheet(
  criteria: readonly CriterionSpec[],
  inputs: Readonly<Record<string, string>>,
): FormRead<readonly number[]> {
  const { values, errors } = readSheet(criteria, inputs);
  return errors.length === 0 ? { ok: true, value: values } : { ok: false, errors };
}

/**
 * Reads a correction: the sheet plus the reason that `CorrectScore`
 * requires (I-23). An empty reason gives a `reason` error after the
 * criterion errors. The reason is passed on exactly as typed.
 */
export function readScoreCorrection(
  criteria: readonly CriterionSpec[],
  inputs: Readonly<Record<string, string>>,
  reason: string,
): FormRead<{ readonly values: readonly number[]; readonly reason: string }> {
  const { values, errors } = readSheet(criteria, inputs);
  if (reason === "") {
    errors.push({ field: "reason", reason: "required" });
  }
  return errors.length === 0 ? { ok: true, value: { values, reason } } : { ok: false, errors };
}

/**
 * Reads a ranking summary (R-EV-08). Every field is required, and the
 * errors follow the order title, neutral summary, rationale. Values are
 * passed on exactly as typed.
 */
export function readRankingSummary(input: RankingSummary): FormRead<RankingSummary> {
  const errors: FieldError[] = [];
  for (const field of ["title", "neutral_summary", "rationale"] as const) {
    if (input[field] === "") {
      errors.push({ field, reason: "required" });
    }
  }
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return {
    ok: true,
    value: { title: input.title, neutral_summary: input.neutral_summary, rationale: input.rationale },
  };
}
