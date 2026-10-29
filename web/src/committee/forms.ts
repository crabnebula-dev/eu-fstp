// Page logic of the committee's cut-off round and ballot (J7, R-EV-08,
// R-EV-09; M4 design section 2.2 and change D5, lane W4c).
//
// - P-02 NOTE 6: effective scores are percentages with two decimals,
//   compared exactly. The page compares the server's text digit by
//   digit, never as a float.
// - NOTE 6 of `state-machine.md` and P-17: a tie across the cut-off
//   needs a recorded tie-break. The form mirrors the domain's
//   `plan_cut_off` (`fstp-domain` `decision.rs`), so a round the domain
//   would refuse is refused before any request.
// - R-EV-09 and Q4: each member casts their own ballot, with no preset.
//
// The module is pure.

import type { FieldError, FormRead } from "../reviewer/forms.js";

/** One row of the ranking as the cut-off form orders it, top first. */
export interface CutOffRow {
  readonly proposal: string;
  /** The effective score as the server sends it: a percentage with two decimals. */
  readonly effective: string;
}

/** What the open-round form holds. */
export interface CutOffInput {
  readonly nominated: string;
  readonly rationale: string;
  readonly tie_break: string;
}

/** A round as `OpenCutOffRound` takes it (D5). */
export interface CutOffRound {
  readonly order: readonly string[];
  readonly nominated: number;
  readonly rationale: string;
  readonly tie_break: string | null;
}

/** A vote as the ballot form holds it. `null` is no choice yet. */
export type VoteChoice = "for" | "against" | "abstain" | null;

/** The canonical text of an effective score (P-02 NOTE 6). */
const SCORE_TEXT = /^(0|[1-9][0-9]*)[.][0-9]{2}$/;

/** A canonical integer: `0`, or a non-zero ASCII digit and ASCII digits. */
const CANONICAL_INTEGER = /^(0|[1-9][0-9]*)$/;

/** Compares two canonical digit strings without leading zeros. */
function compareDigits(a: string, b: string): -1 | 0 | 1 {
  if (a.length !== b.length) {
    return a.length < b.length ? -1 : 1;
  }
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

/**
 * Compares two effective scores exactly, with no rounding and no float
 * (P-02 NOTE 6). Each must be canonical, `0` or a non-zero digit and
 * digits, a point, and two digits. Null when either is not.
 */
export function compareScoreText(a: string, b: string): -1 | 0 | 1 | null {
  if (typeof a !== "string" || typeof b !== "string" || !SCORE_TEXT.test(a) || !SCORE_TEXT.test(b)) {
    return null;
  }
  const pa = a.length - 3;
  const pb = b.length - 3;
  const whole = compareDigits(a.slice(0, pa), b.slice(0, pb));
  if (whole !== 0) {
    return whole;
  }
  // Two fraction digits each, so string order is numeric order.
  const fa = a.slice(pa + 1);
  const fb = b.slice(pb + 1);
  return fa === fb ? 0 : fa < fb ? -1 : 1;
}

/** The `order` error of the rows, or null when they are a valid order. */
function orderError(rows: readonly CutOffRow[]): string | null {
  if (rows.length === 0) {
    return "empty";
  }
  if (rows.some((row) => typeof row.effective !== "string" || !SCORE_TEXT.test(row.effective))) {
    return "unreadable_score";
  }
  for (let i = 0; i + 1 < rows.length; i += 1) {
    const here = rows[i];
    const next = rows[i + 1];
    if (here !== undefined && next !== undefined && compareScoreText(here.effective, next.effective) === -1) {
      return "not_ordered";
    }
  }
  return null;
}

/**
 * The rows in descending order of effective score, top first. The sort
 * is stable, so rows with equal scores keep the server's order. Null
 * when a score is not canonical, since then no order is known.
 *
 * Interim, pending the lead: the domain's `ranking_view` lists rows in
 * proposal order, so the page orders them itself rather than refusing
 * an unsorted view.
 */
export function sortByScore<T extends CutOffRow>(rows: readonly T[]): T[] | null {
  if (rows.some((row) => typeof row.effective !== "string" || !SCORE_TEXT.test(row.effective))) {
    return null;
  }
  const indexed = rows.map((row, i) => ({ row, i }));
  indexed.sort((a, b) => {
    // Both scores are canonical, so the comparison is never null.
    const c = compareScoreText(b.row.effective, a.row.effective) ?? 0;
    return c !== 0 ? c : a.i - b.i;
  });
  return indexed.map((x) => x.row);
}

/** Whether the rows at `i` and `j` exist and tie exactly. */
function ties(rows: readonly CutOffRow[], i: number, j: number): boolean {
  const a = rows[i];
  const b = rows[j];
  return a !== undefined && b !== undefined && compareScoreText(a.effective, b.effective) === 0;
}

/** Whether the row at `index` can move one place `up` (towards the top) or down within its tie. */
export function canMoveInTie(rows: readonly CutOffRow[], index: number, up: boolean): boolean {
  return Number.isSafeInteger(index) && ties(rows, index, up ? index - 1 : index + 1);
}

/**
 * The rows with the row at `index` moved one place `up` or down, within
 * its group of equal scores. NOTE 6 of `state-machine.md` and P-17: the
 * committee orders a tie under P-17, so the order it sends decides who
 * falls within the cut-off. A move out of the tie gives null, so the
 * order stays sorted by score.
 */
export function moveInTie<T extends CutOffRow>(rows: readonly T[], index: number, up: boolean): T[] | null {
  if (!canMoveInTie(rows, index, up)) {
    return null;
  }
  const other = up ? index - 1 : index + 1;
  const out = [...rows];
  const a = out[index];
  const b = out[other];
  if (a === undefined || b === undefined) {
    return null;
  }
  out[index] = b;
  out[other] = a;
  return out;
}

/**
 * Reads the open-round form over `rows`, the ranking top first.
 *
 * Errors come in this field order:
 *
 * - `order`: `empty` for no rows, `unreadable_score` for a row whose
 *   score is not canonical, and `not_ordered` when a later row scores
 *   higher than an earlier one.
 * - `nominated`: the rank position, a canonical integer from 0 to the
 *   number of rows: `required`, `not_an_integer` or `out_of_range`.
 * - `rationale`: required (R-EV-08).
 * - `tie_break`: required only when the rows at positions `nominated`
 *   and `nominated + 1` tie, which is a tie across the cut-off (P-17).
 *
 * The value carries the order as proposal ids, the position, the
 * rationale as typed, and the tie-break as typed or null when empty.
 */
export function readCutOffRound(rows: readonly CutOffRow[], input: CutOffInput): FormRead<CutOffRound> {
  const errors: FieldError[] = [];
  const order = orderError(rows);
  if (order !== null) {
    errors.push({ field: "order", reason: order });
  }
  let nominated: number | null = null;
  const text = input.nominated;
  if (text === "") {
    errors.push({ field: "nominated", reason: "required" });
  } else if (!CANONICAL_INTEGER.test(text)) {
    errors.push({ field: "nominated", reason: "not_an_integer" });
  } else if (compareDigits(text, String(rows.length)) === 1) {
    errors.push({ field: "nominated", reason: "out_of_range" });
  } else {
    // At most the row count, so the conversion is exact.
    nominated = Number(text);
  }
  if (input.rationale === "") {
    errors.push({ field: "rationale", reason: "required" });
  }
  if (nominated !== null && nominated > 0) {
    const last = rows[nominated - 1];
    const first = rows[nominated];
    if (
      last !== undefined &&
      first !== undefined &&
      compareScoreText(last.effective, first.effective) === 0 &&
      input.tie_break === ""
    ) {
      errors.push({ field: "tie_break", reason: "required" });
    }
  }
  if (errors.length > 0 || nominated === null) {
    return { ok: false, errors };
  }
  return {
    ok: true,
    value: {
      order: rows.map((row) => row.proposal),
      nominated,
      rationale: input.rationale,
      tie_break: input.tie_break === "" ? null : input.tie_break,
    },
  };
}

/** Reads the ballot form. A vote has no preset (R-EV-09). */
export function readBallot(input: {
  readonly vote: VoteChoice;
}): FormRead<{ readonly vote: "for" | "against" | "abstain" }> {
  const v = input.vote;
  if (v === "for" || v === "against" || v === "abstain") {
    return { ok: true, value: { vote: v } };
  }
  return { ok: false, errors: [{ field: "vote", reason: "required" }] };
}
