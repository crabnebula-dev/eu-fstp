// Page logic of the FSTP coordinator's knock-out form (J5, R-EV-01; M4
// design section 2.2, lane W4c).
//
// The module is pure.

import type { FieldError, FormRead } from "../reviewer/forms.js";

/** One knock-out result as the form holds it. `null` is no choice yet. */
export type KnockOutChoice = "pass" | "fail" | null;

/** One knock-out outcome as `RecordKnockOut` takes it. */
export interface KnockOutOutcome {
  readonly criterion: string;
  readonly passed: boolean;
}

/** The choice for `criterion`, or `null` when the form holds none. */
function choiceOf(results: Readonly<Record<string, KnockOutChoice>>, criterion: string): KnockOutChoice {
  if (!Object.hasOwn(results, criterion)) {
    return null;
  }
  const v = results[criterion];
  return v === "pass" || v === "fail" ? v : null;
}

/**
 * Reads the knock-out form against the P-09 criteria, in P-09 order.
 *
 * - Every criterion needs an explicit result, with no preset: one
 *   `required` error per missing result. Choices for unknown criteria
 *   are ignored.
 * - A failed criterion needs a reason, which `RecordKnockOut` records:
 *   a `reason` error after the criterion errors.
 * - The value lists one outcome per criterion in P-09 order. The reason
 *   is the text as typed, or null when it is empty.
 */
export function readKnockOut(
  criteria: readonly string[],
  input: {
    readonly results: Readonly<Record<string, KnockOutChoice>>;
    readonly reason: string;
  },
): FormRead<{ readonly outcomes: readonly KnockOutOutcome[]; readonly reason: string | null }> {
  const errors: FieldError[] = [];
  const outcomes: KnockOutOutcome[] = [];
  let failed = false;
  for (const criterion of criteria) {
    const v = choiceOf(input.results, criterion);
    if (v === null) {
      errors.push({ field: criterion, reason: "required" });
    } else {
      outcomes.push({ criterion, passed: v === "pass" });
      failed = failed || v === "fail";
    }
  }
  if (failed && input.reason === "") {
    errors.push({ field: "reason", reason: "required" });
  }
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true, value: { outcomes, reason: input.reason === "" ? null : input.reason } };
}
