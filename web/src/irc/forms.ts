// Page logic of the IRC verdict (J8, R-IR-01, R-IR-02; M4 design
// section 2.2, lane W4c).
//
// The module is pure. It names the verdict and the concern only, so the
// IRC pages carry nothing of the committee's work (R-IR-03).

import type { FieldError, FormRead } from "../reviewer/forms.js";

/** What the IRC verdict form holds. `null` is no choice yet. */
export interface VerdictInput {
  readonly verdict: "validate" | "concern" | null;
  readonly concern: string;
}

/** A verdict as `RecordIrcReview` takes it. */
export type Verdict = { readonly verdict: "validate" } | { readonly verdict: "concern"; readonly concern: string };

/**
 * Reads the verdict form.
 *
 * - No verdict is preset (R-IR-01): no choice gives a `verdict` error.
 * - A concern goes to the applicant, so it needs its text (R-IR-02).
 * - A validation carries no text, even when the concern field holds
 *   some, so text typed for a concern never travels with a validation.
 */
export function readVerdict(input: VerdictInput): FormRead<Verdict> {
  if (input.verdict === "validate") {
    return { ok: true, value: { verdict: "validate" } };
  }
  if (input.verdict === "concern") {
    if (input.concern === "") {
      const errors: FieldError[] = [{ field: "concern", reason: "required" }];
      return { ok: false, errors };
    }
    return { ok: true, value: { verdict: "concern", concern: input.concern } };
  }
  return { ok: false, errors: [{ field: "verdict", reason: "required" }] };
}
