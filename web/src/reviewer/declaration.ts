// Page logic of the conflict declaration (R-CF-02, R-CF-04; M4 design
// section 2.2, lane W4c). The FSTP coordinator, the assigned reviewers
// and the IRC members all declare through this one form.
//
// The module is pure.

import type { FormRead } from "./forms.js";

/** What the declaration form holds. `null` is no choice yet. */
export interface DeclarationInput {
  readonly conflicted: "yes" | "no" | null;
  readonly notifiable: boolean;
}

/** A declaration as `DeclareConflict` takes it. */
export interface Declaration {
  readonly conflicted: boolean;
  readonly notifiable: boolean;
}

/**
 * Reads the declaration form.
 *
 * - No answer is preset (R-CF-02): no choice gives a `conflicted` error,
 *   so nothing is declared by default.
 * - A notifiable conflict is a conflict (R-CF-04): `notifiable` without
 *   a declared conflict gives a `notifiable` error. Interim, pending
 *   Daniel.
 */
export function readDeclaration(input: DeclarationInput): FormRead<Declaration> {
  const errors: { field: string; reason: string }[] = [];
  const chosen = input.conflicted === "yes" || input.conflicted === "no";
  if (!chosen) {
    errors.push({ field: "conflicted", reason: "required" });
  }
  if (input.notifiable === true && input.conflicted !== "yes") {
    errors.push({ field: "notifiable", reason: "needs_conflict" });
  }
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true, value: { conflicted: input.conflicted === "yes", notifiable: input.notifiable === true } };
}
