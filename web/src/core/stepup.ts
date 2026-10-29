// Step-up for high-risk actions (M4 design section 3.9, ADR-014
// "Step-up").
//
// On `step_up_required`, the M3 WebAuthn ceremony runs for the challenge,
// which binds the action's digest, and the action is retried once. On
// `strong_method_required`, the user is sent to add a passkey first,
// which is itself a high-risk action under M3's enrolment rules. The
// ceremony lives in `web/src/auth` (lane W3c). This module takes it as a
// dependency, so it holds no WebAuthn code of its own.

import type { ApiOutcome } from "./api.js";

/** What `withStepUp` needs from the page and from the M3 ceremony. */
export interface StepUpDeps {
  /** Runs the M3 WebAuthn step-up for the challenge. True when it completed. */
  ceremony(challenge: unknown): Promise<boolean>;
  /** Sends the user to add a passkey first. */
  addPasskey(): void;
}

/**
 * Runs `attempt`. On `step_up_required`, runs the ceremony for its
 * challenge and, when the ceremony completed, retries once and returns
 * that outcome, whatever it is. A cancelled, failed or throwing ceremony
 * returns the step-up request without a retry. On
 * `strong_method_required`, calls `addPasskey` and does not retry. Any
 * other outcome is returned as it is.
 */
export async function withStepUp(attempt: () => Promise<ApiOutcome>, deps: StepUpDeps): Promise<ApiOutcome> {
  const first = await attempt();
  if (first.kind === "strong_method_required") {
    deps.addPasskey();
    return first;
  }
  if (first.kind !== "step_up_required") {
    return first;
  }
  let completed: unknown;
  try {
    completed = await deps.ceremony(first.challenge);
  } catch {
    return first;
  }
  if (completed !== true) {
    return first;
  }
  return attempt();
}
