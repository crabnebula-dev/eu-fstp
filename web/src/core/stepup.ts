// Step-up for high-risk actions (M4 design sections 3.7 step 7 and 3.9,
// ADR-014 "Step-up", I-78).
//
// On `step_up_required`, the M3 WebAuthn ceremony runs for the challenge,
// which binds the action's digest, and the action is retried once. On
// `strong_method_required`, the user is sent to add a passkey first,
// which is itself a high-risk action under M3's enrolment rules.
//
// The ceremony is the M3 one of `web/src/auth`, so this module holds no
// WebAuthn code of its own:
//
// 1. A passkey assertion with user verification over the challenge's
//    request options (`auth/webauthn.ts` `assertion`).
// 2. `POST /auth/stepup` with the assertion and `challenge_id`. The cell
//    checks the assertion against the challenge it stored for this
//    session and digest, and records the proof (`StepUp::finish`).
//
// The retry then sends the same request again. The server takes the
// proof for the same digest (`StepUp::take`), so the retry carries no
// step-up member. Interim, pending Daniel and lanes W3b and W4e, which
// fix the server side of this wire.
//
// A page supplies the `ceremony` of `withStepUp`: a dialog whose confirm
// button gives the user gesture and calls `proveStepUp`.

import { post } from "../auth/api.js";
import type { Json } from "../auth/encoding.js";
import { type AssertionBody, assertion, failureOf } from "../auth/webauthn.js";
import type { ApiOutcome, StepUpChallenge } from "./api.js";

/** The M3 route that verifies a step-up assertion and records the proof. */
export const STEP_UP_ROUTE = "/auth/stepup";

/** What the step-up ceremony needs: the M3 assertion and the M3 route. */
export interface CeremonyPorts {
  /** Runs the WebAuthn assertion for the request options. Throws an auth `Failure`. */
  assertion(publicKey: Readonly<Record<string, unknown>>): Promise<AssertionBody>;
  /** Posts `body` to the same-origin `path` and gives the reply status, or 0. */
  post(path: string, body: Json): Promise<{ readonly status: number }>;
}

/** The M3 ceremony of `web/src/auth`. */
const M3_PORTS: CeremonyPorts = Object.freeze({ assertion, post });

/**
 * Runs the M3 WebAuthn step-up for `challenge`: the assertion over its
 * request options, then `POST /auth/stepup` with the assertion and the
 * challenge id. Resolves once the cell recorded the proof for the
 * challenge's digest. Throws an auth `Failure` otherwise: the ceremony's
 * own, or the one of the reply status.
 */
export async function proveStepUp(challenge: StepUpChallenge, ports: CeremonyPorts = M3_PORTS): Promise<void> {
  const a = await ports.assertion(challenge.publicKey);
  const body: Json = {
    authenticator_data: a.authenticator_data,
    challenge_id: challenge.challengeId,
    client_data_json: a.client_data_json,
    credential_id: a.credential_id,
    signature: a.signature,
  };
  const r = await ports.post(STEP_UP_ROUTE, body);
  if (!(r.status >= 200 && r.status <= 299)) {
    throw failureOf(r.status);
  }
}

/** What `withStepUp` needs from the page. */
export interface StepUpDeps {
  /**
   * Runs the step-up for the challenge, normally a dialog that calls
   * `proveStepUp`. True when the proof was recorded.
   */
  ceremony(challenge: StepUpChallenge): Promise<boolean>;
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
