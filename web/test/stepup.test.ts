// stepup.ts (M4 design section 3.9, ADR-014 "Step-up"). On
// `step_up_required`, run the M3 WebAuthn ceremony for the challenge's
// digest and retry once. On `strong_method_required`, send the user to add
// a passkey first, which is itself a high-risk action under M3's rules.

import type { ApiOutcome, StepUpDeps } from "./support/contract.js";
import { eq, test } from "./support/harness.js";
import { core } from "./support/load.js";

const CHALLENGE = { id: "su-1", digest: "c2hhMjU2" };
const DONE: ApiOutcome = { kind: "done", body: { ok: true } };
const STEP: ApiOutcome = { kind: "step_up_required", challenge: CHALLENGE };
const STRONG: ApiOutcome = { kind: "strong_method_required" };

function script(outcomes: readonly ApiOutcome[]): { attempt: () => Promise<ApiOutcome>; calls: () => number } {
  let n = 0;
  return {
    attempt: async () => {
      const o = outcomes[Math.min(n, outcomes.length - 1)];
      n += 1;
      if (o === undefined) {
        throw new Error("script has no outcome");
      }
      return o;
    },
    calls: () => n,
  };
}

function deps(completes: boolean): { deps: StepUpDeps; ceremonies: unknown[]; passkey: () => number } {
  const ceremonies: unknown[] = [];
  let passkey = 0;
  return {
    deps: {
      ceremony: async (c) => {
        ceremonies.push(c);
        return completes;
      },
      addPasskey: () => {
        passkey += 1;
      },
    },
    ceremonies,
    passkey: () => passkey,
  };
}

/** ADR-014: a step-up runs the ceremony for the challenge and retries once. */
test("adr014_stepup_runs_ceremony_and_retries_once", async () => {
  const { withStepUp } = await core("stepup");
  const s = script([STEP, DONE]);
  const d = deps(true);
  eq(await withStepUp(s.attempt, d.deps), DONE, "outcome after the retry");
  eq(s.calls(), 2, "two attempts");
  eq(d.ceremonies, [CHALLENGE], "one ceremony, for the challenge given");
  eq(d.passkey(), 0, "no passkey enrolment");
});

/** ADR-014: a second step-up request after the retry is returned, never looped on. */
test("adr014_stepup_never_retries_twice", async () => {
  const { withStepUp } = await core("stepup");
  const s = script([STEP, STEP, DONE]);
  const d = deps(true);
  eq(await withStepUp(s.attempt, d.deps), STEP, "the second step-up request is returned");
  eq(s.calls(), 2, "two attempts only");
  eq(d.ceremonies.length, 1, "one ceremony only");
});

/** ADR-014: `strong_method_required` sends the user to add a passkey, with no ceremony and no retry. */
test("adr014_stepup_strong_method_required_sends_to_add_passkey", async () => {
  const { withStepUp } = await core("stepup");
  const s = script([STRONG, DONE]);
  const d = deps(true);
  eq(await withStepUp(s.attempt, d.deps), STRONG, "outcome");
  eq(s.calls(), 1, "no retry");
  eq(d.ceremonies.length, 0, "no ceremony");
  eq(d.passkey(), 1, "sent to add a passkey once");
});

/** ADR-014: a cancelled or failed ceremony does not retry the action. */
test("adr014_stepup_cancelled_ceremony_does_not_retry", async () => {
  const { withStepUp } = await core("stepup");
  const s = script([STEP, DONE]);
  const d = deps(false);
  eq(await withStepUp(s.attempt, d.deps), STEP, "the step-up request is returned");
  eq(s.calls(), 1, "no retry");
  eq(d.ceremonies.length, 1, "one ceremony attempted");
});

/** ADR-014: every other outcome passes through after one attempt. */
test("adr014_stepup_other_outcomes_pass_through", async () => {
  const { withStepUp } = await core("stepup");
  const others: readonly ApiOutcome[] = [
    DONE,
    { kind: "pending", confirmPath: "/app/pending/p1", expires: "2026-10-30T10:00:00Z" },
    { kind: "refused", code: "refused", rule: "I-03" },
    { kind: "failed", reason: "network" },
  ];
  for (const o of others) {
    const s = script([o, DONE]);
    const d = deps(true);
    eq(await withStepUp(s.attempt, d.deps), o, `outcome ${o.kind}`);
    eq(s.calls(), 1, `${o.kind}: one attempt`);
    eq(d.ceremonies.length, 0, `${o.kind}: no ceremony`);
  }
});
