// stepup.ts (M4 design section 3.9, ADR-014 "Step-up"). On
// `step_up_required`, run the M3 WebAuthn ceremony for the challenge's
// digest and retry once. On `strong_method_required`, send the user to add
// a passkey first, which is itself a high-risk action under M3's rules.

import { type AssertionBody, Failure } from "../src/auth/webauthn.js";
import { type StepUpChallenge, createApi } from "../src/core/api.js";
import { type CeremonyPorts, STEP_UP_ROUTE, proveStepUp, withStepUp } from "../src/core/stepup.js";
import type { ApiOutcome, StepUpDeps } from "./support/contract.js";
import { assert, eq, test } from "./support/harness.js";
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

// ------------------------------------------------- the M3 ceremony and the wire

const WIRE_CHALLENGE: StepUpChallenge = Object.freeze({
  challengeId: "00112233445566778899aabbccddeeff",
  digest: "cd".repeat(32),
  publicKey: Object.freeze({ challenge: "c3RlcC11cA", userVerification: "required" }),
});

const ASSERTION: AssertionBody = Object.freeze({
  authenticator_data: "aa",
  client_data_json: "bb",
  credential_id: "cc",
  signature: "dd",
});

function ports(status: number): { ports: CeremonyPorts; asserted: unknown[]; posted: [string, unknown][] } {
  const asserted: unknown[] = [];
  const posted: [string, unknown][] = [];
  return {
    ports: {
      assertion: async (publicKey) => {
        asserted.push(publicKey);
        return ASSERTION;
      },
      post: async (path, body) => {
        posted.push([path, body]);
        return { status };
      },
    },
    asserted,
    posted,
  };
}

/**
 * I-78, design section 3.7 step 7: the proof runs the M3 assertion over
 * the challenge's own request options and sends it with the challenge id
 * to the M3 step-up route.
 */
test("i78_stepup_proof_sends_the_assertion_for_the_challenge", async () => {
  const p = ports(200);
  await proveStepUp(WIRE_CHALLENGE, p.ports);
  eq(p.asserted, [WIRE_CHALLENGE.publicKey], "one assertion, over the challenge's options");
  eq(
    p.posted,
    [[STEP_UP_ROUTE, { ...ASSERTION, challenge_id: WIRE_CHALLENGE.challengeId }]],
    "one post to the M3 route with the challenge id",
  );
  eq(STEP_UP_ROUTE, "/auth/stepup", "the M3 route");
});

/** I-78: a refused or failed proof throws the M3 failure of its status, so the dialog shows it. */
test("i78_stepup_proof_refused_reply_throws", async () => {
  for (const [status, code] of [
    [403, "refused"],
    [401, "session"],
    [0, "unavailable"],
    [503, "unavailable"],
  ] as const) {
    let thrown: unknown = null;
    try {
      await proveStepUp(WIRE_CHALLENGE, ports(status).ports);
    } catch (e) {
      thrown = e;
    }
    assert(thrown instanceof Failure, `status ${status}: an auth Failure`);
    eq(thrown.code, code, `status ${status}: failure code`);
  }
});

/**
 * I-78, ADR-014 "Step-up": over the wire, a `step_up_required` answer
 * runs the ceremony for its challenge, and the same request is sent once
 * more after the proof is recorded.
 */
test("i78_stepup_wire_runs_ceremony_then_retries_the_same_request", async () => {
  const requests: { url: string; method: string; body: string | null }[] = [];
  const answers = [
    { status: 401, body: { code: "step_up_required", challenge: { challenge_id: WIRE_CHALLENGE.challengeId, digest: WIRE_CHALLENGE.digest, public_key: WIRE_CHALLENGE.publicKey } } },
    { status: 200, body: { accepted: true } },
  ];
  const fetch = async (url: string, init: RequestInit): Promise<Response> => {
    requests.push({ url, method: init.method ?? "GET", body: typeof init.body === "string" ? init.body : null });
    const a = answers[Math.min(requests.length - 1, answers.length - 1)];
    return new Response(JSON.stringify(a?.body), { status: a?.status ?? 500, headers: { "content-type": "application/json" } });
  };
  const api = createApi({ fetch });
  const op = { method: "POST", path: "/programmes/{programme}/activation", base: "api" } as const;
  const p = ports(200);
  const seen: StepUpChallenge[] = [];
  const out = await withStepUp(() => api.call(op, { programme: "7" }, { revision: { entry: "5", seq: "2" } }, () => true), {
    ceremony: async (c) => {
      seen.push(c);
      await proveStepUp(c, p.ports);
      return true;
    },
    addPasskey: () => {
      throw new Error("no passkey enrolment");
    },
  });
  eq(out, { kind: "done", body: { accepted: true } }, "outcome after the retry");
  eq(seen, [WIRE_CHALLENGE], "the ceremony got the challenge of the answer");
  eq(requests.length, 2, "the action was sent twice");
  eq(requests[0], requests[1], "the retry is the same request");
  eq(requests[0]?.url, "/api/v1/programmes/7/activation", "url");
  eq(p.posted.length, 1, "one proof recorded");
});

/** I-77, ADR-014 "Step-up": over the wire, `strong_method_required` sends the user to add a passkey, with no retry. */
test("i77_stepup_wire_strong_method_sends_to_add_passkey", async () => {
  let sent = 0;
  const fetch = async (): Promise<Response> => {
    sent += 1;
    return new Response('{"code":"strong_method_required"}', { status: 403, headers: { "content-type": "application/json" } });
  };
  const api = createApi({ fetch });
  let passkey = 0;
  const out = await withStepUp(() => api.call({ method: "POST", path: "/programmes", base: "api" }, {}, {}, () => true), {
    ceremony: async () => {
      throw new Error("no ceremony");
    },
    addPasskey: () => {
      passkey += 1;
    },
  });
  eq(out, { kind: "strong_method_required" }, "outcome");
  eq(sent, 1, "no retry");
  eq(passkey, 1, "sent to add a passkey once");
});
