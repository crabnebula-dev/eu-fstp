// Calls of the applicant and call pages, by operation name (M4 design
// sections 2.2 J4, 3.6 and 3.9).
//
// A page names an operation of the registry, such as `proposal.view`.
// Its method and path come from the generated table in `gen/api.ts`, and
// never from this lane. An operation the table does not hold is not
// called, and the page says that the action is not available.
//
// The generated table writes paths relative to `/api/v1` with `base`
// `"api"`, and core `api.ts` reads that form. An entry whose `base` is
// not `api` is a public page, never called from here.

import { type ApiClient, type ApiOutcome, type OperationRef, createApi } from "../core/api.js";
import { OPERATIONS } from "../gen/api.js";
import { type Body, canonical } from "./wire.js";

/** The operations the applicant and call pages call (design section 2.2 J4). */
export type ApplicantOp =
  | "calls.list_open"
  | "calls.get"
  | "calls.guide"
  | "proposal.create"
  | "proposal.list_own"
  | "proposal.view"
  | "proposal.get_workspace"
  | "proposal.save_workspace"
  | "proposal.record_plan"
  | "proposal.add_member"
  | "proposal.add_guardian"
  | "proposal.state_country"
  | "proposal.declare_affiliations"
  | "proposal.state_birth_date"
  | "proposal.submit"
  | "proposal.request_copy"
  | "proposal.withdraw"
  | "me.notices"
  | "stage2.view"
  | "stage2.answer"
  | "stage2.revise"
  | "guardian.begin_consent"
  | "negotiation.view"
  | "negotiation.acknowledge_notice";

/** Why a call gave no value. */
export type Failure =
  | { readonly kind: "unavailable" }
  | { readonly kind: "refused"; readonly code: string; readonly rule: string | null }
  | { readonly kind: "failed"; readonly reason: "network" | "invalid_response" | "request" }
  | { readonly kind: "step_up" }
  | { readonly kind: "pending" };

/** What a call gives: the decoded value, or why there is none. */
export type Outcome<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: Failure };

/** The generated API operation `name`, or null when the table lacks it. */
export function operationRef(name: ApplicantOp): OperationRef | null {
  for (const op of OPERATIONS) {
    if (op.name === name) {
      return op.base === "page" ? null : op;
    }
  }
  return null;
}

let client: ApiClient | null = null;

function api(): ApiClient {
  client ??= createApi({ fetch: (input, init) => globalThis.fetch(input, init) });
  return client;
}

function failureOf(o: ApiOutcome): Failure {
  switch (o.kind) {
    case "refused":
      return Object.freeze({ kind: "refused", code: o.code, rule: o.rule });
    case "failed":
      return Object.freeze({ kind: "failed", reason: o.reason });
    case "step_up_required":
    case "strong_method_required":
      return Object.freeze({ kind: "step_up" });
    case "pending":
      return Object.freeze({ kind: "pending" });
    default:
      return Object.freeze({ kind: "failed", reason: "invalid_response" });
  }
}

/**
 * Calls `name` with its path parameters and, for a command, its body,
 * sent as canonical JSON. `decode` reads the response body and gives
 * null to refuse it. It never throws.
 */
export async function call<T>(
  name: ApplicantOp,
  params: Readonly<Record<string, string>>,
  body: Body | undefined,
  decode: (v: unknown) => T | null,
): Promise<Outcome<T>> {
  const ref = operationRef(name);
  if (ref === null) {
    return Object.freeze({ ok: false, failure: Object.freeze({ kind: "unavailable" }) });
  }
  const box: { value: T | null } = { value: null };
  const validate = (v: unknown): boolean => {
    box.value = decode(v);
    return box.value !== null;
  };
  let o: ApiOutcome;
  try {
    o = await api().call(ref, params, body === undefined ? undefined : canonical(body), validate);
  } catch {
    return Object.freeze({ ok: false, failure: Object.freeze({ kind: "failed", reason: "network" }) });
  }
  if (o.kind === "done" && box.value !== null) {
    return Object.freeze({ ok: true, value: box.value });
  }
  return Object.freeze({ ok: false, failure: failureOf(o) });
}
