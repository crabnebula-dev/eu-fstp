// Calls to the operations of the registry (M4 design sections 2.2, 3.7
// and 3.9), shared by the creator, onboarding and people pages.
//
// - An operation is found by its registry name, such as
//   `creator.save_fields`, in the generated table `OPERATIONS` of
//   `web/src/gen/api.ts` (lane W3a). Its route comes from there, never
//   from this module. An operation the table lacks is `unavailable`, and
//   the page says so.
// - Path parameters fill the operation's `{name}` segments in order, so
//   this module never guesses a parameter name. A call must give exactly
//   one value per segment.
// - Bodies are sent with their members sorted, so the JSON text is the
//   RFC 8785 canonical form the cell takes (design section 8.2).
// - Every call runs through core `withStepUp`. When the server answers
//   `step_up_required`, the step-up dialog opens and the call is retried
//   once after the ceremony (ADR-014 "Step-up").
//
// The generated operation goes to core `api.ts` as it is: its path is
// relative to `/api/v1` with `base` `"api"`. A `"page"` operation is a
// public page and is never called from here.

import { createApi, type ApiOutcome, type OperationRef } from "../core/api.js";
import { withStepUp } from "../core/stepup.js";
import { OPERATIONS } from "../gen/api.js";
import { warn } from "./frame.js";
import { t } from "./i18n.js";
import { canonicalJson, record } from "./model.js";
import { ceremony } from "./stepup.js";

/** The outcome of one call: core's outcomes, or an operation the registry lacks. */
export type Outcome = ApiOutcome | { readonly kind: "unavailable"; readonly name: string };

const api = createApi({ fetch: (input, init) => fetch(input, init) });

const PARAM = /^\{([a-z][a-z0-9_]*)\}$/;

/**
 * The API operation named `name` in the generated table, or null. A name
 * the registry lacks, or a public page, is null. Core `api.ts` checks the
 * operation's base and path.
 */
function find(name: string): OperationRef | null {
  for (const op of OPERATIONS) {
    if (op.name === name) {
      return op.base === "page" ? null : op;
    }
  }
  return null;
}

/** The `{name}` parameters of `path`, in order. */
function paramNames(path: string): string[] {
  const out: string[] = [];
  for (const seg of path.split("/")) {
    const m = PARAM.exec(seg);
    if (m !== null && m[1] !== undefined) {
      out.push(m[1]);
    }
  }
  return out;
}

/** A copy of `v` with every object's members in sorted order. */
function sorted(v: unknown): unknown {
  if (Array.isArray(v)) {
    return (v as unknown[]).map(sorted);
  }
  const o = record(v);
  if (o === null) {
    return v;
  }
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(o).sort()) {
    out[k] = sorted(o[k]);
  }
  return out;
}

/** Sends the user to add a passkey first: the account page of M3. */
function addPasskey(): void {
  location.assign("/auth/account");
}

/**
 * Calls operation `name` with path parameters `values` and `body`.
 * `accept` reads the body of a 2xx reply and refuses any other shape.
 * A body that is not plain JSON data makes no request.
 */
export async function call(
  name: string,
  values: readonly string[],
  body: unknown,
  accept: (v: unknown) => boolean,
): Promise<Outcome> {
  const op = find(name);
  if (op === null) {
    return { kind: "unavailable", name };
  }
  const names = paramNames(op.path);
  if (names.length !== values.length) {
    return { kind: "failed", reason: "request" };
  }
  const params: Record<string, string> = {};
  names.forEach((n, i) => {
    params[n] = values[i] ?? "";
  });
  let payload: unknown = undefined;
  if (body !== undefined) {
    if (canonicalJson(body) === null) {
      return { kind: "failed", reason: "request" };
    }
    payload = sorted(body);
  }
  return withStepUp(() => api.call(op, params, payload, accept), { ceremony, addPasskey });
}

/** Accepts any JSON object, for replies whose members a page does not read. */
export function anyObject(v: unknown): boolean {
  return record(v) !== null;
}

/**
 * Shows the outcome of a call that did not complete in the page alert,
 * and returns true. A done call shows nothing and returns false. A
 * step-up the person cancelled says that nothing was sent.
 */
export function report(alert: HTMLElement, o: Outcome): boolean {
  switch (o.kind) {
    case "done":
      return false;
    case "step_up_required":
      warn(alert, t.label("outcome.step_up_cancelled"));
      return true;
    case "strong_method_required":
      warn(alert, t.label("outcome.strong_method"));
      return true;
    case "pending":
      warn(alert, t.label("outcome.pending"));
      return true;
    case "unavailable":
      warn(alert, t.label("outcome.unavailable"));
      return true;
    case "refused":
      warn(alert, o.rule === null ? t.label("outcome.refused") : t.label("outcome.refused_rule", { rule: o.rule }), o.rule);
      return true;
    case "failed":
      warn(
        alert,
        o.reason === "network"
          ? t.label("outcome.network")
          : o.reason === "request"
            ? t.label("outcome.request")
            : t.label("outcome.invalid_response"),
      );
      return true;
  }
}
