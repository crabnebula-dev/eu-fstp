// The shared kit of the M5 post-grant screens (lanes L-UI1 and L-UI2):
// calls through the generated operation table with step-up, the role
// checks, and small element builders over the Judging page kit.
//
// - An operation is found by its registry name in `gen/api.ts`. A name
//   the table lacks is "not available", and no request is made.
// - A high-risk operation answers `step_up_required`. The step-up
//   dialog of the creator pages runs the M3 ceremony, and the call is
//   retried once (I-78, ADR-014 "Step-up").
// - Bodies are sent in canonical form (RFC 8785).
// - Role checks only decide which actions a page offers. The cell
//   decides every action again, and a refusal shows its rule (I-86).

import { ceremony } from "../creator/stepup.js";
import { h, type Child } from "../core/dom.js";
import type { I18n, Label } from "../core/i18n.js";
import { withStepUp } from "../core/stepup.js";
import type { ApiOutcome } from "../core/api.js";
import { myRoles } from "../home/session.js";
import type { MyRoles, RoleName } from "../home/model.js";
import {
  buttonEl,
  formEl,
  opRef,
  pageI18n,
  textArea,
  textField,
  type Answer,
  type Frame,
  type PageEnv,
  type Problem,
} from "../reviewer/kit.js";
import { CONTRACT_LABELS } from "../contract/messages.en.js";
import { OPERATIONS_LABELS } from "../operations/messages.en.js";
import { PAYMENTS_LABELS } from "../payments/messages.en.js";
import { canonicalBody } from "./models.js";
import { GRANT_LABELS } from "./messages.en.js";
import { VISIBILITY_LABELS } from "./visibility/messages.en.js";

export { buttonEl, formEl, textArea, textField };
export type { Frame, PageEnv };

/** The catalogue of every post-grant page. */
export function labels(env: PageEnv): I18n {
  return pageI18n(env, { ...GRANT_LABELS, ...CONTRACT_LABELS, ...PAYMENTS_LABELS, ...OPERATIONS_LABELS, ...VISIBILITY_LABELS });
}

/** What a call that needs the step-up and the passkey page needs from the page. */
function deps(env: PageEnv): { ceremony: typeof ceremony; addPasskey: () => void } {
  return { ceremony, addPasskey: () => env.navigate("/auth/account") };
}

function problemOf(o: ApiOutcome): Problem {
  switch (o.kind) {
    case "refused":
      return { kind: "refused", code: o.code, rule: o.rule };
    case "failed":
      return { kind: "failed", reason: o.reason };
    default:
      return { kind: "unexpected" };
  }
}

/**
 * Calls the operation `name`. `decode` reads the body of a completed
 * call and gives null to refuse it. The call goes through the step-up
 * when the cell asks for one.
 */
export async function act<T>(
  env: PageEnv,
  name: string,
  params: Readonly<Record<string, string>>,
  body: unknown,
  decode: (v: unknown) => T | null,
): Promise<Answer<T>> {
  const op = opRef(name);
  if (op === null) {
    return { ok: false, problem: { kind: "unavailable" } };
  }
  const box: { v: T | null } = { v: null };
  const validate = (x: unknown): boolean => {
    box.v = decode(x);
    return box.v !== null;
  };
  const sent = body === undefined ? undefined : canonicalBody(body);
  let o: ApiOutcome;
  try {
    o = await withStepUp(() => env.api.call(op, params, sent, validate), deps(env));
  } catch {
    return { ok: false, problem: { kind: "failed", reason: "request" } };
  }
  if (o.kind === "done" && box.v !== null) {
    return { ok: true, data: box.v };
  }
  if (o.kind === "done") {
    return { ok: false, problem: { kind: "failed", reason: "invalid_response" } };
  }
  return { ok: false, problem: problemOf(o) };
}

/** A command's reply: any JSON object. */
export function anyObject(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

/** The caller's roles, or null when they could not be read (then every action is offered). */
export async function rolesOrNull(): Promise<MyRoles | null> {
  const a = await myRoles();
  return a.kind === "roles" ? a.roles : null;
}

/**
 * Whether the caller may be offered the actions of `role`. With
 * `proposal`, a Receiving binding must name that proposal. Unknown roles
 * offer everything, and the cell refuses what it must (I-86).
 */
export function can(roles: MyRoles | null, role: RoleName, proposal?: string): boolean {
  if (roles === null) {
    return true;
  }
  if (role === "applicant" || role === "applicant_team_member" || role === "guardian") {
    return roles.roles.some((b) => b.role === role && (proposal === undefined || b.proposal === proposal));
  }
  if (role === "financial_signatory" || role === "legal_signatory") {
    return roles.signatories.includes(role);
  }
  return roles.roles.some((b) => b.role === role && b.proposal === null);
}

/** The programmes of the caller's bindings of `role`, ascending. */
export function programmesOf(roles: MyRoles | null, role: RoleName): readonly string[] {
  if (roles === null) {
    return [];
  }
  return [...new Set(roles.roles.filter((b) => b.role === role && b.proposal === null).map((b) => b.programme))].sort(
    (a, b) => (a.length === b.length ? (a < b ? -1 : 1) : a.length - b.length),
  );
}

/** The paths of the post-grant pages. */
export const GRANT_PATHS = Object.freeze({
  hub: "/app/grants",
  grant: (p: string): string => `/app/grants/${p}`,
  contract: (p: string): string => `/app/grants/${p}/contract`,
  payments: (p: string): string => `/app/grants/${p}/payments`,
  visibility: (p: string): string => `/app/grants/${p}/visibility`,
  paymentNew: (p: string): string => `/app/grants/${p}/payments/new`,
  payment: (p: string, r: string): string => `/app/grants/${p}/payments/${r}`,
  resubmit: (p: string, r: string): string => `/app/grants/${p}/payments/${r}/resubmit`,
  operations: "/app/operations",
  reports: (programme: string): string => `/app/programmes/${programme}/reports`,
});

/** A link. */
export function link(href: string, text: Label): HTMLElement {
  return h("a", { href }, [text]);
}

/**
 * A status chip: one translated label in a `.badge`. The formal state
 * code stays in the page as visually hidden text and as `data-state`, so
 * the legal state is never ambiguous to assistive technology (I-96) and
 * nobody reads the same words twice.
 */
export function badge(plain: Label | string, formal: string): HTMLElement {
  return h("span", { class: "state-chip", "data-state": formal }, [
    h("span", { class: "badge badge--info" }, [plain]),
    h("span", { class: "state-name fstp-visually-hidden" }, [` (${formal})`]),
  ]);
}

/** A `dl` of label and value pairs. */
export function facts(rows: readonly (readonly [Label, Child])[]): HTMLElement {
  return h(
    "dl",
    {},
    rows.flatMap(([k, v]) => [h("dt", {}, [k]), h("dd", {}, [v])]),
  );
}

/** A section with its heading. */
export function section(id: string, title: Label, children: readonly Child[]): HTMLElement {
  return h("section", { id, "aria-labelledby": `${id}-heading`, class: "card" }, [
    h("h2", { id: `${id}-heading` }, [title]),
    ...children,
  ]);
}

/**
 * Wires a form's submit: runs `go` with the button disabled, and shows a
 * thrown error as a request this page could not form.
 */
export function onSubmit(f: Frame, form: HTMLFormElement, submit: HTMLButtonElement, go: () => Promise<void>): void {
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    submit.disabled = true;
    go()
      .catch(() => {
        f.problem({ kind: "failed", reason: "request" });
      })
      .finally(() => {
        submit.disabled = false;
      });
  });
}

/** A button that runs `go` once per click. */
export function actionButton(id: string, text: Label, f: Frame, go: () => Promise<void>): HTMLButtonElement {
  const b = buttonEl(id, "button", text);
  b.addEventListener("click", () => {
    b.disabled = true;
    go()
      .catch(() => {
        f.problem({ kind: "failed", reason: "request" });
      })
      .finally(() => {
        b.disabled = false;
      });
  });
  return b;
}

/** Whether `to` is the vault origin of this cell: `id.<cell host>` on the page's scheme and port. */
export function isVaultUrl(to: string, here: { readonly protocol: string; readonly hostname: string; readonly port: string }): boolean {
  let u: URL;
  try {
    u = new URL(to);
  } catch {
    return false;
  }
  return (
    u.protocol === here.protocol &&
    u.username === "" &&
    u.password === "" &&
    u.hostname === `id.${here.hostname}` &&
    u.port === here.port &&
    (u.pathname === "/w" || u.pathname === "/r") &&
    u.search === "" &&
    u.hash.length > 1
  );
}
