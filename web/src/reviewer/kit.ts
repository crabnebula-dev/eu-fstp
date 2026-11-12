// The page kit of the Judging pages (lane W4c, M4 design sections 2.2,
// 3.6 and 3.9, ADR-014). It holds the page frame, API calls through the
// generated operation table, and closed response checks. It also holds
// field errors and the one conflict declaration form.
//
// The coordinator, reviewer, committee and IRC pages build on it. It
// shows server text only through text nodes (`core/dom.ts`), and it
// accepts a response only when its check accepts every member, so a
// member a Judging read model must not carry is refused, never shown
// (I-17, design section 3.9).
//
// Interim readings, pending Daniel and the lead's merge of lanes W3a,
// W3b and W4e:
//
// - Operations are looked up by their registry name in `gen/api.ts`. An
//   operation the table does not hold yet is "not available", and no
//   request is made. The generated operation goes to core `api.ts` as it
//   is, with its path relative to `/api/v1`.
// - A completed call answers with its read model as the whole body, as
//   core `api.ts` reads every page's answers.
// - The read models are this lane's reading of design section 3.6. Each
//   check is closed: an unknown or missing member refuses the answer.

import { createApi, type ApiClient, type ApiOutcome, type OperationRef } from "../core/api.js";
import { clearError, linkError } from "../core/a11y.js";
import { h, type AttrValue, type Child } from "../core/dom.js";
import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { parseAmount } from "../core/money.js";
import { navigate, whenLeft, type RouteDef } from "../core/router.js";
import { OPERATIONS } from "../gen/api.js";
import { appShell } from "../home/nav.js";
import { callTitle, followTitles } from "../home/titles.js";
import { readDeclaration, type Declaration } from "./declaration.js";
import { KIT_LABELS } from "./kit.en.js";

// ---------------------------------------------------------------------------
// Pages and their environment
// ---------------------------------------------------------------------------

/** What a page needs from the application around it. */
export interface PageEnv {
  /** The API client of `core/api.ts`. */
  readonly api: ApiClient;
  /** The element the page renders into, such as the shell's `#app`. */
  readonly root: HTMLElement;
  /** Opens another page of the application by its path. */
  readonly navigate: (path: string) => void;
  /** Tenant terminology for labels (I-72 seam). Approved text is never overridden. */
  readonly overrides?: Readonly<Record<string, string>>;
}

/** One page: its route below `/app/` and how it mounts. */
export interface JudgingPage {
  readonly route: RouteDef;
  mount(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void>;
}

/**
 * The name of `call` for a page title: its published title from the
 * caller's own `me.roles` reply (I-86), else "call" and its id.
 */
export function callName(t: I18n, call: string): string {
  return callTitle(call) ?? t.label("kit.call", { id: call });
}

/**
 * Heads the page with `title(name)`, where `name` names `call`, and
 * heads it again in place when the shell learns the call's title, until
 * the person leaves the page (lane m4/site scope item 2).
 */
export function titleWithCall(f: Frame, t: I18n, call: string, title: (name: string) => Label): void {
  f.retitle(title(callName(t, call)));
  const stop = followTitles(() => {
    f.retitle(title(callName(t, call)));
  });
  whenLeft(stop);
}

/** The environment of a page in the browser: same-origin fetch and in-app navigation. */
export function browserEnv(root: HTMLElement): PageEnv {
  return {
    api: createApi({ fetch: (input, init) => fetch(input, init) }),
    root,
    navigate: (path) => navigate(path),
  };
}

/** A path parameter that names an id: a canonical decimal of at most 39 digits. */
const ID = /^(0|[1-9][0-9]{0,38})$/;

/** Whether `s` is a canonical decimal id, as the server spells ids. */
export function isIdText(s: string): boolean {
  return ID.test(s);
}

/** The route `name` at `pattern`, whose every parameter is an id. */
export function idRoute(name: string, pattern: string, params: readonly string[]): RouteDef {
  const segments: Record<string, (s: string) => boolean> = {};
  for (const p of params) {
    segments[p] = isIdText;
  }
  return { name, pattern, segments };
}

/** The catalogue of a page: the kit's labels and the feature's own. */
export function pageI18n(env: PageEnv, labels: Readonly<Record<string, string>>): I18n {
  const all: Record<string, string> = { ...KIT_LABELS };
  for (const [k, v] of Object.entries(labels)) {
    all[k] = v;
  }
  const catalogues = [{ locale: "en", labels: all, approved: {} }];
  return env.overrides === undefined
    ? createI18n({ catalogues, locale: "en" })
    : createI18n({ catalogues, locale: "en", overrides: env.overrides });
}

// ---------------------------------------------------------------------------
// Response checks
// ---------------------------------------------------------------------------

/** A check of one JSON value that narrows its type. */
export type Guard<T> = (v: unknown) => v is T;

/** A string of any content. Server text is only ever shown as text. */
export const isText: Guard<string> = (v): v is string => typeof v === "string";

/** A JSON boolean. */
export const isBool: Guard<boolean> = (v): v is boolean => typeof v === "boolean";

/** A canonical decimal id. */
export const isId: Guard<string> = (v): v is string => typeof v === "string" && ID.test(v);

/** A JSON number that is a non-negative safe integer, such as a P-01 score. */
export const isCount: Guard<number> = (v): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** An ADR-006 EUR amount in its canonical spelling. */
export const isAmount: Guard<string> = (v): v is string => parseAmount(v, "EUR").ok;

/** An effective or weighted score: a percentage with two decimals (P-02 NOTE 6). */
export const isScoreText: Guard<string> = (v): v is string =>
  typeof v === "string" && /^(0|[1-9][0-9]*)[.][0-9]{2}$/.test(v);

/** One of the given strings. */
export function oneOf<T extends string>(...values: readonly T[]): Guard<T> {
  return (v): v is T => typeof v === "string" && (values as readonly string[]).includes(v);
}

/** `null`, or a value `g` accepts. */
export function nullable<T>(g: Guard<T>): Guard<T | null> {
  return (v): v is T | null => v === null || g(v);
}

/** An array whose every item `g` accepts. */
export function list<T>(g: Guard<T>): Guard<readonly T[]> {
  return (v): v is readonly T[] => Array.isArray(v) && v.every((x) => g(x));
}

/** Either check. */
export function either<A, B>(a: Guard<A>, b: Guard<B>): Guard<A | B> {
  return (v): v is A | B => a(v) || b(v);
}

/**
 * A closed object: exactly the members of `spec`, each accepted by its
 * check. An unknown member, such as an identity field a Judging read
 * model must never carry (I-17), refuses the whole value.
 */
export function record<T extends object>(spec: { readonly [K in keyof T]-?: Guard<T[K]> }): Guard<T> {
  const checks = spec as unknown as Readonly<Record<string, Guard<unknown>>>;
  const keys = Object.keys(checks);
  return (v): v is T => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) {
      return false;
    }
    const o = v as Readonly<Record<string, unknown>>;
    const own = Object.keys(o);
    if (own.length !== keys.length || !own.every((k) => Object.hasOwn(checks, k))) {
      return false;
    }
    return keys.every((k) => {
      const g = checks[k];
      return g !== undefined && Object.hasOwn(o, k) && g(o[k]);
    });
  };
}

/** The state tags of `state-machine.md`. */
export const STATE_TAGS = [
  "DRAFT",
  "SUBMITTED",
  "INELIGIBLE",
  "STAGE1",
  "NOT_SELECTED",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "DECLINED",
  "NEGOTIATION",
  "WITHDRAWN",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "TERMINATED",
] as const;

/** A state tag, such as `STAGE1`. */
export type StateTag = (typeof STATE_TAGS)[number];

/** A state tag as the server spells it. */
export const isStateTag: Guard<StateTag> = oneOf(...STATE_TAGS);

/** `GetDeclarationView`: the title and the applicant-written neutral summary, and nothing else (Q9). */
export interface DeclarationView {
  readonly title: string;
  readonly neutral_summary: string;
}

export const isDeclarationView: Guard<DeclarationView> = record<DeclarationView>({
  title: isText,
  neutral_summary: isText,
});

/** `GetContent`: the full proposal, after a declaration of no conflict (R-CF-02). */
export interface ContentView {
  readonly proposal: string;
  readonly call: string;
  readonly state: StateTag;
  readonly title: string;
  readonly text: string;
}

export const isContentView: Guard<ContentView> = record<ContentView>({
  proposal: isId,
  call: isId,
  state: isStateTag,
  title: isText,
  text: isText,
});

/** One of the caller's assignments, as `fstp-api-core` encodes it, with no applicant identity (I-17). */
export interface AssignmentSummary {
  readonly assignment: string;
  readonly proposal: string;
  readonly call: string;
  readonly kind: "reviewer" | "irc" | "amendment";
  /** Whether the caller still has to declare (R-CF-02). */
  readonly awaiting_declaration: boolean;
  readonly active: boolean;
  /** Whether the stage 2 thread opens: an active reviewer assignment in STAGE2 (review finding U5). */
  readonly stage2: boolean;
}

export const isAssignmentSummary: Guard<AssignmentSummary> = record<AssignmentSummary>({
  assignment: isId,
  proposal: isId,
  call: isId,
  kind: oneOf("reviewer", "irc", "amendment"),
  awaiting_declaration: isBool,
  active: isBool,
  stage2: isBool,
});

/**
 * The caller's own assignment `id` of `kind`, read through `op`
 * (`me.assignments` or `me.irc_cases`). When the read fails or the list
 * does not hold it, the frame shows why, the body is left empty, and the
 * result is null.
 */
export async function ownAssignment(
  env: PageEnv,
  t: I18n,
  f: Frame,
  op: "me.assignments" | "me.irc_cases",
  id: string,
  kind: AssignmentSummary["kind"],
): Promise<AssignmentSummary | null> {
  const mine = await readOp(env, op, {}, list(isAssignmentSummary));
  if (!mine.ok) {
    f.problem(mine.problem);
    f.show([]);
    return null;
  }
  const found = mine.data.find((s) => s.assignment === id && s.kind === kind);
  if (found === undefined) {
    f.alert(t.label("kit.not_found"));
    f.show([]);
    return null;
  }
  return found;
}

/** A command's answer: it returns no read model. */
export interface Accepted {
  readonly accepted: true;
}

export const isAccepted: Guard<Accepted> = record<Accepted>({
  accepted: (v): v is true => v === true,
});

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

/** Why a call gave nothing to show. */
export type Problem =
  | { readonly kind: "refused"; readonly code: string; readonly rule: string | null }
  | { readonly kind: "failed"; readonly reason: "network" | "invalid_response" | "request" }
  | { readonly kind: "unavailable" }
  | { readonly kind: "unexpected" };

/** The outcome of a call: its checked data, or the problem. */
export type Answer<T> = { readonly ok: true; readonly data: T } | { readonly ok: false; readonly problem: Problem };

/**
 * The API operation `name` of the generated table, or null when the
 * table does not hold it yet. A public page is null too.
 */
export function opRef(name: string): OperationRef | null {
  for (const op of OPERATIONS) {
    if (op.name === name) {
      return op.base === "page" ? null : op;
    }
  }
  return null;
}

function problemOf(o: ApiOutcome): Problem {
  switch (o.kind) {
    case "refused":
      return { kind: "refused", code: o.code, rule: o.rule };
    case "failed":
      return { kind: "failed", reason: o.reason };
    default:
      // No Judging operation is high-risk, and the web channel executes
      // binding operations, so step-up and pending answers are unexpected.
      return { kind: "unexpected" };
  }
}

/**
 * Calls the operation `name` with `params` and `body`. Its data counts
 * only when `check` accepts the body of the completed call.
 */
export async function callOp<T>(
  env: PageEnv,
  name: string,
  params: Readonly<Record<string, string>>,
  body: unknown,
  check: Guard<T>,
): Promise<Answer<T>> {
  const op = opRef(name);
  if (op === null) {
    return { ok: false, problem: { kind: "unavailable" } };
  }
  const outcome = await env.api.call(op, params, body, check);
  if (outcome.kind !== "done") {
    return { ok: false, problem: problemOf(outcome) };
  }
  const data: unknown = outcome.body;
  return check(data) ? { ok: true, data } : { ok: false, problem: { kind: "failed", reason: "invalid_response" } };
}

/** A read: a GET with no body. */
export function readOp<T>(
  env: PageEnv,
  name: string,
  params: Readonly<Record<string, string>>,
  check: Guard<T>,
): Promise<Answer<T>> {
  return callOp(env, name, params, undefined, check);
}

/** A command that answers `{"accepted": true}`. */
export function writeOp(
  env: PageEnv,
  name: string,
  params: Readonly<Record<string, string>>,
  body: unknown,
): Promise<Answer<Accepted>> {
  return callOp(env, name, params, body, isAccepted);
}

/** The message for a problem. A refusal names the rule only, never an account (design section 3.7). */
export function problemText(t: I18n, p: Problem): Label {
  switch (p.kind) {
    case "refused":
      if (p.rule === "row") {
        return t.label("kit.refused_row");
      }
      if (p.rule === "actor") {
        return t.label("kit.refused_actor");
      }
      return p.rule !== null && p.rule !== ""
        ? t.label("kit.refused_rule", { rule: p.rule })
        : t.label("kit.refused_code", { code: p.code });
    case "failed":
      return p.reason === "network"
        ? t.label("kit.failed_network")
        : p.reason === "request"
          ? t.label("kit.failed_request")
          : t.label("kit.failed_response");
    case "unavailable":
      return t.label("kit.unavailable");
    default:
      return t.label("kit.unexpected");
  }
}

// ---------------------------------------------------------------------------
// Elements
// ---------------------------------------------------------------------------

/** `h` for an element whose type the caller needs. */
function typed<E extends HTMLElement>(
  ctor: abstract new () => E,
  tag: string,
  attrs: Readonly<Record<string, AttrValue>>,
  children: readonly Child[] = [],
): E {
  const el = h(tag, attrs, children);
  if (!(el instanceof ctor)) {
    throw new TypeError(`the document did not create a ${tag} element`);
  }
  return el;
}

/** An `<input>`. */
export function inputEl(attrs: Readonly<Record<string, AttrValue>>): HTMLInputElement {
  return typed(HTMLInputElement, "input", attrs);
}

/** A `<textarea>`. */
export function textareaEl(attrs: Readonly<Record<string, AttrValue>>): HTMLTextAreaElement {
  return typed(HTMLTextAreaElement, "textarea", attrs);
}

/** A `<select>` with its options. */
export function selectEl(attrs: Readonly<Record<string, AttrValue>>, options: readonly Child[]): HTMLSelectElement {
  return typed(HTMLSelectElement, "select", attrs, options);
}

/** A `<button>`. A `type` other than `submit` is a plain button. */
export function buttonEl(id: string, type: "submit" | "button", text: Label): HTMLButtonElement {
  return typed(HTMLButtonElement, "button", { id, type }, [text]);
}

/** A `<form>` that the page validates itself, so the browser shows no bubbles of its own. */
export function formEl(id: string, children: readonly Child[]): HTMLFormElement {
  return typed(HTMLFormElement, "form", { id, novalidate: true }, children);
}

/** A labelled single-line text field. */
export function textField(
  id: string,
  label: Label,
  extra: Readonly<Record<string, AttrValue>> = {},
): { readonly root: HTMLElement; readonly control: HTMLInputElement } {
  const control = inputEl({ id, name: id, type: "text", autocomplete: "off", ...extra });
  return { root: h("div", { class: "fstp-field" }, [h("label", { for: id }, [label]), control]), control };
}

/** A labelled text area. */
export function textArea(id: string, label: Label): { readonly root: HTMLElement; readonly control: HTMLTextAreaElement } {
  const control = textareaEl({ id, name: id, rows: "4" });
  return { root: h("div", { class: "fstp-field" }, [h("label", { for: id }, [label]), control]), control };
}

/** A radio button with its label. */
export function radio(
  id: string,
  name: string,
  value: string,
  label: Label,
): { readonly root: HTMLElement; readonly control: HTMLInputElement } {
  const control = inputEl({ id, name, type: "radio", value });
  return { root: h("div", { class: "fstp-choice" }, [control, h("label", { for: id }, [label])]), control };
}

/** A checkbox with its label, never checked by default. */
export function checkbox(
  id: string,
  name: string,
  label: Label,
): { readonly root: HTMLElement; readonly control: HTMLInputElement } {
  const control = inputEl({ id, name, type: "checkbox" });
  return { root: h("div", { class: "fstp-choice" }, [control, h("label", { for: id }, [label])]), control };
}

/** The paragraphs of a server text, one per non-empty line. */
export function paragraphs(text: string): HTMLElement[] {
  return text
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => h("p", {}, [line]));
}

/** The full proposal section, `#proposal-content`. */
export function contentSection(t: I18n, view: ContentView): HTMLElement {
  return h("section", { id: "proposal-content", "aria-labelledby": "proposal-content-heading" }, [
    h("h2", { id: "proposal-content-heading" }, [t.label("kit.content.heading")]),
    h("h3", {}, [view.title]),
    ...paragraphs(view.text),
  ]);
}

/** "Proposal" plus its id: how Judging pages name an applicant's proposal (I-17). */
export function proposalName(t: I18n, id: string): Label {
  return t.label("kit.proposal", { id });
}

// ---------------------------------------------------------------------------
// The page frame
// ---------------------------------------------------------------------------

/** The frame of one page: `main`, its heading, state, status and alerts. */
export interface Frame {
  /** Replaces the page body. The loading marker leaves with the first call. */
  show(children: readonly Child[]): void;
  /** Shows the page body as loading again. */
  busy(): void;
  /** Writes `#page-status`. */
  status(message: Label): void;
  /** Shows an alert above the page body. */
  alert(message: Label): void;
  /** Shows the alert for a problem. */
  problem(p: Problem): void;
  /** Removes the alert. */
  clearAlert(): void;
  /** Shows the proposal's state in `#proposal-state`. */
  state(tag: StateTag): void;
  /** Replaces the page title, in the `h1` and the document title. */
  retitle(title: Label): void;
}

/**
 * Renders the frame of a page into `env.root`: a `main` landmark with an
 * `h1`, the status region and a body that holds an `aria-busy` marker
 * until the page shows its data (R-NF-03).
 */
export function frame(env: PageEnv, t: I18n, title: Label): Frame {
  document.documentElement.lang = t.locale;
  document.title = title;
  const heading = h("h1", { id: "page-title", tabindex: "-1" }, [title]);
  const stateSlot = h("div", {});
  const alertSlot = h("div", {});
  const status = h("div", { id: "page-status", role: "status", "aria-live": "polite" });
  const body = h("div", { id: "page-body" });
  const main = h("main", { id: "main", "aria-labelledby": "page-title" }, [heading, stateSlot, alertSlot, status, body]);
  // Whether a busy marker replaced the control that held focus.
  let lost = false;
  const busy = (): void => {
    const active = document.activeElement;
    if (active !== null && body.contains(active)) {
      lost = true;
    }
    body.replaceChildren(h("p", { "aria-busy": "true" }, [t.label("kit.loading")]));
  };
  busy();
  // The page shell: skip link, top bar, and the sidebar with the site
  // navigation (`docs/design/01-navigation-home.md`, 2026-11-01).
  env.root.replaceChildren(...appShell(main));
  const showAlert = (message: Label): void => {
    alertSlot.replaceChildren(h("div", { role: "alert", class: "fstp-alert" }, [message]));
  };
  // An in-place update that removes the focused control, such as the
  // sheet of a recorded score, moves focus to what the page says about
  // it: the alert, else the status message, else the heading (WCAG 2.2
  // SC 2.4.3). A body that did not hold focus leaves focus where it is.
  const refocus = (): void => {
    const active = document.activeElement;
    if (active !== null && active !== document.body && active.isConnected) {
      return;
    }
    const target =
      alertSlot.firstElementChild instanceof HTMLElement
        ? alertSlot.firstElementChild
        : (status.textContent ?? "").trim() !== ""
          ? status
          : heading;
    if (!target.hasAttribute("tabindex")) {
      target.setAttribute("tabindex", "-1");
    }
    target.focus();
  };
  return {
    show(children) {
      const active = document.activeElement;
      const held = lost || (active !== null && body.contains(active));
      lost = false;
      body.replaceChildren(...children);
      if (held) {
        refocus();
      }
    },
    busy,
    status(message) {
      status.replaceChildren(message);
    },
    alert: showAlert,
    problem(p) {
      showAlert(problemText(t, p));
    },
    clearAlert() {
      alertSlot.replaceChildren();
    },
    state(tag) {
      stateSlot.replaceChildren(
        h("p", { id: "proposal-state", "data-state": tag }, [
          h("span", { class: "badge badge--info" }, [t.label("kit.state", { state: t.label(`kit.state.${tag}`) })]),
          " ",
          h("span", { class: "state-name" }, [tag]),
        ]),
      );
    },
    retitle(next) {
      heading.replaceChildren(next);
      document.title = next;
    },
  };
}

/**
 * The chip of a proposal state: its label as text in a `.badge`, beside
 * its formal name (R-NF-03: state is never shown by colour alone; I-96).
 */
export function stateChip(t: I18n, tag: StateTag): HTMLElement {
  return h("span", { class: "state-chip" }, [
    h("span", { class: "badge badge--info" }, [t.label(`kit.state.${tag}`)]),
    " ",
    h("span", { class: "state-name" }, [tag]),
  ]);
}

/**
 * Runs `act` and shows a problem when it throws, so a page never fails
 * silently. A thrown error is shown as a request this page could not
 * form, with no detail from the error.
 */
export async function guarded(f: Frame, act: () => Promise<void>): Promise<void> {
  try {
    await act();
  } catch {
    f.problem({ kind: "failed", reason: "request" });
  }
}

/** Runs `act` with `button` disabled, so one click makes one request. */
export async function whileBusy(button: HTMLButtonElement, act: () => Promise<void>): Promise<void> {
  button.disabled = true;
  try {
    await act();
  } finally {
    button.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Field errors (R-NF-03)
// ---------------------------------------------------------------------------

/** One error to show: the control it belongs to and its message. */
export interface ShownError {
  readonly control: HTMLElement;
  readonly message: Label;
  /** Where the message goes, after this element. The control by default. */
  readonly after?: HTMLElement;
}

/**
 * The errors of one form: an error summary that links to each field, and
 * a message after each field that `aria-describedby` points at
 * (`core/a11y.ts`).
 */
export class FormErrors {
  private shown: { readonly control: HTMLElement; readonly el: HTMLElement }[] = [];
  private summary: HTMLElement | null = null;

  constructor(
    private readonly form: HTMLElement,
    private readonly summaryId: string,
    private readonly t: I18n,
  ) {}

  /** Removes every shown error. */
  clear(): void {
    for (const { control, el } of this.shown) {
      clearError(control, el);
      el.remove();
    }
    this.shown = [];
    this.summary?.remove();
    this.summary = null;
  }

  /** Shows `errors` in form order, after removing the earlier ones, and moves focus to the summary. */
  show(errors: readonly ShownError[]): void {
    this.clear();
    if (errors.length === 0) {
      return;
    }
    const items: HTMLElement[] = [];
    const used = new Set<string>();
    for (const e of errors) {
      const id = e.control.getAttribute("id") ?? "";
      let errId = `${id}-error`;
      for (let n = 2; used.has(errId); n += 1) {
        errId = `${id}-error-${String(n)}`;
      }
      used.add(errId);
      const el = h("p", { id: errId, class: "fstp-field-error" }, [e.message]);
      (e.after ?? e.control).after(el);
      linkError(e.control, el);
      this.shown.push({ control: e.control, el });
      items.push(h("li", {}, [id === "" ? e.message : h("a", { href: `#${id}` }, [e.message])]));
    }
    const summary = h("div", { id: this.summaryId, class: "fstp-error-summary", role: "alert", tabindex: "-1" }, [
      h("h2", {}, [this.t.label("kit.errors_title")]),
      h("ul", {}, items),
    ]);
    this.form.prepend(summary);
    this.summary = summary;
    summary.focus();
  }
}

// ---------------------------------------------------------------------------
// The conflict declaration (R-CF-02, R-CF-04)
// ---------------------------------------------------------------------------

/** The pre-declaration view: the title and the neutral summary only (Q9). */
export function declarationViewSection(t: I18n, view: DeclarationView): HTMLElement {
  return h("section", { "aria-labelledby": "declaration-heading" }, [
    h("h2", { id: "declaration-heading" }, [t.label("kit.decl.heading")]),
    h("p", {}, [t.label("kit.decl.intro")]),
    h("dl", {}, [
      h("dt", {}, [t.label("kit.decl.title")]),
      h("dd", { id: "declaration-title" }, [view.title]),
      h("dt", {}, [t.label("kit.decl.summary")]),
      h("dd", { id: "declaration-summary" }, [view.neutral_summary]),
    ]),
  ]);
}

/** When a declaration is made: before reading, or on an active assignment. */
export type DeclarationMoment = "first" | "later";

/**
 * The declaration form, `#declare-form`. No answer is preset. `send`
 * records the declaration, and `done` runs after it was accepted.
 *
 * With `moment` "first", the form asks whether the caller has a conflict
 * before reading (R-CF-02). With "later", it is on an active assignment:
 * the domain takes only a conflicted declaration there, which releases
 * the assignment (`declaration_open` in `fstp-domain` `assignment.rs`,
 * I-03). So the form offers the conflict alone, as a checkbox that is
 * never preset, and the notifiable box.
 */
export function declarationForm(
  t: I18n,
  f: Frame,
  send: (d: Declaration) => Promise<Answer<Accepted>>,
  done: (d: Declaration) => Promise<void>,
  moment: DeclarationMoment = "first",
): HTMLFormElement {
  const later = moment === "later";
  const no = later ? null : radio("declare-conflicted-no", "conflicted", "no", t.label("kit.decl.no"));
  const yes = later
    ? checkbox("declare-conflicted-yes", "conflicted", t.label("kit.decl.later_yes"))
    : radio("declare-conflicted-yes", "conflicted", "yes", t.label("kit.decl.yes"));
  const notifiable = inputEl({ id: "declare-notifiable", name: "notifiable", type: "checkbox" });
  const legend = h("legend", {}, [later ? t.label("kit.decl.later_question") : t.label("kit.decl.question")]);
  const submit = buttonEl("declare-submit", "submit", later ? t.label("kit.decl.later_submit") : t.label("kit.decl.submit"));
  const choices: Child[] = no === null ? [legend, yes.root] : [legend, no.root, yes.root];
  const form = formEl("declare-form", [
    h("fieldset", {}, choices),
    h("div", { class: "fstp-choice" }, [notifiable, h("label", { for: "declare-notifiable" }, [t.label("kit.decl.notifiable")])]),
    submit,
  ]);
  const errors = new FormErrors(form, "declare-errors", t);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const read = readDeclaration({
          conflicted: yes.control.checked ? "yes" : no?.control.checked === true ? "no" : null,
          notifiable: notifiable.checked,
        });
        if (!read.ok) {
          errors.show(
            read.errors.map((e) =>
              e.field === "conflicted"
                ? {
                    control: (no ?? yes).control,
                    message: later ? t.label("kit.decl.err_later") : t.label("kit.decl.err_required"),
                    after: legend,
                  }
                : { control: notifiable, message: t.label("kit.decl.err_notifiable") },
            ),
          );
          return;
        }
        errors.clear();
        f.clearAlert();
        const answer = await send(read.value);
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        f.status(read.value.conflicted ? t.label("kit.decl.done_conflict") : t.label("kit.decl.done_none"));
        await done(read.value);
      }),
    );
  });
  return form;
}

/**
 * The section that lets a caller declare a conflict found while reading
 * an active assignment (R-CF-02, I-03). `send` records the declaration,
 * and `done` runs after it was accepted.
 */
export function laterDeclarationSection(
  t: I18n,
  f: Frame,
  send: (d: Declaration) => Promise<Answer<Accepted>>,
  done: (d: Declaration) => Promise<void>,
): HTMLElement {
  return h("section", { id: "declare-later", "aria-labelledby": "declare-later-heading" }, [
    h("h2", { id: "declare-later-heading" }, [t.label("kit.decl.later_heading")]),
    h("p", {}, [t.label("kit.decl.later_intro")]),
    declarationForm(t, f, send, done, "later"),
  ]);
}

/** The declaration as `DeclareConflict` takes it on the wire. */
export function declarationBody(d: Declaration): Readonly<Record<string, boolean>> {
  return { conflicted: d.conflicted, notifiable: d.notifiable };
}
