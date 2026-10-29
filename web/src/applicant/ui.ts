// The frame and the shared parts of the applicant and call pages (R-NF-03,
// R-NF-04; M4 design section 3.9, ADR-014).
//
// Every page has the document language and title, one `main` landmark
// with its `h1`, and one alert region for refusals. Every element is
// built with `h`, and every text goes in as a text node. Every control
// has a bound label. A field error is linked to its field.

import { clearError, linkError } from "../core/a11y.js";
import { type Child, h } from "../core/dom.js";
import { type ApprovedText, type I18n, type Label, createI18n } from "../core/i18n.js";
import { CALLS_APPROVED, CALLS_LABELS } from "../calls/messages.en.js";
import type { Failure } from "./client.js";
import { APPLICANT_APPROVED, APPLICANT_LABELS, FOOTER_APPROVED } from "./messages.en.js";
import type { ProposalState } from "./rules.js";
import type { Day, Instant } from "./wire.js";

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

let catalogue: I18n | null = null;

/**
 * The English catalogue of the applicant and call pages. Interim, pending
 * the lead: the shell passes no locale or terminology overrides yet, so
 * the pages use English without overrides.
 */
function i18n(): I18n {
  catalogue ??= createI18n({
    catalogues: [
      {
        locale: "en",
        labels: { ...CALLS_LABELS, ...APPLICANT_LABELS },
        approved: { ...CALLS_APPROVED, ...APPLICANT_APPROVED, ...FOOTER_APPROVED },
      },
    ],
    locale: "en",
  });
  return catalogue;
}

/** The interface string `id`. */
export function t(id: string, args?: Readonly<Record<string, string>>): Label {
  return i18n().label(id, args);
}

/** The approved wording `id`. */
export function approved(id: string): ApprovedText {
  return i18n().approved(id);
}

/** The locale of the catalogue. */
export function locale(): string {
  return i18n().locale;
}

/** The label of a proposal state. */
export function stateLabel(s: ProposalState): Label {
  return t(`state.${s}`);
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** The page paths of the applicant and call pages. */
export const APP = Object.freeze({
  calls: "/app/calls",
  call: (c: string): string => `/app/calls/${c}`,
  guide: (c: string): string => `/app/calls/${c}/guide`,
  proposals: "/app/proposals",
  proposal: (p: string): string => `/app/proposals/${p}`,
  workspace: (p: string): string => `/app/proposals/${p}/workspace`,
  plan: (p: string): string => `/app/proposals/${p}/plan`,
  eligibility: (p: string): string => `/app/proposals/${p}/eligibility`,
  submit: (p: string): string => `/app/proposals/${p}/submit`,
  stage2: (p: string): string => `/app/proposals/${p}/stage2`,
  negotiation: (p: string): string => `/app/proposals/${p}/negotiation`,
  guardian: (p: string): string => `/app/proposals/${p}/guardian`,
  team: (p: string): string => `/app/proposals/${p}/team`,
  notices: "/app/notices",
});

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/** The parts of a page that its code fills. */
export interface Frame {
  /** The element the page renders into: the shell's `#app`, or the body. */
  readonly root: HTMLElement;
  /** The one `main` landmark. */
  readonly main: HTMLElement;
  /** The `h1` of the page. */
  readonly heading: HTMLElement;
  /** The page's `role="alert"` region, hidden while it is empty. */
  readonly alert: HTMLElement;
}

function rootElement(): HTMLElement {
  const app = document.getElementById("app");
  return app instanceof HTMLElement ? app : document.body;
}

/**
 * The elements every page's footer shows (M4 design section 3.9
 * "Footer"; P-68, R-WL-04, I-69 seam). No member is optional, so no page
 * can leave one out, and each is approved wording, which tenant
 * terminology never overrides (I-72 seam).
 *
 * The AI disclosure, the Data Act information and the funder visibility
 * elements belong to the pages where they apply. The call page shows
 * the AI disclosure. None of the applicant pages is a tenant admin page
 * or names a funder profile yet.
 */
export interface MandatoryElements {
  /** The privacy notice. */
  readonly privacy: ApprovedText;
  /** The accessibility statement. */
  readonly accessibility: ApprovedText;
  /** The platform attribution (P-68, R-WL-04). */
  readonly attribution: ApprovedText;
}

/** The mandatory elements from the catalogue. */
function mandatoryElements(): MandatoryElements {
  return Object.freeze({
    privacy: approved("footer.privacy"),
    accessibility: approved("footer.accessibility"),
    attribution: approved("footer.attribution"),
  });
}

/**
 * The page footer, a `contentinfo` landmark with every mandatory element.
 *
 * Interim, pending the lead: no shared footer exists in `web/src/core`
 * yet. When one lands, `frame` takes it and this function goes.
 */
export function footer(m: MandatoryElements): HTMLElement {
  return h("footer", { class: "fstp-footer" }, [
    h("p", { id: "footer-privacy" }, [m.privacy]),
    h("p", { id: "footer-accessibility" }, [m.accessibility]),
    h("p", { id: "footer-attribution" }, [m.attribution]),
  ]);
}

/**
 * Starts a page: the document language and title, the navigation, the
 * `main` landmark with its `h1`, the alert region and the footer with
 * its mandatory elements. The page's own content goes into `main` after
 * the alert region. A second call starts again.
 */
export function frame(title: Label): Frame {
  document.documentElement.lang = locale();
  document.title = t("app.document_title", { page: title });
  const root = rootElement();
  root.replaceChildren();
  const nav = h("nav", { "aria-label": t("nav.label") }, [
    h("ul", { class: "fstp-nav" }, [
      h("li", {}, [h("a", { href: APP.calls }, [t("nav.calls")])]),
      h("li", {}, [h("a", { href: APP.proposals }, [t("nav.proposals")])]),
      h("li", {}, [h("a", { href: APP.notices }, [t("nav.notices")])]),
    ]),
  ]);
  const heading = h("h1", {}, [title]);
  const alert = h("p", { id: "page-alert", role: "alert", class: "fstp-alert", hidden: true });
  const main = h("main", { id: "main" }, [heading, alert]);
  root.append(h("header", { class: "fstp-header" }, [nav]), main, footer(mandatoryElements()));
  return { root, main, heading, alert };
}

/**
 * Moves focus to the page's `h1`, for a page that replaced the one
 * holding the focus (WCAG 2.2 SC 2.4.3). The heading takes focus from
 * script only, never from the Tab key.
 */
export function focusHeading(f: Frame): void {
  f.heading.setAttribute("tabindex", "-1");
  f.heading.focus();
}

// ---------------------------------------------------------------------------
// Error summaries
// ---------------------------------------------------------------------------

/** One entry of an error summary: the field to focus and its message. */
export interface SummaryItem {
  readonly target: HTMLElement;
  readonly message: string;
}

/** An error summary with a link to each field in error (WCAG 2.2 SC 3.3.1). */
export interface ErrorSummary {
  readonly root: HTMLElement;
  /** Lists `items` and moves focus to the summary. An empty list hides it. */
  show(items: readonly SummaryItem[]): void;
  /** Hides the summary. */
  clear(): void;
}

/** A hidden error summary whose ids start with `id`. */
export function errorSummary(id: string): ErrorSummary {
  const list = h("ul", {});
  const root = h(
    "div",
    {
      id,
      role: "alert",
      tabindex: "-1",
      class: "fstp-summary",
      "aria-labelledby": `${id}-heading`,
      hidden: true,
    },
    [h("h2", { id: `${id}-heading` }, [t("form.errors.heading")]), list],
  );
  const clear = (): void => {
    root.hidden = true;
    list.replaceChildren();
  };
  return Object.freeze({
    root,
    show(items: readonly SummaryItem[]): void {
      if (items.length === 0) {
        clear();
        return;
      }
      list.replaceChildren(
        ...items.map((i) => {
          const a = h("a", { href: `#${i.target.id}` }, [i.message]);
          a.addEventListener("click", (ev) => {
            ev.preventDefault();
            i.target.focus();
          });
          return h("li", {}, [a]);
        }),
      );
      root.hidden = false;
      root.focus();
    },
    clear,
  });
}

/** Shows `message` in the page's alert region. */
export function showAlert(f: Frame, message: string): void {
  f.alert.textContent = message;
  f.alert.hidden = false;
}

/** Empties and hides the page's alert region. */
export function clearAlert(f: Frame): void {
  f.alert.textContent = "";
  f.alert.hidden = true;
}

/** The message for a call that gave no value. */
export function failureText(x: Failure): Label {
  switch (x.kind) {
    case "unavailable":
      return t("error.unavailable");
    case "refused":
      return x.rule === null || x.rule === ""
        ? t("error.refused", { code: x.code })
        : t("error.refused_rule", { code: x.code, rule: x.rule });
    case "step_up":
      return t("error.step_up");
    case "pending":
      return t("error.pending");
    case "failed":
      return x.reason === "network"
        ? t("error.network")
        : x.reason === "request"
          ? t("error.request")
          : t("error.invalid");
  }
}

/** Shows the message of a failed call in the page's alert region. */
export function showFailure(f: Frame, x: Failure): void {
  showAlert(f, failureText(x));
}

/**
 * Runs a page's loading code. A thrown error never leaves the page blank:
 * the alert region says the answer could not be read.
 */
export function run(f: Frame, body: () => Promise<void>): void {
  body().catch(() => {
    showAlert(f, t("error.invalid"));
  });
}

// ---------------------------------------------------------------------------
// Status regions
// ---------------------------------------------------------------------------

/** A `role="status"` region whose `data-status` names the outcome. */
export function statusRegion(id: string): HTMLElement {
  return h("p", { id, role: "status", class: "fstp-status", "data-status": "idle" });
}

/** Sets the outcome and text of a status region. */
export function setStatus(el: HTMLElement, status: string, message: string): void {
  el.setAttribute("data-status", status);
  el.textContent = message;
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

/** A built control with its root, which holds the label, the hint and the error. */
export interface Control<E extends HTMLElement> {
  readonly root: HTMLElement;
  readonly control: E;
  readonly error: HTMLElement;
}

function errorFor(id: string): HTMLElement {
  return h("p", { id: `${id}-error`, class: "fstp-error", hidden: true });
}

function hintFor(id: string, hint: string | undefined): HTMLElement | null {
  return hint === undefined ? null : h("p", { id: `${id}-hint`, class: "fstp-hint" }, [hint]);
}

/** A labelled `textarea`, with an optional hint and a hidden error. */
export function textArea(
  id: string,
  label: Label,
  opts: { readonly hint?: string; readonly maxlength?: number; readonly rows?: number } = {},
): Control<HTMLTextAreaElement> {
  const attrs: Record<string, string | boolean> = { id, name: id, rows: String(opts.rows ?? 6) };
  if (opts.maxlength !== undefined) {
    attrs["maxlength"] = String(opts.maxlength);
  }
  const hint = hintFor(id, opts.hint);
  if (hint !== null) {
    attrs["aria-describedby"] = `${id}-hint`;
  }
  const control = h("textarea", attrs);
  if (!(control instanceof HTMLTextAreaElement)) {
    throw new TypeError("the document did not create a textarea");
  }
  const error = errorFor(id);
  const kids: Child[] = [h("label", { for: id }, [label])];
  if (hint !== null) {
    kids.push(hint);
  }
  kids.push(error, control);
  return { root: h("div", { class: "fstp-field" }, kids), control, error };
}

/** A labelled single-line text input of `type`, with an optional hint and a hidden error. */
export function textInput(
  id: string,
  label: Label,
  opts: {
    readonly type?: "text" | "email";
    readonly hint?: string;
    readonly maxlength?: number;
    readonly autocomplete?: string;
  } = {},
): Control<HTMLInputElement> {
  const attrs: Record<string, string | boolean> = { id, name: id, type: opts.type ?? "text" };
  if (opts.maxlength !== undefined) {
    attrs["maxlength"] = String(opts.maxlength);
  }
  if (opts.autocomplete !== undefined) {
    attrs["autocomplete"] = opts.autocomplete;
  }
  const hint = hintFor(id, opts.hint);
  if (hint !== null) {
    attrs["aria-describedby"] = `${id}-hint`;
  }
  const control = h("input", attrs);
  if (!(control instanceof HTMLInputElement)) {
    throw new TypeError("the document did not create an input");
  }
  const error = errorFor(id);
  const kids: Child[] = [h("label", { for: id }, [label])];
  if (hint !== null) {
    kids.push(hint);
  }
  kids.push(error, control);
  return { root: h("div", { class: "fstp-field" }, kids), control, error };
}

/** Shows `message` as the error of `control`, linked to it, or clears it with null. */
export function fieldError(control: HTMLElement, error: HTMLElement, message: string | null): void {
  if (message === null) {
    error.textContent = "";
    error.hidden = true;
    clearError(control, error);
    return;
  }
  error.textContent = message;
  error.hidden = false;
  linkError(control, error);
}

/** A button of `type` with its text. */
export function button(id: string, label: Label, type: "button" | "submit" = "button"): HTMLButtonElement {
  const b = h("button", { id, type }, [label]);
  if (!(b instanceof HTMLButtonElement)) {
    throw new TypeError("the document did not create a button");
  }
  return b;
}

// ---------------------------------------------------------------------------
// Times
// ---------------------------------------------------------------------------

/**
 * A `time` element for an instant, shown in the IANA zone `zone`. Its
 * `datetime` holds the RFC 3339 instant in UTC. A zone the browser does
 * not know is shown in UTC.
 */
export function instantTime(at: Instant, zone: string): HTMLElement {
  let shown: string;
  try {
    shown = new Intl.DateTimeFormat(locale(), { dateStyle: "long", timeStyle: "short", timeZone: zone }).format(
      new Date(at.ms),
    );
  } catch {
    shown = at.rfc3339;
  }
  return h("time", { datetime: at.rfc3339 }, [shown]);
}

/** A `time` element for a calendar day, with no time of day (TH-08). */
export function dayTime(d: Day): HTMLElement {
  let shown: string;
  try {
    shown = new Intl.DateTimeFormat(locale(), { dateStyle: "long", timeZone: "UTC" }).format(
      new Date(Date.UTC(d.year, d.month - 1, d.day)),
    );
  } catch {
    shown = d.text;
  }
  return h("time", { datetime: d.text }, [shown]);
}
