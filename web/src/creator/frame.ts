// The page frame of the creator, onboarding and people pages (R-NF-03,
// R-NF-04, R-WL-04, P-68, I-69 seam; M4 design section 3.9 "Footer").
//
// Every page gets the document language and title, one `main` landmark
// with its `h1`, one `role="alert"` region placed right after the heading,
// and one `footer` with the mandatory elements. The alert region is the
// first alert in document order, so a refusal is always the alert a
// reader meets first.
//
// Interim, pending Daniel and the shell of `/app` (design section 3.9):
// no lane owns an application-wide frame yet. It lives here, beside the
// creator, until the lead gives it a home in `web/src/core`.

import { h } from "../core/dom.js";
import { navigate } from "../core/router.js";
import type { ApprovedText, Label } from "../core/i18n.js";
import { appShell } from "../home/nav.js";
import { t } from "./i18n.js";

/**
 * The mandatory elements of every page footer. No member is optional,
 * so a page cannot leave one out (design section 3.9, `MandatoryElements`).
 */
export interface MandatoryElements {
  readonly privacyNotice: ApprovedText;
  readonly accessibilityStatement: ApprovedText;
  readonly platformAttribution: ApprovedText;
  /**
   * The Data Act information for tenants. Interim strict reading, pending
   * Daniel: these pages cannot tell a tenant admin from another viewer
   * before their first read, so every page of the three features shows it.
   * Showing it to more viewers never hides a mandatory element.
   */
  readonly dataActInformation: ApprovedText;
}

/**
 * The mandatory elements of the default package in M4.
 *
 * TODO(legal): the privacy notice, accessibility statement and Data Act
 * information carry placeholder wording until Daniel supplies approved
 * text. The funder visibility elements that the Horizon Europe profile
 * requires are not quoted here from memory, so no page shows them yet.
 */
export function defaultMandatoryElements(): MandatoryElements {
  return {
    privacyNotice: t.approved("footer.privacy_notice"),
    accessibilityStatement: t.approved("footer.accessibility_statement"),
    platformAttribution: t.approved("footer.platform_attribution"),
    dataActInformation: t.approved("footer.data_act_information"),
  };
}

/** The built footer, with one element per mandatory element. */
export function footer(m: MandatoryElements): HTMLElement {
  const item = (key: string, text: ApprovedText): HTMLElement =>
    h("li", {}, [h("span", { "data-mandatory": key }, [text])]);
  return h("footer", { class: "fstp-footer" }, [
    h("ul", {}, [
      item("privacy_notice", m.privacyNotice),
      item("accessibility_statement", m.accessibilityStatement),
      item("data_act_information", m.dataActInformation),
      item("platform_attribution", m.platformAttribution),
    ]),
  ]);
}

/** The element pages render into: the shell's `#app`, else the body. */
function rootElement(): HTMLElement {
  const app = document.getElementById("app");
  return app instanceof HTMLElement ? app : document.body;
}

/** The regions of a built page. */
export interface Frame {
  /** The `main` landmark. Content goes after its heading and alert. */
  readonly main: HTMLElement;
  /** The page's one `role="alert"` region, empty until a refusal. */
  readonly alert: HTMLElement;
}

/**
 * Builds the page: language, title, `main` with the heading and the
 * alert region, and the footer. Everything already in the shell root is
 * replaced, so a second call starts the page again.
 */
export function frame(opts: { readonly title: Label; readonly alertId: string; readonly nav?: HTMLElement }): Frame {
  document.documentElement.lang = t.locale;
  document.title = opts.title;
  const alert = h("p", { id: opts.alertId, role: "alert", class: "fstp-alert" });
  // The page's own navigation, such as the creator steps, opens `main`.
  const own: HTMLElement[] = opts.nav === undefined ? [] : [opts.nav];
  const main = h("main", { id: "main" }, [...own, h("h1", {}, [opts.title]), alert]);
  // The page shell: skip link, top bar, and the sidebar with the site
  // navigation (`docs/design/01-navigation-home.md`, 2026-11-01).
  const parts: HTMLElement[] = [...appShell(main), footer(defaultMandatoryElements())];
  // An open step-up dialog closes first, so its ceremony settles as
  // cancelled instead of waiting on a dialog the new page removed.
  const open = document.getElementById("stepup");
  if (open instanceof HTMLDialogElement && open.open) {
    open.close();
  }
  rootElement().replaceChildren(...parts);
  return { main, alert };
}

/**
 * Marks `main` as loaded: `main[data-ready="true"]` once the page has
 * read its data and drawn its controls. A page whose first read failed
 * stays unmarked and shows why in its alert region.
 */
export function ready(main: HTMLElement): void {
  main.setAttribute("data-ready", "true");
}

/** Empties the alert region and removes its rule. */
export function hush(alert: HTMLElement): void {
  alert.textContent = "";
  alert.removeAttribute("data-rule");
}

/** Shows `message` in the alert region, naming `rule` when the refusal named one. */
export function warn(alert: HTMLElement, message: string, rule: string | null = null): void {
  alert.textContent = message;
  if (rule === null) {
    alert.removeAttribute("data-rule");
  } else {
    alert.setAttribute("data-rule", rule);
  }
}

/** A `role="status"` region, empty until a message is set. */
export function statusRegion(id: string): HTMLElement {
  return h("p", { id, role: "status", class: "fstp-status" });
}

/** The buttons whose action is pending. */
const PENDING = new WeakSet<HTMLElement>();

/**
 * A click handler that ignores presses while `run` is pending. The
 * button is marked `aria-busy` and `aria-disabled`, never `disabled`, so
 * it keeps focus and a keyboard user does not start again from the top
 * of the page (WCAG 2.2 SC 2.4.3).
 */
export function busy(button: HTMLElement, run: () => Promise<void>): () => void {
  return () => {
    if (PENDING.has(button) || button.hasAttribute("disabled")) {
      return;
    }
    PENDING.add(button);
    button.setAttribute("aria-disabled", "true");
    button.setAttribute("aria-busy", "true");
    run().finally(() => {
      PENDING.delete(button);
      button.removeAttribute("aria-disabled");
      button.removeAttribute("aria-busy");
    });
  };
}

/** Opens `path` of this origin. */
export function go(path: string): void {
  navigate(path);
}
