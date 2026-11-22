// The legal pages behind the footer (ADR-037; Daniel, 2026-11-22,
// `legal/README.md` Q6). Each footer element for a legal text is a link to
// its page under `/legal/`, which the server renders from the `legal/`
// draft with the tenant's legal details. The pages work signed out and
// carry the banner "Draft, not yet approved" until Daniel approves the
// text. The `data-mandatory` key stays on the link (I-69).
//
// The paths match `fstp_public::legal::LegalText::path`. The sign-in
// pages keep their own copy in `web/src/auth/layout.ts`, since they import
// nothing outside `web/src/auth`.

import { h } from "../core/dom.js";

/** One legal text with a page behind the footer. */
export interface LegalLink {
  /** The `data-mandatory` key of its footer element. */
  readonly key: string;
  /** The page path. */
  readonly path: string;
}

/** The legal pages, in footer order. */
export const LEGAL_LINKS: readonly LegalLink[] = Object.freeze([
  { key: "privacy_notice", path: "/legal/privacy" },
  { key: "accessibility_statement", path: "/legal/accessibility" },
  { key: "imprint", path: "/legal/imprint" },
  { key: "terms_of_use", path: "/legal/terms" },
  { key: "data_act_information", path: "/legal/data-act" },
]);

/** The page path of the legal text whose footer key is `key`, or null. */
export function legalPath(key: string): string | null {
  return LEGAL_LINKS.find((l) => l.key === key)?.path ?? null;
}

/** One footer item: a link to the legal page of `key`, keyed for I-69, or a plain span for any other element. */
export function footerItem(key: string, text: string): HTMLElement {
  const path = legalPath(key);
  return h("li", {}, [
    path === null ? h("span", { "data-mandatory": key }, [text]) : h("a", { href: path, "data-mandatory": key }, [text]),
  ]);
}
