// The "Progress" and "Activity" links of a proposal, which the home page,
// the proposal page and the guardian page show (R-JV-01; lane j3). The
// guardian gets both, since the guardian sees the route map as part of the
// full journey (Daniel, 2026-11-15, night).
//
// This module imports no generated operation table and no page, so a
// page that shows the links loads nothing else of the voyager surface.

import { h } from "../core/dom.js";
import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { JOURNEY_LABELS } from "./messages.en.js";

/** A catalogue message with its arguments. */
interface LinkMsg {
  readonly key: string;
  readonly args: Readonly<Record<string, string>>;
}

/** The paths of the voyager pages of proposal `p`. */
export const JOURNEY_PATHS = Object.freeze({
  progress: (p: string): string => `/app/proposals/${p}/progress`,
  activity: (p: string): string => `/app/proposals/${p}/activity`,
});

/** One link the home page and the proposal page show. */
export interface JourneyLink {
  readonly href: string;
  readonly label: LinkMsg;
}

/** The "Progress" and "Activity" links of proposal `p`. */
export function journeyLinks(p: string): readonly JourneyLink[] {
  return Object.freeze([
    Object.freeze({ href: JOURNEY_PATHS.progress(p), label: Object.freeze({ key: "journey.link.progress", args: {} }) }),
    Object.freeze({ href: JOURNEY_PATHS.activity(p), label: Object.freeze({ key: "journey.link.activity", args: {} }) }),
  ]);
}

let catalogue: I18n | null = null;

function text(key: string): Label {
  catalogue ??= createI18n({ catalogues: [{ locale: "en", labels: JOURNEY_LABELS, approved: {} }], locale: "en" });
  return catalogue.label(key);
}

/** The "Progress" and "Activity" links of proposal `p` as a small navigation. */
export function journeyNav(p: string): HTMLElement {
  return h("nav", { class: "journey-links", "aria-label": text("journey.link.label") }, [
    h(
      "ul",
      { class: "fstp-list" },
      journeyLinks(p).map((l) => h("li", {}, [h("a", { href: l.href }, [text(l.label.key)])])),
    ),
  ]);
}
