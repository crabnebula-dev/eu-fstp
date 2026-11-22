// The funding card in the footer of every `/app/` page (ADR-034; I-69,
// R-NF-04).
//
// A page inside one programme (`/app/programmes/{programme}/...`) shows
// that programme's card. Any other page shows one compact card per
// active programme of the tenant. The cards come from `GET /brand/funding`,
// the same platform data the public pages show.
//
// The card is platform markup with the programme's values as text only
// (I-68). Its logo is the platform's Funded by the European Union logo on
// a white card in both themes, never recoloured. No brand token reaches
// it, so branding cannot remove or hide it (I-69).
// TODO(legal): the acknowledgement wording (L-08) stays the placeholder.

import { h, mailtoHref } from "../core/dom.js";
import { t } from "../creator/i18n.js";

/** Where the cards are read. */
export const FUNDING_PATH = "/brand/funding";
/** The platform's logo for pages. */
export const LOGO_PATH = "/brand/funded-by-eu.svg";
/** The `data-mandatory` key of the card's part of a footer. */
export const FUNDING_KEY = "funding_card";

/** One programme's card, as `/brand/funding` answers it. */
export interface FundingCard {
  readonly programme: string;
  readonly name: string;
  readonly grantNumber: string | null;
  readonly coordinatorName: string | null;
  readonly coordinatorContact: string | null;
}

/** The tenant's defaults for an empty coordinator field. */
export interface FundingDefaults {
  readonly name: string;
  readonly contact: string;
}

/** A decoded `/brand/funding` answer. */
export interface FundingAnswer {
  readonly cards: readonly FundingCard[];
  readonly defaults: FundingDefaults | null;
}

function text(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" ? v : null;
}

/** The `/brand/funding` answer `body`, or null when it is not one. */
export function decodeFunding(body: unknown): FundingAnswer | null {
  if (typeof body !== "object" || body === null) {
    return null;
  }
  const o = body as Record<string, unknown>;
  const raw = o["cards"];
  if (!Array.isArray(raw)) {
    return null;
  }
  const cards: FundingCard[] = [];
  for (const c of raw) {
    if (typeof c !== "object" || c === null) {
      return null;
    }
    const r = c as Record<string, unknown>;
    const programme = text(r["programme"]);
    const name = text(r["name"]);
    if (programme === null || name === null) {
      return null;
    }
    cards.push({
      programme,
      name,
      grantNumber: text(r["grant_number"]),
      coordinatorName: text(r["coordinator_name"]),
      coordinatorContact: text(r["coordinator_contact"]),
    });
  }
  let defaults: FundingDefaults | null = null;
  const d = o["defaults"];
  if (typeof d === "object" && d !== null) {
    const dr = d as Record<string, unknown>;
    const name = text(dr["name"]);
    const contact = text(dr["contact"]);
    if (name !== null && contact !== null) {
      defaults = { name, contact };
    }
  }
  return { cards, defaults };
}

/**
 * The cards a page shows: its programme's card when the page is inside
 * `programme` and the tenant has it, else every card.
 */
export function cardsFor(programme: string | null, cards: readonly FundingCard[]): readonly FundingCard[] {
  if (programme !== null) {
    const own = cards.filter((c) => c.programme === programme);
    if (own.length > 0) {
      return own;
    }
  }
  return cards;
}

/** One card: the logo with its alternative text, the programme name, and the label and value pairs. */
export function fundingCard(c: FundingCard): HTMLElement {
  const pair = (label: string, value: string | null, link = false): HTMLElement[] => {
    // ADR-034 (lead decision): a contact that is one e-mail address is a link.
    const href = link && value !== null ? mailtoHref(`mailto:${value}`) : null;
    const shown = value ?? t.label("footer.funding.not_set");
    return [h("dt", {}, [label]), h("dd", {}, [href === null ? shown : h("a", { href }, [shown])])];
  };
  return h("section", { class: "funding-card", "aria-label": t.label("footer.funding.label") }, [
    h("img", { class: "eu-emblem", src: LOGO_PATH, alt: t.label("footer.funding.alt") }),
    h("div", { class: "funding-card-text" }, [
      h("p", { class: "funding-card-name" }, [c.name]),
      h("dl", {}, [
        ...pair(t.label("footer.funding.grant"), c.grantNumber),
        ...pair(t.label("footer.funding.coordinator"), c.coordinatorName),
        ...pair(t.label("footer.funding.contact"), c.coordinatorContact, true),
      ]),
      h("p", {}, [t.approved("footer.eu_funding")]),
    ]),
  ]);
}

/** The footer part for `cards`, keyed for I-69, or null for none. */
export function fundingPart(cards: readonly FundingCard[]): HTMLElement | null {
  if (cards.length === 0) {
    return null;
  }
  const programmes = cards.map((c) => c.programme).join(" ");
  return h("div", { class: "funding-cards-wrap", "data-mandatory": FUNDING_KEY, "data-programmes": programmes }, [
    h(
      "ul",
      { class: "funding-cards" },
      cards.map((c) => h("li", {}, [fundingCard(c)])),
    ),
  ]);
}

/** Puts the card part for `cards` first in `footer`, touching the DOM only when the programmes differ. */
export function syncFunding(footer: Element, cards: readonly FundingCard[]): void {
  const want = cards.map((c) => c.programme).join(" ");
  const have = footer.querySelector(`[data-mandatory="${FUNDING_KEY}"]`);
  if (have !== null && have.getAttribute("data-programmes") === want) {
    return;
  }
  have?.remove();
  const part = fundingPart(cards);
  if (part !== null) {
    footer.prepend(part);
  }
}
