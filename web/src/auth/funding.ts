// The funding card in the footer of the sign-in pages (ADR-034; I-69,
// R-NF-04). These pages have no programme in context, so the footer shows
// one compact card per active programme of the tenant, read from
// `GET /brand/funding`, which needs no session.
//
// The card is platform markup with the programme's values as text only
// (I-68). Its logo is the platform's Funded by the European Union logo,
// on a white card in both themes, never recoloured.
// The card ends with the approved funding acknowledgement (L-08, ADR-036),
// as text, or with nothing while a value it names is missing.

import { get, ok } from './api.js';
import { h, mailtoHref } from './dom.js';
import { t } from './layout.js';

/** Where the cards are read. */
export const FUNDING_PATH = '/brand/funding';
/** The platform's logo for pages. */
export const LOGO_PATH = '/brand/funded-by-eu.svg';

/** One programme's card, as `/brand/funding` answers it. */
export interface FundingCard {
  readonly programme: string;
  readonly name: string;
  readonly grantNumber: string | null;
  readonly coordinatorName: string | null;
  readonly coordinatorContact: string | null;
  /** The approved funding acknowledgement, or null while a value it names is missing (L-08). */
  readonly acknowledgement: string | null;
}

function text(v: unknown): string | null {
  return typeof v === 'string' && v.trim() !== '' ? v : null;
}

/** The cards of a `/brand/funding` answer, or null when it is not one. */
export function decodeCards(body: unknown): FundingCard[] | null {
  if (typeof body !== 'object' || body === null) return null;
  const cards = (body as { cards?: unknown }).cards;
  if (!Array.isArray(cards)) return null;
  const out: FundingCard[] = [];
  for (const c of cards) {
    if (typeof c !== 'object' || c === null) return null;
    const r = c as Record<string, unknown>;
    const programme = text(r['programme']);
    const name = text(r['name']);
    if (programme === null || name === null) return null;
    out.push({
      programme,
      name,
      grantNumber: text(r['grant_number']),
      coordinatorName: text(r['coordinator_name']),
      coordinatorContact: text(r['coordinator_contact']),
      acknowledgement: text(r['acknowledgement']),
    });
  }
  return out;
}

/** One card: the logo with its alternative text and the label and value lines. The programme name shows only inside the acknowledgement (ADR-034 Q11). */
export function fundingCard(c: FundingCard): HTMLElement {
  const line = (label: string, value: string | null, link = false): HTMLElement => {
    // ADR-034 (lead decision): a contact that is one e-mail address is a link.
    const href = link && value !== null ? mailtoHref('mailto:' + value) : null;
    const shown = value ?? t('funding.not_set');
    return h('p', { class: 'funding-card-line' }, [
      h('span', { class: 'funding-card-label' }, [label + ': ']),
      href === null ? h('span', {}, [shown]) : h('a', { href }, [shown]),
    ]);
  };
  return h('section', { class: 'funding-card', 'aria-label': t('funding.label') }, [
    h('img', { class: 'eu-emblem', src: LOGO_PATH, alt: t('funding.alt') }),
    h('div', { class: 'funding-card-text' }, [
      // ADR-034 Q11 (Daniel, 2026-11-23): no programme name beside the logo.
      line(t('funding.grant'), c.grantNumber),
      line(t('funding.coordinator'), c.coordinatorName),
      line(t('funding.contact'), c.coordinatorContact, true),
      // L-08 (ADR-036): the approved sentence as text, or nothing.
      ...(c.acknowledgement === null ? [] : [h('p', { class: 'funding-card-ack' }, [c.acknowledgement])]),
    ]),
  ]);
}

/** The footer part with one card per programme, or null for none. */
export function fundingCards(cards: readonly FundingCard[]): HTMLElement | null {
  if (cards.length === 0) return null;
  return h('div', { class: 'funding-cards-wrap', 'data-mandatory': 'funding_card' }, [
    h(
      'ul',
      { class: 'funding-cards' },
      cards.map((c) => h('li', {}, [fundingCard(c)])),
    ),
  ]);
}

/** Reads the cards and puts them first in `footer`'s inner box. */
export async function fillFunding(footer: HTMLElement): Promise<void> {
  const r = await get(FUNDING_PATH);
  const cards = ok(r) ? decodeCards(r.body) : null;
  const part = cards === null ? null : fundingCards(cards);
  if (part === null) return;
  const inner = footer.querySelector('.inner') ?? footer;
  inner.prepend(part);
}
