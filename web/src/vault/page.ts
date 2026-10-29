// The frame and the ticket of the vault origin's pages (I-17, M3 design
// sections 6.5 and 11.2, ADR-009 "Vault origin" and "Tickets").
//
// The browser opens `https://id.<cell host>/w#<ticket>` or `/r#<ticket>`.
// The ticket is the signed ticket in lowercase hex: the canonical claims
// body, then the 64-byte Ed25519 signature. The fragment never reaches a
// server log, and the page removes it from the address bar once read.

import { clear, h } from '../auth/dom.js';
import { isHex, unhex } from '../auth/encoding.js';
import { createI18n } from '../auth/i18n.js';
import { VAULT_EN, type VaultMessageId } from './messages.en.js';

/** The catalogue of the vault pages. */
export const i18n = createI18n<VaultMessageId>(VAULT_EN);

/** A message of the vault catalogue. */
export function t(id: VaultMessageId, args?: Readonly<Record<string, string>>): string {
  return i18n.label(id, args);
}

/** The length of the signature that ends a ticket, in bytes. */
export const SIGNATURE_LEN = 64;

/** The longest ticket the vault takes, in bytes (`MAX_TICKET_LEN`). */
export const MAX_TICKET_LEN = 2048;

/** The live regions of a page. */
export interface Frame {
  readonly main: HTMLElement;
  readonly alert: HTMLElement;
  readonly status: HTMLElement;
}

/** Sets the language and title and fills the shell's `main`. */
export function frame(title: VaultMessageId): Frame {
  document.documentElement.lang = i18n.locale;
  document.title = t(title);
  let main = document.querySelector('main');
  if (main === null) {
    main = h('main', { id: 'main' });
    document.body.append(main);
  }
  clear(main);
  const alert = h('p', { id: 'vault-error', role: 'alert', class: 'alert' });
  const status = h('p', { id: 'vault-status', role: 'status', class: 'status' });
  main.append(h('h1', {}, [t(title)]), alert, status);
  return { main, alert, status };
}

/**
 * The ticket in the fragment, as lowercase hex, or null when there is
 * none or it is outside the ticket's length. The fragment leaves the
 * address bar and the history entry either way.
 */
export function takeTicket(): string | null {
  const f = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  if (f !== '') {
    history.replaceState(null, '', location.pathname);
  }
  return isHex(f, SIGNATURE_LEN + 1, MAX_TICKET_LEN) ? f : null;
}

/**
 * The members of a ticket's claims that the write page shows a form for.
 *
 * Display only: they choose which form to show and fill the ids a fact
 * body names. The vault checks the signature before it uses any field,
 * and refuses a body that the ticket does not admit (`origin_binding`).
 * So nothing read here grants anything.
 */
export interface ClaimsView {
  readonly kind: string;
  readonly account: string;
  readonly proposal: string | null;
  readonly scope: string;
}

/** A decimal id as the claims spell it: no sign and no leading zero. */
export function isId(v: unknown): v is string {
  return typeof v === 'string' && /^(?:0|[1-9][0-9]{0,38})$/.test(v);
}

/**
 * Reads the claims of `ticket` for display, with the browser's UTF-8
 * decoder and `JSON.parse`. Null for a body that does not read as claims.
 */
export function claimsView(ticket: string): ClaimsView | null {
  try {
    const bytes = unhex(ticket);
    const body = bytes.subarray(0, bytes.length - SIGNATURE_LEN);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
    const v: unknown = JSON.parse(text);
    if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
    const o = v as Readonly<Record<string, unknown>>;
    const kind = o['kind'];
    const account = o['account'];
    const proposal = o['proposal'];
    const scope = o['scope'];
    if (typeof kind !== 'string' || !isId(account) || typeof scope !== 'string') return null;
    if (proposal !== null && !isId(proposal)) return null;
    return { kind, account, proposal, scope };
  } catch {
    return null;
  }
}
