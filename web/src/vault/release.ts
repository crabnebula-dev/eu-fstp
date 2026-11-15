// The release loader, `GET /r#<ticket>` on the vault origin (I-17,
// R-AU-01, M3 design section 6.5, ADR-009 "Releases").
//
// The loader holds no released field. It reads the ticket from the
// fragment and posts it to `POST /r` as a top-level form navigation. The
// vault answers with the released fields, rendered server-side under
// `Content-Security-Policy: default-src 'none'`, in a document that runs
// no script (ADR-009 reads "no script" as that response document).
//
// The release must arrive as a navigation, since a document that runs no
// script cannot be built from a `fetch` reply. A form sends
// `application/x-www-form-urlencoded`, so the body is `ticket=<hex>`,
// which `fstp-vault` `origin::release_hex` takes beside the bare hex.

import { h } from '../auth/dom.js';
import { frame, t, takeTicket } from './page.js';

/** Mounts the loader and submits the ticket. */
export function mount(): void {
  const ticket = takeTicket();
  const { main, alert, status } = frame('release.title');
  if (ticket === null) {
    alert.textContent = t('error.link');
    return;
  }
  status.textContent = t('release.opening');
  const form = h('form', { method: 'post', action: '/r' }, [
    h('input', { type: 'hidden', name: 'ticket', value: ticket }),
  ]) as HTMLFormElement;
  main.append(form);
  form.submit();
}
