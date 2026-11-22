// The "Add a passkey" offer after sign-in (Daniel, 2026-11-22, ADR-008
// "Later passkey").
//
// An applicant who signed up with email only signs in by email link. After
// such a sign-in this page offers a passkey, once per browser until
// dismissed. "Send me a link" asks `POST /auth/passkey-link`, which sends a
// fresh "email link, then create passkey" link (the recovery ceremony
// `EmailThenPasskey`). "Not now" remembers the choice in this browser and
// goes on. An account that holds a passkey is never offered one.

import { get, ok, post, record } from './api.js';
import { h } from './dom.js';
import { busy, frame, go, statusRegion, t } from './layout.js';

/** The local storage key that remembers "Not now". */
export const DISMISSED_KEY = 'fstp.passkeyoffer.dismissed';

/** Whether the devices reply `body` lists no passkey. Anything else is false. */
export function holdsNoPasskey(body: unknown): boolean {
  const o = record(body);
  return o !== null && Array.isArray(o['devices']) && o['devices'].length === 0;
}

function dismissed(): boolean {
  try {
    return globalThis.localStorage.getItem(DISMISSED_KEY) === '1';
  } catch {
    return false;
  }
}

function dismiss(): void {
  try {
    globalThis.localStorage.setItem(DISMISSED_KEY, '1');
  } catch {
    // Storage refused: the offer shows again next time.
  }
}

/**
 * Offers a passkey to an account that holds none, then opens `next`. An
 * account with a passkey, a dismissed offer and any failure go to `next`
 * at once.
 */
export async function offerPasskeyThen(next: string): Promise<void> {
  if (dismissed()) {
    go(next);
    return;
  }
  const r = await get('/auth/devices');
  if (!ok(r) || !holdsNoPasskey(r.body)) {
    go(next);
    return;
  }
  const { main, alert } = frame('offer.title', 'offer-error');
  const status = statusRegion('offer-status');
  const send = h('button', { id: 'offer-send', type: 'button', class: 'primary' }, [
    t('offer.send'),
  ]) as HTMLButtonElement;
  const later = h('button', { id: 'offer-later', type: 'button' }, [t('offer.later')]) as HTMLButtonElement;
  const goOn = h('a', { href: next, id: 'offer-continue' }, [t('offer.continue')]);
  send.addEventListener(
    'click',
    busy(send, async () => {
      const s = await post('/auth/passkey-link', {});
      if (ok(s)) {
        status.textContent = t('offer.sent');
        send.hidden = true;
        later.hidden = true;
        goOn.hidden = false;
      } else {
        alert.textContent = t('offer.failed');
      }
    }),
  );
  later.addEventListener('click', () => {
    dismiss();
    go(next);
  });
  goOn.hidden = true;
  main.append(h('p', {}, [t('offer.intro')]), send, later, status, h('p', {}, [goOn]));
}
