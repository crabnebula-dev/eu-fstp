// The magic-link confirm page, `/auth/magic#<token>` (M3 design sections
// 8.1 and 8.7, ADR-008 "Magic links"). Opening the link starts nothing:
// only the confirm button sends `POST /auth/magic/consume {token}`, so a
// mail scanner that fetches the link cannot use it up.

import { ok, post } from '../api.js';
import { h } from '../dom.js';
import { isHex } from '../encoding.js';
import { PATHS, busy, frame, go, hush, showFailure, signedInHome, t, takeFragment } from '../layout.js';
import { Failure, failureOf } from '../webauthn.js';

/** Mounts the confirm page. */
export function mount(): void {
  const fragment = takeFragment();
  const { main, alert } = frame('magic.title', 'magic-error');
  if (!isHex(fragment, 32, 32)) {
    showFailure(alert, new Failure('link'));
    return;
  }
  const token = fragment;
  const button = h('button', { id: 'magic-confirm', type: 'button', class: 'primary' }, [
    t('magic.confirm'),
  ]) as HTMLButtonElement;
  button.addEventListener(
    'click',
    busy(button, async () => {
      hush(alert);
      const r = await post('/auth/magic/consume', { token });
      if (ok(r)) {
        go(signedInHome());
      } else {
        // A refused link is 401 here, not a lost session.
        showFailure(alert, failureOf(r.status === 401 ? 403 : r.status));
      }
    }),
  );
  main.append(h('p', {}, [t('magic.intro')]), button);
}
