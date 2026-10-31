// Invitation enrolment, `/auth/invite#<token>` (M3 design section 8.3
// item 1). The invitation link carries its single-use token in the
// fragment. The page puts it in the ceremony path, which the cell logs
// as its route template only (R-NF-02).
//
// Body forms, a reading of this lane, since lane w3ar fixes none yet:
// `POST /auth/invitations/{token}/register/options {}` answers
// `{challenge_id, public_key}` with the creation options, and
// `POST /auth/invitations/{token}/register` takes the new credential with
// `challenge_id` and opens the session.
//
// Open point: the SaaS first-admin token comes in two halves over two
// channels (design section 8.3, Q35). This page takes the joined token
// from the link. How the second half is entered is not designed yet.

import { ok, post } from '../api.js';
import { h } from '../dom.js';
import { isHex } from '../encoding.js';
import { PATHS, busy, frame, go, hush, showFailure, t, takeFragment } from '../layout.js';
import { Failure, failureOf, optionsOf, registration } from '../webauthn.js';

/** The longest invitation token, in bytes. */
const MAX_TOKEN = 64;

async function enrol(token: string): Promise<void> {
  const base = `/auth/invitations/${token}/register`;
  const o = await post(`${base}/options`, {});
  if (!ok(o)) throw failureOf(o.status === 401 ? 403 : o.status);
  const { challengeId, publicKey } = optionsOf(o.body);
  const c = await registration(publicKey);
  const r = await post(base, { ...c, challenge_id: challengeId });
  if (!ok(r)) throw failureOf(r.status === 401 ? 403 : r.status);
  go(PATHS.account);
}

/** Mounts the invitation page. */
export function mount(): void {
  const fragment = takeFragment();
  const { main, alert } = frame('invite.title', 'invite-error');
  if (!isHex(fragment, 16, MAX_TOKEN)) {
    showFailure(alert, new Failure('link'));
    return;
  }
  const button = h('button', { id: 'invite-register', type: 'button', class: 'primary' }, [
    t('invite.register'),
  ]) as HTMLButtonElement;
  button.addEventListener(
    'click',
    busy(button, async () => {
      hush(alert);
      try {
        await enrol(fragment);
      } catch (e) {
        showFailure(alert, e);
      }
    }),
  );
  main.append(h('p', {}, [t('invite.intro')]), button);
}
