// The login page, `/auth/login` (I-77, R-LG-02, M3 design sections 8.1,
// 8.2 and 8.7).
//
// - Passkey: `POST /auth/passkey/login/options {}` gives a challenge and
//   the cell's request options. The cell sets the RP id and the user
//   verification level, and requires UV of every management holder. The
//   assertion goes to `POST /auth/passkey/login`. A session cookie means
//   success. The page then opens the home page `/app/`, or the `/app/`
//   page a safe `?next=` names (`next.ts`; interim, pending Daniel,
//   design section 15.0, 2026-10-31).
// - Magic link: `POST /auth/magic/request {email}`. The cell answers the
//   same whether or not the address may get a link, so the page shows
//   one fixed message for every accepted request.

import { ok, post } from '../api.js';
import { h } from '../dom.js';
import { PATHS, busy, emailField, frame, go, hush, showFailure, signedInHome, statusRegion, t } from '../layout.js';
import { landingAfterSignIn } from '../next.js';
import { assertion, failureOf, optionsOf } from '../webauthn.js';

async function passkeyLogin(): Promise<void> {
  const o = await post('/auth/passkey/login/options', {});
  if (!ok(o)) throw failureOf(o.status);
  const { challengeId, publicKey } = optionsOf(o.body);
  const a = await assertion(publicKey);
  const r = await post('/auth/passkey/login', { ...a, challenge_id: challengeId });
  // A refused login is 401 here, not a lost session.
  if (r.status === 401) throw failureOf(403);
  if (!ok(r)) throw failureOf(r.status);
  // Interim, design section 15.0 (2026-10-31): the home page, or the
  // same-origin /app/ page the person asked for before signing in.
  go(landingAfterSignIn(location.search, signedInHome()));
}

/** Mounts the login page. */
export function mount(): void {
  const { main, alert } = frame('login.title', 'login-error');

  const passkey = h('button', { id: 'passkey-login', type: 'button', class: 'primary' }, [
    t('login.passkey'),
  ]) as HTMLButtonElement;
  passkey.addEventListener(
    'click',
    busy(passkey, async () => {
      hush(alert);
      try {
        await passkeyLogin();
      } catch (e) {
        showFailure(alert, e);
      }
    }),
  );

  const email = emailField('magic-email');
  const status = statusRegion('magic-status');
  const request = h('button', { id: 'magic-request', type: 'submit', class: 'secondary' }, [
    t('login.magic.submit'),
  ]) as HTMLButtonElement;
  const form = h('form', { id: 'magic-form', novalidate: true, 'aria-labelledby': 'magic-heading' }, [
    email.group,
    request,
  ]) as HTMLFormElement;
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    hush(alert);
    hush(status);
    const address = email.check();
    if (address === null) {
      return;
    }
    busy(request, async () => {
      const r = await post('/auth/magic/request', { email: address });
      if (ok(r)) {
        status.textContent = t('login.magic.sent');
      } else {
        showFailure(alert, failureOf(r.status));
      }
    })();
  });

  main.append(
    h('section', { class: 'card', 'aria-labelledby': 'passkey-heading' }, [
      h('h2', { id: 'passkey-heading' }, [t('login.passkey.heading')]),
      h('p', {}, [t('login.passkey.intro')]),
      passkey,
    ]),
    h('section', { class: 'card', 'aria-labelledby': 'magic-heading' }, [
      h('h2', { id: 'magic-heading' }, [t('login.magic.heading')]),
      h('p', {}, [t('login.magic.intro')]),
      form,
      status,
    ]),
    h('nav', { 'aria-label': t('login.more') }, [
      h('ul', { class: 'links' }, [
        h('li', {}, [h('a', { href: PATHS.signup }, [t('login.signup')])]),
        h('li', {}, [h('a', { href: PATHS.recovery }, [t('login.recovery')])]),
      ]),
    ]),
  );
}
