// Self-registration of a Receiving account, `/auth/signup` (M3 design
// section 8.3 item 2): email proof, then passkey enrolment in the same
// ceremony, at account creation.
//
// Body forms, a reading of this lane for the two routes of design
// section 8.7, which lane w3ar has not fixed yet:
//
// 1. `POST /auth/signup/options {email}` sends the email proof. Its reply
//    is the same for every address, so the page shows one message.
// 2. The proof link opens `/auth/signup#<token>`, with the token in the
//    fragment. `POST /auth/signup/options {token}` then answers
//    `{challenge_id, public_key}` with the creation options.
// 3. `POST /auth/signup` with the new credential, `challenge_id` and
//    `token` creates the account and its session.

import { ok, post } from '../api.js';
import { isHex } from '../encoding.js';
import { h } from '../dom.js';
import {
  PATHS,
  busy,
  emailField,
  frame,
  go,
  hush,
  showFailure,
  statusRegion,
  t,
  takeFragment,
} from '../layout.js';
import { Failure, failureOf, optionsOf, registration } from '../webauthn.js';

/** The longest proof token, in bytes. */
const MAX_TOKEN = 64;

async function register(token: string): Promise<void> {
  const o = await post('/auth/signup/options', { token });
  if (!ok(o)) throw failureOf(o.status === 401 ? 403 : o.status);
  const { challengeId, publicKey } = optionsOf(o.body);
  const c = await registration(publicKey);
  const r = await post('/auth/signup', { ...c, challenge_id: challengeId, token });
  if (!ok(r)) throw failureOf(r.status === 401 ? 403 : r.status);
  go(PATHS.account);
}

function mountRegister(token: string | null): void {
  const { main, alert } = frame('signup.register.title', 'signup-error');
  if (token === null) {
    showFailure(alert, new Failure('link'));
    return;
  }
  const button = h('button', { id: 'signup-register', type: 'button', class: 'primary' }, [
    t('signup.register'),
  ]) as HTMLButtonElement;
  button.addEventListener(
    'click',
    busy(button, async () => {
      hush(alert);
      try {
        await register(token);
      } catch (e) {
        showFailure(alert, e);
      }
    }),
  );
  main.append(h('p', {}, [t('signup.register.intro')]), button);
}

function mountRequest(): void {
  const { main, alert } = frame('signup.title', 'signup-error');
  const email = emailField('signup-email');
  const status = statusRegion('signup-status');
  const submit = h('button', { id: 'signup-submit', type: 'submit', class: 'primary' }, [
    t('signup.submit'),
  ]) as HTMLButtonElement;
  const form = h('form', { id: 'signup-form', novalidate: true }, [email.group, submit]);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    hush(alert);
    hush(status);
    const address = email.check();
    if (address === null) {
      return;
    }
    busy(submit, async () => {
      const r = await post('/auth/signup/options', { email: address });
      if (ok(r)) {
        status.textContent = t('signup.sent');
      } else {
        showFailure(alert, failureOf(r.status));
      }
    })();
  });
  main.append(h('p', {}, [t('signup.intro')]), form, status);
}

/** Mounts the signup page: the email step, or the passkey step of a proof link. */
export function mount(): void {
  const fragment = takeFragment();
  if (fragment === '') {
    mountRequest();
  } else {
    mountRegister(isHex(fragment, 16, MAX_TOKEN) ? fragment : null);
  }
}
