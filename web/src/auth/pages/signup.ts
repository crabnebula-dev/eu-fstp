// Self-registration of a Receiving account, `/auth/signup` (M3 design
// section 8.3 item 2): email proof, then, optionally, a passkey.
//
// Daniel, 2026-11-22 (ADR-032, ADR-008): "Email only, passkey optional".
// The confirmed email finishes the registration where the organisation
// offers email links, and the account signs in by magic link. A passkey
// stays on offer in the same step.
//
// Body forms:
//
// 1. `POST /auth/signup/options {email}` sends the email proof. Its reply
//    is the same for every address, so the page shows one message.
// 2. The proof link opens `/auth/signup#<token>`, with the token in the
//    fragment.
// 3. `POST /auth/signup {token}` creates the account with no passkey and
//    opens a magic-link session. A 403 says the organisation asks for a
//    passkey.
// 4. Or `POST /auth/signup/options {token}` answers `{challenge_id,
//    public_key}`, and `POST /auth/signup` with the new credential,
//    `challenge_id` and `token` creates the account with its passkey.

import { ok, post, record } from '../api.js';
import { claimPath, kept } from '../anondraft.js';
import { offerPasskeyThen } from '../passkeyoffer.js';
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
  signedInHome,
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
  landAfterSignup();
}

/**
 * Opens the page after a registration. ADR-032: a draft started without
 * an account moves into the new account on the claim page.
 */
function landAfterSignup(): void {
  const draft = kept();
  go(draft === null ? signedInHome() : claimPath(draft.call));
}

function mountRegister(token: string | null): void {
  const { main, alert } = frame('signup.register.title', 'signup-error');
  if (token === null) {
    showFailure(alert, new Failure('link'));
    return;
  }
  // Daniel, 2026-11-22 (ADR-032, ADR-008): "Email only, passkey
  // optional". The confirmed email finishes the registration, and the
  // account signs in by email link. A passkey stays on offer.
  const finish = h('button', { id: 'signup-finish', type: 'button', class: 'primary' }, [
    t('signup.finish'),
  ]) as HTMLButtonElement;
  const button = h('button', { id: 'signup-register', type: 'button' }, [
    t('signup.register'),
  ]) as HTMLButtonElement;
  finish.addEventListener(
    'click',
    busy(finish, async () => {
      hush(alert);
      const r = await post('/auth/signup', { token });
      if (ok(r)) {
        // ADR-008 "Later passkey": with no draft to claim, the new
        // email-only account is offered a passkey first.
        const draft = kept();
        if (draft === null) {
          await offerPasskeyThen(signedInHome());
        } else {
          go(claimPath(draft.call));
        }
        return;
      }
      if (r.status === 403) {
        // The organisation does not offer email links: a passkey is needed.
        alert.textContent = t('signup.passkey.needed');
        return;
      }
      showFailure(alert, failureOf(r.status === 401 ? 403 : r.status));
    }),
  );
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
  main.append(
    h('p', {}, [t('signup.register.intro')]),
    finish,
    h('p', {}, [t('signup.passkey.optional')]),
    button,
  );
}

/**
 * The "Check your email" state after a sent request (`auth-check-email`
 * prototype). The reply is the same for every address, so the page says
 * the same for every address.
 */
function sent(address: string): void {
  const { main } = frame('signup.sent.title', 'signup-error');
  const status = statusRegion('signup-status');
  main.append(
    h('section', { class: 'card', 'aria-labelledby': 'signup-sent-heading' }, [
      h('h2', { id: 'signup-sent-heading' }, [t('signup.sent.heading')]),
      h('p', { class: 'pid' }, [address]),
      status,
    ]),
    codeForm(address),
    h('p', {}, [h('a', { href: PATHS.signup }, [t('signup.sent.again')])]),
  );
  status.textContent = t('signup.sent');
}

/**
 * The typed code of the registration email (Daniel, 2026-11-22, ADR-008
 * "Registration code"). The right code answers the proof token, and the
 * page goes on as the link does.
 */
function codeForm(address: string): HTMLElement {
  const errorId = 'signup-code-error';
  const input = h('input', {
    id: 'signup-code',
    name: 'code',
    type: 'text',
    inputmode: 'numeric',
    autocomplete: 'one-time-code',
    spellcheck: 'false',
  }) as HTMLInputElement;
  const error = h('p', { id: errorId, class: 'field-error' });
  const submit = h('button', { id: 'signup-code-submit', type: 'submit' }, [
    t('signup.code.submit'),
  ]) as HTMLButtonElement;
  const form = h('form', { id: 'signup-code-form', novalidate: true }, [
    h('p', {}, [t('signup.code.intro')]),
    h('div', { class: 'field' }, [h('label', { for: 'signup-code' }, [t('signup.code.label')]), input, error]),
    submit,
  ]);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const code = input.value.replace(/\s/g, '');
    busy(submit, async () => {
      const r = await post('/auth/signup/code', { code, email: address });
      const o = record(r.body);
      const token = o === null ? null : o['token'];
      if (ok(r) && typeof token === 'string' && isHex(token, 32, 32)) {
        input.removeAttribute('aria-invalid');
        mountRegister(token);
        return;
      }
      input.setAttribute('aria-invalid', 'true');
      input.setAttribute('aria-describedby', errorId);
      error.textContent = t('signup.code.wrong');
      input.focus();
    })();
  });
  return form;
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
        sent(address);
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
