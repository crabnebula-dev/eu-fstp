// Account recovery, `/auth/recovery` (I-79, M3 design section 8.5).
//
// The cell recomputes the recovery path from the account's holdings at
// every step. The page only shows what the cell answers. The fragment
// says which step a link opens:
//
// | Fragment              | Step |
// | --------------------- | ---- |
// | none                  | Ask for recovery: `POST /auth/recovery {email}`, one reply for every address |
// | `e.<case>.<token>`    | Email proof: `POST /auth/recovery/{case}/email {token}` answers `{path}`, and for `EmailThenPasskey` also `enrolment`, a one-time enrolment token |
// | `c.<case>.<token>`    | New passkey: `POST /auth/recovery/{case}/complete {token}` answers the creation options, then the same route takes the credential with `challenge_id` and `token` |
// | `a.<case>`            | Approval by another current tenant admin, with a step-up: `POST /auth/recovery/{case}/approve {command_id, stepup}` |
//
// The fragment grammar and the bodies other than approve are a reading of
// this lane. Lane w3ar fixes only the approve body so far.
//
// Opening a link sends nothing. Each step waits for its button, as the
// magic-link confirm page does, so a mail scanner that opens the link
// cannot use up the single-use proof or receive the enrolment token.

import { ok, post, record } from '../api.js';
import { h } from '../dom.js';
import { isHex } from '../encoding.js';
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
import { approveRecovery, askStepUp } from '../stepup.js';
import { Failure, failureOf, optionsOf, registration } from '../webauthn.js';

/** The longest recovery token, in bytes. */
const MAX_TOKEN = 64;

function caseOk(c: string | undefined): c is string {
  return isHex(c, 16, 16);
}

function tokenOk(c: string | undefined): c is string {
  return isHex(c, 16, MAX_TOKEN);
}

/** A refused ceremony step answers 401 or 403, never a lost session here. */
function refused(status: number): Failure {
  return failureOf(status === 401 ? 403 : status);
}

async function complete(recoveryCase: string, token: string): Promise<void> {
  const route = `/auth/recovery/${recoveryCase}/complete`;
  const o = await post(route, { token });
  if (!ok(o)) throw refused(o.status);
  const { challengeId, publicKey } = optionsOf(o.body);
  const c = await registration(publicKey);
  const r = await post(route, { ...c, challenge_id: challengeId, token });
  if (!ok(r)) throw refused(r.status);
  go(signedInHome());
}

/** Mounts the new passkey step. Returns its button. */
function mountComplete(recoveryCase: string, token: string): HTMLButtonElement {
  const { main, alert } = frame('recovery.complete.title', 'recovery-error');
  const button = h('button', { id: 'recovery-complete', type: 'button', class: 'primary' }, [
    t('recovery.complete'),
  ]) as HTMLButtonElement;
  button.addEventListener(
    'click',
    busy(button, async () => {
      hush(alert);
      try {
        await complete(recoveryCase, token);
      } catch (e) {
        showFailure(alert, e);
      }
    }),
  );
  main.append(h('p', {}, [t('recovery.complete.intro')]), button);
  return button;
}

/**
 * Sends the email proof. Returns true when the step is over, so the
 * button leaves the page, and false when the cell refused it.
 */
async function prove(recoveryCase: string, token: string, status: HTMLElement, alert: HTMLElement): Promise<boolean> {
  status.textContent = t('recovery.checking');
  const r = await post(`/auth/recovery/${recoveryCase}/email`, { token });
  hush(status);
  if (!ok(r)) {
    showFailure(alert, refused(r.status));
    return false;
  }
  const o = record(r.body);
  const path = o?.['path'];
  const enrolment = o?.['enrolment'];
  if (path === 'EmailThenPasskey' && typeof enrolment === 'string' && tokenOk(enrolment)) {
    // The page frame is rebuilt, so focus moves to the next step.
    mountComplete(recoveryCase, enrolment).focus();
  } else if (path === 'SecondAdmin') {
    status.textContent = t('recovery.path.second_admin');
  } else if (path === 'OperatorProcess') {
    status.textContent = t('recovery.path.operator');
  } else if (path === 'HostConsole') {
    status.textContent = t('recovery.path.host');
  } else {
    showFailure(alert, new Failure('malformed'));
    return false;
  }
  return true;
}

/**
 * The email proof step. Only the confirm button sends the proof, so
 * opening the link spends nothing (ADR-008 "Magic links" rule, applied to
 * the recovery proof).
 */
function mountProof(recoveryCase: string, token: string): void {
  const { main, alert } = frame('recovery.title', 'recovery-error');
  const status = statusRegion('recovery-status');
  const button = h('button', { id: 'recovery-proof', type: 'button', class: 'primary' }, [
    t('recovery.proof.confirm'),
  ]) as HTMLButtonElement;
  button.addEventListener(
    'click',
    busy(button, async () => {
      hush(alert);
      let done = false;
      try {
        done = await prove(recoveryCase, token, status, alert);
      } catch (e) {
        showFailure(alert, e);
      }
      if (done && button.isConnected) {
        button.remove();
        status.focus();
      }
    }),
  );
  status.tabIndex = -1;
  main.append(h('p', {}, [t('recovery.proof.intro')]), button, status);
}

function mountApprove(recoveryCase: string): void {
  const { main, alert } = frame('recovery.approve.title', 'recovery-error');
  const status = statusRegion('recovery-status');
  const button = h('button', { id: 'recovery-approve', type: 'button', class: 'primary' }, [
    t('recovery.approve'),
  ]) as HTMLButtonElement;
  button.addEventListener('click', () => {
    hush(alert);
    hush(status);
    askStepUp(approveRecovery(recoveryCase), async (s) => {
      const r = await post(`/auth/recovery/${recoveryCase}/approve`, {
        command_id: s.command_id,
        stepup: s.stepup,
      });
      if (r.status === 401) {
        go(PATHS.login);
        return;
      }
      if (!ok(r)) throw failureOf(r.status);
      button.remove();
      status.textContent = t('recovery.approved');
      return status;
    });
  });
  status.tabIndex = -1;
  main.append(h('p', {}, [t('recovery.approve.intro')]), button, status);
}

function mountRequest(): void {
  const { main, alert } = frame('recovery.title', 'recovery-error');
  const email = emailField('recovery-email');
  const status = statusRegion('recovery-status');
  const submit = h('button', { id: 'recovery-submit', type: 'submit', class: 'primary' }, [
    t('recovery.submit'),
  ]) as HTMLButtonElement;
  const form = h('form', { id: 'recovery-form', novalidate: true }, [email.group, submit]);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    hush(alert);
    hush(status);
    const address = email.check();
    if (address === null) {
      return;
    }
    busy(submit, async () => {
      const r = await post('/auth/recovery', { email: address });
      if (ok(r)) {
        status.textContent = t('recovery.sent');
      } else {
        showFailure(alert, failureOf(r.status));
      }
    })();
  });
  main.append(h('p', {}, [t('recovery.intro')]), form, status);
}

/** Mounts the recovery page for the step its link names. */
export function mount(): void {
  const fragment = takeFragment();
  if (fragment === '') {
    mountRequest();
    return;
  }
  const [step, recoveryCase, token, ...rest] = fragment.split('.');
  if (rest.length === 0 && caseOk(recoveryCase)) {
    if (step === 'e' && tokenOk(token)) {
      mountProof(recoveryCase, token);
      return;
    }
    if (step === 'c' && tokenOk(token)) {
      mountComplete(recoveryCase, token);
      return;
    }
    if (step === 'a' && token === undefined) {
      mountApprove(recoveryCase);
      return;
    }
  }
  const { alert } = frame('recovery.title', 'recovery-error');
  showFailure(alert, new Failure('link'));
}
