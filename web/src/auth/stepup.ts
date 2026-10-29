// The step-up of a high-risk action (I-78, R-LG-03, M3 design section
// 8.4, ADR-008 "Step-up").
//
// A page asks for a step-up through the modal `dialog#stepup`. Its
// confirm button runs the ceremony, then the action itself, in that
// order, and Escape or cancel closes it with nothing sent.
//
// The ceremony, on the wire of lane w3ar:
//
// 1. `POST /auth/stepup/options {command, command_id}`. The cell binds the
//    challenge to this session and to
//    `SHA-256(canonical(command) || command_id)`, and answers
//    `{challenge_id, public_key}` with `userVerification: required`.
// 2. A passkey assertion with UV over that challenge.
// 3. `POST /auth/stepup` with the assertion and `challenge_id`. The
//    step-up id is the challenge id, as the cell keys it. A reply that
//    names its own `stepup` id is used instead.
//
// The action then names `{command_id, stepup}`. One step-up authorises
// one action, so every action asks again.

import { ok, post, record, type Reply } from './api.js';
import { h } from './dom.js';
import { isHex, randomHex, type Json } from './encoding.js';
import { hush, showFailure, t } from './layout.js';
import { Failure, assertion, failureOf, optionsOf } from './webauthn.js';

/** A granted step-up for one action. */
export interface StepUp {
  readonly command_id: string;
  readonly stepup: string;
}

/**
 * The step-up action of adding a passkey, a route with no domain command
 * yet (design section 8.3). Lane w3ar reports that the `AddPasskey`
 * digest of `RegisterCredential` names a credential id that the options
 * call cannot know. This page uses the route action of the e2e contract
 * (`e2e/playwright.config.ts` `ROUTE_ACTIONS`), pending the lead.
 */
export const ADD_PASSKEY: Json = { type: 'AddPasskey' };

/** The step-up action of removing passkey `credential` of `account`. */
export function revokeCredential(account: string, credential: string): Json {
  return { auth: { account, credential, type: 'RevokeCredential' } };
}

/** The step-up action of approving recovery case `recoveryCase`. */
export function approveRecovery(recoveryCase: string): Json {
  return { auth: { case: recoveryCase, type: 'ApproveRecovery' } };
}

/** Runs the step-up ceremony for `command`. */
export async function stepUp(command: Json): Promise<StepUp> {
  const command_id = randomHex(16);
  const o = await post('/auth/stepup/options', { command, command_id });
  if (!ok(o)) throw failureOf(o.status);
  const { challengeId, publicKey } = optionsOf(o.body);
  const a = await assertion(publicKey);
  const g: Reply = await post('/auth/stepup', { ...a, challenge_id: challengeId });
  if (!ok(g)) throw failureOf(g.status);
  const named = record(g.body)?.['stepup'];
  return { command_id, stepup: isHex(named, 16, 16) ? named : challengeId };
}

interface Dialog {
  readonly dialog: HTMLDialogElement;
  readonly confirm: HTMLButtonElement;
  readonly alert: HTMLElement;
}

let shared: Dialog | null = null;
/**
 * The action of a step-up. It may return the element that takes focus
 * once the dialog closes, for an action that removes its own trigger.
 */
export type StepUpAction = (s: StepUp) => Promise<HTMLElement | void>;

let pending: StepUpAction | null = null;
let pendingCommand: Json = null;

function dialog(): Dialog {
  // A page frame rebuilt for a new link drops the old dialog.
  if (shared !== null && shared.dialog.isConnected) {
    return shared;
  }
  const confirm = h('button', { id: 'stepup-confirm', type: 'button', class: 'primary' }, [
    t('stepup.confirm'),
  ]) as HTMLButtonElement;
  const cancel = h('button', { id: 'stepup-cancel', type: 'button', class: 'secondary' }, [
    t('stepup.cancel'),
  ]) as HTMLButtonElement;
  const alert = h('p', { id: 'stepup-error', role: 'alert', class: 'alert' });
  const d = h(
    'dialog',
    { id: 'stepup', 'aria-labelledby': 'stepup-title', 'aria-describedby': 'stepup-intro' },
    [
      h('h2', { id: 'stepup-title' }, [t('stepup.title')]),
      h('p', { id: 'stepup-intro' }, [t('stepup.intro')]),
      alert,
      h('div', { class: 'actions' }, [confirm, cancel]),
    ],
  ) as HTMLDialogElement;
  cancel.addEventListener('click', () => d.close());
  d.addEventListener('close', () => {
    pending = null;
    pendingCommand = null;
    hush(alert);
  });
  confirm.addEventListener('click', () => {
    const then = pending;
    if (then === null || confirm.getAttribute('aria-busy') === 'true') {
      return;
    }
    // `aria-disabled`, not `disabled`: the button keeps focus.
    confirm.setAttribute('aria-disabled', 'true');
    confirm.setAttribute('aria-busy', 'true');
    hush(alert);
    stepUp(pendingCommand)
      .then((granted) => {
        // A dialog closed during the ceremony cancels the action. The
        // unused step-up expires on its own.
        if (!d.open || pending !== then) throw new Failure('cancelled');
        return then(granted);
      })
      .then(
        (target) => {
          d.close();
          // Closing returns focus to the trigger. An action that removed
          // it names where focus goes instead.
          if (target instanceof HTMLElement && target.isConnected) target.focus();
        },
        (e: unknown) => {
          showFailure(alert, e);
        },
      )
      .finally(() => {
        confirm.removeAttribute('aria-disabled');
        confirm.removeAttribute('aria-busy');
        if (d.open) confirm.focus();
      });
  });
  const main = document.querySelector('main') ?? document.body;
  main.append(d);
  shared = { dialog: d, confirm, alert };
  return shared;
}

/**
 * Opens the step-up dialog for `command`. Once the user confirms and the
 * step-up is granted, `then` runs the action with it. A failure of either
 * shows in the dialog, which stays open for another try or cancel.
 */
export function askStepUp(command: Json, then: StepUpAction): void {
  const d = dialog();
  if (d.dialog.open) {
    return;
  }
  pending = then;
  pendingCommand = command;
  hush(d.alert);
  d.dialog.showModal();
  d.confirm.focus();
}
