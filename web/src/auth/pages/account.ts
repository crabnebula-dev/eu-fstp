// The account page, `/auth/account`: sessions and passkeys (R-LG-04,
// I-78, M3 design sections 8.2, 8.3 and 8.7).
//
// - `GET /auth/sessions` lists the account's live sessions, with the one
//   this page runs in marked `current`. Without a session the cell
//   answers 401 and the page opens the login page.
// - `DELETE /auth/sessions/{id}` ends one. Ending the current session
//   signs out.
// - `GET /auth/devices` lists the account's passkeys.
// - Adding a passkey is the high-risk action `AddPasskey`. The step-up
//   comes first, then `POST /auth/passkeys/options {command_id, stepup}`
//   and `POST /auth/passkeys` with the new credential.
// - Removing a passkey is `ChangeLoginMethods`. The step-up names the
//   command the gate admits, `RevokeCredential {account, credential}`,
//   and `DELETE /auth/devices/{id}?command_id=..&stepup=..` names the
//   step-up (lane w3ar). The command needs the account id, which the
//   devices reply must carry as `account`. Lane w3ar does not send it
//   yet, so removal fails closed until it does.
// - SA-11 (Daniel, 2026-11-15 night): the account sets or clears its own
//   display name, `GET` and `POST /api/v1/me/display-name`
//   (`me.display_name`, `me.set_display_name`). Plain text, at most 100
//   characters. Only the team and member pages show it.
//   TODO(legal): the privacy notice needs a line for this processing.
//   Daniel supplies the wording.

import { del, get, ok, post, record, type Reply } from '../api.js';
import { clear, h } from '../dom.js';
import { isHex } from '../encoding.js';
import { PATHS, frame, go, hush, i18n, showFailure, statusRegion, t } from '../layout.js';
import { appShell, awaitsActivation } from '../appshell.js';
import { ADD_PASSKEY, askStepUp, revokeCredential, type StepUp } from '../stepup.js';
import { Failure, failureOf, optionsOf, registration } from '../webauthn.js';

/** One live session, as `GET /auth/sessions` lists it. */
interface SessionItem {
  readonly id: string;
  readonly current: boolean;
  readonly method: string;
  readonly started: bigint;
  readonly lastUsed: bigint;
}

/** One passkey, as `GET /auth/devices` lists it. */
interface DeviceItem {
  readonly id: string;
  readonly current: boolean;
  /** A suspect passkey is disabled for good (ADR-008, 2026-11-19). */
  readonly suspect: boolean;
}

/** The display name routes of the API (SA-11). */
const DISPLAY_NAME = '/api/v1/me/display-name';

/** The longest display name, in characters (SA-11). */
const NAME_MAX = 100;

/**
 * The `me.set_display_name` body for `text`: the trimmed name, or null to
 * clear a blank one. Null as a whole for a name the cell refuses: longer
 * than 100 characters, or with markup or a control character. It restates
 * `web/src/admin/team/model.ts` `displayNameBody`, since the auth pages
 * are delivered on their own.
 */
export function nameBody(text: string): { display_name: string | null } | null {
  const v = text.trim();
  if (v === '') return { display_name: null };
  if ([...v].length > NAME_MAX || /[<>\p{Cc}]/u.test(v)) return null;
  return { display_name: v };
}

/**
 * The rule a display name another account of the organisation holds is
 * refused under (SA-11 amendment, `fstp_api_core::display_name::TAKEN_RULE`).
 */
export const NAME_TAKEN_RULE = 'SA-11-unique';

/**
 * Whether `r` refuses a display name because another account of the
 * organisation holds it (SA-11 amendment). The refusal names no account.
 */
export function nameTaken(r: Reply): boolean {
  return !ok(r) && record(r.body)?.['rule'] === NAME_TAKEN_RULE;
}

/** The own display name of a `me.display_name` reply, null for none, undefined for another shape. */
function nameOf(body: unknown): string | null | undefined {
  const o = record(body);
  if (o === null || Object.keys(o).length !== 1) return undefined;
  const n = o['display_name'];
  return n === null || typeof n === 'string' ? n : undefined;
}

/** The longest credential id, in bytes (WebAuthn Level 2 section 5.8.3). */
const MAX_CREDENTIAL = 1023;

/** A UTC microsecond instant: a decimal string, as the cell writes it. */
function micros(v: unknown): bigint | null {
  if (typeof v === 'string' && /^-?(?:0|[1-9][0-9]{0,18})$/.test(v)) {
    return BigInt(v);
  }
  return null;
}

function sessionsOf(body: unknown): SessionItem[] {
  const list = record(body)?.['sessions'];
  if (!Array.isArray(list)) throw new Failure('malformed');
  return list.map((x: unknown) => {
    const o = record(x);
    const id = o?.['id'];
    const current = o?.['current'];
    const method = o?.['method'];
    const started = micros(o?.['started']);
    const lastUsed = micros(o?.['last_used']);
    if (
      !isHex(id, 16, 16) ||
      typeof current !== 'boolean' ||
      typeof method !== 'string' ||
      started === null ||
      lastUsed === null
    ) {
      throw new Failure('malformed');
    }
    return { id, current, method, started, lastUsed };
  });
}

function devicesOf(body: unknown): { devices: DeviceItem[]; account: string | null } {
  const o = record(body);
  const list = o?.['devices'];
  if (!Array.isArray(list)) throw new Failure('malformed');
  const account = o?.['account'];
  const devices = list.map((x: unknown) => {
    const d = record(x);
    const id = d?.['id'];
    const current = d?.['current'];
    if (!isHex(id, 1, MAX_CREDENTIAL) || typeof current !== 'boolean') {
      throw new Failure('malformed');
    }
    return { id, current, suspect: d?.['suspect'] === true };
  });
  return {
    devices,
    account: typeof account === 'string' && /^(?:0|[1-9][0-9]{0,38})$/.test(account) ? account : null,
  };
}

const DATE = new Intl.DateTimeFormat(i18n.locale, { dateStyle: 'medium', timeStyle: 'short' });

/** An instant in UTC microseconds, in the catalogue locale. */
function when(us: bigint): string {
  return DATE.format(new Date(Number(us / 1000n)));
}

function methodLabel(method: string): string {
  if (method === 'passkey') return t('account.session.passkey');
  if (method === 'magic_link') return t('account.session.magic_link');
  return t('account.session.other');
}

/** Mounts the account page. */
export function mount(): void {
  const { main, alert } = frame('account.title', 'account-error');
  appShell(main);
  const status = statusRegion('account-status');
  const sessions = h('ul', { id: 'sessions-list', class: 'items', 'aria-labelledby': 'sessions-heading' });
  const devices = h('ul', { id: 'devices-list', class: 'items', 'aria-labelledby': 'devices-heading' });
  const add = h('button', { id: 'passkey-add', type: 'button', class: 'secondary' }, [
    t('account.passkey.add'),
  ]) as HTMLButtonElement;
  let account: string | null = null;

  /** Handles a reply that is not 2xx: 401 leaves for the login page. */
  const failed = (r: Reply): Failure => {
    if (r.status === 401) go(PATHS.login);
    return failureOf(r.status);
  };

  const loadSessions = async (): Promise<void> => {
    const r = await get('/auth/sessions');
    if (!ok(r)) throw failed(r);
    const items = sessionsOf(r.body);
    clear(sessions);
    for (const s of items) {
      const detailId = `session-${s.id}-detail`;
      const end = h('button', { type: 'button', class: 'secondary', 'aria-describedby': detailId }, [
        s.current ? t('account.session.signout') : t('account.session.end'),
      ]);
      end.addEventListener('click', () => endSession(s));
      const detail = h('p', { id: detailId }, [
        t('account.session.detail', { started: when(s.started), last_used: when(s.lastUsed) }),
      ]);
      sessions.append(
        h('li', s.current ? { 'aria-current': 'true' } : {}, [
          h('strong', {}, [methodLabel(s.method)]),
          ...(s.current ? [' ', h('span', { class: 'tag' }, [t('account.session.current')])] : []),
          detail,
          end,
        ]),
      );
    }
  };

  const loadDevices = async (): Promise<void> => {
    const r = await get('/auth/devices');
    if (!ok(r)) throw failed(r);
    const got = devicesOf(r.body);
    account = got.account;
    clear(devices);
    for (const d of got.devices) {
      const suffix = d.id.slice(-6);
      const remove = h('button', { type: 'button', class: 'secondary' }, [
        t('account.device.remove', { suffix }),
      ]);
      remove.addEventListener('click', () => removeDevice(d));
      devices.append(
        h('li', d.current ? { 'aria-current': 'true' } : {}, [
          h('strong', {}, [t('account.device.label', { suffix })]),
          ...(d.current ? [' ', h('span', { class: 'tag' }, [t('account.device.current')])] : []),
          ...(d.suspect ? [' ', h('span', { class: 'tag' }, [t('account.device.disabled')])] : []),
          ' ',
          remove,
        ]),
      );
    }
  };

  // The lists are rebuilt after a change, which removes the focused
  // button. Focus then moves to the status region, which reads the
  // outcome (R-NF-03, WCAG 2.4.3).
  status.tabIndex = -1;

  const show = (p: Promise<void>, done?: string): void => {
    hush(alert);
    hush(status);
    p.then(
      () => {
        if (done !== undefined) {
          status.textContent = done;
          status.focus();
        }
      },
      (e: unknown) => showFailure(alert, e),
    );
  };

  const endSession = (s: SessionItem): void => {
    show(
      (async () => {
        const r = await del(`/auth/sessions/${s.id}`);
        if (s.current && (ok(r) || r.status === 401)) {
          go(PATHS.login);
          return;
        }
        if (!ok(r)) throw failed(r);
        await loadSessions();
      })(),
      s.current ? undefined : t('account.session.ended'),
    );
  };

  const removeDevice = (d: DeviceItem): void => {
    hush(alert);
    hush(status);
    if (account === null) {
      showFailure(alert, new Failure('unavailable'));
      return;
    }
    askStepUp(revokeCredential(account, d.id), async (s: StepUp) => {
      const q = `command_id=${s.command_id}&stepup=${s.stepup}`;
      const r = await del(`/auth/devices/${d.id}?${q}`);
      if (!ok(r)) throw failed(r);
      await loadDevices();
      status.textContent = t('account.device.removed');
      return status;
    });
  };

  add.addEventListener('click', () => {
    hush(alert);
    hush(status);
    askStepUp(ADD_PASSKEY, async (s: StepUp) => {
      const ids = { command_id: s.command_id, stepup: s.stepup };
      const o = await post('/auth/passkeys/options', ids);
      if (!ok(o)) throw failed(o);
      const { challengeId, publicKey } = optionsOf(o.body);
      const c = await registration(publicKey);
      const r = await post('/auth/passkeys', { ...c, ...ids, challenge_id: challengeId });
      if (!ok(r)) throw failed(r);
      await loadDevices();
      status.textContent = t('account.passkey.added');
    });
  });

  // SA-11: the display name form.
  const nameInput = h('input', {
    id: 'display-name',
    type: 'text',
    autocomplete: 'nickname',
    'aria-describedby': 'display-name-hint',
  }) as HTMLInputElement;
  const nameNow = h('p', { id: 'display-name-now' });
  const saveName = h('button', { id: 'display-name-save', type: 'submit' }, [t('account.name.save')]);
  const clearName = h('button', { id: 'display-name-clear', type: 'button', class: 'secondary' }, [
    t('account.name.clear'),
  ]);
  const nameForm = h('form', { id: 'display-name-form', novalidate: '' }, [
    h('label', { for: 'display-name' }, [t('account.name.label')]),
    nameInput,
    h('p', { id: 'display-name-hint', class: 'hint' }, [t('account.name.hint')]),
    saveName,
    ' ',
    clearName,
  ]);
  const showName = (n: string | null): void => {
    nameInput.value = n ?? '';
    nameNow.textContent = n === null ? t('account.name.none') : '';
  };
  const loadName = async (): Promise<void> => {
    const r = await get(DISPLAY_NAME);
    if (!ok(r)) throw failed(r);
    const n = nameOf(r.body);
    if (n === undefined) throw new Failure('malformed');
    showName(n);
  };
  const sendName = (text: string): void => {
    const body = nameBody(text);
    hush(alert);
    hush(status);
    if (body === null) {
      alert.textContent = t('account.name.invalid');
      nameInput.setAttribute('aria-invalid', 'true');
      nameInput.focus();
      return;
    }
    nameInput.removeAttribute('aria-invalid');
    show(
      (async () => {
        const r = await post(DISPLAY_NAME, body);
        if (nameTaken(r)) {
          // SA-11 amendment: the name is in use. The field keeps the
          // text so the person can change it.
          alert.textContent = t('account.name.taken');
          nameInput.setAttribute('aria-invalid', 'true');
          nameInput.focus();
          return;
        }
        if (!ok(r)) throw failed(r);
        await loadName();
        status.textContent =
          body.display_name === null ? t('account.name.cleared') : t('account.name.saved');
        status.focus();
      })(),
    );
  };
  nameForm.addEventListener('submit', (e) => {
    e.preventDefault();
    sendName(nameInput.value);
  });
  clearName.addEventListener('click', () => sendName(''));

  // The section shows once its read answered. Before activation the cell
  // refuses the read (ADR-021), so the page does not send it and the
  // section stays hidden: the browser would log the refusal as an error
  // (ADR-014).
  const nameSection = h('section', { id: 'display-name-section', 'aria-labelledby': 'display-name-heading', hidden: '' }, [
    h('h2', { id: 'display-name-heading' }, [t('account.name.heading')]),
    h('p', {}, [t('account.name.intro')]),
    nameNow,
    nameForm,
  ]);
  main.append(
    status,
    nameSection,
    h('section', { 'aria-labelledby': 'sessions-heading' }, [
      h('h2', { id: 'sessions-heading' }, [t('account.sessions')]),
      sessions,
    ]),
    h('section', { 'aria-labelledby': 'devices-heading' }, [
      h('h2', { id: 'devices-heading' }, [t('account.devices')]),
      devices,
      add,
    ]),
  );
  show(
    (async () => {
      await loadSessions();
      await loadDevices();
    })(),
  );
  void awaitsActivation().then((waiting) =>
    waiting
      ? undefined
      : loadName().then(
          () => nameSection.removeAttribute('hidden'),
          () => undefined,
        ),
  );
}
