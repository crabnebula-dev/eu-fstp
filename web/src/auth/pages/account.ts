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

import { del, get, ok, post, record, type Reply } from '../api.js';
import { clear, h } from '../dom.js';
import { isHex } from '../encoding.js';
import { PATHS, frame, go, hush, i18n, showFailure, statusRegion, t } from '../layout.js';
import { type NavRoles, navRolesOf, siteLinks } from '../sitenav.js';
import { ADD_PASSKEY, askStepUp, revokeCredential, type StepUp } from '../stepup.js';
import { Failure, failureOf, optionsOf, registration } from '../webauthn.js';

/** The caller's own roles (`me.roles`, I-86), for the role links of the navigation. */
const ME_ROLES = '/api/v1/me/roles';

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
    return { id, current };
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

/**
 * The navigation of the account page, before `main`: Home, every page
 * the caller may open without an id, and Account as the current page
 * (Daniel, 2026-10-31: "please add all links to routes in the top row";
 * `docs/design/01-navigation-home.md` "Top row"). It holds the links of
 * `sitenav.ts`, which restates the sidebar of the `/app/` pages.
 * The role links follow once `me.roles` answers. A failed read leaves
 * the links every signed-in person has. A second mount keeps the one
 * navigation.
 */
function siteNav(main: HTMLElement): void {
  if (document.getElementById('site-nav') !== null) return;
  const list = h('ul', { class: 'links' });
  const fill = (roles: NavRoles | null): void => {
    clear(list);
    for (const l of siteLinks(roles)) {
      const attrs: Record<string, string> = { href: l.href, 'data-nav': l.kind };
      if (l.kind === 'account') attrs['aria-current'] = 'page';
      const text = t(`account.nav.${l.kind}`);
      list.append(h('li', {}, [h('a', attrs, [text])]));
    }
  };
  fill(null);
  main.before(h('nav', { id: 'site-nav', 'aria-label': t('account.nav') }, [list]));
  void get(ME_ROLES).then(
    (r) => {
      const roles = ok(r) ? navRolesOf(r.body) : null;
      if (roles !== null) fill(roles);
    },
    () => undefined,
  );
}

/** Mounts the account page. */
export function mount(): void {
  const { main, alert } = frame('account.title', 'account-error');
  siteNav(main);
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

  main.append(
    status,
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
}
