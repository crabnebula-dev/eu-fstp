// The operator page of the pilot `fstp-control` (ADR-009 "Pilot route
// feed", rows "Operator page", "Step-up per change" and "Staff passkey
// enrolment"; decided by Daniel on 2026-11-21, lane L15).
//
// - Log in with a pinned staff passkey (I-77).
// - See the served routes and the changes that `fstp-control route add`
//   and `route remove` proposed.
// - Approve one change with a fresh step-up bound to it (I-78). The
//   server signs the new table only then.
// - Enrol a new passkey: the page shows the staff entry the operator pins
//   in the configuration. The entry grants nothing until then.
//
// The ceremonies reuse `../auth/webauthn.js`. Every call goes through
// `../auth/api.js`, which sends the CSRF header. Nothing here builds HTML
// from strings (`../auth/dom.js`).

import { get, ok, post, record } from '../auth/api.js';
import { clear, h } from '../auth/dom.js';
import { isHex } from '../auth/encoding.js';
import { Failure, assertion, registration } from '../auth/webauthn.js';

/** A challenge and its WebAuthn options, from `fstp-control`. */
interface Options {
  readonly challengeId: string;
  readonly publicKey: Readonly<Record<string, unknown>>;
}

function optionsOf(body: unknown): Options {
  const o = record(body);
  const publicKey = record(o?.['public_key']);
  const challengeId = o?.['challenge_id'];
  if (publicKey === null || !isHex(challengeId, 32, 32)) {
    throw new Failure('malformed');
  }
  return { challengeId, publicKey };
}

function text(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function app(): HTMLElement {
  const el = document.getElementById('app');
  if (el === null) {
    throw new Failure('malformed');
  }
  return el;
}

function show(title: string, ...children: readonly (Node | string)[]): void {
  const root = app();
  clear(root);
  root.appendChild(h('h1', {}, [title]));
  for (const c of children) {
    root.appendChild(typeof c === 'string' ? h('p', {}, [c]) : c);
  }
}

function failed(e: unknown): void {
  const code = e instanceof Failure ? e.code : 'unavailable';
  show('Routes', `The step did not complete (${code}).`, button('Back', () => void start()));
}

function button(label: string, onClick: () => void): HTMLElement {
  const b = h('button', { type: 'button' }, [label]);
  b.addEventListener('click', onClick);
  return b;
}

async function login(): Promise<void> {
  const r = await post('/api/login/options', {});
  if (!ok(r)) throw new Failure('unavailable');
  const o = optionsOf(r.body);
  const a = await assertion(o.publicKey);
  const done = await post('/api/login', { ...a, challenge_id: o.challengeId });
  if (!ok(done)) throw new Failure('refused');
}

async function approve(id: string): Promise<void> {
  const r = await post(`/api/changes/${id}/options`, {});
  if (!ok(r)) throw new Failure('refused');
  const o = optionsOf(r.body);
  const a = await assertion(o.publicKey);
  const done = await post(`/api/changes/${id}/approve`, { ...a, challenge_id: o.challengeId });
  if (!ok(done)) throw new Failure('refused');
}

async function enrol(): Promise<void> {
  const r = await post('/api/register/options', {});
  if (!ok(r)) throw new Failure('unavailable');
  const o = optionsOf(r.body);
  const c = await registration(o.publicKey);
  const done = await post('/api/register', { ...c, challenge_id: o.challengeId });
  const entry = record(done.body);
  if (!ok(done) || entry === null) throw new Failure('refused');
  show(
    'Staff passkey',
    'Add this entry to "staff" in the configuration of fstp-control, then restart it.',
    h('p', {}, [
      `{"cose_key": "${text(entry['cose_key'])}", "credential_id": "${text(entry['credential_id'])}", "staff": "${text(entry['staff'])}"}`,
    ]),
    button('Back', () => void start()),
  );
}

function describe(route: unknown): string {
  const r = record(route);
  if (r === null) return '';
  const app = record(r['app']);
  const vault = record(r['vault']);
  return `${text(r['host'])}: cell ${text(r['cell'])}, app ${text(app?.['address'])} (${text(app?.['server_name'])}, pin ${text(app?.['cert_sha256'])}), vault ${text(vault?.['address'])} (${text(vault?.['server_name'])}, pin ${text(vault?.['cert_sha256'])})`;
}

async function start(): Promise<void> {
  const r = await get('/api/state');
  if (r.status === 401) {
    show(
      'Routes',
      'Log in with your staff passkey.',
      button('Log in', () => void login().then(start, failed)),
      button('Enrol a new passkey', () => void enrol().catch(failed)),
    );
    return;
  }
  const state = record(r.body);
  if (!ok(r) || state === null) {
    failed(new Failure('unavailable'));
    return;
  }
  const routes = Array.isArray(state['routes']) ? (state['routes'] as unknown[]) : [];
  const pending = Array.isArray(state['pending']) ? (state['pending'] as unknown[]) : [];
  const list = h('ul', {}, routes.map((x) => h('li', {}, [describe(x)])));
  const waiting = h(
    'ul',
    {},
    pending.map((x) => {
      const c = record(x);
      const id = text(c?.['id']);
      const what =
        text(c?.['op']) === 'remove'
          ? `Remove every route of cell ${text(c?.['cell'])}`
          : `Add or replace: ${describe(c?.['route'])}`;
      return h('li', {}, [
        h('p', {}, [what]),
        h('p', {}, [`Change digest ${text(c?.['digest'])}`]),
        button('Approve with a passkey step-up', () => void approve(id).then(start, failed)),
      ]);
    }),
  );
  show(
    'Routes',
    `Served version ${String(state['version'])}.`,
    list,
    h('h2', {}, ['Waiting changes']),
    pending.length === 0 ? 'None.' : waiting,
    button('Refresh', () => void start()),
  );
}

void start().catch(failed);
