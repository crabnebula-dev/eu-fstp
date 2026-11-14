// The "Demo sign-in" notice in the top bar (lane m4/site scope item 8),
// which is also the "Switch person" control (lane m4/demo-switch). Test
// only: `fstp-e2e-cell` serves the demo modules on a cell started with
// `--demo-signin`, and no shipped cell serves them (layering rule A9). It
// has no effect on import; `notice.ts` and `account.ts` call it.
//
// - The notice is a button in every top bar. It names the person signed
//   in now, once the cell said who that is.
// - It opens a modal dialog that lists the people of the scene from
//   `GET /auth/demo-signin/people`: each person's name, roles and the
//   line on what they can do. The current person is marked and has no
//   button.
// - "Sign in as <name>" posts `POST /auth/demo-signin/switch {account}`,
//   which issues one fresh single-use token, and redeems it at once on
//   `POST /auth/demo-signin`. The cell then holds a session for that
//   person in this tab, and the page opens their home page `/app/`.
// - The dialog is native: Escape and Close close it, and focus returns
//   to the notice (R-NF-03).

import { get, ok, post } from '../auth/api.js';
import { h } from '../auth/dom.js';
import { createI18n } from '../auth/i18n.js';
import { DEMO_EN, type DemoMessageId } from './messages.en.js';
import { type DemoPerson, type DemoScene, currentPerson, readScene, readToken } from './people.js';

const i18n = createI18n<DemoMessageId>(DEMO_EN);

/** The route that redeems a token (the cell's `demo_signin::ROUTE`). */
const ROUTE = '/auth/demo-signin';

/** The route that lists the people of the scene. */
const PEOPLE = '/auth/demo-signin/people';

/** The route that issues a token for one person. */
const SWITCH = '/auth/demo-signin/switch';

/** The home page a switch lands on. */
const HOME = '/app/';

/** The id of the switcher dialog. */
const DIALOG = 'demo-switch';

/** The name of the person signed in now, once read. */
let who: string | null = null;

/** The first read of the people, shared by every top bar of the page. */
let first: Promise<DemoScene | null> | null = null;

/** Reads the scene and its people, or null when the cell refused. */
async function readPeople(): Promise<DemoScene | null> {
  const r = await get(PEOPLE);
  return ok(r) ? readScene(r.body) : null;
}

/** The text of the notice. */
function noticeText(): string {
  return who === null ? i18n.label('notice.switch') : i18n.label('notice.switch_as', { name: who });
}

/** Writes the notice text into every notice of the page. */
function relabel(): void {
  for (const b of Array.from(document.querySelectorAll('.demo-notice'))) {
    b.textContent = noticeText();
  }
}

/** Signs in as `p` in this tab, then opens their home page. */
async function switchTo(p: DemoPerson, button: HTMLElement, status: HTMLElement, alert: HTMLElement): Promise<void> {
  if (button.getAttribute('aria-busy') === 'true') {
    return;
  }
  button.setAttribute('aria-busy', 'true');
  alert.textContent = '';
  status.textContent = i18n.label('switch.busy', { name: p.name });
  try {
    const issued = await post(SWITCH, { account: p.account });
    const token = ok(issued) ? readToken(issued.body) : null;
    if (token !== null && ok(await post(ROUTE, { token }))) {
      location.replace(HOME);
      return;
    }
    status.textContent = '';
    alert.textContent = i18n.label('switch.failed');
  } finally {
    button.removeAttribute('aria-busy');
  }
}

/** One person of the list. */
function item(p: DemoPerson, status: HTMLElement, alert: HTMLElement): HTMLElement {
  const parts: HTMLElement[] = [
    h('p', { class: 'demo-person-name' }, [
      h('strong', {}, [p.name]),
      i18n.label('switch.roles_after'),
      h('span', { 'data-demo-roles': true }, [p.roles]),
    ]),
    h('p', { class: 'muted', 'data-demo-does': true }, [p.does]),
  ];
  if (p.current) {
    parts.push(h('p', {}, [h('span', { class: 'badge badge--success', 'data-demo-current': true }, [i18n.label('switch.current')])]));
  } else {
    const button = h('button', { type: 'button', class: 'primary btn--primary', 'data-demo-switch-to': p.account }, [
      i18n.label('switch.signin', { name: p.name }),
    ]);
    button.addEventListener('click', () => {
      void switchTo(p, button, status, alert);
    });
    parts.push(h('p', {}, [button]));
  }
  return h('li', { class: p.current ? 'card card--primary' : 'card', 'data-demo-person': p.account, 'aria-current': p.current ? 'true' : false }, parts);
}

/** Fills `d` with the scene and its people, read now. */
async function fill(d: HTMLElement): Promise<void> {
  const intro = d.querySelector('#demo-switch-scene');
  const list = d.querySelector('#demo-switch-people');
  const status = d.querySelector('#demo-switch-status');
  const alert = d.querySelector('#demo-switch-error');
  if (!(intro instanceof HTMLElement) || !(list instanceof HTMLElement) || !(status instanceof HTMLElement) || !(alert instanceof HTMLElement)) {
    return;
  }
  alert.textContent = '';
  status.textContent = i18n.label('switch.loading');
  list.replaceChildren();
  const scene = await readPeople();
  status.textContent = '';
  if (scene === null) {
    alert.textContent = i18n.label('switch.list_failed');
    return;
  }
  who = currentPerson(scene)?.name ?? who;
  relabel();
  intro.textContent = i18n.label('switch.scene', { scene: scene.scene });
  list.replaceChildren(...scene.people.map((p) => item(p, status, alert)));
}

/** The switcher dialog of the page, built once. */
function dialog(): HTMLDialogElement {
  const found = document.getElementById(DIALOG);
  if (found instanceof HTMLDialogElement) {
    return found;
  }
  const close = h('button', { type: 'button', 'data-demo-switch-close': true }, [i18n.label('switch.close')]);
  const d = h('dialog', { id: DIALOG, 'aria-labelledby': 'demo-switch-title' }, [
    h('h2', { id: 'demo-switch-title' }, [i18n.label('switch.title')]),
    h('p', { id: 'demo-switch-scene' }),
    h('p', { id: 'demo-switch-error', role: 'alert', class: 'alert fstp-alert' }),
    h('p', { id: 'demo-switch-status', role: 'status', class: 'status fstp-status' }),
    h('ul', { id: 'demo-switch-people', class: 'journey-list' }),
    h('div', { class: 'actions' }, [close]),
  ]);
  if (!(d instanceof HTMLDialogElement)) {
    throw new TypeError('dialog');
  }
  close.addEventListener('click', () => d.close());
  document.body.append(d);
  return d;
}

/** Opens the switcher from `button`, and gives focus back to it on close. */
function open(button: HTMLElement): void {
  const d = dialog();
  if (d.open) {
    return;
  }
  d.addEventListener('close', () => button.focus(), { once: true });
  button.setAttribute('aria-expanded', 'true');
  d.addEventListener('close', () => button.setAttribute('aria-expanded', 'false'), { once: true });
  d.showModal();
  void fill(d);
}

/** Puts the notice in every top bar that lacks it. */
export function showNotice(): void {
  for (const bar of Array.from(document.querySelectorAll('header .topbar'))) {
    if (bar.querySelector('.demo-notice') === null) {
      const button = h(
        'button',
        {
          type: 'button',
          class: 'badge badge--warning demo-notice',
          'aria-haspopup': 'dialog',
          'aria-controls': DIALOG,
          'aria-expanded': 'false',
          'data-demo-switch': true,
        },
        [noticeText()],
      );
      button.addEventListener('click', () => open(button));
      bar.append(button);
    }
  }
  if (document.querySelector('.demo-notice') !== null) {
    dialog();
  }
  if (first === null) {
    first = readPeople();
    void first.then((scene) => {
      const p = scene === null ? null : currentPerson(scene);
      if (p !== null) {
        who = p.name;
        relabel();
      }
    });
  }
}
