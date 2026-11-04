// The demo sign-in page of the test cell, `GET /auth/demo-signin` (lane
// m4/site scope item 8). Test only: `fstp-e2e-cell` serves this module on
// a cell started with `--demo-signin`, and no shipped cell serves it
// (layering rule A9).
//
// The token travels in the fragment. The page takes it out of the
// address bar, posts it once, and opens the home page `/app/` when the
// cell opened a session. A refused token shows an alert, and the cell
// sets no cookie.

import { post, ok } from '../auth/api.js';
import { h, installTrustedTypesPolicy } from '../auth/dom.js';
import { createI18n } from '../auth/i18n.js';
import { DEMO_EN, type DemoMessageId } from './messages.en.js';

const i18n = createI18n<DemoMessageId>(DEMO_EN);

/** The route that redeems a token (the cell's `demo_signin::ROUTE`). */
const ROUTE = '/auth/demo-signin';

async function run(): Promise<void> {
  installTrustedTypesPolicy();
  document.documentElement.lang = i18n.locale;
  document.title = i18n.label('signin.title');
  let main = document.querySelector('main');
  if (main === null) {
    main = h('main', { id: 'main' });
    document.body.append(main);
  }
  const status = h('p', { id: 'demo-signin-status', role: 'status', class: 'status' }, [i18n.label('signin.busy')]);
  const alert = h('p', { id: 'demo-signin-error', role: 'alert', class: 'alert' });
  main.replaceChildren(h('h1', {}, [i18n.label('signin.title')]), alert, status);
  const token = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  if (token !== '') {
    history.replaceState(null, '', location.pathname);
  }
  if (token === '') {
    status.textContent = '';
    alert.textContent = i18n.label('signin.missing');
    return;
  }
  const r = await post(ROUTE, { token });
  if (ok(r)) {
    location.replace('/app/');
    return;
  }
  status.textContent = '';
  alert.textContent = i18n.label('signin.refused');
}

void run();
