// The entry of the vault origin's pages (I-17, M3 design sections 6.5 and
// 11.2, ADR-009 "Vault origin").
//
// # Delivery
//
// The vault serves one shell, `web/src/vault/shell.html`, on `GET /w` and
// `GET /r`: the static pages and scripts that ADR-009 lists as its third
// route group. The shell loads this module from `/assets/vault/main.js`,
// which imports `/assets/auth/{dom,encoding,i18n}.js`, and the stylesheet
// `/assets/auth/auth.css`. `/assets/` serves the tsc output `web/dist/`
// and the `.css` files of `web/src` at the same relative paths.
//
// The shell replies need a CSP that runs these same-origin scripts and
// nothing else. Proposed for lane W2d, since `fstp-vault` sends
// `default-src 'none'` on every reply today:
// `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
// form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.
// The release document itself keeps `default-src 'none'` and runs no
// script.

import { installTrustedTypesPolicy } from '../auth/dom.js';
import { mount as release } from './release.js';
import { mount as write } from './write.js';

/** Mounts the page of the current path. */
function run(): void {
  if (location.pathname === '/r') {
    release();
  } else {
    write();
  }
}

installTrustedTypesPolicy();
run();
// A link to the same page with another ticket does not reload it, so the
// page mounts again for the new fragment.
window.addEventListener('hashchange', run);
