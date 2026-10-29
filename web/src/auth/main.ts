// The entry of the cell origin's auth pages (M3 design section 11.2,
// ADR-003, ADR-014).
//
// # Delivery
//
// The cell serves one shell, `web/src/auth/shell.html`, on each page path
// of `PATHS`: `/auth/login`, `/auth/signup`, `/auth/invite`,
// `/auth/magic`, `/auth/recovery` and `/auth/account`. The shell holds no
// text and no inline script or style. It loads this module from
// `/assets/auth/main.js` and the stylesheet from `/assets/auth/auth.css`.
// `/assets/` serves the tsc output `web/dist/` and the `.css` files of
// `web/src` at the same relative paths. Each page reply carries the cell
// CSP of design section 11.2, which allows exactly this:
// `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';
// frame-ancestors 'none'; form-action 'self'`.
//
// Design section 8.7 lists no page routes, and `GET /auth/sessions` is
// the JSON route of R-LG-04, so the sessions and devices page is
// `/auth/account` (e2e contract, `e2e/playwright.config.ts` `PAGES`).

import { installTrustedTypesPolicy } from './dom.js';
import { PATHS } from './layout.js';
import { mount as account } from './pages/account.js';
import { mount as invite } from './pages/invite.js';
import { mount as login } from './pages/login.js';
import { mount as magic } from './pages/magic.js';
import { mount as recovery } from './pages/recovery.js';
import { mount as signup } from './pages/signup.js';

const PAGES: Readonly<Record<string, () => void>> = {
  [PATHS.login]: login,
  [PATHS.signup]: signup,
  [PATHS.invite]: invite,
  [PATHS.magic]: magic,
  [PATHS.recovery]: recovery,
  [PATHS.account]: account,
};

/** Mounts the page of the current path. */
function run(): void {
  const page = Object.prototype.hasOwnProperty.call(PAGES, location.pathname)
    ? PAGES[location.pathname]
    : undefined;
  (page ?? login)();
}

installTrustedTypesPolicy();
run();
// A link to the same page with another fragment does not reload it, so
// the page mounts again for the new fragment.
window.addEventListener('hashchange', run);
