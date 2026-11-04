// The notice of a demo sign-in session on the M3 account page
// `/auth/account` (lane m4/site scope item 8). Test only: `fstp-e2e-cell`
// adds this module to the account page of a session that its demo
// sign-in opened, on a cell started with `--demo-signin`. No shipped cell
// serves it (layering rule A9).
//
// The top bar says "Demo sign-in". The page's own step-up stays the
// passkey ceremony, so it is not changed here: a demo account holds no
// passkey, so removing a passkey or ending a session on this page is not
// part of the demo (`docs/handoff/m4-demo.md`).

import { showNotice } from './banner.js';

showNotice();
new MutationObserver(showNotice).observe(document.body, { childList: true, subtree: true });
