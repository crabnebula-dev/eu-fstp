// The notice of a demo sign-in session on every `/app/` page (lane
// m4/site scope item 8). Test only: `fstp-e2e-cell` adds this module to
// the `/app/` shell of a session that its demo sign-in opened, on a cell
// started with `--demo-signin`. No shipped cell serves it (layering rule
// A9).
//
// - The top bar says "Demo sign-in", so nobody mistakes the session for
//   the real flow.
// - The step-up dialog stays, so the demo shows where the platform asks
//   for it. Its confirm button reads "Confirm" and posts
//   `{"challenge_id", "demo": true}` to `/auth/stepup` instead of running
//   the passkey ceremony. The cell records the step-up for a demo session
//   only, and the page retries the command as after a passkey, so every
//   other guard still runs. Escape and Cancel still cancel.

import { post, ok } from '../auth/api.js';
import { createI18n } from '../auth/i18n.js';
import { showNotice } from './banner.js';
import { DEMO_EN, type DemoMessageId } from './messages.en.js';

const i18n = createI18n<DemoMessageId>(DEMO_EN);

/** The event the step-up dialog takes as a proof recorded by other means. */
const PROVED = 'fstp-stepup-proved';

/** Posts the demo step-up of the open dialog `d`, then lets the dialog settle. */
async function confirm(d: HTMLDialogElement, button: HTMLElement): Promise<void> {
  const error = d.querySelector('#stepup-error');
  const id = d.getAttribute('data-challenge') ?? '';
  if (button.getAttribute('aria-busy') === 'true' || id === '') {
    return;
  }
  button.setAttribute('aria-busy', 'true');
  try {
    const r = await post('/auth/stepup', { challenge_id: id, demo: true });
    if (ok(r)) {
      d.dispatchEvent(new CustomEvent(PROVED));
    } else if (error !== null) {
      error.textContent = i18n.label('stepup.failed');
    }
  } finally {
    button.removeAttribute('aria-busy');
  }
}

/** Turns the step-up dialog, once it exists, into the demo confirmation. */
function stepUp(): void {
  const d = document.getElementById('stepup');
  if (!(d instanceof HTMLDialogElement) || d.getAttribute('data-demo') === 'true') {
    return;
  }
  const button = d.querySelector('#stepup-confirm');
  if (!(button instanceof HTMLElement)) {
    return;
  }
  d.setAttribute('data-demo', 'true');
  button.textContent = i18n.label('stepup.confirm');
  const intro = d.querySelector('#stepup-intro');
  if (intro !== null) {
    intro.textContent = i18n.label('stepup.intro');
  }
  // A capture listener on the button runs before the page's own, which
  // would start the passkey ceremony.
  button.addEventListener(
    'click',
    (e) => {
      e.stopImmediatePropagation();
      e.preventDefault();
      void confirm(d, button);
    },
    true,
  );
}

function watch(): void {
  showNotice();
  stepUp();
}

watch();
new MutationObserver(watch).observe(document.body, { childList: true, subtree: true });
