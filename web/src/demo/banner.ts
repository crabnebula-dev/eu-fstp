// The "Demo sign-in" notice in the top bar (lane m4/site scope item 8).
// Test only: `fstp-e2e-cell` serves the demo modules on a cell started
// with `--demo-signin`, and no shipped cell serves them (layering rule
// A9). It has no effect on import; `notice.ts` and `account.ts` call it.

import { h } from '../auth/dom.js';
import { createI18n } from '../auth/i18n.js';
import { DEMO_EN, type DemoMessageId } from './messages.en.js';

const i18n = createI18n<DemoMessageId>(DEMO_EN);

/** Puts the notice in every top bar that lacks it. */
export function showNotice(): void {
  for (const bar of Array.from(document.querySelectorAll('header .topbar'))) {
    if (bar.querySelector('.demo-notice') === null) {
      bar.append(h('span', { class: 'badge badge--warning demo-notice', role: 'note' }, [i18n.label('notice.text')]));
    }
  }
}
