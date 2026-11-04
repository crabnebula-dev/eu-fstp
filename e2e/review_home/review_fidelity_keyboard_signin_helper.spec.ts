/**
 * Reviewer test (spec fidelity and test integrity), R-NF-03.
 *
 * `r_nf_03_flows_complete_by_keyboard_alone` (`r-nf-03-auth-and-vault-pages.spec.ts`)
 * enrols by Tab and Enter, then calls `expectSignedIn`. Before the home
 * page landing, that helper only waited for the account page. It now
 * clicks the Account link with the mouse, so the R-NF-03 keyboard flow
 * no longer proves that a person reaches the account page by keyboard.
 *
 * This test enrols by keyboard alone, calls `expectSignedIn` as the
 * R-NF-03 flow does, and asserts that no pointer event reached the page.
 * Every person and text is synthetic.
 */

import { expect, test, type Page } from '@playwright/test';
import { UI, expectSignedIn } from '../playwright.config';
import { DemoPage, newPerson, personOf } from '../navigation/support';

/** Presses Tab until `selector` has focus, as the R-NF-03 spec does. */
async function tabTo(page: Page, selector: string, max = 40): Promise<void> {
  for (let i = 0; i < max; i++) {
    if (await page.evaluate((s) => document.activeElement?.matches(s) === true, selector)) return;
    await page.keyboard.press('Tab');
  }
  throw new Error(`${selector} is not reachable by Tab within ${max} presses`);
}

test('review_fidelity_r_nf_03_keyboard_flow_sign_in_helper_uses_no_pointer', async ({ browser }) => {
  test.setTimeout(180_000);
  const demo = await DemoPage.open(browser);
  const p = await newPerson(browser);
  try {
    await demo.chooseScene('/demo/reset');
    const a1 = personOf(await demo.people(), 'a1', 'reset');
    // Count every trusted pointer or mouse press, across the navigations of this tab.
    await p.context.addInitScript(() => {
      const bump = (e: Event): void => {
        if (!e.isTrusted) return;
        try {
          const n = Number(sessionStorage.getItem('review-pointer') ?? '0');
          sessionStorage.setItem('review-pointer', String(n + 1));
        } catch {
          // no storage: the count stays empty
        }
      };
      for (const t of ['pointerdown', 'mousedown']) window.addEventListener(t, bump, true);
    });
    await p.page.goto(a1.link);
    await tabTo(p.page, UI.invite.register);
    await p.page.keyboard.press('Enter');
    await expectSignedIn(p.page, p.origin);
    const presses = await p.page.evaluate(() => Number(sessionStorage.getItem('review-pointer') ?? '0'));
    expect(presses, 'the R-NF-03 keyboard flow reaches the account page without a pointer').toBe(0);
  } finally {
    await p.context.close();
    await demo.close();
  }
});
