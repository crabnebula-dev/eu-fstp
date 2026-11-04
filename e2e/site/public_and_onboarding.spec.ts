/**
 * Public pages without script, and the onboarding Channels step (lane
 * m4/site scope items 6 and 7).
 *
 * - r_pb_04_public_pages_without_script (R-PB-04, R-JV-06): with
 *   JavaScript disabled, the public open calls page that the demo front
 *   door links shows its h1 and the seeded open call, and the call page
 *   it links shows the call title as its h1 and the call's content. No
 *   public page holds a script element.
 * - p32_onboarding_email_only (P-32; WhatsApp B-03 and Matrix B-05
 *   deferred): the onboarding Channels step offers email and no WhatsApp
 *   or Matrix control, and it still saves as validated.
 *
 * Every person, call and text is synthetic.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { ApplicantControl } from '../applicant/support';
import { APP, ONBOARDING_STEPS, ONBOARDING_UI } from '../creator/contract';
import { cellA, fillOnboardingStep, firstAdmin, saveOnboardingStep } from '../creator/support';
import { FrontDoor, SITE, suiteCell } from './contract';

// A step that waits on a navigation or an action fails within half a minute, not at the test timeout.
test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

test.describe('R-PB-04 public pages', () => {
  /**
   * R-PB-04, R-JV-06: the public calls list and a call page render
   * their h1 and content with scripts off.
   */
  test('r_pb_04_public_pages_without_script', async ({ browser, request }) => {
    const cell = suiteCell();
    const control = new ApplicantControl(request, cell);
    await control.reset();
    const s = await control.scenario('OPEN_CALL');

    const door = await FrontDoor.open(browser, cell);
    let href: string;
    try {
      const link = door.page.locator(SITE.demo.publicCalls);
      await expect(link, 'the demo front door links the public open calls page').toHaveCount(1);
      href = (await link.getAttribute('href')) ?? '';
    } finally {
      await door.close();
    }
    const u = new URL(href, cell.control);
    expect(u.origin, 'the public open calls page is on the cell origin').toBe(cell.origin);

    const context = await browser.newContext({ javaScriptEnabled: false });
    try {
      const page = await context.newPage();
      const list = await page.goto(u.href);
      expect(list?.status(), 'the public open calls page answers 200').toBe(200);
      await expect(page.locator('main h1')).toHaveText(/\S/);
      await expect(page.locator('main'), 'the list names the open call').toContainText(s.call.title);
      expect(await page.locator('script').count(), 'R-PB-04: no script on the public list').toBe(0);
      await expect(page.locator('aside.sidebar'), 'public pages have no sidebar').toHaveCount(0);

      const callLink = page.locator('main a', { hasText: s.call.title }).first();
      await expect(callLink, 'the list links the call page').toBeVisible();
      await callLink.click();
      await page.waitForLoadState('load');
      expect(new URL(page.url()).origin).toBe(cell.origin);
      await expect(page.locator('main h1'), 'the call page names the call').toHaveText(s.call.title);
      for (const amount of s.call.amounts) {
        await expect(page.locator('main'), `the call page shows ${amount} as server text`).toContainText(amount);
      }
      expect(await page.locator('script').count(), 'R-PB-04: no script on the call page').toBe(0);
    } finally {
      await context.close();
    }
  });
});

test.describe('P-32 onboarding channels', () => {
  test.describe.configure({ timeout: 600_000 });

  /** P-32: email is the one channel the Channels step offers. */
  test('p32_onboarding_email_only', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1 } = await firstAdmin(person, control);
    const page = a1.page;
    for (const step of ONBOARDING_STEPS) {
      if (step === 'channels') break;
      await page.goto(`${origin}${APP.onboarding(step)}`);
      await fillOnboardingStep(page, step);
      await saveOnboardingStep(page, 'validated');
    }
    await page.goto(`${origin}${APP.onboarding('channels')}`);
    const form = page.locator(ONBOARDING_UI.form);
    await expect(form).toHaveCount(1);
    await expect(page.locator('main'), 'the Channels step names email as the channel').toContainText(/\bemail\b/i);

    const controls = await page.locator('main').evaluate((m) =>
      Array.from(m.querySelectorAll('input, select, textarea, button, [role="switch"], [role="checkbox"]')).map((c) => {
        const id = c.getAttribute('id') ?? '';
        const label = id === '' ? '' : (document.querySelector(`label[for="${CSS.escape(id)}"]`)?.textContent ?? '');
        return [id, c.getAttribute('name') ?? '', c.getAttribute('aria-label') ?? '', label, c.closest('label')?.textContent ?? ''].join(' ');
      }),
    );
    expect(
      controls.filter((c) => /whatsapp|matrix/i.test(c)),
      'P-32: no WhatsApp or Matrix control on the Channels step',
    ).toEqual([]);
    const labels = await page.locator('main label').allInnerTexts();
    expect(labels.filter((l) => /whatsapp|matrix/i.test(l)), 'P-32: no WhatsApp or Matrix label').toEqual([]);

    await saveOnboardingStep(page, 'validated');
  });
});
