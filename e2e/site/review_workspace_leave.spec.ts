/**
 * Review reproducer (lane m4/site, independent review of 2026-11-04).
 * It fails against the lane's working tree and passes once fixed.
 *
 * i21_review_unsaved_workspace_edit_is_not_dropped_on_in_app_navigation:
 * before the lane, leaving the workspace with an unsaved edit was a
 * document load, and the `beforeunload` guard of `workspace.ts` asked
 * the person first. Links inside `/app/` now render in place, so that
 * guard never runs. `whenLeft` starts one more save and the page goes.
 * When that save fails too, the edit is gone and nothing says so: the
 * failed status and its retry button sit on the page that was left.
 *
 * The cell's workspace save is made to fail with a 503 for this test
 * only, as a network or cell outage would. Every person and text is
 * synthetic.
 */

import { expect } from '@playwright/test';
import { signUp, syntheticEmail, test, VirtualAuthenticator } from '../playwright.config';
import { AUI, ApplicantControl } from '../applicant/support';
import { SITE, accountToHome, suiteCell } from './contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

test.describe('review: leaving the workspace', () => {
  test.describe.configure({ timeout: 240_000 });

  /** I-21, ADR-014: an edit whose save failed is not dropped without a word when the person opens another page. */
  test('i21_review_unsaved_workspace_edit_is_not_dropped_on_in_app_navigation', async ({ person, request }) => {
    const cell = suiteCell();
    const control = new ApplicantControl(request, cell);
    await control.reset();
    const sc = await control.scenario('OPEN_CALL');
    const page = await person();
    await VirtualAuthenticator.attach(page);
    await signUp(page, control, cell.origin, syntheticEmail('site-review-leave'));
    await accountToHome(page, cell.origin);

    await page.locator(SITE.workLink('open-calls')).first().click();
    await page.waitForURL((u) => u.pathname === '/app/calls');
    await page.locator(`main a[href="/app/calls/${sc.call.id}"]`).first().click();
    await page.waitForURL((u) => u.pathname === `/app/calls/${sc.call.id}`);
    await page.locator(AUI.call.start).click();
    await page.waitForURL((u) => /^\/app\/proposals\/[^/]+\/workspace$/.test(u.pathname));
    const workspace = new URL(page.url()).pathname;

    // Every workspace save fails from here on.
    await page.route('**/api/v1/proposals/*/workspace', async (route) => {
      if (route.request().method() === 'PUT') {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"code":"unavailable"}' });
      } else {
        await route.continue();
      }
    });
    await page.locator(AUI.workspace.title).fill('Synthetic title that is not saved');
    await expect(page.locator(AUI.workspace.status)).toHaveAttribute('data-status', 'failed');

    let asked = false;
    page.on('dialog', (d) => {
      asked = true;
      void d.dismiss();
    });
    await page.locator('aside nav a[data-nav="proposals"]').first().click();
    // Give the leave save time to fail, and the page time to say so.
    await page.waitForTimeout(3_000);
    const stayed = new URL(page.url()).pathname === workspace;
    const told = await page
      .locator('[role="alert"], [role="status"]')
      .filter({ hasText: /not saved|could not be saved|unsaved/i })
      .count();
    expect(
      asked || stayed || told > 0,
      'the person is asked, kept on the workspace, or told that the edit was not saved',
    ).toBe(true);
  });
});
