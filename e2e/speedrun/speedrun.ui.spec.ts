/**
 * The speedrun through the post-grant screens of lane m5/ui
 * (`docs/handoff/m5-ui.md`), by clicking from the demo sign-in of each
 * person (M5 design sections 1.2 and 7, the demo click-through rule).
 * Each person starts at the home page `/app/` and follows links only.
 * The wire-level run of the same path is `speedrun.api.spec.ts`.
 *
 * Covers R-NG-03, R-CT-01, R-PR-01, R-RP-03, R-NF-03 (state shown as
 * text beside the formal state, I-96). Every person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { Seat, WHO, X, chooseGrantScene } from './support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** Waits for a client-side navigation to `path` and its `h1`. */
async function onPage(page: Page, path: RegExp): Promise<void> {
  await page.waitForURL((u) => path.test(u.pathname));
  await expect(page.locator('main h1').first()).toBeVisible();
}

/** Follows the link of `selector` from the page the person is on. */
async function click(page: Page, selector: string, path: RegExp): Promise<void> {
  const link = page.locator(selector).first();
  await expect(link, `the page offers ${selector}`).toBeVisible();
  await link.click();
  await onPage(page, path);
}

test.describe('speedrun through the screens', () => {
  test.describe.configure({ timeout: 300_000 });

  test('ui_lead_reaches_grant_contract_and_payments', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'UNDER_REVIEW');
    const lead = await Seat.signIn(browser, cell, WHO.lead);
    const page = lead.page;
    await click(page, '#home-work a[data-work="grant"]', new RegExp(`/app/grants/${X}$`));
    await expect(page.locator('#grant-state')).toHaveAttribute('data-state', /IN_EXECUTION/);
    await click(page, `a[href="/app/grants/${X}/contract"]`, /\/contract$/);
    await expect(page.locator('#contract-status')).toContainText(/effective/i);
    await page.goBack();
    await click(page, `a[href="/app/grants/${X}/payments"]`, /\/payments$/);
    await expect(page.locator('#pay-table')).toBeVisible();
    await lead.close();
  });

  test('ui_programme_manager_and_finance_reach_operations', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'PAID');
    for (const who of [WHO.pm, WHO.finance, WHO.releaser, WHO.signatory, WHO.auditor]) {
      const seat = await Seat.signIn(browser, cell, who);
      await click(seat.page, '#home-work a[data-work="operations"]', /\/app\/operations$/);
      await seat.close();
    }
    const pm = await Seat.signIn(browser, cell, WHO.pm);
    await click(pm.page, '#home-work a[data-work="grants"]', /\/app\/grants$/);
    await click(pm.page, `a[href="/app/grants/${X}"]`, new RegExp(`/app/grants/${X}$`));
    await pm.close();
  });

  /**
   * R-NG-03: the reviewer reaches the grants list from the home page, then
   * the grant under "Grants you review". The overview is refused to a
   * reviewer, so the page reads `grant.determination_view` and shows the
   * determination form (M5 reads follow-up, `docs/handoff/m5-ui.md`).
   */
  test('ui_reviewer_reaches_the_grants_list', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'NEGOTIATION_READY');
    const r1 = await Seat.signIn(browser, cell, WHO.reviewer);
    await click(r1.page, '#home-work a[data-work="grants"]', /\/app\/grants$/);
    await click(r1.page, `a[href="/app/grants/${X}"]`, new RegExp(`/app/grants/${X}$`));
    await expect(r1.page.locator('#grant-determine-form')).toBeVisible();
    await r1.close();
  });

  test('ui_report_approver_reaches_the_funder_reports', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'ALL_CLOSED');
    const rep = await Seat.signIn(browser, cell, WHO.reportApprover);
    await click(rep.page, 'aside nav a[href="/app/operations"]', /\/app\/operations$/);
    await rep.page.goto(`${cell.origin}/app/programmes/1/reports`);
    await expect(rep.page.locator('#ops-reports-table')).toBeVisible();
    await expect(rep.page.locator('#ops-reports-table')).toContainText(/approved/i);
    await rep.close();
  });
});
