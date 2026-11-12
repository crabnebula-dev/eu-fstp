/**
 * The hardship scene `HARDSHIP` by clicking from the demo sign-in
 * (R-PR-04, I-86, the demo click-through rule). The lead has filed a hardship
 * request through the real operations. Finance verifies the evidence on
 * the synthetic vault page. The vault holds the fact, the platform holds a
 * reference only. Every person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { Seat, WHO, X, chooseGrantScene } from './support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** Follows the link of `selector` and waits for its page. */
async function click(page: Page, selector: string, path: RegExp): Promise<void> {
  const link = page.locator(selector).first();
  await expect(link, `the page offers ${selector}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await expect(page.locator('main h1').first()).toBeVisible();
}

/** Presses the vault button of a grant page and finishes on the vault origin page. */
async function throughVault(page: Page, button: string, done: string): Promise<void> {
  await page.locator(button).click();
  await page.waitForURL((u) => u.pathname === '/r');
  const action = page.locator('#vault-action');
  await expect(action).toBeVisible();
  await action.click();
  await expect(page.locator(done)).toBeVisible();
}

test.describe('hardship scene', () => {
  test.describe.configure({ timeout: 300_000 });

  test('r_pr_04_lead_sees_the_hardship_request_and_files_evidence', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'HARDSHIP');
    const lead = await Seat.signIn(browser, cell, WHO.lead);
    const page = lead.page;
    await click(page, '#home-work a[data-work="grant"]', new RegExp(`/app/grants/${X}$`));
    await click(page, `a[href="/app/grants/${X}/payments"]`, /\/payments$/);
    await expect(page.locator('#pay-table')).toContainText(/hardship/i);
    await page.goBack();
    await throughVault(page, '#grant-hardship-submit', '#vault-done');
    await lead.close();
  });

  test('r_pr_04_finance_verifies_the_hardship_evidence_on_the_vault_page', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'HARDSHIP');
    const finance = await Seat.signIn(browser, cell, WHO.finance);
    const page = finance.page;
    await click(page, '#home-work a[data-work="operations"]', /\/app\/operations$/);
    await page.goto(`${cell.origin}/app/grants/${X}`);
    await expect(page.locator('main h1').first()).toBeVisible();
    await throughVault(page, '#grant-hardship-verify', '#vault-done');
    await finance.close();
  });
});
