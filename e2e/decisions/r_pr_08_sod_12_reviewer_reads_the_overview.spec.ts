/**
 * Decided by Daniel on 2026-11-13 (`docs/handoff/m5-ui.md`): the assigned
 * reviewer reads the grant overview after NEGOTIATION, for the line review
 * of payment requests (R-PR-08, SoD-12). Operations offers a funder
 * reports link only to a person whose `report.list` admits them, so the
 * reviewer R1 sees none (R-RP-03, R-AC-01).
 *
 * R1 starts at the demo sign-in and follows links only (R-NF-03). Every
 * person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { Seat, WHO, X, chooseGrantScene } from '../speedrun/support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

async function click(page: Page, selector: string, path: RegExp): Promise<void> {
  const link = page.locator(selector).first();
  await expect(link, `the page offers ${selector}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await expect(page.locator('main h1').first()).toBeVisible();
}

test.describe('the assigned reviewer after NEGOTIATION', () => {
  test.describe.configure({ timeout: 300_000 });

  test('r_pr_08_sod_12_reviewer_reaches_the_overview_from_the_line_review', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'UNDER_REVIEW');
    const r1 = await Seat.signIn(browser, cell, WHO.reviewer);
    const page = r1.page;
    await click(page, '#home-payment-review a[data-work="operations"]', /\/app\/operations$/);
    // R-RP-03, R-AC-01: report.list refuses R1, so Operations offers no funder reports link.
    await expect(page.locator('a[href$="/reports"]')).toHaveCount(0);
    await click(page, 'ul[data-task="review"] li a', new RegExp(`/app/grants/${X}/payments/\\d+$`));
    await expect(page.locator('#pay-status')).toHaveAttribute('data-status', 'UNDER_REVIEW');
    await click(page, '#pay-reviewer-grant', new RegExp(`/app/grants/${X}$`));
    await expect(page.locator('#grant-state')).toHaveAttribute('data-state', 'IN_EXECUTION');
    // The reviewer reads no contract and no payment list, so the page offers Operations instead.
    await expect(page.locator('#grant-reviewer-operations a')).toBeVisible();
    await expect(page.locator(`a[href="/app/grants/${X}/contract"]`)).toHaveCount(0);
    await expect(page.locator(`a[href="/app/grants/${X}/payments"]`)).toHaveCount(0);
    await r1.close();
  });
});
