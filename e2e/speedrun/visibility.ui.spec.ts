/**
 * The grantee visibility screen of M9 lane P2, by clicking from the demo
 * sign-in (the demo click-through rule). The lead of grant x starts at
 * the home page `/app/`, opens the grant from its Home card, follows the
 * "Public visibility" link, saves a funded choice and withdraws it. The
 * public funded page of the programme follows each change on the next
 * request.
 *
 * Covers R-PB-02, R-PB-03, I-43 and R-NF-03. Every person and text is
 * synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { Seat, WHO, X, chooseGrantScene } from './support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

const TITLE = 'Synthetic Harbour Sensor Network';

async function onPage(page: Page, path: RegExp): Promise<void> {
  await page.waitForURL((u) => path.test(u.pathname));
  await expect(page.locator('main h1').first()).toBeVisible();
}

async function click(page: Page, selector: string, path: RegExp): Promise<void> {
  const link = page.locator(selector).first();
  await expect(link, `the page offers ${selector}`).toBeVisible();
  await link.click();
  await onPage(page, path);
}

test.describe('grantee visibility', () => {
  test.describe.configure({ timeout: 300_000 });

  test('r_pb_02_lead_sets_and_withdraws_the_public_choice_by_clicking', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'IN_EXECUTION');
    const lead = await Seat.signIn(browser, cell, WHO.lead);
    const page = lead.page;
    await click(page, '#home-work a[data-work="grant"]', new RegExp(`/app/grants/${X}$`));
    await click(page, `a[href="/app/grants/${X}/visibility"]`, new RegExp(`/app/grants/${X}/visibility$`));
    await expect(page.locator('#grant-visibility-note-platform')).toBeVisible();
    await expect(page.locator('#grant-visibility-funded-none')).toBeVisible();

    await page.locator('#grant-visibility-funded-level-full').check();
    await page.locator('#grant-visibility-funded-title').fill(TITLE);
    await page.locator('#grant-visibility-funded-summary').fill('A synthetic public summary written by the grantee.');
    await page.locator('#grant-visibility-funded-grantee').fill('Synthetic Harbour Lab');
    await page.locator('#grant-visibility-funded-save').click();
    await expect(page.locator('#page-status')).toContainText(/choice is saved/i);
    const effective = page.locator('#grant-visibility-funded-effective');
    await expect(effective).toBeVisible();
    // The demo programme allows Full for funded grants (P-50).
    await expect(effective).toHaveAttribute('data-effective', 'full');

    // The public funded page reads the choice on the next request (I-43).
    const visitor = await browser.newContext();
    const pub = await visitor.newPage();
    await pub.goto(`${cell.origin}/p/1/funded`);
    await expect(pub.locator('main')).toContainText(TITLE);
    await expect(pub.locator('main')).toContainText('Synthetic Harbour Lab');

    await page.locator('#grant-visibility-funded-withdraw').click();
    await expect(page.locator('#page-status')).toContainText(/withdrawn/i);
    await expect(page.locator('#grant-visibility-funded-none')).toBeVisible();
    await pub.goto(`${cell.origin}/p/1/funded`);
    await expect(pub.locator('main')).not.toContainText(TITLE);
    await visitor.close();
    await lead.close();
  });
});
