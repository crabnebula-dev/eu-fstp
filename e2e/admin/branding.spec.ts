/**
 * The tenant admin's branding and terminology screens (M9 lane P2;
 * R-WL-03, R-WL-05, I-70, I-72).
 *
 * The first tenant admin of the `reset` scene signs in from the demo
 * page and reaches both screens by clicking from Home. A colour pair
 * below the contrast minimum is listed by name and blocks the save. Once
 * every pair passes, the save completes after the step-up. The
 * terminology screen saves one label and offers no field for fixed
 * wording. Every name and colour here is synthetic.
 */

import { expect, test } from '@playwright/test';
import { confirmStepUp } from '../playwright.config';
import { DemoPage, enrolFromLink, expectHome, newPerson, personOf, settle } from '../navigation/support';

test('r_wl_03_i70_i72_tenant_admin_sets_branding_and_terminology_by_clicking', async ({ browser }) => {
  test.setTimeout(240_000);
  const demo = await DemoPage.open(browser);
  let link = '';
  try {
    await demo.chooseScene('/demo/reset');
    link = personOf(await demo.people(), 'a1', 'reset').link;
  } finally {
    await demo.close();
  }
  const p = await newPerson(browser);
  try {
    await enrolFromLink(p, link);
    await expectHome(p, 'a1 in reset');
    const page = p.page;

    // From Home to the branding screen, by clicking.
    await page.locator('a[data-work="branding"]').click();
    await expect(page).toHaveURL(/\/app\/admin\/branding$/);
    await settle(page);
    await page.locator('#branding-name').fill('Synthetic Tenant');
    // I-70: text on the dark brand fill in the brand colour itself fails.
    await page.locator('#branding-dark-on-brand').fill('#3b82f6');
    await page.locator('#branding-check').click();
    await expect(page.locator('#branding-failing li[data-pair="dark.on-brand/brand"]')).toBeVisible();
    await page.locator('#branding-save').click();
    await expect(page.locator('[role="alert"]')).toContainText('Nothing was saved');
    // A dark text on the fill passes, and the save goes through the step-up.
    await page.locator('#branding-dark-on-brand').fill('#0f172a');
    await page.locator('#branding-check').click();
    await expect(page.locator('#branding-pass')).toBeVisible();
    await page.locator('#branding-save').click();
    await confirmStepUp(page);
    await expect(page.locator('#page-status')).toContainText('The brand colours are saved.');

    // Back Home, then to the terminology screen.
    await page.locator('a[data-nav="home"]').first().click();
    await expectHome(p, 'a1 back home');
    await page.locator('a[data-work="terminology"]').click();
    await expect(page).toHaveURL(/\/app\/admin\/terminology$/);
    await settle(page);
    await expect(page.locator('#terminology-journey-node-withdrawn')).toHaveCount(0);
    await page.locator('#terminology-vocab-call').fill('Open round');
    await page.locator('#terminology-save').click();
    await confirmStepUp(page);
    await expect(page.locator('#page-status')).toContainText('The terminology is saved.');
  } finally {
    await p.context.close();
  }
});
