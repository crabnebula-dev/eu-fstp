/**
 * A tenant admin sets a programme up, by clicking from sign-in (SA-12,
 * Daniel 2026-11-15 night; the click-through rule: each person reaches
 * their work by clicking from sign-in).
 *
 * The programme set-up scene holds programme manager M1 on a built
 * SuperSAFE draft, and tenant admins A1 and A2 of an active organisation.
 * A2 holds no Drafting binding and built nothing.
 *
 * - r_pg_02_sa12_tenant_admin_starts_a_draft_and_saves_a_field: A2 clicks
 *   "Programme editor of programme N" on the home page, finds the other
 *   set-up pages linked there, opens the starting point page, applies the
 *   shipped SuperSAFE template and saves a field of step 1. No step
 *   refuses A2 as an actor.
 *
 * The sign-in link is the one page the test opens by URL. Run with
 * `tools/demo/run.sh e2e admin/setup.spec.ts` against the demo. Every
 * person, address and name is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { CREATOR_UI } from '../creator/contract';
import { setFieldValue } from '../creator/support';
import { FrontDoor, suiteCell } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The scene link of the front door. */
const SCENE = '/demo/setup';

/** Tenant admin A2 of the set-up scene (`scenario/setup.rs`). */
const A2 = /Tenant admin A2/;

/** Signs `who` in with one click on the front door of a fresh set-up scene. */
async function signIn(browser: Browser, who: RegExp): Promise<{ page: Page; close: () => Promise<void> }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(SCENE);
  const href = await door.signIn(who).getAttribute('href');
  await door.close();
  expect(href, `the front door offers "Sign in as" for ${who}`).not.toBeNull();
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(new URL(href ?? '', cell.control).href);
  await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
  await settle(page);
  return { page, close: () => context.close() };
}

test.describe('a tenant admin sets a programme up', () => {
  test.describe.configure({ timeout: 300_000 });

  /** SA-12, R-PG-02, R-PG-01, SA-09: A2 reaches the editor from home, starts the draft and saves a field. */
  test('r_pg_02_sa12_tenant_admin_starts_a_draft_and_saves_a_field', async ({ browser }) => {
    const a2 = await signIn(browser, A2);
    const page = a2.page;
    try {
      // Home, then the Programme editor of the draft.
      await page.locator('main').getByRole('link', { name: /^Programme editor of programme \d+$/ }).first().click();
      await page.waitForURL((u) => /^\/app\/programmes\/\d+\/studio$/.test(u.pathname));
      await settle(page);
      await expect(page.locator('#studio-status')).toHaveAttribute('data-status', 'draft');
      // The editor links the other set-up pages.
      await expect(page.locator('#studio-setup-link')).toBeVisible();
      await expect(page.locator('#studio-knock-outs-link')).toBeVisible();
      await expect(page.locator('#studio-people-link')).toBeVisible();

      // The starting point page, then the shipped SuperSAFE template.
      await page.locator('#studio-start').getByRole('link', { name: 'Choose a starting point' }).click();
      await page.waitForURL((u) => /^\/app\/programmes\/\d+\/creator\/start$/.test(u.pathname));
      await settle(page);
      await page.locator('[data-start="template"][data-template="1"]').click();
      await page.waitForURL((u) => /^\/app\/programmes\/\d+\/creator\/funder$/.test(u.pathname));
      await settle(page);
      await expect(page.locator('#creator-error')).toBeHidden();

      // A field of step 1, saved as A2.
      await setFieldValue(page, 'funder.action_acronym', 'SYNTHETIC-SA12');
      await page.locator(CREATOR_UI.stepSave).click();
      await expect(page.locator(CREATOR_UI.stepStatus)).toHaveAttribute('data-state', 'saved');
      await expect(page.locator('#creator-error')).toBeHidden();
    } finally {
      await a2.close();
    }
  });
});
