/**
 * The team and member pages and the display name, by clicking from
 * sign-in (SA-11, Daniel 2026-11-15 night; the click-through rule: each
 * person reaches their work by clicking from sign-in).
 *
 * The programme set-up scene holds programme manager M1 on a draft
 * programme, and tenant admins A1 and A2 of an active organisation.
 *
 * - i86_sa11_programme_manager_clicks_from_home_to_the_team_page: M1
 *   clicks "Team of programme N" on the home page and sees its own role.
 * - i86_sa11_tenant_admin_reaches_team_and_members_and_sets_a_display_name:
 *   A2 clicks from home to the team page, then to the member page, sets a
 *   display name on the account page, and finds it on the member page.
 *
 * The sign-in link is the one page each test opens by URL. Run with
 * `tools/demo/run.sh e2e admin/team.spec.ts` against the demo. Every
 * person, address and name is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell } from '../site/contract';

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

/** Clicks the first home link to a team page and waits for the page. */
async function homeToTeam(page: Page): Promise<void> {
  await page.locator('main').getByRole('link', { name: /^Team of programme \d+$/ }).first().click();
  await page.waitForURL((u) => /^\/app\/programmes\/\d+\/team$/.test(u.pathname));
  await settle(page);
  await expect(page.locator('h1')).toHaveText('Team');
  await expect(page.locator('#team-rows')).toBeVisible();
}

test.describe('team and member pages', () => {
  test.describe.configure({ timeout: 300_000 });

  /** SA-11, I-86, SA-09: the manager reaches the team page from home. */
  test('i86_sa11_programme_manager_clicks_from_home_to_the_team_page', async ({ browser }) => {
    const m1 = await signIn(browser, DOOR.m1);
    try {
      await homeToTeam(m1.page);
      const own = m1.page.locator('#team-rows tr[data-role="programme_manager"]');
      await expect(own.first()).toBeVisible();
      // The manager may invite, and is offered no grant, end or reinstatement.
      await expect(m1.page.locator('#team-invite-form')).toBeVisible();
      await expect(m1.page.locator('#team-rows [data-action]')).toHaveCount(0);
      // No applicant is ever listed.
      await expect(m1.page.locator('#team-rows tr[data-role^="applicant"]')).toHaveCount(0);
    } finally {
      await m1.close();
    }
  });

  /** SA-11, I-86, I-78: a tenant admin reaches both pages and names itself on the account page. */
  test('i86_sa11_tenant_admin_reaches_team_and_members_and_sets_a_display_name', async ({ browser }) => {
    const a2 = await signIn(browser, A2);
    const page = a2.page;
    try {
      // Home, then the team page of the programme.
      await homeToTeam(page);
      await expect(page.locator('#team-rows tr[data-role="programme_manager"]').first()).toBeVisible();
      await expect(page.locator('#team-rows [data-action="end"]').first()).toBeVisible();

      // Home again, then the member page from the navigation.
      await page.locator('a[data-nav="members"]').first().click();
      await page.waitForURL((u) => u.pathname === '/app/admin/members');
      await settle(page);
      await expect(page.locator('h1')).toHaveText('Members');
      await expect(page.locator('#members-rows')).toBeVisible();

      // The account page: set a display name.
      await page.locator('a[data-nav="account"]').first().click();
      await page.waitForURL((u) => u.pathname === '/auth/account');
      await expect(page.locator('#display-name-section')).toBeVisible();
      await page.locator('#display-name').fill('Synthetic Admin A2');
      await page.locator('#display-name-save').click();
      await expect(page.locator('#account-status')).toContainText('Your display name is saved.');

      // Back to the member page, by clicking: the name is shown there.
      await page.locator('a[data-nav="members"]').first().click();
      await page.waitForURL((u) => u.pathname === '/app/admin/members');
      await settle(page);
      await expect(page.locator('#members-rows')).toContainText('Synthetic Admin A2');
    } finally {
      await a2.close();
    }
  });
});
