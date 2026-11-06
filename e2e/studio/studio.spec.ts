/**
 * The Planning Studio against `fstp-e2e-cell` (lane studio;
 * `SPEC/12-journey-ui.md` section 8.2; `docs/design/05-programme-staff-studio.md`;
 * the click-through rule: each person reaches their work by clicking from
 * sign-in).
 *
 * - r_pg_01_programme_manager_walks_the_studios_and_sees_the_report: the
 *   demo programme manager M1 signs in with one click and clicks
 *   "Programme set-up" on the home page. The page groups the 11 creator
 *   steps under the five plain headings, each with its studio name
 *   (R-PG-01). M1 clicks through every step the report opens, each step
 *   page showing the same grouped navigation, and every locked step says
 *   what it waits for. M1 then opens "Approval and publication" and sees
 *   the gate of the final report (I-66), the I-67 approver rule, the
 *   programme's published calls with their state (R-PC-02) and the
 *   return-to-DRAFT note (R-PC-03).
 *
 * Every page reached is checked for console errors and CSP violations.
 * Run with `tools/demo/run.sh e2e studio/` against the lane's cell. Every
 * person and text is synthetic.
 */

import { expect, type Locator, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell, watchProblems } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The plain headings of the five studios, then their studio names. */
const GROUPS = [
  'Funder and identity',
  'Eligibility and scope',
  'Evaluation, money and contract',
  'Support, people and communications',
  'Review and approval',
];
const STUDIO_NAMES = [
  'Studio: Surveying the territory',
  'Studio: Border rules',
  'Studio: Instruments',
  'Studio: Support and crew',
  'Studio: Charter seal',
];
const STEPS = ['funder', 'identity', 'eligibility', 'funding', 'evaluation', 'money', 'contract', 'support', 'people', 'comms', 'review'];

/** The grouped step navigation of a studio or creator page. */
function stepsNav(page: Page): Locator {
  return page.getByRole('navigation', { name: 'Set-up steps' });
}

/** Checks the grouping of section 8.2 on the current page. */
async function expectGrouping(page: Page, why: string): Promise<void> {
  const nav = stepsNav(page);
  await expect(nav.locator('h2'), `${why}: the plain headings`).toHaveText(GROUPS);
  await expect(nav.locator('.voyage-label'), `${why}: the studio names`).toHaveText(STUDIO_NAMES);
  const steps = await nav.locator('li[data-step]').evaluateAll((els) => els.map((e) => e.getAttribute('data-step')));
  expect(steps, `${why}: the 11 creator steps in order`).toEqual(STEPS);
}

/** Clicks "Programme set-up of programme ..." on the home page. */
async function toStudio(page: Page): Promise<void> {
  await page.locator('main').getByRole('link', { name: /^Programme set-up of programme / }).first().click();
  await page.waitForURL((u) => /^\/app\/programmes\/\d+\/studio$/.test(u.pathname));
  await settle(page);
  await expect(page.locator('main h1')).toHaveText('Programme set-up');
  await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
}

test.describe('planning studio', () => {
  test.describe.configure({ timeout: 240_000 });

  /** R-PG-01, R-PG-02, R-PG-03, R-PC-02, R-PC-03, I-66, I-67. */
  test('r_pg_01_programme_manager_walks_the_studios_and_sees_the_report', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    await door.chooseScene('/demo/review?stage=stage1');
    const href = await door.signIn(DOOR.m1).getAttribute('href');
    await door.close();
    expect(href, 'the front door offers "Sign in as" for M1').not.toBeNull();
    const context = await browser.newContext();
    const watch = await watchProblems(context);
    const page = await context.newPage();
    try {
      // The sign-in link is the one page this spec opens by URL.
      await page.goto(new URL(href ?? '', cell.control).href);
      await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
      await settle(page);

      await toStudio(page);
      await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
      await expectGrouping(page, 'overview');

      // Each locked step holds no link and says what it waits for.
      const locked = stepsNav(page).locator('li[data-step][data-locked="true"]');
      for (const li of await locked.all()) {
        await expect(li.locator('a')).toHaveCount(0);
        await expect(li).toContainText(/Opens (when step \d+ validates|once the validation report can be read)\./);
      }

      // Walk every open step by clicking it in the step navigation.
      const open = await stepsNav(page)
        .locator('li[data-step]:not([data-locked]) a')
        .evaluateAll((els) => els.map((e) => e.getAttribute('href') ?? ''));
      expect(open.length, 'step 1 opens at least').toBeGreaterThan(0);
      for (const path of open) {
        await stepsNav(page).locator(`a[href="${path}"]`).click();
        await page.waitForURL((u) => u.pathname === path);
        await settle(page);
        await expect(page.locator('main h1')).toHaveText('Programme set-up');
        await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
        await expectGrouping(page, path);
        await expect(stepsNav(page).locator('[aria-current="step"]')).toHaveCount(1);
      }

      // Back to the overview from Home, then the report.
      await page.getByRole('link', { name: 'Home', exact: true }).first().click();
      await page.waitForURL((u) => u.pathname === HOME);
      await settle(page);
      await toStudio(page);
      const gate = await page.locator('#studio-report').getAttribute('data-gate');
      expect(['failures', 'warnings', 'clean', 'unknown']).toContain(gate);
      await page.locator('main').getByRole('link', { name: 'Open approval and publication' }).click();
      await page.waitForURL((u) => /^\/app\/programmes\/\d+\/studio\/approval$/.test(u.pathname));
      await settle(page);
      await expect(page.locator('main h1')).toHaveText('Approval and publication');
      await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
      const activation = page.locator('#seal-activation');
      await expect(activation).toContainText('(I-67)');
      await expect(activation.locator('select')).toHaveCount(0);
      await expect(page.locator('#seal-call-list li[data-state="PUBLISHED"]').first()).toBeVisible();
      await expect(page.locator('#seal-change [data-note="returns-to-draft"]')).toContainText('DRAFT');
      await expect(page.locator('[data-action="approve-call"]')).toHaveCount(1);

      expect(watch.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await context.close();
    }
  });
});
