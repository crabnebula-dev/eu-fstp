/**
 * The programme set-up scene of the demo, by clicking from sign-in
 * (`fstp-e2e-cell` `scenario/setup.rs`; M4 design sections 2.2 J1 and
 * 8.2; the click-through rule: each person reaches their work by
 * clicking from sign-in).
 *
 * - r_pg_01_r_nf_03_m1_clicks_from_sign_in_to_the_review_previews: on
 *   the front door, the presenter chooses the "programme_setup" scene and
 *   signs in as programme manager M1 with one click. M1 clicks
 *   "Programme set-up of programme N" on the home page. The overview
 *   shows all 11 steps validated, none locked (R-PG-01). M1 clicks
 *   "11. Review: validated" and the review page shows the final report
 *   with no failure and its three previews: the Guide for Applicants, the
 *   public programme page and the contract. Each preview holds text from
 *   the draft values, and the contract preview marks each value only a
 *   grant sets (R-PG-01, R-CT-01). Both pages pass the in-house page
 *   structure and contrast checks of design section 8.7 (R-NF-03).
 *
 * The sign-in link is the one page this spec opens by URL. Every page
 * reached is checked for console errors and CSP violations. Run with
 * `tools/demo/run.sh e2e studio/setup_review.spec.ts` against the demo.
 * Every person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { CREATOR_UI } from '../creator/contract';
import { contrastBothThemes, structureProblems } from '../creator/support';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell, watchProblems } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The scene link of the front door. */
const SCENE = '/demo/setup';

/** The 11 creator steps, in order. */
const STEPS = ['funder', 'identity', 'eligibility', 'funding', 'evaluation', 'money', 'contract', 'support', 'people', 'comms', 'review'];

/** The markers of the contract preview for values only a grant sets (`creator_ops.rs` `per_grant`). */
const PER_GRANT = [
  '[proposal: set for each grant]',
  '[granted amount: set for each grant]',
  '[agreed plan version: set for each grant]',
];

/** The marker of a draft field with no value (`creator_ops.rs` `unset`). */
const UNSET = /not set in the draft/;

/** The grouped step navigation of a studio or creator page. */
function stepsNav(page: Page): ReturnType<Page['locator']> {
  return page.getByRole('navigation', { name: 'Set-up steps' });
}

test.describe('programme set-up scene', () => {
  test.describe.configure({ timeout: 300_000 });

  /** R-PG-01, R-PG-02, R-CT-01, R-NF-03, I-66. */
  test('r_pg_01_r_nf_03_m1_clicks_from_sign_in_to_the_review_previews', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    await door.chooseScene(SCENE);
    await expect(door.page.locator('#demo-scene')).toContainText('programme_setup');
    await expect(door.item(DOOR.m1).locator('[data-demo-does]')).toContainText('programme set-up');
    const href = await door.signIn(DOOR.m1).getAttribute('href');
    await door.close();
    expect(href, 'the front door offers "Sign in as" for M1').not.toBeNull();

    const context = await browser.newContext();
    const watch = await watchProblems(context);
    const page = await context.newPage();
    const problems: string[] = [];
    try {
      await page.goto(new URL(href ?? '', cell.control).href);
      await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
      await settle(page);

      // Home, then "Programme set-up of programme N".
      await page.locator('main').getByRole('link', { name: /^Programme set-up of programme \d+$/ }).first().click();
      await page.waitForURL((u) => /^\/app\/programmes\/\d+\/studio$/.test(u.pathname));
      await settle(page);
      await expect(page.locator('main h1')).toHaveText('Programme set-up');
      await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
      await expect(page.locator('#studio-status')).toHaveAttribute('data-status', 'draft');

      // Every step validates, so none is locked and Review opens.
      const items = stepsNav(page).locator('li[data-step]');
      expect(await items.evaluateAll((els) => els.map((e) => e.getAttribute('data-step')))).toEqual(STEPS);
      await expect(stepsNav(page).locator('li[data-step][data-locked]')).toHaveCount(0);
      await expect(stepsNav(page).locator('li[data-step]:not([data-condition="valid"])')).toHaveCount(0);
      await expect(page.locator('#studio-report')).toHaveAttribute('data-gate', 'clean');
      problems.push(...(await structureProblems(page, 'set-up overview')), ...(await contrastBothThemes(page, 'set-up overview')));

      // "11. Review: validated", then the report and the three previews.
      await stepsNav(page).getByRole('link', { name: '11. Review: validated' }).click();
      await page.waitForURL((u) => /^\/app\/programmes\/\d+\/creator\/review$/.test(u.pathname));
      await settle(page);
      await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
      const report = page.locator(CREATOR_UI.report);
      await expect(report).toBeVisible();
      await expect(report.locator('li[data-severity="failure"]')).toHaveCount(0);
      await expect(report.locator('li[data-severity="warning"][data-acknowledged="false"]')).toHaveCount(0);
      await expect(page.locator(CREATOR_UI.requestActivation)).toBeEnabled();

      for (const id of [CREATOR_UI.previewGuide, CREATOR_UI.previewPublic, CREATOR_UI.previewContract]) {
        const region = page.locator(id);
        await expect(region, `${id} shows text`).not.toHaveText('');
        await expect(region, `${id} is available`).not.toContainText('This preview is not available.');
        await expect(region, `${id} reads the built draft`).not.toContainText(UNSET);
      }
      await expect(page.locator(CREATOR_UI.previewGuide)).toContainText('SuperSAFE');
      await expect(page.locator(CREATOR_UI.previewPublic)).toContainText('SuperSAFE');
      const contract = page.locator(CREATOR_UI.previewContract);
      await expect(contract).toContainText('Sub-grant agreement for proposal [proposal: set for each grant]');
      for (const marker of PER_GRANT) {
        await expect(contract, `the contract preview marks ${marker}`).toContainText(marker);
      }
      problems.push(...(await structureProblems(page, 'review')), ...(await contrastBothThemes(page, 'review')));

      expect(problems, 'R-NF-03: structure, names and contrast').toEqual([]);
      expect(watch.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await context.close();
    }
  });
});
