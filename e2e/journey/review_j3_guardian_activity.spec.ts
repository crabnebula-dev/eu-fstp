/**
 * Review of lane j3 (leaks and markup safety; the click-through rule).
 *
 * - review_j3_o60_guardian_reaches_the_activity_log_by_clicking: the
 *   guardian of the IRC_REVIEW_MINOR applicant scene is a reader of the
 *   activity log (design 02 "Audience": guardians see their own consent
 *   steps, O-60; R-JV-03). The `proposal.diary` read gives the guardian
 *   their guardian step. The guardian must reach that log by clicking
 *   from sign-in: from the home page, or from the guardian page the home
 *   page links to. Neither page holds a link to the activity log.
 *
 * Synthetic data only. Run with `tools/demo/run.sh e2e journey/review_j3`.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { FrontDoor, suiteCell, watchProblems, type PageProblem } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The guardian of the minor lead's proposal (`scenario.rs` `GUARDIAN`). */
const GUARDIAN = /synthetic-guardian-[0-9a-f]+@e2e\.invalid/;

async function signIn(browser: Browser, scene: string, who: RegExp): Promise<{ page: Page; problems: () => readonly PageProblem[]; close: () => Promise<void> }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(scene);
  const href = await door.signIn(who).getAttribute('href');
  await door.close();
  expect(href, `the front door offers "Sign in as" for ${who.source}`).not.toBeNull();
  const context = await browser.newContext();
  const watch = await watchProblems(context);
  const page = await context.newPage();
  await page.goto(new URL(href ?? '', cell.control).href);
  await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
  await settle(page);
  return { page, problems: watch.problems, close: () => context.close() };
}

test.describe('review j3: guardian click-through', () => {
  test.describe.configure({ timeout: 180_000 });

  /** O-60, R-JV-03, the click-through rule. */
  test('review_j3_o60_guardian_reaches_the_activity_log_by_clicking', async ({ browser }) => {
    const who = await signIn(browser, '/demo/applicant?at=IRC_REVIEW_MINOR', GUARDIAN);
    const { page } = who;
    try {
      const activity = 'main a[href^="/app/proposals/"][href$="/activity"]';
      const onHome = await page.locator(activity).count();

      // The guardian's work item on the home page leads to the guardian page.
      const guardianLink = page.locator('main a[href^="/app/proposals/"][href$="/guardian"]').first();
      await expect(guardianLink, 'the home page links the guardian page').toBeVisible();
      const guardianHref = (await guardianLink.getAttribute('href')) ?? '';
      const proposal = /^\/app\/proposals\/(\d+)\/guardian$/.exec(guardianHref)?.[1] ?? '';
      expect(proposal, 'the guardian page names a proposal').not.toBe('');
      await guardianLink.click();
      await page.waitForURL((u) => u.pathname === guardianHref);
      await settle(page);
      const onGuardianPage = await page.locator(activity).count();

      // The log holds the guardian's own step, so it is the guardian's work.
      await page.goto(new URL(`/app/proposals/${proposal}/activity`, page.url()).href);
      await settle(page);
      const steps = page.locator('main ol.diary > li').filter({ hasText: 'Guardian step' });
      await expect(steps, 'the read gives the guardian their step (O-60)').not.toHaveCount(0);

      expect(
        onHome + onGuardianPage,
        'click-through rule: the guardian reaches the activity log from the home page or the guardian page',
      ).toBeGreaterThan(0);
    } finally {
      await who.close();
    }
  });
});
