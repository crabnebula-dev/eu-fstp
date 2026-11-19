/**
 * Issue 6 M3 (I-10, H-03): the notice of assessment stages the validator
 * dropped, and the coordinator's re-run.
 *
 * - issue6_m3_reviewer_sees_the_dropped_stage_notice: reviewer R1 opens the
 *   assignment of x after the test hook recorded one dropped stage. The
 *   findings panel shows a status notice with the count, the stage and the
 *   code as fixed labels, and no control.
 * - issue6_m3_coordinator_runs_the_assessment_again: coordinator C1 sees the
 *   count on the call board, clicks "Run the assessment of proposal 1001
 *   again", and the dropped stage is gone, because the synthetic assessor
 *   drops nothing.
 *
 * The hook `POST /test/assessor/refuse` exists in the e2e cell only (a test
 * binary, never shipped). Run with `tools/demo/run.sh e2e assess/` against
 * the lane's cell. Every person, proposal and text is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell, watchProblems, type PageProblem } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The seeded proposal x of the review scenes. */
const X = '1001';
/** The call of every seed. */
const CALL = '1';
const SCENE = '/demo/review?stage=stage1';

async function signIn(
  browser: Browser,
  who: RegExp,
): Promise<{ page: Page; problems: () => readonly PageProblem[]; close: () => Promise<void> }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(SCENE);
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

/** The test hook: one dropped stage on x. */
async function dropStage(page: Page): Promise<void> {
  const r = await page.request.post(`${suiteCell().control}/test/assessor/refuse`, {
    data: { proposal: X, stage: 'quality', code: 'score_like' },
  });
  expect(r.ok(), 'the cell records the dropped stage').toBe(true);
}

async function clickHref(page: Page, href: string, path: RegExp, why: string): Promise<void> {
  const link = page.locator(`a[href="${href}"]`).first();
  await expect(link, `${why}: a link to ${href}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
}

test.describe('Issue 6 M3 dropped stages', () => {
  test.describe.configure({ timeout: 240_000 });

  /** I-10, H-03. */
  test('issue6_m3_reviewer_sees_the_dropped_stage_notice', async ({ browser }) => {
    const who = await signIn(browser, DOOR.r1);
    const { page } = who;
    try {
      await dropStage(page);
      await page.reload();
      await settle(page);
      const work = page.locator('#home-work a[data-work="assignment"], #home-work a[data-work="assignments"]').first();
      await expect(work, 'R1 has review work').toBeVisible();
      await work.click();
      await settle(page);
      if (/^\/app\/me\/assignments$/.test(new URL(page.url()).pathname)) {
        await page.locator('#assignments-table a[href^="/app/assignments/"]').first().click();
        await settle(page);
      }
      await page.waitForURL((u) => /^\/app\/assignments\/\d+$/.test(u.pathname));
      const none = page.getByRole('radio', { name: 'No, I have no conflict of interest' });
      if (await none.isVisible()) {
        await none.check();
        await page.getByRole('button', { name: 'Record my declaration' }).click();
        await settle(page);
      }
      const notice = page.locator('#findings-refused');
      await expect(notice, 'the notice').toBeVisible();
      await expect(notice).toHaveAttribute('role', 'status');
      await expect(notice).toContainText('One check of the AI assessor was dropped');
      await expect(notice).toContainText('Quality assessment');
      await expect(notice).toContainText('code: score_like');
      await expect(notice.locator('button'), 'a reviewer has no re-run control').toHaveCount(0);
      expect(who.problems(), 'no CSP violation or console error').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** I-10, H-03. */
  test('issue6_m3_coordinator_runs_the_assessment_again', async ({ browser }) => {
    const who = await signIn(browser, DOOR.c1);
    const { page } = who;
    try {
      await dropStage(page);
      await clickHref(page, `/app/calls/${CALL}/board`, new RegExp(`^/app/calls/${CALL}/board$`), 'home');
      const row = page.locator(`#findings-status tr[data-findings-proposal="${X}"]`);
      await expect(row).toContainText('One check was dropped.');
      await row.getByRole('button', { name: `Run the assessment of proposal ${X} again` }).click();
      await expect(row, 'the dropped stage is gone after the run').not.toContainText('was dropped');
      expect(who.problems(), 'no CSP violation or console error').toEqual([]);
    } finally {
      await who.close();
    }
  });
});
