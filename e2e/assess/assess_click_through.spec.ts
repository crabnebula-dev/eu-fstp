/**
 * M7 demo path (design section 7, lanes L-UI and L-DEMO): each person
 * reaches the AI assessment by clicking from the demo sign-in.
 *
 * - r_la_06_applicant_checks_the_draft: the lead of the open call scene
 *   starts a draft, writes it, clicks "Check my draft" and runs the
 *   pre-check. The page states that an AI system reads the draft and that
 *   the assessor is synthetic (R-LA-08). The run lists findings, among
 *   them a completeness finding for the missing team section, and no
 *   score (TH-02). After the one check of the day the button is disabled
 *   and the next instant is shown (P-23, TH-29).
 * - r_la_03_reviewer_marks_findings: committee member R1 of the stage 1
 *   scene opens the assignment of x, sees the assessor findings with the
 *   AI disclosure, agrees with one and disputes another (R-LA-03, I-10).
 * - i10_coordinator_sees_counts_only: coordinator C1 opens the call board
 *   and sees per proposal "Findings pending" or a count, and no
 *   statement (I-10).
 *
 * The cell runs the synthetic assessor in the `fstp-assessor` child; no
 * model API is called. Run with `tools/demo/run.sh e2e assess/` against
 * the lane's cell. Every person, proposal and text is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell, watchProblems, type PageProblem } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The seeded proposal x of the review scenes (`scenario.rs` `PROPOSALS`). */
const X = '1001';
/** The draft z of the DRAFT scene (`scenario.rs` `At::Draft`). */
const Z = '1002';
/** The lead of z on the front door. */
const LEAD_Z = /synthetic-lead-z(?:-self)?-[0-9a-f]+@e2e\.invalid/;
/** The call of every seed. */
const CALL = '1';

/** Signs `who` in from the front door of `scene` and returns their home page. */
async function signIn(
  browser: Browser,
  scene: string,
  who: RegExp,
): Promise<{ page: Page; problems: () => readonly PageProblem[]; close: () => Promise<void> }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(scene);
  const href = await door.signIn(who).getAttribute('href');
  await door.close();
  expect(href, `the front door offers "Sign in as" for ${who.source}`).not.toBeNull();
  const context = await browser.newContext();
  const watch = await watchProblems(context);
  const page = await context.newPage();
  // The sign-in link is the one page this spec opens by URL: the click on
  // "Sign in as", made in a context of the person's own.
  await page.goto(new URL(href ?? '', cell.control).href);
  await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
  await settle(page);
  return { page, problems: watch.problems, close: () => context.close() };
}

/** Clicks the first link whose `href` matches `href` and waits for `path`. */
async function clickHref(page: Page, href: string, path: RegExp, why: string): Promise<void> {
  const link = page.locator(`a[href="${href}"]`).first();
  await expect(link, `${why}: a link to ${href}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
}


test.describe('M7 AI assessment click-through', () => {
  test.describe.configure({ timeout: 240_000 });

  /** R-LA-06, R-LA-08, TH-02, TH-29, I-21. */
  test('r_la_06_applicant_checks_the_draft', async ({ browser }) => {
    const who = await signIn(browser, '/demo/applicant?at=DRAFT', LEAD_Z);
    const { page } = who;
    try {
      const work = page.locator('#home-work a[data-work="proposal"], #home-work a[data-work="proposals"]').first();
      await expect(work, 'the lead has a draft').toBeVisible();
      await work.click();
      await settle(page);
      if (new URL(page.url()).pathname === '/app/proposals') {
        await page.locator(`main a[href="/app/proposals/${Z}"]`).first().click();
        await settle(page);
      }
      await clickHref(page, `/app/proposals/${Z}/workspace`, new RegExp(`^/app/proposals/${Z}/workspace$`), 'proposal page');
      // The draft is the corpus omission item: no team section.
      await expect(page.locator('#ws-narrative')).not.toHaveValue(/Team and experience/);
      await page.locator('#precheck-open').click();
      await page.waitForURL((u) => /^\/app\/proposals\/\d+\/precheck$/.test(u.pathname));
      await settle(page);
      const disclosure = page.locator('#precheck-disclosure');
      await expect(disclosure, 'R-LA-08: the AI disclosure').toContainText('AI system');
      await expect(disclosure, 'the demo names its synthetic assessor').toContainText('Synthetic assessor (demo)');
      await expect(page.locator('#precheck-none')).toBeVisible();
      await expect(page.locator('#precheck-remaining')).toContainText('1 today');

      await page.locator('#precheck-run').click();
      const latest = page.locator('#precheck-latest');
      await expect(latest, 'the run is listed').toBeVisible();
      await expect(latest).toHaveAttribute('data-state', 'done');
      const findings = latest.locator('li.precheck-finding');
      expect(await findings.count(), 'the run has findings').toBeGreaterThan(0);
      await expect(latest.locator('li.precheck-finding[data-kind="completeness"]').first()).toBeVisible();
      await expect(
        latest.locator('li.precheck-finding[data-kind="completeness"] .precheck-element[data-element="team_experience"]'),
        'the missing team section is found',
      ).toContainText('Team and experience');
      const text = (await page.locator('main').innerText()).toLowerCase();
      expect(text.includes('score:'), 'TH-02: no score on the page').toBe(false);
      expect(text.includes('confidence'), 'TH-02: no confidence on the page').toBe(false);

      // P-23: one check a day per proposal, so none is left now.
      await expect(page.locator('#precheck-run')).toBeDisabled();
      await expect(page.locator('#precheck-limit')).toContainText('next check is available');
      expect(who.problems(), 'no CSP violation or console error').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** R-LA-03, R-LA-08, I-10. */
  test('r_la_03_reviewer_marks_findings', async ({ browser }) => {
    const who = await signIn(browser, '/demo/review?stage=stage1', DOOR.r1);
    const { page } = who;
    try {
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
        // R-CF-02: the reviewer declares before reading.
        await none.check();
        await page.getByRole('button', { name: 'Record my declaration' }).click();
        await settle(page);
      }
      const panel = page.locator('#findings');
      await expect(panel, 'the findings panel').toBeVisible();
      await expect(panel.locator('.ai-disclosure')).toContainText('AI system');
      await expect(panel.locator('.ai-disclosure')).toContainText('Synthetic assessor (demo)');
      const items = panel.locator('li.finding');
      expect(await items.count(), 'the assessor left findings').toBeGreaterThan(0);
      const first = items.first();
      const id = await first.getAttribute('data-finding');
      await first.getByRole('button', { name: /^Agree with finding 1$/ }).click();
      await expect(panel.locator(`li.finding[data-finding="${id}"]`)).toHaveAttribute('data-mark', 'Agreed');
      if ((await items.count()) > 1) {
        const second = items.nth(1);
        const id2 = await second.getAttribute('data-finding');
        await second.getByRole('button', { name: /^Dispute finding 2$/ }).click();
        await expect(panel.locator(`li.finding[data-finding="${id2}"]`)).toHaveAttribute('data-mark', 'Disputed');
      }
      const text = (await panel.innerText()).toLowerCase();
      expect(text.includes('confidence'), 'no confidence is shown').toBe(false);
      expect(who.problems(), 'no CSP violation or console error').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** I-10, M7 design section 7. */
  test('i10_coordinator_sees_counts_only', async ({ browser }) => {
    const who = await signIn(browser, '/demo/review?stage=stage1', DOOR.c1);
    const { page } = who;
    try {
      await clickHref(page, `/app/calls/${CALL}/board`, new RegExp(`^/app/calls/${CALL}/board$`), 'home');
      const status = page.locator('#findings-status');
      await expect(status, 'the assessment status').toBeVisible();
      await expect(status.locator('.ai-disclosure')).toContainText('AI system');
      const row = status.locator(`tr[data-findings-proposal="${X}"]`);
      await expect(row).toHaveAttribute("data-findings-status", "ready");
      await expect(row).toContainText(/\d+ findings?|Findings pending/);
      const text = await status.innerText();
      expect(text.includes('treated as data'), 'I-10: no statement reaches the coordinator').toBe(false);
      expect(who.problems(), 'no CSP violation or console error').toEqual([]);
    } finally {
      await who.close();
    }
  });
});
