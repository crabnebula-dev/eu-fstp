/**
 * The applicant reads the application on the proposal page (Daniel,
 * 2026-11-15, night: "on this page i would like to be able to read the
 * application"; lane m4/proposal-read).
 *
 * On the demo cell started with `--demo-signin`, the scene "review
 * stage1" holds submitted proposals in STAGE1. The spec chooses that
 * scene on the front door, signs in as a listed applicant lead with one
 * click, and reaches the lead's own proposal from the home page by
 * clicking only. The proposal page shows the "Application" section: each
 * answer under its question, as text, read without a refusal (SA-09 rule
 * 7, I-21, R-AC-01).
 *
 * Without a stack manifest the spec fails at its first step with
 * `StackMissing`. Every person and text is synthetic.
 */

import { expect, test, type Page } from '@playwright/test';
import { FrontDoor, SITE, suiteCell } from '../site/contract';
import { HOME, settle } from '../navigation/support';

/** A seeded applicant lead on the front door (`scenario.rs` `PROPOSALS`). */
const LEAD = /synthetic-lead-[a-z](?:-self)?-[0-9a-f]+@e2e\.invalid/;

/** The proposal page path. */
const PROPOSAL_PATH = /^\/app\/proposals\/(\d+)$/;

/** Records each API read of `page` that answered 400 or more. */
function failedReads(page: Page): () => string[] {
  const failed: string[] = [];
  page.on('response', (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith('/api/') && r.status() >= 400) failed.push(`${r.status()} ${u.pathname}`);
  });
  return () => failed;
}

/** The visible alert texts of the page. */
async function alerts(page: Page): Promise<string[]> {
  return page
    .locator('[role="alert"]')
    .evaluateAll((es) =>
      es
        .filter((e) => (e as HTMLElement).getClientRects().length > 0 && (e.textContent ?? '').trim() !== '')
        .map((e) => (e.textContent ?? '').trim()),
    );
}

test.describe('the application on the proposal page', () => {
  test.describe.configure({ timeout: 240_000 });
  test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

  /**
   * I-21, R-AC-01, SA-09 rule 7: the demo applicant clicks from home to
   * the proposal page of a STAGE1 proposal and reads the submitted
   * application, each answer under its question.
   */
  test('i21_demo_applicant_reads_the_application_of_a_stage1_proposal', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    const leads: string[] = [];
    try {
      await door.chooseScene('/demo/review?stage=stage1');
      const items = door.item(LEAD);
      const n = await items.count();
      expect(n, 'the front door lists an applicant lead in review stage1').toBeGreaterThan(0);
      for (let i = 0; i < n; i++) {
        const href = await items.nth(i).locator(SITE.demo.signIn).getAttribute('href');
        if (href !== null) leads.push(new URL(href, cell.control).href);
      }
    } finally {
      await door.close();
    }
    expect(leads.length, 'each listed lead has a "Sign in as" link').toBeGreaterThan(0);

    // The first lead whose home page leads to a STAGE1 proposal.
    let read = false;
    for (const link of leads) {
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await page.goto(link);
        await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
        await settle(page);
        const own = page.locator('#home-work a[data-work="proposal"]');
        if ((await own.count()) === 0) continue;
        const failed = failedReads(page);
        await own.first().click();
        await page.waitForURL((u) => PROPOSAL_PATH.test(u.pathname));
        await settle(page);
        const state = page.locator('#proposal-state');
        await expect(state).toBeVisible();
        if ((await state.getAttribute('data-state')) !== 'STAGE1') continue;

        const section = page.locator('#proposal-application');
        await expect(section, 'the proposal page shows the application').toBeVisible();
        await expect(section.getByRole('heading', { level: 2, name: 'Application' })).toBeVisible();
        await expect(section.locator('#application-source')).toContainText('as submitted');
        await expect(section.locator('#application-edit'), 'no edit link after submission').toHaveCount(0);
        const questions = section.locator('#application-answers dt');
        const answers = section.locator('#application-answers dd');
        await expect(questions).toHaveText(['Proposal title', 'Neutral summary', 'Narrative']);
        await expect(answers).toHaveCount(3);
        const title = (await answers.first().textContent())?.trim() ?? '';
        expect(title.length, 'the lead reads the submitted title').toBeGreaterThan(0);
        await page.waitForLoadState('networkidle');
        expect(failed(), 'the proposal page reads without a refusal').toEqual([]);
        expect(await alerts(page), 'the proposal page shows no refusal').toEqual([]);
        read = true;
        break;
      } finally {
        await context.close();
      }
    }
    expect(read, 'a demo applicant reached and read a STAGE1 proposal by clicking').toBe(true);
  });
});
