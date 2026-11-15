/**
 * The applicant reads the application on the proposal page (Daniel,
 * 2026-11-15, night: "on this page i would like to be able to read the
 * application"; lane m4/proposal-read).
 *
 * The e2e cell seeds a proposal in STAGE1 (`POST /test/scenario/applicant
 * {"at":"STAGE1"}`): submitted through the production commands, then
 * admitted. Its lead signs in through the enrolment link, lands on the
 * home page, and reaches the proposal page by clicking only. The page
 * shows the "Application" section: each answer under its question, as
 * text, and the plan the lead recorded (R-SB-01, lane m4/author-reads),
 * read without a refusal (SA-09 rule 7, I-21, R-AC-01).
 *
 * Without a stack manifest the spec fails at its first step with
 * `StackMissing`. Every person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { APP, freshCell, must, seededPerson } from './support';

/** Records each API call of `page` that answered 400 or more. */
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
  test.describe.configure({ timeout: 180_000 });
  test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

  /**
   * I-21, R-AC-01, SA-09 rule 7: the applicant lead clicks from home to
   * the proposal page of a STAGE1 proposal and reads the submitted
   * application, each answer under its question.
   */
  test('i21_applicant_reads_the_application_of_a_stage1_proposal', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('STAGE1');
    const proposal = must(s.proposal, 'proposal');
    const title = must(s.title, 'title');
    const page = await seededPerson(person, origin, must(s.lead, 'lead'));
    // The enrolment lands on the account page. Its Home link opens `/app/`.
    await settle(page);
    if (new URL(page.url()).pathname !== HOME) {
      await page.locator('nav a[data-nav="home"]').first().click();
      await page.waitForURL((u) => u.origin === origin && u.pathname === HOME);
      await settle(page);
    }

    const failed = failedReads(page);
    const own = page.locator(`#home-work a[data-work="proposal"][href="${APP.proposal(proposal)}"]`);
    await expect(own, 'the home page links the lead to the proposal').toHaveCount(1);
    await own.click();
    await page.waitForURL((u) => u.pathname === APP.proposal(proposal));
    await settle(page);
    await expect(page.locator('#proposal-state')).toHaveAttribute('data-state', 'STAGE1');

    const section = page.locator('#proposal-application');
    await expect(section, 'the proposal page shows the application').toBeVisible();
    await expect(section.getByRole('heading', { level: 2, name: 'Application' })).toBeVisible();
    await expect(section.locator('#application-source')).toContainText('as submitted');
    await expect(section.locator('#application-edit'), 'no edit link after submission').toHaveCount(0);
    await expect(section.locator('#application-answers dt')).toHaveText(['Proposal title', 'Neutral summary', 'Narrative']);
    const answers = section.locator('#application-answers dd');
    await expect(answers).toHaveCount(3);
    await expect(answers.first(), 'the lead reads the submitted title').toHaveText(title);
    // Lane m4/author-reads: the plan the lead recorded, read back. The seed
    // records it through the ledger, so the cell holds no work plan text
    // for it, and the page says so rather than show an empty text.
    const plan = section.locator('#application-plan');
    await expect(plan.getByRole('heading', { level: 3, name: 'Plan' })).toBeVisible();
    await expect(plan.locator('#application-plan-tasks > li')).toHaveCount(1);
    await expect(plan.locator('.fstp-plan-milestone')).toHaveCount(1);
    await expect(plan.locator('#application-plan-total')).toContainText('EUR');
    await expect(plan.locator('#application-plan-text-missing')).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(failed(), 'the proposal page reads without a refusal').toEqual([]);
    expect(await alerts(page), 'the proposal page shows no refusal').toEqual([]);
  });
});
