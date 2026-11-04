/**
 * Reactive pages (lane m4/site scope item 2, R-NF-03, ADR-014 "store").
 *
 * r_nf_03_reactive_update: after one real action per role group, the
 * status on the page and the list it belongs to change in place, from
 * the operation's reply or a re-read, without a document load. The
 * person reaches the page, acts and returns to the list by clicking,
 * all in one document.
 *
 * - FSTP coordinator (J5): records the stage 1 close of x on the call
 *   board. The row of x leaves STAGE1 at once (NOTE 3, I-07).
 * - Assigned reviewer (J6): declares no conflict and saves a score. The
 *   content and the sheet appear, and the status of the assignment in
 *   "My assignments" changes (R-CF-02, R-EV-02).
 * - Applicant (J4): starts a proposal, autosaves its title, saves a plan
 *   milestone. The plan status and the total show, and "My
 *   applications" lists the new title (I-21, ADR-006).
 *
 * Every person, amount and text is synthetic.
 */

import { expect } from '@playwright/test';
import { signUp, syntheticEmail, test, VirtualAuthenticator } from '../playwright.config';
import { AUI, ApplicantControl, PLAN_DAYS, fillAndAutosave } from '../applicant/support';
import { REVIEW_UI } from '../review/contract';
import { assignmentOf, proposal, seed } from '../review/support';
import { Document, SITE, accountToHome, clickTo, enrolToHome, suiteCell } from './contract';

// A step that waits on a navigation or an action fails within half a minute, not at the test timeout.
test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

test.describe('R-NF-03 reactive pages', () => {
  test.describe.configure({ timeout: 300_000 });

  /** R-NF-03, NOTE 3: the board row of x changes in place after the stage 1 close. */
  test('r_nf_03_reactive_update_coordinator_stage1_close', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1_scored');
    const { s } = seeded;
    const x = proposal(s, 'x');
    const page = await enrolToHome(person, seeded.cell.origin, s.people.c1.invite_url);
    const doc = await Document.watch(page);
    const board = new RegExp(`^/app/calls/${s.call}/board$`);

    await clickTo(page, page.locator(SITE.workLink('board')).first(), board, 'home to the call board');
    const row = page.locator(REVIEW_UI.board.row(x.id));
    await expect(row).toHaveAttribute('data-state', 'STAGE1');
    await page.locator(REVIEW_UI.board.close(x.id)).click();
    await expect(row, 'the row of x leaves STAGE1 in place').not.toHaveAttribute('data-state', 'STAGE1');
    await expect(row).toHaveAttribute('data-state', /^(STAGE2|NOT_SELECTED)$/);
    await expect(page.locator(REVIEW_UI.board.close(x.id)), 'no close control is left for x').toHaveCount(0);
    await doc.expectSame('the stage 1 close');

    await clickTo(page, page.locator('aside nav a[data-nav="home"]').first(), /^\/app\/$/, 'sidebar home');
    await clickTo(page, page.locator(SITE.workLink('board')).first(), board, 'home to the call board again');
    await expect(page.locator(REVIEW_UI.board.row(x.id))).not.toHaveAttribute('data-state', 'STAGE1');
    await doc.expectSame('the board after the close');
  });

  /** R-NF-03, R-CF-02, R-EV-02: the declaration and the score change the page and the list in place. */
  test('r_nf_03_reactive_update_reviewer_score_save', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const { s } = seeded;
    const a = assignmentOf(s, 'x', 'r1');
    const page = await enrolToHome(person, seeded.cell.origin, s.people.r1.invite_url);
    const doc = await Document.watch(page);

    await clickTo(page, page.locator(SITE.workLink('assignments')).first(), /^\/app\/me\/assignments$/, 'home to my assignments');
    const link = page.locator(`main a[href="/app/assignments/${a}"]`).first();
    const rowOf = () => page.locator('main tr, main li').filter({ has: page.locator(`a[href="/app/assignments/${a}"]`) }).first();
    const before = (await rowOf().innerText()).replace(/\s+/g, ' ').trim();

    await clickTo(page, link, new RegExp(`^/app/assignments/${a}$`), 'assignments to the assignment of x');
    await page.locator(REVIEW_UI.declaration.no).check();
    await page.locator(REVIEW_UI.declaration.submit).click();
    await expect(page.locator(REVIEW_UI.content), 'the content appears in place').toBeVisible();
    await expect(page.locator(REVIEW_UI.score.form), 'the score sheet appears in place').toBeVisible();
    for (const c of s.criteria) await page.locator(REVIEW_UI.score.input(c.id)).fill(String(c.max));
    await page.locator(REVIEW_UI.score.submit).click();
    await expect(page.locator(REVIEW_UI.status), 'the save outcome shows').toBeVisible();
    await doc.expectSame('the declaration and the score');

    await clickTo(page, page.locator(SITE.sidebarLink('/app/me/assignments')).first(), /^\/app\/me\/assignments$/, 'sidebar to my assignments');
    await expect
      .poll(async () => (await rowOf().innerText()).replace(/\s+/g, ' ').trim(), {
        message: 'the assignment of x shows its new status in the list',
      })
      .not.toBe(before);
    await doc.expectSame('my assignments after the score');
  });

  /** R-NF-03, I-21, ADR-006: the start, the autosave and the plan save update the pages in place. */
  test('r_nf_03_reactive_update_applicant_plan_save', async ({ person, request }) => {
    const cell = suiteCell();
    const control = new ApplicantControl(request, cell);
    await control.reset();
    const sc = await control.scenario('OPEN_CALL');
    const page = await person();
    await VirtualAuthenticator.attach(page);
    await signUp(page, control, cell.origin, syntheticEmail('site-reactive'));
    await accountToHome(page, cell.origin);
    const doc = await Document.watch(page);

    await clickTo(page, page.locator(SITE.workLink('open-calls')).first(), /^\/app\/calls$/, 'home to open calls');
    await clickTo(page, page.locator(`main a[href="/app/calls/${sc.call.id}"]`).first(), new RegExp(`^/app/calls/${sc.call.id}$`), 'open calls to the call');
    await page.locator(AUI.call.start).click();
    await page.waitForURL((u) => /^\/app\/proposals\/[^/]+\/workspace$/.test(u.pathname));
    await doc.expectSame('starting a proposal (a form submit)');
    const p = new URL(page.url()).pathname.split('/')[3] ?? '';
    expect(p).not.toBe('');

    const title = 'Synthetic reactive site proposal';
    await fillAndAutosave(page, AUI.workspace.title, title, AUI.workspace.status);
    await clickTo(page, page.locator(`main a[href="/app/proposals/${p}/plan"]`).first(), new RegExp(`^/app/proposals/${p}/plan$`), 'workspace to the plan');
    await page.locator(AUI.plan.description).fill('A synthetic work plan.');
    await page.locator(AUI.plan.amount).fill('1500.50');
    await page.locator(AUI.plan.start).fill(PLAN_DAYS.start);
    await page.locator(AUI.plan.due).fill(PLAN_DAYS.due);
    await page.locator(AUI.plan.save).click();
    await expect(page.locator(AUI.plan.status)).toHaveAttribute('data-status', 'saved');
    await expect(page.locator('main'), 'the saved amount and the total show as server text').toContainText('1500.50');
    await doc.expectSame('the plan save');

    await clickTo(page, page.locator('aside nav a[data-nav="proposals"]').first(), /^\/app\/proposals$/, 'sidebar to my applications');
    await expect(page.locator(AUI.proposals.list), 'my applications lists the autosaved title').toContainText(title);
    await doc.expectSame('my applications after the saves');
  });
});
