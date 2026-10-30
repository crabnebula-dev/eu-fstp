/**
 * J5, the FSTP coordinator (M4 design section 2.2): intake, declaration,
 * knock-out, assignment, admission, the stage 1 close and notifiable
 * conflicts, in the browser against the e2e cell.
 *
 * - R-CF-02: the coordinator declares per proposal before the knock-out
 *   read, and sees only the title and the neutral summary before that
 *   (Q9).
 * - R-EV-01: a proposal failing any knock-out criterion receives no
 *   further review.
 * - R-CF-03, SoD-10 and SoD-11 (I-34, I-35): the P-39 and proximity
 *   checks show pass or fail only.
 * - I-07, I-08 and NOTE 3 of `state-machine.md`: the coordinator records
 *   the stage 1 close and cannot choose its outcome, which is computed.
 * - R-CF-04: a notifiable conflict produces a draft for the coordinator.
 * - I-17: no identity attribute of an applicant reaches these pages.
 *
 * Page paths and element ids are in `contract.ts`.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { REVIEW_API, REVIEW_PAGES, REVIEW_UI } from './contract';
import {
  apiGet,
  assignmentOf,
  clickWrite,
  expectAccepted,
  expectFieldError,
  expectNoCanary,
  expectRefusal,
  expectState,
  openPage,
  proposal,
  seed,
  signIn,
  watchResponses,
  watchWrites,
} from './support';

test.describe('J5 FSTP coordinator', () => {
  test('r_cf_02_coordinator_declares_before_the_knock_out_read', async ({ person, request }) => {
    const seeded = await seed(request, 'submitted');
    const { cell, s } = seeded;
    const x = proposal(s, 'x');
    const c1 = await signIn(person, seeded, 'c1');
    const responses = watchResponses(c1);

    await openPage(c1, cell.origin, REVIEW_PAGES.intake(s.call));
    await expect(c1.locator(REVIEW_UI.link(REVIEW_PAGES.coordinatorDeclaration(x.id)))).toBeVisible();

    // Before the declaration: title and neutral summary only, and the
    // content route refuses.
    await openPage(c1, cell.origin, REVIEW_PAGES.coordinatorDeclaration(x.id));
    await expect(c1.locator(REVIEW_UI.declaration.title)).toHaveText(x.title);
    await expect(c1.locator(REVIEW_UI.declaration.summary)).toHaveText(x.neutral_summary);
    await expect(c1.locator(REVIEW_UI.content)).toHaveCount(0);
    await expect(c1.locator('body')).not.toContainText(s.content_canary);
    expectRefusal(await apiGet(c1, cell.origin, REVIEW_API.content(x.id)), 'content before declaring');

    // No answer is preset (R-CF-02).
    await expect(c1.locator(REVIEW_UI.declaration.no)).not.toBeChecked();
    await expect(c1.locator(REVIEW_UI.declaration.yes)).not.toBeChecked();
    await c1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(c1, REVIEW_UI.declaration.submit, /\/coordinator-declaration$/)).toBeLessThan(300);

    // After it: the knock-out page shows the content, and the route admits the read.
    await openPage(c1, cell.origin, REVIEW_PAGES.knockOut(x.id));
    await expect(c1.locator(REVIEW_UI.content)).toContainText(s.content_canary);
    expectAccepted(await apiGet(c1, cell.origin, REVIEW_API.content(x.id)), 'content after declaring');
    await expectNoCanary(c1, s.identity_canaries, 'coordinator knock-out page', responses);
  });

  test('r_ev_01_failed_knock_out_makes_the_proposal_ineligible', async ({ person, request }) => {
    const seeded = await seed(request, 'submitted');
    const { cell, s } = seeded;
    const z = proposal(s, 'z');
    const [first, ...rest] = s.knock_out;
    if (first === undefined) throw new Error('the scenario has no P-09 criterion');
    const c1 = await signIn(person, seeded, 'c1');

    await openPage(c1, cell.origin, REVIEW_PAGES.coordinatorDeclaration(z.id));
    await c1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(c1, REVIEW_UI.declaration.submit, /\/coordinator-declaration$/)).toBeLessThan(300);

    await openPage(c1, cell.origin, REVIEW_PAGES.knockOut(z.id));
    const writes = watchWrites(c1, /\/knock-out$/);
    await c1.locator(REVIEW_UI.knockOut.fail(first)).check();
    for (const c of rest) await c1.locator(REVIEW_UI.knockOut.pass(c)).check();
    // A failure without a reason is refused in the page, before any request.
    await c1.locator(REVIEW_UI.knockOut.submit).click();
    await expectFieldError(c1, REVIEW_UI.knockOut.reason);
    expect(writes.seen(), 'no knock-out request without a reason').toBe(0);

    await c1.locator(REVIEW_UI.knockOut.reason).fill('Synthetic: the annex is missing.');
    expect(await clickWrite(c1, REVIEW_UI.knockOut.submit, /\/knock-out$/)).toBeLessThan(300);
    await expectState(c1, 'INELIGIBLE');

    // No further review: the assignment view is closed in INELIGIBLE
    // (`fstp-access` READ_RULES, R-AC-01), so the page offers no
    // assignment and no admission.
    expectRefusal(
      await apiGet(c1, cell.origin, REVIEW_API.assignmentsOf(z.id)),
      'assignment view of an INELIGIBLE proposal',
      'R-AC-01',
    );
    await openPage(c1, cell.origin, REVIEW_PAGES.assignments(z.id));
    await expect(c1.locator('[role="alert"]')).toContainText('R-AC-01');
    await expect(c1.locator(REVIEW_UI.assign.submit)).toHaveCount(0);
    await expect(c1.locator(REVIEW_UI.assign.admit)).toHaveCount(0);
  });

  test('r_cf_03_assignment_checks_show_pass_or_fail_only', async ({ person, request }) => {
    const seeded = await seed(request, 'submitted');
    const { cell, s } = seeded;
    const x = proposal(s, 'x');
    const c1 = await signIn(person, seeded, 'c1');
    const responses = watchResponses(c1);

    await openPage(c1, cell.origin, REVIEW_PAGES.coordinatorDeclaration(x.id));
    await c1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(c1, REVIEW_UI.declaration.submit, /\/coordinator-declaration$/)).toBeLessThan(300);
    await openPage(c1, cell.origin, REVIEW_PAGES.knockOut(x.id));
    for (const c of s.knock_out) await c1.locator(REVIEW_UI.knockOut.pass(c)).check();
    expect(await clickWrite(c1, REVIEW_UI.knockOut.submit, /\/knock-out$/)).toBeLessThan(300);

    await openPage(c1, cell.origin, REVIEW_PAGES.assignments(x.id));
    const assign = async (who: 'r1' | 'r2' | 'r4'): Promise<void> => {
      await c1.locator(REVIEW_UI.assign.reviewer).selectOption({ label: s.people[who].label });
      expect(await clickWrite(c1, REVIEW_UI.assign.submit, /\/assignments$/)).toBeLessThan(300);
    };
    // R1 and R4 share organisation O1, so P-39 = 2 is not met yet.
    await assign('r1');
    await assign('r4');
    const p39 = c1.locator(REVIEW_UI.assign.p39);
    const proximity = c1.locator(REVIEW_UI.assign.proximity);
    await expect(p39).toHaveAttribute('data-check', 'fail');
    await expect(proximity).toHaveAttribute('data-check', /^(pass|fail)$/);
    // R2 of O2 meets it.
    await assign('r2');
    await expect(p39).toHaveAttribute('data-check', 'pass');

    // The checks state an outcome only: they name no reviewer, and no
    // affiliation or other identity attribute reaches the page (R-CF-03).
    for (const check of [p39, proximity]) {
      for (const who of ['r1', 'r2', 'r4'] as const) {
        await expect(check).not.toContainText(s.people[who].label);
      }
    }
    await expectNoCanary(c1, s.identity_canaries, 'assignment page', responses);

    // R-EV-02, R-CF-02: admission needs at least P-03 assignees declared
    // free of conflict, so each new assignee declares on their own
    // assignment first, which they find in their own list.
    for (const who of ['r1', 'r2', 'r4'] as const) {
      const reviewer = await signIn(person, seeded, who);
      const mine = await apiGet(reviewer, cell.origin, '/api/v1/me/assignments');
      expectAccepted(mine, `${who}'s assignments`);
      const rows = JSON.parse(mine.body) as readonly { assignment: string; proposal: string; kind: string }[];
      const row = rows.find((r) => r.proposal === x.id && r.kind === 'reviewer');
      if (row === undefined) throw new Error(`${who} has no reviewer assignment of x`);
      await openPage(reviewer, cell.origin, REVIEW_PAGES.assignment(row.assignment));
      await reviewer.locator(REVIEW_UI.declaration.no).check();
      expect(await clickWrite(reviewer, REVIEW_UI.declaration.submit, /\/declaration$/), who).toBeLessThan(300);
    }

    await openPage(c1, cell.origin, REVIEW_PAGES.assignments(x.id));
    expect(await clickWrite(c1, REVIEW_UI.assign.admit, /\/admission$/)).toBeLessThan(300);
    await expectState(c1, 'STAGE1');
  });

  test('i07_i08_stage1_close_outcome_is_computed_not_chosen', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1_scored');
    const { cell, s } = seeded;
    const x = proposal(s, 'x');
    const w = proposal(s, 'w');
    const c1 = await signIn(person, seeded, 'c1');

    await openPage(c1, cell.origin, REVIEW_PAGES.board(s.call));
    for (const p of [x, w]) {
      const row = c1.locator(REVIEW_UI.board.row(p.id));
      await expect(row).toHaveAttribute('data-state', 'STAGE1');
      // NOTE 3: no control in the row can state an outcome.
      await expect(row.locator('select, input, textarea')).toHaveCount(0);
      await expect(row.locator(REVIEW_UI.board.close(p.id))).toBeVisible();
    }
    expect(await clickWrite(c1, REVIEW_UI.board.close(x.id), /\/stage1-close$/)).toBeLessThan(300);
    expect(await clickWrite(c1, REVIEW_UI.board.close(w.id), /\/stage1-close$/)).toBeLessThan(300);
    // x scores strictly above P-02 and w does not (I-08).
    await expect(c1.locator(REVIEW_UI.board.row(x.id))).toHaveAttribute('data-state', 'STAGE2');
    await expect(c1.locator(REVIEW_UI.board.row(w.id))).toHaveAttribute('data-state', 'NOT_SELECTED');
  });

  test('r_cf_04_notifiable_conflict_draft_reaches_the_coordinator', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const { cell, s } = seeded;
    const w = proposal(s, 'w');
    const r1 = await signIn(person, seeded, 'r1');
    await openPage(r1, cell.origin, REVIEW_PAGES.assignment(assignmentOf(s, 'w', 'r1')));
    await r1.locator(REVIEW_UI.declaration.yes).check();
    await r1.locator(REVIEW_UI.declaration.notifiable).check();
    expect(await clickWrite(r1, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);

    const c1 = await signIn(person, seeded, 'c1');
    const responses = watchResponses(c1);
    await openPage(c1, cell.origin, REVIEW_PAGES.notifiableConflicts(s.call));
    await expect(c1.locator(REVIEW_UI.notifiable.item(w.id))).toHaveCount(1);
    await expectNoCanary(c1, s.identity_canaries, 'notifiable conflicts page', responses);
  });
});
