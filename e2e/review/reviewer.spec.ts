/**
 * J6, assigned reviewers (M4 design section 2.2): assignments, the
 * declaration before reading, the score sheet, corrections, the ranking
 * summary and stage 2, in the browser against the e2e cell.
 *
 * - R-CF-02: reviewers declare conflicts before accessing full content,
 *   and see only the title and the neutral summary until then (Q9).
 * - I-03: a reviewer with a declared conflict on a proposal cannot read
 *   its content or act on it as a reviewer.
 * - R-EV-02 and P-01 NOTE 6: every criterion is scored on the integer
 *   scale 0 to N.
 * - I-23: a correction is a new record and carries its reason.
 * - R-EV-08: the ranking summary holds title, neutral summary and
 *   rationale.
 * - R-EV-05 and NOTE 4: in stage 2 reviewers ask questions or record
 *   "no questions", and the window closes once every assignee has.
 * - R-NF-03: field errors are tied to their fields, and the error
 *   summary links to them.
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
  openPage,
  proposal,
  seed,
  signIn,
  watchResponses,
  watchWrites,
} from './support';

test.describe('J6 assigned reviewers', () => {
  test('r_cf_02_reviewer_sees_title_and_summary_only_before_declaring', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'stage1');
    const { cell, s } = seeded;
    const x = proposal(s, 'x');
    const a = assignmentOf(s, 'x', 'r1');
    const r1 = await signIn(person, seeded, 'r1');
    const responses = watchResponses(r1);

    await openPage(r1, cell.origin, REVIEW_PAGES.myAssignments());
    await expect(r1.locator(REVIEW_UI.link(REVIEW_PAGES.assignment(a)))).toBeVisible();

    await openPage(r1, cell.origin, REVIEW_PAGES.assignment(a));
    await expect(r1.locator(REVIEW_UI.declaration.title)).toHaveText(x.title);
    await expect(r1.locator(REVIEW_UI.declaration.summary)).toHaveText(x.neutral_summary);
    await expect(r1.locator(REVIEW_UI.content)).toHaveCount(0);
    await expect(r1.locator(REVIEW_UI.score.form)).toHaveCount(0);
    await expectNoCanary(r1, [s.content_canary], 'assignment page before declaring', responses);
    expectRefusal(await apiGet(r1, cell.origin, REVIEW_API.content(x.id)), 'content before declaring');

    await expect(r1.locator(REVIEW_UI.declaration.no)).not.toBeChecked();
    await expect(r1.locator(REVIEW_UI.declaration.yes)).not.toBeChecked();
    await r1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(r1, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);

    await expect(r1.locator(REVIEW_UI.content)).toContainText(s.content_canary);
    await expect(r1.locator(REVIEW_UI.score.form)).toBeVisible();
    expectAccepted(await apiGet(r1, cell.origin, REVIEW_API.content(x.id)), 'content after declaring');
    await expectNoCanary(r1, s.identity_canaries, 'assignment page after declaring', responses);
  });

  test('i03_declared_conflict_bars_content_and_scoring', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const { cell, s } = seeded;
    const x = proposal(s, 'x');
    const r2 = await signIn(person, seeded, 'r2');

    await openPage(r2, cell.origin, REVIEW_PAGES.assignment(assignmentOf(s, 'x', 'r2')));
    await r2.locator(REVIEW_UI.declaration.yes).check();
    expect(await clickWrite(r2, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);
    await expect(r2.locator(REVIEW_UI.status)).toBeVisible();

    await r2.reload();
    await expect(r2.locator('main')).toBeVisible();
    await expect(r2.locator(REVIEW_UI.content)).toHaveCount(0);
    await expect(r2.locator(REVIEW_UI.score.form)).toHaveCount(0);
    await expect(r2.locator('body')).not.toContainText(s.content_canary);
    expectRefusal(
      await apiGet(r2, cell.origin, REVIEW_API.content(x.id)),
      'content after a declared conflict',
      'I-03',
    );

    // The pair: R1 declares no conflict on the same proposal and reads it.
    const r1 = await signIn(person, seeded, 'r1');
    await openPage(r1, cell.origin, REVIEW_PAGES.assignment(assignmentOf(s, 'x', 'r1')));
    await r1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(r1, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);
    expectAccepted(await apiGet(r1, cell.origin, REVIEW_API.content(x.id)), 'content without conflict');
  });

  test('r_ev_02_score_sheet_takes_integers_on_the_p01_scale', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const { cell, s } = seeded;
    const a = assignmentOf(s, 'x', 'r1');
    const r1 = await signIn(person, seeded, 'r1');

    await openPage(r1, cell.origin, REVIEW_PAGES.assignment(a));
    await r1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(r1, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);

    const [first, ...rest] = s.criteria;
    if (first === undefined) throw new Error('the scenario has no P-01 criterion');
    // One labelled field per criterion, no more (NOTE 6).
    await expect(r1.locator(`${REVIEW_UI.score.form} input`)).toHaveCount(s.criteria.length);
    for (const c of s.criteria) {
      await expect(r1.locator(REVIEW_UI.score.input(c.id))).toBeVisible();
    }

    const writes = watchWrites(r1, /\/scores$/);
    await r1.locator(REVIEW_UI.score.input(first.id)).fill(`${Math.min(first.max, 3)}.5`);
    for (const c of rest) await r1.locator(REVIEW_UI.score.input(c.id)).fill(String(c.max));
    await r1.locator(REVIEW_UI.score.submit).click();
    await expectFieldError(r1, REVIEW_UI.score.input(first.id));
    const summary = r1.locator(REVIEW_UI.score.errors);
    await expect(summary).toBeVisible();
    await expect(summary.locator(`a[href="${REVIEW_UI.score.input(first.id)}"]`)).toHaveCount(1);
    // The field keeps what the user typed, so the error stays visible.
    await expect(r1.locator(REVIEW_UI.score.input(first.id))).toHaveValue(`${Math.min(first.max, 3)}.5`);

    await r1.locator(REVIEW_UI.score.input(first.id)).fill(String(first.max + 1));
    await r1.locator(REVIEW_UI.score.submit).click();
    await expectFieldError(r1, REVIEW_UI.score.input(first.id));
    expect(writes.seen(), 'no score request for a value off the scale').toBe(0);

    await r1.locator(REVIEW_UI.score.input(first.id)).fill('0');
    expect(await clickWrite(r1, REVIEW_UI.score.submit, /\/scores$/)).toBeLessThan(300);
    await expect(r1.locator(REVIEW_UI.status)).toBeVisible();

    await r1.reload();
    await expect(r1.locator(REVIEW_UI.score.input(first.id))).toHaveValue('0');
    for (const c of rest) await expect(r1.locator(REVIEW_UI.score.input(c.id))).toHaveValue(String(c.max));
  });

  test('i23_score_correction_needs_a_reason', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1_scored');
    const { cell, s } = seeded;
    const a = assignmentOf(s, 'x', 'r1');
    const [first] = s.criteria;
    if (first === undefined) throw new Error('the scenario has no P-01 criterion');
    const r1 = await signIn(person, seeded, 'r1');

    await openPage(r1, cell.origin, REVIEW_PAGES.assignment(a));
    await r1.locator(REVIEW_UI.score.correct).click();
    const field = r1.locator(REVIEW_UI.score.input(first.id));
    const before = await field.inputValue();
    const after = before === '0' ? '1' : '0';
    await field.fill(after);
    const writes = watchWrites(r1, /\/scores\/[^/]+$/);
    await r1.locator(REVIEW_UI.score.submit).click();
    await expectFieldError(r1, REVIEW_UI.score.reason);
    expect(writes.seen(), 'no correction request without a reason').toBe(0);

    await r1.locator(REVIEW_UI.score.reason).fill('Synthetic: misread the work plan.');
    expect(await clickWrite(r1, REVIEW_UI.score.submit, /\/scores\/[^/]+$/)).toBeLessThan(300);
    await r1.reload();
    await expect(r1.locator(REVIEW_UI.score.input(first.id))).toHaveValue(after);
  });

  test('r_ev_08_ranking_summary_needs_title_summary_and_rationale', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1_scored');
    const { cell, s } = seeded;
    const r1 = await signIn(person, seeded, 'r1');
    const responses = watchResponses(r1);

    await openPage(r1, cell.origin, REVIEW_PAGES.rankingSummary(assignmentOf(s, 'x', 'r1')));
    const writes = watchWrites(r1, /\/ranking-summary$/);
    await r1.locator(REVIEW_UI.summary.submit).click();
    for (const f of [REVIEW_UI.summary.title, REVIEW_UI.summary.neutral, REVIEW_UI.summary.rationale]) {
      await expectFieldError(r1, f);
    }
    expect(writes.seen(), 'no summary request with empty fields').toBe(0);

    await r1.locator(REVIEW_UI.summary.title).fill('Synthetic open sensor kit');
    await r1.locator(REVIEW_UI.summary.neutral).fill('A kit for air quality readings.');
    await r1.locator(REVIEW_UI.summary.rationale).fill('Clear plan, modest budget.');
    expect(await clickWrite(r1, REVIEW_UI.summary.submit, /\/ranking-summary$/)).toBeLessThan(300);
    await expectNoCanary(r1, s.identity_canaries, 'ranking summary page', responses);
  });

  test('r_ev_05_reviewer_question_reaches_the_stage2_thread', async ({ person, request }) => {
    const seeded = await seed(request, 'stage2');
    const { cell, s } = seeded;
    const r1 = await signIn(person, seeded, 'r1');
    const responses = watchResponses(r1);

    await openPage(r1, cell.origin, REVIEW_PAGES.stage2(assignmentOf(s, 'x', 'r1')));
    const writes = watchWrites(r1, /\/questions$/);
    await r1.locator(REVIEW_UI.stage2.ask).click();
    await expectFieldError(r1, REVIEW_UI.stage2.question);
    expect(writes.seen(), 'no empty question is sent').toBe(0);

    await r1.locator(REVIEW_UI.stage2.question).fill('Synthetic: which sensors are in the kit?');
    expect(await clickWrite(r1, REVIEW_UI.stage2.ask, /\/questions$/)).toBeLessThan(300);
    await r1.reload();
    await expect(r1.locator(REVIEW_UI.stage2.thread)).toContainText('which sensors are in the kit?');
    await expectNoCanary(r1, s.identity_canaries, 'stage 2 page', responses);
  });

  test('r_ev_05_stage2_window_closes_once_every_assignee_records_no_questions', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'stage2');
    const { cell, s } = seeded;
    const r1 = await signIn(person, seeded, 'r1');
    const r2 = await signIn(person, seeded, 'r2');

    // One assignee's record leaves the window open for the other (O-50).
    await openPage(r1, cell.origin, REVIEW_PAGES.stage2(assignmentOf(s, 'x', 'r1')));
    expect(await clickWrite(r1, REVIEW_UI.stage2.noQuestions, /\/no-questions$/)).toBeLessThan(300);
    await openPage(r2, cell.origin, REVIEW_PAGES.stage2(assignmentOf(s, 'x', 'r2')));
    await expect(r2.locator(REVIEW_UI.stage2.question)).toBeVisible();

    // Every active assignee has recorded it: the window closes at once (NOTE 4).
    expect(await clickWrite(r2, REVIEW_UI.stage2.noQuestions, /\/no-questions$/)).toBeLessThan(300);
    for (const page of [r1, r2]) {
      await page.reload();
      await expect(page.locator('main')).toBeVisible();
      await expect(page.locator(REVIEW_UI.stage2.question)).toHaveCount(0);
      await expect(page.locator(REVIEW_UI.stage2.ask)).toHaveCount(0);
    }
  });
});
