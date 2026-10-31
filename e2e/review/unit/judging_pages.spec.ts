/**
 * Page behaviour of the Judging pages against a fake `/api/v1` (lane
 * W4c, fix round 1). Each test drives the tsc build of `web/src` in
 * Chromium, so it needs no e2e stack.
 *
 * - NOTE 6 of `state-machine.md`, P-17 and R-EV-08: the committee places
 *   tied proposals in the order of its tie-break, and the round is opened
 *   with that order.
 * - R-CF-02 and I-03: a conflict found while reading is declared on the
 *   active assignment, which releases it, and the page then shows no
 *   content and no form to act.
 * - R-CF-02: the summary and stage 2 pages wait for the declaration.
 *
 * Build first: web/node_modules/.bin/tsc -p web
 */

import { expect, test } from '@playwright/test';
import { REVIEW_PAGES, REVIEW_UI } from '../contract';
import { open, serve, writesOf, type FakeOp } from './fake_api';

const RANKING_OPS: readonly FakeOp[] = [
  { name: 'committee.ranking', method: 'GET', path: '/calls/{call}/ranking' },
  { name: 'committee.open_round', method: 'POST', path: '/calls/{call}/cut-off-rounds' },
];

function rankedRow(proposal: string, effective: string): Record<string, unknown> {
  return {
    proposal,
    recused: false,
    title: `Synthetic title ${proposal}`,
    neutral_summary: 'Synthetic summary.',
    rationale: 'Synthetic rationale.',
    effective,
    criterion_scores: [],
    requested: '50000.00',
    remaining_budget: '60000.00',
  };
}

const REVIEWER_OPS: readonly FakeOp[] = [
  { name: 'me.assignments', method: 'GET', path: '/me/assignments' },
  { name: 'review.read_content', method: 'GET', path: '/proposals/{proposal}/content' },
  { name: 'review.score_sheet', method: 'GET', path: '/assignments/{assignment}/score-sheet' },
  { name: 'review.declare_assignment', method: 'POST', path: '/assignments/{assignment}/declaration' },
  { name: 'review.ranking_summary', method: 'POST', path: '/assignments/{assignment}/ranking-summary' },
  { name: 'review.stage2_thread', method: 'GET', path: '/assignments/{assignment}/stage2' },
];

function reviewerAnswers(awaiting: boolean): Record<string, unknown> {
  return {
    'GET /api/v1/me/assignments': [
      { assignment: '21', proposal: '11', call: '5', kind: 'reviewer', awaiting_declaration: awaiting, active: !awaiting },
    ],
    'GET /api/v1/proposals/11/content': {
      proposal: '11',
      call: '5',
      state: 'STAGE1',
      title: 'Synthetic title',
      text: 'Synthetic content.',
    },
    'GET /api/v1/assignments/21/score-sheet': {
      stage: 'One',
      plan: '3',
      criteria: [{ id: '1', text: 'Synthetic criterion', max: 5 }],
      current: null,
    },
    'GET /api/v1/assignments/21/stage2': { state: 'STAGE2', open: true, own_no_questions: false, entries: [] },
    'POST /api/v1/assignments/21/declaration': { accepted: true },
  };
}

test.describe('W4c Judging page behaviour', () => {
  /**
   * NOTE 6 of `state-machine.md`, P-17 and R-EV-08. The server lists the
   * rows in proposal order. The page orders them by score, lets the
   * committee move the tied 12 above 11, and opens the round with that
   * order, so 12 falls within a cut-off at 2.
   */
  test('r_ev_08_note6_the_round_opens_with_the_tie_order_the_committee_sets', async ({ page }) => {
    const seen = await serve(page, RANKING_OPS, {
      'GET /api/v1/calls/5/ranking': [rankedRow('11', '80.00'), rankedRow('12', '80.00'), rankedRow('13', '90.00')],
      'POST /api/v1/calls/5/cut-off-rounds': { round: '7' },
    });
    await open(page, REVIEW_PAGES.ranking('5'));
    const rows = page.locator(`${REVIEW_UI.ranking.table} tbody tr`);
    await expect(rows).toHaveCount(3);
    expect(await rows.evaluateAll((els) => els.map((e) => e.getAttribute('data-proposal')))).toEqual([
      '13',
      '11',
      '12',
    ]);
    // 13 ties with nothing, so it has no move control.
    await expect(page.locator('#round-form').getByRole('button', { name: /Proposal 13/ })).toHaveCount(0);
    await page.getByRole('button', { name: 'Move Proposal 12 up' }).click();
    expect(await rows.evaluateAll((els) => els.map((e) => e.getAttribute('data-proposal')))).toEqual([
      '13',
      '12',
      '11',
    ]);
    await expect(page.getByRole('button', { name: 'Move Proposal 12 down' })).toBeFocused();
    await page.locator(REVIEW_UI.ranking.nominated).fill('2');
    await page.locator(REVIEW_UI.ranking.rationale).fill('Synthetic: budget for two.');
    await page.locator(REVIEW_UI.ranking.tieBreak).fill('Synthetic P-17: 12 is more frugal.');
    await page.locator(REVIEW_UI.ranking.open).click();
    await expect.poll(() => writesOf(seen).length).toBe(1);
    expect(writesOf(seen)[0]).toEqual({
      key: 'POST /api/v1/calls/5/cut-off-rounds',
      body: {
        order: ['13', '12', '11'],
        nominated: 2,
        rationale: 'Synthetic: budget for two.',
        tie_breaks: 'Synthetic P-17: 12 is more frugal.',
      },
    });
  });

  /**
   * NOTE 6 and P-17: the tie check runs on the order the committee set,
   * so a cut-off inside the tie still needs its tie-break.
   */
  test('p17_a_reordered_tie_across_the_cutoff_still_needs_a_tie_break', async ({ page }) => {
    const seen = await serve(page, RANKING_OPS, {
      'GET /api/v1/calls/5/ranking': [rankedRow('11', '80.00'), rankedRow('12', '80.00')],
      'POST /api/v1/calls/5/cut-off-rounds': { round: '7' },
    });
    await open(page, REVIEW_PAGES.ranking('5'));
    await page.getByRole('button', { name: 'Move Proposal 12 up' }).click();
    await page.locator(REVIEW_UI.ranking.nominated).fill('1');
    await page.locator(REVIEW_UI.ranking.rationale).fill('Synthetic: budget for one.');
    await page.locator(REVIEW_UI.ranking.open).click();
    await expect(page.locator(REVIEW_UI.ranking.tieBreak)).toHaveAttribute('aria-invalid', 'true');
    expect(writesOf(seen)).toEqual([]);
  });

  /**
   * R-CF-02 and I-03: the conflict found while reading is declared with
   * `conflicted: true`, never preset, and the page then shows neither the
   * content nor the score sheet.
   */
  test('r_cf_02_i03_a_conflict_found_while_reading_releases_the_reviewer_assignment', async ({ page }) => {
    const seen = await serve(page, REVIEWER_OPS, reviewerAnswers(false));
    await open(page, REVIEW_PAGES.assignment('21'));
    await expect(page.locator(REVIEW_UI.declaration.yes)).not.toBeChecked();
    await expect(page.locator(REVIEW_UI.declaration.no)).toHaveCount(0);
    await page.locator(REVIEW_UI.declaration.submit).click();
    await expect(page.locator(REVIEW_UI.declaration.yes)).toHaveAttribute('aria-invalid', 'true');
    expect(writesOf(seen)).toEqual([]);

    await page.locator(REVIEW_UI.declaration.yes).check();
    await page.locator(REVIEW_UI.declaration.submit).click();
    await expect.poll(() => writesOf(seen).length).toBe(1);
    expect(writesOf(seen)[0]).toEqual({
      key: 'POST /api/v1/assignments/21/declaration',
      body: { conflicted: true, notifiable: false },
    });
    await expect(page.locator(REVIEW_UI.content)).toHaveCount(0);
    await expect(page.locator(REVIEW_UI.score.form)).toHaveCount(0);
    await expect(page.locator(REVIEW_UI.status)).not.toBeEmpty();
  });

  /** R-CF-02, R-CF-04 and I-03 for the IRC: a notifiable conflict found while reading the case. */
  test('r_cf_02_i03_a_conflict_found_while_reading_releases_the_irc_assignment', async ({ page }) => {
    const seen = await serve(
      page,
      [
        { name: 'me.irc_cases', method: 'GET', path: '/me/irc-cases' },
        { name: 'irc.case', method: 'GET', path: '/irc-assignments/{irc_assignment}/case' },
        { name: 'irc.declare', method: 'POST', path: '/irc-assignments/{irc_assignment}/declaration' },
        { name: 'irc.review', method: 'POST', path: '/irc-assignments/{irc_assignment}/review' },
      ],
      {
        'GET /api/v1/me/irc-cases': [
          { assignment: '31', proposal: '11', call: '5', kind: 'irc', awaiting_declaration: false, active: true },
        ],
        'GET /api/v1/irc-assignments/31/case': {
          proposal: '11',
          state: 'IRC_REVIEW',
          title: 'Synthetic title',
          text: 'Synthetic content.',
          outcome: 'nominated',
        },
        'POST /api/v1/irc-assignments/31/declaration': { accepted: true },
      },
    );
    await open(page, REVIEW_PAGES.ircCase('31'));
    await page.locator(REVIEW_UI.declaration.yes).check();
    await page.locator(REVIEW_UI.declaration.notifiable).check();
    await page.locator(REVIEW_UI.declaration.submit).click();
    await expect.poll(() => writesOf(seen).length).toBe(1);
    expect(writesOf(seen)[0]).toEqual({
      key: 'POST /api/v1/irc-assignments/31/declaration',
      body: { conflicted: true, notifiable: true },
    });
    await expect(page.locator(REVIEW_UI.irc.case)).toHaveCount(0);
    await expect(page.locator(REVIEW_UI.irc.submit)).toHaveCount(0);
  });

  /**
   * R-CF-02: before the declaration the ranking summary page offers no
   * form, only the way to the declaration.
   */
  test('r_cf_02_the_summary_page_waits_for_the_declaration', async ({ page }) => {
    const seen = await serve(page, REVIEWER_OPS, reviewerAnswers(true));
    await open(page, REVIEW_PAGES.rankingSummary('21'));
    await expect(page.locator(REVIEW_UI.summary.submit)).toHaveCount(0);
    await expect(page.locator(REVIEW_UI.link(REVIEW_PAGES.assignment('21')))).toHaveCount(1);
    expect(seen.map((r) => r.key)).toEqual(['GET /api/v1/me/assignments']);
  });

  /**
   * R-CF-02: before the declaration the stage 2 page reads no thread,
   * which holds the applicants' answers.
   */
  test('r_cf_02_the_stage2_page_reads_no_thread_before_the_declaration', async ({ page }) => {
    const seen = await serve(page, REVIEWER_OPS, reviewerAnswers(true));
    await open(page, REVIEW_PAGES.stage2('21'));
    await expect(page.locator(REVIEW_UI.stage2.thread)).toHaveCount(0);
    await expect(page.locator(REVIEW_UI.link(REVIEW_PAGES.assignment('21')))).toHaveCount(1);
    expect(seen.map((r) => r.key)).toEqual(['GET /api/v1/me/assignments']);
  });
});
