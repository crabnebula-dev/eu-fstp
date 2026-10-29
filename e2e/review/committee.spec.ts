/**
 * J7, the committee (M4 design section 2.2 and change D5): the ranking
 * view, cut-off rounds, ballots and the recorded cut-off, in the browser
 * against the e2e cell.
 *
 * - R-EV-08: the cut-off is set from the ranking view with the remaining
 *   budget visible, and the rationale is recorded. The view has weighted
 *   scores per criterion (D9) and no LLM findings (`roles-and-sod.md`).
 * - R-EV-09, NOTE 8 of P-16 and Q4: each member casts their own ballot,
 *   and no page lets one member state another's vote. A member with a
 *   conflict on a ranked proposal recuses from the call's vote, and no
 *   vote is delegated to or from a recused member (R-CF-02).
 * - Q16: a ranking row where the viewer has a conflict shows "recused"
 *   only.
 * - NOTE 6 of `state-machine.md`: outcomes are computed from the order
 *   and the position. A tie across the cut-off needs a recorded P-17
 *   tie-break.
 * - ADR-006: amounts are shown as the server's decimal strings.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { REVIEW_API, REVIEW_PAGES, REVIEW_UI, type PersonaKey } from './contract';
import {
  captureWrite,
  clickWrite,
  expectAccepted,
  expectFieldError,
  expectNoCanary,
  expectRefusal,
  openPage,
  proposal,
  replay,
  seed,
  signIn,
  watchResponses,
  watchWrites,
  type Seeded,
} from './support';

/** An ADR-006 EUR amount as text: no grouping, two decimals. */
const AMOUNT = /(^|[^0-9.,])(0|[1-9][0-9]*)\.[0-9]{2}([^0-9]|$)/;

/** Opens a cut-off round from the ranking page and returns its id. */
async function openRound(
  page: Page,
  seeded: Seeded,
  nominated: string,
  tieBreak = '',
): Promise<string> {
  await openPage(page, seeded.cell.origin, REVIEW_PAGES.ranking(seeded.s.call));
  await page.locator(REVIEW_UI.ranking.nominated).fill(nominated);
  await page.locator(REVIEW_UI.ranking.rationale).fill('Synthetic: within the remaining budget.');
  if (tieBreak !== '') await page.locator(REVIEW_UI.ranking.tieBreak).fill(tieBreak);
  expect(await clickWrite(page, REVIEW_UI.ranking.open, /\/cut-off-rounds$/)).toBeLessThan(300);
  await page.waitForURL((u) => /^\/app\/cut-off-rounds\/[^/]+$/.test(u.pathname));
  const id = new URL(page.url()).pathname.split('/').pop();
  if (id === undefined || id === '') throw new Error('the round page names no round');
  return id;
}

test.describe('J7 committee', () => {
  test('r_ev_08_ranking_view_shows_scores_and_budget_and_no_findings', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'ranked');
    const { cell, s } = seeded;
    const r1 = await signIn(person, seeded, 'r1');
    const responses = watchResponses(r1);

    await openPage(r1, cell.origin, REVIEW_PAGES.ranking(s.call));
    const table = r1.locator(REVIEW_UI.ranking.table);
    await expect(table).toBeVisible();
    await expect(table.locator('th[scope="col"]').first()).toBeVisible();
    for (const key of ['x', 'v', 'w'] as const) {
      const p = proposal(s, key);
      const row = r1.locator(REVIEW_UI.ranking.row(p.id));
      await expect(row).toContainText(p.title);
      for (const c of s.criteria) {
        await expect(row.locator(`[data-criterion="${c.id}"]`)).toHaveCount(1);
      }
    }
    // The server's order: x, v, w by effective score.
    const order = await r1
      .locator(`${REVIEW_UI.ranking.table} tr[data-proposal]`)
      .evaluateAll((rows) => rows.map((r) => r.getAttribute('data-proposal')));
    expect(order).toEqual(['x', 'v', 'w'].map((k) => proposal(s, k as 'x' | 'v' | 'w').id));

    await expect(r1.locator(REVIEW_UI.ranking.remainingBudget)).toHaveText(AMOUNT);
    await expect(r1.locator(REVIEW_UI.ranking.findings)).toHaveCount(0);
    await expectNoCanary(r1, s.identity_canaries, 'ranking view', responses);
  });

  test('r_ev_09_recused_member_sees_recused_rows_and_cannot_vote', async ({ person, request }) => {
    const seeded = await seed(request, 'ranked');
    const { cell, s } = seeded;
    const w = proposal(s, 'w');
    const r4 = await signIn(person, seeded, 'r4');

    // Q16: the row of the proposal R4 is conflicted on shows "recused" only.
    await openPage(r4, cell.origin, REVIEW_PAGES.ranking(s.call));
    const row = r4.locator(REVIEW_UI.ranking.row(w.id));
    await expect(row).toHaveAttribute('data-recused', 'true');
    await expect(row).not.toContainText(w.title);
    await expect(row).not.toContainText(w.neutral_summary);
    await expect(row.locator('[data-criterion]')).toHaveCount(0);

    // R1 opens a round. R4 is recused from the whole vote of the call.
    const r1 = await signIn(person, seeded, 'r1');
    const round = await openRound(r1, seeded, '2');
    await openPage(r4, cell.origin, REVIEW_PAGES.round(round));
    await expect(r4.locator(REVIEW_UI.round.cast)).toHaveCount(0);
    await expect(r4.locator(REVIEW_UI.round.delegate)).toHaveCount(0);

    // No delegation to a recused member is offered (NOTE 8).
    const options = await r1.locator(`${REVIEW_UI.round.delegateTo} option`).allInnerTexts();
    expect(options.map((o) => o.trim())).not.toContain(s.people.r4.label);

    // R1's own ballot, captured before it reaches the cell, is refused
    // from R4's session and accepted from R1's.
    await r1.locator(REVIEW_UI.round.for).check();
    const ballot = await captureWrite(r1, /\/ballot$/, () => r1.locator(REVIEW_UI.round.cast).click());
    expect(ballot.path).toBe(REVIEW_API.ballot(round));
    expectRefusal(await replay(r4, cell.origin, ballot), 'ballot of a recused member');
    expectAccepted(await replay(r1, cell.origin, ballot), 'ballot of a member');
  });

  test('r_ev_09_ballots_are_cast_by_members_and_outcomes_computed', async ({ person, request }) => {
    const seeded = await seed(request, 'ranked');
    const { cell, s } = seeded;
    const pages = new Map<PersonaKey, Page>();
    for (const who of ['r1', 'r2', 'r3', 'h1'] as const) {
      pages.set(who, await signIn(person, seeded, who));
    }
    const r1 = pages.get('r1');
    const h1 = pages.get('h1');
    if (r1 === undefined || h1 === undefined) throw new Error('personas did not sign in');

    // x and v within the cut-off, w below it.
    const round = await openRound(r1, seeded, '2');
    for (const [who, page] of pages) {
      await openPage(page, cell.origin, REVIEW_PAGES.round(round));
      // The ballot form takes the viewer's own vote: no voter choice.
      const cast = page.locator(REVIEW_UI.round.cast);
      await expect(cast).toBeVisible();
      const form = page.locator('form').filter({ has: cast });
      await expect(form.locator('select')).toHaveCount(0);
      await expect(form.locator('input:not([type="radio"])')).toHaveCount(0);
      // No vote is preset (R-EV-09).
      for (const v of [REVIEW_UI.round.for, REVIEW_UI.round.against, REVIEW_UI.round.abstain]) {
        await expect(page.locator(v), who).not.toBeChecked();
      }
      await page.locator(REVIEW_UI.round.for).check();
      expect(await clickWrite(page, REVIEW_UI.round.cast, /\/ballot$/), who).toBeLessThan(300);
    }

    expect(await clickWrite(h1, REVIEW_UI.round.record, /\/record$/)).toBeLessThan(300);
    await h1.reload();
    const state = (key: 'x' | 'v' | 'w') => h1.locator(REVIEW_UI.round.row(proposal(s, key).id));
    await expect(state('x')).toHaveAttribute('data-state', 'IRC_REVIEW');
    await expect(state('v')).toHaveAttribute('data-state', 'IRC_REVIEW');
    await expect(state('w')).toHaveAttribute('data-state', 'NOT_SELECTED');
  });

  test('r_ev_08_cutoff_with_unbroken_tie_is_rejected_from_the_interface', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'ranked_tie');
    const { cell, s } = seeded;
    const r1 = await signIn(person, seeded, 'r1');

    await openPage(r1, cell.origin, REVIEW_PAGES.ranking(s.call));
    const writes = watchWrites(r1, /\/cut-off-rounds$/);
    // x and w tie, so a cut-off at 1 falls across the tie.
    await r1.locator(REVIEW_UI.ranking.nominated).fill('1');
    await r1.locator(REVIEW_UI.ranking.rationale).fill('Synthetic: budget for one.');
    await r1.locator(REVIEW_UI.ranking.open).click();
    await expectFieldError(r1, REVIEW_UI.ranking.tieBreak);
    // A rationale is required too (R-EV-08).
    await r1.locator(REVIEW_UI.ranking.rationale).fill('');
    await r1.locator(REVIEW_UI.ranking.open).click();
    await expectFieldError(r1, REVIEW_UI.ranking.rationale);
    expect(writes.seen(), 'no round request without tie-break or rationale').toBe(0);

    // With both recorded, the round opens.
    const round = await openRound(r1, seeded, '1', 'Synthetic P-17: exceptional quality.');
    expect(round).not.toBe('');
  });
});
