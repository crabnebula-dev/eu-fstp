/**
 * Review reproducer (lane m4/site, independent review of 2026-11-04).
 * It fails against the lane's working tree and passes once fixed.
 *
 * r_ev_01_review_board_summary_counts_every_selected_proposal: the call
 * board heads its table with "Proposals selected for Stage 2: N"
 * (`stage1-close` prototype). The page counts only the rows whose state
 * is STAGE2 now. Once a selected proposal moves on (RANKED, IRC_REVIEW,
 * NEGOTIATION and later), it leaves that count, so on a ranked call the
 * board tells the coordinator that fewer proposals, or none, were
 * selected than the board itself lists.
 *
 * Every person, proposal and value is synthetic.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { seed } from '../review/support';
import { enrolToHome } from './contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The states a proposal reaches only after it was selected for stage 2 (state machine). */
const AFTER_SELECTION = new Set([
  'STAGE2', 'RANKED', 'IRC_REVIEW', 'DEFERRED', 'DECLINED', 'NEGOTIATION', 'GRANTED', 'IN_EXECUTION', 'COMPLETED', 'TERMINATED',
]);

test.describe('review: call board summary', () => {
  test.describe.configure({ timeout: 240_000 });

  /** R-EV-01, NOTE 3: the selected count of the board is not lower than the selected rows it lists. */
  test('r_ev_01_review_board_summary_counts_every_selected_proposal', async ({ person, request }) => {
    const seeded = await seed(request, 'ranked');
    const { s } = seeded;
    const page = await enrolToHome(person, seeded.cell.origin, s.people.c1.invite_url);
    await page.locator('#home-work a[data-work="board"]').first().click();
    await page.waitForURL((u) => u.pathname === `/app/calls/${s.call}/board`);
    await expect(page.locator('#board-summary')).toBeVisible();
    const states = await page.locator('#board-table tr[data-state]').evaluateAll((rows) =>
      rows.map((r) => r.getAttribute('data-state') ?? ''),
    );
    const selected = states.filter((x) => AFTER_SELECTION.has(x)).length;
    expect(selected, 'the ranked scene lists proposals selected for stage 2').toBeGreaterThan(0);
    const summary = (await page.locator('#board-summary').innerText()).trim();
    const m = /selected for Stage 2: (\d+)/.exec(summary);
    expect(m, `the summary names a selected count: "${summary}"`).not.toBeNull();
    expect(Number(m?.[1] ?? '-1'), `"${summary}" against the rows ${states.join(', ')}`).toBe(selected);
  });
});
