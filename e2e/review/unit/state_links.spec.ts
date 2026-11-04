/**
 * The Judging lists link only pages that open in the proposal's state
 * (review findings U5 and U7 of lane m4home; Daniel's click-through rule
 * of 2026-10-31: each person reaches their work by clicking from
 * sign-in, so a list never offers a link that only refuses). Each test
 * drives the tsc build of `web/src` in Chromium against a fake
 * `/api/v1`, so it needs no e2e stack.
 *
 * - R-EV-02: the reviewer's list links the stage 2 thread only for an
 *   assignment whose row says it opens (`stage2`, an active reviewer
 *   assignment in STAGE2).
 * - R-EV-01: an INELIGIBLE proposal in the intake queue has no
 *   declaration, knock-out or assignment link, since it gets no further
 *   review. A SUBMITTED one keeps all three.
 *
 * Every value is synthetic. Build first: web/node_modules/.bin/tsc -p web
 */

import { expect, test } from '@playwright/test';
import { REVIEW_PAGES } from '../contract';
import { open, serve } from './fake_api';

test.describe('lane m4home state links', () => {
  test('r_ev_02_assignment_list_links_stage2_only_where_it_opens', async ({ page }) => {
    await serve(page, [{ name: 'me.assignments', method: 'GET', path: '/me/assignments' }], {
      'GET /api/v1/me/assignments': [
        { assignment: '21', proposal: '11', call: '5', kind: 'reviewer', awaiting_declaration: false, active: true, stage2: false },
        { assignment: '22', proposal: '12', call: '5', kind: 'reviewer', awaiting_declaration: false, active: true, stage2: true },
      ],
    });
    await open(page, REVIEW_PAGES.myAssignments());
    await expect(page.locator('main a[href="/app/assignments/21"]')).toHaveCount(1);
    await expect(
      page.locator('main a[href="/app/assignments/21/stage2"]'),
      'no stage 2 link for a proposal outside STAGE2',
    ).toHaveCount(0);
    await expect(page.locator('main a[href="/app/assignments/22/stage2"]'), 'the stage 2 link in STAGE2').toHaveCount(1);
  });

  test('r_ev_01_intake_offers_no_action_link_for_an_ineligible_proposal', async ({ page }) => {
    await serve(page, [{ name: 'intake.queue', method: 'GET', path: '/calls/{call}/intake' }], {
      'GET /api/v1/calls/5/intake': {
        knock_out: [{ id: '1', text: 'Synthetic criterion' }],
        proposals: [
          { proposal: '11', state: 'INELIGIBLE', title: 'Synthetic ineligible title' },
          { proposal: '12', state: 'SUBMITTED', title: 'Synthetic submitted title' },
        ],
      },
    });
    await open(page, REVIEW_PAGES.intake('5'));
    await expect(page.locator('tr[data-proposal="11"] a'), 'no action link for INELIGIBLE').toHaveCount(0);
    await expect(page.locator('tr[data-proposal="11"]')).toContainText('No action is open for proposal 11.');
    for (const path of ['declaration', 'knock-out', 'assignments']) {
      await expect(page.locator(`tr[data-proposal="12"] a[href="/app/proposals/12/${path}"]`)).toHaveCount(1);
    }
  });
});
