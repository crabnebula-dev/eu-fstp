/**
 * I-17: Judging roles cannot read identity attributes of an applicant
 * before the proposal enters negotiation. M4 design section 8.2 runs a
 * canary scan on every Judging page DOM. Design section 3.6 adds that no
 * Judging read model carries an identity field.
 *
 * The scenario's identity canaries are strings that only the applicants'
 * identity attributes hold: vault names, countries and affiliations, and
 * the applicants' login emails and display names. Each scan covers the
 * page's DOM, title and form values, and every API response the page
 * received. So a response that carried an identity field fails the scan
 * even when the page did not show it.
 *
 * The last spec tampers with a real response of the cell. It adds an
 * identity member to the ranking view on its way to the page. The
 * generated validators accept closed objects only (design section 3.9),
 * so the page must refuse the response and show an alert, never the
 * value.
 */

import { expect, type Page, type Route } from '@playwright/test';
import { test } from '../playwright.config';
import { REVIEW_PAGES, REVIEW_UI } from './contract';
import {
  assignmentOf,
  clickWrite,
  expectNoCanary,
  ircAssignmentOf,
  openPage,
  proposal,
  seed,
  signIn,
  watchResponses,
} from './support';

/** Opens each path in turn and scans it. */
async function scanAll(
  page: Page,
  origin: string,
  paths: readonly string[],
  canaries: readonly string[],
): Promise<void> {
  const responses = watchResponses(page);
  for (const path of paths) {
    await openPage(page, origin, path);
    await expectNoCanary(page, canaries, path, responses);
  }
}

test.describe('I-17 Judging pages carry no identity attribute', () => {
  test('i17_no_identity_canary_on_coordinator_and_reviewer_pages', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const { cell, s } = seeded;
    const x = proposal(s, 'x');

    const c1 = await signIn(person, seeded, 'c1');
    await scanAll(
      c1,
      cell.origin,
      [
        REVIEW_PAGES.intake(s.call),
        REVIEW_PAGES.board(s.call),
        REVIEW_PAGES.assignments(x.id),
        REVIEW_PAGES.notifiableConflicts(s.call),
      ],
      s.identity_canaries,
    );

    const r1 = await signIn(person, seeded, 'r1');
    const a = assignmentOf(s, 'x', 'r1');
    await scanAll(
      r1,
      cell.origin,
      [REVIEW_PAGES.myAssignments(), REVIEW_PAGES.assignment(a), REVIEW_PAGES.assignment(assignmentOf(s, 'w', 'r1'))],
      s.identity_canaries,
    );
    // After the declaration the full content is shown: still no identity.
    await openPage(r1, cell.origin, REVIEW_PAGES.assignment(a));
    await r1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(r1, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);
    await expect(r1.locator(REVIEW_UI.content)).toBeVisible();
    await scanAll(r1, cell.origin, [REVIEW_PAGES.assignment(a), REVIEW_PAGES.rankingSummary(a)], s.identity_canaries);
  });

  test('i17_no_identity_canary_on_committee_pages', async ({ person, request }) => {
    const seeded = await seed(request, 'ranked');
    const { cell, s } = seeded;
    for (const who of ['r1', 'r4', 'h1'] as const) {
      const page = await signIn(person, seeded, who);
      await scanAll(page, cell.origin, [REVIEW_PAGES.ranking(s.call)], s.identity_canaries);
    }
  });

  test('i17_no_identity_canary_on_irc_pages', async ({ person, request }) => {
    const seeded = await seed(request, 'irc_review');
    const { cell, s } = seeded;
    const i1 = await signIn(person, seeded, 'i1');
    const a = ircAssignmentOf(s, 'x', 'i1');
    await scanAll(i1, cell.origin, [REVIEW_PAGES.myIrcCases(), REVIEW_PAGES.ircCase(a)], s.identity_canaries);
    await i1.locator(REVIEW_UI.declaration.no).check();
    expect(await clickWrite(i1, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);
    await expect(i1.locator(REVIEW_UI.irc.case)).toBeVisible();
    await scanAll(i1, cell.origin, [REVIEW_PAGES.ircCase(a)], s.identity_canaries);
  });

  test('i17_an_identity_member_in_a_judging_response_is_refused_by_the_page', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'ranked');
    const { cell, s } = seeded;
    const canary = s.identity_canaries[0];
    if (canary === undefined) throw new Error('the scenario has no identity canary');
    const r1 = await signIn(person, seeded, 'r1');

    // The untampered page renders, so a page that refuses everything cannot pass.
    await openPage(r1, cell.origin, REVIEW_PAGES.ranking(s.call));
    await expect(r1.locator(REVIEW_UI.ranking.table)).toBeVisible();

    /** Adds `applicant_email` at the top, or inside the first object of the first array. */
    const tamper = (nested: boolean) => async (route: Route) => {
      const res = await route.fetch();
      const body = (await res.json()) as unknown;
      if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        throw new Error('the ranking view is not a JSON object');
      }
      const top = body as Record<string, unknown>;
      if (nested) {
        const list = Object.values(top).find(
          (v): v is unknown[] => Array.isArray(v) && typeof v[0] === 'object' && v[0] !== null,
        );
        if (list === undefined) throw new Error('the ranking view has no list of rows');
        (list[0] as Record<string, unknown>)['applicant_email'] = canary;
      } else {
        top['applicant_email'] = canary;
      }
      await route.fulfill({ response: res, json: top });
    };

    for (const nested of [false, true]) {
      await r1.route(`**/api/v1/calls/${s.call}/ranking`, tamper(nested));
      await r1.goto(`${cell.origin}${REVIEW_PAGES.ranking(s.call)}`);
      await expect(r1.getByRole('alert').first()).toBeVisible();
      await expectNoCanary(r1, [canary], nested ? 'nested tampered ranking' : 'tampered ranking');
      await r1.unroute(`**/api/v1/calls/${s.call}/ranking`);
    }
  });
});
