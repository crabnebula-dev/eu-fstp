/**
 * Review reproducers (lane m4/site, independent review of 2026-11-04).
 * Each test fails against the lane's working tree and passes once the
 * defect it names is fixed.
 *
 * - r_nf_03_review_home_score_count_*: the reviewer's home card says
 *   "N proposals need your score" (`01-navigation-home.md`), and the IRC
 *   card "N nominated proposals for independent review". The page counts
 *   only assignments with `active: true`, so an assignment that still
 *   waits for its declaration is left out, and a scored one stays in.
 *   A reviewer with two unscored assignments to declare reads "0", and a
 *   reviewer who scored one of two still reads "2".
 * - r_lg_04_review_profile_session_start_is_a_date: the profile page
 *   `/app/me` lists each session with its start as the raw microsecond
 *   count of the wire (such as `1793350800000000`), where the M3 page of
 *   passkeys and sessions shows a date.
 *
 * Every person, proposal and value is synthetic.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { REVIEW_UI } from '../review/contract';
import { assignmentOf, seed } from '../review/support';
import { enrolToHome } from './contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

test.describe('review: home counts and the profile', () => {
  test.describe.configure({ timeout: 240_000 });

  /** 01-navigation-home.md, R-CF-02: two unscored assignments awaiting declaration are two proposals to score. */
  test('r_nf_03_review_home_score_count_includes_assignments_awaiting_declaration', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    // r1 holds two reviewer assignments in stage1, both awaiting the declaration.
    const page = await enrolToHome(person, seeded.cell.origin, seeded.s.people.r1.invite_url);
    await expect(page.locator('#home-reviewer h2')).toHaveText('2 proposals need your score');
  });

  /** 01-navigation-home.md, R-EV-02: a recorded score leaves the count. */
  test('r_nf_03_review_home_score_count_drops_a_scored_assignment', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const { s } = seeded;
    // r3 holds two active, unscored reviewer assignments in stage1.
    const page = await enrolToHome(person, seeded.cell.origin, s.people.r3.invite_url);
    await expect(page.locator('#home-reviewer h2')).toHaveText('2 proposals need your score');
    const a = assignmentOf(s, 'x', 'r3');
    await page.locator('#home-work a[data-work="assignments"]').first().click();
    await page.waitForURL((u) => u.pathname === '/app/me/assignments');
    await page.locator(`main a[href="/app/assignments/${a}"]`).first().click();
    await page.waitForURL((u) => u.pathname === `/app/assignments/${a}`);
    for (const c of s.criteria) await page.locator(REVIEW_UI.score.input(c.id)).fill(String(c.max));
    await page.locator(REVIEW_UI.score.submit).click();
    await expect(page.locator(REVIEW_UI.status)).not.toBeEmpty();
    await page.locator('aside nav a[data-nav="home"]').first().click();
    await page.waitForURL((u) => u.pathname === '/app/');
    await expect(page.locator('#home-reviewer h2')).toHaveText('1 proposal needs your score');
  });

  /** 01-navigation-home.md, O-58: IRC cases awaiting the declaration are counted. */
  test('r_nf_03_review_home_irc_count_includes_cases_awaiting_declaration', async ({ person, request }) => {
    const seeded = await seed(request, 'irc_review');
    const page = await enrolToHome(person, seeded.cell.origin, seeded.s.people.i1.invite_url);
    await page.locator('#home-work a[data-work="irc-cases"]').first().click();
    await page.waitForURL((u) => u.pathname === '/app/me/irc-cases');
    await expect(page.locator('main a[href^="/app/irc-assignments/"]').first()).toBeVisible();
    const cases = await page.locator('main a[href^="/app/irc-assignments/"]').count();
    expect(cases, 'i1 holds IRC cases in irc_review').toBeGreaterThan(0);
    await page.locator('aside nav a[data-nav="home"]').first().click();
    await page.waitForURL((u) => u.pathname === '/app/');
    await expect(page.locator('#home-irc h2')).toHaveText(
      `${cases} nominated proposal${cases === 1 ? '' : 's'} for independent review`,
    );
  });

  /** R-LG-04, 06-profile-page.md: a session's start reads as a date, not the wire's microseconds. */
  test('r_lg_04_review_profile_session_start_is_a_date', async ({ person, request }) => {
    const seeded = await seed(request, 'stage1');
    const page = await enrolToHome(person, seeded.cell.origin, seeded.s.people.r1.invite_url);
    await page.locator('aside a[data-nav="account"]').first().click();
    await page.waitForURL((u) => u.pathname === '/app/me');
    const row = page.locator('#sessions-list tr').first();
    await expect(row).toBeVisible();
    const cells = (await row.locator('td').allInnerTexts()).map((x) => x.trim());
    for (const c of cells) {
      expect(c, 'no session cell shows a raw microsecond count').not.toMatch(/^\d{13,}$/);
    }
  });
});
