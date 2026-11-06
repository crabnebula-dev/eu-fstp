/**
 * The voyager surface against `fstp-e2e-cell` (lane j3; `SPEC/12-journey-ui.md`
 * sections 6 to 8; `docs/design/02-voyager-route-diary.md`; the click-through
 * rule: each person reaches their work by clicking from sign-in).
 *
 * - r_jv_01_applicant_reaches_the_progress_map_and_the_activity_log: the
 *   demo lead of the STAGE2 applicant scene signs in with one click, opens
 *   their proposal, then "Progress". The map is a group of sixteen node
 *   links, each named by plain label, formal state and status (I-96,
 *   R-JV-01). The text list holds the same nodes in the same order, with
 *   the current item marked (R-JV-05). A list link opens that node's help
 *   panel with no reload, and with no target the current node's panel
 *   shows. Under reduced motion the current ring stops (R-NF-03). Then
 *   "Activity" opens the log: newest first, the move into STAGE2, the
 *   submission receipt with "Anchor pending" (R-JV-04, O-56), and no
 *   guardian step (O-60).
 * - r_jv_03_reviewer_sees_where_the_proposal_is: an assigned reviewer of
 *   the stage 2 scene opens their assignment of x and sees the "Proposal
 *   status" strip with STAGE2 current (section 8.3). Opened by URL, the
 *   progress page of that proposal shows the strip and no map, list or
 *   withdrawal, since the reviewer is not on the team (review J3-R2).
 * - r_jv_03_o58_irc_member_sees_no_strip: an IRC member of the IRC scene
 *   sees no strip on their cases or their case page (O-58).
 * - r_jv_03_o60_guardian_reaches_the_activity_log: the guardian of the
 *   IRC_REVIEW_MINOR scene clicks "Activity" on the home page and on the
 *   guardian page, and the log holds their guardian step (O-60, review
 *   J3-R1).
 *
 * Every page reached is checked for console errors and CSP violations, so
 * the map never reaches the page through an HTML sink (ADR-014). Run with
 * `tools/demo/run.sh e2e journey/` against the lane's cell. Every person,
 * proposal and text is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell, watchProblems, type PageProblem } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The guardian of the minor lead's proposal (`scenario.rs` `GUARDIAN`). */
const GUARDIAN = /synthetic-guardian-[0-9a-f]+@e2e\.invalid/;

/** The seeded proposal x of the applicant scenes (`scenario.rs` `PROPOSALS`). */
const X = { id: '1001', title: 'Synthetic open sensor kit' } as const;

/** The route order of the design's "Progress as a list". */
const ROUTE = [
  'DRAFT',
  'SUBMITTED',
  'STAGE1',
  'STAGE2',
  'RANKED',
  'IRC_REVIEW',
  'NEGOTIATION',
  'GRANTED',
  'IN_EXECUTION',
  'COMPLETED',
  'DEFERRED',
  'INELIGIBLE',
  'NOT_SELECTED',
  'DECLINED',
  'WITHDRAWN',
  'TERMINATED',
] as const;

/** The accessible name of a node: "<plain> (<STATE>), <status words>". */
const NODE_NAME =
  /^(.+) \(([A-Z0-9_]+)\), (completed|current stage|upcoming|possible pause, returns at the stage it left|upcoming, final outcome|possible final outcome)$/;

/** Signs `who` in from the front door of the scene `scene`, and returns their page on the home page. */
async function signIn(browser: Browser, scene: string, who: RegExp): Promise<{ page: Page; problems: () => readonly PageProblem[]; close: () => Promise<void> }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(scene);
  const href = await door.signIn(who).getAttribute('href');
  await door.close();
  expect(href, `the front door offers "Sign in as" for ${who.source}`).not.toBeNull();
  const context = await browser.newContext();
  const watch = await watchProblems(context);
  const page = await context.newPage();
  // The sign-in link is the one page this spec opens by URL: it is the
  // click on "Sign in as", made in a context of the person's own.
  await page.goto(new URL(href ?? '', cell.control).href);
  await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
  await settle(page);
  return { page, problems: watch.problems, close: () => context.close() };
}

/** Clicks the link named `name` in `main` and waits for `path`. */
async function clickTo(page: Page, name: RegExp, path: RegExp, why: string): Promise<void> {
  const link = page.locator('main').getByRole('link', { name }).first();
  await expect(link, `${why}: the link ${name.source}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
}

/** Clicks the first link in `main` whose `href` starts with `prefix`, and waits for `path`. */
async function clickHref(page: Page, prefix: string, path: RegExp, why: string): Promise<void> {
  const link = page.locator(`main a[href^="${prefix}"]`).first();
  await expect(link, `${why}: a link to ${prefix}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
}

test.describe('voyager surface', () => {
  test.describe.configure({ timeout: 240_000 });

  /** R-JV-01, R-JV-04, R-JV-05, I-96, O-56, O-60, R-NF-03. */
  test('r_jv_01_applicant_reaches_the_progress_map_and_the_activity_log', async ({ browser }) => {
    const who = await signIn(browser, '/demo/applicant?at=STAGE2', DOOR.leadX);
    const { page } = who;
    try {
      await clickTo(page, new RegExp(X.title), new RegExp(`^/app/proposals/${X.id}$`), 'home');
      await clickTo(page, /^Progress$/, new RegExp(`^/app/proposals/${X.id}/progress$`), 'proposal page');
      await expect(page.locator('main h1')).toHaveText('Application progress');

      // The map: one group, sixteen node links named by label, state and status.
      const svg = page.locator('main svg[role="group"]');
      await expect(svg, 'the map').toHaveCount(1);
      const nodes = svg.locator('a');
      await expect(nodes).toHaveCount(16);
      const onMap: string[] = [];
      for (let i = 0; i < 16; i += 1) {
        const name = (await nodes.nth(i).getAttribute('aria-label')) ?? '';
        const m = NODE_NAME.exec(name);
        expect(m, `I-96: node ${i} is named "<label> (<STATE>), <status>": ${name}`).not.toBeNull();
        onMap.push(m?.[2] ?? '');
        expect(await nodes.nth(i).getAttribute('href'), `node ${name} is a link`).toMatch(/#node-[A-Z0-9_]+$/);
      }
      expect(onMap, 'R-JV-05: the map in route order').toEqual([...ROUTE]);
      await expect(svg.locator('a[aria-label="Stage 2 questions (STAGE2), current stage"]')).toHaveCount(1);
      for (const done of ['Draft (DRAFT)', 'Submitted (SUBMITTED)', 'Stage 1 evaluation (STAGE1)']) {
        await expect(svg.locator(`a[aria-label="${done}, completed"]`), `${done} completed`).toHaveCount(1);
      }

      // The text list: the same nodes in the same order, the current one marked.
      const list = page.getByRole('region', { name: 'Progress as a list' }).locator('ol > li');
      await expect(list).toHaveCount(16);
      const inList: string[] = [];
      for (let i = 0; i < 16; i += 1) {
        const t = (await list.nth(i).innerText()).replace(/\s+/g, ' ');
        inList.push(/\(([A-Z0-9_]+)\)/.exec(t)?.[1] ?? '');
      }
      expect(inList, 'R-JV-05: the list holds the map nodes in order').toEqual(onMap);
      await expect(page.locator('main ol > li[aria-current="step"]')).toContainText('(STAGE2)');

      // Help panels: the current one with no target, another one on its link.
      await expect(page.locator('#node-STAGE2'), 'the current panel shows with no target').toBeVisible();
      const before = page.url();
      await list.filter({ hasText: '(SUBMITTED)' }).getByRole('link').click();
      const panel = page.locator('#node-SUBMITTED');
      await expect(panel, 'the SUBMITTED panel opens').toBeVisible();
      for (const h of [/What is happening now/, /Who acts/, /Deadline/, /What you can do/, /cannot see/i]) {
        await expect(panel.getByRole('heading', { name: h }), `the panel part ${h.source}`).toHaveCount(1);
      }
      expect(new URL(page.url()).pathname, 'no other page').toBe(new URL(before).pathname);

      // Reduced motion stops the ring.
      const ring = svg.locator('.current-ring');
      await expect(ring).toHaveCount(1);
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      expect(await ring.evaluate((e) => getComputedStyle(e).animationName), 'the ring pulses').not.toBe('none');
      await page.emulateMedia({ reducedMotion: 'reduce' });
      expect(await ring.evaluate((e) => getComputedStyle(e).animationName), 'R-NF-03: the ring stops').toBe('none');
      await page.emulateMedia({ reducedMotion: 'no-preference' });

      // The activity log, from the proposal page.
      await page.goBack();
      await page.waitForURL((u) => u.pathname === `/app/proposals/${X.id}`);
      await settle(page);
      await clickTo(page, /^Activity$/, new RegExp(`^/app/proposals/${X.id}/activity$`), 'proposal page');
      await expect(page.locator('main h1')).toHaveText('Activity log');
      const entries = page.locator('main ol.diary > li');
      expect(await entries.count(), 'the log lists the route so far').toBeGreaterThanOrEqual(3);
      // The scene records reviewer questions after the move, so the move is
      // listed but is not the newest entry. Newest first is checked on every
      // entry's machine time instead (I-93).
      await expect(
        entries.filter({ hasText: 'Stage 1 evaluation (STAGE1) to Stage 2 questions (STAGE2)' }),
        'the move into STAGE2',
      ).toHaveCount(1);
      await expect(entries.filter({ hasText: 'Anchor pending' }), 'R-JV-04, O-56: the receipt').toHaveCount(1);
      await expect(entries.filter({ hasText: /Your consent/ }), 'O-60: no guardian step for the lead').toHaveCount(0);
      const times: string[] = [];
      for (const t of await entries.locator('time').all()) {
        const at = (await t.getAttribute('datetime')) ?? '';
        expect(at, 'each entry has a machine time').toMatch(/^\d{4}-\d{2}-\d{2}T/);
        times.push(at);
      }
      expect(times.length, 'every entry has a time').toBe(await entries.count());
      for (let i = 1; i < times.length; i += 1) {
        expect(Date.parse(times[i - 1]), `I-93: newest first at entry ${i}`).toBeGreaterThanOrEqual(Date.parse(times[i]));
      }
      expect(who.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** Section 8.3, R-JV-03: an assigned reviewer sees where the proposal is. */
  test('r_jv_03_reviewer_sees_where_the_proposal_is', async ({ browser }) => {
    const who = await signIn(browser, '/demo/review?stage=stage2', DOOR.r1);
    const { page } = who;
    try {
      await clickTo(page, /review assignments/i, /^\/app\/me\/assignments$/, 'home');
      await clickHref(page, '/app/assignments/', /^\/app\/assignments\/\d+/, 'assignments');
      const strip = page.getByRole('region', { name: 'Proposal status' });
      await expect(strip, 'the strip').toBeVisible();
      await expect(strip.locator('ol > li')).toHaveCount(10);
      await expect(strip.locator('li[aria-current="step"]')).toContainText('(STAGE2)');

      // Review J3-R2: the reviewer reads the route, yet is not on the team.
      // No link reaches the progress page for them. Opened by URL, it shows
      // the strip the read gives and the refusal, with no map, no list and
      // no withdrawal.
      const assignment = /^\/app\/assignments\/(\d+)/.exec(new URL(page.url()).pathname)?.[1] ?? "";
      const proposal = await page.evaluate(async (a) => {
        const res = await fetch("/api/v1/me/assignments", { credentials: "same-origin" });
        const rows = (await res.json()) as { assignment: string; proposal: string }[];
        return rows.find((r) => r.assignment === a)?.proposal ?? "";
      }, assignment);
      expect(proposal, "the assignment names its proposal").not.toBe("");
      await page.goto(new URL(`/app/proposals/${proposal}/progress`, page.url()).href);
      await settle(page);
      await expect(page.locator("main svg[role=\"group\"]"), "no route map").toHaveCount(0);
      await expect(page.locator("#journey-list, #journey-help, #journey-withdraw"), "no list, panels or withdrawal").toHaveCount(0);
      await expect(page.getByRole("region", { name: "Proposal status" }), "the strip the read gives").toBeVisible();
      await expect(page.locator("main")).toContainText("cannot be shown to you");
      expect(who.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** O-58: an IRC member gets no route strip on any IRC page. */
  test('r_jv_03_o58_irc_member_sees_no_strip', async ({ browser }) => {
    const who = await signIn(browser, '/demo/review?stage=irc_review', DOOR.i1);
    const { page } = who;
    try {
      await clickTo(page, /IRC cases/i, /^\/app\/me\/irc-cases$/, 'home');
      await expect(page.getByRole('region', { name: 'Proposal status' })).toHaveCount(0);
      await expect(page.locator('ol.strip, svg[role="group"]')).toHaveCount(0);
      await clickHref(page, '/app/irc-assignments/', /^\/app\/irc-assignments\/\d+/, 'IRC cases');
      await expect(page.getByRole('region', { name: 'Proposal status' })).toHaveCount(0);
      await expect(page.locator('ol.strip, svg[role="group"]')).toHaveCount(0);
      expect(who.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** O-60, R-JV-03, the click-through rule: the guardian reaches their consent steps. */
  test('r_jv_03_o60_guardian_reaches_the_activity_log', async ({ browser }) => {
    const who = await signIn(browser, '/demo/applicant?at=IRC_REVIEW_MINOR', GUARDIAN);
    const { page } = who;
    try {
      const guardianLink = page.locator('main a[href^="/app/proposals/"][href$="/guardian"]').first();
      await expect(guardianLink, 'the home page links the guardian page').toBeVisible();
      const guardianHref = (await guardianLink.getAttribute('href')) ?? '';
      const proposal = /^\/app\/proposals\/(\d+)\/guardian$/.exec(guardianHref)?.[1] ?? '';
      expect(proposal, 'the guardian page names a proposal').not.toBe('');
      const activity = new RegExp(`^/app/proposals/${proposal}/activity$`);
      const steps = page.locator('main ol.diary > li').filter({ hasText: 'Guardian step' });

      // From the home page.
      await clickTo(page, /^Activity$/, activity, 'home');
      await expect(steps, 'O-60: the read gives the guardian their step').not.toHaveCount(0);

      // From the guardian page, which the home page links to.
      await page.goBack();
      await page.waitForURL((u) => u.pathname === HOME);
      await settle(page);
      await clickHref(page, guardianHref, new RegExp(`^${guardianHref}$`), 'home');
      await clickTo(page, /^Activity$/, activity, 'guardian page');
      await expect(steps, 'O-60: the same log').not.toHaveCount(0);
      expect(who.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await who.close();
    }
  });
});
