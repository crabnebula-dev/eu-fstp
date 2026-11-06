/**
 * The server-rendered progress map against `fstp-e2e-cell` (ADR-015
 * amendment of 2026-11-06; `SPEC/12-journey-ui.md` sections 6, 8.1 and
 * 8.3; review J3-R2; the click-through rule; lane j4).
 *
 * - r_jv_01_adr015_applicant_reaches_the_server_map_by_clicking: the
 *   demo lead of the STAGE2 applicant scene signs in with one click,
 *   opens the proposal, then "Progress". The page reads
 *   `proposal.route_map`, and the map it draws is the reply's tree: the
 *   same node names, in the same order, with the reply's statuses. The
 *   lead sees the withdrawal. The page asks no `proposal.list_own`.
 * - r_jv_03_j3r2_reviewer_progress_url_shows_no_map: an assigned reviewer
 *   of the stage 2 scene opens the progress URL of the proposal they
 *   review. The journey read gives no map, so no map, list, help panel or
 *   withdrawal shows, and no route map tree reaches the page.
 *
 * Every page reached is checked for console errors and CSP violations.
 * Run with `tools/demo/run.sh e2e journey/` against the lane's cell.
 * Every person, proposal and text is synthetic. Lane j4 test author: red
 * until the read and the page are built.
 */

import { expect, type Browser, type Page, type Response } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell, watchProblems, type PageProblem } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The seeded proposal x of the applicant scenes (`scenario.rs` `PROPOSALS`). */
const X = { id: '1001', title: 'Synthetic open sensor kit' } as const;

/** The status words that end a node's accessible name, by the reply's status. */
const WORDS: Readonly<Record<string, string>> = {
  completed: 'completed',
  current: 'current stage',
  upcoming: 'upcoming',
  pause: 'possible pause, returns at the stage it left',
  positive_end: 'upcoming, final outcome',
  negative_end: 'possible final outcome',
};

/** Signs `who` in from the front door of `scene`, and keeps every API response the page receives. */
async function signIn(
  browser: Browser,
  scene: string,
  who: RegExp,
): Promise<{ page: Page; responses: Response[]; problems: () => readonly PageProblem[]; close: () => Promise<void> }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(scene);
  const href = await door.signIn(who).getAttribute('href');
  await door.close();
  expect(href, `the front door offers "Sign in as" for ${who.source}`).not.toBeNull();
  const context = await browser.newContext();
  const watch = await watchProblems(context);
  const page = await context.newPage();
  const responses: Response[] = [];
  page.on('response', (r) => {
    if (new URL(r.url()).pathname.startsWith('/api/')) {
      responses.push(r);
    }
  });
  await page.goto(new URL(href ?? '', cell.control).href);
  await page.waitForURL((u) => u.origin === cell.origin && u.pathname === HOME);
  await settle(page);
  return { page, responses, problems: watch.problems, close: () => context.close() };
}

async function clickTo(page: Page, name: RegExp, path: RegExp, why: string): Promise<void> {
  const link = page.locator('main').getByRole('link', { name }).first();
  await expect(link, `${why}: the link ${name.source}`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
}

function pathOf(r: Response): string {
  return new URL(r.url()).pathname;
}

test.describe('server-rendered progress map', () => {
  test.describe.configure({ timeout: 240_000 });

  /** ADR-015 amendment, R-JV-01, R-JV-05, section 8.1, NOTE 10, the click-through rule. */
  test('r_jv_01_adr015_applicant_reaches_the_server_map_by_clicking', async ({ browser }) => {
    const who = await signIn(browser, '/demo/applicant?at=STAGE2', DOOR.leadX);
    const { page } = who;
    try {
      await clickTo(page, new RegExp(X.title), new RegExp(`^/app/proposals/${X.id}$`), 'home');
      const mapRead = page.waitForResponse((r) => pathOf(r).endsWith(`/proposals/${X.id}/route-map`));
      // Home and the proposal page read proposal.list_own. The check below
      // covers only what the progress page reads.
      who.responses.length = 0;
      await clickTo(page, /^Progress$/, new RegExp(`^/app/proposals/${X.id}/progress$`), 'proposal page');
      const reply = await mapRead;
      expect(reply.status(), 'the lead reads the route map').toBe(200);
      const body = (await reply.json()) as {
        tree: unknown;
        nodes: { state: string; status: string }[];
      };

      const svg = page.locator('main svg[role="group"]');
      await expect(svg, 'the map').toHaveCount(1);
      const names = await svg.locator('a').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') ?? ''));
      expect(names.length, 'one link per node').toBe(body.nodes.length);
      body.nodes.forEach((n, i) => {
        const name = names[i] ?? '';
        expect(name, `node ${i} is ${n.state}, ${n.status}`).toContain(`(${n.state}), ${WORDS[n.status] ?? '?'}`);
      });

      // The drawn map is the reply's tree: the same elements in the same
      // order, with the same texts.
      const drawn = await svg.evaluate((root) => {
        const walk = (e: Element): unknown => ({
          tag: e.localName,
          children: [...e.childNodes].map((c) => (c.nodeType === 3 ? { text: c.textContent ?? '' } : walk(c as Element))),
        });
        return walk(root);
      });
      const strip = (v: unknown): unknown => {
        const o = v as { tag?: string; text?: string; children?: unknown[] };
        return o.tag === undefined ? { text: o.text } : { tag: o.tag, children: (o.children ?? []).map(strip) };
      };
      expect(drawn, 'the page draws the server tree').toEqual(strip(body.tree));

      await expect(page.locator('#journey-list'), 'the list').toHaveCount(1);
      await expect(page.locator('#journey-help'), 'the help panels').toHaveCount(1);
      await expect(page.locator('#journey-withdraw'), 'NOTE 10: the lead sees the withdrawal').toHaveCount(1);
      expect(who.responses.some((r) => pathOf(r).endsWith('/me/proposals')), 'J3-R2: no proposal.list_own read').toBe(false);
      expect(who.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await who.close();
    }
  });

  /** Section 8.3, review J3-R2, O-58. */
  test('r_jv_03_j3r2_reviewer_progress_url_shows_no_map', async ({ browser }) => {
    const who = await signIn(browser, '/demo/review?stage=stage2', DOOR.r1);
    const { page } = who;
    try {
      await clickTo(page, /review assignments/i, /^\/app\/me\/assignments$/, 'home');
      const first = page.locator('main a[href^="/app/assignments/"]').first();
      await expect(first, 'an assignment').toBeVisible();
      await first.click();
      await page.waitForURL((u) => /^\/app\/assignments\/\d+/.test(u.pathname));
      await settle(page);
      const assignment = /^\/app\/assignments\/(\d+)/.exec(new URL(page.url()).pathname)?.[1] ?? '';
      const proposal = await page.evaluate(async (a) => {
        const res = await fetch('/api/v1/me/assignments', { credentials: 'same-origin' });
        const rows = (await res.json()) as { assignment: string; proposal: string }[];
        return rows.find((r) => r.assignment === a)?.proposal ?? '';
      }, assignment);
      expect(proposal, 'the assignment names its proposal').not.toBe('');

      const journey = page.waitForResponse((r) => pathOf(r).endsWith(`/proposals/${proposal}/journey`));
      await page.goto(new URL(`/app/proposals/${proposal}/progress`, page.url()).href);
      const j = await journey;
      await settle(page);
      expect(j.status(), 'the reviewer reads the route').toBe(200);
      const flags = (await j.json()) as { map?: unknown; withdraw?: unknown; strip?: unknown };
      expect(flags.map, 'section 8.3: the read gives the reviewer no map').toBe(false);
      expect(flags.withdraw, 'NOTE 10: nor the withdrawal').toBe(false);
      expect(flags.strip, 'section 8.3: the strip').toBe(true);

      await expect(page.locator('main svg[role="group"]'), 'no route map').toHaveCount(0);
      await expect(page.locator('#journey-map, #journey-list, #journey-help, #journey-withdraw'), 'no map, list, panels or withdrawal').toHaveCount(0);
      await expect(page.getByRole('region', { name: 'Proposal status' }), 'the strip the read gives').toBeVisible();
      const trees = who.responses.filter((r) => pathOf(r).endsWith(`/proposals/${proposal}/route-map`) && r.status() === 200);
      expect(trees.length, 'no route map tree reaches the reviewer').toBe(0);
      expect(who.problems(), 'no console error or CSP violation').toEqual([]);
    } finally {
      await who.close();
    }
  });
});
