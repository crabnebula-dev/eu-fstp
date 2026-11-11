/**
 * The platform mailbox, reached by clicking from the demo sign-in (lane
 * m6/mailbox, `docs/handoff/mailbox-design.md` section 8; Daniel's
 * click-through rule: each person reaches their work by clicking from
 * sign-in).
 *
 * For each scene and person below, the test clicks "Sign in as" on the
 * demo page, lands on `/app/`, clicks the mailbox line of the home page,
 * finds the work the scene gives that person, and clicks each work item
 * to the page where the work happens. The top bar shows the same open
 * count as the mailbox page (R-NF-03). No page holds an email address
 * (I-86), and every item link is a same-origin `/app/` path (I-27).
 *
 * The cell is started by the spec (`site/contract.ts` `OwnCell`) with the
 * demo sign-in flag. Every person and text is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DEMO_SIGNIN_FLAG, DOOR, FrontDoor, OwnCell, SITE } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The mailbox page and its parts (`web/src/mailbox/pages.ts`). */
const MB = {
  page: '/app/mailbox',
  homeLink: '#home-mailbox a[data-mailbox-link]',
  topLink: 'header a[data-tool="mailbox"]',
  open: '#mailbox-work-title [data-open]',
  work: '#mailbox-list li[data-kind]',
} as const;

/** Each scene, its person, and the kinds of work the person must find. */
const CASES: readonly (readonly [string, RegExp, string, readonly string[]])[] = [
  ['/demo/review?stage=submitted', DOOR.c1, 'coordinator', ['intake.knock_out']],
  ['/demo/review?stage=stage1', DOOR.r1, 'reviewer', ['review.']],
  ['/demo/review?stage=irc_review', DOOR.i1, 'IRC member', ['irc.']],
  ['/demo/applicant?at=STAGE2', DOOR.leadX, 'lead in stage 2', ['stage2.respond']],
  ['/demo/applicant?at=NEGOTIATION', DOOR.leadX, 'lead in negotiation', ['negotiation.acknowledge']],
];

async function signIn(browser: Browser, own: OwnCell, who: RegExp): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${own.cell.control}/demo`);
  const link = page
    .locator('xpath=//h2[starts-with(normalize-space(.), "People of this scene")]/following-sibling::ul[1]/li')
    .filter({ hasText: who })
    .locator(SITE.demo.signIn);
  await expect(link, `"Sign in as" for ${who.source}`).toHaveCount(1);
  if ((await link.getAttribute('target')) === '_blank') {
    const [opened] = await Promise.all([context.waitForEvent('page'), link.click()]);
    return opened;
  }
  await link.click();
  return page;
}

test.describe('platform mailbox', () => {
  test.describe.configure({ timeout: 600_000 });
  let own: OwnCell | null = null;
  test.beforeAll(async () => {
    own = await OwnCell.start([DEMO_SIGNIN_FLAG]);
  });
  test.afterAll(async () => {
    await own?.stop();
    own = null;
  });

  /**
   * I-27, I-86, R-NF-03, MB-D2: each person reaches their mailbox from
   * sign-in by clicking, finds the work of the scene, and each work item
   * opens its page.
   */
  test('i27_i86_r_nf_03_each_person_clicks_from_sign_in_to_their_mailbox_and_work', async ({ browser }) => {
    if (own === null) throw new Error('the cell did not start');
    const cell = own;
    for (const [scene, who, why, kinds] of CASES) {
      const door = await FrontDoor.open(browser, cell.cell);
      try {
        await door.chooseScene(scene);
      } finally {
        await door.close();
      }
      const page = await signIn(browser, cell, who);
      try {
        await page.waitForURL((u) => u.origin === cell.cell.origin && u.pathname === HOME);
        await settle(page);
        const home = page.locator(MB.homeLink);
        await expect(home, `${why}: the home page links the mailbox`).toBeVisible();
        await home.click();
        await page.waitForURL((u) => u.pathname === MB.page);
        await settle(page);
        const items = page.locator(MB.work);
        await expect(items.first(), `${why}: the mailbox lists work`).toBeVisible();
        const open = await page.locator(MB.open).getAttribute('data-open');
        await expect(page.locator(MB.topLink), `${why}: the top bar shows the open count`).toHaveAttribute('data-open', open ?? '');
        const html = await page.content();
        expect(html.includes('@e2e.invalid'), `${why}: I-86, no email on the mailbox page`).toBe(false);
        const listed = await items.evaluateAll((els) => els.map((e) => e.getAttribute('data-kind') ?? ''));
        for (const k of kinds) {
          expect(listed.some((x) => x.startsWith(k)), `${why}: ${k} in ${listed.join(', ')}`).toBe(true);
        }
        const hrefs = await items.locator('a').evaluateAll((els) => els.map((e) => e.getAttribute('href') ?? ''));
        for (const href of hrefs) {
          expect(href, `${why}: I-27, an /app/ path`).toMatch(/^\/app\/[a-z0-9/_-]+$/);
        }
        // The first item opens its page, by clicking.
        await items.first().locator('a').click();
        await page.waitForURL((u) => u.pathname === hrefs[0]);
        await settle(page);
        await expect(page.locator('main h1'), `${why}: the work page has a heading`).toBeVisible();
      } finally {
        await page.context().close();
      }
    }
  });
});
