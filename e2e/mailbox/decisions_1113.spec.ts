/**
 * The mailbox decisions of 2026-11-13 (`docs/handoff/mailbox-design.md`,
 * "Decided by Daniel on 2026-11-13"), reached by clicking from the demo
 * sign-in (R-NF-03):
 *
 * - MB-Q1, ADR-020: the lead of a NOT_SELECTED proposal marks its outcome
 *   notice read on the mailbox page, and the mark shows after the reload.
 * - MB-Q2, R-EV-05: the lead in stage 2 sees one message per unanswered
 *   question, each naming its question.
 * - MB-Q3: a staff member sees the grant of their role as a notice, and
 *   its link opens the home page that lists their roles.
 *
 * No page holds an email address (I-86), and every link is an `/app/`
 * path (I-27). Every person and text is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { HOME, settle } from '../navigation/support';
import { DEMO_SIGNIN_FLAG, DOOR, FrontDoor, OwnCell, SITE } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

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

/** Chooses `scene`, signs `who` in, and clicks from home to the mailbox. */
async function mailboxOf(browser: Browser, own: OwnCell, scene: string, who: RegExp): Promise<Page> {
  const door = await FrontDoor.open(browser, own.cell);
  try {
    await door.chooseScene(scene);
  } finally {
    await door.close();
  }
  const page = await signIn(browser, own, who);
  await page.waitForURL((u) => u.origin === own.cell.origin && u.pathname === HOME);
  await settle(page);
  await page.locator('#home-mailbox a[data-mailbox-link]').click();
  await page.waitForURL((u) => u.pathname === '/app/mailbox');
  await settle(page);
  expect((await page.content()).includes('@e2e.invalid'), 'I-86: no address on the mailbox page').toBe(false);
  return page;
}

test.describe('mailbox decisions of 2026-11-13', () => {
  test.describe.configure({ timeout: 600_000 });
  let own: OwnCell | null = null;
  test.beforeAll(async () => {
    own = await OwnCell.start([DEMO_SIGNIN_FLAG]);
  });
  test.afterAll(async () => {
    await own?.stop();
    own = null;
  });

  test('adr020_i86_lead_marks_the_outcome_notice_read', async ({ browser }) => {
    if (own === null) throw new Error('the cell did not start');
    const page = await mailboxOf(browser, own, '/demo/applicant?at=NOT_SELECTED', DOOR.leadX);
    const notice = page.locator('#mailbox-notice-list li[data-kind="notice.outcome"]');
    await expect(notice.locator('[data-read]')).toHaveAttribute('data-read', 'false');
    await notice.locator('button[data-mark-read]').click();
    await expect(page.locator('#mailbox-notice-list li[data-kind="notice.outcome"] [data-read]')).toHaveAttribute('data-read', 'true');
    await expect(page.locator('#mailbox-notice-list li[data-kind="notice.outcome"] button[data-mark-read]')).toHaveCount(0);
    await page.context().close();
  });

  test('r_ev_05_lead_sees_one_message_per_unanswered_question', async ({ browser }) => {
    if (own === null) throw new Error('the cell did not start');
    const page = await mailboxOf(browser, own, '/demo/applicant?at=STAGE2', DOOR.leadX);
    const items = page.locator('#mailbox-list li[data-kind="stage2.respond"]');
    await expect(items).toHaveCount(2);
    await expect(items.nth(0)).toContainText(/Answer question 1 on proposal \d+/);
    await expect(items.nth(1)).toContainText(/Answer question 2 on proposal \d+/);
    const href = await items.first().locator('a').getAttribute('href');
    expect(href, 'I-27: an /app/ path').toMatch(/^\/app\/proposals\/\d+\/stage2$/);
    await items.first().locator('a').click();
    await page.waitForURL((u) => u.pathname === href);
    await page.context().close();
  });

  test('sod09_mb_q3_staff_member_sees_the_role_grant_as_a_notice', async ({ browser }) => {
    if (own === null) throw new Error('the cell did not start');
    const page = await mailboxOf(browser, own, '/demo/review?stage=submitted', DOOR.c1);
    const grant = page.locator('#mailbox-notice-list li[data-kind="role.granted"]').first();
    await expect(grant).toContainText(/You hold a new role in programme \d+/);
    await expect(grant.locator('[data-read]')).toHaveAttribute('data-read', 'false');
    await grant.locator('a').click();
    await page.waitForURL((u) => u.pathname === HOME);
    await page.context().close();
  });
});
