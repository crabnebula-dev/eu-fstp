/**
 * The mail of the demo cell (M6 design section 8, lane L6-DEMO): the
 * real timeline task, dispatcher and SMTP client send to the test sink
 * over TLS. Each person starts from the demo page and follows links
 * only. Covers R-SB-04, R-IR-02 (email), R-NT-03, I-25, I-26 and I-27.
 *
 * Not covered here, with the reason in `docs/handoff/m6-demo.md`: the
 * P-05 tightening with its corrigendum mail (the studio edit has no
 * wire-level step in the demo yet), the milestone reminders and the
 * contract notice mails (the timeline has no source for them yet).
 * Every person and text is synthetic.
 */

import { expect, type Browser, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { DOOR, FrontDoor, suiteCell } from '../site/contract';
import type { CellEndpoints } from '../creator/contract';
import { Seat } from '../speedrun/support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

const ROWS = '#demo-mail li[data-demo-mail]';

/** The mail rows of the demo page, read afresh. */
async function mailRows(page: Page, cell: CellEndpoints): Promise<{ text: string; phase: string; raw: string | null }[]> {
  await page.goto(`${cell.control}/demo`);
  const out: { text: string; phase: string; raw: string | null }[] = [];
  for (const li of await page.locator(ROWS).all()) {
    out.push({
      text: (await li.innerText()).trim(),
      phase: (await li.getAttribute('data-phase')) ?? '',
      raw: (await li.locator('a').count()) > 0 ? await li.locator('a').first().getAttribute('href') : null,
    });
  }
  return out;
}

async function untilRows(
  page: Page,
  cell: CellEndpoints,
  what: string,
  ok: (rows: { text: string; phase: string }[]) => boolean,
): Promise<{ text: string; phase: string; raw: string | null }[]> {
  await expect
    .poll(async () => ok(await mailRows(page, cell)), { message: what, timeout: 30_000, intervals: [500, 1000] })
    .toBe(true);
  return mailRows(page, cell);
}

async function scene(browser: Browser, href: string): Promise<{ cell: CellEndpoints; door: FrontDoor }> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  await door.chooseScene(href);
  return { cell, door };
}

test.describe('mail through the dispatcher', () => {
  test.describe.configure({ timeout: 240_000 });

  /** R-IR-02, I-27: the concern notice mail names ids and a link, never the concern text. */
  test('i27_irc_concern_mail_holds_ids_and_a_link_only', async ({ browser }) => {
    const { cell, door } = await scene(browser, '/demo/applicant?at=DEFERRED_AFTER_CONCERN');
    const rows = await untilRows(door.page, cell, 'the concern mail is sent', (r) => r.some((x) => x.phase === 'SENT'));
    const sent = rows.find((r) => r.phase === 'SENT');
    expect(sent?.raw, 'the row links the raw message').toBeTruthy();
    await door.page.goto(new URL(sent?.raw ?? '', cell.control).href);
    const raw = await door.page.locator('#raw-message').innerText();
    expect(raw).toContain('/app/notices');
    expect(raw).toContain('X-FSTP-Event:');
    expect(raw, 'I-27: the concern text stays on the platform').not.toMatch(/frugal|Synthetic concern/i);
    await door.close();
  });

  /** R-SB-04: the applicant requests a copy, and the demo page lists the mail to the given address. */
  test('r_sb_04_applicant_requests_a_copy_and_the_mail_is_listed', async ({ browser }) => {
    const { cell, door } = await scene(browser, '/demo/applicant?at=STAGE2');
    const lead = await Seat.signIn(browser, cell, DOOR.leadX);
    const before = (await mailRows(door.page, cell)).length;
    await lead.ok('POST', '/proposals/1001/copy', { email: 'copy@e2e.invalid' });
    const rows = await untilRows(door.page, cell, 'the copy mail is sent', (r) => r.length > before && r.every((x) => x.phase === 'SENT'));
    expect(rows.length).toBe(before + 1);
    const last = rows[rows.length - 1];
    await door.page.goto(new URL(last?.raw ?? '', cell.control).href);
    const raw = await door.page.locator('#raw-message').innerText();
    expect(raw).toMatch(/To: <requested-copy@e2e\.invalid>/);
    expect(raw, 'I-27: no narrative in the mail').not.toContain('SYNTHETIC-CONTENT-CANARY');
    await lead.close();
    await door.close();
  });

  /** I-26: a 451 refusal is retried after its backoff, and the message is sent once. */
  test('i26_a_451_refusal_is_retried_and_sent_once', async ({ browser }) => {
    const { cell, door } = await scene(browser, '/demo/applicant?at=STAGE2');
    const lead = await Seat.signIn(browser, cell, DOOR.leadX);
    await door.page.goto(`${cell.control}/demo/mail/fault?kind=refuse451`);
    await lead.ok('POST', '/proposals/1001/copy', { email: 'copy@e2e.invalid' });
    await untilRows(door.page, cell, 'the refused message shows TRANSIENT', (r) => r.some((x) => x.phase === 'TRANSIENT'));
    // The dispatcher keeps the cell clock: after the backoff it tries again.
    await door.page.goto(`${cell.control}/demo/advance?minutes=60`);
    const rows = await untilRows(door.page, cell, 'the retry is sent', (r) => r.some((x) => x.phase === 'SENT'));
    expect(rows.filter((r) => r.phase === 'SENT').length).toBe(1);
    await lead.close();
    await door.close();
  });

  /** I-25, I-26: an accepted message whose reply is lost is never sent again; it shows IN_DOUBT. */
  test('i26_a_lost_reply_ends_in_doubt_and_is_never_resent', async ({ browser }) => {
    const { cell, door } = await scene(browser, '/demo/applicant?at=STAGE2');
    const lead = await Seat.signIn(browser, cell, DOOR.leadX);
    await door.page.goto(`${cell.control}/demo/mail/fault?kind=lose_reply`);
    await lead.ok('POST', '/proposals/1001/copy', { email: 'copy@e2e.invalid' });
    await untilRows(door.page, cell, 'the message is committing', (r) => r.some((x) => x.phase === 'COMMITTING'));
    await door.page.goto(`${cell.control}/demo/advance?minutes=60`);
    const rows = await untilRows(door.page, cell, 'the message shows IN_DOUBT', (r) => r.some((x) => x.phase === 'IN_DOUBT'));
    expect(rows.length).toBe(1);
    await door.page.goto(`${cell.control}/demo/advance?minutes=1440`);
    await door.page.waitForTimeout(2500);
    expect((await mailRows(door.page, cell)).length, 'the sink holds the message once').toBe(1);
    await lead.close();
    await door.close();
  });
});
