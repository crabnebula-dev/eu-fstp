/**
 * The demo page answers while mail is in flight (I-27 demo, the flake of
 * `i27_irc_concern_mail_holds_ids_and_a_link_only`). The cause was a
 * request handler that waited for the mail mirror on a runtime worker,
 * while the mirror's holder waited for the I/O driver that the worker
 * should have turned. Many readers at once, while the concern mail is
 * sent, must all be answered and the mail must still be sent.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { FrontDoor, suiteCell } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

test.describe('mail in flight', () => {
  test.describe.configure({ timeout: 120_000 });

  test('i27_demo_page_answers_many_readers_while_the_concern_mail_is_sent', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    await door.chooseScene('/demo/applicant?at=DEFERRED_AFTER_CONCERN');
    const url = `${cell.control}/demo`;
    const readers = Array.from({ length: 8 }, async () => {
      for (let i = 0; i < 25; i += 1) {
        const r = await door.page.request.get(url, { timeout: 20_000 });
        expect(r.status(), 'the demo page answers').toBe(200);
      }
    });
    await Promise.all(readers);
    await expect
      .poll(async () => (await (await door.page.request.get(url, { timeout: 20_000 })).text()).includes('data-phase="SENT"'), {
        message: 'the concern mail is sent',
        timeout: 30_000,
        intervals: [500, 1000],
      })
      .toBe(true);
    await door.close();
  });
});
