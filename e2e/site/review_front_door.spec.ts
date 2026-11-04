/**
 * Review reproducer (lane m4/site, independent review of 2026-11-04).
 * It fails against the lane's working tree and passes once fixed.
 *
 * i70_review_front_door_keeps_keyboard_focus: the demo front door
 * (`GET /demo`, scope item 7) carries `<meta http-equiv="refresh"
 * content="10">`. Every ten seconds the document loads again, so a
 * keyboard or screen reader user who tabbed to a person's link loses
 * their place and hears the page from the top (WCAG 2.2 SC 2.2.1, a
 * timed refresh with no way to turn it off, failure F41; SC 2.4.3).
 * The front door is now the one page Daniel shares to start the demo.
 *
 * Every person and value is synthetic.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { FrontDoor, suiteCell } from './contract';

test.describe('review: demo front door', () => {
  test.describe.configure({ timeout: 120_000 });

  /** I-70, R-NF-03 (WCAG 2.2 SC 2.2.1, 2.4.3): focus on a front door link stays put while the person reads. */
  test('i70_review_front_door_keeps_keyboard_focus', async ({ browser }) => {
    const door = await FrontDoor.open(browser, suiteCell());
    try {
      const page = door.page;
      const link = door.items().nth(2).locator('a').first();
      await expect(link).toBeVisible();
      const href = (await link.getAttribute('href')) ?? '';
      await link.focus();
      await page.evaluate(() => {
        (window as unknown as Record<string, unknown>)['fstpReviewMarker'] = 'kept';
      });
      // Longer than the ten-second refresh of the page.
      await page.waitForTimeout(12_000);
      const marker = await page.evaluate(() => (window as unknown as Record<string, unknown>)['fstpReviewMarker'] ?? null);
      expect(marker, 'the front door does not load itself again while the person reads it').toBe('kept');
      const focused = await page.evaluate(() => document.activeElement?.getAttribute('href') ?? null);
      expect(focused, 'keyboard focus stays on the link the person reached').toBe(href);
    } finally {
      await door.close();
    }
  });
});
