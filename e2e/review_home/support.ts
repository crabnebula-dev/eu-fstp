/**
 * Waits of the review_home specs, kept here so the shared navigation
 * helpers stay as they are.
 */

import { expect, type Page, type Request } from '@playwright/test';

/**
 * Waits until the SA-09 shell has asked the page gate for every link of
 * the page. A link stays in the page, hidden, while its answer is
 * pending (`web/src/shell/gate.ts` `PENDING`), and a closed page's link
 * is then removed. Counting or reading links before that can see a link
 * the gate is about to remove.
 */
export async function gateSettled(page: Page): Promise<void> {
  await expect(page.locator('a[data-page-gate]'), 'the page gate answered for every link').toHaveCount(0);
}

/**
 * Tracks the API requests `page` has in flight. `idle()` waits until
 * every one of them finished or failed. After an in-app navigation,
 * `waitForLoadState('networkidle')` returns at once, since the document
 * reached that state long before, so it does not wait for the new
 * page's reads.
 */
export function apiReads(page: Page): { readonly idle: () => Promise<void>; readonly stop: () => void } {
  const open = new Set<Request>();
  const started = (q: Request): void => {
    if (new URL(q.url()).pathname.startsWith('/api/')) open.add(q);
  };
  const ended = (q: Request): void => {
    open.delete(q);
  };
  page.on('request', started);
  page.on('requestfinished', ended);
  page.on('requestfailed', ended);
  return {
    idle: async () => {
      await expect
        .poll(() => [...open].map((q) => `${q.method()} ${new URL(q.url()).pathname}`), {
          message: 'the page finished its API reads',
        })
        .toEqual([]);
    },
    stop: () => {
      page.off('request', started);
      page.off('requestfinished', ended);
      page.off('requestfailed', ended);
    },
  };
}
