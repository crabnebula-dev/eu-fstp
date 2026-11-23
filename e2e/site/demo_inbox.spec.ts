/**
 * The demo inbox of `fstp-e2e-cell` (ADR-008 record of lane L37; Daniel,
 * 2026-11-22). Test only: the cell is the test-only binary of layering
 * rule A9, started with `--demo-signin`.
 *
 * - demo_inbox_click_through: a person starts on the demo front door and
 *   reaches every email link by clicking. From the front door to the
 *   demo inbox, to the sign-up page. The sign-up email lands on the
 *   inbox with its code, which finishes the registration. On the passkey
 *   offer, "Send me a link" lands a passkey link on the inbox, which
 *   opens the recovery page and creates a passkey. On the sign-in page,
 *   "Send me a link" lands a sign-in link there, which signs the person
 *   in.
 * - demo_inbox_absent_without_flag: the cell started without the flag
 *   answers 404 on `/demo/inbox`, and its front door names no inbox.
 *
 * Every address is synthetic.
 */

import { expect, type BrowserContext, type Page } from '@playwright/test';
import { VirtualAuthenticator, test } from '../playwright.config';
import { HOME } from '../navigation/support';
import { DEMO_SIGNIN_FLAG, FrontDoor, OwnCell } from './contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** Opens the link `link` of `page` in the new tab it opens, and gives the tab. */
async function follow(context: BrowserContext, link: ReturnType<Page['locator']>): Promise<Page> {
  const [tab] = await Promise.all([context.waitForEvent('page'), link.click()]);
  await tab.waitForLoadState('load');
  return tab;
}

/** Refreshes the inbox by its own link, as the page tells a person to. */
async function refresh(inbox: Page): Promise<void> {
  await inbox.locator('main a[href="/demo/inbox"]').click();
  await expect(inbox.locator('h1')).toHaveText('Demo inbox');
}

test.describe('demo inbox', () => {
  test.describe.configure({ timeout: 180_000 });

  test('demo_inbox_click_through', async ({ browser }) => {
    const own = await OwnCell.start([DEMO_SIGNIN_FLAG]);
    const email = `inbox-${Date.now()}@e2e.invalid`;
    try {
      const door = await FrontDoor.open(browser, own.cell);
      const inbox = door.page;
      await inbox.locator('a[data-demo-link="inbox"]').click();
      await expect(inbox.locator('h1')).toHaveText('Demo inbox');
      await expect(inbox.locator('#demo-inbox-empty')).toBeVisible();

      // Sign up: the email lands on the inbox with its link and code.
      const tab = await follow(door.context, inbox.locator(`main a[href="${own.cell.origin}/auth/signup"]`));
      await tab.locator('#signup-email').fill(email);
      await tab.locator('#signup-submit').click();
      await expect(tab.locator('#signup-code')).toBeVisible();
      await refresh(inbox);
      const signup = inbox.locator('li[data-demo-mail="signup"]');
      await expect(signup).toContainText(email);
      await expect(signup.locator('a[data-demo-mail-link]')).toHaveAttribute('href', new RegExp(`^${own.cell.origin}/auth/signup#[0-9a-f]{64}$`));
      const code = (await signup.locator('[data-demo-code]').textContent()) ?? '';
      expect(code, 'ADR-008: a 6-digit code').toMatch(/^[0-9]{6}$/);
      await tab.locator('#signup-code').fill(code);
      await tab.locator('#signup-code-submit').click();
      await tab.locator('#signup-finish').click();

      // The passkey offer: "Send me a link" lands a passkey link.
      await tab.locator('#offer-send').click();
      await expect(tab.locator('#offer-continue')).toBeVisible();
      await refresh(inbox);
      const passkey = inbox.locator('li[data-demo-mail="passkey_link"]');
      await expect(passkey).toContainText(email);
      const recovery = await follow(door.context, passkey.locator('a[data-demo-mail-link]'));
      await VirtualAuthenticator.attach(recovery);
      await recovery.locator('#recovery-proof').click();
      await recovery.locator('#recovery-complete').click();
      await recovery.waitForURL((u) => u.origin === own.cell.origin && u.pathname === HOME);

      // The sign-in page: "Send me a link" lands a sign-in link.
      const login = await follow(door.context, inbox.locator(`main a[href="${own.cell.origin}/auth/login"]`));
      await login.locator('#magic-email').fill(email);
      await login.locator('#magic-request').click();
      await refresh(inbox);
      const magic = inbox.locator('li[data-demo-mail="magic"]');
      await expect(magic).toContainText(email);
      const confirm = await follow(door.context, magic.locator('a[data-demo-mail-link]'));
      await confirm.locator('#magic-confirm').click();
      // The account holds a passkey now, so no offer: straight home.
      await confirm.waitForURL((u) => u.origin === own.cell.origin && u.pathname === HOME);
      await door.context.close();
    } finally {
      await own.stop();
    }
  });

  test('demo_inbox_absent_without_flag', async ({ browser }) => {
    const own = await OwnCell.start([]);
    try {
      const door = await FrontDoor.open(browser, own.cell);
      await expect(door.page.locator('a[href="/demo/inbox"]')).toHaveCount(0);
      const r = await door.page.goto(`${own.cell.control}/demo/inbox`);
      expect(r?.status(), 'GET /demo/inbox without the flag').toBe(404);
      await door.context.close();
    } finally {
      await own.stop();
    }
  });
});
