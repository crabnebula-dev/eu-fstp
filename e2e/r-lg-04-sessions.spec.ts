/**
 * R-LG-04: users can see and end their sessions and linked devices. M3
 * design sections 8.2 and 14.5 (`r_lg_04_sessions_and_devices_listed_and_ended`,
 * "also Playwright"), ADR-008 "Sessions". Removing a device is the
 * high-risk action `ChangeLoginMethods`, so it asks for a step-up (I-78).
 *
 * Two browsers of one person share a synced passkey, as two devices do.
 */

import { expect, type Page } from '@playwright/test';
import {
  Control,
  PAGES,
  UI,
  VirtualAuthenticator,
  confirmStepUp,
  enrolByInvite,
  keyForNextPasskey,
  passkeyLogin,
  sessionStatus,
  stack,
  syncedAuthenticator,
  test,
  type VirtualCredential,
} from './playwright.config';

/** The first tenant admin, enrolled in a first browser. */
async function enrolled(
  person: () => Promise<Page>,
  control: Control,
): Promise<{ page: Page; device: VirtualAuthenticator }> {
  const fresh = await control.reset();
  const page = await person();
  const device = await VirtualAuthenticator.attach(page);
  await enrolByInvite(page, control.cell.origin, fresh.first_admin.url);
  return { page, device };
}

/** Whether a browser holding only `c` can sign in to `origin`. */
async function signsInWith(
  person: () => Promise<Page>,
  origin: string,
  c: VirtualCredential,
): Promise<boolean> {
  const page = await person();
  const a = await VirtualAuthenticator.attach(page);
  await a.add(c);
  return passkeyLogin(page, origin);
}

test.describe('R-LG-04 sessions and devices', () => {
  test('r_lg_04_sessions_listed_and_another_session_ended', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { page: first, device } = await enrolled(person, control);

    const second = await person();
    await syncedAuthenticator(second, device);
    expect(await passkeyLogin(second, cell.origin)).toBe(true);

    await first.goto(`${cell.origin}${PAGES.account}`);
    const sessions = first.locator(`${UI.account.sessions} > li`);
    await expect(sessions).toHaveCount(2);
    // The page marks the session it runs in.
    await expect(first.locator(`${UI.account.sessions} > li[aria-current="true"]`)).toHaveCount(1);

    // End the other session from the first browser.
    const other = first.locator(`${UI.account.sessions} > li:not([aria-current="true"])`);
    await expect(other).toHaveCount(1);
    await other.getByRole('button').click();
    await expect(sessions).toHaveCount(1);
    await expect(first.locator(`${UI.account.sessions} > li[aria-current="true"]`)).toHaveCount(1);

    // The second browser is signed out, the first is not.
    expect(await sessionStatus(second, cell.origin)).toBe(401);
    await second.goto(`${cell.origin}${PAGES.account}`);
    await expect(second).toHaveURL((u) => u.pathname === PAGES.login);
    expect(await sessionStatus(first, cell.origin)).toBe(200);
  });

  test('r_lg_04_current_session_ended_signs_out', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { page } = await enrolled(person, control);
    await page.goto(`${cell.origin}${PAGES.account}`);
    const mine = page.locator(`${UI.account.sessions} > li[aria-current="true"]`);
    await expect(mine).toHaveCount(1);
    await mine.getByRole('button').click();
    await expect(page).toHaveURL((u) => u.pathname === PAGES.login);
    expect(await sessionStatus(page, cell.origin)).toBe(401);
  });

  test('r_lg_04_devices_listed_and_removed_with_step_up', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { page, device } = await enrolled(person, control);
    await page.goto(`${cell.origin}${PAGES.account}`);
    const devices = page.locator(`${UI.account.devices} > li`);
    await expect(devices).toHaveCount(1);

    // Link a second device: a security key, added with a step-up.
    const next = await keyForNextPasskey(page);
    await page.locator(UI.account.addPasskey).click();
    await confirmStepUp(page);
    await expect(devices).toHaveCount(2);
    const key = await next.key;
    const creds = [...(await device.credentials()), ...(await key.credentials())];
    expect(creds).toHaveLength(2);

    // Remove one device. The page asks for a step-up first.
    const removals: string[] = [];
    page.on('request', (r) => {
      const p = new URL(r.url()).pathname;
      if (r.method() === 'DELETE' || p.startsWith('/auth/stepup')) removals.push(`${r.method()} ${p}`);
    });
    await devices.first().getByRole('button').click();
    await confirmStepUp(page);
    await expect(devices).toHaveCount(1);
    expect(removals.slice(0, 2)).toEqual(['POST /auth/stepup/options', 'POST /auth/stepup']);
    expect(removals.filter((x) => x.startsWith('DELETE /auth/devices/'))).toHaveLength(1);

    // Exactly one of the two passkeys still signs in.
    const outcomes: boolean[] = [];
    for (const c of creds) {
      outcomes.push(await signsInWith(person, cell.origin, c));
    }
    expect(outcomes.filter((x) => x)).toHaveLength(1);
  });
});
