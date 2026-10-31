/**
 * I-20: the platform stores no link between tenant accounts in different
 * tenants (T-ISO). M3 design sections 8.1, 8.2 and 14.4, ADR-008
 * "Relying party id".
 *
 * One synthetic person with one authenticator joins two tenant cells
 * whose hosts are siblings under one parent domain. Chromium accepts a
 * parent-domain RP id for such hosts, so a cell that used one would let
 * one passkey serve both tenants. The RP id must be the exact cell host:
 * then the passkey of tenant A is never offered on tenant B, the two
 * passkeys share no credential id and no user handle, and a session of
 * one cell is refused by the other (B11).
 */

import { expect, type Page } from '@playwright/test';
import {
  Control,
  SESSION_COOKIE,
  VirtualAuthenticator,
  b64url,
  call,
  enrolByInvite,
  hostOf,
  parentOf,
  passkeyLogin,
  sessionStatus,
  stack,
  test,
  PAGES,
  type CellEndpoints,
} from './playwright.config';

/** The RP ids and credential ids a cell's login options name. */
interface LoginOptionsSeen {
  rpIds: string[];
  allowed: string[];
}

/** Records the login options `page` receives from `cell`. */
function watchLoginOptions(page: Page, cell: CellEndpoints): LoginOptionsSeen {
  const seen: LoginOptionsSeen = { rpIds: [], allowed: [] };
  page.on('response', async (r) => {
    const u = new URL(r.url());
    if (u.origin !== cell.origin || u.pathname !== '/auth/passkey/login/options') {
      return;
    }
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) {
        v.forEach(walk);
      } else if (typeof v === 'object' && v !== null) {
        for (const [k, x] of Object.entries(v)) {
          if (k === 'rpId' && typeof x === 'string') seen.rpIds.push(x);
          if (k === 'allowCredentials' && Array.isArray(x)) {
            for (const c of x) {
              if (typeof c === 'object' && c !== null && typeof c.id === 'string') {
                seen.allowed.push(c.id);
              }
            }
          }
          walk(x);
        }
      }
    };
    walk(await r.json());
  });
  return seen;
}

test.describe('I-20 passkeys per tenant', () => {
  test('i20_passkey_of_one_tenant_is_not_offered_on_another', async ({ person, request }) => {
    const { a, b } = stack().cells;
    const hostA = hostOf(a.origin);
    const hostB = hostOf(b.origin);
    // Precondition: sibling hosts, so a parent-domain RP id is possible.
    expect(hostA).not.toBe(hostB);
    expect(parentOf(hostA)).toBe(parentOf(hostB));
    expect(parentOf(hostA).includes('.'), 'the parent is a registrable domain').toBe(true);

    const freshA = await new Control(request, a).reset();
    const freshB = await new Control(request, b).reset();

    const page = await person();
    const device = await VirtualAuthenticator.attach(page);
    await enrolByInvite(page, a.origin, freshA.first_admin.url);

    const afterA = await device.credentials();
    expect(afterA).toHaveLength(1);
    const credA = afterA[0];
    if (credA === undefined) throw new Error('unreachable');
    expect(credA.rpId, 'the RP id is the exact host of cell A').toBe(hostA);
    expect(credA.isResidentCredential).toBe(true);

    // On cell B the passkey of cell A is not offered and cannot sign in.
    await page.context().clearCookies();
    const seenB = watchLoginOptions(page, b);
    expect(await passkeyLogin(page, b.origin)).toBe(false);
    expect(await sessionStatus(page, b.origin)).toBe(401);
    expect(seenB.rpIds.length, 'cell B names its RP id').toBeGreaterThan(0);
    expect(new Set(seenB.rpIds)).toEqual(new Set([hostB]));
    expect(seenB.allowed).not.toContain(b64url(credA.credentialId));
    const unused = (await device.credentials()).find((c) => c.credentialId === credA.credentialId);
    expect(unused?.signCount, 'the passkey of cell A was not used on cell B').toBe(credA.signCount);

    // The same person joins cell B with the same authenticator.
    await enrolByInvite(page, b.origin, freshB.first_admin.url);
    const both = await device.credentials();
    expect(both).toHaveLength(2);
    const credB = both.find((c) => c.credentialId !== credA.credentialId);
    if (credB === undefined) throw new Error('no second credential');
    expect(credB.rpId).toBe(hostB);
    expect(credB.userHandle, 'no shared user handle across tenants').not.toBe(credA.userHandle);

    // Each cell signs in with its own passkey only.
    await page.context().clearCookies();
    const countsBefore = new Map((await device.credentials()).map((c) => [c.credentialId, c.signCount]));
    expect(await passkeyLogin(page, b.origin)).toBe(true);
    const countsAfter = new Map((await device.credentials()).map((c) => [c.credentialId, c.signCount]));
    expect(countsAfter.get(credA.credentialId)).toBe(countsBefore.get(credA.credentialId));
    expect(countsAfter.get(credB.credentialId)).not.toBe(countsBefore.get(credB.credentialId));
  });

  test('i20_session_of_one_cell_is_refused_by_another', async ({ person, request }) => {
    const { a, b } = stack().cells;
    const freshA = await new Control(request, a).reset();
    await new Control(request, b).reset();

    const page = await person();
    await VirtualAuthenticator.attach(page);
    await enrolByInvite(page, a.origin, freshA.first_admin.url);
    const cookies = await page.context().cookies(a.origin);
    const session = cookies.find((c) => c.name === SESSION_COOKIE);
    if (session === undefined) throw new Error('no session cookie on cell A');
    // `__Host-`: host-only, Secure, Path=/ (design section 8.2).
    expect(session.domain).toBe(hostOf(a.origin));
    expect(session.secure).toBe(true);
    expect(session.path).toBe('/');
    expect(await page.context().cookies(b.origin)).toEqual([]);

    // The same cookie value presented to cell B is refused (B11).
    await page.goto(`${b.origin}${PAGES.login}`);
    await page.context().addCookies([
      {
        name: SESSION_COOKIE,
        value: session.value,
        url: b.origin,
        secure: true,
        httpOnly: true,
        sameSite: 'Strict',
      },
    ]);
    expect(await sessionStatus(page, b.origin)).toBe(401);
    expect((await call(page, b.origin, 'GET', '/auth/devices')).status).toBe(401);

    // Positive control: cell A still admits it.
    await page.goto(`${a.origin}${PAGES.login}`);
    expect(await sessionStatus(page, a.origin)).toBe(200);
  });
});
