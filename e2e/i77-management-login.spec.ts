/**
 * I-77: accounts holding any Drafting, Judging, Operations or tenant admin
 * role log in with a phishing-resistant method only (R-LG-02, TH-55,
 * T-AU-ROLES). M3 design sections 8.1, 8.2 and 14.4, ADR-008 "Methods in
 * M3", `authentication.md` "Strong methods".
 *
 * The browser carries part of this guarantee: the login page must never
 * hand a management account a magic link, and a passkey assertion without
 * user verification must not start a management session. Each refusal
 * here is paired with a positive control over the same wire, so a route
 * that answers nothing cannot pass.
 */

import { expect, type Page } from '@playwright/test';
import {
  Control,
  SESSION_COOKIE,
  VirtualAuthenticator,
  consumeMagic,
  createProgramme,
  enableMagicLinks,
  enrolByInvite,
  passkeyLogin,
  requestMagic,
  runHighRisk,
  sessionStatus,
  signUp,
  stack,
  test,
  syncedAuthenticator,
  syntheticEmail,
  PAGES,
} from './playwright.config';

/** Every `userVerification` value in a JSON value. */
function uvLevels(v: unknown, seen: string[]): void {
  if (Array.isArray(v)) {
    for (const x of v) uvLevels(x, seen);
  } else if (typeof v === 'object' && v !== null) {
    for (const [k, x] of Object.entries(v)) {
      if (k === 'userVerification' && typeof x === 'string') seen.push(x);
      else uvLevels(x, seen);
    }
  }
}

/** Records the user verification levels of the login options `page` gets. */
function watchUvLevels(page: Page): string[] {
  const seen: string[] = [];
  page.on('response', async (r) => {
    if (new URL(r.url()).pathname === '/auth/passkey/login/options') {
      uvLevels(await r.json(), seen);
    }
  });
  return seen;
}

test.describe('I-77 management login', () => {
  test('i77_management_account_is_never_sent_a_magic_link', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const fresh = await control.reset();

    const admin = await person();
    await VirtualAuthenticator.attach(admin);
    await enrolByInvite(admin, cell.origin, fresh.first_admin.url);
    await enableMagicLinks(admin, control);

    // Positive control: a Receiving account is sent a magic link.
    const applicantEmail = syntheticEmail('applicant');
    const applicant = await person();
    await VirtualAuthenticator.attach(applicant);
    await signUp(applicant, control, cell.origin, applicantEmail);

    const anon = await person();
    const answers: string[] = [];
    anon.on('response', async (r) => {
      if (new URL(r.url()).pathname === '/auth/magic/request') {
        answers.push(`${r.status()} ${await r.text()}`);
      }
    });
    const shownApplicant = await requestMagic(anon, cell.origin, applicantEmail);
    expect((await control.mailbox(applicantEmail)).filter((m) => m.kind === 'magic')).toHaveLength(1);

    // The tenant admin holds a management role: no link, and the same
    // answer as for an address that has no account.
    const shownAdmin = await requestMagic(anon, cell.origin, fresh.first_admin.email);
    const shownUnknown = await requestMagic(anon, cell.origin, syntheticEmail('nobody'));
    expect(shownAdmin).toBe(shownApplicant);
    expect(shownUnknown).toBe(shownApplicant);
    await expect.poll(() => answers.length).toBe(3);
    expect(new Set(answers).size, 'one answer whether or not the account may use links').toBe(1);
    expect((await control.mailbox(fresh.first_admin.email)).filter((m) => m.kind === 'magic')).toEqual(
      [],
    );
  });

  test('i77_management_passkey_login_without_user_verification_is_refused', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const fresh = await control.reset();

    const enrol = await person();
    const device = await VirtualAuthenticator.attach(enrol);
    await enrolByInvite(enrol, cell.origin, fresh.first_admin.url);

    // The same passkey on a device that answers without the UV flag, as a
    // modified client or authenticator would. The cell itself must refuse
    // it (ADR-008 "User verification").
    const page = await person();
    const ctx = page.context();
    const synced = await syncedAuthenticator(page, device);
    await synced.setBadUserVerification(true);
    const asked = watchUvLevels(page);
    expect(await passkeyLogin(page, cell.origin)).toBe(false);
    expect(asked.length, 'the login options name a user verification level').toBeGreaterThan(0);
    expect(asked).not.toContain('discouraged');
    expect(await sessionStatus(page, cell.origin)).toBe(401);
    expect((await ctx.cookies(cell.origin)).map((c) => c.name)).not.toContain(SESSION_COOKIE);

    // Positive control: the same credential with UV signs in.
    await synced.setBadUserVerification(false);
    expect(await passkeyLogin(page, cell.origin)).toBe(true);
    const cookie = (await ctx.cookies(cell.origin)).find((c) => c.name === SESSION_COOKIE);
    expect(cookie?.secure).toBe(true);
    expect(cookie?.httpOnly).toBe(true);
    expect(cookie?.sameSite).toBe('Strict');
    expect(cookie?.path).toBe('/');
  });

  test('i77_grant_of_a_management_role_ends_the_accounts_weak_sessions', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const fresh = await control.reset();

    const admin = await person();
    await VirtualAuthenticator.attach(admin);
    await enrolByInvite(admin, cell.origin, fresh.first_admin.url);
    await enableMagicLinks(admin, control);
    const programme = await createProgramme(admin, control);

    // A Receiving account with a passkey session (strong, with UV) and a
    // magic-link session (weak).
    const email = syntheticEmail('grantee');
    const strong = await person();
    const device = await VirtualAuthenticator.attach(strong);
    await signUp(strong, control, cell.origin, email);
    const weak = await person();
    await requestMagic(weak, cell.origin, email);
    const link = await control.newest(email, 'magic');
    expect(await consumeMagic(weak, cell.origin, link.link)).toBe(true);
    expect(await sessionStatus(weak, cell.origin)).toBe(200);

    // The grant of an Operations role ends the weak session in its batch.
    const account = await control.account(email);
    const grant = await control.command('GrantRole', {
      programme,
      account,
      role: 'FinanceApprover',
    });
    await runHighRisk(admin, cell.origin, grant.command);
    expect(await sessionStatus(weak, cell.origin)).toBe(401);
    await weak.goto(`${cell.origin}${PAGES.account}`);
    await expect(weak).toHaveURL((u) => u.pathname === PAGES.login);
    expect(await sessionStatus(strong, cell.origin)).toBe(200);

    // From now on the account is never sent a magic link.
    const before = (await control.mailbox(email)).filter((m) => m.kind === 'magic').length;
    await requestMagic(weak, cell.origin, email);
    expect((await control.mailbox(email)).filter((m) => m.kind === 'magic')).toHaveLength(before);

    // And its passkey still signs in, with UV.
    const again = await person();
    await syncedAuthenticator(again, device);
    expect(await passkeyLogin(again, cell.origin)).toBe(true);
  });
});
