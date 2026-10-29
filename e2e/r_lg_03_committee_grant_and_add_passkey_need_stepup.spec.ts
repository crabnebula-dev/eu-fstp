/**
 * R-LG-03: high-risk actions need a fresh phishing-resistant step-up
 * (I-78, T-AU-STEPUP). Its AC: "granting a committee role, exporting the
 * tenant or adding a passkey fails without a step-up in the last P-71".
 * M3 design sections 8.4 and 14.4, ADR-008 "Step-up".
 *
 * Tenant export arrives with the export routes in M9, so this spec covers
 * the committee grant and the passkey addition. Each refusal is paired
 * with an accepted request over the same wire, so a route that refuses
 * everything cannot pass.
 */

import { expect, type Page } from '@playwright/test';
import {
  Control,
  P71_MICROS,
  PAGES,
  ROUTE_ACTIONS,
  UI,
  VirtualAuthenticator,
  call,
  cellOptions,
  confirmStepUp,
  createIn,
  createProgramme,
  enrolByInvite,
  keyForNextPasskey,
  okJson,
  randomHex,
  sendCommand,
  signUp,
  stack,
  stepUp,
  syntheticEmail,
  test,
} from './playwright.config';

/** A tenant admin with a passkey, signed in on the account page. */
async function admin(
  person: () => Promise<Page>,
  control: Control,
): Promise<{ page: Page; device: VirtualAuthenticator }> {
  const fresh = await control.reset();
  const page = await person();
  const device = await VirtualAuthenticator.attach(page);
  await enrolByInvite(page, control.cell.origin, fresh.first_admin.url);
  return { page, device };
}

test.describe('R-LG-03 step-up for high-risk actions', () => {
  test('r_lg_03_committee_grant_fails_without_a_step_up_in_the_last_p71', async ({
    person,
    request,
  }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { page } = await admin(person, control);
    const programme = await createProgramme(page, control);

    const email = syntheticEmail('reviewer');
    const reviewer = await person();
    await VirtualAuthenticator.attach(reviewer);
    await signUp(reviewer, control, cell.origin, email);
    const account = await control.account(email);

    const grant = (
      await control.command('GrantRole', { programme, account, role: 'CommitteeMember' })
    ).command;
    const other = (
      await control.command('GrantRole', { programme, account, role: 'CommitteeChair' })
    ).command;

    // No step-up: a well-formed body without the optional `stepup`
    // member, which the gate refuses under I-78.
    const none = await sendCommand(page, cell.origin, grant, { command_id: randomHex(16) });
    expect(none.status, none.body).toBe(403);

    // A step-up for another command.
    const forOther = await stepUp(page, cell.origin, other);
    const wrong = await sendCommand(page, cell.origin, grant, forOther);
    expect(wrong.status, wrong.body).toBe(403);

    // A step-up P-71 plus 1 µs old.
    const stale = await stepUp(page, cell.origin, grant);
    await control.advanceClock(P71_MICROS + 1);
    const late = await sendCommand(page, cell.origin, grant, stale);
    expect(late.status, late.body).toBe(403);

    // Accepted: a step-up exactly P-71 old is still fresh.
    const fresh = await stepUp(page, cell.origin, grant);
    await control.advanceClock(P71_MICROS);
    okJson(await sendCommand(page, cell.origin, grant, fresh), 'grant with a fresh step-up');
  });

  test('r_lg_03_add_passkey_fails_without_a_step_up_in_the_last_p71', async ({
    person,
    request,
  }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { page, device } = await admin(person, control);

    // No step-up. The route takes `{command_id, stepup}` and refuses a
    // body without `stepup` before any ceremony (`fstp-cell`
    // `routes::auth::add_passkey` answers 400). Either refusal keeps the
    // invariant: no creation options, so no passkey can be added.
    const none = await call(page, cell.origin, 'POST', '/auth/passkeys/options', {
      command_id: randomHex(16),
    });
    expect([400, 403], none.body).toContain(none.status);
    expect(none.body).not.toContain('public_key');

    // A step-up P-71 plus 1 µs old.
    const stale = await stepUp(page, cell.origin, ROUTE_ACTIONS.addPasskey);
    await control.advanceClock(P71_MICROS + 1);
    const late = await call(page, cell.origin, 'POST', '/auth/passkeys/options', stale);
    expect(late.status, late.body).toBe(403);

    // A step-up for another action.
    const forOther = await stepUp(page, cell.origin, ROUTE_ACTIONS.removeDevice('0'));
    const wrong = await call(page, cell.origin, 'POST', '/auth/passkeys/options', forOther);
    expect(wrong.status, wrong.body).toBe(403);

    // Accepted over the same wire: a fresh step-up with the enrolled
    // passkey, then the ceremony on a new security key.
    const fresh = await stepUp(page, cell.origin, ROUTE_ACTIONS.addPasskey);
    const key = await VirtualAuthenticator.attach(page, { transport: 'usb' });
    // The same wire as the account page: `{challenge_id, public_key}`
    // options, then the new credential's hex members.
    const options = cellOptions(
      okJson(
        await call(page, cell.origin, 'POST', '/auth/passkeys/options', fresh),
        'passkey options with a fresh step-up',
      ),
      'passkey options',
    );
    const credential = await createIn(page, options.public_key);
    okJson(
      await call(page, cell.origin, 'POST', '/auth/passkeys', {
        ...credential,
        ...fresh,
        challenge_id: options.challenge_id,
      }),
      'passkey added',
    );
    expect((await device.credentials()).length + (await key.credentials()).length).toBe(2);
  });

  test('r_lg_03_add_passkey_page_asks_for_a_step_up', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { page, device } = await admin(person, control);
    await page.goto(`${cell.origin}${PAGES.account}`);
    const devices = page.locator(`${UI.account.devices} > li`);
    await expect(devices).toHaveCount(1);

    const next = await keyForNextPasskey(page);
    const steps: string[] = [];
    page.on('request', (r) => {
      const p = new URL(r.url()).pathname;
      if (r.method() === 'POST' && p.startsWith('/auth/')) steps.push(p);
    });
    await page.locator(UI.account.addPasskey).click();
    await confirmStepUp(page);
    await expect(devices).toHaveCount(2);
    const key = await next.key;
    expect((await device.credentials()).length + (await key.credentials()).length).toBe(2);
    // The step-up precedes the passkey ceremony, and is not skipped.
    expect(steps).toEqual([
      '/auth/stepup/options',
      '/auth/stepup',
      '/auth/passkeys/options',
      '/auth/passkeys',
    ]);
  });
});
