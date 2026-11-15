/**
 * The programme set-up wizard, by clicking from sign-in
 * (`docs/design/11-programme-setup-wizard.md`; Daniel's answers of
 * 2026-11-15; the click-through rule: each person reaches their work by
 * clicking from sign-in).
 *
 * The demo scene is the programme set-up scene. Its organisation was
 * founded through onboarding and activated by a second tenant admin
 * (ADR-021, SoD-18). M1 holds a fully built SuperSAFE draft.
 *
 * - r_pg_01_i67_setup_wizard_walks_from_start_to_request_activation:
 *   1. Tenant admin A2 clicks "Set up a new programme with the wizard"
 *      on the home page. Stage 1 opens a draft with the demo step-up
 *      and invites the programme manager by exact email, with role dates
 *      (design doc 11 Q1, Q3). The progress page of the new draft lists
 *      the invitation.
 *   2. M1 clicks "Set-up wizard of programme N" on the home page and
 *      saves each stage in turn. The stage bar marks one current stage
 *      and the summary panel names the set-up so far (R-PG-01).
 *   3. On the Team stage M1 plans a finance approver, an Operations role
 *      shown as planned (Q2). Choosing the same person as payment
 *      releaser is refused live under SoD-04, and "Add to team" is
 *      disabled.
 *   4. On Review and confirm M1 acknowledges each warning and requests
 *      activation (I-66). The progress page then shows the approval by a
 *      tenant admin outside the builders as the current milestone, with
 *      the I-67 notice and the empty place of the override (Q4).
 *
 * Every page reached is checked for console errors. With
 * `FSTP_SETUP_SHOTS` set to a directory, each page is also saved as a
 * screenshot there. Run with `tools/demo/run.sh e2e
 * studio/setup_wizard.spec.ts` against the demo. Every person and address
 * is synthetic.
 */

import { join } from 'node:path';
import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell } from '../site/contract';
import { Seat } from '../speedrun/support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** Tenant admin A2 of the programme set-up scene. */
const A2 = /Tenant admin A2/;

/** The synthetic addresses of design doc 11 section 9. */
const PM = 's.okafor@horizon-bridges.example';
const FINANCE = 'k.wu@horizon-bridges.example';

/** Saves a screenshot of `page` as `name` when `FSTP_SETUP_SHOTS` names a directory. */
async function shot(page: Page, name: string): Promise<void> {
  const dir = process.env['FSTP_SETUP_SHOTS'];
  if (dir !== undefined && dir !== '') {
    await page.screenshot({ path: join(dir, `${name}.png`), fullPage: true });
  }
}

/** Collects console errors of `page`. The 401 that asks for a step-up (I-78) is the protocol. */
function watch(page: Page): () => string[] {
  const out: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error' && !m.text().includes('status of 401')) out.push(m.text());
  });
  page.on('pageerror', (e) => out.push(String(e)));
  return () => out;
}

/** Waits for the wizard page at `path` to be ready. */
async function readyAt(page: Page, path: RegExp): Promise<void> {
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
  await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
}

test.describe('programme set-up wizard', () => {
  test.describe.configure({ timeout: 300_000 });

  /** R-PG-01, I-66, I-67, SoD-04, ADR-021, design doc 11. */
  test('r_pg_01_i67_setup_wizard_walks_from_start_to_request_activation', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    await door.chooseScene('/demo/setup');
    await expect(door.page.locator('#demo-scene')).toContainText('programme_setup');
    await expect(door.item(A2)).toHaveCount(1);
    await door.close();

    // 1. A2 opens a draft and invites its programme manager.
    const a2 = await Seat.signIn(browser, cell, A2);
    const a2Errors = watch(a2.page);
    await a2.page.locator('#home-work a[data-work="setup"]').click();
    await readyAt(a2.page, /^\/app\/setup\/new$/);
    await expect(a2.page.locator('main h1')).toHaveText('Set up a new programme');
    await expect(a2.page.locator('#setup-active')).toContainText('ADR-021');
    const bar = a2.page.getByRole('navigation', { name: 'Set-up stages' });
    await expect(bar.locator('li[aria-current="step"]')).toHaveAttribute('data-stage', 'start');
    await expect(a2.page.getByRole('complementary', { name: 'Your set-up so far' })).toBeVisible();
    await a2.page.locator('#setup-pm-email').fill(PM);
    await a2.page.locator('#setup-pm-end').fill('2029-12-31');
    await shot(a2.page, '01-start');
    await a2.page.locator('#setup-open').click();
    const dialog = a2.page.locator('dialog#stepup');
    await expect(a2.page.locator('#setup-progress-status, dialog#stepup[open]').first()).toBeVisible();
    if (await dialog.isVisible()) {
      await a2.page.locator('#stepup-confirm').click();
      await expect(dialog).toBeHidden();
    }
    await readyAt(a2.page, /^\/app\/programmes\/\d+\/setup\/progress$/);
    await expect(a2.page.locator('main h1')).toHaveText('Set-up progress');
    await expect(a2.page.locator('#setup-strip li[data-milestone="drafted"]')).toHaveAttribute('data-condition', 'done');
    await expect(a2.page.locator('#setup-strip li[data-milestone="invited"]')).not.toHaveAttribute('data-condition', 'current');
    const pmRow = a2.page.locator('#setup-team-status tr[data-role="programme_manager"]');
    await expect(pmRow).toContainText(PM);
    await expect(pmRow).toContainText('Accept the invitation from the email.');
    await shot(a2.page, '09-progress-new-draft');
    expect(a2Errors(), 'no console error on the admin pages').toEqual([]);
    await a2.close();

    // 2. M1 walks the stages of the built draft.
    const m1 = await Seat.signIn(browser, cell, DOOR.m1);
    const m1Errors = watch(m1.page);
    await m1.page.locator('#home-work a[data-work="setup"]').first().click();
    await readyAt(m1.page, /^\/app\/programmes\/\d+\/setup\/programme$/);
    const p = /\/app\/programmes\/(\d+)\//.exec(new URL(m1.page.url()).pathname)?.[1] ?? '';
    expect(p, 'the programme of the wizard').not.toBe('');
    const stages = m1.page.getByRole('navigation', { name: 'Set-up stages' });
    await expect(stages.locator('li[aria-current="step"]')).toHaveAttribute('data-stage', 'programme');
    await expect(stages.locator('li[data-stage="start"] a')).toHaveCount(0);
    const summary = m1.page.getByRole('complementary', { name: 'Your set-up so far' });
    await expect(summary).toContainText('of 7 stages complete.');
    await shot(m1.page, '02-programme');

    const walk: readonly [string, string][] = [
      ['programme', 'applicants'],
      ['applicants', 'evaluation'],
      ['evaluation', 'team'],
    ];
    for (const [from, to] of walk) {
      await expect(m1.page.locator(`#setup-stage[data-stage="${from}"]`)).toBeVisible();
      await m1.page.locator('#setup-continue').click();
      await readyAt(m1.page, new RegExp(`^/app/programmes/${p}/setup/${to}$`));
      await expect(stages.locator('li[aria-current="step"]')).toHaveAttribute('data-stage', to);
      await expect(stages.locator(`li[data-stage="${from}"] a`)).toHaveCount(1);
      await shot(m1.page, `0${String(['programme', 'applicants', 'evaluation', 'team'].indexOf(to) + 2)}-${to}`);
    }

    // 3. The Team stage: a planned Operations row and a live SoD-04 refusal.
    await m1.page.locator('#setup-team-email').fill(FINANCE);
    await m1.page.locator('#setup-role-finance_approver').check();
    await expect(m1.page.locator('#setup-sod li[data-rule="SoD-09"]')).toHaveAttribute('data-badge', 'not_affected');
    await m1.page.locator('#setup-team-add').click();
    await expect(m1.page.locator('#setup-team-status')).toContainText(FINANCE);
    const planned = m1.page.locator('#setup-team-tables tr[data-role="finance_approver"]');
    await expect(planned).toHaveAttribute('data-status', 'planned');
    await expect(planned).toContainText('Planned, granted after activation');
    await m1.page.locator('#setup-team-email').fill(FINANCE);
    await m1.page.locator('#setup-role-payment_releaser').check();
    await expect(m1.page.locator('#setup-sod li[data-rule="SoD-04"]')).toHaveAttribute('data-badge', 'refused');
    await expect(m1.page.locator('#setup-team-add')).toBeDisabled();
    await expect(m1.page.locator('#setup-team-add-why')).toContainText('SoD-04');
    await shot(m1.page, '05-team');
    await m1.page.locator('#setup-team-email').fill('');
    await m1.page.locator('#setup-continue').click();
    await readyAt(m1.page, new RegExp(`^/app/programmes/${p}/setup/communications$`));
    await shot(m1.page, '06-communications');
    await m1.page.locator('#setup-continue').click();
    await readyAt(m1.page, new RegExp(`^/app/programmes/${p}/setup/review$`));

    // 4. Review and confirm, then the progress page.
    await expect(m1.page.locator('#report li[data-severity="failure"]')).toHaveCount(0);
    const acks = m1.page.locator('#report [data-action="acknowledge"]');
    while ((await acks.count()) > 0) {
      await acks.first().click();
      await settle(m1.page);
    }
    await expect(m1.page.locator('#report li[data-severity="warning"][data-acknowledged="false"]')).toHaveCount(0);
    await expect(m1.page.locator('#request-activation')).toBeEnabled();
    await expect(m1.page.locator('#setup-approver')).toContainText('I-67');
    await expect(m1.page.locator('#setup-approver-override')).toBeHidden();
    await expect(m1.page.locator('[data-review-card]')).toHaveCount(5);
    await shot(m1.page, '07-review');
    await m1.page.locator('#request-activation').click();
    await readyAt(m1.page, new RegExp(`^/app/programmes/${p}/setup/progress$`));
    await expect(m1.page.locator('#setup-progress-status')).toHaveAttribute('data-status', 'requested');
    await expect(m1.page.locator('#setup-strip li[aria-current="step"]')).toHaveAttribute('data-milestone', 'approved');
    await expect(m1.page.locator('#setup-next')).toContainText('outside the builders');
    await expect(m1.page.locator('#setup-approver')).toBeVisible();
    await expect(m1.page.locator('#setup-approver-override')).toHaveCount(1);
    const ops = m1.page.locator('#setup-team-status tr[data-role="finance_approver"]');
    await expect(ops.locator('td[data-cell="not_needed"]')).toHaveCount(1);
    await shot(m1.page, '08-progress');
    expect(m1Errors(), 'no console error on the wizard pages').toEqual([]);
    await m1.close();
  });
});
