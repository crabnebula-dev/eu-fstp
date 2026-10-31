/**
 * SuperSAFE built in the creator, through the browser (M4 exit criterion
 * "the SuperSAFE programme is built in the creator"; design sections
 * 2.2 J0 to J2, 8.2 and 8.7).
 *
 * R-PG-01: programmes are built in a guided creator with per-step
 * validation, previews and a final validation report. R-PG-02: a
 * programme can start from a template. R-PG-03: activation needs a clean
 * report and a second approver (I-66, I-67).
 *
 * The cast is synthetic (design section 2.1): tenant admins A1 and A2,
 * programme manager M1, and the invitees of the People step. A1 opens
 * the draft, M1 builds it from the shipped SuperSAFE template, and A2
 * approves activation. The compiled draft must equal the SuperSAFE
 * fixture of `fstp-programme` in canonical form.
 *
 * Red until the pages of lane W4a and `fstp-e2e-cell` of lane W5 exist.
 * Without a stack manifest each test fails at its first step with
 * `StackMissing`, which names the missing piece. No test is skipped.
 */

import { expect, type Page } from '@playwright/test';
import { call, syntheticEmail, test } from '../playwright.config';
import { API, APP, APPROVAL_UI, CREATOR_STEPS, CREATOR_UI, REVIEW_STEP, STEPUP } from './contract';
import {
  addProgrammeManager,
  applySuperSafeTemplate,
  canon,
  cellA,
  contrastBothThemes,
  draftValue,
  fixtureValue,
  footerProblems,
  invite,
  newPerson,
  onboardedTenant,
  openDraft,
  programmeOf,
  readDraft,
  readReport,
  reviewAndRequest,
  saveStep,
  setFieldValue,
  structureProblems,
  superSafe,
  tabTo,
  walkCreatorSteps,
  withStepUp,
  type Person,
  type Tenant,
} from './support';

test.describe.configure({ timeout: 900_000 });

/** The People step invitations of J1: every role the cycle needs, none of them enrolled yet. */
const CAST: readonly (readonly [string, string])[] = [
  ['d1', 'call_drafter'],
  ['m2', 'programme_manager'],
  ['c1', 'fstp_coordinator'],
  ['r1', 'committee_member'],
  ['r2', 'committee_member'],
  ['r3', 'committee_member'],
  ['r4', 'committee_member'],
  ['h1', 'committee_chair'],
  ['i1', 'irc_member'],
  ['i2', 'irc_member'],
];

/** A2 approves the activation request of `p` with step-up, on the approval inbox. */
async function approveActivation(a2: Person, origin: string, p: string): Promise<void> {
  await a2.page.goto(`${origin}${APP.approvals}`);
  const item = a2.page.locator(APPROVAL_UI.item(p));
  await expect(item).toHaveCount(1);
  await withStepUp(a2.page, item.locator('[data-action="approve"]'));
}

/** Onboards, opens the draft, adds M1 and applies the SuperSAFE template. */
async function draftFromTemplate(
  person: () => Promise<Page>,
  request: Parameters<typeof cellA>[0],
): Promise<{ t: Tenant; p: string; m1: Person }> {
  const t = await onboardedTenant(person, cellA(request));
  const p = await openDraft(t.a1, t.cell.origin);
  const { m1 } = await addProgrammeManager(person, t, p);
  await applySuperSafeTemplate(m1, t.cell.origin, p);
  return { t, p, m1 };
}

test.describe('SuperSAFE in the creator', () => {
  /**
   * R-PG-02 (template start), R-PG-01 (per-step validation, previews,
   * report), R-PG-03 with I-66 and I-67 (clean report, second approver).
   * The browser twin of `r_pg_02_supersafe_built_through_creator_api`.
   */
  test('r_pg_02_supersafe_built_through_the_creator_pages_equals_the_fixture', async ({ person, request }) => {
    const f = superSafe();
    const { t, p, m1 } = await draftFromTemplate(person, request);
    const origin = t.cell.origin;
    expect((await readDraft(m1.page, origin, p)).status).toBe('draft');

    await walkCreatorSteps(m1, origin, p, f, async (step) => {
      if (step !== 'people') return;
      for (const [tag, role] of CAST) {
        const item = await invite(m1.page, origin, p, syntheticEmail(tag), role);
        // No invitee has an account yet, so the live check cannot run (InviteeWithoutAccount).
        await expect(item).toHaveAttribute('data-sod', 'unchecked');
      }
    });

    const built = await readDraft(m1.page, origin, p);
    expect(canon(built.spec), 'the draft built in the pages equals the SuperSAFE fixture').toBe(canon(f.spec));

    const acked = await reviewAndRequest(m1, origin, p);
    expect(acked, 'the invitations without an account were warnings to acknowledge').toContain('InviteeWithoutAccount');
    const report = await readReport(m1.page, origin, p);
    expect(report.filter((r) => r.severity === 'failure')).toEqual([]);
    expect(report.filter((r) => !r.acknowledged)).toEqual([]);

    await approveActivation(t.a2, origin, p);
    await expect.poll(async () => (await readDraft(t.a2.page, origin, p)).status).toBe('active');
    const active = await readDraft(t.a2.page, origin, p);
    expect(canon(active.spec), 'activation never rewrites the built policy').toBe(canon(f.spec));
  });

  /**
   * I-50 and I-66, R-PG-01 AC: a per-recipient cap above the funder
   * ceiling fails the step and the report, the report names both values,
   * and activation cannot be requested until it is fixed.
   */
  test('i50_cap_above_ceiling_names_both_values_and_blocks_the_activation_request', async ({ person, request }) => {
    const f = superSafe();
    const { t, p, m1 } = await draftFromTemplate(person, request);
    const origin = t.cell.origin;
    const ceiling = fixtureValue(f, 'funder.p58_recipient_ceiling');
    expect(ceiling).toBe('400000.00');

    await m1.page.goto(`${origin}${APP.creatorStep(p, 'funder')}`);
    await setFieldValue(m1.page, 'funder.p58_recipient_ceiling', ceiling);
    await saveStep(m1.page);

    await m1.page.goto(`${origin}${APP.creatorStep(p, 'money')}`);
    await setFieldValue(m1.page, 'money.p05_recipient_cap', '400000.01');
    const money = await saveStep(m1.page);
    expect(money.failures).toContain('CapAboveCeiling');

    await m1.page.goto(`${origin}${APP.creatorStep(p, REVIEW_STEP)}`);
    const item = m1.page.locator(`${CREATOR_UI.report} li[data-check="CapAboveCeiling"][data-severity="failure"]`);
    await expect(item).toHaveCount(1);
    await expect(item).toContainText('400000.01');
    await expect(item).toContainText('400000.00');
    await expect(m1.page.locator(CREATOR_UI.requestActivation)).toBeDisabled();
    expect((await readReport(m1.page, origin, p)).map((r) => r.check)).toContain('CapAboveCeiling');

    await m1.page.goto(`${origin}${APP.creatorStep(p, 'money')}`);
    await setFieldValue(m1.page, 'money.p05_recipient_cap', ceiling);
    expect((await saveStep(m1.page)).failures).not.toContain('CapAboveCeiling');
    expect((await readReport(m1.page, origin, p)).map((r) => r.check)).not.toContain('CapAboveCeiling');
  });

  /**
   * I-66: a warning blocks the activation request until it is
   * acknowledged at the current revision.
   */
  test('i66_activation_request_needs_every_warning_acknowledged', async ({ person, request }) => {
    const f = superSafe();
    const { t, p, m1 } = await draftFromTemplate(person, request);
    const origin = t.cell.origin;
    await walkCreatorSteps(m1, origin, p, f, async (step) => {
      if (step === 'people') await invite(m1.page, origin, p, syntheticEmail('c1'), 'fstp_coordinator');
    });
    await m1.page.goto(`${origin}${APP.creatorStep(p, REVIEW_STEP)}`);
    const report = m1.page.locator(CREATOR_UI.report);
    await expect(report.locator('li[data-severity="failure"]')).toHaveCount(0);
    const pending = report.locator('li[data-severity="warning"][data-acknowledged="false"]');
    expect(await pending.count(), 'an invitee without an account leaves a warning').toBeGreaterThan(0);
    await expect(m1.page.locator(CREATOR_UI.requestActivation)).toBeDisabled();
    expect((await readReport(m1.page, origin, p)).some((r) => r.severity === 'warning' && !r.acknowledged)).toBe(true);

    for (let guard = 0; (await pending.count()) > 0; guard++) {
      expect(guard).toBeLessThan(200);
      await pending.first().locator('[data-action="acknowledge"]').click();
    }
    await expect(m1.page.locator(CREATOR_UI.requestActivation)).toBeEnabled();
  });

  /**
   * TH-49 and `programme-creator.md` (Template library): template
   * narrative is shown as editable text and never applied silently. Until
   * M1 accepts it, the draft holds no value for the field.
   */
  test('th49_template_narrative_is_shown_as_editable_text_until_accepted', async ({ person, request }) => {
    const f = superSafe();
    const { t, p, m1 } = await draftFromTemplate(person, request);
    const origin = t.cell.origin;
    const key = 'identity.name';
    await m1.page.goto(`${origin}${APP.creatorStep(p, 'identity')}`);
    const field = m1.page.locator(`[data-field="${key}"]`);
    await expect(field.locator('[data-action="accept-narrative"]')).toHaveCount(1);
    const control = field.locator('[data-path=""]');
    await expect(control).toBeEditable();
    await expect(control).toHaveValue(String(fixtureValue(f, key)));
    expect(draftValue(await readDraft(m1.page, origin, p), key), 'not applied before acceptance').toBeNull();

    await field.locator('[data-action="accept-narrative"]').click();
    await expect(field.locator('[data-action="accept-narrative"]')).toHaveCount(0);
    await expect
      .poll(async () => draftValue(await readDraft(m1.page, origin, p), key))
      .toBe(fixtureValue(f, key));
  });

  /**
   * R-LG-03: opening a draft is high-risk (design section 2.2 J1, Q10).
   * Cancelling the step-up opens no draft.
   */
  test('r_lg_03_cancelled_step_up_opens_no_draft', async ({ person, request }) => {
    const t = await onboardedTenant(person, cellA(request));
    const page = t.a1.page;
    const created: number[] = [];
    page.on('response', (r) => {
      if (r.request().method() === 'POST' && new URL(r.url()).pathname === '/api/v1/programmes' && r.ok()) {
        created.push(r.status());
      }
    });
    await page.goto(`${t.cell.origin}${APP.creatorNew}`);
    await page.locator(CREATOR_UI.open).click();
    await expect(page.locator(STEPUP.dialog)).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator(STEPUP.dialog)).toBeHidden();
    await expect(page).toHaveURL((u) => u.pathname === APP.creatorNew);
    expect(created, 'no programme was created without the step-up').toEqual([]);
  });

  /**
   * R-NF-03 (WCAG 2.2 AA, in-house checks of design section 8.7): every
   * creator page state has a language, a title, one main landmark, an h1,
   * a name for every control, and AA text contrast in light and dark.
   */
  test('r_nf_03_creator_pages_have_structure_names_and_contrast', async ({ person, request }) => {
    const problems: string[] = [];
    await eachCreatorPage(person, request, async (page, label) => {
      problems.push(...(await structureProblems(page, label)), ...(await contrastBothThemes(page, label)));
    });
    expect(problems).toEqual([]);
  });

  /**
   * R-WL-04 and P-68 (platform attribution), with the I-69 seam: every
   * creator page shows the privacy notice, the accessibility statement and
   * the platform attribution, and tenant admins also see the Data Act
   * information (design section 3.9, Footer).
   */
  test('r_wl_04_every_creator_page_shows_the_mandatory_footer', async ({ person, request }) => {
    const problems: string[] = [];
    await eachCreatorPage(person, request, async (page, label, tenantAdmin) => {
      problems.push(...(await footerProblems(page, label, tenantAdmin)));
    });
    expect(problems).toEqual([]);
  });

  /**
   * R-NF-03: a creator step is reachable and saves by keyboard alone, and
   * so is the step-up of opening a draft.
   */
  test('r_nf_03_creator_step_and_open_draft_complete_by_keyboard_alone', async ({ person, request }) => {
    const f = superSafe();
    const t = await onboardedTenant(person, cellA(request));
    const origin = t.cell.origin;
    const a1 = t.a1.page;
    await a1.goto(`${origin}${APP.creatorNew}`);
    await tabTo(a1, CREATOR_UI.open);
    await a1.keyboard.press('Enter');
    await expect(a1.locator(STEPUP.dialog)).toBeVisible();
    await tabTo(a1, STEPUP.confirm);
    await a1.keyboard.press('Enter');
    await expect(a1).toHaveURL((u) => /\/creator\/start$/.test(u.pathname));
    const p = programmeOf(a1);
    const { m1 } = await addProgrammeManager(person, t, p);
    await applySuperSafeTemplate(m1, origin, p);

    await m1.page.goto(`${origin}${APP.creatorStep(p, 'funder')}`);
    const ceiling = '[data-field="funder.p58_recipient_ceiling"] [data-path=""]';
    await tabTo(m1.page, ceiling);
    await m1.page.keyboard.type(String(fixtureValue(f, 'funder.p58_recipient_ceiling')));
    await tabTo(m1.page, CREATOR_UI.stepSave);
    await m1.page.keyboard.press('Enter');
    await expect(m1.page.locator(CREATOR_UI.stepStatus)).toHaveAttribute('data-state', 'saved');
    expect(draftValue(await readDraft(m1.page, origin, p), 'funder.p58_recipient_ceiling')).toBe(
      fixtureValue(f, 'funder.p58_recipient_ceiling'),
    );
  });
});

/**
 * Visits every creator page state of J1 and runs `check` on each: the
 * open-draft page and its step-up dialog (A1), the starting point page,
 * steps 1 to 10 and the review (M1), the invitation landing (an
 * invitee), the people admin page (A1) and the approval inbox (A2).
 */
async function eachCreatorPage(
  person: () => Promise<Page>,
  request: Parameters<typeof cellA>[0],
  check: (page: Page, label: string, tenantAdmin: boolean) => Promise<void>,
): Promise<void> {
  const t = await onboardedTenant(person, cellA(request));
  const origin = t.cell.origin;
  const a1 = t.a1.page;
  await a1.goto(`${origin}${APP.creatorNew}`);
  await check(a1, 'open draft', true);
  await a1.locator(CREATOR_UI.open).click();
  await expect(a1.locator(STEPUP.dialog)).toBeVisible();
  await check(a1, 'open draft step-up dialog', true);
  await a1.keyboard.press('Escape');
  const p = await openDraft(t.a1, origin);
  await check(a1, 'starting point', true);

  const invitee = await newPerson(person, syntheticEmail('m1'));
  await invite(a1, origin, p, invitee.email, 'programme_manager');
  await check(a1, 'people step', true);
  const mail = await t.control.newest(invitee.email, 'invitation');
  await invitee.page.goto(mail.link);
  await check(invitee.page, 'invitation landing', false);
  await t.a1.page.goto(`${origin}${APP.people(p)}`);
  await check(a1, 'people admin', true);

  const { m1 } = await addProgrammeManager(person, t, p);
  await applySuperSafeTemplate(m1, origin, p);
  for (const step of CREATOR_STEPS) {
    await m1.page.goto(`${origin}${APP.creatorStep(p, step)}`);
    await check(m1.page, `creator step ${step}`, false);
  }
  await m1.page.goto(`${origin}${APP.creatorStep(p, REVIEW_STEP)}`);
  await check(m1.page, 'review', false);
  await t.a2.page.goto(`${origin}${APP.approvals}`);
  await check(t.a2.page, 'approval inbox', true);
  // The draft read is the same-origin API the pages use.
  expect((await call(m1.page, origin, 'GET', API.draft(p))).status).toBe(200);
}
