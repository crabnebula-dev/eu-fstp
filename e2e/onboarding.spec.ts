/**
 * Tenant onboarding in the cell, through the browser (design sections
 * 2.2 J0, 3.5 and 8.7 `onboarding`).
 *
 * R-TN-01: new tenants are set up through a guided onboarding flow. Each
 * step validates before the next opens, and the tenant can save and
 * return at any point (`programme-creator.md`). SoD-07: at least two
 * tenant admins. R-LG-03: inviting a tenant admin and changing a tenant
 * setting are high-risk, so each needs a fresh step-up. SoD-14 and SoD-15:
 * the Administrators step validates only with a holder of Financial
 * signatory and of Legal signatory, which another tenant admin grants
 * (SoD-07). SoD-18: one tenant admin requests activation of the
 * organisation and a different one approves it.
 *
 * The page contract is in `creator/contract.ts`. Red until the pages of
 * lane W4a and `fstp-e2e-cell` of lane W5 exist.
 */

import { expect, type Page } from '@playwright/test';
import { call, enrolByInvite, okJson, syntheticEmail, test } from './playwright.config';
import {
  API,
  APP,
  ONBOARDING_STEPS,
  ONBOARDING_UI,
  SETTING_UI,
  SIGNATORY_ROLES,
  STEPUP,
  signatoryRoleChoice,
} from './creator/contract';
import {
  cancelStepUp,
  cellA,
  completeOnboarding,
  contrastBothThemes,
  fillOnboardingStep,
  firstAdmin,
  footerProblems,
  grantSignatories,
  grantSignatory,
  inviteSecondAdmin,
  navStatuses,
  newPerson,
  saveOnboardingStep,
  structureProblems,
  tabTo,
  verifyOnIdentityPage,
  walkStepsBeforeAdministrators,
  withStepUp,
  ONBOARDING_VALUES,
} from './creator/support';

test.describe.configure({ timeout: 600_000 });

/** The status of `step` as `GET /api/v1/admin/onboarding/{step}` answers it. */
async function apiStatus(page: Page, origin: string, step: (typeof ONBOARDING_STEPS)[number]): Promise<unknown> {
  return okJson(await call(page, origin, 'GET', API.onboardingStep(step)), `GET onboarding ${step}`)['status'];
}

test.describe('R-TN-01 onboarding', () => {
  /**
   * R-TN-01 and SoD-07: A1 walks the nine steps in the order of the spec
   * table. Each opens only once the one before validated. A2 joins as the
   * second verified admin, and onboarding completes.
   */
  test('r_tn_01_onboarding_walks_every_step_in_order_and_completes', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1, a1Account } = await firstAdmin(person, control);
    const page = a1.page;
    await page.goto(`${origin}${APP.onboarding('organisation')}`);
    expect(Object.keys(await navStatuses(page)), 'the steps in the order of the spec table').toEqual([...ONBOARDING_STEPS]);

    for (const [i, step] of ONBOARDING_STEPS.entries()) {
      await page.goto(`${origin}${APP.onboarding(step)}`);
      const before = await navStatuses(page);
      expect(before[step], `${step} is open once the steps before it validated`).toMatch(/^(open|saved)$/);
      for (const later of ONBOARDING_STEPS.slice(i + 1)) {
        expect(before[later], `${later} stays locked while ${step} is not validated`).toBe('locked');
      }
      if (step === 'administrators') break;
      await fillOnboardingStep(page, step);
      await saveOnboardingStep(page, 'validated');
      expect(await apiStatus(page, origin, step)).toBe('validated');
      await expect(page.locator(ONBOARDING_UI.next)).toHaveCount(1);
    }

    const { a2 } = await inviteSecondAdmin(person, control, a1);
    // SoD-07, SoD-14, SoD-15: A2 grants both signatory roles to A1.
    await grantSignatories(a2, origin, a1Account);
    await completeOnboarding(page, origin);
    for (const step of ONBOARDING_STEPS) {
      expect(await apiStatus(page, origin, step), `${step} after completion`).toBe('validated');
    }
  });

  /**
   * R-TN-01: a later step opened directly shows that it is locked and
   * offers no form, and a step with invalid values does not open the next.
   */
  test('r_tn_01_a_later_step_stays_locked_until_the_earlier_one_validates', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1 } = await firstAdmin(person, control);
    const page = a1.page;

    await page.goto(`${origin}${APP.onboarding('identity')}`);
    await expect(page.locator(ONBOARDING_UI.locked)).toBeVisible();
    await expect(page.locator(ONBOARDING_UI.form)).toHaveCount(0);
    expect(await apiStatus(page, origin, 'identity')).toBe('locked');

    await page.goto(`${origin}${APP.onboarding('organisation')}`);
    await page.locator('[name="data_protection_contact"]').fill(ONBOARDING_VALUES.dataProtectionContact);
    await saveOnboardingStep(page, 'invalid_values');
    await expect(page.locator(ONBOARDING_UI.next)).toHaveCount(0);
    expect((await navStatuses(page))['agreements']).toBe('locked');
    expect(await apiStatus(page, origin, 'agreements')).toBe('locked');

    // Save and return: the saved contact is still there after a reload.
    await page.reload();
    await expect(page.locator('[name="data_protection_contact"]')).toHaveValue(ONBOARDING_VALUES.dataProtectionContact);
  });

  /**
   * SoD-07: onboarding completes only with two verified tenant admins. The
   * Administrators step fails with one, and so does completion while the
   * second admin has not verified identity (Q2, interim).
   */
  test('sod07_onboarding_completes_only_with_two_verified_admins', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1, a1Account } = await firstAdmin(person, control);
    const page = a1.page;
    await walkStepsBeforeAdministrators(page, origin);

    await page.goto(`${origin}${APP.onboarding('administrators')}`);
    await saveOnboardingStep(page, 'too_few_admins');
    await page.goto(`${origin}${APP.onboardingSummary}`);
    await page.locator(ONBOARDING_UI.complete).click();
    await expect(page.getByRole('alert').first()).toBeVisible();
    await expect(page.locator(`${ONBOARDING_UI.completeOutcome}[data-outcome="completed"]`)).toHaveCount(0);

    // A2 enrols but has not verified identity yet.
    const email = syntheticEmail('a2');
    await page.goto(`${origin}${APP.onboarding('administrators')}`);
    await page.locator(ONBOARDING_UI.adminInviteEmail).fill(email);
    await withStepUp(page, page.locator(ONBOARDING_UI.adminInviteSubmit));
    const a2 = await newPerson(person, email);
    await enrolByInvite(a2.page, origin, (await control.newest(email, 'admin_invitation')).link);
    await page.goto(`${origin}${APP.onboardingSummary}`);
    await page.locator(ONBOARDING_UI.complete).click();
    await expect(page.getByRole('alert').first()).toBeVisible();
    await expect(page.locator(`${ONBOARDING_UI.completeOutcome}[data-outcome="completed"]`)).toHaveCount(0);

    await verifyOnIdentityPage(a2, control, origin);
    // SoD-14, SoD-15: A2 grants both signatory roles to A1 (SoD-07).
    await grantSignatories(a2, origin, a1Account);
    await completeOnboarding(page, origin);
  });

  /**
   * SoD-14, SoD-15, SoD-07 and SoD-18 through the pages. With two verified
   * admins and no signatory, the Administrators step names each role
   * still missing and does not validate, and an activation request is
   * refused. A1 cannot grant a role to A1, so A2 grants both. Completing
   * onboarding does not activate the organisation. A1 requests
   * activation, A1's own approval is refused, and A2's approval
   * activates it.
   */
  test('sod14_sod18_signatories_block_the_administrators_step_and_activation_needs_a_second_admin', async ({
    person,
    request,
  }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1, a1Account } = await firstAdmin(person, control);
    const page = a1.page;
    await walkStepsBeforeAdministrators(page, origin);
    const { a2, a2Account } = await inviteSecondAdmin(person, control, a1);
    const alert = page.locator(ONBOARDING_UI.alert).first();
    const activation = async (p: Page): Promise<Record<string, unknown>> => {
      return okJson(await call(p, origin, 'GET', API.activation), 'GET activation');
    };
    const holders = async (p: Page): Promise<unknown> => {
      return okJson(await call(p, origin, 'GET', API.signatories), 'GET signatories')['signatories'];
    };

    // SoD-14, SoD-15: two verified admins but no signatory, so the step is blocked.
    await page.goto(`${origin}${APP.onboarding('administrators')}`);
    await expect(page.locator(`${ONBOARDING_UI.admins} li[data-account]`)).toHaveCount(2);
    for (const role of SIGNATORY_ROLES) {
      await expect(
        page.locator(`${ONBOARDING_UI.signatories} section[data-signatory-role="${role}"] [data-empty="true"]`),
        `SoD-14, SoD-15: ${role} has no holder`,
      ).toHaveCount(1);
    }
    await expect(page.locator(ONBOARDING_UI.signatoryMissing)).toBeVisible();
    await saveOnboardingStep(page, 'no_financial_signatory');
    await expect(page.locator(ONBOARDING_UI.next)).toHaveCount(0);
    expect(await apiStatus(page, origin, 'administrators')).not.toBe('validated');

    // SoD-14: an activation request without a Financial signatory is refused.
    await page.goto(`${origin}${APP.onboardingSummary}`);
    await expect(page.locator(ONBOARDING_UI.activationState)).toHaveAttribute('data-state', 'not_requested');
    await expect(page.locator(ONBOARDING_UI.activationMissing)).toBeVisible();
    await page.locator(ONBOARDING_UI.activationRequest).click();
    await expect(alert).toHaveAttribute('data-rule', 'SoD-14');
    expect((await activation(page))['state']).toBe('not_requested');

    // SoD-07: A1 cannot grant a signatory role to A1, and no step-up begins.
    await page.goto(`${origin}${APP.onboarding('administrators')}`);
    await page.locator(ONBOARDING_UI.signatoryAccount).selectOption(a1Account);
    await page.locator(signatoryRoleChoice('financial_signatory')).check();
    await page.locator(ONBOARDING_UI.signatoryGrant).click();
    await expect(alert).toHaveAttribute('data-rule', 'SoD-07');
    await expect(page.locator(STEPUP.dialog)).toBeHidden();
    expect(await holders(page), 'SoD-07: the self-grant bound nothing').toEqual([]);

    // SoD-15: with only a Financial signatory, the step names the Legal role.
    await grantSignatory(a2, origin, a1Account, 'financial_signatory');
    await page.goto(`${origin}${APP.onboarding('administrators')}`);
    await saveOnboardingStep(page, 'no_legal_signatory');
    await expect(page.locator(ONBOARDING_UI.next)).toHaveCount(0);
    await grantSignatory(a2, origin, a1Account, 'legal_signatory');
    await completeOnboarding(page, origin);
    expect(await apiStatus(page, origin, 'administrators')).toBe('validated');

    // SoD-18: completing onboarding does not activate the organisation.
    await page.goto(`${origin}${APP.onboardingSummary}`);
    const state = page.locator(ONBOARDING_UI.activationState);
    await expect(state).toHaveAttribute('data-state', 'not_requested');
    expect((await activation(page))['state']).toBe('not_requested');
    await page.locator(ONBOARDING_UI.activationRequest).click();
    await expect(state).toHaveAttribute('data-state', 'requested');

    // SoD-18: A1 requested activation, so A1's approval is refused.
    await page.locator(ONBOARDING_UI.activationApprove).click();
    await expect(alert).toHaveAttribute('data-rule', 'SoD-18');
    await page.reload();
    await expect(state).toHaveAttribute('data-state', 'requested');
    const requested = await activation(page);
    expect(requested['state']).toBe('requested');
    expect(requested['requested_by']).toBe(a1Account);
    expect(requested['approved_by']).toBeNull();

    // SoD-18: A2, a second tenant admin, approves, and the organisation is active.
    await a2.page.goto(`${origin}${APP.onboardingSummary}`);
    const a2State = a2.page.locator(ONBOARDING_UI.activationState);
    await expect(a2State).toHaveAttribute('data-state', 'requested');
    await a2.page.locator(ONBOARDING_UI.activationApprove).click();
    await expect(a2State).toHaveAttribute('data-state', 'active');
    const active = await activation(a2.page);
    expect(active['state']).toBe('active');
    expect(active['requested_by']).toBe(a1Account);
    expect(active['approved_by']).toBe(a2Account);
  });

  /**
   * R-LG-03: inviting a tenant admin grants tenant admin, so it is
   * high-risk (`authentication.md`). A cancelled step-up sends no
   * invitation, and a completed one does.
   */
  test('r_lg_03_inviting_a_tenant_admin_needs_step_up', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1 } = await firstAdmin(person, control);
    const page = a1.page;
    await walkStepsBeforeAdministrators(page, origin);
    const email = syntheticEmail('a2');
    await page.goto(`${origin}${APP.onboarding('administrators')}`);
    await page.locator(ONBOARDING_UI.adminInviteEmail).fill(email);
    await cancelStepUp(page, page.locator(ONBOARDING_UI.adminInviteSubmit));
    await expect(control.newest(email, 'admin_invitation')).rejects.toThrow(/no admin_invitation message/);

    await page.locator(ONBOARDING_UI.adminInviteEmail).fill(email);
    await withStepUp(page, page.locator(ONBOARDING_UI.adminInviteSubmit));
    expect((await control.newest(email, 'admin_invitation')).link).toContain('/auth/invite');
  });

  /**
   * R-LG-03: every tenant setting change is high-risk (design section
   * 3.5, interim strict reading). P-69, the template licence, is the
   * example: a cancelled step-up leaves it unchanged.
   */
  test('r_lg_03_changing_a_tenant_setting_needs_step_up', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1 } = await firstAdmin(person, control);
    const page = a1.page;
    await page.goto(`${origin}${APP.setting('p69')}`);
    const current = page.locator(SETTING_UI.current);
    await expect(current).toBeVisible();
    const was = (await current.innerText()).trim();
    const next = was === 'MIT' ? 'Apache-2.0' : 'MIT';

    await page.locator(SETTING_UI.value).fill(next);
    await cancelStepUp(page, page.locator(SETTING_UI.save));
    await page.reload();
    await expect(page.locator(SETTING_UI.current)).toHaveText(was);

    await page.locator(SETTING_UI.value).fill(next);
    await withStepUp(page, page.locator(SETTING_UI.save));
    await page.reload();
    await expect(page.locator(SETTING_UI.current)).toHaveText(next);
  });

  /**
   * R-NF-03 (in-house checks of design section 8.7): every onboarding
   * page state has structure, named controls and AA contrast in light
   * and dark.
   */
  test('r_nf_03_onboarding_pages_have_structure_names_and_contrast', async ({ person, request }) => {
    const problems: string[] = [];
    await eachOnboardingPage(person, request, async (page, label) => {
      problems.push(...(await structureProblems(page, label)), ...(await contrastBothThemes(page, label)));
    });
    expect(problems).toEqual([]);
  });

  /**
   * R-WL-04 and P-68, with the I-69 seam: every onboarding page shows the
   * privacy notice, the accessibility statement, the platform attribution
   * and, for the tenant admin, the Data Act information.
   */
  test('r_wl_04_every_onboarding_page_shows_the_mandatory_footer', async ({ person, request }) => {
    const problems: string[] = [];
    await eachOnboardingPage(person, request, async (page, label) => {
      problems.push(...(await footerProblems(page, label, true)));
    });
    expect(problems).toEqual([]);
  });

  /** R-NF-03: the Organisation step completes by keyboard alone. */
  test('r_nf_03_an_onboarding_step_completes_by_keyboard_alone', async ({ person, request }) => {
    const control = cellA(request);
    const origin = control.cell.origin;
    const { a1 } = await firstAdmin(person, control);
    const page = a1.page;
    await page.goto(`${origin}${APP.onboarding('organisation')}`);
    await tabTo(page, '[name="data_protection_contact"]');
    await page.keyboard.type(ONBOARDING_VALUES.dataProtectionContact);
    await tabTo(page, 'input[type="checkbox"][name="signatories"]');
    await page.keyboard.press('Space');
    await tabTo(page, ONBOARDING_UI.save);
    await page.keyboard.press('Enter');
    await expect(page.locator(ONBOARDING_UI.outcome)).toHaveAttribute('data-outcome', 'validated');
    await tabTo(page, ONBOARDING_UI.next);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL((u) => u.pathname === APP.onboarding('agreements'));
  });
});

/**
 * Visits every onboarding page state and runs `check` on each: the
 * identity page, each step before and after its save, the step-up dialog
 * of the P-20 setting and of the admin invitation, a locked step, and
 * the summary.
 */
async function eachOnboardingPage(
  person: () => Promise<Page>,
  request: Parameters<typeof cellA>[0],
  check: (page: Page, label: string) => Promise<void>,
): Promise<void> {
  const control = cellA(request);
  const origin = control.cell.origin;
  const { a1 } = await firstAdmin(person, control);
  const page = a1.page;
  await page.goto(`${origin}${APP.identity}`);
  await check(page, 'identity');
  await page.goto(`${origin}${APP.onboarding('channels')}`);
  await check(page, 'locked step');
  for (const step of ONBOARDING_STEPS) {
    await page.goto(`${origin}${APP.onboarding(step)}`);
    await check(page, `${step} open`);
    if (step === 'payments') {
      await page.locator(`${ONBOARDING_UI.p20}[value="${ONBOARDING_VALUES.p20}"]`).check();
      await page.locator(ONBOARDING_UI.p20Save).click();
      await expect(page.locator(STEPUP.dialog)).toBeVisible();
      await check(page, 'P-20 step-up dialog');
      await page.keyboard.press('Escape');
    }
    if (step === 'administrators') {
      await page.locator(ONBOARDING_UI.adminInviteEmail).fill(syntheticEmail('a2'));
      await page.locator(ONBOARDING_UI.adminInviteSubmit).click();
      await expect(page.locator(STEPUP.dialog)).toBeVisible();
      await check(page, 'admin invitation step-up dialog');
      await page.keyboard.press('Escape');
      break;
    }
    await fillOnboardingStep(page, step);
    await saveOnboardingStep(page, 'validated');
    await check(page, `${step} validated`);
  }
  await page.goto(`${origin}${APP.onboardingSummary}`);
  await check(page, 'summary');
}
