/**
 * I-67 in the browser: activating a programme needs approval by a second
 * person who did not build it (design sections 2.2 J1, 3.2 and 8.7
 * `creator/second_person`).
 *
 * The builder set is every account that issued `OpenDraft`, `ApplyStart`,
 * an `EditPolicy`, a creator record, an import resolution, or a
 * `GrantRole` on the draft (Q1, interim). The approver is a tenant admin
 * outside it. The vault must answer `IsVerified` for the approver and
 * every builder, and `SameIdentityAsAny(approver, builders)` must answer
 * false (Q2, interim).
 *
 * Red until the pages of lane W4a and `fstp-e2e-cell` of lane W5 exist.
 */

import { expect, type Page } from '@playwright/test';
import { call, confirmStepUp, test } from '../playwright.config';
import { APP, APPROVAL_UI, STEPUP } from './contract';
import {
  addProgrammeManager,
  applySuperSafeTemplate,
  cellA,
  fixtureValue,
  onboardedTenant,
  openDraft,
  readDraft,
  reviewAndRequest,
  saveStep,
  setFieldValue,
  superSafe,
  walkCreatorSteps,
  type Person,
  type Tenant,
} from './support';

test.describe.configure({ timeout: 900_000 });

/** A tenant, a draft opened by A1, built by M1 from the template, with activation requested. */
async function requested(
  person: () => Promise<Page>,
  request: Parameters<typeof cellA>[0],
  opts: { readonly m1SameIdentityAsA2?: boolean } = {},
): Promise<{ t: Tenant; p: string; m1: Person }> {
  const f = superSafe();
  const t = await onboardedTenant(person, cellA(request));
  const origin = t.cell.origin;
  const p = await openDraft(t.a1, origin);
  const { m1 } = await addProgrammeManager(person, t, p, opts.m1SameIdentityAsA2 === true ? t.a2Account : undefined);
  await applySuperSafeTemplate(m1, origin, p);
  await walkCreatorSteps(m1, origin, p, f);
  await reviewAndRequest(m1, origin, p);
  return { t, p, m1 };
}

/**
 * Clicks approve on the inbox item of `p` and returns the refusal's rule.
 * When the page asks for a step-up first, the step-up is completed, so
 * the refusal cannot come from a missing step-up.
 */
async function refusedApproval(page: Page, origin: string, p: string): Promise<string | null> {
  await page.goto(`${origin}${APP.approvals}`);
  const item = page.locator(APPROVAL_UI.item(p));
  await expect(item).toHaveCount(1);
  await item.locator('[data-action="approve"]').click();
  const alert = page.locator(APPROVAL_UI.error);
  const dialog = page.locator(STEPUP.dialog);
  await expect(alert.or(dialog)).toBeVisible();
  if (await dialog.isVisible()) {
    await confirmStepUp(page);
  }
  await expect(alert).toBeVisible();
  await expect(alert).toHaveAttribute('role', 'alert');
  return alert.getAttribute('data-rule');
}

test.describe('I-67 second approver', () => {
  /**
   * I-67: A1 opened the draft and granted M1, so A1 is a builder. The
   * inbox offers A1 no approval, and the same-origin call from A1's page
   * is refused under I-67 without asking for a step-up.
   */
  test('i67_builder_admin_cannot_approve_activation', async ({ person, request }) => {
    const { t, p } = await requested(person, request);
    const origin = t.cell.origin;
    const a1 = t.a1.page;
    await a1.goto(`${origin}${APP.approvals}`);
    await expect(a1.locator(`${APPROVAL_UI.item(p)} [data-action="approve"]`)).toHaveCount(0);

    const draft = await readDraft(a1, origin, p);
    const r = await call(a1, origin, 'POST', `/api/v1/programmes/${p}/activation`, { revision: draft.revision });
    expect(r.status, r.body).toBeGreaterThanOrEqual(400);
    expect(r.status, r.body).toBeLessThan(500);
    const body = JSON.parse(r.body) as { rule?: unknown };
    expect(body.rule, 'a builder is refused under I-67 before any step-up').toBe('I-67');
    expect((await readDraft(a1, origin, p)).status).toBe('draft');
  });

  /**
   * I-67 Sybil case (Q2): M1's verified identity names the same person as
   * A2. A2 is outside the builder set by account, but not by person, so
   * the approval is refused and the draft stays a draft.
   */
  test('i67_approver_sharing_identity_with_a_builder_is_refused', async ({ person, request }) => {
    const { t, p } = await requested(person, request, { m1SameIdentityAsA2: true });
    const origin = t.cell.origin;
    expect(await refusedApproval(t.a2.page, origin, p)).toBe('I-67');
    expect((await readDraft(t.a2.page, origin, p)).status).toBe('draft');
  });

  /**
   * I-66 with the I-67 clearance: an edit after the activation request
   * voids it, since the clearance binds the draft revision. A2's approval
   * then activates nothing.
   */
  test('i66_edit_after_the_activation_request_voids_it', async ({ person, request }) => {
    const f = superSafe();
    const { t, p, m1 } = await requested(person, request);
    const origin = t.cell.origin;
    await m1.page.goto(`${origin}${APP.creatorStep(p, 'identity')}`);
    await setFieldValue(m1.page, 'identity.scope', `${String(fixtureValue(f, 'identity.scope'))}, revised`);
    await saveStep(m1.page);

    const a2 = t.a2.page;
    await a2.goto(`${origin}${APP.approvals}`);
    const approve = a2.locator(`${APPROVAL_UI.item(p)} [data-action="approve"]`);
    if ((await approve.count()) > 0) {
      await refusedApproval(a2, origin, p);
    }
    expect((await readDraft(a2, origin, p)).status).toBe('draft');
  });
});
