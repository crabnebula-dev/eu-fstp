/**
 * The speedrun through the post-grant screens of lane m5/ui
 * (`docs/handoff/m5-ui.md`), by clicking from the demo sign-in of each
 * person (M5 design sections 1.2 and 7, the demo click-through rule).
 * Each person starts at the home page `/app/` and follows links only.
 * The wire-level run of the same path is `speedrun.api.spec.ts`.
 *
 * Covers R-NG-03, R-CT-01, R-PR-01, R-RP-03, R-NF-03 (state shown as
 * text beside the formal state, I-96). Every person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { FrontDoor } from '../site/contract';
import { Seat, WHO, X, chooseGrantScene, demoLink } from './support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** Waits for a client-side navigation to `path` and its `h1`. */
async function onPage(page: Page, path: RegExp): Promise<void> {
  await page.waitForURL((u) => path.test(u.pathname));
  await expect(page.locator('main h1').first()).toBeVisible();
}

/** Follows the link of `selector` from the page the person is on. */
async function click(page: Page, selector: string, path: RegExp): Promise<void> {
  const link = page.locator(selector).first();
  await expect(link, `the page offers ${selector}`).toBeVisible();
  await link.click();
  await onPage(page, path);
}

test.describe('speedrun through the screens', () => {
  test.describe.configure({ timeout: 300_000 });

  test('ui_lead_reaches_grant_contract_and_payments', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'UNDER_REVIEW');
    const lead = await Seat.signIn(browser, cell, WHO.lead);
    const page = lead.page;
    await click(page, '#home-work a[data-work="grant"]', new RegExp(`/app/grants/${X}$`));
    await expect(page.locator('#grant-state')).toHaveAttribute('data-state', /IN_EXECUTION/);
    await click(page, `a[href="/app/grants/${X}/contract"]`, /\/contract$/);
    await expect(page.locator('#contract-status')).toContainText(/effective/i);
    await page.goBack();
    await click(page, `a[href="/app/grants/${X}/payments"]`, /\/payments$/);
    await expect(page.locator('#pay-table')).toBeVisible();
    await lead.close();
  });

  test('ui_programme_manager_and_finance_reach_operations', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'PAID');
    for (const who of [WHO.pm, WHO.finance, WHO.releaser, WHO.signatory, WHO.auditor]) {
      const seat = await Seat.signIn(browser, cell, who);
      await click(seat.page, '#home-work a[data-work="operations"]', /\/app\/operations$/);
      await seat.close();
    }
    const pm = await Seat.signIn(browser, cell, WHO.pm);
    await click(pm.page, '#home-work a[data-work="grants"]', /\/app\/grants$/);
    await click(pm.page, `a[href="/app/grants/${X}"]`, new RegExp(`/app/grants/${X}$`));
    await pm.close();
  });

  /**
   * R-NG-03: the reviewer reaches the grants list from the home page, then
   * the grant under "Grants you review". The overview is refused to a
   * reviewer, so the page reads `grant.determination_view` and shows the
   * determination form (M5 reads follow-up, `docs/handoff/m5-ui.md`).
   */
  test('ui_reviewer_reaches_the_grants_list', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'NEGOTIATION_READY');
    const r1 = await Seat.signIn(browser, cell, WHO.reviewer);
    await click(r1.page, '#home-work a[data-work="grants"]', /\/app\/grants$/);
    await click(r1.page, `a[href="/app/grants/${X}"]`, new RegExp(`/app/grants/${X}$`));
    await expect(r1.page.locator('#grant-determine-form')).toBeVisible();
    await r1.close();
  });

  test('ui_report_approver_reaches_the_funder_reports', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'ALL_CLOSED');
    const rep = await Seat.signIn(browser, cell, WHO.reportApprover);
    await click(rep.page, 'aside nav a[href="/app/operations"]', /\/app\/operations$/);
    await rep.page.goto(`${cell.origin}/app/programmes/1/reports`);
    await expect(rep.page.locator('#ops-reports-table')).toBeVisible();
    await expect(rep.page.locator('#ops-reports-table')).toContainText(/approved/i);
    await rep.close();
  });
});

/**
 * Presses the button `selector`, then waits until `done` shows. When the
 * cell asks for a step-up (I-78), the step-up dialog opens, and the person
 * confirms it with its demo confirm button, as at the demo.
 */
async function press(page: Page, selector: string, done: string): Promise<void> {
  await page.locator(selector).click();
  const dialog = page.locator('dialog#stepup');
  const shown = page.locator(`${done}, dialog#stepup[open]`).first();
  await expect(shown).toBeVisible();
  if (await dialog.isVisible()) {
    await page.locator('#stepup-confirm').click();
    await expect(dialog).toBeHidden();
  }
  await expect(page.locator(done).first()).toBeVisible();
}

/** Opens the queue row of `task` on the Operations page and returns the request page's path. */
async function openQueued(page: Page, task: 'review' | 'approve' | 'release'): Promise<void> {
  await click(page, `ul[data-task="${task}"] li a`, new RegExp(`/app/grants/${X}/payments/\\d+$`));
}

/**
 * Lane m5/polish-access: the payment path from UNDER_REVIEW to RELEASED by
 * clicking only, with no API call (M5 design section 1.2 rows 11 and 12).
 *
 * - R-PR-08, R-AC-01: the assigned reviewer R1 reaches the request from the
 *   Home card "Payment requests to review" and Operations, sees the evidence
 *   and decides the line on the page (`payment.line_review_view`).
 * - SoD-04, I-05: finance F1 approves and releaser P1 releases. The reviewer
 *   is offered neither.
 * - R-PR-05, I-33: the demo page names the verified bank details and the
 *   end of the P-36 hold. The first release press is refused with I-33.
 *   After the hold link on /demo, the same button releases.
 */
test.describe('payment path by clicking', () => {
  test.describe.configure({ timeout: 300_000 });

  test('ui_payment_under_review_to_released_by_clicking', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'UNDER_REVIEW');
    const door = await FrontDoor.open(browser, cell);
    await expect(door.page.locator('#demo-bank')).toHaveAttribute('data-verified', 'true');
    await expect(door.page.locator('#demo-bank')).toContainText(/verified by finance.*P-36 hold of \d+ days ends/);
    await door.close();

    // R1: Home, "Payment requests to review", Operations, the request, the line review.
    const r1 = await Seat.signIn(browser, cell, WHO.reviewer);
    await expect(r1.page.locator('aside nav a[href="/app/operations"]')).toBeVisible();
    await click(r1.page, '#home-payment-review a[data-work="operations"]', /\/app\/operations$/);
    await openQueued(r1.page, 'review');
    await expect(r1.page.locator('#pay-status')).toHaveAttribute('data-status', 'UNDER_REVIEW');
    await expect(r1.page.locator('#pay-lines-table')).toContainText(/MIT/);
    await expect(r1.page.locator('#pay-approve-submit, #pay-release-submit')).toHaveCount(0);
    const forms = r1.page.locator('form[id^="pay-review-form-"]');
    const n = await forms.count();
    expect(n, 'the line review offers a form per line').toBeGreaterThan(0);
    for (let i = n - 1; i >= 0; i -= 1) {
      // The last decision closes the view, so the forms are decided from the last one up.
      const id = await forms.nth(i).getAttribute('id');
      await press(r1.page, `#${id ?? ''} button[type="submit"]`, i === 0 ? '#pay-review-complete' : '#page-status:not(:empty)');
    }
    await expect(r1.page.locator('#pay-review-complete')).toBeVisible();
    await r1.close();

    // F1: Home, Operations, the approval queue, approve.
    const f1 = await Seat.signIn(browser, cell, WHO.finance);
    await click(f1.page, '#home-work a[data-work="operations"]', /\/app\/operations$/);
    await openQueued(f1.page, 'approve');
    await press(f1.page, '#pay-approve-submit', '#pay-status[data-status="PAYMENT_APPROVED"]');
    await f1.close();

    // P1: Home, Operations, the release queue. The hold still runs (I-33).
    const p1 = await Seat.signIn(browser, cell, WHO.releaser);
    await click(p1.page, '#home-work a[data-work="operations"]', /\/app\/operations$/);
    await openQueued(p1.page, 'release');
    await press(p1.page, '#pay-release-submit', 'main [role="alert"]');
    await expect(p1.page.locator('main [role="alert"]')).toContainText(/I-33/);
    await expect(p1.page.locator('#pay-status')).toHaveAttribute('data-status', 'PAYMENT_APPROVED');

    // The presenter follows the hold link on /demo, then P1 presses release again.
    await demoLink(browser, cell, '/demo/clock?to=p36');
    await press(p1.page, '#pay-release-submit', '#pay-status[data-status="RELEASED"]');
    await p1.close();
  });
});
