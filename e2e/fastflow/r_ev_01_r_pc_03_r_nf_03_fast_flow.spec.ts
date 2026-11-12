/**
 * The fast flow of the demo (lane m4/fast-flow): the knock-out criteria
 * and the early decision, as one live chain clicked from the front door
 * `/demo` (the click-through rule: each person reaches their work by
 * clicking from sign-in).
 *
 * - R-PC-03, roles table: "Call drafter D1" writes the knock-out criteria
 *   on "Knock-out criteria", reached from Home. Programme manager M1,
 *   another person, approves and publishes call 1 on "Approval and
 *   publication", reached from "Programme set-up".
 * - R-EV-01, R-CF-02: Coordinator C1 reaches the intake queue from the
 *   mailbox, declares no conflict, sees the criteria D1 wrote by their
 *   text, fails one proposal with a reason (INELIGIBLE) and passes
 *   another.
 * - O-54, I-27: the lead of the failed proposal reads the outcome and the
 *   reason on the proposal page. The notice mail on `/demo` holds ids and
 *   a link only.
 * - R-NF-03: every page reached is ready, with no console error.
 *
 * Run with `tools/demo/run.sh e2e fastflow/` against the demo cell. Every
 * person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell } from '../site/contract';
import { Seat } from '../speedrun/support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The criteria D1 writes, in P-09 order. */
const WRITTEN = [
  'Synthetic: the proposal builds open technology for the Open Internet Stack.',
  'Synthetic: research and development is the primary objective.',
  'Synthetic: the proposal is written in English.',
];

/** The reason C1 records for the failed proposal. */
const REASON = 'Synthetic: the project bridges two closed protocols, so it does not build open technology.';

/** Proposal z, which fails, and proposal x, which passes. */
const Z = '1002';
const X = '1001';

const D1 = /Call drafter D1/;
const LEAD_Z = /synthetic-lead-z-[0-9a-f]+@e2e\.invalid/;

/** Clicks `link` and waits for the client-side page at `path`, ready. */
async function go(page: Page, link: string, path: RegExp): Promise<void> {
  const a = page.locator(link).first();
  await expect(a, `the page offers ${link}`).toBeVisible();
  await a.click();
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
}

/** Presses `button`, confirms a step-up when one opens (I-78), and waits for `done`. */
async function press(page: Page, button: string, done: string): Promise<void> {
  await page.locator(button).click();
  const dialog = page.locator('dialog#stepup');
  await expect(page.locator(`${done}, dialog#stepup[open]`).first()).toBeVisible();
  if (await dialog.isVisible()) {
    await page.locator('#stepup-confirm').click();
    await expect(dialog).toBeHidden();
  }
  await expect(page.locator(done).first()).toBeVisible();
}

/**
 * Collects console errors of `page`. The 401 that asks for a step-up
 * (I-78) is the protocol, not an error, so it is left out.
 */
function watch(page: Page): () => string[] {
  const out: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error' && !m.text().includes('status of 401')) out.push(m.text());
  });
  page.on('pageerror', (e) => out.push(String(e)));
  return () => out;
}

test.describe('fast flow: criteria and the early decision', () => {
  test.describe.configure({ timeout: 300_000 });

  test('r_ev_01_r_pc_03_r_nf_03_drafter_writes_the_criteria_and_the_coordinator_applies_them', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    await door.chooseScene('/demo/fast');
    await expect(door.page.locator('#demo-scene')).toContainText('fast_flow');
    await expect(door.item(D1).locator('[data-demo-role]')).toHaveText('Call drafter');

    // 1. D1 writes the knock-out criteria, from Home.
    const d1 = await Seat.signIn(browser, cell, D1);
    const d1Errors = watch(d1.page);
    await go(d1.page, '#home-work a[data-work="knock-outs"]', /^\/app\/programmes\/1\/studio\/knock-outs$/);
    await expect(d1.page.locator('main h1')).toHaveText('Knock-out criteria');
    await expect(d1.page.locator('main[data-ready="true"]')).toHaveCount(1);
    await expect(d1.page.locator('[data-note="separation"]')).toContainText('SoD-01');
    await expect(d1.page.locator('[data-note="returns-to-draft"]')).toBeVisible();
    const field = d1.page.locator('[data-field="evaluation.p09_knock_outs"]');
    const texts = field.locator('textarea');
    await expect(texts.first()).toBeVisible();
    while ((await texts.count()) < WRITTEN.length) {
      await field.locator('[data-action="add"]').first().click();
    }
    while ((await texts.count()) > WRITTEN.length) {
      await field.locator('[data-action="remove"]').last().click();
    }
    for (const [i, text] of WRITTEN.entries()) {
      await texts.nth(i).fill(text);
    }
    await d1.page.locator('#knock-outs-save').click();
    await expect(d1.page.locator('#knock-outs-status')).toHaveAttribute('data-state', 'saved');
    for (const [i, text] of WRITTEN.entries()) {
      await expect(texts.nth(i), 'the saved criteria read back by their text').toHaveValue(text);
    }
    expect(d1Errors(), 'no console error on the drafter pages').toEqual([]);
    // R-PC-03: the drafter is offered no approval of the call. The page
    // is the programme manager's, so its report read is refused here.
    await d1.page.goto(`${cell.origin}/app/programmes/1/studio/approval`);
    await settle(d1.page);
    await expect(d1.page.locator('[data-note="drafter"]')).toBeVisible();
    await expect(d1.page.locator('[data-action="approve-call"]')).toHaveCount(0);
    await d1.close();

    // 2. M1, another person, approves and publishes call 1.
    const m1 = await Seat.signIn(browser, cell, DOOR.m1);
    const m1Errors = watch(m1.page);
    await go(m1.page, '#home-work a[data-work="studio"]', /^\/app\/programmes\/1\/studio$/);
    await go(m1.page, 'main a[href="/app/programmes/1/studio/approval"]', /\/studio\/approval$/);
    await expect(m1.page.locator('#seal-call-list li[data-call="1"]')).toHaveAttribute('data-state', 'DRAFT');
    await expect(m1.page.locator('#seal-call-number')).toHaveValue('1');
    await press(m1.page, '[data-action="approve-call"]', '#seal-call-status:has-text("Approved")');
    await press(m1.page, '[data-action="publish-call"]', '#seal-call-status:has-text("Published")');
    expect(m1Errors(), 'no console error on the approval page').toEqual([]);
    await m1.close();

    // 3. The synthetic proposals arrive, through the demo control.
    await door.chooseScene('/demo/fast/submit');
    await expect(door.item(LEAD_Z).locator('[data-demo-does]')).toContainText(`proposal ${Z}, now SUBMITTED`);

    // 4. C1 reaches the intake queue from the mailbox.
    const c1 = await Seat.signIn(browser, cell, DOOR.c1);
    const c1Errors = watch(c1.page);
    await go(c1.page, '#home-mailbox a[data-mailbox-link]', /^\/app\/mailbox$/);
    await go(c1.page, '#mailbox-list li[data-kind="intake.knock_out"] a', /^\/app\/calls\/1\/intake$/);
    for (const [p, fail] of [
      [Z, true],
      [X, false],
    ] as const) {
      await go(c1.page, `#intake-table tr[data-proposal="${p}"] a[href="/app/proposals/${p}/declaration"]`, /\/declaration$/);
      await c1.page.locator('#declare-conflicted-no').check();
      await c1.page.locator('#declare-submit').click();
      await go(c1.page, `a[href="/app/proposals/${p}/knock-out"]:has-text("Go to the knock-out check")`, /\/knock-out$/);
      // The criteria D1 wrote, by their text, in P-09 order.
      await expect(c1.page.locator('#knockout-form legend')).toHaveText(WRITTEN);
      const ids = await c1.page
        .locator('#knockout-form input[type="radio"][value="pass"]')
        .evaluateAll((els) => els.map((e) => e.id.replace(/^knockout-/, '').replace(/-pass$/, '')));
      for (const [i, id] of ids.entries()) {
        await c1.page.locator(`#knockout-${id}-${fail && i === 0 ? 'fail' : 'pass'}`).check();
      }
      if (fail) {
        await c1.page.locator('#knockout-submit').click();
        await expect(c1.page.locator('#knockout-reason'), 'R-EV-01: a failure needs its reason').toHaveAttribute('aria-invalid', 'true');
        await c1.page.locator('#knockout-reason').fill(REASON);
      }
      await c1.page.locator('#knockout-submit').click();
      await expect(c1.page.locator('#proposal-state')).toHaveAttribute('data-state', fail ? 'INELIGIBLE' : 'SUBMITTED');
      if (fail) {
        // Back to the intake queue by the mailbox in the top bar.
        await go(c1.page, 'header a[data-tool="mailbox"]', /^\/app\/mailbox$/);
        await go(c1.page, '#mailbox-list li[data-kind="intake.knock_out"] a', /^\/app\/calls\/1\/intake$/);
        await expect(c1.page.locator(`#intake-table tr[data-proposal="${Z}"]`)).toHaveAttribute('data-state', 'INELIGIBLE');
      }
    }
    expect(c1Errors(), 'no console error on the coordinator pages').toEqual([]);
    await c1.close();

    // 5. The lead of z reads the outcome and the reason (O-54).
    await door.reload();
    const lead = await Seat.signIn(browser, cell, LEAD_Z);
    await go(lead.page, `#home-work a[href="/app/proposals/${Z}"]`, new RegExp(`^/app/proposals/${Z}$`));
    await expect(lead.page.locator('#proposal-outcome')).toContainText('Not eligible');
    await expect(lead.page.locator('#proposal-knock-out-reason')).toContainText(REASON);
    await lead.close();

    // 6. I-27: the notice mail holds ids and a link, never the reason.
    let raw: string | null = null;
    await expect
      .poll(
        async () => {
          await door.reload();
          const row = door.page.locator('#demo-mail li[data-demo-mail]', { hasText: `Proposal ${Z}: status INELIGIBLE` }).filter({ has: door.page.locator('a') });
          if ((await row.count()) === 0) return false;
          raw = await row.first().locator('a').first().getAttribute('href');
          return raw !== null;
        },
        { message: 'the outcome mail of the lead is listed', timeout: 30_000, intervals: [500, 1000] },
      )
      .toBe(true);
    await door.page.goto(new URL(raw ?? '', cell.control).href);
    const message = await door.page.locator('#raw-message').innerText();
    expect(message).toContain(`/app/proposals/${Z}`);
    expect(message, 'I-27: the reason stays on the platform').not.toContain('closed protocols');
    expect(message, 'I-27: the criteria stay on the platform').not.toContain('Open Internet Stack');
    await door.close();
  });
});
