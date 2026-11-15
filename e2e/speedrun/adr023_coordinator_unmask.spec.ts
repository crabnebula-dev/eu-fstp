/**
 * The coordinator unmask of ADR-023 (I-17 as amended 2026-11-15) in the
 * demo scene `stage1`, by clicking from the demo sign-in.
 *
 * - Coordinator C1 opens the board, follows the Unmask link of a
 *   proposal, unmasks its applicant with a purpose and the step-up, and
 *   sees the synthetic identity on the vault origin page.
 * - C1 unmasks the person behind a reviewer handle from the assignment
 *   page, the same way.
 * - Committee member R1 sees no Unmask control, and the cell refuses the
 *   parties read and the unmask (I-17: other Judging roles stay masked).
 *
 * Every person and text is synthetic. With `FSTP_UNMASK_SHOTS` set, the
 * spec saves its screenshots in that directory.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { FrontDoor, suiteCell } from '../site/contract';
import { Seat } from './support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

const SHOTS = process.env['FSTP_UNMASK_SHOTS'] ?? '';
const PURPOSE = 'Synthetic purpose: confirm the declared organisation before the knock-out decision.';

async function shot(page: Page, name: string): Promise<void> {
  if (SHOTS !== '') {
    await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
  }
}

/** Opens the Unmask form of the control `button`, gives the purpose and confirms the step-up. */
async function unmask(page: Page, button: ReturnType<Page['locator']>, name: string): Promise<void> {
  const id = (await button.getAttribute('id')) ?? '';
  expect(id, 'the control has an id').not.toBe('');
  await button.click();
  await expect(page.locator(`#${id}-form`)).toContainText('As FSTP coordinator you can see who this is. Your purpose is recorded.');
  await page.locator(`#${id}-purpose`).fill(PURPOSE);
  await shot(page, `${name}-form`);
  await page.locator(`#${id}-submit`).click();
  const dialog = page.locator('#stepup');
  await expect(dialog, 'the unmask asks for the step-up (I-78)').toBeVisible();
  await page.locator('#stepup-confirm').click();
  await page.waitForURL((u) => u.pathname === '/r' && u.hostname.startsWith('id.'));
  await expect(page.locator('#vault-identity')).toBeVisible();
}

test.describe('coordinator unmask', () => {
  test.describe.configure({ timeout: 300_000 });

  test('i17_adr023_coordinator_unmasks_an_applicant_and_a_reviewer_handle', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    try {
      await door.chooseScene('/demo/review?stage=stage1');
    } finally {
      await door.close();
    }

    const c1 = await Seat.signIn(browser, cell, /Coordinator C1/);
    const page = c1.page;
    await page.goto(`${cell.origin}/app/calls/1/board`);
    const link = page.locator('a[id^="unmask-link-"]').first();
    await expect(link, 'the board offers an Unmask link per proposal').toBeVisible();
    await shot(page, '01-board');
    const proposal = ((await link.getAttribute('id')) ?? '').replace('unmask-link-', '');
    await link.click();
    await page.waitForURL((u) => u.pathname === `/app/proposals/${proposal}/parties`);
    await expect(page.locator('#parties-table')).toBeVisible();
    await expect(page.locator('main')).toContainText('Your purpose is recorded');
    await shot(page, '02-parties');

    // The applicant: the identity opens on the vault origin, never on the app's.
    const applicant = page.locator('tr[data-party="applicant"] button[id^="unmask-binding-"]').first();
    await unmask(page, applicant, '03-applicant');
    await expect(page.locator('#vault-identity')).toContainText('Synthetic applicant');
    await expect(page.locator('#vault-identity')).toContainText('applicant');
    await shot(page, '04-applicant-on-vault');

    // A reviewer handle, from the assignment page.
    await page.goto(`${cell.origin}/app/proposals/${proposal}/assignments`);
    const reviewer = page.locator('#assigned-list button[id^="unmask-assignment-"]').first();
    await expect(reviewer, 'each assigned reviewer has an Unmask control').toBeVisible();
    await shot(page, '05-assignments');
    await unmask(page, reviewer, '06-reviewer');
    await expect(page.locator('#vault-identity')).toContainText('Committee member');
    await expect(page.locator('#vault-identity')).toContainText('reviewer');
    await shot(page, '07-reviewer-on-vault');

    // The auditor's view is the audit read; the coordinator's own unmasks
    // are not on the coordinator's app pages.
    await page.goto(`${cell.origin}/app/proposals/${proposal}/parties`);
    await expect(page.locator('main')).not.toContainText('Synthetic applicant');
    await c1.close();

    // I-17: a committee member stays masked.
    const r1 = await Seat.signIn(browser, cell, /Committee member R1/);
    await r1.refused('GET', `/proposals/${proposal}/parties`);
    await r1.refused('POST', '/programmes/1/unmask', {
      purpose: PURPOSE,
      subject: { assignment: '1', type: 'Assignment' },
    });
    await r1.page.goto(`${cell.origin}/app/proposals/${proposal}/parties`);
    await expect(r1.page.locator('main h1')).toBeVisible();
    await expect(r1.page.locator('button[id^="unmask-"]')).toHaveCount(0);
    await shot(r1.page, '08-committee-member-refused');
    await r1.close();
  });
});
