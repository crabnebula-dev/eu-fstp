/**
 * R-SB-03: applicants can withdraw at any point before contract
 * signature (M4 design sections 2.2 J4 and 8.7, lane W4b).
 *
 * `state-machine.md` NOTE 10 opens withdrawal in DRAFT, SUBMITTED,
 * STAGE1, STAGE2, RANKED, IRC_REVIEW, DEFERRED and NEGOTIATION. Terminal
 * states have no exits. The proposal page offers the withdraw control in
 * exactly those states, and asks for confirmation in a modal dialog
 * before it sends anything (WCAG 2.2 SC 3.3.4).
 *
 * Without a stack manifest, each test fails at its first step with
 * `StackMissing`.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import {
  API,
  APP,
  AUI,
  Traffic,
  draftedProposal,
  expectState,
  freshCell,
  must,
  seededPerson,
  submitDraft,
  type ScenarioAt,
  type State,
} from './support';

/** Withdraws through the proposal page and checks the outcome. */
async function withdraw(page: Page, origin: string, proposal: string, from: State): Promise<void> {
  await expectState(page, origin, proposal, from);
  await page.locator(AUI.proposal.withdraw).click();
  const dialog = page.locator(AUI.proposal.withdrawDialog);
  await expect(dialog).toBeVisible();
  const sent = page.waitForResponse(
    (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.withdrawal(proposal),
  );
  await page.locator(AUI.proposal.withdrawConfirm).click();
  expect((await sent).ok(), `the cell accepts a withdrawal from ${from}`).toBe(true);
  await expectState(page, origin, proposal, 'WITHDRAWN');
  await expect(page.locator(AUI.proposal.withdraw), 'WITHDRAWN is terminal').toHaveCount(0);
}

test.describe('R-SB-03 withdrawal', () => {
  /** R-SB-03, NOTE 10: a draft can be withdrawn. */
  test('r_sb_03_withdraw_from_draft', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'wdraft');
    await withdraw(d.page, origin, d.proposal, 'DRAFT');
  });

  /** R-SB-03, NOTE 10: a submitted proposal can be withdrawn. */
  test('r_sb_03_withdraw_from_submitted', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'wsubmitted');
    const { response } = await submitDraft(d.page, origin, d.proposal);
    expect(response.ok()).toBe(true);
    await withdraw(d.page, origin, d.proposal, 'SUBMITTED');
  });

  for (const at of ['STAGE2', 'NEGOTIATION'] as const satisfies readonly ScenarioAt[]) {
    /**
     * R-SB-03 AC, NOTE 10: a withdrawal from a later non-terminal state
     * before GRANTED succeeds, NEGOTIATION included.
     */
    test(`r_sb_03_withdraw_from_${at.toLowerCase()}`, async ({ person, request }) => {
      const { origin, control } = await freshCell(request);
      const s = await control.scenario(at);
      const page = await seededPerson(person, origin, must(s.lead, 'lead'));
      await withdraw(page, origin, must(s.proposal, 'proposal'), at);
    });
  }

  /**
   * R-SB-03 NOTE and state-machine NOTE 10: terminal states have no
   * exits. In NOT_SELECTED and INELIGIBLE the proposal page offers no
   * withdraw control, and the state stays as it was.
   */
  test('r_sb_03_no_withdrawal_in_a_terminal_state', async ({ person, request }) => {
    for (const at of ['NOT_SELECTED', 'INELIGIBLE'] as const satisfies readonly ScenarioAt[]) {
      const { origin, control } = await freshCell(request);
      const s = await control.scenario(at);
      const page = await seededPerson(person, origin, must(s.lead, 'lead'));
      const proposal = must(s.proposal, 'proposal');
      await expectState(page, origin, proposal, at);
      await expect(page.locator(AUI.proposal.withdraw), `${at} offers no withdrawal`).toHaveCount(0);
      await expect(page.locator(AUI.proposal.withdrawDialog), `${at} has no withdrawal dialog`).toHaveCount(0);
      await page.goto(`${origin}${APP.proposals}`);
      await expect(page.locator(`${AUI.proposals.list} a[href="${APP.proposal(proposal)}"]`)).toHaveCount(1);
      await expectState(page, origin, proposal, at);
    }
  });

  /**
   * R-SB-03 and WCAG 2.2 SC 3.3.4: the confirmation can be declined. The
   * cancel button and the Escape key each close the dialog, send nothing
   * and leave the proposal as it was.
   */
  test('r_sb_03_cancelled_withdrawal_sends_nothing', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'wcancel');
    const traffic = new Traffic(d.page);
    await expectState(d.page, origin, d.proposal, 'DRAFT');
    const dialog = d.page.locator(AUI.proposal.withdrawDialog);

    await d.page.locator(AUI.proposal.withdraw).click();
    await expect(dialog).toBeVisible();
    await d.page.locator(AUI.proposal.withdrawCancel).click();
    await expect(dialog).toBeHidden();

    await d.page.locator(AUI.proposal.withdraw).click();
    await expect(dialog).toBeVisible();
    await d.page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();

    expect(traffic.to('POST', API.withdrawal(d.proposal)), 'nothing was sent').toEqual([]);
    await expectState(d.page, origin, d.proposal, 'DRAFT');
  });
});
