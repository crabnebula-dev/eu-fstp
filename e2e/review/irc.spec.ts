/**
 * J8, the IRC (M4 design section 2.2): cases, the declaration before
 * reading, the case view and the verdict, in the browser against the e2e
 * cell.
 *
 * - R-CF-02: IRC review is among the acts a conflict bars, so IRC
 *   members declare before they read the nominated proposal.
 * - R-IR-03: IRC members see the nominated proposal and its outcome, not
 *   committee deliberation. The case has no score, ballot, rationale or
 *   tie-break (design section 3.6, Q16).
 * - R-IR-01 and P-15: the proposal moves to NEGOTIATION only when every
 *   reviewing IRC member validates.
 * - I-18 and NOTE 14: a minor-flagged proposal without a verified
 *   guardian consent record does not enter negotiation.
 * - R-IR-02 and NOTE 7: a concern carries its text for the applicant, and
 *   with a later call published the proposal is deferred.
 * - I-17: no identity attribute of an applicant reaches these pages.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { REVIEW_API, REVIEW_PAGES, REVIEW_UI, type PersonaKey, type ProposalKey } from './contract';
import {
  apiGet,
  clickWrite,
  expectAccepted,
  expectFieldError,
  expectNoCanary,
  expectRefusal,
  expectState,
  ircAssignmentOf,
  openPage,
  proposal,
  seed,
  signIn,
  watchResponses,
  watchWrites,
  type Seeded,
} from './support';

/** Declares no conflict on the IRC case of `who` on `key`. */
async function declareNone(page: Page, seeded: Seeded, key: ProposalKey, who: PersonaKey): Promise<void> {
  await openPage(page, seeded.cell.origin, REVIEW_PAGES.ircCase(ircAssignmentOf(seeded.s, key, who)));
  await page.locator(REVIEW_UI.declaration.no).check();
  expect(await clickWrite(page, REVIEW_UI.declaration.submit, /\/declaration$/)).toBeLessThan(300);
  await expect(page.locator(REVIEW_UI.irc.case)).toBeVisible();
}

/** Records a validation on the open case page. */
async function validate(page: Page): Promise<void> {
  await page.locator(REVIEW_UI.irc.validate).check();
  expect(await clickWrite(page, REVIEW_UI.irc.submit, /\/review$/)).toBeLessThan(300);
}

/**
 * The state of proposal `key` once its IRC review has ended, as the FSTP
 * coordinator's call board shows it. The IRC case reads only while the
 * proposal is in IRC_REVIEW (`fstp_access::READ_RULES`, D11), so the
 * IRC member's own page cannot show the state that follows it.
 */
async function expectOutcome(
  person: () => Promise<Page>,
  seeded: Seeded,
  key: ProposalKey,
  tag: string,
): Promise<void> {
  const c1 = await signIn(person, seeded, 'c1');
  await openPage(c1, seeded.cell.origin, REVIEW_PAGES.board(seeded.s.call));
  await expect(c1.locator(REVIEW_UI.board.row(proposal(seeded.s, key).id))).toHaveAttribute('data-state', tag);
}

test.describe('J8 IRC', () => {
  test('r_cf_02_irc_member_declares_before_reading_the_case', async ({ person, request }) => {
    const seeded = await seed(request, 'irc_review');
    const { cell, s } = seeded;
    const a = ircAssignmentOf(s, 'x', 'i1');
    const i1 = await signIn(person, seeded, 'i1');

    await openPage(i1, cell.origin, REVIEW_PAGES.myIrcCases());
    await expect(i1.locator(REVIEW_UI.link(REVIEW_PAGES.ircCase(a)))).toBeVisible();

    await openPage(i1, cell.origin, REVIEW_PAGES.ircCase(a));
    await expect(i1.locator(REVIEW_UI.irc.case)).toHaveCount(0);
    await expect(i1.locator('body')).not.toContainText(s.content_canary);
    expectRefusal(await apiGet(i1, cell.origin, REVIEW_API.ircCase(a)), 'case before declaring');

    await declareNone(i1, seeded, 'x', 'i1');
    await expect(i1.locator(REVIEW_UI.irc.case)).toContainText(s.content_canary);
    expectAccepted(await apiGet(i1, cell.origin, REVIEW_API.ircCase(a)), 'case after declaring');
  });

  test('r_ir_03_irc_case_shows_proposal_and_outcome_without_deliberation', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'irc_review');
    const { s } = seeded;
    expect(s.deliberation_canaries.length, 'the scenario plants deliberation canaries').toBeGreaterThan(0);
    const i1 = await signIn(person, seeded, 'i1');
    const responses = watchResponses(i1);

    await declareNone(i1, seeded, 'x', 'i1');
    await expect(i1.locator(REVIEW_UI.irc.outcome)).toBeVisible();
    await expect(i1.locator(REVIEW_UI.irc.case)).toContainText(proposal(s, 'x').title);
    await expectNoCanary(i1, s.deliberation_canaries, 'IRC case', responses);
    await expectNoCanary(i1, s.identity_canaries, 'IRC case', responses);
  });

  test('r_ir_01_every_irc_validation_moves_the_proposal_to_negotiation', async ({
    person,
    request,
  }) => {
    const seeded = await seed(request, 'irc_review');
    const i1 = await signIn(person, seeded, 'i1');
    const i2 = await signIn(person, seeded, 'i2');

    await declareNone(i1, seeded, 'x', 'i1');
    await validate(i1);
    // P-15 = 2: one validation is not enough.
    await i1.reload();
    await expectState(i1, 'IRC_REVIEW');

    await declareNone(i2, seeded, 'x', 'i2');
    await validate(i2);
    await expectOutcome(person, seeded, 'x', 'NEGOTIATION');
  });

  test('i18_minor_without_consent_stays_in_irc_review', async ({ person, request }) => {
    const seeded = await seed(request, 'irc_review');
    const i1 = await signIn(person, seeded, 'i1');
    const i2 = await signIn(person, seeded, 'i2');

    await declareNone(i1, seeded, 'v', 'i1');
    await validate(i1);
    await declareNone(i2, seeded, 'v', 'i2');
    await i2.locator(REVIEW_UI.irc.validate).check();
    // The last validation may be refused under I-18 or recorded without a
    // transition. Either way v never enters NEGOTIATION.
    await i2.locator(REVIEW_UI.irc.submit).click();
    await i2.reload();
    await expectState(i2, 'IRC_REVIEW');

    // The pair: x, validated by the same two members, does enter it.
    await declareNone(i1, seeded, 'x', 'i1');
    await validate(i1);
    await declareNone(i2, seeded, 'x', 'i2');
    await validate(i2);
    await expectOutcome(person, seeded, 'x', 'NEGOTIATION');
  });

  test('r_ir_02_concern_needs_its_text_and_defers_the_proposal', async ({ person, request }) => {
    const seeded = await seed(request, 'irc_review');
    expect(seeded.s.future_call, 'the scenario publishes a later call (NOTE 7)').toBe(true);
    const i1 = await signIn(person, seeded, 'i1');

    await declareNone(i1, seeded, 'u', 'i1');
    const writes = watchWrites(i1, /\/review$/);
    await i1.locator(REVIEW_UI.irc.concern).check();
    await i1.locator(REVIEW_UI.irc.submit).click();
    await expectFieldError(i1, REVIEW_UI.irc.concernText);
    expect(writes.seen(), 'no concern is sent without its text').toBe(0);

    await i1.locator(REVIEW_UI.irc.concernText).fill('Synthetic: the plan is not frugal enough.');
    expect(await clickWrite(i1, REVIEW_UI.irc.submit, /\/review$/)).toBeLessThan(300);
    await expectOutcome(person, seeded, 'u', 'DEFERRED');
  });
});
