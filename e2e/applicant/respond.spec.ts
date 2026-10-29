/**
 * Journey J4, second half: respond in stage 2, read notices, land in
 * negotiation, and the guardian's consent (M4 design sections 2.2 and
 * 8.7, lane W4b).
 *
 * Each test seeds a proposal in the state it needs through the e2e
 * cell's scenario route (`support.ts`). Without a stack manifest, each
 * test fails at its first step with `StackMissing`.
 */

import { expect } from '@playwright/test';
import { VAULT_PAGES, test } from '../playwright.config';
import {
  API,
  APP,
  AUI,
  PLAN_DAYS,
  Traffic,
  canary,
  expectState,
  forbiddenFieldsOn,
  freshCell,
  jsonLeaves,
  must,
  parsedOrNull,
  seededPerson,
} from './support';

test.describe('J4 respond', () => {
  /**
   * TH-08 and P-11 (reviewer anonymity towards applicants): stage 2
   * questions show the reviewers' pseudonymous handles only, and their
   * times at day granularity (design section 3.6, `GetStage2Thread`).
   * No reviewer identity canary reaches the page or the read model.
   */
  test('th08_stage2_questions_show_handles_and_days_only', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('STAGE2');
    const stage2 = must(s.stage2, 'stage2');
    const proposal = must(s.proposal, 'proposal');
    const page = await seededPerson(person, origin, must(s.lead, 'lead'));
    const traffic = new Traffic(page);
    await page.goto(`${origin}${APP.stage2(proposal)}`);

    const items = page.locator(`${AUI.stage2.questions} > li`);
    await expect(items.first()).toBeVisible();
    const n = await items.count();
    for (let i = 0; i < n; i++) {
      const item = items.nth(i);
      const handle = await item.getAttribute('data-handle');
      expect(stage2.handles, `question ${i} carries a seeded handle`).toContain(handle);
      await expect(item).toContainText(handle ?? '');
      const times = item.locator('time');
      expect(await times.count(), `question ${i} shows its day`).toBeGreaterThan(0);
      for (const dt of await times.evaluateAll((ts) => ts.map((t) => t.getAttribute('datetime')))) {
        expect(dt, `question ${i}: a day, never a time of day`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      }
      expect(await item.innerText(), `question ${i} shows no time of day`).not.toMatch(/\b\d{1,2}:\d{2}\b/);
    }
    const html = await page.content();
    for (const h of stage2.hidden) {
      expect(html, 'no reviewer identity on the page').not.toContain(h);
    }
    await traffic.settle();
    const reads = traffic.received.filter((r) => r.path === API.stage2(proposal));
    expect(reads.length, 'the page read the thread').toBeGreaterThan(0);
    for (const r of traffic.received) {
      for (const h of stage2.hidden) {
        expect(r.body, `${r.path} carries no reviewer identity`).not.toContain(h);
      }
    }
  });

  /**
   * R-EV-05: in stage 2, applicants answer the questions and can submit
   * a revised plan including budget changes. Each goes to its own route.
   * The revised amount travels as an ADR-006 string.
   */
  test('r_ev_05_applicant_answers_and_submits_a_revised_plan', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('STAGE2');
    const proposal = must(s.proposal, 'proposal');
    const page = await seededPerson(person, origin, must(s.lead, 'lead'));
    const traffic = new Traffic(page);
    await page.goto(`${origin}${APP.stage2(proposal)}`);

    const answer = canary('ANSWER');
    await page.locator(AUI.stage2.answer).fill(`A synthetic answer ${answer}`);
    const answered = page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.stage2Answers(proposal),
    );
    await page.locator(AUI.stage2.answerSend).click();
    expect((await answered).ok()).toBe(true);
    await expect(page.locator(AUI.stage2.status)).toHaveAttribute('data-status', 'saved');
    expect(traffic.to('POST', API.stage2Answers(proposal))[0]?.body ?? '').toContain(answer);

    await page.locator(AUI.stage2.planAmount).fill('1800.00');
    await page.locator(AUI.stage2.planStart).fill(PLAN_DAYS.start);
    await page.locator(AUI.stage2.planDue).fill(PLAN_DAYS.due);
    await page.locator(AUI.stage2.planDescription).fill('A synthetic revised work plan.');
    const revised = page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.stage2Revision(proposal),
    );
    await page.locator(AUI.stage2.revise).click();
    expect((await revised).ok()).toBe(true);
    await expect(page.locator(AUI.stage2.status)).toHaveAttribute('data-status', 'saved');
    const leaves = jsonLeaves(parsedOrNull(traffic.to('POST', API.stage2Revision(proposal))[0]?.body ?? null));
    expect(leaves.strings, 'the revised amount is a JSON string').toContain('1800.00');
    expect(leaves.numbers.filter((x) => x.startsWith('1800')), 'never a number').toEqual([]);
    await expectState(page, origin, proposal, 'STAGE2');
  });

  /**
   * R-EV-04: non-selected applicants are notified. The outcome notice is
   * recorded at once and listed on the notices page, linked to the
   * proposal, which reads NOT_SELECTED (sending within P-08 arrives with
   * M6).
   */
  test('r_ev_04_not_selected_notice_reaches_the_applicant', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('NOT_SELECTED');
    const proposal = must(s.proposal, 'proposal');
    const page = await seededPerson(person, origin, must(s.lead, 'lead'));
    await page.goto(`${origin}${APP.notices}`);
    const notice = page.locator(`${AUI.notices.list} li[data-kind="ProposalOutcome"]`);
    await expect(notice).toHaveCount(1);
    await notice.locator(`a[href="${APP.proposal(proposal)}"]`).click();
    await expect(page.locator(AUI.proposal.state)).toHaveAttribute('data-state', 'NOT_SELECTED');
  });

  /**
   * R-IR-02: an IRC concern is sent to the applicant, and the proposal
   * is deferred or declined per the state machine. With a later call
   * published, the proposal reads DEFERRED (NOTE 7), and the concern is
   * listed on the notices page.
   */
  test('r_ir_02_irc_concern_reaches_the_applicant', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('DEFERRED_AFTER_CONCERN');
    const proposal = must(s.proposal, 'proposal');
    const page = await seededPerson(person, origin, must(s.lead, 'lead'));
    await page.goto(`${origin}${APP.notices}`);
    const notice = page.locator(`${AUI.notices.list} li[data-kind="IrcConcern"]`);
    await expect(notice).toHaveCount(1);
    await notice.locator(`a[href="${APP.proposal(proposal)}"]`).click();
    await expect(page.locator(AUI.proposal.state)).toHaveAttribute('data-state', 'DEFERRED');
  });

  /**
   * R-NG-06: applicants receive a data protection notice at negotiation.
   * The negotiation landing shows it with its version and the next steps.
   * The acknowledgement names that version, and it stays recorded after
   * a reload, when the page offers no second acknowledgement.
   */
  test('r_ng_06_negotiation_notice_is_shown_and_acknowledged', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('NEGOTIATION');
    const proposal = must(s.proposal, 'proposal');
    const page = await seededPerson(person, origin, must(s.lead, 'lead'));
    const traffic = new Traffic(page);
    await page.goto(`${origin}${APP.negotiation(proposal)}`);
    const notice = page.locator(AUI.negotiation.notice);
    await expect(notice).toBeVisible();
    const version = await notice.getAttribute('data-notice-version');
    expect(version ?? '', 'the notice names its version').not.toBe('');
    await expect(page.locator(AUI.negotiation.nextSteps)).toBeVisible();

    const sent = page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.negotiationNotice(proposal),
    );
    await page.locator(AUI.negotiation.acknowledge).click();
    expect((await sent).ok()).toBe(true);
    const body = traffic.to('POST', API.negotiationNotice(proposal))[0]?.body ?? null;
    expect(jsonLeaves(parsedOrNull(body)).strings, 'the shown version is acknowledged').toContain(version);
    await expect(page.locator(AUI.negotiation.acknowledged)).toBeVisible();

    await page.reload();
    await expect(page.locator(AUI.negotiation.acknowledged)).toBeVisible();
    await expect(page.locator(AUI.negotiation.acknowledge)).toHaveCount(0);
  });

  /**
   * I-18, R-NG-01 NOTE and state-machine NOTE 14: a minor-flagged
   * proposal enters negotiation only with a verified guardian consent.
   * The guardian gives consent on the vault origin, so the guardian page
   * asks for no identity attribute and hands over to the vault's write
   * page, with the ticket in the fragment. Until the consent is
   * effective, the lead's proposal stays IRC_REVIEW.
   */
  test('i18_guardian_consent_runs_on_the_vault_origin_and_the_proposal_waits', async ({ person, request }) => {
    const { origin, vault, control } = await freshCell(request);
    const s = await control.scenario('IRC_REVIEW_MINOR');
    const proposal = must(s.proposal, 'proposal');
    const guardian = await seededPerson(person, origin, must(s.guardian, 'guardian'));
    await guardian.goto(`${origin}${APP.guardian(proposal)}`);
    await expect(guardian.locator(AUI.guardian.consentStart)).toBeVisible();
    expect(await forbiddenFieldsOn(guardian, 'guardian')).toEqual([]);

    const begun = guardian.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.guardianConsent(proposal),
    );
    await guardian.locator(AUI.guardian.consentStart).click();
    expect((await begun).ok()).toBe(true);
    await guardian.waitForURL(
      (u) => u.origin === vault && u.pathname === VAULT_PAGES.write && u.search === '' && u.hash.length > 1,
    );

    const lead = await seededPerson(person, origin, must(s.lead, 'lead'));
    await expectState(lead, origin, proposal, 'IRC_REVIEW');
    await expect(lead.locator(`a[href="${APP.negotiation(proposal)}"]`), 'no negotiation landing yet').toHaveCount(0);
  });
});
