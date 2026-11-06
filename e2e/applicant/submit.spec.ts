/**
 * Journey J4, submission (M4 design sections 2.2 and 8.7, lane W4b):
 * the form holds only what evaluation needs, the data protection notice
 * and the ethics self-declaration travel with the submission, and the
 * applicant can ask for a copy.
 *
 * Without a stack manifest, each test fails at its first step with
 * `StackMissing`.
 */

import { expect } from '@playwright/test';
import { syntheticEmail, test } from '../playwright.config';
import {
  API,
  APP,
  AUI,
  SECOND_MICROS,
  Traffic,
  canary,
  controlsOf,
  draftedProposal,
  expectState,
  forbiddenFieldsOn,
  freshCell,
  jsonLeaves,
  parsedOrNull,
  submitDraft,
} from './support';

test.describe('J4 submit', () => {
  /**
   * R-SB-01 AC: no submission form contains identity document, date of
   * birth or payment fields. Every applicant form before negotiation is
   * scanned: the call page, workspace, plan, eligibility, submit and
   * proposal pages. Q24 (interim, pending Daniel): no file input either.
   * The scan must see controls on each form page, so it is never vacuous.
   */
  test('r_sb_01_no_applicant_form_has_identity_dob_payment_or_file_fields', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'rsb01');
    const problems: string[] = [];
    for (const [label, path, form] of [
      ['call', APP.call(d.call.id), false],
      ['workspace', APP.workspace(d.proposal), true],
      ['plan', APP.plan(d.proposal), true],
      ['eligibility', APP.eligibility(d.proposal), true],
      ['submit', APP.submit(d.proposal), true],
      ['proposal', APP.proposal(d.proposal), true],
    ] as const) {
      await d.page.goto(`${origin}${path}`);
      await expect(d.page.locator('main')).toBeVisible();
      if (form) {
        expect((await controlsOf(d.page)).length, `${label}: the scan sees the form`).toBeGreaterThan(0);
      }
      problems.push(...(await forbiddenFieldsOn(d.page, label)));
    }
    expect(problems).toEqual([]);
  });

  /**
   * R-NG-06: applicants receive a data protection notice at submission.
   * The submit page shows it with its version, and the submission names
   * that version (design section 2.2, `Submit` with notice version). The
   * proposal then reads SUBMITTED.
   */
  test('r_ng_06_submission_carries_the_shown_notice_version', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'rng06');
    const traffic = new Traffic(d.page);
    const { version, response } = await submitDraft(d.page, origin, d.proposal);
    expect(response.ok(), 'the cell accepts the submission').toBe(true);
    const sent = traffic.to('POST', API.submission(d.proposal));
    expect(sent).toHaveLength(1);
    expect(jsonLeaves(parsedOrNull(sent[0]?.body ?? null)).strings, 'the shown version is sent').toContain(version);
    await expectState(d.page, origin, d.proposal, 'SUBMITTED');
  });

  /**
   * R-SB-05: submissions include an ethics self-declaration. Without an
   * answer, or with a declared issue but no description, the page sends
   * nothing and names the missing field. A declared issue travels with
   * the submission, so it can be flagged to the assigned reviewers.
   */
  test('r_sb_05_submission_needs_an_ethics_self_declaration', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'rsb05');
    const traffic = new Traffic(d.page);
    await d.page.goto(`${origin}${APP.submit(d.proposal)}`);
    await d.page.locator(AUI.submit.noticeRead).check();

    await d.page.locator(AUI.submit.confirm).click();
    const errors = d.page.locator(AUI.submit.errors);
    await expect(errors).toBeVisible();
    await expect(errors.locator(`a[href="${AUI.submit.ethicsNone}"]`)).toHaveCount(1);
    expect(traffic.to('POST', API.submission(d.proposal)), 'nothing is sent without an answer').toEqual([]);

    await d.page.locator(AUI.submit.ethicsDeclared).check();
    await d.page.locator(AUI.submit.confirm).click();
    await expect(d.page.locator(AUI.submit.ethicsDetails)).toHaveAttribute('aria-invalid', 'true');
    expect(traffic.to('POST', API.submission(d.proposal)), 'nothing is sent without a description').toEqual([]);

    const issue = canary('ETHICS');
    await d.page.locator(AUI.submit.ethicsDetails).fill(`A synthetic ethics issue ${issue}`);
    const sent = d.page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.submission(d.proposal),
    );
    await d.page.locator(AUI.submit.confirm).click();
    expect((await sent).ok()).toBe(true);
    const body = traffic.to('POST', API.submission(d.proposal))[0]?.body ?? '';
    expect(body, 'the declared issue travels with the submission').toContain(issue);
    await expectState(d.page, origin, d.proposal, 'SUBMITTED');
  });

  /**
   * R-SB-02 AC: a minor-flagged submission reaches SUBMITTED without a
   * guardian record. The fresh applicant has no adult attestation in the
   * vault, so the proposal is minor-flagged (state-machine NOTE 14). The
   * submission needs no guardian step, and the pages ask for none.
   */
  test('r_sb_02_minor_flagged_draft_reaches_submitted_without_guardian', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'rsb02');
    const traffic = new Traffic(d.page);
    const { response } = await submitDraft(d.page, origin, d.proposal);
    expect(response.ok()).toBe(true);
    await expectState(d.page, origin, d.proposal, 'SUBMITTED');
    const guardian = traffic.sent.filter((r) => r.path.includes('/guardian'));
    expect(guardian.map((r) => `${r.method} ${r.path}`), 'no guardian request').toEqual([]);
  });

  /**
   * I-86, I-18, R-SB-01, R-SB-02 and Q23 B (design section 15.0,
   * 2026-11-06): the lead states a date of birth at submission, in its own
   * form, to the vault route only. No other request carries it, no reply
   * echoes it, and no page shows it afterwards. A lead under 18 at the
   * deadline still submits without a guardian.
   */
  test('i86_date_of_birth_reaches_only_the_vault', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'dob');
    const traffic = new Traffic(d.page);
    const dob = '2011-07-14';
    await d.page.goto(`${origin}${APP.submit(d.proposal)}`);
    await d.page.locator(AUI.submit.birthDate).fill(dob);
    const stated = d.page.waitForResponse(
      (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === API.birthDate(d.proposal),
    );
    await d.page.locator(AUI.submit.birthDateSave).click();
    expect((await stated).ok(), 'the vault route accepts the date').toBe(true);
    await expect(d.page.locator(AUI.submit.birthDateStatus)).toHaveAttribute('data-status', 'saved');
    await expect(d.page.locator(AUI.submit.birthDate), 'the page keeps no copy').toHaveValue('');

    const { response } = await submitDraft(d.page, origin, d.proposal);
    expect(response.ok(), 'a minor submits without a guardian (R-SB-02)').toBe(true);
    await expectState(d.page, origin, d.proposal, 'SUBMITTED');
    for (const path of [APP.proposal(d.proposal), APP.submit(d.proposal), APP.proposals]) {
      await d.page.goto(`${origin}${path}`);
      await expect(d.page.locator('main')).toBeVisible();
      expect(await d.page.content(), `${path} shows no date of birth`).not.toContain(dob);
    }
    await traffic.settle();

    const vault = traffic.to('PUT', API.birthDate(d.proposal));
    expect(vault).toHaveLength(1);
    expect(jsonLeaves(parsedOrNull(vault[0]?.body ?? null)).strings).toEqual([dob]);
    const elsewhere = traffic.sent.filter((r) => r.path !== API.birthDate(d.proposal) && (r.body ?? '').includes(dob));
    expect(elsewhere.map((r) => `${r.method} ${r.path}`), 'no other request carries it').toEqual([]);
    const echoed = traffic.received.filter((r) => (r.body ?? '').includes(dob));
    expect(echoed.map((r) => `${r.method} ${r.path}`), 'no reply echoes it').toEqual([]);
    const guardian = traffic.sent.filter((r) => r.path.includes('/guardian'));
    expect(guardian.map((r) => `${r.method} ${r.path}`), 'no guardian request').toEqual([]);
  });

  /**
   * `state-machine.md`, DRAFT to SUBMITTED needs the call open. Once the
   * deadline has passed on the cell clock, no submission is accepted, the
   * page says so in an alert, and the proposal stays DRAFT. The page may
   * offer the confirm button and show the cell's refusal, or offer none.
   * Supporting test: the guard is the domain's, claimed by the M2 suites.
   */
  test('state_machine_submission_after_the_deadline_is_refused_and_shown', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'deadline');
    const traffic = new Traffic(d.page);
    await control.advanceClock(d.call.until_deadline_micros + SECOND_MICROS);
    await d.page.goto(`${origin}${APP.submit(d.proposal)}`);
    await expect(d.page.locator('main')).toBeVisible();
    const confirm = d.page.locator(AUI.submit.confirm);
    if ((await confirm.count()) > 0 && (await confirm.isEnabled())) {
      await d.page.locator(AUI.submit.noticeRead).check();
      await d.page.locator(AUI.submit.ethicsNone).check();
      const sent = d.page.waitForResponse(
        (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.submission(d.proposal),
      );
      await confirm.click();
      const status = (await sent).status();
      expect(status, 'the cell refuses').toBeGreaterThanOrEqual(400);
      expect(status).toBeLessThan(500);
    }
    await expect(d.page.getByRole('alert').first()).toBeVisible();
    await expectState(d.page, origin, d.proposal, 'DRAFT');
    await traffic.settle();
    const accepted = traffic.received.filter(
      (r) => r.path === API.submission(d.proposal) && r.status >= 200 && r.status < 300,
    );
    expect(accepted, 'no submission was accepted').toEqual([]);
  });

  /**
   * R-SB-04: applicants can obtain a copy of their application at an
   * email address they provide. A malformed address is a field error and
   * sends nothing. A valid one is sent to the copy route, and the page
   * confirms the request (sending arrives with M6).
   */
  test('r_sb_04_copy_request_goes_to_the_address_given', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'rsb04');
    const traffic = new Traffic(d.page);
    await d.page.goto(`${origin}${APP.proposal(d.proposal)}`);
    await d.page.locator(AUI.proposal.copyEmail).fill('not an address');
    await d.page.locator(AUI.proposal.copyRequest).click();
    await expect(d.page.locator(AUI.proposal.copyEmail)).toHaveAttribute('aria-invalid', 'true');
    expect(traffic.to('POST', API.copy(d.proposal))).toEqual([]);

    const to = syntheticEmail('copy');
    await d.page.locator(AUI.proposal.copyEmail).fill(to);
    const sent = d.page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.copy(d.proposal),
    );
    await d.page.locator(AUI.proposal.copyRequest).click();
    expect((await sent).ok()).toBe(true);
    const body = traffic.to('POST', API.copy(d.proposal))[0]?.body ?? null;
    expect(jsonLeaves(parsedOrNull(body)).strings, 'the address given is sent').toContain(to);
    const status = d.page.locator(AUI.proposal.copyStatus);
    await expect(status).toBeVisible();
    await expect(status).not.toHaveText('');
  });
});
