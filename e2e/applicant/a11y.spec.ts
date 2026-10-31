/**
 * R-NF-03: the user interface meets WCAG 2.2 level AA, on the applicant
 * pages (M4 design sections 3.9 and 8.7, lane W4b).
 *
 * The checks are in-house, as in M3 (`e2e/r-nf-03-auth-and-vault-pages`):
 * structure and accessible names on every applicant page, error
 * summaries tied to their fields, and a submission by keyboard alone.
 * Focus order, focus visibility and contrast of the shared tokens are
 * checked by lane W5's `a11y` spec across every page. A manual review
 * is recorded in the exit audit (Q21).
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
  structureProblems,
  tabTo,
  visibleErrorTexts,
  type ScenarioAt,
} from './support';

/** Visits `path` and returns the page's structure problems. */
async function problemsAt(page: Page, origin: string, label: string, path: string): Promise<string[]> {
  await page.goto(`${origin}${path}`);
  await expect(page.locator('main')).toBeVisible();
  return structureProblems(page, label);
}

test.describe('R-NF-03 applicant pages', () => {
  /**
   * R-NF-03: every page of the draft path has a language, a title, one
   * main landmark and an h1, and every control has an accessible name.
   * The withdrawal dialog is checked open.
   */
  test('r_nf_03_draft_pages_have_structure_and_named_controls', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'a11ydraft');
    const problems: string[] = [];
    for (const [label, path] of [
      ['calls', APP.calls],
      ['call', APP.call(d.call.id)],
      ['guide', APP.guide(d.call.id)],
      ['proposals', APP.proposals],
      ['proposal', APP.proposal(d.proposal)],
      ['workspace', APP.workspace(d.proposal)],
      ['plan', APP.plan(d.proposal)],
      ['eligibility', APP.eligibility(d.proposal)],
      ['submit', APP.submit(d.proposal)],
      ['notices', APP.notices],
    ] as const) {
      problems.push(...(await problemsAt(d.page, origin, label, path)));
    }
    await d.page.goto(`${origin}${APP.proposal(d.proposal)}`);
    await d.page.locator(AUI.proposal.withdraw).click();
    await expect(d.page.locator(AUI.proposal.withdrawDialog)).toBeVisible();
    problems.push(...(await structureProblems(d.page, 'withdraw dialog')));
    expect(problems).toEqual([]);
  });

  /**
   * R-NF-03: the same checks on the response pages: stage 2, the
   * negotiation landing, the notices page with a notice, and the
   * guardian page.
   */
  test('r_nf_03_response_pages_have_structure_and_named_controls', async ({ person, request }) => {
    const problems: string[] = [];
    const pages: readonly [ScenarioAt, string, (p: string) => string, 'lead' | 'guardian'][] = [
      ['STAGE2', 'stage2', APP.stage2, 'lead'],
      ['NEGOTIATION', 'negotiation', APP.negotiation, 'lead'],
      ['NOT_SELECTED', 'notices', () => APP.notices, 'lead'],
      ['IRC_REVIEW_MINOR', 'guardian', APP.guardian, 'guardian'],
    ];
    for (const [at, label, path, who] of pages) {
      const { origin, control } = await freshCell(request);
      const s = await control.scenario(at);
      const link = who === 'lead' ? must(s.lead, 'lead') : must(s.guardian, 'guardian');
      const page = await seededPerson(person, origin, link);
      problems.push(...(await problemsAt(page, origin, label, path(must(s.proposal, 'proposal')))));
    }
    expect(problems).toEqual([]);
  });

  /**
   * R-NF-03 (WCAG 2.2 SC 3.3.1 and 1.3.1): a refused submit shows an
   * error summary as an alert, with a link to each field in error. Each
   * field is marked invalid and references a visible error text. A
   * summary link moves focus to its field. Nothing is sent.
   */
  test('r_nf_03_submit_errors_are_summarised_and_tied_to_fields', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'a11yerrors');
    const traffic = new Traffic(d.page);
    await d.page.goto(`${origin}${APP.submit(d.proposal)}`);
    await d.page.locator(AUI.submit.confirm).click();

    const summary = d.page.locator(AUI.submit.errors);
    await expect(summary).toBeVisible();
    await expect(summary).toHaveAttribute('role', 'alert');
    await expect(summary.locator(`a[href="${AUI.submit.noticeRead}"]`)).toHaveCount(1);
    await expect(summary.locator(`a[href="${AUI.submit.ethicsNone}"]`)).toHaveCount(1);

    await expect(d.page.locator(AUI.submit.noticeRead)).toHaveAttribute('aria-invalid', 'true');
    expect(await visibleErrorTexts(d.page, AUI.submit.noticeRead), 'the notice field names its error').not.toEqual([]);
    expect(await visibleErrorTexts(d.page, AUI.submit.ethics), 'the ethics group names its error').not.toEqual([]);

    await summary.locator(`a[href="${AUI.submit.noticeRead}"]`).click();
    expect(await d.page.evaluate(() => document.activeElement?.id)).toBe('submit-notice-read');
    expect(traffic.to('POST', API.submission(d.proposal)), 'nothing was sent').toEqual([]);
  });

  /**
   * R-NF-03 (WCAG 2.2 SC 2.1.1): a submission completes by keyboard
   * alone, from the notice to the confirmation.
   */
  test('r_nf_03_submission_completes_by_keyboard_alone', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const d = await draftedProposal(person, control, origin, 'a11ykeys');
    await d.page.goto(`${origin}${APP.submit(d.proposal)}`);
    await expect(d.page.locator(AUI.submit.notice)).toBeVisible();
    await tabTo(d.page, AUI.submit.noticeRead);
    await d.page.keyboard.press('Space');
    await expect(d.page.locator(AUI.submit.noticeRead)).toBeChecked();
    await tabTo(d.page, AUI.submit.ethicsNone);
    await d.page.keyboard.press('Space');
    await expect(d.page.locator(AUI.submit.ethicsNone)).toBeChecked();
    const sent = d.page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.submission(d.proposal),
    );
    await tabTo(d.page, AUI.submit.confirm);
    await d.page.keyboard.press('Enter');
    expect((await sent).ok()).toBe(true);
    await expectState(d.page, origin, d.proposal, 'SUBMITTED');
  });
});
