/**
 * Journey J4, first half: find a call, start a proposal and write the
 * draft (M4 design sections 2.2 and 8.7, lane W4b).
 *
 * Each test resets cell `a` of the e2e cell and seeds an open SuperSAFE
 * call (`support.ts`, e2e cell contract). A fresh applicant signs up
 * through M3 in a browser context of their own. Without a stack
 * manifest, each test fails at its first step with `StackMissing`.
 */

import { expect } from '@playwright/test';
import { call, test } from '../playwright.config';
import {
  API,
  APP,
  AUI,
  PLAN_DAYS,
  Traffic,
  canary,
  fillAndAutosave,
  freshCell,
  jsonLeaves,
  newApplicant,
  parsedOrNull,
  startProposal,
} from './support';

/** A regular expression that finds `text` with no digit or dot glued to it. */
function standalone(text: string): RegExp {
  const esc = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^0-9.])${esc}([^0-9]|$)`);
}

test.describe('J4 find a call and draft', () => {
  /**
   * ADR-006 and the Guide's "Call at a glance" (`guide-for-applicants.md`):
   * the call page shows every amount as the server's ADR-006 text, byte
   * for byte, and the deadline as a machine-readable instant together
   * with its time zone. The browser never computes money (section 3.9).
   */
  test('adr006_call_page_shows_amounts_as_server_text_and_deadline_with_zone', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(person, control, origin, 'callpage');
    await page.goto(`${origin}${APP.calls}`);
    const entry = page.locator(`${AUI.calls.list} li`).filter({ hasText: s.call.title });
    await expect(entry).toHaveCount(1);
    await entry.locator(`a[href="${APP.call(s.call.id)}"]`).click();
    await expect(page.locator(AUI.call.title)).toHaveText(s.call.title);

    const amounts = page.locator(AUI.call.amounts);
    await expect(amounts).toBeVisible();
    const shown = await amounts.innerText();
    for (const a of s.call.amounts) {
      expect(shown, `the amount ${a} appears verbatim`).toMatch(standalone(a));
    }

    const deadline = page.locator(AUI.call.deadline);
    await expect(deadline).toContainText(s.call.time_zone);
    const time = deadline.locator('time[datetime]');
    await expect(time).toHaveCount(1);
    const datetime = await time.getAttribute('datetime');
    expect(Date.parse(datetime ?? ''), 'the deadline instant').toBe(Date.parse(s.call.deadline));
  });

  /**
   * R-LA-08: applicants are informed that AI assessment is used, in the
   * call text. The call page carries the disclosure, and its Guide link
   * opens the call's Guide for Applicants.
   */
  test('r_la_08_call_page_discloses_ai_assessment_and_links_the_guide', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(person, control, origin, 'aidisclosure');
    await page.goto(`${origin}${APP.call(s.call.id)}`);
    const disclosure = page.locator(AUI.call.aiDisclosure);
    await expect(disclosure).toBeVisible();
    expect((await disclosure.innerText()).trim().length, 'the disclosure has text').toBeGreaterThan(0);
    await page.locator(AUI.call.guideLink).click();
    await expect(page).toHaveURL((u) => u.origin === origin && u.pathname === APP.guide(s.call.id));
    const guide = page.locator(AUI.guide.body);
    await expect(guide).toBeVisible();
    await expect(guide.locator('h2').first()).toBeVisible();
    // Q38: the cell has a pre-check provider, so the Guide describes the
    // available pre-check and no longer says it is not yet available.
    await expect(guide).toContainText('The pre-submission check is available on this platform.');
    await expect(guide).toContainText('You are then interacting with an AI system, not a person.');
    await expect(guide).not.toContainText('not yet available');
  });

  /**
   * I-21 and design section 3.6 (`GetOwnWorkspace` admits the team only):
   * the workspace autosaves the draft to the workspace route and to no
   * other, the draft survives a reload, and another account can read
   * neither the workspace nor the proposal. Supporting test: the Judging
   * and operator rows of I-21 are claimed by the authorisation matrix.
   */
  test('i21_workspace_autosaves_and_only_the_team_reads_it', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(person, control, origin, 'workspace');
    const traffic = new Traffic(page);
    const proposal = await startProposal(page, origin, s.call);
    const secret = canary('DRAFT');
    const narrative = `A synthetic narrative ${secret}`;
    await fillAndAutosave(page, AUI.workspace.narrative, narrative, AUI.workspace.status);

    const puts = traffic.to('PUT', API.workspace(proposal));
    expect(
      puts.some((r) => (r.body ?? '').includes(secret)),
      'the draft goes to the workspace route',
    ).toBe(true);
    const elsewhere = traffic.sent.filter((r) => r.path !== API.workspace(proposal) && (r.body ?? '').includes(secret));
    expect(elsewhere.map((r) => `${r.method} ${r.path}`), 'no other route receives the draft').toEqual([]);

    await page.reload();
    await expect(page.locator(AUI.workspace.narrative)).toHaveValue(narrative);

    const outsider = await newApplicant(person, control, origin, 'outsider');
    for (const path of [API.workspace(proposal), API.view(proposal)]) {
      const a = await call(outsider.page, origin, 'GET', path);
      expect(a.status, `${path} is refused to another account`).toBeGreaterThanOrEqual(400);
      expect(a.status).toBeLessThan(500);
      expect(a.body).not.toContain(secret);
    }
  });

  /**
   * ADR-006: the plan editor takes an amount only in its canonical
   * spelling. A non-canonical spelling is a field error, and nothing is
   * sent. A canonical amount travels as a JSON string, never a number.
   */
  test('adr006_plan_amount_takes_only_the_canonical_spelling', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(person, control, origin, 'planamount');
    const proposal = await startProposal(page, origin, s.call);
    const traffic = new Traffic(page);
    await page.goto(`${origin}${APP.plan(proposal)}`);
    await page.locator(AUI.plan.description).fill('A synthetic work plan.');
    await page.locator(AUI.plan.start).fill(PLAN_DAYS.start);
    await page.locator(AUI.plan.due).fill(PLAN_DAYS.due);

    for (const wrong of ['1500.5', '1500', '1,500.50', '01500.50', '-1500.50', '1500.500']) {
      await page.locator(AUI.plan.amount).fill(wrong);
      await page.locator(AUI.plan.save).click();
      await expect(page.locator(AUI.plan.amount), `${wrong} is refused`).toHaveAttribute('aria-invalid', 'true');
    }
    expect(traffic.to('PUT', API.plan(proposal)), 'no plan is sent for a wrong spelling').toEqual([]);

    const saved = page.waitForResponse(
      (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === API.plan(proposal),
    );
    await page.locator(AUI.plan.amount).fill('1500.50');
    await page.locator(AUI.plan.save).click();
    expect((await saved).ok()).toBe(true);
    await expect(page.locator(AUI.plan.status)).toHaveAttribute('data-status', 'saved');
    const put = traffic.to('PUT', API.plan(proposal));
    expect(put).toHaveLength(1);
    const leaves = jsonLeaves(parsedOrNull(put[0]?.body ?? null));
    expect(leaves.strings, 'the amount is a JSON string').toContain('1500.50');
    expect(leaves.numbers.filter((n) => n.startsWith('1500')), 'the amount is never a number').toEqual([]);
  });

  /**
   * ADR-014 "DOM": applicant text reaches the page through `textContent`
   * only. Markup typed into the draft never runs and never becomes
   * elements, on the workspace, the proposal page and the submit page.
   */
  test('adr014_applicant_text_is_rendered_as_text', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(person, control, origin, 'xss');
    const dialogs: string[] = [];
    page.on('dialog', (d) => {
      dialogs.push(d.message());
      void d.dismiss();
    });
    const proposal = await startProposal(page, origin, s.call);
    const title = 'T <img src=x onerror="window.__fstpXss=1"> end';
    const narrative = '"><script>window.__fstpXss=2</script><a href="javascript:window.__fstpXss=3">x</a>';
    await fillAndAutosave(page, AUI.workspace.title, title, AUI.workspace.status);
    await fillAndAutosave(page, AUI.workspace.narrative, narrative, AUI.workspace.status);

    for (const path of [APP.workspace(proposal), APP.proposal(proposal), APP.submit(proposal)]) {
      await page.goto(`${origin}${path}`);
      await expect(page.locator('main')).toBeVisible();
      expect(await page.evaluate(() => (window as { __fstpXss?: unknown }).__fstpXss), `${path}: no payload ran`).toBe(
        undefined,
      );
      expect(await page.locator('img[src="x"], a[href^="javascript:"]').count(), `${path}: no element was built`).toBe(0);
    }
    await page.goto(`${origin}${APP.proposal(proposal)}`);
    await expect(page.locator(AUI.proposal.title)).toHaveText(title);
    await page.goto(`${origin}${APP.workspace(proposal)}`);
    await expect(page.locator(AUI.workspace.title)).toHaveValue(title);
    await expect(page.locator(AUI.workspace.narrative)).toHaveValue(narrative);
    expect(dialogs).toEqual([]);
  });

  /**
   * R-NG-01: the country of residence or establishment is collected at
   * submission and held only in the identity vault. Declared affiliations
   * go to the vault too (design section 2.2, `VaultBound<T>`). Each goes
   * to its vault route and no other. The pages never read either back,
   * and neither appears in a later read of the proposal or the workspace.
   */
  test('r_ng_01_country_and_affiliations_reach_only_the_vault_routes', async ({ person, request }) => {
    const { origin, control } = await freshCell(request);
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(person, control, origin, 'vaultonly');
    const traffic = new Traffic(page);
    const proposal = await startProposal(page, origin, s.call);
    await page.goto(`${origin}${APP.eligibility(proposal)}`);

    const options = await page
      .locator(`${AUI.eligibility.country} option`)
      .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value).filter((v) => v !== ''));
    const country = options[0];
    if (country === undefined) throw new Error('the country control offers no country');
    await page.locator(AUI.eligibility.country).selectOption(country);
    const stated = page.waitForResponse(
      (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === API.country(proposal),
    );
    await page.locator(AUI.eligibility.countrySave).click();
    expect((await stated).ok()).toBe(true);
    await expect(page.locator(AUI.eligibility.status)).toHaveAttribute('data-status', 'saved');

    const affiliation = canary('AFF');
    await page.locator(AUI.eligibility.affiliations).fill(`Synthetic organisation ${affiliation}`);
    const declared = page.waitForResponse(
      (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === API.affiliations(proposal),
    );
    await page.locator(AUI.eligibility.affiliationsSave).click();
    expect((await declared).ok()).toBe(true);
    await expect(page.locator(AUI.eligibility.status)).toHaveAttribute('data-status', 'saved');

    for (const path of [
      APP.eligibility(proposal),
      APP.proposal(proposal),
      APP.workspace(proposal),
      APP.submit(proposal),
      APP.proposals,
    ]) {
      await page.goto(`${origin}${path}`);
      await expect(page.locator('main')).toBeVisible();
      expect(await page.locator('body').innerText(), `${path} never shows the affiliations`).not.toContain(affiliation);
      expect(await page.content(), `${path} holds no affiliation text`).not.toContain(affiliation);
    }
    await traffic.settle();

    const hasCountry = (body: string | null): boolean => {
      const l = jsonLeaves(parsedOrNull(body));
      return l.strings.includes(country) || l.numbers.includes(country);
    };
    expect(hasCountry(traffic.to('PUT', API.country(proposal))[0]?.body ?? null), 'the country goes to its route').toBe(
      true,
    );
    const countryElsewhere = traffic.sent.filter((r) => r.path !== API.country(proposal) && hasCountry(r.body));
    expect(countryElsewhere.map((r) => `${r.method} ${r.path}`)).toEqual([]);
    const affElsewhere = traffic.sent.filter(
      (r) => r.path !== API.affiliations(proposal) && (r.body ?? '').includes(affiliation),
    );
    expect(affElsewhere.map((r) => `${r.method} ${r.path}`)).toEqual([]);

    const reads = traffic.received.filter((r) =>
      [API.view(proposal), API.workspace(proposal), API.listOwn].includes(r.path),
    );
    expect(reads.length, 'the proposal was read back').toBeGreaterThan(0);
    for (const r of reads) {
      expect(r.body, `${r.path} holds no affiliation`).not.toContain(affiliation);
      const l = jsonLeaves(parsedOrNull(r.body));
      expect(l.keys.filter((k) => /country/i.test(k)), `${r.path} has no country member`).toEqual([]);
      expect(hasCountry(r.body), `${r.path} holds no country value`).toBe(false);
    }
    for (const r of traffic.received) {
      expect(r.body, `${r.method} ${r.path} echoes no affiliation`).not.toContain(affiliation);
    }
  });
});
