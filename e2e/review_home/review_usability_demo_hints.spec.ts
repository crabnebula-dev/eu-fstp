/**
 * Reviewer tests (usability by clicking), the demo-page hints of the
 * interim home page (M4 design section 15.0, 2026-10-31) and journeys
 * J6, J7 and J8 of design section 2.2.
 *
 * Under each person the demo page says what that person can do in the
 * scene (`demo.rs` `what_they_can_do`). These tests follow the hint by
 * clicking from the sign-in link and check that the promised work opens.
 *
 * 1. Committee member R1 in `review ranked`: the hint says "3 review
 *    assignments". Every assignment page answers "The platform refused
 *    this under rule R-AC-01." The hint counts finished assignments.
 * 2. IRC member I1 in applicant `NEGOTIATION`: the hint says "1 IRC case
 *    ... then validate or raise a concern". The case page answers the
 *    same refusal.
 * 3. Committee chair H1 in `review ranked`: the hint promises "the
 *    cut-off rounds of each published call". No scene has an open round,
 *    and the home page has no cut-off round link.
 *
 * Every person and text is synthetic.
 */

import { expect, test, type Browser, type Page } from '@playwright/test';
import { DemoPage, HOME, NAV_UI, classify, enrolFromLink, expectHome, newPerson, personOf, settle } from '../navigation/support';

/** The hint line under the person with `key` on the demo page. */
async function hintOf(demo: DemoPage, key: string): Promise<string> {
  const lines = await demo.page.evaluate(() => {
    const h2 = Array.from(document.querySelectorAll('h2')).find((e) =>
      (e.textContent ?? '').startsWith('People of this scene'),
    );
    const ul = h2?.nextElementSibling;
    return Array.from(ul?.querySelectorAll('li') ?? []).map((li) => ({
      label: (li.querySelector('a')?.textContent ?? '').trim(),
      email: (li.querySelector('small')?.textContent ?? '').trim(),
      hint: (li.querySelector('span')?.textContent ?? '').trim(),
    }));
  });
  const line = lines.find((l) => classify({ label: l.label, email: l.email, link: '' })?.key === key);
  expect(line, `the demo page lists ${key}`).toBeDefined();
  return line?.hint ?? '';
}

/** The visible, non-empty alert texts of the page. */
async function alerts(page: Page): Promise<string[]> {
  return page
    .locator('[role="alert"]')
    .evaluateAll((es) =>
      es
        .filter((e) => (e as HTMLElement).getClientRects().length > 0 && (e.textContent ?? '').trim() !== '')
        .map((e) => (e.textContent ?? '').trim()),
    );
}

/**
 * Signs `key` in from the demo page of `scene`, clicks the home link
 * `kind`, then clicks the first link of that list matching `item`, and
 * returns the hint and the alerts of the page it opened.
 */
async function followHint(
  browser: Browser,
  scene: string,
  key: string,
  kind: 'assignments' | 'irc-cases',
  item: RegExp,
): Promise<{ hint: string; opened: string; refusals: string[] }> {
  const demo = await DemoPage.open(browser);
  const p = await newPerson(browser);
  try {
    await demo.chooseScene(scene);
    const hint = await hintOf(demo, key);
    await enrolFromLink(p, personOf(await demo.people(), key, scene).link);
    await expectHome(p, `${key} in ${scene}`);
    await p.page.locator(NAV_UI.workLink(kind)).first().click();
    await p.page.waitForURL((u) => u.pathname !== HOME);
    await settle(p.page);
    const hrefs = await p.page
      .locator('main a[href]')
      .evaluateAll((as) => as.map((a) => a.getAttribute('href') ?? ''));
    const first = hrefs.find((h) => item.test(h));
    expect(first, `${key}'s ${kind} page lists a piece of work, as the hint says`).toBeDefined();
    const list = new URL(p.page.url()).pathname;
    await p.page.locator(`main a[href="${first ?? ''}"]`).first().click();
    await p.page.waitForURL((u) => u.pathname !== list);
    await settle(p.page);
    await p.page.waitForLoadState('networkidle');
    return { hint, opened: p.page.url(), refusals: await alerts(p.page) };
  } finally {
    await p.context.close();
    await demo.close();
  }
}

/**
 * Fix round of lane m4home (findings U2 and U3): the hint counts only the
 * assignments whose page still opens ("N review assignments to work on")
 * and names finished ones apart. Each test checks the property: when the
 * hint promises work, the first piece opens without a refusal, and when
 * the scene holds only finished work, the hint promises none. The
 * stage1 and irc_review tests keep the check from passing vacuously.
 */
async function checkHint(
  browser: Browser,
  scene: string,
  key: string,
  kind: 'assignments' | 'irc-cases',
  noun: string,
  item: RegExp,
  promised: boolean,
): Promise<void> {
  const demo = await DemoPage.open(browser);
  let hint = '';
  try {
    await demo.chooseScene(scene);
    hint = await hintOf(demo, key);
  } finally {
    await demo.close();
  }
  const n = Number(new RegExp(`(\\d+) ${noun}s? to work on`).exec(hint)?.[1] ?? '0');
  expect(n > 0, `the hint "${hint}" promises ${noun}s to work on only when there are some`).toBe(promised);
  expect(hint, 'the hint never counts finished work as work').not.toMatch(new RegExp(`[1-9]\\d* ${noun}s?, `));
  if (!promised) return;
  const r = await followHint(browser, scene, key, kind, item);
  expect(r.refusals, `the ${noun} the hint promises (${r.opened}) opens without a refusal`).toEqual([]);
}

test('review_usability_hint_review_assignments_open_for_r1_in_review_ranked', async ({ browser }) => {
  test.setTimeout(240_000);
  await checkHint(browser, '/demo/review?stage=ranked', 'r1', 'assignments', 'review assignment', /^\/app\/assignments\/\d+$/, false);
});

test('review_usability_hint_review_assignments_open_for_r1_in_review_stage1', async ({ browser }) => {
  test.setTimeout(240_000);
  await checkHint(browser, '/demo/review?stage=stage1', 'r1', 'assignments', 'review assignment', /^\/app\/assignments\/\d+$/, true);
});

test('review_usability_hint_irc_case_opens_for_i1_in_applicant_negotiation', async ({ browser }) => {
  test.setTimeout(240_000);
  await checkHint(browser, '/demo/applicant?at=NEGOTIATION', 'i1', 'irc-cases', 'IRC case', /^\/app\/irc-assignments\/\d+$/, false);
});

test('review_usability_hint_irc_case_opens_for_i1_in_review_irc_review', async ({ browser }) => {
  test.setTimeout(240_000);
  await checkHint(browser, '/demo/review?stage=irc_review', 'i1', 'irc-cases', 'IRC case', /^\/app\/irc-assignments\/\d+$/, true);
});

test('review_usability_hint_chair_cut_off_rounds_reachable_in_review_ranked', async ({ browser }) => {
  test.setTimeout(180_000);
  const scene = '/demo/review?stage=ranked';
  const demo = await DemoPage.open(browser);
  const p = await newPerson(browser);
  try {
    await demo.chooseScene(scene);
    const hint = await hintOf(demo, 'h1');
    await enrolFromLink(p, personOf(await demo.people(), 'h1', scene).link);
    await expectHome(p, `h1 in ${scene}`);
    if (/cut-off round/.test(hint)) {
      await expect(
        p.page.locator(NAV_UI.workLink('cut-off-round')),
        `the hint "${hint}" promises cut-off rounds, so H1's home page links to one`,
      ).not.toHaveCount(0);
    }
  } finally {
    await p.context.close();
    await demo.close();
  }
});
