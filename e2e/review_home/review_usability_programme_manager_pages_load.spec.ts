/**
 * Reviewer test (usability by clicking), journeys J1 and J3 of M4 design
 * section 2.2 and the interim home page of section 15.0 (2026-10-31).
 *
 * Every review and applicant scene lists `Programme manager M1`. The
 * demo page says M1 can use "the creator and people pages of the
 * programme". M1's home page links to `/app/programmes/1/creator/review`
 * and `/app/programmes/1/people`. The seeded programme was activated
 * through the test kit, so it has no creator draft. Both pages read
 * `GET /api/v1/programmes/1/draft`, which answers 404, and both show
 * "This was refused under rule Input." The people page then lists no
 * invitation and offers no invite. `nav_programme_manager_m1_*` passes
 * because it checks the path only.
 *
 * Every person and text is synthetic.
 */

import { expect, test, type Page } from '@playwright/test';
import { DemoPage, HOME, NAV_UI, enrolFromLink, expectHome, newPerson, personOf, settle } from '../navigation/support';


/** Clicks the home link of `kind`, waits for the page's reads, and returns the API reads that failed. */
async function openFromHome(page: Page, kind: string): Promise<string[]> {
  const failed: string[] = [];
  const onResponse = (r: { url(): string; status(): number }): void => {
    const u = new URL(r.url());
    if (u.pathname.startsWith('/api/') && r.status() >= 400) failed.push(`${r.status()} ${u.pathname}`);
  };
  page.on('response', onResponse);
  await page.locator(NAV_UI.workLink(kind as never)).first().click();
  await page.waitForURL((u) => u.pathname !== HOME);
  await settle(page);
  await page.waitForLoadState('networkidle');
  page.off('response', onResponse);
  return failed;
}

/** The visible alert texts of the page. */
async function alerts(page: Page): Promise<string[]> {
  return page
    .locator('[role="alert"]')
    .evaluateAll((es) =>
      es
        .filter((e) => (e as HTMLElement).getClientRects().length > 0 && (e.textContent ?? '').trim() !== '')
        .map((e) => (e.textContent ?? '').trim()),
    );
}

/** The hint line under M1 on the demo page. */
async function hintOfM1(demo: DemoPage): Promise<string> {
  return demo.page.evaluate(() => {
    const li = Array.from(document.querySelectorAll('li')).find((e) =>
      (e.querySelector('a')?.textContent ?? '').trim() === 'Programme manager M1',
    );
    return (li?.querySelector('span')?.textContent ?? '').trim();
  });
}

/**
 * Fix round of lane m4home (finding U1). The seeded programme holds no
 * creator draft, so the home page may leave the creator and people links
 * out. Each test checks the property the finding asks for: a page M1's
 * home page links loads without a refusal, and the demo hint names a
 * page only when the home page links it. The call board is M1's work in
 * every seed, so it must be linked.
 */
const PAGES = [
  { kind: 'creator', named: /set-up|creator/i, required: false },
  { kind: 'people', named: /people/i, required: false },
  { kind: 'board', named: /board/i, required: true },
] as const;

for (const { kind, named, required } of PAGES) {
  test(`review_usability_programme_manager_m1_${kind}_page_loads_in_review_stage1`, async ({ browser }) => {
    test.setTimeout(180_000);
    const demo = await DemoPage.open(browser);
    const p = await newPerson(browser);
    try {
      await demo.chooseScene('/demo/review?stage=stage1');
      const hint = await hintOfM1(demo);
      const m1 = personOf(await demo.people(), 'm1', 'review_stage1');
      await enrolFromLink(p, m1.link);
      await expectHome(p, 'M1 in review stage1 (J1)');
      const linked = (await p.page.locator(NAV_UI.workLink(kind as never)).count()) > 0;
      if (required) {
        expect(linked, `M1's home page links the ${kind} page`).toBe(true);
      }
      expect(named.test(hint), `the hint "${hint}" names the ${kind} page only when the home page links it`).toBe(linked);
      if (!linked) return;
      const failed = await openFromHome(p.page, kind);
      expect(failed, `M1's ${kind} page (${p.page.url()}) reads without a refusal`).toEqual([]);
      expect(await alerts(p.page), `M1's ${kind} page shows no refusal`).toEqual([]);
    } finally {
      await p.context.close();
      await demo.close();
    }
  });
}
