/**
 * The page gate of SA-09 (`docs/design/spec-amendments.md`). Daniel,
 * 2026-11-15: "I should never be able to see a route that my user (or a
 * non-logged in user) does not have permissions to see."
 *
 * - A visitor with no session who opens `/app/grants` lands on the login
 *   page, which returns them to `/app/grants` after sign-in.
 * - An applicant who opens `/app/admin/approvals` gets the one "Page not
 *   found" page, status 404, as for a path that does not exist.
 * - Every in-app link of the navigation of each demo person opens with
 *   status 200: the navigation lists only pages the person may open.
 *
 * Every person, proposal and text is synthetic.
 */

import { expect, test } from '@playwright/test';
import { PAGES, stack } from '../playwright.config';
import { DemoPage, HOME, classify, enrolFromLink, newPerson, personOf, settle } from './support';

/** The heading of the not-found page (`applicant/messages.en.ts` `app.not_found`). */
const NOT_FOUND_TITLE = 'Page not found';

test.describe('SA-09 page gate', () => {
  /** r_ac_01_sa09: signed out, `/app/grants` answers 303 to sign-in with the page as return path. */
  test('r_ac_01_sa09_signed_out_grants_lands_on_sign_in', async ({ browser }) => {
    test.setTimeout(180_000);
    const demo = await DemoPage.open(browser);
    const context = await browser.newContext();
    try {
      await demo.chooseScene('/demo/applicant?at=OPEN_CALL');
      const origin = stack().cells.a.origin;
      const page = await context.newPage();
      const r = await page.request.get(`${origin}/app/grants`, { maxRedirects: 0 });
      expect(r.status(), 'the cell answers 303 before it serves the shell').toBe(303);
      await page.goto(`${origin}/app/grants`);
      await expect(page).toHaveURL(
        (u) => u.pathname === PAGES.login && u.searchParams.get('next') === '/app/grants',
      );
      await expect(page.locator('body')).not.toContainText('The platform refused');
    } finally {
      await context.close();
      await demo.close();
    }
  });

  /** r_ac_01_sa09: an applicant on `/app/admin/approvals` sees the not-found page, 404, as an unknown path. */
  test('r_ac_01_sa09_applicant_on_admin_approvals_sees_page_not_found', async ({ browser }) => {
    test.setTimeout(180_000);
    const demo = await DemoPage.open(browser);
    const p = await newPerson(browser);
    try {
      await demo.chooseScene('/demo/applicant?at=NEGOTIATION');
      await enrolFromLink(p, personOf(await demo.people(), 'lead-x', 'applicant_NEGOTIATION').link);
      await expect(p.page).toHaveURL((u) => u.origin === p.origin && !u.pathname.startsWith('/auth/'));
      await settle(p.page);
      const closed = await p.page.goto(`${p.origin}/app/admin/approvals`);
      expect(closed?.status(), 'the page answers 404').toBe(404);
      await settle(p.page);
      await expect(p.page.locator('h1').first()).toHaveText(NOT_FOUND_TITLE);
      await expect(p.page.locator('body')).not.toContainText('The platform refused');
      const unknown = await p.page.request.get(`${p.origin}/app/no-such-page`);
      expect(unknown.status()).toBe(404);
      expect(await closed?.body(), 'the same bytes as an unknown path').toEqual(await unknown.body());
    } finally {
      await p.context.close();
      await demo.close();
    }
  });

  /** r_ac_01_sa09: every navigation link of each demo person opens with 200. */
  test('r_ac_01_sa09_every_nav_link_of_each_demo_person_opens', async ({ browser }) => {
    test.setTimeout(600_000);
    const demo = await DemoPage.open(browser);
    try {
      for (const scene of ['/demo/review?stage=stage1', '/demo/applicant?at=NEGOTIATION']) {
        await demo.chooseScene(scene);
        const people = (await demo.people()).filter((x) => classify(x) !== null);
        expect(people.length, `${scene} lists people`).toBeGreaterThan(0);
        for (const person of people) {
          const who = `${scene}: ${classify(person)?.key ?? person.label}`;
          const p = await newPerson(browser);
          try {
            await enrolFromLink(p, person.link);
            await expect(p.page).toHaveURL((u) => u.origin === p.origin && !u.pathname.startsWith('/auth/'));
            await p.page.goto(`${p.origin}${HOME}`);
            await settle(p.page);
            // The gate has answered every link once none waits for it.
            await expect(p.page.locator('a[data-page-gate]')).toHaveCount(0);
            const hrefs = await p.page
              .locator('nav a[href^="/app/"], aside a[href^="/app/"]')
              .evaluateAll((as) => as.map((a) => a.getAttribute('href') ?? ''));
            expect(hrefs.length, `${who}: the navigation has links`).toBeGreaterThan(0);
            test.info().annotations.push({ type: 'links', description: `${who}: ${[...new Set(hrefs)].join(' ')}` });
            for (const href of new Set(hrefs)) {
              const r = await p.page.request.get(`${p.origin}${href}`, { maxRedirects: 0 });
              expect(r.status(), `${who}: ${href} opens`).toBe(200);
            }
          } finally {
            await p.context.close();
          }
        }
      }
    } finally {
      await demo.close();
    }
  });
});
