/**
 * One app shell (lane m4/site scope item 1, ADR-014 "Shell, assets and
 * headers", R-NF-03).
 *
 * - adr014_no_reload_navigation: following sidebar and in-page links
 *   across several pages keeps one document. The URL changes, the
 *   document title changes, focus lands on the h1, and a polite live
 *   region names the page.
 * - adr014_history_and_deep_links: Back and Forward restore the earlier
 *   pages without a new document. A reload and a pasted deep link show
 *   the same h1 and main content as navigating there.
 *
 * Each runs for an applicant, a reviewer and a coordinator of the demo
 * scenes, signed in with a passkey on the suite's cell. The page
 * contract is in `contract.ts`. Every person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { ApplicantControl, must } from '../applicant/support';
import { seed, assignmentOf, proposal } from '../review/support';
import {
  Document,
  SITE,
  clickTo,
  enrolToHome,
  expectAnnounced,
  pathOf,
  seen,
  suiteCell,
  type Seen,
} from './contract';

// A step that waits on a navigation or an action fails within half a minute, not at the test timeout.
test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** One step of a walk: the link to follow and the path it leads to. */
interface Step {
  readonly why: string;
  readonly link: (page: Page) => ReturnType<Page['locator']>;
  readonly to: RegExp;
}

/** A person of a demo scene, signed in and on the home page, and the walk they take. */
interface Walker {
  readonly name: string;
  readonly signIn: (person: () => Promise<Page>, request: Parameters<typeof seed>[0]) => Promise<{ page: Page; steps: Step[] }>;
}

const HOME_PATH = /^\/app\/$/;

/** The sidebar Home link. */
const sidebarHome = (page: Page): ReturnType<Page['locator']> => page.locator('aside nav a[data-nav="home"]').first();

const WALKERS: readonly Walker[] = [
  {
    // J4: the lead of a proposal in STAGE2.
    name: 'applicant',
    signIn: async (person, request) => {
      const cell = suiteCell();
      const control = new ApplicantControl(request, cell);
      await control.reset();
      const s = await control.scenario('STAGE2');
      const lead = must(s.lead, 'the STAGE2 lead');
      const p = must(s.proposal, 'the STAGE2 proposal');
      const page = await enrolToHome(person, cell.origin, lead.enrol_url);
      return {
        page,
        steps: [
          { why: 'home to own proposal', link: (pg) => pg.locator(SITE.workLink('proposal')).first(), to: new RegExp(`^/app/proposals/${p}$`) },
          { why: 'proposal to its stage 2 questions', link: (pg) => pg.locator(`main a[href="/app/proposals/${p}/stage2"]`).first(), to: new RegExp(`^/app/proposals/${p}/stage2$`) },
          { why: 'sidebar to my applications', link: (pg) => pg.locator('aside nav a[data-nav="proposals"]').first(), to: /^\/app\/proposals$/ },
          { why: 'sidebar to open calls', link: (pg) => pg.locator('aside nav a[data-nav="calls"]').first(), to: /^\/app\/calls$/ },
          { why: 'sidebar back home', link: sidebarHome, to: HOME_PATH },
        ],
      };
    },
  },
  {
    // J6: an assigned reviewer in stage 1.
    name: 'reviewer',
    signIn: async (person, request) => {
      const seeded = await seed(request, 'stage1');
      const a = assignmentOf(seeded.s, 'x', 'r1');
      const page = await enrolToHome(person, seeded.cell.origin, seeded.s.people.r1.invite_url);
      return {
        page,
        steps: [
          { why: 'home to my assignments', link: (pg) => pg.locator(SITE.workLink('assignments')).first(), to: /^\/app\/me\/assignments$/ },
          { why: 'assignments to one assignment', link: (pg) => pg.locator(`main a[href="/app/assignments/${a}"]`).first(), to: new RegExp(`^/app/assignments/${a}$`) },
          { why: 'sidebar back home', link: sidebarHome, to: HOME_PATH },
          { why: 'sidebar to open calls', link: (pg) => pg.locator('aside nav a[data-nav="calls"]').first(), to: /^\/app\/calls$/ },
        ],
      };
    },
  },
  {
    // J5: the FSTP coordinator with submitted proposals.
    name: 'coordinator',
    signIn: async (person, request) => {
      const seeded = await seed(request, 'submitted');
      const x = proposal(seeded.s, 'x');
      const page = await enrolToHome(person, seeded.cell.origin, seeded.s.people.c1.invite_url);
      return {
        page,
        steps: [
          { why: 'home to the intake queue', link: (pg) => pg.locator(SITE.workLink('intake')).first(), to: new RegExp(`^/app/calls/${seeded.s.call}/intake$`) },
          { why: 'intake to a declaration', link: (pg) => pg.locator(`main a[href="/app/proposals/${x.id}/declaration"]`).first(), to: new RegExp(`^/app/proposals/${x.id}/declaration$`) },
          { why: 'sidebar back home', link: sidebarHome, to: HOME_PATH },
          { why: 'home to the call board', link: (pg) => pg.locator(SITE.workLink('board')).first(), to: new RegExp(`^/app/calls/${seeded.s.call}/board$`) },
        ],
      };
    },
  },
];

test.describe('ADR-014 one app shell', () => {
  test.describe.configure({ timeout: 240_000 });

  for (const w of WALKERS) {
    /**
     * ADR-014 and R-NF-03: in-app links never load a new document. Each
     * click changes the URL and the title, moves focus to the h1, and
     * the polite live region names the new page.
     */
    test(`adr014_no_reload_navigation_${w.name}`, async ({ person, request }) => {
      const { page, steps } = await w.signIn(person, request);
      const doc = await Document.watch(page);
      let before: Seen = await seen(page);
      for (const s of steps) {
        const now = await clickTo(page, s.link(page), s.to, `${w.name}: ${s.why}`);
        await doc.expectSame(`${w.name}: ${s.why}`);
        expect(now.path, `${w.name}: ${s.why}: the URL changes`).not.toBe(before.path);
        before = now;
      }
    });

    /**
     * ADR-014: Back and Forward restore the pages in one document; a
     * reload and a pasted deep link show the same h1 and main content as
     * the click did.
     */
    test(`adr014_history_and_deep_links_${w.name}`, async ({ person, request }) => {
      const { page, steps } = await w.signIn(person, request);
      const doc = await Document.watch(page);
      const trail: Seen[] = [await seen(page)];
      for (const s of steps.slice(0, 2)) {
        trail.push(await clickTo(page, s.link(page), s.to, `${w.name}: ${s.why}`));
      }
      const [first, second, third] = trail;
      if (first === undefined || second === undefined || third === undefined) throw new Error('the walk has three pages');

      const expectShows = async (p: Page, want: Seen, why: string): Promise<void> => {
        await expect(p, `${why}: the URL`).toHaveURL((u) => u.pathname === want.path);
        const now = await seen(p);
        expect(now.h1, `${why}: the same h1 as by clicking`).toBe(want.h1);
        expect(now.main, `${why}: the same main content as by clicking`).toBe(want.main);
      };

      await page.goBack();
      await expectShows(page, second, `${w.name}: Back to ${second.path}`);
      await expectAnnounced(page, third, `${w.name}: Back to ${second.path}`);
      await page.goBack();
      await expectShows(page, first, `${w.name}: Back to ${first.path}`);
      await page.goForward();
      await expectShows(page, second, `${w.name}: Forward to ${second.path}`);
      await page.goForward();
      await expectShows(page, third, `${w.name}: Forward to ${third.path}`);
      await doc.expectSame(`${w.name}: Back and Forward`);

      await page.reload();
      await expectShows(page, third, `${w.name}: reload of ${third.path}`);

      for (const want of [second, third]) {
        const tab = await page.context().newPage();
        await tab.goto(`${new URL(page.url()).origin}${want.path}`);
        await expectShows(tab, want, `${w.name}: deep link ${want.path}`);
        expect(pathOf(tab)).toBe(want.path);
        await tab.close();
      }
    });
  }
});
