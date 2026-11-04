/**
 * A crawl of every page each demo person reaches by clicking, from the
 * home page they land on (lane m4/site scope items 1 to 3).
 *
 * - adr014_no_csp_violation: no `securitypolicyviolation` event fires
 *   and no console or uncaught error is logged on any page, with the CSP
 *   and Trusted Types of ADR-014 unchanged.
 * - i70_tokens_light_and_dark: every page computes the custom properties
 *   of the copied token sheet in the light and the dark scheme
 *   (`prefers-color-scheme`), sits on `--color-surface-0` with
 *   `--color-text-1`, and its body text meets 4.5:1 (I-70, R-NF-03).
 * - r_nf_03_state_never_colour_only: every status chip or badge has
 *   text, and each proposal state is shown by a `.badge` with text.
 *
 * The crawl clicks visible links of `main`, the sidebar and the top bar
 * that stay on the cell origin under `/app/` (and the account page),
 * depth first, and returns with Back (`contract.ts` `crawl`). Every
 * person and text is synthetic.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { ApplicantControl, must } from '../applicant/support';
import { seed } from '../review/support';
import { M4Control } from '../creator/contract';
import type { PersonaKey, ReviewStage } from '../review/contract';
import {
  chipProblems,
  crawl,
  enrolToHome,
  suiteCell,
  tokenProblems,
  watchProblems,
} from './contract';

// A step that waits on a navigation or an action fails within half a minute, not at the test timeout.
test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** A demo person, signed in on the home page. */
interface Seat {
  readonly name: string;
  readonly signIn: (person: () => Promise<Page>, request: Parameters<typeof seed>[0]) => Promise<Page>;
}

const review = (name: string, stage: ReviewStage, who: PersonaKey): Seat => ({
  name,
  signIn: async (person, request) => {
    const seeded = await seed(request, stage);
    return enrolToHome(person, seeded.cell.origin, seeded.s.people[who].invite_url);
  },
});

const SEATS: readonly Seat[] = [
  {
    name: 'applicant_stage2',
    signIn: async (person, request) => {
      const cell = suiteCell();
      const control = new ApplicantControl(request, cell);
      await control.reset();
      const s = await control.scenario('STAGE2');
      return enrolToHome(person, cell.origin, must(s.lead, 'the STAGE2 lead').enrol_url);
    },
  },
  review('reviewer_stage1', 'stage1', 'r1'),
  review('coordinator_submitted', 'submitted', 'c1'),
  review('committee_chair_ranked', 'ranked', 'h1'),
  review('committee_member_ranked', 'ranked', 'r1'),
  review('irc_member_irc_review', 'irc_review', 'i1'),
  {
    name: 'tenant_admin_reset',
    signIn: async (person, request) => {
      const cell = suiteCell();
      const fresh = await new M4Control(request, cell).reset();
      return enrolToHome(person, cell.origin, fresh.url);
    },
  },
];

test.describe('the pages each demo person reaches', () => {
  test.describe.configure({ timeout: 420_000 });

  for (const seat of SEATS) {
    /** ADR-014: no CSP or Trusted Types violation and no console error on any reached page. */
    test(`adr014_no_csp_violation_${seat.name}`, async ({ person, request }) => {
      const page = await seat.signIn(person, request);
      const watch = await watchProblems(page.context());
      // The init script reaches documents loaded from now on.
      await page.reload();
      const visited = await crawl(page, async () => undefined);
      expect(visited.length, `${seat.name}: the crawl reaches more than the home page`).toBeGreaterThan(1);
      expect(watch.problems(), `ADR-014: ${seat.name}: pages ${visited.join(', ')}`).toEqual([]);
    });

    /** I-70, R-NF-03: the token sheet in both schemes, and AA body text, on every reached page. */
    test(`i70_tokens_light_and_dark_${seat.name}`, async ({ person, request }) => {
      const page = await seat.signIn(person, request);
      const problems: string[] = [];
      const visited = await crawl(page, async (p) => {
        const label = new URL(p.url()).pathname;
        problems.push(...(await tokenProblems(p, 'light', label)), ...(await tokenProblems(p, 'dark', label)));
        await p.emulateMedia({ colorScheme: 'light' });
      });
      expect(visited.length, `${seat.name}: the crawl reaches more than the home page`).toBeGreaterThan(1);
      expect(problems, `I-70: ${seat.name}`).toEqual([]);
    });

    /** R-NF-03: state is never shown by colour alone; every chip carries its text. */
    test(`r_nf_03_state_never_colour_only_${seat.name}`, async ({ person, request }) => {
      const page = await seat.signIn(person, request);
      const problems: string[] = [];
      let chips = 0;
      const visited = await crawl(page, async (p) => {
        const r = await chipProblems(p, new URL(p.url()).pathname);
        problems.push(...r.problems);
        chips += r.chips;
      });
      expect(visited.length, `${seat.name}: the crawl reaches more than the home page`).toBeGreaterThan(1);
      expect(problems, `R-NF-03: ${seat.name}`).toEqual([]);
      if (seat.name !== 'tenant_admin_reset') {
        expect(chips, `R-NF-03: ${seat.name}: the reached pages show state as status chips`).toBeGreaterThan(0);
      }
    });
  }
});
