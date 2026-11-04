/**
 * Every person reaches their work by clicking (Daniel's report of
 * 2026-10-31; M4 design section 2.2, journeys J0 to J8).
 *
 * Interim, pending Daniel: design section 2.2 names no home page. The
 * page contract is in `support.ts`. For each scene of the demo page and
 * each person it lists, a test opens the person's sign-in link from the
 * demo page, creates a passkey and checks:
 *
 * - the browser lands on the home page `/app/`, not on `/auth/account`;
 * - the home page names the person's work, and offers the page their
 *   role starts from, beyond the open calls;
 * - the person reaches each work page by clicking visible links only;
 * - every page on the way links to the home and account pages, and the
 *   account page links to the home page.
 *
 * `page.goto` opens only the first sign-in link of a person. The person
 * without a role also types the sign-up address the demo page names, as
 * the demo page tells them to (J4).
 *
 * The scene tables restate what `fstp-e2e-cell` `scenario.rs` seeds.
 * Every person, proposal and text is synthetic.
 */

import { expect, test } from '@playwright/test';
import { UI, syntheticEmail } from '../playwright.config';
import { expectStructure } from '../review/support';
import {
  DemoPage,
  HOME,
  NAV_UI,
  accountRoundTrip,
  classify,
  enrolFromLink,
  expectHome,
  expectNav,
  newPerson,
  personOf,
  reach,
  settle,
  type ListedPerson,
  type Work,
  type WorkKind,
} from './support';

// ---------------------------------------------------------------------------
// The work of each person
// ---------------------------------------------------------------------------

/** The call of every seed (`scenario.rs` `CALL`). */
const CALL = '1';
/** Its title (`scenario.rs` `CALL_TITLE`). */
const CALL_TITLE = 'SuperSAFE open call 2026';

/** The seeded proposals an applicant scene's lead owns (`scenario.rs` `PROPOSALS`). */
const PROPOSAL = {
  x: { id: '1001', title: 'Synthetic open sensor kit' },
  v: { id: '1004', title: 'Synthetic school data vault' },
} as const;

/** J6: an assigned reviewer reaches one of their assignments. */
const ASSIGNMENT: Work = {
  what: 'assignment',
  kinds: ['assignments', 'assignment'],
  target: /^\/app\/assignments\/\d+$/,
};

/** J8: an IRC member reaches one of their IRC cases. */
const IRC_CASE: Work = {
  what: 'irc_case',
  kinds: ['irc-cases', 'irc-case'],
  target: /^\/app\/irc-assignments\/\d+$/,
};

/** J5: the coordinator reaches the intake, board or ranking of the call. */
const CALL_WORK: Work = {
  what: 'call',
  kinds: ['intake', 'board', 'ranking'],
  target: new RegExp(`^/app/calls/${CALL}/(intake|board|ranking)$`),
  names: CALL_TITLE,
};

/** J7: a committee member or the chair reaches the ranking of the call. */
const RANKING: Work = {
  what: 'ranking',
  kinds: ['ranking'],
  target: new RegExp(`^/app/calls/${CALL}/ranking$`),
  names: CALL_TITLE,
};

/** J7: a committee member reaches the open cut-off round. */
const ROUND: Work = {
  what: 'cut_off_round',
  kinds: ['cut-off-round', 'ranking'],
  target: /^\/app\/cut-off-rounds\/\d+$/,
};

/**
 * J1, J3: a programme manager reaches the call board. The seeded
 * programme was activated without the creator, so it has no creator
 * draft, and the home page links no creator or people page for it
 * (review finding U1). The creator journey of a drafted programme is
 * covered by `e2e/creator/`.
 */
const PM_BOARD: Work = {
  what: 'call_board',
  kinds: ['board'],
  target: new RegExp(`^/app/calls/${CALL}/board$`),
  names: CALL_TITLE,
};

/** J0: the first tenant admin reaches the onboarding steps. */
const ONBOARDING: Work = {
  what: 'onboarding',
  kinds: ['onboarding'],
  target: /^\/app\/admin\/onboarding\/[^/]+$/,
};

/** J4: the lead reaches their own proposal. */
function ownProposal(p: { readonly id: string; readonly title: string }): Work {
  return {
    what: 'proposal',
    kinds: ['proposal', 'proposals'],
    target: new RegExp(`^/app/proposals/${p.id}$`),
    names: p.title,
  };
}

/** J4: the guardian of a minor lead reaches the guardian page. */
function guardianPage(p: { readonly id: string; readonly title: string }): Work {
  return {
    what: 'guardian_page',
    kinds: ['guardian', 'proposal'],
    target: new RegExp(`^/app/proposals/${p.id}/guardian$`),
    names: p.title,
  };
}

/** J4: a person with no role reaches an open call. */
const OPEN_CALL: Work = {
  what: 'open_call',
  kinds: ['open-calls'],
  target: /^\/app\/calls\/\d+$/,
};

/** One scene of the demo page and the work of each person it lists. */
interface Scene {
  /** The words of the test name, such as `review_stage1`. */
  readonly name: string;
  /** The scene link on the demo page. */
  readonly href: string;
  /** Every person the scene lists, by key, with the work each one reaches. */
  readonly people: Readonly<Record<string, readonly Work[]>>;
}

/** Who has reviewer and IRC assignments, and whether the call has a ranking or an open round. */
interface Holds {
  readonly reviewers: readonly string[];
  readonly irc: readonly string[];
  readonly ranking: boolean;
  /** No seed holds an open round yet: `irc_review` records its round. */
  readonly openRound: boolean;
}

/** The Judging personas and the programme manager of every review and applicant seed. */
function judging(h: Holds): Record<string, readonly Work[]> {
  const committee = (key: string): Work[] => [
    ...(h.reviewers.includes(key) ? [ASSIGNMENT] : []),
    ...(h.ranking ? [RANKING] : []),
    ...(h.openRound ? [ROUND] : []),
  ];
  return {
    c1: [CALL_WORK],
    r1: committee('r1'),
    r2: committee('r2'),
    r3: committee('r3'),
    r4: committee('r4'),
    h1: [...(h.ranking ? [RANKING] : []), ...(h.openRound ? [ROUND] : [])],
    i1: h.irc.includes('i1') ? [IRC_CASE] : [],
    i2: h.irc.includes('i2') ? [IRC_CASE] : [],
    m1: [PM_BOARD],
  };
}

const NONE: Holds = { reviewers: [], irc: [], ranking: false, openRound: false };
const R12: Holds = { ...NONE, reviewers: ['r1', 'r2'] };
const R12_IRC: Holds = { ...R12, irc: ['i1', 'i2'] };

const review = (stage: string, h: Holds): Scene => ({
  name: `review_${stage}`,
  href: `/demo/review?stage=${stage}`,
  people: judging(h),
});

const applicant = (at: string, h: Holds, extra: Record<string, readonly Work[]>): Scene => ({
  name: `applicant_${at.toLowerCase()}`,
  href: `/demo/applicant?at=${at}`,
  people: { ...judging(h), ...extra },
});

/** The scenes of the demo page (`demo.rs` `REVIEW_STAGES`, `APPLICANT_AT`, reset). */
const SCENES: readonly Scene[] = [
  review('submitted', NONE),
  review('stage1', { ...NONE, reviewers: ['r1', 'r2', 'r3', 'r4'] }),
  review('stage1_scored', { ...NONE, reviewers: ['r1', 'r2', 'r3', 'r4'] }),
  review('stage2', R12),
  // R4 declares a conflict on w in this seed, which releases the
  // assignment (`scenario.rs`, Q16), so R4 has no assignment left.
  review('ranked', { ...NONE, reviewers: ['r1', 'r2'], ranking: true }),
  review('ranked_tie', { ...R12, ranking: true }),
  review('irc_review', R12_IRC),
  applicant('OPEN_CALL', NONE, {}),
  applicant('STAGE2', R12, { 'lead-x': [ownProposal(PROPOSAL.x)] }),
  applicant('IRC_REVIEW_MINOR', R12_IRC, {
    'lead-v': [ownProposal(PROPOSAL.v)],
    guardian: [guardianPage(PROPOSAL.v)],
  }),
  applicant('NEGOTIATION', R12_IRC, { 'lead-x': [ownProposal(PROPOSAL.x)] }),
  applicant('NOT_SELECTED', R12, { 'lead-x': [ownProposal(PROPOSAL.x)] }),
  applicant('DEFERRED_AFTER_CONCERN', R12_IRC, { 'lead-x': [ownProposal(PROPOSAL.x)] }),
  applicant('INELIGIBLE', NONE, { 'lead-x': [ownProposal(PROPOSAL.x)] }),
  { name: 'reset', href: '/demo/reset', people: { a1: [ONBOARDING] } },
];

/** The role words of a person key, for test names. */
function roleOf(key: string): string {
  if (key === 'c1') return 'coordinator';
  if (/^r\d$/.test(key)) return 'committee_member';
  if (key === 'h1') return 'committee_chair';
  if (/^i\d$/.test(key)) return 'irc_member';
  if (/^m\d$/.test(key)) return 'programme_manager';
  if (key.startsWith('lead-')) return 'applicant';
  if (key === 'guardian') return 'guardian';
  return 'tenant_admin';
}

/**
 * The home link kind each role always has, whatever the scene holds:
 * the page the role's work starts from (review finding F3). The open
 * calls, which every person has, never count.
 */
const ROLE_LINK: Readonly<Record<string, WorkKind>> = {
  coordinator: 'intake',
  committee_member: 'assignments',
  committee_chair: 'ranking',
  irc_member: 'irc-cases',
  programme_manager: 'board',
  applicant: 'proposal',
  guardian: 'guardian',
  tenant_admin: 'onboarding',
};

/** The journeys of design section 2.2 a person's work belongs to. */
function journeysOf(key: string): string {
  const role = roleOf(key);
  return (
    {
      coordinator: 'J5',
      committee_member: 'J6, J7',
      committee_chair: 'J7',
      irc_member: 'J8',
      programme_manager: 'J1',
      applicant: 'J4',
      guardian: 'J4',
      tenant_admin: 'J0',
    }[role] ?? 'J0 to J8'
  );
}

/** `nav_<persona>_<scene>_<what>`. */
function testName(scene: Scene, key: string, works: readonly Work[]): string {
  const who = `${roleOf(key)}_${key.replace(/-/g, '_')}`;
  const what = works.length === 0 ? 'lands_on_home' : `reaches_${works.map((w) => w.what).join('_and_')}`;
  return `nav_${who}_${scene.name}_${what}`;
}

// ---------------------------------------------------------------------------
// The scenes
// ---------------------------------------------------------------------------

/**
 * nav_demo_every_scene_is_covered: the demo page offers exactly the
 * scenes this spec walks, so a new scene cannot go untested (J0 to J8).
 */
test('nav_demo_every_scene_is_covered', async ({ browser }) => {
  const demo = await DemoPage.open(browser);
  try {
    const offered = [...new Set(await demo.sceneLinks())].sort();
    expect(offered, 'the scenes of the demo page').toEqual(SCENES.map((s) => s.href).sort());
  } finally {
    await demo.close();
  }
});

for (const scene of SCENES) {
  test.describe(`scene ${scene.name}`, () => {
    let listed: ListedPerson[] = [];

    test.beforeAll(async ({ browser }) => {
      test.setTimeout(180_000);
      const demo = await DemoPage.open(browser);
      try {
        await demo.chooseScene(scene.href);
        listed = await demo.people();
      } finally {
        await demo.close();
      }
    });

    /**
     * nav_demo_<scene>_lists_every_person_a_test_covers: the scene lists
     * exactly the people below, so nobody it lists goes untested (J0 to
     * J8).
     */
    test(`nav_demo_${scene.name}_lists_every_person_a_test_covers`, () => {
      const keys = listed.map((p) => classify(p)?.key ?? `unknown: ${p.label} ${p.email}`).sort();
      expect(keys, `the people of scene ${scene.name}`).toEqual(Object.keys(scene.people).sort());
    });

    for (const [key, works] of Object.entries(scene.people)) {
      /**
       * One person of the scene signs in from the demo page and reaches
       * each piece of their work by clicking (design section 2.2, the
       * journey named in the step labels). A person whose role has no
       * work in this scene still lands on a home page that offers the
       * role's pages, never on a not-found page. The home page passes
       * the R-NF-03 structure checks of design section 8.7.
       */
      test(testName(scene, key, works), async ({ browser }) => {
        const who = `${key} in ${scene.name} (${journeysOf(key)})`;
        const p = await newPerson(browser);
        try {
          await enrolFromLink(p, personOf(listed, key, scene.name).link);
          await expectHome(p, who);
          await expectStructure(p.page, `${who}: ${HOME}`);
          await expect(p.page.locator(NAV_UI.noRole), `${who}: a role holder is not told they have none`).toHaveCount(0);
          await expect(
            p.page.locator(`${NAV_UI.work} a[data-work]:not([data-work="open-calls"])`).first(),
            `${who}: the home page names the person's work, beyond the open calls`,
          ).toBeVisible();
          const own = ROLE_LINK[roleOf(key)];
          expect(own, `${who}: the role has a home link kind`).toBeDefined();
          await expect(
            p.page.locator(NAV_UI.workLink(own ?? 'open-calls')).first(),
            `${who}: the home page offers the role's own page (${own ?? 'none'})`,
          ).toBeVisible();
          for (const w of works) {
            await reach(p, w, who);
          }
          await accountRoundTrip(p, who);
        } finally {
          await p.context.close();
        }
      });
    }
  });
}

// ---------------------------------------------------------------------------
// A person with no role, and a returning person
// ---------------------------------------------------------------------------

test.describe('a person with no role', () => {
  /**
   * nav_no_role_home_says_so_and_offers_open_calls: a person who signs
   * up during an open call has no role. The home page says so and links
   * to the open calls, and never shows a not-found page (J4, account
   * creation).
   */
  test('nav_no_role_home_says_so_and_offers_open_calls', async ({ browser }) => {
    test.setTimeout(180_000);
    const demo = await DemoPage.open(browser);
    const p = await newPerson(browser);
    try {
      await demo.chooseScene('/demo/applicant?at=OPEN_CALL');
      const email = syntheticEmail('nav-norole');
      // The demo page names the sign-up address as text for a person to type.
      await p.page.goto(`${p.origin}/auth/signup`);
      await p.page.locator(UI.signup.email).fill(email);
      await p.page.locator(UI.signup.submit).click();
      await expect(p.page.locator(UI.signup.status)).toBeVisible();
      await demo.reload();
      const proof = (await demo.messages()).find((m) => m.to === email);
      expect(proof, `the demo page lists the sign-up proof sent to ${email}`).toBeDefined();
      await p.page.goto(proof?.link ?? '');
      await p.page.locator(UI.signup.register).click();
      const who = 'a person with no role (J4)';
      await expectHome(p, who);
      await expectStructure(p.page, `${who}: ${HOME}`);
      await expect(p.page.locator(NAV_UI.noRole), `${who}: the home page says the person has no role`).toBeVisible();
      await expect(p.page.locator(NAV_UI.noRole)).not.toHaveText('');
      await reach(p, OPEN_CALL, who);
      await accountRoundTrip(p, who);
    } finally {
      await p.context.close();
      await demo.close();
    }
  });
});

test.describe('a returning person', () => {
  /**
   * nav_committee_member_r1_passkey_login_lands_on_home: a person who
   * signs in again with their passkey on `/auth/login`, the link the demo
   * page gives signed-in people, lands on the home page (J6).
   */
  test('nav_committee_member_r1_passkey_login_lands_on_home', async ({ browser }) => {
    test.setTimeout(180_000);
    const demo = await DemoPage.open(browser);
    const p = await newPerson(browser);
    try {
      await demo.chooseScene('/demo/review?stage=stage1');
      await enrolFromLink(p, personOf(await demo.people(), 'r1', 'review_stage1').link);
      // Signed in on whichever page the enrolment ends on; this test checks the second sign-in.
      await expect(p.page).toHaveURL((u) => u.origin === p.origin && !u.pathname.startsWith('/auth/invite'));
      await settle(p.page);
      await p.context.clearCookies();
      await p.page.goto(`${p.origin}/auth/login`);
      await p.page.locator(UI.login.passkey).click();
      const who = 'r1 signing in again (J6)';
      await expectHome(p, who);
      await expectNav(p, `${who}, ${HOME}`);
      await reach(p, ASSIGNMENT, who);
    } finally {
      await p.context.close();
      await demo.close();
    }
  });

  /**
   * nav_committee_member_r2_typed_home_address_shows_home: a signed-in
   * person who types the address `/app/` sees the home page with their
   * work, never "Page not found". This test checks the home page apart
   * from the landing after sign-in, so it types the address (J6).
   */
  test('nav_committee_member_r2_typed_home_address_shows_home', async ({ browser }) => {
    test.setTimeout(180_000);
    const demo = await DemoPage.open(browser);
    const p = await newPerson(browser);
    try {
      await demo.chooseScene('/demo/review?stage=stage1');
      await enrolFromLink(p, personOf(await demo.people(), 'r2', 'review_stage1').link);
      await expect(p.page).toHaveURL((u) => u.origin === p.origin && !u.pathname.startsWith('/auth/invite'));
      await settle(p.page);
      await p.page.goto(`${p.origin}${HOME}`);
      const who = 'r2 typing /app/ (J6)';
      await expectHome(p, who);
      await expectNav(p, `${who}, ${HOME}`);
      await reach(p, ASSIGNMENT, who);
    } finally {
      await p.context.close();
      await demo.close();
    }
  });
});
