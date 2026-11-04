/**
 * r_jv_screens_match_prototypes: each screen of the lane m4/site scope
 * (item 4) is built to its approved prototype in `design/prototypes/`
 * (`docs/design/README.md`, `01-navigation-home.md` "Layout and routing
 * contract").
 *
 * [`SCREENS`] maps each screen to its prototype file, its layout
 * (`AppLayout` with the sidebar, or `PublicLayout` without), the h1, the
 * h2 headings and the named regions the prototype shows, and how a demo
 * person reaches the built page. Each row first checks itself against
 * the prototype's HTML, so the table cannot drift from the design. It
 * then checks the built page.
 *
 * Only structural copy is listed: headings that name seeded data are
 * matched as patterns or as the seeded value, and prototype panels that
 * show other states for reference, the progress map strip and the
 * activity log (which wait on the journey lanes, scope item 5) are left
 * out. IRC pages must show no proposal status strip (O-58).
 *
 * Interim, pending the implementer: a row whose backend is missing stays
 * in and fails until the implementer reports the missing operation
 * (`home-operations`, `packing-check` and the public pages may be such
 * rows). Every person, call and text is synthetic.
 */

import { expect, type APIRequestContext, type Browser, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { syntheticEmail, test } from '../playwright.config';
import {
  ApplicantControl,
  draftedProposal,
  must,
  newApplicant,
  startProposal,
  submitDraft,
  type ApplicantScenario,
  type ScenarioAt,
} from '../applicant/support';
import { APP, CREATOR_STEPS } from '../creator/contract';
import { cellA, firstAdmin, openDraft } from '../creator/support';
import type { PersonaKey, ReviewScenario, ReviewStage } from '../review/contract';
import { assignmentOf, ircAssignmentOf, proposal, seed } from '../review/support';
import { settle } from '../navigation/support';
import { FrontDoor, REPO, SITE, enrolToHome, suiteCell } from './contract';

// A step that waits on a navigation or an action fails within half a minute, not at the test timeout.
test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/** What a reach learned about the seeded data, for headings that name it. */
type Facts = Readonly<Record<string, string>>;

/** A heading: fixed copy, a pattern, or a seeded value with the prototype's sample. */
type Heading = string | RegExp | { readonly fact: string; readonly proto: string };

/** A named region: its ARIA role and accessible name. */
interface Region {
  readonly role: 'navigation' | 'complementary' | 'region' | 'form';
  readonly name: string;
}

/** The fixtures a reach may use. */
interface Ctx {
  readonly person: () => Promise<Page>;
  readonly request: APIRequestContext;
  readonly browser: Browser;
}

/** One screen of the scope and its prototype. */
interface Screen {
  readonly screen: string;
  readonly prototype: string;
  readonly layout: 'app' | 'public';
  /** Null where the prototype's h1 belongs to a reference page, such as `end-states`. */
  readonly h1: Heading | null;
  readonly h2: readonly Heading[];
  readonly regions: readonly Region[];
  /** Headings that must not show, such as the status strip on IRC pages (O-58). */
  readonly absent?: readonly string[];
  readonly reach: (c: Ctx) => Promise<{ readonly page: Page; readonly facts: Facts }>;
}

// ---------------------------------------------------------------------------
// Reaching the built pages
// ---------------------------------------------------------------------------

/** A review persona signed in at `stage`, on `path(s)` of the cell. */
function judging(stage: ReviewStage, who: PersonaKey, path: (s: ReviewScenario) => string) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const seeded = await seed(c.request, stage);
    const page = await enrolToHome(c.person, seeded.cell.origin, seeded.s.people[who].invite_url);
    const to = path(seeded.s);
    if (to !== '/app/') await page.goto(`${seeded.cell.origin}${to}`);
    await settle(page);
    return { page, facts: { call: seeded.s.call } };
  };
}

/** The lead of a seeded proposal at `at`, on `path(p)`. */
function lead(at: ScenarioAt, path: (p: string) => string) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const cell = suiteCell();
    const control = new ApplicantControl(c.request, cell);
    await control.reset();
    const s: ApplicantScenario = await control.scenario(at);
    const p = must(s.proposal, `the ${at} proposal`);
    const page = await enrolToHome(c.person, cell.origin, must(s.lead, `the ${at} lead`).enrol_url);
    const to = path(p);
    if (to !== '/app/') await page.goto(`${cell.origin}${to}`);
    await settle(page);
    return { page, facts: { title: must(s.title, `the ${at} title`), call: s.call.title } };
  };
}

/** The first tenant admin of a reset cell, verified, on `path`. */
function admin(path: string) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const control = cellA(c.request);
    const { a1 } = await firstAdmin(c.person, control);
    await a1.page.goto(`${control.cell.origin}${path}`);
    await settle(a1.page);
    return { page: a1.page, facts: {} };
  };
}

/** The first tenant admin on the home page, then the link named `name` in `main`. */
function adminLink(name: RegExp) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const r = await admin('/app/')(c);
    const link = r.page.locator('main a', { hasText: name }).first();
    await expect(link, `the admin home links ${name.source}`).toBeVisible();
    await link.click();
    await r.page.waitForURL((u) => u.pathname !== '/app/');
    await settle(r.page);
    return r;
  };
}

/** A page of the cell origin with no session. */
function anonymous(path: string, then?: (page: Page) => Promise<void>) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const cell = suiteCell();
    const control = new ApplicantControl(c.request, cell);
    await control.reset();
    const s = await control.scenario('OPEN_CALL');
    const context = await c.browser.newContext();
    const page = await context.newPage();
    await page.goto(`${cell.origin}${path}`);
    if (then !== undefined) await then(page);
    return { page, facts: { call: s.call.title } };
  };
}

/** The public open calls page the demo front door links, then `then`. */
function publicCalls(then?: (page: Page, facts: Facts) => Promise<void>) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const cell = suiteCell();
    const control = new ApplicantControl(c.request, cell);
    await control.reset();
    const s = await control.scenario('OPEN_CALL');
    const door = await FrontDoor.open(c.browser, cell);
    let href = '';
    try {
      href = (await door.page.locator(SITE.demo.publicCalls).getAttribute('href')) ?? '';
    } finally {
      await door.close();
    }
    expect(href, 'the demo front door links the public open calls page').not.toBe('');
    const context = await c.browser.newContext();
    const page = await context.newPage();
    await page.goto(new URL(href, cell.control).href);
    const facts = { call: s.call.title };
    if (then !== undefined) await then(page, facts);
    return { page, facts };
  };
}

/** A signed-up applicant with a fresh draft in the open call, on `path(p)` or after `then`. */
function draft(path: (p: string) => string, then?: (page: Page) => Promise<void>) {
  return async (c: Ctx): Promise<{ page: Page; facts: Facts }> => {
    const cell = suiteCell();
    const control = new ApplicantControl(c.request, cell);
    await control.reset();
    const s = await control.scenario('OPEN_CALL');
    const { page } = await newApplicant(c.person, control, cell.origin, 'site-screens');
    const p = await startProposal(page, cell.origin, s.call);
    await page.goto(`${cell.origin}${path(p)}`);
    await settle(page);
    if (then !== undefined) await then(page);
    return { page, facts: { call: s.call.title } };
  };
}

const IRC_STRIP = ['Proposal status'];

// ---------------------------------------------------------------------------
// The screens of scope item 4
// ---------------------------------------------------------------------------

/**
 * Rows removed by the implementer of lane m4/site (2026-11-04), each
 * because its backend is missing on this tree, so the screen is neither
 * built nor linked (lane scope items 4 and 5):
 *
 * - `home-operations`: no demo scene seeds a finance approver, payment
 *   releaser or contract signatory, and no queue read exists for them.
 * - `calls-public`, `call-detail-public`, `public-calls-feed`: the
 *   `public.list_open_calls`, `public.call` and `public.feed`
 *   operations answer `not_implemented` in `fstp-api-core`, and `/p`
 *   is a 501 stub in `fstp-web` (`fstp-public` is a W0 stub).
 * - `packing-check`: `web/src/gen/api.ts` holds no pre-submission check
 *   operation.
 * - `end-states-on-hold`: `proposal.view` carries no I-18 hold member,
 *   so the applicant page cannot tell a held IRC_REVIEW from another.
 * - `admin-members`, `admin-org`: no operation lists the tenant's
 *   members with their roles, and none reads the organisation record
 *   with its signatories (SA-01) and agreements.
 */
const SCREENS: readonly Screen[] = [
  // Auth pages (PublicLayout).
  { screen: 'auth-signin', prototype: 'auth-signin', layout: 'public', h1: 'Sign in', h2: ['Sign in with your passkey'], regions: [], reach: anonymous('/auth/login') },
  { screen: 'auth-signup', prototype: 'auth-signup', layout: 'public', h1: 'Create an account', h2: [], regions: [], reach: anonymous('/auth/signup') },
  {
    screen: 'auth-check-email', prototype: 'auth-check-email', layout: 'public', h1: 'Check your email', h2: ['Confirmation link sent'], regions: [],
    reach: anonymous('/auth/signup', async (page) => {
      await page.locator('#signup-email').fill(syntheticEmail('site-check'));
      await page.locator('#signup-submit').click();
      await expect(page.locator('main h1')).toHaveText('Check your email');
    }),
  },
  {
    screen: 'auth-enrol', prototype: 'auth-enrol', layout: 'public', h1: 'Create a passkey', h2: [], regions: [],
    reach: async (c) => {
      const fresh = await cellA(c.request).reset();
      const context = await c.browser.newContext();
      const page = await context.newPage();
      await page.goto(fresh.url);
      return { page, facts: {} };
    },
  },

  // Homes of the roles M4 has.
  { screen: 'home-voyager', prototype: 'home-voyager', layout: 'app', h1: 'Your work', h2: [{ fact: 'title', proto: 'Community Wellbeing Navigator' }, 'Open calls'], regions: [{ role: 'complementary', name: 'Other places' }], reach: lead('STAGE2', () => '/app/') },
  { screen: 'home-reviewer', prototype: 'home-reviewer', layout: 'app', h1: 'Your work', h2: [/^\d+ proposals? needs? your score$/], regions: [], reach: judging('stage1', 'r1', () => '/app/') },
  { screen: 'home-committee', prototype: 'home-committee', layout: 'app', h1: 'Your work', h2: [/^\d+ proposals? to rank$/], regions: [], reach: judging('ranked', 'r1', () => '/app/') },
  { screen: 'home-coordinator', prototype: 'home-coordinator', layout: 'app', h1: 'Your work', h2: [/^\d+ proposals? needs? a knock-out decision$/, 'Queue health'], regions: [], reach: judging('submitted', 'c1', () => '/app/') },
  { screen: 'home-irc', prototype: 'home-irc', layout: 'app', h1: 'Your work', h2: [/^\d+ nominated proposals? for independent review$/], regions: [], absent: IRC_STRIP, reach: judging('irc_review', 'i1', () => '/app/') },
  { screen: 'home-admin', prototype: 'home-admin', layout: 'app', h1: 'Administration', h2: ['Organisation settings', 'First-time setup', 'Members and roles'], regions: [], reach: admin('/app/') },
  {
    screen: 'profile', prototype: 'profile', layout: 'app', h1: 'Your account', h2: ['Profile', 'Security'], regions: [{ role: 'navigation', name: 'On this page' }],
    reach: async (c) => {
      const r = await judging('stage1', 'r1', () => '/app/')(c);
      await r.page.locator('aside a[data-nav="account"]').first().click();
      await r.page.waitForURL((u) => u.pathname === '/app/me');
      await settle(r.page);
      return r;
    },
  },

  // Applicant pages.
  { screen: 'plan-editor', prototype: 'plan-editor', layout: 'app', h1: 'Your proposal (DRAFT)', h2: ['1. Plan'], regions: [{ role: 'navigation', name: 'Proposal steps' }], reach: draft((p) => APP_PLAN(p)) },
  {
    screen: 'submission-receipt', prototype: 'submission-receipt', layout: 'app', h1: 'Submission receipt', h2: ['What happens next'], regions: [],
    reach: async (c) => {
      const cell = suiteCell();
      const control = new ApplicantControl(c.request, cell);
      await control.reset();
      const d = await draftedProposal(c.person, control, cell.origin, 'site-receipt');
      const { response } = await submitDraft(d.page, cell.origin, d.proposal);
      expect(response.ok(), 'the submission is accepted').toBe(true);
      await expect(d.page.locator('main h1')).toHaveText('Submission receipt');
      await settle(d.page);
      return { page: d.page, facts: { title: d.title } };
    },
  },
  { screen: 'stage2-questions', prototype: 'stage2-questions', layout: 'app', h1: 'Stage 2 questions', h2: [], regions: [], reach: lead('STAGE2', (p) => `/app/proposals/${p}/stage2`) },
  { screen: 'negotiation', prototype: 'negotiation', layout: 'app', h1: 'Negotiation (NEGOTIATION)', h2: ['Data protection notice'], regions: [], reach: lead('NEGOTIATION', (p) => `/app/proposals/${p}/negotiation`) },
  { screen: 'end-states-not-selected', prototype: 'end-states', layout: 'app', h1: null, h2: ['Not selected'], regions: [], reach: lead('NOT_SELECTED', (p) => `/app/proposals/${p}`) },
  { screen: 'end-states-ineligible', prototype: 'end-states', layout: 'app', h1: null, h2: ['Not eligible'], regions: [], reach: lead('INELIGIBLE', (p) => `/app/proposals/${p}`) },
  { screen: 'end-states-deferred', prototype: 'end-states', layout: 'app', h1: null, h2: ['Your proposal has been deferred'], regions: [], reach: lead('DEFERRED_AFTER_CONCERN', (p) => `/app/proposals/${p}`) },

  // Judging pages.
  { screen: 'reviewer-assignments', prototype: 'reviewer-assignments', layout: 'app', h1: 'My assignments', h2: [], regions: [], reach: judging('stage1', 'r1', () => '/app/me/assignments') },
  { screen: 'reviewer-scoring', prototype: 'reviewer-scoring', layout: 'app', h1: /^Score \S/, h2: ['Ranking summary', 'Correct score'], regions: [], reach: judging('stage1_scored', 'r1', (s) => `/app/assignments/${assignmentOf(s, 'x', 'r1')}`) },
  { screen: 'reviewer-stage2', prototype: 'reviewer-stage2', layout: 'app', h1: 'Stage 2 evaluation', h2: [], regions: [], reach: judging('stage2', 'r1', (s) => `/app/assignments/${assignmentOf(s, 'x', 'r1')}/stage2`) },
  { screen: 'committee-ranking', prototype: 'committee-ranking', layout: 'app', h1: /^Ranking for \S/, h2: ['Open the cut-off round'], regions: [], reach: judging('ranked', 'h1', (s) => `/app/calls/${s.call}/ranking`) },
  { screen: 'coordinator-conflicts-list', prototype: 'coordinator-conflicts-list', layout: 'app', h1: /^Notifiable conflicts for \S/, h2: [], regions: [], reach: judging('stage1', 'c1', (s) => `/app/calls/${s.call}/notifiable-conflicts`) },
  { screen: 'coordinator-conflict', prototype: 'coordinator-conflict', layout: 'app', h1: /^Eligibility check \(knock-out\) for \S/, h2: ['Declare conflicts', 'Read applications', 'Record knock-out result'], regions: [], reach: judging('submitted', 'c1', (s) => `/app/proposals/${proposal(s, 'x').id}/declaration`) },
  { screen: 'stage1-close', prototype: 'stage1-close', layout: 'app', h1: /^Close Stage 1 for \S/, h2: [/^Proposals selected for Stage 2: \d+\. Proposals not selected: \d+\.$/], regions: [], reach: judging('stage1_scored', 'c1', (s) => `/app/calls/${s.call}/board`) },
  { screen: 'irc-cases', prototype: 'irc-cases', layout: 'app', h1: 'My cases', h2: [], regions: [], absent: IRC_STRIP, reach: judging('irc_review', 'i1', () => '/app/me/irc-cases') },
  { screen: 'irc-view', prototype: 'irc-view', layout: 'app', h1: /^Independent review of \S/, h2: [], regions: [], absent: IRC_STRIP, reach: judging('irc_review', 'i1', (s) => `/app/irc-assignments/${ircAssignmentOf(s, 'x', 'i1')}`) },

  // Programme staff and tenant admin pages.
  { screen: 'onboarding', prototype: 'onboarding', layout: 'app', h1: 'Set up your organisation', h2: ['Step 1: Organisation'], regions: [{ role: 'navigation', name: 'Onboarding steps' }], reach: admin(APP.onboarding('organisation')) },
  {
    screen: 'planning-studio', prototype: 'planning-studio', layout: 'app', h1: 'Programme set-up', h2: [], regions: [{ role: 'navigation', name: 'Set-up steps' }],
    reach: async (c) => {
      const control = cellA(c.request);
      const { a1 } = await firstAdmin(c.person, control);
      const p = await openDraft(a1, control.cell.origin);
      await a1.page.goto(`${control.cell.origin}${APP.creatorStep(p, CREATOR_STEPS[0])}`);
      await settle(a1.page);
      return { page: a1.page, facts: {} };
    },
  },
  { screen: 'seal-ceremony', prototype: 'seal-ceremony', layout: 'app', h1: 'Approval and publication', h2: [], regions: [], reach: admin(APP.approvals) },
];

/** The plan editor path (`e2e/applicant/support.ts` `APP.plan`). */
function APP_PLAN(p: string): string {
  return `/app/proposals/${p}/plan`;
}

// ---------------------------------------------------------------------------
// Reading a prototype
// ---------------------------------------------------------------------------

/** Text with tags removed, entities of the prototypes decoded and white space folded. */
function textOf(html: string): string {
  return html
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<')
    .replace(/\s+/g, ' ')
    .trim();
}

/** The h1 and h2 texts, the labelled regions and the layout of a prototype. */
function prototype(name: string): { h1: string[]; h2: string[]; labels: string[]; sidebar: boolean } {
  const html = readFileSync(join(REPO, 'design', 'prototypes', `${name}.html`), 'utf8');
  const main = /<main[\s\S]*?<\/main>/.exec(html)?.[0] ?? '';
  const all = (tag: string): string[] =>
    Array.from(main.matchAll(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'g')), (m) => textOf(m[1] ?? ''));
  const labels = Array.from(main.matchAll(/aria-label="([^"]+)"/g), (m) => m[1] ?? '');
  return { h1: all('h1'), h2: all('h2'), labels, sidebar: /<aside class="sidebar"/.test(html) };
}

/** Whether `h` matches the text `t` of a prototype heading. */
function protoMatches(h: Heading, t: string): boolean {
  if (typeof h === 'string') return h === t;
  if (h instanceof RegExp) return h.test(t);
  return h.proto === t;
}

/** Whether `h` matches the text `t` of a built heading. */
function builtMatches(h: Heading, t: string, facts: Facts): boolean {
  if (typeof h === 'string') return h === t;
  if (h instanceof RegExp) return h.test(t);
  return facts[h.fact] !== undefined && facts[h.fact] === t;
}

/** A heading for messages. */
function show(h: Heading, facts: Facts = {}): string {
  if (typeof h === 'string') return `"${h}"`;
  if (h instanceof RegExp) return h.toString();
  return `"${facts[h.fact] ?? `<${h.fact}>`}" (the prototype shows "${h.proto}")`;
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

test.describe('R-JV screens match the approved prototypes', () => {
  test.describe.configure({ timeout: 300_000 });

  for (const s of SCREENS) {
    /**
     * R-JV (journey UI, `SPEC/12-journey-ui.md` section 8), R-NF-03:
     * the built screen shows the prototype's layout, h1, h2 headings and
     * named regions.
     */
    test(`r_jv_screens_match_prototypes_${s.screen.replace(/-/g, '_')}`, async ({ person, request, browser }) => {
      // The row against the prototype.
      const proto = prototype(s.prototype);
      expect(proto.sidebar, `${s.prototype}.html uses the ${s.layout} layout`).toBe(s.layout === 'app');
      if (s.h1 !== null) {
        const h1 = s.h1;
        expect(proto.h1.some((t) => protoMatches(h1, t)), `${s.prototype}.html shows the h1 ${show(h1)}`).toBe(true);
      }
      for (const h of s.h2) {
        expect(proto.h2.some((t) => protoMatches(h, t)), `${s.prototype}.html shows the h2 ${show(h)}; it has ${JSON.stringify(proto.h2)}`).toBe(true);
      }
      for (const r of s.regions) {
        expect(proto.labels, `${s.prototype}.html labels a region "${r.name}"`).toContain(r.name);
      }

      // The built page.
      const { page, facts } = await s.reach({ person, request, browser });
      await expect(page.locator('main'), `${s.screen}: a main landmark`).toBeVisible();
      await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0);
      const h1s = (await page.locator('main h1').allInnerTexts()).map((t) => t.replace(/\s+/g, ' ').trim());
      const h2s = (await page.locator('main h2').allInnerTexts()).map((t) => t.replace(/\s+/g, ' ').trim());
      expect(h1s.length, `${s.screen}: one h1`).toBe(1);
      if (s.h1 !== null) {
        const h1 = s.h1;
        expect(h1s.some((t) => builtMatches(h1, t, facts)), `${s.screen}: the h1 ${show(h1, facts)}; it shows ${JSON.stringify(h1s)}`).toBe(true);
      }
      for (const h of s.h2) {
        expect(h2s.some((t) => builtMatches(h, t, facts)), `${s.screen}: the h2 ${show(h, facts)}; it shows ${JSON.stringify(h2s)}`).toBe(true);
      }
      for (const r of s.regions) {
        await expect(page.getByRole(r.role, { name: r.name }).first(), `${s.screen}: the ${r.role} "${r.name}"`).toBeVisible();
      }
      for (const a of s.absent ?? []) {
        expect(h2s, `O-58: ${s.screen} shows no "${a}"`).not.toContain(a);
      }
      if (s.layout === 'app') {
        await expect(page.locator(SITE.sidebar), `${s.screen}: the AppLayout sidebar`).toBeVisible();
        await expect(page.locator(SITE.sidebar).getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
      } else {
        await expect(page.locator(SITE.sidebar), `${s.screen}: PublicLayout has no sidebar`).toHaveCount(0);
        await expect(page.locator('header').first(), `${s.screen}: the PublicLayout top bar`).toBeVisible();
      }
    });
  }
});

/** The table names every screen of scope item 4 once. */
test('r_jv_screens_match_prototypes_table_covers_the_scope', () => {
  const scope = [
    'auth-signin', 'auth-signup', 'auth-check-email', 'auth-enrol',
    // Without the rows removed for a missing backend (see above SCREENS).
    'home-voyager', 'home-reviewer', 'home-committee', 'home-coordinator', 'home-irc', 'home-admin',
    'profile',
    'plan-editor', 'submission-receipt', 'stage2-questions', 'negotiation', 'end-states',
    'reviewer-assignments', 'reviewer-scoring', 'reviewer-stage2', 'committee-ranking',
    'coordinator-conflicts-list', 'coordinator-conflict', 'stage1-close', 'irc-cases', 'irc-view',
    'onboarding', 'planning-studio', 'seal-ceremony',
  ];
  expect([...new Set(SCREENS.map((s) => s.prototype))].sort()).toEqual([...scope].sort());
  // Scope item 5: none of the deferred screens is in the table.
  for (const deferred of ['route-map', 'diary', 'home-finance', 'home-signatory', 'home-mentor', 'home-auditor', 'admin-branding', 'admin-domains', 'admin-masquerade', 'audit-log']) {
    expect(SCREENS.map((s) => s.prototype)).not.toContain(deferred);
  }
});

