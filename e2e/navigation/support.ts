/**
 * The contract and helpers of the click-through spec
 * (`click_through.spec.ts`): every person reaches their work by clicking.
 *
 * This file is not a spec. Playwright collects `*.spec.ts` files only.
 *
 * Daniel, 2026-10-31: "the demo is useless. I don't do anything except
 * register a passkey; the only route that works is auth". Every sign-in
 * flow ended on `/auth/account`, `/app/` answered "Page not found", and
 * the shell only offered the applicant's navigation. The journey specs
 * passed because they open deep paths directly.
 *
 * # Page contract
 *
 * Interim, pending Daniel: design section 2.2 names no home page and no
 * landing after sign-in other than the account page. These paths and
 * ids are the test author's reading of journeys J0 to J8. A page may add
 * elements, but each id here keeps its role.
 *
 * - Every sign-in and enrolment ends on the home page [`HOME`], `/app/`.
 * - The home page holds `#home` in its `main`. It lists the person's work
 *   in `#home-work`: one `li` per piece of work, each with one link
 *   `a[data-work="<kind>"]` (see [`WorkKind`]). The item names the work,
 *   such as the call or the proposal title.
 * - A person with no role sees `#home-no-role`, a text that says so, and
 *   a link `a[data-work="open-calls"]` to the open calls. A person with a
 *   role never sees `#home-no-role`.
 * - Every `/app/` page has a `nav` with a link `a[data-nav="home"]` to
 *   `/app/` and a link `a[data-nav="account"]` to `/auth/account`. The
 *   account page has a `nav` with a link `a[data-nav="home"]`.
 *   Since the approved sidebar layout (`docs/design/01-navigation-home.md`,
 *   2026-11-01), both links sit in the sidebar `nav`, with every page the
 *   person may open without an id between them.
 *
 * # Demo contract
 *
 * The specs drive the demo page on the control base (`GET /demo`,
 * `fstp-e2e-cell` `demo.rs`) as a person does: they click a scene link,
 * then read the people the page lists under "People of this scene". Each
 * person's link is opened in a new browser context with its own virtual
 * authenticator. Interim, pending Daniel: each review and applicant
 * scene lists a programme manager labelled `Programme manager M1`.
 *
 * Every person, proposal and text is synthetic.
 */

import { expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { PAGES, StackMissing, UI, VirtualAuthenticator, stack, type CellEndpoints } from '../playwright.config';

// ---------------------------------------------------------------------------
// Paths and ids
// ---------------------------------------------------------------------------

/** The home page on the cell origin. */
export const HOME = '/app/';

/** The account page of M3 (`web/src/auth/pages/account.ts`). */
export const ACCOUNT = PAGES.account;

/**
 * The kinds of work a home page links to. Each names the page the link
 * opens, or the list a person picks the page from.
 */
export type WorkKind =
  /** `/app/me/assignments`, the reviewer's assignments (J6). */
  | 'assignments'
  /** `/app/assignments/{a}`, one assignment (J6). */
  | 'assignment'
  /** `/app/me/irc-cases`, the IRC member's cases (J8). */
  | 'irc-cases'
  /** `/app/irc-assignments/{a}`, one IRC case (J8). */
  | 'irc-case'
  /** `/app/calls/{c}/intake` (J5). */
  | 'intake'
  /** `/app/calls/{c}/board` (J5). */
  | 'board'
  /** `/app/calls/{c}/ranking` (J7). */
  | 'ranking'
  /** `/app/cut-off-rounds/{r}`, an open round (J7). */
  | 'cut-off-round'
  /** `/app/proposals`, the applicant's proposals (J4). */
  | 'proposals'
  /** `/app/proposals/{x}`, one own proposal (J4). */
  | 'proposal'
  /** `/app/proposals/{x}/guardian`, the guardian page (J4). */
  | 'guardian'
  /** `/app/admin/onboarding/{step}` (J0). */
  | 'onboarding'
  /** `/app/creator/new` or `/app/programmes/{p}/creator/{step}` (J1). */
  | 'creator'
  /** `/app/calls`, the open calls (J4). */
  | 'open-calls';

/** The element ids and attributes of the contract above. */
export const NAV_UI = {
  home: '#home',
  work: '#home-work',
  workItem: '#home-work li',
  workLink: (kind: WorkKind): string => `#home-work a[data-work="${kind}"]`,
  noRole: '#home-no-role',
  navHome: 'nav a[data-nav="home"]',
  navAccount: 'nav a[data-nav="account"]',
} as const;

/** The title the not-found page shows (`web/src/applicant/messages.en.ts`). */
const NOT_FOUND_TITLE = 'Page not found';

// ---------------------------------------------------------------------------
// The demo page
// ---------------------------------------------------------------------------

/** One person the demo page lists: the link text, the email and the sign-in link. */
export interface ListedPerson {
  readonly label: string;
  readonly email: string;
  readonly link: string;
}

/** One message the demo page lists: its kind, its recipient and its link. */
export interface ListedMessage {
  readonly kind: string;
  readonly to: string;
  readonly link: string;
}

/** The demo page of cell `a`, open in a browser context of its own. */
export class DemoPage {
  private constructor(
    readonly context: BrowserContext,
    readonly page: Page,
    readonly cell: CellEndpoints,
  ) {}

  /** Opens `GET /demo` on the control base of cell `a`. */
  static async open(browser: Browser): Promise<DemoPage> {
    const cell = stack().cells.a;
    const context = await browser.newContext();
    const page = await context.newPage();
    const r = await page.goto(`${cell.control}/demo`);
    if (r === null || !r.ok()) {
      throw new StackMissing(`the demo page ${cell.control}/demo answered ${r?.status() ?? 'nothing'}`);
    }
    return new DemoPage(context, page, cell);
  }

  /** The scene links the page offers, as their `href` attributes. */
  async sceneLinks(): Promise<string[]> {
    return this.page
      .locator('a[href^="/demo/review?"], a[href^="/demo/applicant?"], a[href="/demo/reset"]')
      .evaluateAll((as) => as.map((a) => a.getAttribute('href') ?? ''));
  }

  /**
   * Clicks the scene link `href`, as a person does, and waits until the
   * cell has seeded it and the demo page shows again.
   */
  async chooseScene(href: string): Promise<void> {
    const link = this.page.locator(`a[href="${href}"]`);
    await expect(link, `the demo page offers the scene ${href}`).toBeVisible();
    const back = this.page.waitForEvent('framenavigated', {
      predicate: (f) => f === this.page.mainFrame() && new URL(f.url()).pathname === '/demo',
      timeout: 120_000,
    });
    await link.click();
    await back;
    await this.page.waitForLoadState('load');
    await expect(this.page.locator('h1')).toContainText('FSTP demo');
  }

  /** Reloads the page, for new messages. */
  async reload(): Promise<void> {
    await this.page.goto(`${this.cell.control}/demo`);
  }

  /** The people the page lists under "People of this scene", with their unused links. */
  async people(): Promise<ListedPerson[]> {
    return this.page.evaluate(() => {
      const h2 = Array.from(document.querySelectorAll('h2')).find((e) =>
        (e.textContent ?? '').startsWith('People of this scene'),
      );
      const ul = h2?.nextElementSibling;
      if (ul === null || ul === undefined || ul.tagName !== 'UL') return [];
      return Array.from(ul.querySelectorAll('li')).flatMap((li) => {
        const a = li.querySelector('a');
        const small = li.querySelector('small');
        if (a === null || small === null) return [];
        return [{ label: (a.textContent ?? '').trim(), email: (small.textContent ?? '').trim(), link: a.href }];
      });
    });
  }

  /** The messages the page lists under "Messages the cell sent", newest first. */
  async messages(): Promise<ListedMessage[]> {
    return this.page.evaluate(() => {
      const h2 = Array.from(document.querySelectorAll('h2')).find((e) =>
        (e.textContent ?? '').startsWith('Messages the cell sent'),
      );
      let el = h2?.nextElementSibling ?? null;
      while (el !== null && el.tagName !== 'UL') el = el.nextElementSibling;
      if (el === null) return [];
      return Array.from(el.querySelectorAll('li')).flatMap((li) => {
        const a = li.querySelector('a');
        const m = /^(\S+) to (\S+):/.exec((li.textContent ?? '').trim());
        if (a === null || m === null) return [];
        return [{ kind: m[1] ?? '', to: m[2] ?? '', link: a.href }];
      });
    });
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}

// ---------------------------------------------------------------------------
// People of a scene
// ---------------------------------------------------------------------------

/** Which person of the demo a listed entry is, by its label or email. */
export interface Who {
  /** A stable key, such as `r1`, `lead-x`, `guardian` or `a1`. */
  readonly key: string;
  /** The role word for test names, such as `committee_member`. */
  readonly role: string;
}

/**
 * Classifies a listed person. The review personas carry their label
 * (`scenario.rs` `PERSONAS`). A person without a label shows the email,
 * which `control::email` builds as `synthetic-<tag>-<hex>@e2e.invalid`.
 */
export function classify(p: ListedPerson): Who | null {
  const byLabel: ReadonlyArray<readonly [RegExp, string]> = [
    [/^Coordinator (C\d)$/, 'coordinator'],
    [/^Committee member (R\d)$/, 'committee_member'],
    [/^Committee chair (H\d)$/, 'committee_chair'],
    [/^IRC member (I\d)$/, 'irc_member'],
    [/^Programme manager (M\d)$/, 'programme_manager'],
  ];
  for (const [re, role] of byLabel) {
    const m = re.exec(p.label);
    if (m !== null && m[1] !== undefined) return { key: m[1].toLowerCase(), role };
  }
  const lead = /^synthetic-lead-([a-z])(?:-self)?-[0-9a-f]+@e2e\.invalid$/.exec(p.email);
  if (lead !== null && lead[1] !== undefined) return { key: `lead-${lead[1]}`, role: 'applicant' };
  if (/^synthetic-guardian-[0-9a-f]+@e2e\.invalid$/.test(p.email)) return { key: 'guardian', role: 'guardian' };
  if (/^synthetic-a1-[0-9a-f]+@e2e\.invalid$/.test(p.email)) return { key: 'a1', role: 'tenant_admin' };
  return null;
}

/** The listed person with key `key`. Fails with a reason naming the scene. */
export function personOf(listed: readonly ListedPerson[], key: string, scene: string): ListedPerson {
  const p = listed.find((x) => classify(x)?.key === key);
  if (p === undefined) {
    const seen = listed.map((x) => classify(x)?.key ?? `unknown (${x.label})`).join(', ');
    throw new Error(`the demo page lists no person ${key} in scene ${scene}; it lists: ${seen || 'nobody'}`);
  }
  return p;
}

// ---------------------------------------------------------------------------
// A person's browser
// ---------------------------------------------------------------------------

/** A person in a browser context of their own, with a virtual authenticator. */
export interface Person {
  readonly context: BrowserContext;
  readonly page: Page;
  readonly origin: string;
}

/** A new browser context and page for one person. */
export async function newPerson(browser: Browser): Promise<Person> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await VirtualAuthenticator.attach(page);
  return { context, page, origin: stack().cells.a.origin };
}

/**
 * Opens the person's sign-in link from the demo page, the only `goto` of
 * the journey, and creates a passkey with "Create a passkey".
 */
export async function enrolFromLink(p: Person, link: string): Promise<void> {
  const u = new URL(link);
  expect(u.origin, 'the sign-in link is on the cell origin').toBe(p.origin);
  expect(u.pathname).toBe(PAGES.invite);
  await p.page.goto(link);
  await p.page.locator(UI.invite.register).click();
}

/** Waits until a page has loaded its data: a `main`, and nothing busy in it. */
export async function settle(page: Page): Promise<void> {
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0);
}

/**
 * The person landed on the home page after signing in, and the page is
 * a home page, not the not-found page.
 */
export async function expectHome(p: Person, why: string): Promise<void> {
  await expect(p.page, `${why}: lands on the home page ${HOME}, not ${ACCOUNT}`).toHaveURL(
    (u) => u.origin === p.origin && u.pathname === HOME,
  );
  await settle(p.page);
  await expect(p.page.locator('h1').first(), `${why}: the home page is not "${NOT_FOUND_TITLE}"`).not.toHaveText(
    NOT_FOUND_TITLE,
  );
  await expect(p.page.locator(NAV_UI.home), `${why}: the home page shows ${NAV_UI.home}`).toBeVisible();
}

/** The page has visible links to the home page and to the account page. */
export async function expectNav(p: Person, where: string, links: ReadonlyArray<'home' | 'account'> = ['home', 'account']): Promise<void> {
  for (const which of links) {
    const sel = which === 'home' ? NAV_UI.navHome : NAV_UI.navAccount;
    const path = which === 'home' ? HOME : ACCOUNT;
    const a = p.page.locator(sel).first();
    await expect(a, `${where}: a visible link to the ${which} page (${sel})`).toBeVisible();
    const href = (await a.getAttribute('href')) ?? '';
    expect(new URL(href, p.page.url()).href, `${where}: the ${which} link opens ${path}`).toBe(`${p.origin}${path}`);
  }
}

/** The path of the page. */
function pathOf(page: Page): string {
  return new URL(page.url()).pathname;
}

/** Clicks `link` and waits until the page has left `from`. */
async function clickAway(page: Page, link: ReturnType<Page['locator']>, from: string): Promise<void> {
  await expect(link).toBeVisible();
  await link.click();
  await page.waitForURL((u) => u.pathname !== from);
  await settle(page);
}

/** One piece of work a person reaches from the home page. */
export interface Work {
  /** The words of the test name, such as `assignment`. */
  readonly what: string;
  /** The kinds of home link that may lead to the work, in order of preference. */
  readonly kinds: readonly WorkKind[];
  /** The path of the work page. */
  readonly target: RegExp;
  /** A text the home item of the work holds, such as the call or proposal title. */
  readonly names?: string;
}

/** The most links a person follows from the home page to a work page. */
const MAX_HOPS = 3;

/**
 * From the home page, follows the home link of `work` and then links in
 * `main` only, until the page path matches `work.target`. Every page on
 * the way has the home and account links. Ends back on the home page,
 * through its link.
 */
export async function reach(p: Person, work: Work, who: string): Promise<void> {
  const page = p.page;
  expect(pathOf(page), `${who}: starts from the home page`).toBe(HOME);
  const link = page.locator(work.kinds.map((k) => NAV_UI.workLink(k)).join(', ')).first();
  await expect(link, `${who}: the home page links to the ${work.what} (${work.kinds.join(' or ')})`).toBeVisible();
  const name = ((await link.getAttribute('aria-label')) ?? (await link.innerText())).trim();
  expect(name, `${who}: the home link of the ${work.what} has a name`).not.toBe('');
  if (work.names !== undefined) {
    // The `li` of `#home-work` that holds `link`. A `has` filter queries
    // its locator inside each `li`, where `#home-work` never is, so the
    // item is found from the link itself (implementer's fix, reported).
    await expect(
      link.locator(`xpath=ancestor::li[ancestor::*[@id="home-work"]][1]`),
      `${who}: the home page names the ${work.what}`,
    ).toContainText(work.names);
  }
  await clickAway(page, link, HOME);
  for (let hop = 0; ; hop += 1) {
    const here = pathOf(page);
    await expectNav(p, `${who}, ${here}`);
    if (work.target.test(here)) break;
    expect(hop, `${who}: reaches ${work.target} within ${MAX_HOPS} clicks; stopped at ${here}`).toBeLessThan(MAX_HOPS);
    const i = await page.locator('main a[href]').evaluateAll((as, src) => {
      const re = new RegExp(src);
      return as.findIndex(
        (a) => a instanceof HTMLAnchorElement && a.getClientRects().length > 0 && re.test(new URL(a.href).pathname),
      );
    }, work.target.source);
    expect(i, `${who}: ${here} has a visible link to ${work.target}`).toBeGreaterThanOrEqual(0);
    await clickAway(page, page.locator('main a[href]').nth(i), here);
  }
  await expect(page, `${who}: reaches the ${work.what}`).toHaveURL((u) => work.target.test(u.pathname));
  await clickAway(page, page.locator(NAV_UI.navHome).first(), pathOf(page));
  await expect(page, `${who}: the home link leads home`).toHaveURL((u) => u.pathname === HOME);
}

/**
 * From the home page, the account link opens the account page, and its
 * home link leads back home.
 */
export async function accountRoundTrip(p: Person, who: string): Promise<void> {
  const page = p.page;
  await expectNav(p, `${who}, ${HOME}`);
  await clickAway(page, page.locator(NAV_UI.navAccount).first(), HOME);
  await expect(page, `${who}: the account link opens ${ACCOUNT}`).toHaveURL((u) => u.pathname === ACCOUNT);
  await expect(page.locator(UI.account.sessions)).toBeVisible();
  await expectNav(p, `${who}, ${ACCOUNT}`, ['home']);
  await clickAway(page, page.locator(NAV_UI.navHome).first(), ACCOUNT);
  await expect(page, `${who}: the account page's home link leads home`).toHaveURL((u) => u.pathname === HOME);
  await settle(page);
}
