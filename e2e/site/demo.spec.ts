/**
 * The demo front door and the demo sign-in of `fstp-e2e-cell` (lane
 * m4/site scope items 7 and 8; Daniel, 2026-11-04: "for the demo it
 * makes NO SENSE to have to use and generate passkeys"). Test only: the
 * cell is the test-only binary of layering rule A9.
 *
 * - demo_front_door: `/demo` names the scene, then lists each synthetic
 *   person with their role, a sign-in link and one line on what they can
 *   do, styled on the tokens (I-70). The contract of
 *   `e2e/navigation/support.ts` `DemoPage` still holds.
 * - demo_signin_one_click: on a cell started with `--demo-signin`, one
 *   click on "Sign in as <name>" lands an applicant, a reviewer and a
 *   coordinator on `/app/`, signed in as that person, with no WebAuthn
 *   call and no virtual authenticator. The top bar shows "Demo sign-in"
 *   on every page. A step-up still opens, with a plain Confirm button,
 *   and still guards the command (R-LG-03).
 * - demo_signin_token_refusals: a reused, expired or forged token is
 *   refused, each paired with a fresh token that works.
 * - demo_signin_absent_without_flag: the cell started without the flag
 *   answers 404 on the demo sign-in route, offers no "Sign in as" link,
 *   and shows no demo notice in a passkey session. The Rust half,
 *   `crates/fstp-web/tests/demo_signin_absent.rs`, checks that the
 *   platform's routes and `fstp-web` hold no such route.
 *
 * The demo sign-in specs start cells of their own on free loopback ports
 * (`contract.ts` `OwnCell`), so one run covers the cell with and without
 * the flag. Every person and text is synthetic.
 */

import { expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { SESSION_COOKIE, VirtualAuthenticator, call, sessionStatus, test } from '../playwright.config';
import { DemoPage } from '../navigation/support';
import { API, APP, IDENTITY_UI, M4Control, SETTING_UI } from '../creator/contract';
import {
  DEMO_CONFIRM,
  DEMO_NOTICE,
  DEMO_SIGNIN_FLAG,
  DEMO_SIGNIN_PATH,
  DEMO_TOKEN_MICROS,
  DOOR,
  FrontDoor,
  OwnCell,
  SITE,
  forgedToken,
  randomToken,
  suiteCell,
  tokenProblems,
  watchWebAuthn,
} from './contract';
import { HOME, settle } from '../navigation/support';

// A step that waits on a navigation or an action fails within half a minute, not at the test timeout.
test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The words a role line on the front door may hold. */
const ROLE_WORDS =
  /applicant|guardian|coordinator|committee member|committee chair|irc member|programme manager|tenant admin|no role/i;

// ---------------------------------------------------------------------------
// demo_front_door
// ---------------------------------------------------------------------------

test.describe('demo front door', () => {
  test.describe.configure({ timeout: 240_000 });

  /** Scope item 7: the front door names the scene and each person by role, with a link and a line. */
  test('demo_front_door', async ({ browser }) => {
    const cell = suiteCell();
    const door = await FrontDoor.open(browser, cell);
    try {
      for (const [href, scene, people] of [
        ['/demo/applicant?at=STAGE2', /STAGE2/, [
          [DOOR.c1, /coordinator/i],
          [DOOR.r1, /committee member/i],
          [DOOR.m1, /programme manager/i],
          [DOOR.leadX, /applicant/i],
        ]],
        ['/demo/review?stage=stage1', /stage1/, [
          [DOOR.c1, /coordinator/i],
          [DOOR.r1, /committee member/i],
          [DOOR.h1, /committee chair/i],
          [DOOR.i1, /irc member/i],
        ]],
        ['/demo/reset', /reset/i, [[DOOR.a1, /tenant admin/i]]],
      ] as const) {
        await door.chooseScene(href);
        await expect(door.page.locator(SITE.demo.scene), `${href}: the front door names the scene`).toContainText(scene);
        const items = door.items();
        expect(await items.count(), `${href}: the front door lists people`).toBeGreaterThan(0);
        for (let i = 0; i < (await items.count()); i += 1) {
          const it = items.nth(i);
          const text = (await it.innerText()).replace(/\s+/g, ' ').trim();
          await expect(it.locator(SITE.demo.role), `${href}: "${text}" names a role`).toHaveText(ROLE_WORDS);
          const does = (await it.locator(SITE.demo.does).innerText()).trim();
          expect(does, `${href}: "${text}" says what the person can do`).not.toBe('');
          expect(does.split(/\s+/).length, `${href}: one short line for "${text}"`).toBeLessThan(40);
          await expect(it.locator('small'), `${href}: "${text}" shows a synthetic email`).toHaveText(/@e2e\.invalid$/);
          const first = it.locator('a').first();
          const link = new URL((await first.getAttribute('href')) ?? '', cell.control);
          expect(link.origin, `${href}: the sign-in link of "${text}" is on the cell origin`).toBe(cell.origin);
          expect(link.hash.length, `${href}: the sign-in token of "${text}" travels in the fragment`).toBeGreaterThan(1);
        }
        for (const [who, role] of people) {
          await expect(door.item(who), `${href}: lists ${who.source}`).toHaveCount(1);
          await expect(door.item(who).locator(SITE.demo.role), `${href}: ${who.source} is a ${role.source}`).toHaveText(role);
        }
        for (const scheme of ['light', 'dark'] as const) {
          expect(await tokenProblems(door.page, scheme, `/demo ${href}`), `I-70: the front door on the tokens`).toEqual([]);
        }
        await door.page.emulateMedia({ colorScheme: 'light' });
      }
    } finally {
      await door.close();
    }

    // The click-through contract of `e2e/navigation/support.ts` still reads the page.
    const demo = await DemoPage.open(browser);
    try {
      await demo.chooseScene('/demo/applicant?at=STAGE2');
      const listed = await demo.people();
      expect(listed.length, 'DemoPage.people() still reads the people').toBeGreaterThan(0);
      for (const p of listed) {
        expect(new URL(p.link).pathname, `${p.label}: the first link stays the one-time enrolment link`).toBe('/auth/invite');
      }
    } finally {
      await demo.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Demo sign-in on a cell started with the flag
// ---------------------------------------------------------------------------

/** A context with no virtual authenticator, watching WebAuthn calls. */
async function bareContext(browser: Browser): Promise<{
  readonly context: BrowserContext;
  readonly page: Page;
  readonly webauthn: () => readonly string[];
}> {
  const context = await browser.newContext();
  const w = await watchWebAuthn(context);
  const page = await context.newPage();
  return { context, page, webauthn: w.calls };
}

/**
 * Opens the front door of `own` in `page`, chooses nothing, and clicks
 * the "Sign in as" link of `who`. Returns the page that shows the cell
 * origin after the click: the same page, or the one the link opened.
 */
async function clickSignIn(page: Page, own: OwnCell, who: RegExp): Promise<Page> {
  await page.goto(`${own.cell.control}/demo`);
  const link = page
    .locator('xpath=//h2[starts-with(normalize-space(.), "People of this scene")]/following-sibling::ul[1]/li')
    .filter({ hasText: who })
    .locator(SITE.demo.signIn);
  await expect(link, `the front door offers "Sign in as" for ${who.source}`).toHaveCount(1);
  await expect(link).toHaveAccessibleName(/^Sign in as \S/);
  const href = new URL((await link.getAttribute('href')) ?? '', own.cell.control);
  expect(href.origin, 'the demo sign-in link is on the cell origin').toBe(own.cell.origin);
  expect(href.pathname).toBe(DEMO_SIGNIN_PATH);
  expect(href.search, 'no token in the query string').toBe('');
  expect(href.hash.length, 'the demo token travels in the fragment').toBeGreaterThan(1);
  const target = await link.getAttribute('target');
  if (target === '_blank') {
    const [opened] = await Promise.all([page.context().waitForEvent('page'), link.click()]);
    return opened;
  }
  await link.click();
  return page;
}

/** The person landed on `/app/` of `origin`, signed in, with the demo notice in the top bar. */
async function expectDemoHome(page: Page, origin: string, why: string): Promise<void> {
  await page.waitForURL((u) => u.origin === origin && u.pathname === HOME);
  await settle(page);
  await expect(page.locator('main #home'), `${why}: the home page`).toBeVisible();
  await expect(page.locator('header').getByText(DEMO_NOTICE), `${why}: the top bar shows "${DEMO_NOTICE}"`).toBeVisible();
  expect(await sessionStatus(page, origin), `${why}: the session is admitted`).toBe(200);
}

/** The front door's "Sign in as" link of `who`, read in a context of its own. */
async function signInHref(browser: Browser, own: OwnCell, who: RegExp): Promise<string> {
  const door = await FrontDoor.open(browser, own.cell);
  try {
    const link = door.signIn(who);
    await expect(link, `the front door offers "Sign in as" for ${who.source}`).toHaveCount(1);
    return new URL((await link.getAttribute('href')) ?? '', own.cell.control).href;
  } finally {
    await door.close();
  }
}

/** A refused demo token: an alert, no landing on `/app/`, no session and no session cookie. */
async function expectRefused(page: Page, origin: string, why: string): Promise<void> {
  await expect(page.getByRole('alert').first(), `${why}: the page says the sign-in is refused`).toBeVisible();
  expect(new URL(page.url()).pathname, `${why}: the person is not on the home page`).not.toBe(HOME);
  expect(await sessionStatus(page, origin), `${why}: no session is admitted`).not.toBe(200);
  const cookies = await page.context().cookies(origin);
  expect(cookies.map((c) => c.name), `${why}: no session cookie is set`).not.toContain(SESSION_COOKIE);
}

test.describe('demo sign-in with the flag', () => {
  test.describe.configure({ timeout: 300_000 });
  let own: OwnCell | null = null;
  const cellOf = (): OwnCell => {
    if (own === null) throw new Error(`the cell with ${DEMO_SIGNIN_FLAG} did not start`);
    return own;
  };

  // Each test starts a cell of its own, so each one reports its own reason.
  test.beforeEach(async () => {
    own = await OwnCell.start([DEMO_SIGNIN_FLAG]);
  });
  test.afterEach(async () => {
    await own?.stop();
    own = null;
  });

  /**
   * Scope item 8: one click signs in an applicant, a reviewer and a
   * coordinator, with no WebAuthn call, and every page shows the notice.
   * R-LG-03: a step-up still opens and still guards the command.
   */
  test('demo_signin_one_click', async ({ browser, request }) => {
    const c = cellOf();
    const door = await FrontDoor.open(browser, c.cell);
    try {
      await door.chooseScene('/demo/applicant?at=STAGE2');
    } finally {
      await door.close();
    }
    for (const [who, work, label] of [
      [DOOR.leadX, 'proposal', 'applicant'],
      [DOOR.r1, 'assignments', 'reviewer'],
      [DOOR.c1, 'intake', 'coordinator'],
    ] as const) {
      const bare = await bareContext(browser);
      try {
        const page = await clickSignIn(bare.page, c, who);
        await expectDemoHome(page, c.cell.origin, label);
        const link = page.locator(SITE.workLink(work)).first();
        await expect(link, `${label}: the home page lists the ${work} work of that person`).toBeVisible();
        await link.click();
        await page.waitForURL((u) => u.pathname !== HOME);
        await settle(page);
        await expect(page.locator('header').getByText(DEMO_NOTICE), `${label}: every page shows the notice`).toBeVisible();
        // The M3 account page of the same session says so too.
        await page.goto(`${c.cell.origin}/auth/account`);
        await expect(page.locator('header').getByText(DEMO_NOTICE), `${label}: the account page shows the notice`).toBeVisible();
        expect(bare.webauthn(), `${label}: no WebAuthn call`).toEqual([]);
      } finally {
        await bare.context.close();
      }
    }

    // The step-up of a high-risk action: the tenant admin changes P-69.
    const reset = await FrontDoor.open(browser, c.cell);
    let email = '';
    try {
      await reset.chooseScene('/demo/reset');
      email = (await reset.item(DOOR.a1).locator('small').innerText()).trim();
    } finally {
      await reset.close();
    }
    const bare = await bareContext(browser);
    try {
      const page = await clickSignIn(bare.page, c, DOOR.a1);
      const origin = c.cell.origin;
      await expectDemoHome(page, origin, 'tenant admin');

      // Identity first, as for every tenant admin (`e2e/creator/support.ts` `verifyOnIdentityPage`).
      const control = new M4Control(request, c.cell);
      await page.goto(`${origin}${APP.identity}`);
      const started = page.waitForResponse(
        (r) => new URL(r.url()).pathname === API.meVerification && r.request().method() === 'POST',
      );
      await page.locator(IDENTITY_UI.verify).click();
      expect((await started).ok(), 'the verification starts').toBe(true);
      await control.verify(await control.account(email));

      await page.goto(`${origin}${APP.setting('p69')}`);
      const current = page.locator(SETTING_UI.current);
      await expect(current).toBeVisible();
      const was = (await current.innerText()).trim();
      const next = was === 'MIT' ? 'Apache-2.0' : 'MIT';
      const dialog = page.locator(SITE.stepup.dialog);
      const confirm = page.locator(SITE.stepup.confirm);

      await page.locator(SETTING_UI.value).fill(next);
      await page.locator(SETTING_UI.save).click();
      await expect(dialog, 'R-LG-03: the step-up still opens').toBeVisible();
      await expect(confirm).toHaveAccessibleName(DEMO_CONFIRM);
      await page.keyboard.press('Escape');
      await expect(dialog).toBeHidden();
      await page.reload();
      await expect(page.locator(SETTING_UI.current), 'R-LG-03: a cancelled step-up changes nothing').toHaveText(was);

      await page.locator(SETTING_UI.value).fill(next);
      await page.locator(SETTING_UI.save).click();
      await expect(dialog).toBeVisible();
      await confirm.click();
      await expect(dialog).toBeHidden();
      await page.reload();
      await expect(page.locator(SETTING_UI.current), 'the confirmed step-up lets the command run').toHaveText(next);
      expect(bare.webauthn(), 'the demo step-up makes no WebAuthn call').toEqual([]);
    } finally {
      await bare.context.close();
    }
  });

  /** Scope item 8: the cell refuses a reused, an expired and a forged token. */
  test('demo_signin_token_refusals', async ({ browser, request }) => {
    const c = cellOf();
    const origin = c.cell.origin;
    const door = await FrontDoor.open(browser, c.cell);
    try {
      await door.chooseScene('/demo/applicant?at=STAGE2');
    } finally {
      await door.close();
    }
    const open = async (href: string): Promise<{ context: BrowserContext; page: Page }> => {
      const b = await bareContext(browser);
      await b.page.goto(href);
      return { context: b.context, page: b.page };
    };

    // Reused: the first use signs in, the second is refused.
    const once = await signInHref(browser, c, DOOR.c1);
    const first = await open(once);
    try {
      await expectDemoHome(first.page, origin, 'the first use of a token');
    } finally {
      await first.context.close();
    }
    const again = await open(once);
    try {
      await expectRefused(again.page, origin, 'a reused token');
    } finally {
      await again.context.close();
    }

    // Forged: one character changed, and a random token of the same length.
    for (const [what, forge] of [
      ['a token with one character changed', forgedToken],
      ['a random token', randomToken],
    ] as const) {
      const genuine = await signInHref(browser, c, DOOR.r1);
      const bad = await open(forge(genuine));
      try {
        await expectRefused(bad.page, origin, what);
      } finally {
        await bad.context.close();
      }
      const good = await open(genuine);
      try {
        await expectDemoHome(good.page, origin, `the genuine token beside ${what}`);
      } finally {
        await good.context.close();
      }
    }
    const empty = await open(`${origin}${DEMO_SIGNIN_PATH}`);
    try {
      await expectRefused(empty.page, origin, 'no token');
    } finally {
      await empty.context.close();
    }

    // Expired: older than its lifetime on the cell clock.
    const stale = await signInHref(browser, c, DOOR.leadX);
    await c.control(request).advanceClock(2 * DEMO_TOKEN_MICROS);
    const late = await open(stale);
    try {
      await expectRefused(late.page, origin, 'an expired token');
    } finally {
      await late.context.close();
    }
    const fresh = await open(await signInHref(browser, c, DOOR.leadX));
    try {
      await expectDemoHome(fresh.page, origin, 'a fresh token after the expired one');
    } finally {
      await fresh.context.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Without the flag
// ---------------------------------------------------------------------------

/**
 * The status of `GET` and of a same-origin `POST` on the demo sign-in
 * route of `origin`, from a browser page of that origin. The browser
 * resolves names under `localhost` (RFC 6761), and sends the `Origin`
 * and `X-FSTP-Request` fields a state-changing call needs.
 */
/** The demo modules of `web/src/demo`, which the cell serves only with the flag. */
const DEMO_MODULES = ['/assets/demo/notice.js', '/assets/demo/signin.js'] as const;

async function probeRoute(
  browser: Browser,
  origin: string,
): Promise<{ readonly get: number; readonly post: number; readonly assets: readonly number[] }> {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    const g = await page.goto(`${origin}${DEMO_SIGNIN_PATH}`);
    await page.goto(`${origin}/auth/login`);
    const p = await call(page, origin, 'POST', DEMO_SIGNIN_PATH, { token: '00' });
    const assets: number[] = [];
    for (const m of DEMO_MODULES) assets.push((await page.request.get(`${origin}${m}`)).status());
    return { get: g?.status() ?? 0, post: p.status, assets };
  } finally {
    await context.close();
  }
}

test.describe('demo sign-in without the flag', () => {
  test.describe.configure({ mode: 'serial', timeout: 300_000 });
  let plain: OwnCell | null = null;
  let flagged: OwnCell | null = null;

  test.beforeAll(async () => {
    plain = await OwnCell.start([]);
  });
  test.afterAll(async () => {
    await plain?.stop();
    await flagged?.stop();
    plain = null;
    flagged = null;
  });

  /**
   * Scope item 8, layering rule A9: without the flag the cell answers 404
   * on the demo sign-in route, both methods, and its front door offers
   * no "Sign in as" link. With the flag, the same route is served, so
   * the path checked here is the real one.
   */
  test('demo_signin_absent_without_flag', async ({ browser }) => {
    if (plain === null) throw new Error('the cell without the flag did not start');
    const origin = plain.cell.origin;
    const probe = await probeRoute(browser, origin);
    expect(probe.get, `GET ${DEMO_SIGNIN_PATH} without the flag`).toBe(404);
    expect(probe.post, `POST ${DEMO_SIGNIN_PATH} without the flag`).toBe(404);
    expect(probe.assets, `the demo modules ${DEMO_MODULES.join(", ")} without the flag`).toEqual(DEMO_MODULES.map(() => 404));

    const door = await FrontDoor.open(browser, plain.cell);
    try {
      await door.chooseScene('/demo/applicant?at=STAGE2');
      await expect(door.page.locator(SITE.demo.signIn), 'no "Sign in as" link without the flag').toHaveCount(0);
      // A passkey session on the plain cell shows no demo notice.
      const first = door.item(DOOR.c1).locator('a').first();
      const invite = new URL((await first.getAttribute('href')) ?? '', plain.cell.control).href;
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await VirtualAuthenticator.attach(page);
        await page.goto(invite);
        await page.locator('#invite-register').click();
        await page.waitForURL((u) => u.origin === origin && u.pathname === HOME);
        await settle(page);
        await expect(page.locator('header').getByText(DEMO_NOTICE), 'a passkey session shows no demo notice').toHaveCount(0);
        const answer = await call(page, origin, 'GET', DEMO_SIGNIN_PATH);
        expect(answer.status, 'the route stays absent for a signed-in person').toBe(404);
      } finally {
        await context.close();
      }
    } finally {
      await door.close();
    }

    flagged = await OwnCell.start([DEMO_SIGNIN_FLAG]);
    const served = await probeRoute(browser, flagged.cell.origin);
    expect(served.get, `GET ${DEMO_SIGNIN_PATH} with the flag is served`).not.toBe(404);
    expect(served.assets, `the demo modules ${DEMO_MODULES.join(", ")} with the flag`).toEqual(DEMO_MODULES.map(() => 200));
  });
});
