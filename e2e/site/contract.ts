/**
 * The page contract and the helpers of the site specs (`e2e/site/`),
 * lane m4/site: one reactive website at `/app/`, built to the approved
 * designs (ADR-014, `SPEC/12-journey-ui.md` sections 4 and 8,
 * `docs/design/README.md` and `01-navigation-home.md`).
 *
 * This file is not a spec. Playwright collects `*.spec.ts` files only.
 * Every person, proposal and text is synthetic.
 *
 * Interim, pending Daniel: the ids, attributes and routes below are the
 * test author's reading of the lane scope of 2026-11-04. A page may add
 * elements, but each one named here keeps its role. The contracts of
 * `e2e/navigation/support.ts`, `e2e/review/contract.ts`,
 * `e2e/applicant/support.ts` and `e2e/creator/contract.ts` still hold.
 *
 * # App shell (scope item 1, ADR-014 "Shell, assets and headers")
 *
 * - Every `/app/` path is served by the one shell and rendered by
 *   `web/src/core/router.ts`. Following a link inside `/app/` or
 *   submitting a form there never loads a new document: the URL changes
 *   through the History API and the page renders into `main`.
 * - After every such navigation, focus is on the page's `main h1`, a
 *   polite live region (`[aria-live="polite"]`) holds the text of that
 *   `h1`, and `document.title` names the new page.
 * - Back, forward, reload and a pasted deep link each show the same `h1`
 *   and the same `main` text. Back and forward stay in the document.
 * - A link outside `/app/` (the auth pages, the vault origin, public
 *   pages) is a normal navigation.
 *
 * # Tokens and layout (scope item 3, I-70, R-NF-03)
 *
 * - Every page uses the custom properties of the copied token sheet
 *   (`design/tokens.css`, copied into `web/`): [`TOKENS`] holds the light
 *   and dark values each page must compute for `:root`, under
 *   `prefers-color-scheme`. The body background is `--color-surface-0`
 *   and the body text `--color-text-1`, at 4.5:1 or more.
 * - A status chip is a `.badge` (`design/tokens.css` section 6) with its
 *   state as text. The proposal state of `#proposal-state` and of each
 *   row with `data-state` is shown by such a chip.
 *
 * # Demo front door (scope item 7)
 *
 * The demo page `GET /demo` on the control base keeps the contract of
 * `e2e/navigation/support.ts` `DemoPage`: an `h1` holding "FSTP demo",
 * the scene links, and the people under an `h2` starting "People of this
 * scene", one `li` each, whose first `a` is the person's one-time
 * sign-in link and whose `small` is the email. It adds:
 *
 * - `#demo-scene`, which names the scene the cell holds, such as
 *   `stage1` or `STAGE2` (or `Reset`);
 * - in each person's `li`, `[data-demo-role]` with the role in words and
 *   `[data-demo-does]` with one line on what the person can do;
 * - `a[data-demo-link="public-calls"]`, a link to the public open calls
 *   page on the cell origin;
 * - styling on the tokens, as every other page.
 *
 * # Demo sign-in (scope item 8, Daniel 2026-11-04)
 *
 * Test only, in `fstp-e2e-cell` only (layering rule A9).
 *
 * - The flag is [`DEMO_SIGNIN_FLAG`]. Without it nothing changes, and
 *   both methods on [`DEMO_SIGNIN_PATH`] answer 404 on the cell origin.
 * - With it, each person's `li` on `/demo` holds one
 *   `a[data-demo-signin]` whose accessible name is "Sign in as <name>".
 *   Its `href` is `<cell origin>/auth/demo-signin#<token>`: the token
 *   travels in the fragment, as every M3 token does. The control base
 *   issues the token, and the cell origin redeems it once. A token lives
 *   at most five minutes of the cell's test clock.
 * - Redeeming opens a session for that seeded account on the cell origin
 *   and lands on `/app/`, with no WebAuthn call.
 * - A reused, expired or forged token is refused: the page shows an
 *   element with `role="alert"`, and no session cookie is set.
 * - Every page of such a session shows the text [`DEMO_NOTICE`] in the
 *   top bar (`header`). A passkey session never shows it.
 * - A high-risk action still opens `dialog#stepup`. Its confirm button
 *   `#stepup-confirm` is named "Confirm" and runs no WebAuthn ceremony.
 *   Escape still cancels it, and the command still needs the step-up.
 */

import { expect, type APIRequestContext, type Browser, type BrowserContext, type Locator, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  Control,
  StackMissing,
  VirtualAuthenticator,
  openLink,
  stack,
  type CellEndpoints,
} from '../playwright.config';
import { HOME, settle } from '../navigation/support';

// ---------------------------------------------------------------------------
// Constants of the contract
// ---------------------------------------------------------------------------

/** The repository root. */
export const REPO = resolve(__dirname, '..', '..');

/** The demo sign-in flag of `fstp-e2e-cell`. */
export const DEMO_SIGNIN_FLAG = '--demo-signin';

/** The demo sign-in route on the cell origin. */
export const DEMO_SIGNIN_PATH = '/auth/demo-signin';

/** The notice every page of a demo sign-in session shows in its top bar. */
export const DEMO_NOTICE = 'Demo sign-in';

/** The name of the confirm button of a demo step-up. */
export const DEMO_CONFIRM = 'Confirm';

/** The longest a demo sign-in token lives, in microseconds of the cell clock. */
export const DEMO_TOKEN_MICROS = 5 * 60 * 1_000_000;

/** The ids and selectors of the site contract. */
export const SITE = {
  h1: 'main h1',
  live: '[aria-live="polite"]',
  sidebar: 'aside.sidebar',
  sidebarLink: (path: string): string => `aside nav a[href="${path}"]`,
  workLink: (kind: string): string => `#home-work a[data-work="${kind}"]`,
  chip: '.badge',
  demo: {
    scene: '#demo-scene',
    role: '[data-demo-role]',
    does: '[data-demo-does]',
    signIn: 'a[data-demo-signin]',
    publicCalls: 'a[data-demo-link="public-calls"]',
  },
  stepup: { dialog: '#stepup', confirm: '#stepup-confirm' },
} as const;

/**
 * The values of `design/tokens.css` (sections 1 and 2) each page must
 * compute on `:root`, in the light and the dark scheme. Tenants may
 * override tokens (I-72), but the synthetic demo tenant overrides none.
 */
export const TOKENS = {
  light: {
    '--color-surface-0': '#ffffff',
    '--color-surface-1': '#f8fafc',
    '--color-text-1': '#0f172a',
    '--color-text-2': '#334155',
    '--color-brand-text': '#1e40af',
    '--color-focus': '#2563eb',
    '--color-state-error-text': '#b91c1c',
  },
  dark: {
    '--color-surface-0': '#0f172a',
    '--color-surface-1': '#1e293b',
    '--color-text-1': '#f1f5f9',
    '--color-text-2': '#cbd5e1',
    '--color-brand-text': '#93c5fd',
    '--color-focus': '#60a5fa',
    '--color-state-error-text': '#f87171',
  },
} as const;

/** A colour scheme Playwright can emulate. */
export type Scheme = keyof typeof TOKENS;

/** Every proposal state by its spec name (`state-machine.md`). */
export const STATE_NAMES: ReadonlySet<string> = new Set([
  'DRAFT', 'SUBMITTED', 'INELIGIBLE', 'STAGE1', 'NOT_SELECTED', 'STAGE2', 'RANKED', 'IRC_REVIEW',
  'DEFERRED', 'DECLINED', 'NEGOTIATION', 'WITHDRAWN', 'GRANTED', 'IN_EXECUTION', 'COMPLETED', 'TERMINATED',
]);

// ---------------------------------------------------------------------------
// One document: the marker and the load count
// ---------------------------------------------------------------------------

/**
 * Watches one page for document loads. Each `load` event is a new
 * document, which an in-app navigation must never cause.
 */
export class Document {
  private loads = 0;
  private readonly marker: string;

  private constructor(readonly page: Page) {
    this.marker = `site-${Math.random().toString(16).slice(2)}`;
    page.on('load', () => {
      this.loads += 1;
    });
  }

  /** Starts watching `page`: puts a marker on its window. */
  static async watch(page: Page): Promise<Document> {
    const d = new Document(page);
    await d.mark();
    return d;
  }

  /** Puts the marker on the current window again, after a deliberate load. */
  async mark(): Promise<void> {
    this.loads = 0;
    await this.page.evaluate((m) => {
      (window as unknown as Record<string, unknown>)['fstpSiteMarker'] = m;
    }, this.marker);
  }

  /** The document is the one marked: no load since, and the marker is there. */
  async expectSame(why: string): Promise<void> {
    const m = await this.page.evaluate(() => (window as unknown as Record<string, unknown>)['fstpSiteMarker']);
    expect(m, `ADR-014: ${why} keeps the document (the window marker survives)`).toBe(this.marker);
    expect(this.loads, `ADR-014: ${why} loads no new document`).toBe(0);
  }

  /** Document loads since the marker was set. */
  get loadCount(): number {
    return this.loads;
  }
}

/** The path of the page. */
export function pathOf(page: Page): string {
  return new URL(page.url()).pathname;
}

/** The trimmed text of the page's first `main h1`. */
export async function h1Text(page: Page): Promise<string> {
  const h1 = page.locator(SITE.h1).first();
  await expect(h1, `${pathOf(page)} has a main h1`).toBeVisible();
  return (await h1.innerText()).trim();
}

/** The `main` text with its white space folded, for comparing two renders of one page. */
export async function mainText(page: Page): Promise<string> {
  return (await page.locator('main').first().innerText()).replace(/\s+/g, ' ').trim();
}

/** One page as the person saw it. */
export interface Seen {
  readonly path: string;
  readonly h1: string;
  readonly main: string;
  readonly title: string;
}

/** What the page shows now. */
export async function seen(page: Page): Promise<Seen> {
  await settle(page);
  return { path: pathOf(page), h1: await h1Text(page), main: await mainText(page), title: await page.title() };
}

/**
 * The navigation contract after an in-app navigation (ADR-014, R-NF-03):
 * focus on the `h1`, the polite live region names it, and the document
 * title names the page and differs from `before` when the `h1` does.
 */
export async function expectAnnounced(page: Page, before: Seen | null, why: string): Promise<Seen> {
  const now = await seen(page);
  await expect
    .poll(() => page.evaluate(() => document.activeElement?.matches('main h1') === true), {
      message: `R-NF-03: ${why}: focus moves to the page's h1 "${now.h1}"`,
    })
    .toBe(true);
  await expect
    .poll(
      () =>
        page.evaluate(
          (sel) => Array.from(document.querySelectorAll(sel)).map((e) => (e.textContent ?? '').trim()),
          SITE.live,
        ),
      { message: `R-NF-03: ${why}: a polite live region names "${now.h1}"` },
    )
    .toContainEqual(expect.stringContaining(now.h1));
  expect(now.title, `${why}: the document has a title`).not.toBe('');
  if (before !== null && before.h1 !== now.h1) {
    expect(now.title, `ADR-014: ${why}: document.title changes with the page`).not.toBe(before.title);
  }
  return now;
}

/**
 * Clicks `link`, which must be visible and lead into `/app/`, and waits
 * until the path matches `to` and the page settled. Returns what the
 * page shows, after the navigation contract held.
 */
export async function clickTo(page: Page, link: Locator, to: RegExp, why: string): Promise<Seen> {
  const before = await seen(page);
  await expect(link, `${why}: the link is visible`).toBeVisible();
  await link.click();
  await page.waitForURL((u) => to.test(u.pathname));
  return expectAnnounced(page, before, why);
}

// ---------------------------------------------------------------------------
// Signing in demo people with a passkey (the suite's cell, no flag)
// ---------------------------------------------------------------------------

/** The suite's cell `a`. */
export function suiteCell(): CellEndpoints {
  return stack().cells.a;
}

/**
 * A person in a context of their own: opens their one-time enrolment
 * link, creates a passkey, and lands on the home page `/app/`.
 */
export async function enrolToHome(person: () => Promise<Page>, origin: string, link: string): Promise<Page> {
  const page = await person();
  await VirtualAuthenticator.attach(page);
  const u = new URL(link);
  expect(u.origin, 'the enrolment link is on the cell origin').toBe(origin);
  await openLink(page, link);
  await page.locator('#invite-register').click();
  await page.waitForURL((x) => x.origin === origin && x.pathname === HOME);
  await settle(page);
  return page;
}

/** From the account page, the site navigation's Home link opens `/app/`, a normal navigation. */
export async function accountToHome(page: Page, origin: string): Promise<void> {
  await page.locator('nav a[data-nav="home"]').first().click();
  await page.waitForURL((x) => x.origin === origin && x.pathname === HOME);
  await settle(page);
}

// ---------------------------------------------------------------------------
// The demo front door of any cell
// ---------------------------------------------------------------------------

/** One person the front door lists. */
export interface DoorPerson {
  readonly item: Locator;
  readonly role: string;
  readonly does: string;
  readonly email: string;
}

/** The demo page `GET /demo` of `cell`, in a context of its own. */
export class FrontDoor {
  private constructor(
    readonly context: BrowserContext,
    readonly page: Page,
    readonly cell: CellEndpoints,
  ) {}

  static async open(browser: Browser, cell: CellEndpoints): Promise<FrontDoor> {
    const context = await browser.newContext();
    const page = await context.newPage();
    const r = await page.goto(`${cell.control}/demo`);
    if (r === null || !r.ok()) {
      throw new StackMissing(`the demo page ${cell.control}/demo answered ${r?.status() ?? 'nothing'}`);
    }
    return new FrontDoor(context, page, cell);
  }

  /** Clicks the scene link `href` and waits until the demo page shows again. */
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

  /** Loads the page again, for fresh tokens. */
  async reload(): Promise<void> {
    await this.page.goto(`${this.cell.control}/demo`);
  }

  /** The `li` of each person under "People of this scene". */
  items(): Locator {
    return this.page.locator('xpath=//h2[starts-with(normalize-space(.), "People of this scene")]/following-sibling::ul[1]/li');
  }

  /** The `li` of the person whose text matches `who`, such as `Coordinator C1` or the email. */
  item(who: RegExp): Locator {
    return this.items().filter({ hasText: who });
  }

  /** The "Sign in as" link of the person `who`. */
  signIn(who: RegExp): Locator {
    return this.item(who).locator(SITE.demo.signIn);
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}

/** The person patterns of the front door, by key (`scenario.rs` `PERSONAS`). */
export const DOOR = {
  c1: /Coordinator C1/,
  r1: /Committee member R1/,
  h1: /Committee chair H1/,
  i1: /IRC member I1/,
  m1: /Programme manager M1/,
  leadX: /synthetic-lead-x(?:-self)?-[0-9a-f]+@e2e\.invalid/,
  a1: /synthetic-a1-[0-9a-f]+@e2e\.invalid/,
} as const;

// ---------------------------------------------------------------------------
// A cell of this spec's own, with or without the demo flag
// ---------------------------------------------------------------------------

/** The `fstp-e2e-cell` binary that `tools/demo/run.sh` builds. */
export function cellBinary(): string {
  return process.env['FSTP_E2E_CELL_BIN'] ?? join(REPO, 'target', 'debug', 'fstp-e2e-cell');
}

/**
 * A short-lived `fstp-e2e-cell` that a spec starts itself, on free
 * loopback ports (`--port 0`), so one run covers the cell with and
 * without [`DEMO_SIGNIN_FLAG`]. It serves the packed pages of `web/`, as
 * `tools/demo/run.sh` builds them. Stopped when the spec ends.
 */
export class OwnCell {
  private constructor(
    private readonly child: ChildProcess,
    private readonly dir: string,
    readonly cell: CellEndpoints,
    readonly cellB: CellEndpoints,
  ) {}

  static async start(flags: readonly string[]): Promise<OwnCell> {
    const bin = cellBinary();
    if (!existsSync(bin)) {
      throw new StackMissing(`${bin} is missing; build it with tools/demo/run.sh or cargo build -p fstp-api-testkit --bin fstp-e2e-cell`);
    }
    const dir = mkdtempSync(join(tmpdir(), 'fstp-site-cell-'));
    const manifest = join(dir, 'stack.json');
    const child = spawn(bin, ['--port', '0', '--web', join(REPO, 'web'), '--manifest-out', manifest, ...flags], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let log = '';
    child.stdout?.on('data', (c) => {
      log += c.toString();
    });
    child.stderr?.on('data', (c) => {
      log += c.toString();
    });
    let exited: string | null = null;
    child.once('exit', (code, signal) => {
      exited = `exited with ${code ?? signal ?? 'nothing'}`;
    });
    child.once('error', (e) => {
      exited = `could not start: ${e.message}`;
    });
    await expect
      .poll(
        () => {
          if (exited !== null) return `stopped`;
          return existsSync(manifest) && readFileSync(manifest, 'utf8').length > 0 ? 'ready' : 'waiting';
        },
        { timeout: 30_000, message: `fstp-e2e-cell ${flags.join(' ')} writes its manifest` },
      )
      .not.toBe('waiting');
    if (exited !== null) {
      rmSync(dir, { recursive: true, force: true });
      throw new Error(`fstp-e2e-cell ${flags.join(' ')} ${String(exited)}: ${log.trim()}`);
    }
    const m = JSON.parse(readFileSync(manifest, 'utf8')) as {
      cells?: { a?: CellEndpoints; b?: CellEndpoints };
    };
    const a = m.cells?.a;
    const b = m.cells?.b;
    if (a === undefined || b === undefined) {
      child.kill('SIGTERM');
      rmSync(dir, { recursive: true, force: true });
      throw new StackMissing('the own cell wrote a manifest without cells a and b');
    }
    return new OwnCell(child, dir, a, b);
  }

  /** The control routes of cell `a`. */
  control(request: APIRequestContext): Control {
    return new Control(request, this.cell);
  }

  async stop(): Promise<void> {
    if (this.child.exitCode === null) {
      const gone = new Promise<void>((r) => {
        this.child.once('exit', () => r());
      });
      this.child.kill('SIGTERM');
      await gone;
    }
    rmSync(this.dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// WebAuthn, CSP and console watchers
// ---------------------------------------------------------------------------

/**
 * Records every `navigator.credentials.get` and `.create` call of every
 * page of `context`, in every document. The call still runs.
 */
export async function watchWebAuthn(context: BrowserContext): Promise<{ readonly calls: () => readonly string[] }> {
  const calls: string[] = [];
  await context.exposeBinding('fstpSiteWebAuthn', (_source, kind: unknown) => {
    calls.push(String(kind));
  });
  await context.addInitScript(() => {
    const proto = (globalThis as unknown as { CredentialsContainer?: { prototype: Record<string, unknown> } })
      .CredentialsContainer?.prototype;
    if (proto === undefined) return;
    for (const k of ['get', 'create']) {
      const orig = proto[k];
      if (typeof orig !== 'function') continue;
      proto[k] = function (this: unknown, ...args: unknown[]): unknown {
        void (window as unknown as { fstpSiteWebAuthn: (k: string) => Promise<void> }).fstpSiteWebAuthn(k);
        return (orig as (...a: unknown[]) => unknown).apply(this, args);
      };
    }
  });
  return { calls: () => [...calls] };
}

/** One problem a page showed: a CSP violation, a console error or an uncaught error. */
export interface PageProblem {
  readonly kind: 'csp' | 'console' | 'pageerror';
  readonly where: string;
  readonly what: string;
}

/**
 * Records every `securitypolicyviolation` event, console error and
 * uncaught error of every page of `context`.
 */
export async function watchProblems(context: BrowserContext): Promise<{ readonly problems: () => readonly PageProblem[] }> {
  const problems: PageProblem[] = [];
  await context.exposeBinding('fstpSiteCsp', (source, what: unknown) => {
    problems.push({ kind: 'csp', where: source.page?.url() ?? '', what: String(what) });
  });
  await context.addInitScript(() => {
    window.addEventListener(
      'securitypolicyviolation',
      (e) => {
        void (window as unknown as { fstpSiteCsp: (w: string) => Promise<void> }).fstpSiteCsp(
          `${e.violatedDirective} blocked ${e.blockedURI || 'inline'} at ${e.sourceFile}:${e.lineNumber}`,
        );
      },
      true,
    );
  });
  const watch = (page: Page): void => {
    page.on('console', (m) => {
      if (m.type() === 'error') {
        problems.push({ kind: 'console', where: page.url(), what: `${m.text()} (${m.location().url})` });
      }
    });
    page.on('pageerror', (e) => {
      problems.push({ kind: 'pageerror', where: page.url(), what: e.message });
    });
  };
  for (const p of context.pages()) watch(p);
  context.on('page', watch);
  return { problems: () => [...problems] };
}

// ---------------------------------------------------------------------------
// The crawl: every page a person reaches by clicking
// ---------------------------------------------------------------------------

/** Whether a same-origin link path is a page the crawl follows. */
export function crawlable(path: string): boolean {
  return (path.startsWith('/app/') || path === '/auth/account') && !path.startsWith('/app/assets/');
}

/** The most pages one crawl visits. */
export const CRAWL_LIMIT = 24;

/** The deepest a crawl clicks from the home page. */
export const CRAWL_DEPTH = 3;

/**
 * From the page shown now, clicks every visible link of `main`, the
 * sidebar and the top bar that leads to a [`crawlable`] page not seen
 * yet, depth first, and returns with Back after each. Calls `visit` on
 * every page, the first one included. Returns the paths visited.
 */
export async function crawl(page: Page, visit: (page: Page) => Promise<void>): Promise<string[]> {
  const origin = new URL(page.url()).origin;
  const visited: string[] = [];
  const seenPaths = new Set<string>();
  const walk = async (depth: number): Promise<void> => {
    await settle(page);
    const here = pathOf(page);
    seenPaths.add(here);
    visited.push(here);
    await visit(page);
    if (depth >= CRAWL_DEPTH) return;
    const hrefs = await page
      .locator('main a[href], aside a[href], header a[href]')
      .evaluateAll((as) =>
        as
          .filter((a) => a instanceof HTMLAnchorElement && a.getClientRects().length > 0 && a.target === '')
          .map((a) => (a as HTMLAnchorElement).href),
      );
    for (const href of hrefs) {
      if (visited.length >= CRAWL_LIMIT) return;
      const u = new URL(href);
      if (u.origin !== origin || !crawlable(u.pathname) || seenPaths.has(u.pathname)) continue;
      seenPaths.add(u.pathname);
      const raw = await page.locator('main a[href], aside a[href], header a[href]').evaluateAll(
        (as, want) => as.findIndex((a) => a instanceof HTMLAnchorElement && a.href === want && a.getClientRects().length > 0),
        href,
      );
      if (raw < 0) continue;
      const from = page.url();
      await page.locator('main a[href], aside a[href], header a[href]').nth(raw).click();
      await page.waitForURL((x) => x.pathname === u.pathname);
      await walk(depth + 1);
      await page.goBack();
      await page.waitForURL((x) => x.href === from);
      await settle(page);
    }
  };
  await walk(0);
  return visited;
}

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------

/** `#rrggbb` as its channels. */
export function hexRgb(hex: string): readonly [number, number, number] {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex.trim());
  if (m === null) throw new Error(`${hex} is not #rrggbb`);
  return [parseInt(m[1] ?? '0', 16), parseInt(m[2] ?? '0', 16), parseInt(m[3] ?? '0', 16)];
}

/** A computed `rgb()` or `rgba()` value as its channels and alpha, or null. */
export function cssRgb(v: string): { readonly rgb: readonly [number, number, number]; readonly alpha: number } | null {
  const m = /^rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:[,\s/]+([\d.]+))?\s*\)$/.exec(v.trim());
  if (m === null) return null;
  return { rgb: [Number(m[1]), Number(m[2]), Number(m[3])], alpha: m[4] === undefined ? 1 : Number(m[4]) };
}

/** The WCAG 2.2 relative luminance of an sRGB colour. */
function luminance(c: readonly [number, number, number]): number {
  const lin = c.map((x) => {
    const s = x / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * (lin[0] ?? 0) + 0.7152 * (lin[1] ?? 0) + 0.0722 * (lin[2] ?? 0);
}

/** The WCAG 2.2 contrast ratio of two colours. */
export function contrast(a: readonly [number, number, number], b: readonly [number, number, number]): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** What a page computes for the tokens and the body colours in one scheme. */
export interface TokenRead {
  readonly tokens: Readonly<Record<string, string>>;
  readonly bodyBg: string;
  readonly htmlBg: string;
  readonly bodyColor: string;
}

/** Reads the tokens of [`TOKENS`] and the body colours, under `scheme`. */
export async function readTokens(page: Page, scheme: Scheme): Promise<TokenRead> {
  await page.emulateMedia({ colorScheme: scheme });
  return page.evaluate((names) => {
    const root = getComputedStyle(document.documentElement);
    const body = getComputedStyle(document.body);
    const tokens: Record<string, string> = {};
    for (const n of names) tokens[n] = root.getPropertyValue(n).trim().toLowerCase();
    return { tokens, bodyBg: body.backgroundColor, htmlBg: root.backgroundColor, bodyColor: body.color };
  }, Object.keys(TOKENS[scheme]));
}

/**
 * The I-70 token problems of the page under `scheme`: a token that is not
 * the sheet's value, a body that is not on `--color-surface-0` with
 * `--color-text-1`, or body text under 4.5:1.
 */
export async function tokenProblems(page: Page, scheme: Scheme, label: string): Promise<string[]> {
  const r = await readTokens(page, scheme);
  const want = TOKENS[scheme];
  const out: string[] = [];
  for (const [name, value] of Object.entries(want)) {
    if (r.tokens[name] !== value) out.push(`${label} (${scheme}): ${name} is "${r.tokens[name] ?? ''}", not ${value}`);
  }
  const bg = cssRgb(r.bodyBg);
  const html = cssRgb(r.htmlBg);
  const ground = bg !== null && bg.alpha > 0 ? bg : html;
  const fg = cssRgb(r.bodyColor);
  if (ground === null || ground.alpha === 0 || fg === null) {
    out.push(`${label} (${scheme}): no body background or text colour (${r.bodyBg}, ${r.htmlBg}, ${r.bodyColor})`);
    return out;
  }
  const surface = hexRgb(want['--color-surface-0']);
  const text = hexRgb(want['--color-text-1']);
  if (ground.rgb.join() !== surface.join()) {
    out.push(`${label} (${scheme}): the page background is rgb(${ground.rgb.join()}), not --color-surface-0`);
  }
  if (fg.rgb.join() !== text.join()) {
    out.push(`${label} (${scheme}): the body text is rgb(${fg.rgb.join()}), not --color-text-1`);
  }
  const ratio = contrast(fg.rgb, ground.rgb);
  if (ratio < 4.5) out.push(`${label} (${scheme}): body text contrast ${ratio.toFixed(2)}:1 is under 4.5:1`);
  return out;
}

// ---------------------------------------------------------------------------
// Status chips
// ---------------------------------------------------------------------------

/**
 * The R-NF-03 chip problems of the page: a chip or badge without text,
 * and a proposal state (`#proposal-state`, or a row with a `data-state`
 * holding a state name) not shown by a `.badge` with text.
 */
export async function chipProblems(page: Page, label: string): Promise<{ problems: string[]; chips: number }> {
  const r = await page.evaluate((states) => {
    const out: string[] = [];
    const chips = Array.from(
      document.querySelectorAll('.badge, .role-chip, [class~="chip"], [class*="status-chip"], [class*="badge--"]'),
    );
    for (const c of chips) {
      if ((c.textContent ?? '').trim() === '') out.push(`a ${c.tagName.toLowerCase()}.${c.className} has no text`);
    }
    const stated = Array.from(document.querySelectorAll('main #proposal-state, main [data-state]')).filter(
      (e) => e.id === 'proposal-state' || states.includes(e.getAttribute('data-state') ?? ''),
    );
    for (const e of stated) {
      const badge = e.matches('.badge') ? e : e.querySelector('.badge');
      const name = e.getAttribute('data-state') ?? e.id;
      if (badge === null) out.push(`the state ${name} is not shown by a .badge`);
      else if ((badge.textContent ?? '').trim() === '') out.push(`the .badge of state ${name} has no text`);
    }
    return { out, chips: document.querySelectorAll('.badge').length };
  }, [...STATE_NAMES]);
  return { problems: r.out.map((p) => `${label}: ${p}`), chips: r.chips };
}

// ---------------------------------------------------------------------------
// Demo tokens
// ---------------------------------------------------------------------------

/** `href` with its fragment token changed in its last character. */
export function forgedToken(href: string): string {
  const u = new URL(href);
  const t = u.hash.slice(1);
  if (t === '') throw new Error(`${href} carries no token in its fragment`);
  const last = t.slice(-1);
  const swap = last === 'A' ? 'B' : last === '0' ? '1' : last === 'a' ? 'b' : 'A';
  u.hash = `${t.slice(0, -1)}${swap}`;
  return u.href;
}

/** `href` with a random token of the same length. */
export function randomToken(href: string): string {
  const u = new URL(href);
  const n = Math.max(1, u.hash.length - 1);
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  u.hash = Array.from(b, (x) => abc[x % abc.length] ?? 'A').join('');
  return u.href;
}
