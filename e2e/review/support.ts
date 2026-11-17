/**
 * Helpers of the review journey specs (J5 to J8, M4 design section 2.2).
 *
 * The specs reach the e2e cell through the stack manifest that
 * `playwright.config.ts` reads (`FSTP_E2E_STACK`). They reuse its M3
 * helpers for enrolment, same-origin calls and the virtual
 * authenticator. Without a stack, every journey spec fails at its first
 * step with `StackMissing`, which names the missing piece. No spec is
 * skipped.
 *
 * Refusals are checked as M3's specs check them: each one is paired with
 * an accepted request over the same wire, so a route that refuses
 * everything, or a body the cell cannot decode, cannot pass.
 */

import { expect, type APIRequestContext, type Page, type Request, type Response } from '@playwright/test';
import {
  type Answer,
  type CellEndpoints,
  Control,
  StackMissing,
  VirtualAuthenticator,
  call,
  enrolByInvite,
  pageCdp,
  stack,
} from '../playwright.config';
import {
  REVIEW_SCENARIO_ROUTE,
  REVIEW_UI,
  type PersonaKey,
  type ProposalKey,
  type ReviewScenario,
  type ReviewStage,
  type SeededProposal,
} from './contract';

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const PERSONAS: readonly PersonaKey[] = ['c1', 'r1', 'r2', 'r3', 'r4', 'h1', 'i1', 'i2'];

/** Checks the parts of the scenario every spec relies on. */
function scenarioOf(v: unknown, stage: ReviewStage): ReviewScenario {
  const fail = (what: string): never => {
    throw new StackMissing(`review scenario ${stage}: ${what}`);
  };
  if (!isObject(v)) return fail('expected a JSON object');
  for (const k of ['programme', 'call', 'content_canary'] as const) {
    if (typeof v[k] !== 'string' || v[k] === '') fail(`\`${k}\` must be a non-empty string`);
  }
  const people = v['people'];
  if (!isObject(people)) return fail('`people` is missing');
  for (const p of PERSONAS) {
    const one = people[p];
    if (!isObject(one) || typeof one['invite_url'] !== 'string' || typeof one['label'] !== 'string') {
      fail(`people.${p} needs \`invite_url\` and \`label\``);
    }
  }
  if (!Array.isArray(v['criteria']) || v['criteria'].length === 0) fail('`criteria` is empty');
  if (!Array.isArray(v['identity_canaries']) || v['identity_canaries'].length === 0) {
    fail('`identity_canaries` is empty, so the I-17 scans would prove nothing');
  }
  if (!isObject(v['proposals'])) fail('`proposals` is missing');
  return v as unknown as ReviewScenario;
}

/** The e2e cell's control routes, with the review scenario of this lane. */
export class ReviewControl extends Control {
  /** `POST /test/scenario/review {stage}`, after a reset of the cell. */
  async review(stage: ReviewStage): Promise<ReviewScenario> {
    await this.reset();
    const r = await this.requestContext.post(`${this.cell.control}${REVIEW_SCENARIO_ROUTE}`, {
      data: { stage },
    });
    if (!r.ok()) {
      throw new StackMissing(`devstack control review scenario ${stage} answered ${r.status()}`);
    }
    return scenarioOf(await r.json(), stage);
  }

  constructor(
    readonly requestContext: APIRequestContext,
    cell: CellEndpoints,
  ) {
    super(requestContext, cell);
  }
}

/** A seeded cell and its scenario at `stage`. */
export interface Seeded {
  readonly cell: CellEndpoints;
  readonly control: ReviewControl;
  readonly s: ReviewScenario;
}

/** Resets cell `a` and seeds the review scenario at `stage`. */
export async function seed(request: APIRequestContext, stage: ReviewStage): Promise<Seeded> {
  const cell = stack().cells.a;
  const control = new ReviewControl(request, cell);
  const s = await control.review(stage);
  return { cell, control, s };
}

/** A proposal the stage must hold. */
export function proposal(s: ReviewScenario, key: ProposalKey): SeededProposal {
  const p = s.proposals[key];
  if (p === undefined) throw new StackMissing(`review scenario: proposal ${key} is missing`);
  return p;
}

/** The reviewer assignment of `who` on proposal `key`. */
export function assignmentOf(s: ReviewScenario, key: ProposalKey, who: PersonaKey): string {
  const a = proposal(s, key).assignments[who];
  if (a === undefined) throw new StackMissing(`review scenario: ${who} is not assigned to ${key}`);
  return a;
}

/** The IRC assignment of `who` on proposal `key`. */
export function ircAssignmentOf(s: ReviewScenario, key: ProposalKey, who: PersonaKey): string {
  const a = proposal(s, key).irc_assignments[who];
  if (a === undefined) throw new StackMissing(`review scenario: ${who} has no IRC case on ${key}`);
  return a;
}

// ---------------------------------------------------------------------------
// People
// ---------------------------------------------------------------------------

/**
 * A persona in its own browser context, signed in with a passkey that it
 * enrolled from its invitation link.
 */
export async function signIn(
  person: () => Promise<Page>,
  seeded: Seeded,
  who: PersonaKey,
): Promise<Page> {
  const page = await person();
  await VirtualAuthenticator.attach(page);
  await enrolByInvite(page, seeded.cell.origin, seeded.s.people[who].invite_url);
  return page;
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/** Roles of controls, which need an accessible name (R-NF-03). */
const CONTROL_ROLES = new Set([
  'button', 'link', 'textbox', 'checkbox', 'radio', 'combobox', 'listbox', 'option', 'spinbutton',
]);

interface AxNode {
  ignored?: boolean;
  role?: { value?: unknown };
  name?: { value?: unknown };
}

/**
 * The in-house R-NF-03 structure checks of design section 8.7 that hold
 * on every page: a language, a title, one `main` landmark, an `h1`, no
 * positive tabindex, and an accessible name on every control as
 * Chromium computes it.
 */
export async function expectStructure(page: Page, label: string): Promise<void> {
  const problems: string[] = [];
  const doc = await page.evaluate(() => ({
    lang: document.documentElement.lang,
    title: document.title.trim(),
    mains: document.querySelectorAll('main, [role="main"]').length,
    headings: document.querySelectorAll('h1').length,
    positive: Array.from(document.querySelectorAll('[tabindex]')).filter(
      (e) => Number(e.getAttribute('tabindex')) > 0,
    ).length,
  }));
  if (doc.lang === '') problems.push('no document language');
  if (doc.title === '') problems.push('no title');
  if (doc.mains !== 1) problems.push(`${doc.mains} main landmarks, not 1`);
  if (doc.headings < 1) problems.push('no h1');
  if (doc.positive > 0) problems.push('a positive tabindex');
  const cdp = await pageCdp(page);
  const { nodes } = (await cdp.send('Accessibility.getFullAXTree')) as { nodes: AxNode[] };
  for (const n of nodes) {
    const role = typeof n.role?.value === 'string' ? n.role.value : '';
    if (n.ignored === true || !CONTROL_ROLES.has(role)) continue;
    const name = typeof n.name?.value === 'string' ? n.name.value.trim() : '';
    if (name === '') problems.push(`a ${role} has no accessible name`);
  }
  expect(problems, `R-NF-03 structure of ${label}`).toEqual([]);
}

/** Opens `path` on the cell origin, waits for its main landmark, and checks its structure. */
export async function openPage(page: Page, origin: string, path: string): Promise<void> {
  await page.goto(`${origin}${path}`);
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0);
  await expectStructure(page, path);
}

/** The state tag the page shows for its proposal. */
export async function expectState(page: Page, tag: string): Promise<void> {
  await expect(page.locator(REVIEW_UI.state)).toHaveAttribute('data-state', tag);
}

/**
 * A field error tied to its field (R-NF-03): the control is marked
 * invalid and described by a visible message.
 */
export async function expectFieldError(page: Page, control: string): Promise<void> {
  const c = page.locator(control);
  await expect(c).toHaveAttribute('aria-invalid', 'true');
  const ids = ((await c.getAttribute('aria-describedby')) ?? '').split(/\s+/).filter((x) => x !== '');
  expect(ids.length, `${control} is described by its error`).toBeGreaterThan(0);
  const texts = await Promise.all(
    ids.map((id) => page.locator(`[id="${id}"]`).innerText().catch(() => '')),
  );
  expect(texts.some((t) => t.trim() !== ''), `${control} has a visible error message`).toBe(true);
}

// ---------------------------------------------------------------------------
// Writes the page makes
// ---------------------------------------------------------------------------

/** Whether `r` is a state-changing API request whose path matches `path`. */
function isWrite(r: Request, path: RegExp): boolean {
  return r.method() !== 'GET' && path.test(new URL(r.url()).pathname);
}

/** Records every state-changing API request of `page` to a path matching `path`. */
export function watchWrites(page: Page, path: RegExp): { readonly seen: () => number } {
  let n = 0;
  page.on('request', (r) => {
    if (isWrite(r, path)) n += 1;
  });
  return { seen: () => n };
}

/**
 * How long after its click a write must have left the page. The pages
 * send a write straight from the click handler, so this bounds only a
 * click that sends nothing, not the cell's answer.
 */
const WRITE_SENT_WITHIN_MS = 10_000;

/**
 * Clicks `selector` and returns the status of the write it makes to `path`.
 *
 * A click can legitimately send nothing: the page refused the form before
 * any request, or a re-render reset a control the step chose before it
 * (CI runs 44100079149, 44100123474). Such a click fails here within
 * `WRITE_SENT_WITHIN_MS` and names the page's alerts and field errors,
 * instead of waiting for a response until the test timeout.
 */
export async function clickWrite(page: Page, selector: string, path: RegExp): Promise<number> {
  let found: (r: Request) => void = () => undefined;
  const first = new Promise<Request>((resolve) => {
    found = resolve;
  });
  const onRequest = (r: Request): void => {
    if (isWrite(r, path)) found(r);
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  let sent: Request | null;
  page.on('request', onRequest);
  try {
    await page.locator(selector).click();
    const late = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), WRITE_SENT_WITHIN_MS);
    });
    sent = await Promise.race([first, late]);
  } finally {
    clearTimeout(timer);
    page.off('request', onRequest);
  }
  if (sent === null) {
    const shown = await page
      .locator('[role="alert"], [aria-invalid="true"]')
      .evaluateAll((es) =>
        es.map((e) => `${e.id === '' ? e.tagName.toLowerCase() : `#${e.id}`}: ${(e.textContent ?? '').trim()}`),
      )
      .catch(() => [] as string[]);
    throw new Error(
      `clicking ${selector} sent no write to ${path} within ${WRITE_SENT_WITHIN_MS / 1000} s; ` +
        `the page shows: ${shown.length === 0 ? 'no alert and no field error' : shown.join(' | ')}`,
    );
  }
  const res = await sent.response();
  if (res === null) throw new Error(`the write ${sent.method()} ${new URL(sent.url()).pathname} got no response`);
  return res.status();
}

/** A write the page made, captured and stopped before it reached the cell. */
export interface CapturedWrite {
  readonly method: 'POST' | 'PUT' | 'DELETE';
  readonly path: string;
  readonly body: string;
}

/**
 * Runs `act` and captures the first state-changing API request to `path`
 * that it makes. The request is aborted, so the cell never sees it.
 */
export async function captureWrite(
  page: Page,
  path: RegExp,
  act: () => Promise<void>,
): Promise<CapturedWrite> {
  const box: { w: CapturedWrite | null } = { w: null };
  await page.route('**/api/v1/**', async (route) => {
    const r = route.request();
    const method = r.method();
    if (box.w === null && isWrite(r, path) && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
      box.w = { method, path: new URL(r.url()).pathname, body: r.postData() ?? '' };
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  await act();
  await expect.poll(() => box.w !== null, { message: `a write to ${path}` }).toBe(true);
  await page.unroute('**/api/v1/**');
  const w = box.w;
  if (w === null) throw new Error(`no write to ${path}`);
  return w;
}

/**
 * Sends a captured write again from `page`, byte for byte, with the
 * session of whoever `page` belongs to and the CSRF header of ADR-014.
 */
export async function replay(page: Page, origin: string, w: CapturedWrite): Promise<Answer> {
  expect(new URL(page.url()).origin).toBe(origin);
  return page.evaluate(
    async ([m, p, b]) => {
      const init: RequestInit = {
        method: m,
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-fstp-request': '1' },
      };
      if (b !== '') init.body = b;
      const r = await fetch(p, init);
      return { status: r.status, body: await r.text() };
    },
    [w.method, w.path, w.body] as const,
  );
}

/** A GET of an API path from `page`. */
export function apiGet(page: Page, origin: string, path: string): Promise<Answer> {
  return call(page, origin, 'GET', path);
}

/**
 * A refusal as design section 3.7 shows `ApiError`: a 4xx with the body
 * `{"code": "...", "rule": "..."}` and nothing else. It names the rule
 * only, never an account. When `rule` is given, the refusal names it.
 */
export function expectRefusal(a: Answer, what: string, rule?: string): void {
  expect(a.status, `${what}: ${a.body}`).toBeGreaterThanOrEqual(400);
  expect(a.status, `${what}: ${a.body}`).toBeLessThan(500);
  let v: unknown;
  try {
    v = JSON.parse(a.body);
  } catch {
    throw new Error(`${what}: the refusal body is not JSON: ${a.body}`);
  }
  if (!isObject(v)) throw new Error(`${what}: the refusal body is not an object: ${a.body}`);
  expect(Object.keys(v).sort(), `${what}: refusal members`).toEqual(['code', 'rule']);
  expect(typeof v['code'] === 'string' && v['code'] !== '', `${what}: refusal code`).toBe(true);
  expect(typeof v['rule'], `${what}: the refusal names its rule`).toBe('string');
  if (rule !== undefined) expect(v['rule'], `${what}: refusal rule`).toBe(rule);
}

/** An accepted call. */
export function expectAccepted(a: Answer, what: string): void {
  expect(a.status, `${what}: ${a.body}`).toBeGreaterThanOrEqual(200);
  expect(a.status, `${what}: ${a.body}`).toBeLessThan(300);
}

// ---------------------------------------------------------------------------
// Canaries (I-17, R-IR-03)
// ---------------------------------------------------------------------------

/** The API response bodies a page received, as `watchResponses` collects them. */
export interface WatchedResponses {
  readonly bodies: () => readonly string[];
  /** Waits until every body seen so far has been read. */
  readonly settle: () => Promise<void>;
}

/**
 * Every API response body `page` receives, for the canary scans.
 *
 * A body is read once its request has finished, so the whole body is in
 * the browser, as `applicant/support.ts` `Traffic` does. Reading on
 * 'response' could still be pending when a scan ran, so the scan missed
 * that body, or could wait forever on a body a navigation cut short. A
 * later navigation can evict a finished body before it is read ("No
 * resource with given identifier"). Such a body is skipped, as before.
 */
export function watchResponses(page: Page): WatchedResponses {
  const bodies: string[] = [];
  const pending: Promise<void>[] = [];
  const unread = new Set<string>();
  page.on('requestfinished', (q: Request) => {
    const path = new URL(q.url()).pathname;
    if (!path.startsWith('/api/v1/')) return;
    const label = `${q.method()} ${path}`;
    unread.add(label);
    pending.push(
      q.response().then(
        async (r: Response | null) => {
          const body = r === null ? null : await r.text().catch(() => null);
          if (body !== null) bodies.push(body);
          unread.delete(label);
        },
        () => {
          unread.delete(label);
        },
      ),
    );
  });
  const settle = async (): Promise<void> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`response bodies still unread after 20 s: ${[...unread].join(', ')}`)),
        20_000,
      );
    });
    try {
      await Promise.race([Promise.all(pending), late]);
    } finally {
      clearTimeout(timer);
    }
  };
  return { bodies: () => bodies, settle };
}

/**
 * No canary appears in the page: its serialised DOM, its title, the
 * values of its form controls, or any API response it received.
 */
export async function expectNoCanary(
  page: Page,
  canaries: readonly string[],
  label: string,
  responses?: WatchedResponses,
): Promise<void> {
  expect(canaries.length, `${label}: the scan has canaries`).toBeGreaterThan(0);
  // Every body the page received so far is in the scan, not only those
  // whose read happened to finish first.
  await responses?.settle();
  const seen = await page.evaluate(() => {
    const values = Array.from(document.querySelectorAll('input, textarea, select')).map(
      (e) => (e as HTMLInputElement).value,
    );
    return [document.documentElement.outerHTML, document.title, ...values].join('\n');
  });
  const all = [seen, ...(responses?.bodies() ?? [])].join('\n');
  const found = canaries.filter((c) => c !== '' && all.includes(c));
  expect(found, `${label}: canaries on the page or in its responses`).toEqual([]);
}
