/**
 * Helpers of the speedrun specs (M5 design sections 1.2 and 7, lane
 * L-DEMO). Every person signs in by the "Sign in as" link of the demo
 * page, as a person at the demo would. Test only: the cell is the
 * test-only binary of layering rule A9. Every person and text is
 * synthetic.
 *
 * The API steps use the pages' own wire: same-origin calls with the
 * session cookie, the CSRF header and canonical JSON, and the demo
 * step-up (`POST /auth/stepup` with `demo: true`) when a high-risk call
 * asks for it (I-78). The UI steps, which need the post-grant screens of
 * lane m5/ui, live in `speedrun.ui.spec.ts`.
 */

import { expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { call, canonicalJson, type Answer } from '../playwright.config';
import { FrontDoor, suiteCell } from '../site/contract';
import type { CellEndpoints } from '../creator/contract';

/** The persons of the post-grant scenes, by their front-door names (`postgrant.rs`). */
export const WHO = {
  lead: /Lead applicant X/,
  pm: /Programme manager M1/,
  reviewer: /Committee member R1/,
  coordinator: /Coordinator C1/,
  finance: /Finance approver F1/,
  releaser: /Payment releaser P1/,
  signatory: /Contract signatory S1/,
  auditor: /Auditor A1/,
  reportApprover: /Report approver \(Financial signatory\) F2/,
} as const;

/** Proposal x of the seeds. */
export const X = '1001';

/** The API base of the cell. */
export const V1 = '/api/v1';

/** The scenes of `GET /demo/grant?at=`. */
export type GrantScene =
  | 'NEGOTIATION_READY'
  | 'SENT'
  | 'EFFECTIVE'
  | 'IN_EXECUTION'
  | 'UNDER_REVIEW'
  | 'PAID'
  | 'ALL_CLOSED'
  | 'HARDSHIP';

/** One person, signed in by the front door's link, in a context of their own. */
export class Seat {
  private constructor(
    readonly context: BrowserContext,
    readonly page: Page,
    readonly cell: CellEndpoints,
  ) {}

  /** Opens the front door, reads the "Sign in as" link of `who` and follows it. */
  static async signIn(browser: Browser, cell: CellEndpoints, who: RegExp): Promise<Seat> {
    const door = await FrontDoor.open(browser, cell);
    let href: string;
    try {
      const link = door.signIn(who);
      await expect(link, `the front door offers "Sign in as" for ${who.source}`).toHaveCount(1);
      href = new URL((await link.getAttribute('href')) ?? '', cell.control).href;
    } finally {
      await door.close();
    }
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(href);
    await page.waitForURL((u) => u.origin === cell.origin && u.pathname === '/app/');
    return new Seat(context, page, cell);
  }

  /** One API call as this person. A high-risk call is confirmed once with the demo step-up (I-78). */
  async api(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Answer> {
    const url = `${V1}${path}`;
    let a = await call(this.page, this.cell.origin, method, url, method === 'GET' ? undefined : (body ?? {}));
    if (a.status !== 200 && a.body.includes('step_up_required')) {
      const id = (JSON.parse(a.body) as { challenge: { challenge_id: string } }).challenge.challenge_id;
      const s = await call(this.page, this.cell.origin, 'POST', '/auth/stepup', { challenge_id: id, demo: true });
      expect(s.status, `the demo step-up: ${s.body}`).toBe(200);
      a = await call(this.page, this.cell.origin, method, url, method === 'GET' ? undefined : (body ?? {}));
    }
    return a;
  }

  /** An API call that must succeed, with its JSON body. */
  async ok(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Record<string, unknown>> {
    const a = await this.api(method, path, body);
    expect(a.status, `${method} ${path}: ${a.body}`).toBe(200);
    return a.body === '' ? {} : (JSON.parse(a.body) as Record<string, unknown>);
  }

  /** An API call that the cell must refuse. */
  async refused(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Answer> {
    const a = await this.api(method, path, body);
    expect(a.status, `${method} ${path} must be refused: ${a.body}`).toBeGreaterThanOrEqual(400);
    return a;
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}

/** Opens the front door and chooses a post-grant scene by its link. */
export async function chooseGrantScene(browser: Browser, scene: GrantScene): Promise<CellEndpoints> {
  const cell = suiteCell();
  const door = await FrontDoor.open(browser, cell);
  try {
    await door.chooseScene(`/demo/grant?at=${scene}`);
  } finally {
    await door.close();
  }
  return cell;
}

/** Follows one demo-page link, such as a clock link, as a person at the demo does. */
export async function demoLink(browser: Browser, cell: CellEndpoints, href: string): Promise<void> {
  const door = await FrontDoor.open(browser, cell);
  try {
    await door.chooseScene(href);
  } finally {
    await door.close();
  }
}

/** Waits until `read` returns a value that `done` accepts, polling the cell (never a fixed sleep). */
export async function until<T>(what: string, read: () => Promise<T>, done: (v: T) => boolean): Promise<T> {
  await expect
    .poll(async () => done(await read()), { message: what, timeout: 30_000, intervals: [250, 500, 1000] })
    .toBe(true);
  return read();
}

export { canonicalJson };
