/**
 * The MCP endpoints of the e2e cell (lane W3c scope items 3 to 5, M4
 * design section 3.8, ADR-013), driven against the lane's own cell.
 *
 * - i87_mcp_public_lists_the_open_call (I-87, R-PB-01): an MCP client
 *   with no credential opens a session on `/mcp/public` at the floor
 *   revision 2025-06-18, lists only the public tools, and reads the
 *   seeded open call through `fstp_public_list_open_calls`. The call's
 *   title is in `structuredContent.data`, classified public, and never in
 *   the `content` sentence (TH-60).
 * - adr013_mcp_public_get_answers_405 (H-23): `GET` on `/mcp/public`
 *   answers 405, so no server stream exists.
 * - adr013_mcp_without_token_gets_401_challenge (RFC 9728): a POST to
 *   `/mcp` with no token gets 401 with a Bearer challenge naming the
 *   protected resource metadata, and that document names the cell's MCP
 *   URL.
 *
 * The requests run inside a page on the cell origin, so they reach the
 * cell through the stack's resolver rules and TLS pins, and carry the
 * cell's own `Origin`, which the server accepts. The context bypasses
 * the public page's CSP so the test can fetch from it. Every call and
 * text is synthetic.
 *
 * Status: red until the e2e cell serves `/mcp` and `/mcp/public`.
 */

import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { ApplicantControl } from '../applicant/support';
import { FrontDoor, SITE, suiteCell } from '../site/contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The floor revision of ADR-013, which the lane scope serves. */
const FLOOR = '2025-06-18';

/** One HTTP exchange made from the page. */
interface Exchange {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/** Sends `method` to `path` from the page, with `headers` and `body`. */
async function exchange(
  page: Page,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string | null,
): Promise<Exchange> {
  return page.evaluate(
    async ({ method, path, headers, body }) => {
      const init: RequestInit = { method, headers, credentials: 'omit' };
      if (body !== null) init.body = body;
      const r = await fetch(path, init);
      const h: Record<string, string> = {};
      r.headers.forEach((v, k) => {
        h[k] = v;
      });
      return { status: r.status, headers: h, body: await r.text() };
    },
    { method, path, headers, body },
  );
}

/** A JSON-RPC POST to `path` with `extra` headers. */
function rpc(page: Page, path: string, message: unknown, extra: Record<string, string> = {}): Promise<Exchange> {
  return exchange(
    page,
    'POST',
    path,
    { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...extra },
    JSON.stringify(message),
  );
}

/** The parsed JSON body of `x`. */
function json(x: Exchange): Record<string, unknown> {
  const v: unknown = JSON.parse(x.body);
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error(`not an object: ${x.body}`);
  return v as Record<string, unknown>;
}

/** The object member `k` of `o`. */
function member(o: unknown, k: string): Record<string, unknown> {
  const v = (o as Record<string, unknown> | null)?.[k];
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error(`no object ${k}`);
  return v as Record<string, unknown>;
}

/** Opens a page on the cell's public open calls page and returns it with the programme slug. */
async function publicPage(
  browser: import('@playwright/test').Browser,
  request: import('@playwright/test').APIRequestContext,
): Promise<{ page: Page; slug: string; title: string; close: () => Promise<void> }> {
  const cell = suiteCell();
  const control = new ApplicantControl(request, cell);
  await control.reset();
  const s = await control.scenario('OPEN_CALL');
  const door = await FrontDoor.open(browser, cell);
  let href: string;
  try {
    href = (await door.page.locator(SITE.demo.publicCalls).getAttribute('href')) ?? '';
  } finally {
    await door.close();
  }
  const u = new URL(href, cell.control);
  const m = /^\/p\/([^/]+)(?:\/calls)?\/?$/.exec(u.pathname);
  expect(m, `the public calls link ${u.pathname} names a programme`).not.toBeNull();
  const context = await browser.newContext({ bypassCSP: true });
  const page = await context.newPage();
  const r = await page.goto(u.href);
  expect(r?.status()).toBe(200);
  return { page, slug: decodeURIComponent(m?.[1] ?? ''), title: s.call.title, close: () => context.close() };
}

test.describe('MCP endpoints of the cell', () => {
  /**
   * I-87, R-PB-01, TH-60, TH-63: the public tools through `/mcp/public`
   * with no credential show the seeded open call, as the public page does.
   */
  test('i87_mcp_public_lists_the_open_call', async ({ browser, request }) => {
    const { page, slug, title, close } = await publicPage(browser, request);
    try {
      const init = await rpc(page, '/mcp/public', {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: FLOOR, capabilities: {}, clientInfo: { name: 'synthetic-e2e', version: '0' } },
      });
      expect(init.status, init.body).toBe(200);
      const result = member(json(init), 'result');
      expect(result['protocolVersion']).toBe(FLOOR);
      expect(result['instructions'], 'no instructions (TH-63)').toBeUndefined();
      const session = init.headers['mcp-session-id'] ?? '';
      expect(session, 'an Mcp-Session-Id').not.toBe('');
      const h = { 'mcp-session-id': session, 'mcp-protocol-version': FLOOR };
      const done = await rpc(page, '/mcp/public', { jsonrpc: '2.0', method: 'notifications/initialized' }, h);
      expect(done.status).toBe(202);

      const list = await rpc(page, '/mcp/public', { jsonrpc: '2.0', id: 2, method: 'tools/list' }, h);
      expect(list.status, list.body).toBe(200);
      const tools = member(json(list), 'result')['tools'];
      expect(Array.isArray(tools)).toBe(true);
      const names = (tools as { name?: unknown }[]).map((t) => String(t.name));
      expect(names).toContain('fstp_public_list_open_calls');
      for (const n of names) expect(n, 'only public tools on /mcp/public').toMatch(/^fstp_public_/);

      const call = await rpc(
        page,
        '/mcp/public',
        { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'fstp_public_list_open_calls', arguments: { slug } } },
        h,
      );
      expect(call.status, call.body).toBe(200);
      const r = member(json(call), 'result');
      expect(r['isError'] ?? false).toBe(false);
      const sc = member(r, 'structuredContent');
      expect(sc['classification']).toBe('public');
      expect(JSON.stringify(sc['data']), 'the open call is in the data').toContain(title);
      expect(JSON.stringify(r['content']), 'TH-60: no data in the content sentence').not.toContain(title);
    } finally {
      await close();
    }
  });

  /** H-23: no server-initiated stream exists. */
  test('adr013_mcp_public_get_answers_405', async ({ browser, request }) => {
    const { page, close } = await publicPage(browser, request);
    try {
      const r = await exchange(page, 'GET', '/mcp/public', { accept: 'text/event-stream' }, null);
      expect(r.status).toBe(405);
    } finally {
      await close();
    }
  });

  /** RFC 9728, ADR-013: the missing-token challenge and the metadata it names. */
  test('adr013_mcp_without_token_gets_401_challenge', async ({ browser, request }) => {
    const { page, close } = await publicPage(browser, request);
    try {
      const r = await rpc(page, '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
      expect(r.status).toBe(401);
      const origin = new URL(page.url()).origin;
      const meta = `${origin}/.well-known/oauth-protected-resource`;
      expect(r.headers['www-authenticate'] ?? '').toContain(`resource_metadata="${meta}"`);
      const doc = await exchange(page, 'GET', '/.well-known/oauth-protected-resource', {}, null);
      expect(doc.status).toBe(200);
      expect(json(doc)['resource']).toBe(`${origin}/mcp`);
    } finally {
      await close();
    }
  });
});
