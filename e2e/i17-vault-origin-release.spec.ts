/**
 * I-17: Judging roles cannot read identity attributes of an applicant
 * before the proposal enters negotiation. M3 design sections 6.5 and
 * 14.4, ADR-009 "Vault origin" and "Releases", `overview.md` (the vault
 * origin, decided 2026-10-28).
 *
 * The browser carries this part: released attributes are shown only on
 * the vault origin `id.<cell host>`, in a document that runs no script,
 * and the application origin cannot read that document by fetch, frame,
 * popup or form. The attributes never travel through the cell origin.
 *
 * The scenario comes from the devstack seeding of design section 6.9: a
 * proposal in NEGOTIATION whose lead's verification and country the vault
 * holds, as canary strings. That claim rests on seeded facts, as section
 * 6.9 requires a test to say.
 */

import { expect, type Page, type Response } from '@playwright/test';
import {
  Control,
  VirtualAuthenticator,
  call,
  enrolByInvite,
  hostOf,
  okJson,
  releaseTicketBody,
  stack,
  test,
  PAGES,
  VAULT_PAGES,
  type CellEndpoints,
  type NegotiationScenario,
} from './playwright.config';

/** Every response a page received, with its body when it has one. */
interface Seen {
  readonly url: string;
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
  readonly navigation: boolean;
}

function record(page: Page): Seen[] {
  const seen: Seen[] = [];
  page.on('response', async (r: Response) => {
    let body = '';
    try {
      body = await r.text();
    } catch {
      // Redirects and aborted loads have no body.
    }
    seen.push({
      url: r.url(),
      status: r.status(),
      headers: r.headers(),
      body,
      navigation: r.request().isNavigationRequest() && r.frame() === page.mainFrame(),
    });
  });
  return seen;
}

/** A release ticket link from `POST /api/v1/vault-tickets` (design 8.7). */
async function releaseTicket(
  page: Page,
  cell: CellEndpoints,
  proposal: string,
): Promise<{ status: number; url: string | null }> {
  const a = await call(page, cell.origin, 'POST', '/api/v1/vault-tickets', releaseTicketBody(proposal));
  if (a.status < 200 || a.status >= 300) {
    return { status: a.status, url: null };
  }
  const url = okJson(a, 'release ticket')['url'];
  if (typeof url !== 'string') throw new Error('release ticket: `url` must be a string');
  return { status: a.status, url };
}

/** The scenario, an enrolled Operations holder and its recorder. */
async function operationsHolder(
  person: () => Promise<Page>,
  control: Control,
): Promise<{ s: NegotiationScenario; ops: Page; seen: Seen[] }> {
  await control.reset();
  const s = await control.negotiation();
  expect(s.released.length, 'the scenario names released canaries').toBeGreaterThan(0);
  const ops = await person();
  const seen = record(ops);
  await VirtualAuthenticator.attach(ops);
  await enrolByInvite(ops, control.cell.origin, s.operations.invite_url);
  return { s, ops, seen };
}

function expectNoCanaryFromCell(seen: Seen[], cell: CellEndpoints, released: readonly string[]): void {
  for (const r of seen) {
    if (new URL(r.url).origin !== cell.origin) continue;
    for (const canary of released) {
      expect(r.body.includes(canary), `cell origin response ${r.url} carries a released attribute`).toBe(
        false,
      );
    }
  }
}

test.describe('I-17 vault origin release', () => {
  test('i17_release_is_shown_only_on_the_vault_origin_with_no_script', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { s, ops, seen } = await operationsHolder(person, control);

    const t = await releaseTicket(ops, cell, s.proposal);
    if (t.url === null) throw new Error(`release ticket refused with ${t.status}`);
    const link = new URL(t.url);
    expect(link.origin).toBe(cell.vault_origin);
    expect(hostOf(link.origin)).toBe(`id.${hostOf(cell.origin)}`);
    expect(link.pathname).toBe(VAULT_PAGES.release);
    expect(link.search, 'the ticket never travels in the query').toBe('');
    expect(link.hash.length, 'the ticket travels in the fragment').toBeGreaterThan(1);

    await ops.goto(t.url);
    for (const canary of s.released) {
      await expect(ops.locator('body')).toContainText(canary);
    }
    expect(new URL(ops.url()).origin).toBe(cell.vault_origin);

    // The document that shows the attributes is a navigation response of
    // the vault origin, under `default-src 'none'`, with no script.
    const shown = seen.filter((r) => r.navigation && s.released.every((c) => r.body.includes(c)));
    expect(shown.length, 'the released fields arrive as a document').toBeGreaterThan(0);
    for (const r of shown) {
      expect(new URL(r.url).origin).toBe(cell.vault_origin);
      expect(r.status).toBe(200);
      expect(r.headers['content-security-policy']).toBe("default-src 'none'");
      expect(r.headers['cache-control'] ?? '').toContain('no-store');
      expect(r.headers['set-cookie']).toBeUndefined();
      expect(r.headers['access-control-allow-origin']).toBeUndefined();
    }
    expect(await ops.evaluate(() => document.scripts.length)).toBe(0);
    expect(await ops.evaluate(() => document.cookie)).toBe('');

    // Every response that carried a released attribute came from the vault.
    for (const r of seen) {
      if (s.released.some((c) => r.body.includes(c))) {
        expect(new URL(r.url).origin).toBe(cell.vault_origin);
      }
    }
    expectNoCanaryFromCell(seen, cell, s.released);
  });

  test('i17_application_origin_cannot_read_the_release', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { s, ops, seen } = await operationsHolder(person, control);
    await ops.goto(`${cell.origin}${PAGES.account}`);

    // fetch in CORS and no-cors mode. The cell CSP may block the request,
    // the vault sends no CORS grant, and a no-cors answer is opaque.
    // Whichever stops it, the page reads nothing.
    for (const mode of ['cors', 'no-cors'] as const) {
      const t = await releaseTicket(ops, cell, s.proposal);
      if (t.url === null) throw new Error(`release ticket refused with ${t.status}`);
      const got = await ops.evaluate(
        async ([u, m]) => {
          const url = new URL(u);
          try {
            const r = await fetch(`${url.origin}${url.pathname}`, {
              method: 'POST',
              body: url.hash.slice(1),
              mode: m,
            });
            const text = await r.text();
            return r.type === 'opaque' && r.status === 0 && text === ''
              ? 'refused opaque'
              : `read ${r.status} ${text}`;
          } catch (e) {
            return `refused ${(e as Error).name}`;
          }
        },
        [t.url, mode] as const,
      );
      expect(got, `fetch in ${mode} mode`).toMatch(/^refused (TypeError|opaque)$/);
    }

    // A frame: the vault refuses framing, and the cell page cannot reach
    // into a cross-origin frame in any case.
    const t3 = await releaseTicket(ops, cell, s.proposal);
    if (t3.url === null) throw new Error(`release ticket refused with ${t3.status}`);
    const framed = await ops.evaluate(async (u) => {
      const f = document.createElement('iframe');
      const loaded = new Promise<void>((resolve) => {
        f.addEventListener('load', () => resolve(), { once: true });
      });
      f.src = u;
      document.body.append(f);
      await loaded;
      try {
        return `read ${f.contentWindow?.document.body.innerText ?? ''}`;
      } catch (e) {
        return `refused ${(e as Error).name}`;
      }
    }, t3.url);
    expect(framed).toBe('refused SecurityError');

    // A popup: cross-origin, so the opener cannot read its document.
    const t4 = await releaseTicket(ops, cell, s.proposal);
    if (t4.url === null) throw new Error(`release ticket refused with ${t4.status}`);
    const popupWait = ops.context().waitForEvent('page');
    const fromOpener = ops.evaluate((u) => {
      const w = window.open(u, '_blank');
      if (w === null) {
        return Promise.resolve('no popup');
      }
      // Polls until the popup leaves its initial same-origin blank page.
      // The test timeout bounds it.
      return new Promise<string>((resolve) => {
        const probe = (): void => {
          if (w.closed) {
            resolve('refused severed');
            return;
          }
          try {
            const text = w.document.body?.innerText ?? '';
            if (w.location.href !== 'about:blank' && text.length > 0) {
              resolve(`read ${text}`);
              return;
            }
          } catch (e) {
            resolve(`refused ${(e as Error).name}`);
            return;
          }
          setTimeout(probe, 20);
        };
        probe();
      });
    }, t4.url);
    const popup = await popupWait;
    for (const canary of s.released) {
      await expect(popup.locator('body')).toContainText(canary);
    }
    expect(new URL(popup.url()).origin).toBe(cell.vault_origin);
    expect(await fromOpener).toMatch(/^refused (SecurityError|severed)$/);

    expectNoCanaryFromCell(seen, cell, s.released);
  });

  test('i17_cell_origin_forms_cannot_post_to_the_vault_origin', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { s, ops, seen } = await operationsHolder(person, control);
    const nav = await ops.goto(`${cell.origin}${PAGES.account}`);
    const csp = nav?.headers()['content-security-policy'] ?? '';
    // Design section 11.2: the cell origin's CSP.
    for (const d of [
      "default-src 'self'",
      "script-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ]) {
      expect(csp.split(';').map((x) => x.trim())).toContain(d);
    }

    const t = await releaseTicket(ops, cell, s.proposal);
    if (t.url === null) throw new Error(`release ticket refused with ${t.status}`);
    const violated = await ops.evaluate((u) => {
      const url = new URL(u);
      return new Promise<string>((resolve) => {
        document.addEventListener(
          'securitypolicyviolation',
          (e) => resolve(e.effectiveDirective),
          { once: true },
        );
        const f = document.createElement('form');
        f.method = 'post';
        f.action = `${url.origin}${url.pathname}`;
        const i = document.createElement('input');
        i.type = 'hidden';
        i.name = 'ticket';
        i.value = url.hash.slice(1);
        f.append(i);
        document.body.append(f);
        f.submit();
      });
    }, t.url);
    expect(violated).toBe('form-action');
    expect(new URL(ops.url()).origin).toBe(cell.origin);
    expectNoCanaryFromCell(seen, cell, s.released);
  });

  test('i17_release_ticket_refused_to_judging_and_before_negotiation', async ({
    person,
    request,
  }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const { s, ops } = await operationsHolder(person, control);

    // Positive control: the Operations holder gets a ticket in NEGOTIATION.
    expect((await releaseTicket(ops, cell, s.proposal)).url).not.toBeNull();
    // Before negotiation, no ticket.
    const early = await releaseTicket(ops, cell, s.ranked_proposal);
    expect(early.url).toBeNull();
    expect(early.status).toBe(403);

    // A Judging role holder gets none, in NEGOTIATION or before.
    const judge = await person();
    await VirtualAuthenticator.attach(judge);
    await enrolByInvite(judge, cell.origin, s.judging.invite_url);
    for (const p of [s.proposal, s.ranked_proposal]) {
      const r = await releaseTicket(judge, cell, p);
      expect(r.url).toBeNull();
      expect(r.status).toBe(403);
    }
  });
});
