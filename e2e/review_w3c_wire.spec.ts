/**
 * Review reproducers for lane w3c: the shared spec helpers must speak the
 * cell's real body forms (M3 design sections 8.4 and 8.7, R-LG-03, I-78).
 *
 * The cell refuses every route body that is not its RFC 8785 canonical
 * text (`fstp-cell` `http::body`), and its step-up options reply is
 * `{challenge_id, public_key}` (`routes::auth::stepup_options`). These
 * tests need no stack: a routed origin records what the helpers send.
 */

import { expect, test, type Page } from '@playwright/test';
import { sendCommand, stepUp } from './playwright.config';

const ORIGIN = 'https://a.fstp.test';

/** RFC 8785 member order for the values these helpers send. */
function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
    .join(',')}}`;
}

/** Serves a blank page on ORIGIN and records each POST body by path. */
async function fakeCell(page: Page, reply: (path: string) => unknown): Promise<Map<string, string>> {
  const bodies = new Map<string, string>();
  await page.route(`${ORIGIN}/**`, async (route) => {
    const r = route.request();
    const path = new URL(r.url()).pathname;
    if (r.method() === 'GET') {
      await route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>x</title>' });
      return;
    }
    bodies.set(path, r.postData() ?? '');
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reply(path)) });
  });
  await page.goto(`${ORIGIN}/auth/account`);
  return bodies;
}

test('review_r_lg_03_send_command_body_is_canonical', async ({ page }) => {
  const bodies = await fakeCell(page, () => ({}));
  await sendCommand(page, ORIGIN, { core: { type: 'X' } }, { command_id: '00'.repeat(16), stepup: '11'.repeat(16) });
  const sent = bodies.get('/api/v1/commands') ?? '';
  expect(sent).toBe(canonical(JSON.parse(sent)));
});

test('review_i78_stepup_options_body_is_canonical', async ({ page }) => {
  const bodies = await fakeCell(page, () => ({ stepup: '22'.repeat(16), publicKey: {} }));
  await stepUp(page, ORIGIN, { core: { type: 'X' } }).catch(() => undefined);
  const sent = bodies.get('/auth/stepup/options') ?? '';
  expect(sent).toBe(canonical(JSON.parse(sent)));
});

test('review_i78_stepup_helper_reads_the_cell_options_reply', async ({ page }) => {
  // The cell's reply shape. A short WebAuthn timeout ends the ceremony,
  // since no authenticator is attached.
  await fakeCell(page, () => ({
    challenge_id: '33'.repeat(16),
    public_key: { challenge: 'AAAAAAAAAAAAAAAAAAAAAA', rpId: 'a.fstp.test', timeout: 500, userVerification: 'required' },
  }));
  const err = await stepUp(page, ORIGIN, { core: { type: 'X' } }).then(
    () => '',
    (e: unknown) => String(e),
  );
  expect(err).not.toContain('`stepup` must be a lowercase hex id');
});
