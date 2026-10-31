/**
 * Review reproducers for lane W4a: the creator, onboarding and people
 * pages (M4 design sections 2.2 J0 to J2, 3.5 and 3.9).
 *
 * The browser tests need no stack. They compile `web/src` with tsc into a
 * temporary directory and serve it on a routed origin. The routed origin
 * replaces the W0 stub `gen/api.js` with a small operation table and
 * answers each API call from a fake that records the request bodies.
 * The fake answers in the `fstp-tenant` codec form, the form the pages
 * state that they send and read (`web/src/onboarding/pages/settings.ts`).
 *
 * Each test fails against the code under review and passes once the
 * defect it names is fixed.
 */

import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, normalize } from 'node:path';

const ORIGIN = 'https://a.fstp.test';
const WEB = join(__dirname, '..', '..', 'web');

/** The operations these tests reach, as the generated table would list them. */
const OPS: readonly (readonly [string, string, string])[] = [
  ['tenant.settings', 'GET', '/api/v1/admin/settings'],
  ['tenant.set_login_methods', 'PUT', '/api/v1/admin/settings/login-methods'],
  ['tenant.set_mcp', 'PUT', '/api/v1/admin/settings/mcp'],
  ['tenant.get_step', 'GET', '/api/v1/admin/onboarding/{step}'],
  ['tenant.save_step', 'PUT', '/api/v1/admin/onboarding/{step}'],
  ['people.get_invitation', 'GET', '/api/v1/invitations/{invitation}'],
  ['people.accept_invitation', 'POST', '/api/v1/invitations/{invitation}/accept'],
];

const GEN_API = `export const OPERATIONS = ${JSON.stringify(OPS.map(([name, method, path]) => ({ name, method, path })))};\n`;

const SHELL =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title></title>' +
  '<script type="module" src="/assets/creator/main.js"></script></head><body></body></html>';

const ONBOARDING = [
  'organisation',
  'agreements',
  'branding',
  'domains_and_email',
  'identity',
  'inference',
  'payments',
  'channels',
  'administrators',
] as const;

let dist = '';

test.describe.configure({ timeout: 180_000 });

test.beforeAll(() => {
  dist = mkdtempSync(join(tmpdir(), 'fstp-review-w4a-'));
  execFileSync(join(WEB, 'node_modules', '.bin', 'tsc'), ['-p', join(WEB, 'tsconfig.json'), '--outDir', dist], {
    stdio: 'pipe',
  });
});

test.afterAll(() => {
  if (dist !== '') rmSync(dist, { recursive: true, force: true });
});

/** One API request the fake received. */
interface Sent {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
}

/**
 * Serves the compiled pages on ORIGIN. `api` answers each API call with
 * a status and a JSON body. Every request with a body is recorded.
 */
async function cell(page: Page, api: (method: string, path: string, body: unknown) => [number, unknown]): Promise<Sent[]> {
  const sent: Sent[] = [];
  await page.route(`${ORIGIN}/**`, async (route) => {
    const r = route.request();
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/app/')) {
      await route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: SHELL });
      return;
    }
    if (path === '/assets/gen/api.js') {
      await route.fulfill({ status: 200, contentType: 'text/javascript', body: GEN_API });
      return;
    }
    if (path.startsWith('/assets/')) {
      const file = normalize(join(dist, path.slice('/assets/'.length)));
      if (!file.startsWith(dist) || !existsSync(file)) {
        await route.fulfill({ status: 404, contentType: 'text/plain', body: 'no' });
        return;
      }
      await route.fulfill({ status: 200, contentType: 'text/javascript', body: readFileSync(file) });
      return;
    }
    if (path === '/auth/sessions') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{"sessions":[]}' });
      return;
    }
    const raw = r.postData();
    const body: unknown = raw === null || raw === '' ? undefined : JSON.parse(raw);
    if (body !== undefined) sent.push({ method: r.method(), path, body });
    const [status, out] = api(r.method(), path, body);
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(out) });
  });
  return sent;
}

/** Whether `xs` is a strictly ascending list of strings, as `fstp-tenant` `take_name_set` requires. */
function strictlyAscending(xs: unknown): boolean {
  if (!Array.isArray(xs)) return false;
  for (let i = 1; i < xs.length; i += 1) {
    if (!(String(xs[i - 1]) < String(xs[i]))) return false;
  }
  return true;
}

/** The settings of a tenant, in the `fstp-tenant` codec form (`codec.rs` `setting`). */
function settings(p70: string[], p74: unknown): Record<string, unknown> {
  return {
    p20: 'record_only',
    p69: 'MIT',
    p70,
    p71: '300000000',
    p72: { absolute_us: '43200000000', idle_us: '1800000000' },
    p74,
  };
}

test.describe('W4a review reproducers', () => {
  /**
   * R-LG-03, P-70: the codec decodes a set of login methods with
   * `take_name_set`, which refuses a list that is not strictly
   * ascending. The page sends the methods in the order of
   * `LOGIN_METHODS` with passkey first, so passkey and email links go out
   * as `["passkey","magic_link"]` and every second method is refused.
   */
  test('review_p70_login_methods_are_sent_strictly_ascending', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      if (method === 'GET' && path === '/api/v1/admin/settings') return [200, settings(['passkey'], null)];
      return [200, {}];
    });
    await page.goto(`${ORIGIN}/app/admin/settings/p70`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.getByLabel('Email links').check();
    await page.locator('#setting-save').click();
    await expect.poll(() => sent.filter((s) => s.method === 'PUT').length).toBe(1);
    const value = (sent.find((s) => s.method === 'PUT')?.body as { value?: unknown } | undefined)?.value;
    expect(strictlyAscending(value), `P-70 value sent: ${JSON.stringify(value)}`).toBe(true);
  });

  /**
   * R-TN-01, P-18: the Identity step sends `p18` in the order of its
   * checkboxes, EUDI Wallet first. `take_name_set` refuses
   * `["eudi_wallet","document_upload"]`, so a tenant cannot default to
   * both verification methods.
   */
  test('review_identity_step_sends_p18_strictly_ascending', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      const m = /^\/api\/v1\/admin\/onboarding\/([a-z_]+)$/.exec(path);
      if (m !== null && method === 'GET') {
        const step = m[1] ?? '';
        const i = ONBOARDING.indexOf(step as (typeof ONBOARDING)[number]);
        const status = i < 4 ? 'validated' : i === 4 ? 'open' : 'locked';
        return [200, { step, status, revision: '9', values: null, outcome: null, accepted: null }];
      }
      if (m !== null && method === 'PUT') return [200, { status: 'validated', outcome: 'validated' }];
      return [404, { code: 'not_found', rule: null }];
    });
    await page.goto(`${ORIGIN}/app/admin/onboarding/identity`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.locator('[id="ob.p18.eudi_wallet"]').check();
    await page.locator('[id="ob.p18.document_upload"]').check();
    await page.locator('[id="ob.p45.tenant_registration"]').check();
    await page.locator('#onboarding-save').click();
    await expect.poll(() => sent.filter((s) => s.method === 'PUT').length).toBe(1);
    const values = (sent.find((s) => s.method === 'PUT')?.body as { values?: { p18?: unknown } } | undefined)?.values;
    expect(strictlyAscending(values?.p18), `p18 sent: ${JSON.stringify(values?.p18)}`).toBe(true);
  });

  /**
   * P-74, I-84 seam: `roles: null` means every role (`McpSettings`). A
   * tenant whose MCP server is limited to committee members, as the codec
   * spells the role, opens the P-74 page and only turns the public tools
   * off. The page finds no checkbox for the stored role, so it sends
   * `roles: null` and silently opens the MCP server to every role.
   */
  test('review_p74_save_never_widens_a_role_restriction', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      if (method === 'GET' && path === '/api/v1/admin/settings') {
        return [200, settings(['passkey'], { enabled: true, public_tools: true, roles: ['Committee member'] })];
      }
      return [200, {}];
    });
    await page.goto(`${ORIGIN}/app/admin/settings/p74`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.locator('[id="setting-value.public_tools"]').uncheck();
    await page.locator('#setting-save').click();
    await expect.poll(() => sent.filter((s) => s.method === 'PUT').length).toBe(1);
    const value = (sent.find((s) => s.method === 'PUT')?.body as { value?: { roles?: unknown } } | undefined)?.value;
    expect(value?.roles, `P-74 value sent: ${JSON.stringify(value)}`).not.toBeNull();
  });

  /**
   * J2: the confidentiality terms of a Judging role state the
   * programme's P-75 and P-77 choices through bound placeholders. When
   * the invitation read carries neither, as for a draft whose P-75 and
   * P-77 are still gaps, the page states "may not read" and "may only
   * prepare" as if the programme had chosen them, and offers acceptance
   * of those terms.
   */
  test('review_judging_terms_never_state_an_unknown_p75_or_p77_choice', async ({ page }) => {
    await cell(page, (method, path) => {
      if (method === 'GET' && path.startsWith('/api/v1/invitations/')) {
        return [200, { role: 'committee_member', terms_version: 1, state: 'invited' }];
      }
      return [404, { code: 'not_found', rule: null }];
    });
    await page.goto(`${ORIGIN}/app/invitation#${'ab'.repeat(16)}`);
    await expect(page.locator('h2')).toBeVisible();
    const terms = (await page.locator('main').textContent()) ?? '';
    expect(terms).not.toContain('may not read full proposal content');
    expect(terms).not.toContain('may only prepare binding actions');
  });

  /**
   * J2, SoD-07: a tenant admin who grants a role to their own account
   * needs a second admin's approval with step-up,
   * `admin.approve_self_grant`, in the approval inbox. The inbox lists
   * activation requests only, and no page of the lane calls the
   * operation, so this journey step cannot be reached.
   */
  test('review_sod07_self_grant_approval_is_reachable_from_a_page', () => {
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith('.ts')) files.push(p);
      }
    };
    for (const d of ['creator', 'people', 'onboarding']) walk(join(WEB, 'src', d));
    const callers = files.filter((f) => readFileSync(f, 'utf8').includes('"admin.approve_self_grant"'));
    expect(callers, 'pages that call admin.approve_self_grant').not.toEqual([]);
  });
});
