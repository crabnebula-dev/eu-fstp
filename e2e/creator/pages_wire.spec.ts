/**
 * Browser checks of what the creator, onboarding and people pages send
 * (M4 lane W4a, design sections 2.2 J0 to J2, 3.3, 3.5 and 3.9).
 *
 * These need no stack. They compile `web/src` with tsc into a temporary
 * directory and serve it on a routed origin. The routed origin replaces
 * the W0 stub `gen/api.js` with a small operation table, and a fake
 * answers each API call and records every request body. The operation
 * routes are the ones of the section 2.2 journey tables. Interim, pending
 * the generated table of lane W3a.
 */

import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, normalize } from 'node:path';

const ORIGIN = 'https://a.fstp.test';
const WEB = join(__dirname, '..', '..', 'web');

/** The operations these checks reach, as the generated table would list them. */
const OPS: readonly (readonly [string, string, string])[] = [
  ['tenant.get_settings', 'GET', '/api/v1/admin/settings'],
  ['tenant.set_mcp', 'PUT', '/api/v1/admin/settings/{param}'],
  ['tenant.get_step', 'GET', '/api/v1/admin/onboarding/{step}'],
  ['tenant.save_step', 'PUT', '/api/v1/admin/onboarding/{step}'],
  ['admin.list_approvals', 'GET', '/api/v1/admin/approvals'],
  ['admin.approve_self_grant', 'POST', '/api/v1/admin/approvals/{approval}'],
  ['creator.get_draft', 'GET', '/api/v1/programmes/{programme}/draft'],
  ['creator.list_invitations', 'GET', '/api/v1/programmes/{programme}/invitations'],
  ['creator.list_templates', 'GET', '/api/v1/creator/templates'],
  ['roles.grant', 'POST', '/api/v1/programmes/{programme}/roles'],
  ['import.upload', 'POST', '/api/v1/programmes/{programme}/imports'],
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
  dist = mkdtempSync(join(tmpdir(), 'fstp-w4a-wire-'));
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

/** Serves the compiled pages on ORIGIN. `api` answers each API call. Every request with a body is recorded. */
async function cell(page: Page, api: (method: string, path: string) => [number, unknown]): Promise<Sent[]> {
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
    const raw = r.postData();
    const body: unknown = raw === null || raw === '' ? undefined : JSON.parse(raw);
    if (body !== undefined) sent.push({ method: r.method(), path, body });
    const [status, out] = api(r.method(), path);
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(out) });
  });
  return sent;
}

const NOT_FOUND: [number, unknown] = [404, { code: 'not_found', rule: null }];

test.describe('W4a page wire', () => {
  /**
   * R-LG-03, P-74: "every role" (`roles: null`) is an explicit choice.
   * An admin who limits the server and chooses no role sends an empty
   * set, which the codec reads as no role, never as every role.
   */
  test('r_lg_03_p74_every_role_is_an_explicit_choice', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      if (method === 'GET' && path === '/api/v1/admin/settings') {
        return [200, { p74: { enabled: true, public_tools: false, roles: null } }];
      }
      return method === 'PUT' ? [200, {}] : NOT_FOUND;
    });
    await page.goto(`${ORIGIN}/app/admin/settings/p74`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await expect(page.locator('[id="setting-value.scope.every"]')).toBeChecked();
    await page.locator('[id="setting-value.scope.listed"]').check();
    await page.locator('#setting-save').click();
    await expect.poll(() => sent.filter((s) => s.method === 'PUT').length).toBe(1);
    expect(sent.find((s) => s.method === 'PUT')?.body).toEqual({
      value: { enabled: true, public_tools: false, roles: [] },
    });
  });

  /**
   * R-LG-03, P-74: an unset P-74 picks no scope, so a save without a
   * choice sends nothing and says why.
   */
  test('r_lg_03_p74_unset_scope_sends_nothing', async ({ page }) => {
    const sent = await cell(page, (method, path) =>
      method === 'GET' && path === '/api/v1/admin/settings' ? [200, { p74: null }] : NOT_FOUND,
    );
    await page.goto(`${ORIGIN}/app/admin/settings/p74`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.locator('#setting-save').click();
    await expect(page.locator('#setting-error')).not.toBeEmpty();
    expect(sent).toEqual([]);
  });

  /**
   * R-TN-01, Q22: the Agreements step sends only the versions the
   * control plane recorded as accepted. With none recorded it sends
   * nothing and says why, so the page never makes up a version.
   */
  test('r_tn_01_agreements_step_sends_no_version_the_control_plane_never_recorded', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      const m = /^\/api\/v1\/admin\/onboarding\/([a-z_]+)$/.exec(path);
      if (m !== null && method === 'GET') {
        const step = m[1] ?? '';
        const i = ONBOARDING.indexOf(step as (typeof ONBOARDING)[number]);
        const status = i < 1 ? 'validated' : i === 1 ? 'open' : 'locked';
        return [200, { step, status, revision: '3', values: null, outcome: null, accepted: null }];
      }
      return m !== null ? [200, { status: 'validated', outcome: 'validated' }] : NOT_FOUND;
    });
    await page.goto(`${ORIGIN}/app/admin/onboarding/agreements`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.locator('#onboarding-save').click();
    await expect(page.locator('#onboarding-error')).toContainText('has not recorded');
    expect(sent).toEqual([]);
  });

  /**
   * SoD-07, J2: a self-grant waits in the approval inbox. A second admin
   * approves it there with `admin.approve_self_grant`. The requesting
   * admin is offered no approval of their own grant.
   */
  test('sod07_self_grant_is_approved_from_the_inbox_by_a_second_admin_only', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      if (method === 'GET' && path === '/api/v1/admin/approvals') {
        return [
          200,
          {
            approvals: [
              { kind: 'self_grant', programme: 'p1', approvable: true, approval: 'a1', role: 'committee_chair', grantee: 'admin-7' },
              { kind: 'self_grant', programme: 'p1', approvable: false, approval: 'a2', role: 'call_drafter', grantee: 'admin-3' },
            ],
          },
        ];
      }
      return method === 'POST' ? [200, {}] : NOT_FOUND;
    });
    await page.goto(`${ORIGIN}/app/admin/approvals`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await expect(page.locator('li[data-approval="self_grant"][data-id="a2"] [data-action="approve"]')).toHaveCount(0);
    await page.locator('li[data-approval="self_grant"][data-id="a1"] [data-action="approve"]').click();
    await expect(page.locator('li[data-approval="self_grant"][data-id="a1"]')).toHaveAttribute('data-status', 'approved');
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/admin/approvals/a1', body: {} }]);
  });

  /**
   * SoD-07, J2: the grant of a role to the admin's own account names the
   * second admin approval its invitation carries, so the server can
   * consume it.
   */
  test('sod07_self_grant_names_the_second_admin_approval', async ({ page }) => {
    const sent = await cell(page, (method, path) => {
      if (method === 'GET' && path === '/api/v1/programmes/p1/draft') {
        return [200, { spec: {}, revision: '5', status: 'active' }];
      }
      if (method === 'GET' && path === '/api/v1/programmes/p1/invitations') {
        return [
          200,
          {
            invitations: [
              { id: 'i1', email: 'a@example.test', role: 'committee_chair', state: 'verified', sod: 'pass', approval: 'a1' },
            ],
          },
        ];
      }
      return method === 'POST' ? [200, {}] : NOT_FOUND;
    });
    await page.goto(`${ORIGIN}/app/programmes/p1/people`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.locator('li[data-invitation="i1"] [data-action="grant"]').click();
    await expect.poll(() => sent.length).toBe(1);
    expect(sent[0]).toEqual({ method: 'POST', path: '/api/v1/programmes/p1/roles', body: { approval: 'a1', invitation: 'i1' } });
  });

  /**
   * I-65, design section 3.3: an import document is UTF-8 only. A file
   * that is not UTF-8 is refused before any request, never changed.
   */
  test('i65_import_upload_refuses_a_document_that_is_not_utf8', async ({ page }) => {
    const sent = await cell(page, (method, path) =>
      method === 'GET' && path === '/api/v1/creator/templates' ? [200, { templates: [] }] : [200, {}],
    );
    await page.goto(`${ORIGIN}/app/programmes/p1/creator/start`);
    await expect(page.locator('main[data-ready="true"]')).toBeVisible();
    await page.locator('[data-start="import"]').click();
    await page
      .locator('#import-file')
      .setInputFiles({ name: 'annex.md', mimeType: 'text/markdown', buffer: Buffer.from([0x23, 0x20, 0xff, 0xfe, 0x41]) });
    await page.locator('#import-upload').click();
    await expect(page.locator('#creator-error')).toContainText('not UTF-8');
    expect(sent).toEqual([]);
  });
});
