/**
 * Review reproducers for lane W4b (M4 design sections 2.2 J4, 3.9, 8.7
 * and 9). Each test fails against the pages as written and passes once
 * the finding it names is fixed.
 *
 * The browser tests need no stack. A routed origin serves the compiled
 * pages from `web/dist` (run `web/node_modules/.bin/tsc -p web` first),
 * an operation table with the W3a paths for the operations used, and a
 * fake `/api/v1` that records what the pages send.
 */

import { expect, test, type Page } from '@playwright/test';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';

const ORIGIN = 'https://a.fstp.test';
const WEB = resolve(__dirname, '..', '..', 'web');
const DIST = join(WEB, 'dist');

/** The W3a table entries (`gen/api.ts` on m4/app) for the operations used here. */
const TABLE = `export const OPERATIONS = [
  { name: "proposal.view", method: "GET", path: "/proposals/{proposal}", base: "api" },
  { name: "proposal.record_plan", method: "PUT", path: "/proposals/{proposal}/plan", base: "api" },
  { name: "stage2.view", method: "GET", path: "/proposals/{proposal}/stage2", base: "api" },
  { name: "stage2.revise", method: "POST", path: "/proposals/{proposal}/stage2/revision", base: "api" },
];`;

const SHELL =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>x</title></head>' +
  '<body><div id="app"></div><script type="module" src="/dist/applicant/main.js"></script></body></html>';

interface Sent {
  readonly method: string;
  readonly path: string;
  readonly body: string;
}

/**
 * Serves the shell, the compiled modules and a fake API on ORIGIN.
 * `reply` answers each API request by method and path.
 */
async function fakeCell(page: Page, reply: (method: string, path: string) => unknown): Promise<Sent[]> {
  if (!existsSync(join(DIST, 'applicant', 'main.js'))) {
    throw new Error('web/dist is missing: run web/node_modules/.bin/tsc -p web first');
  }
  const sent: Sent[] = [];
  await page.route(`${ORIGIN}/**`, async (route) => {
    const r = route.request();
    const path = new URL(r.url()).pathname;
    if (path === '/dist/gen/api.js') {
      await route.fulfill({ status: 200, contentType: 'text/javascript', body: TABLE });
      return;
    }
    if (path.startsWith('/dist/')) {
      const file = join(DIST, path.slice('/dist/'.length));
      if (!file.startsWith(DIST) || !existsSync(file) || extname(file) !== '.js') {
        await route.fulfill({ status: 404, body: '' });
        return;
      }
      await route.fulfill({ status: 200, contentType: 'text/javascript', body: readFileSync(file, 'utf8') });
      return;
    }
    if (path.startsWith('/api/v1/')) {
      sent.push({ method: r.method(), path, body: r.postData() ?? '' });
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(reply(r.method(), path)),
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'text/html', body: SHELL });
  });
  return sent;
}

/**
 * Design 2.2 J4 "Save a plan version: `proposal.record_plan`,
 * `RecordPlanVersion`". The M2 domain records a plan of origin
 * "submitted" only with at least one task, a milestone in every task,
 * and an amount, a start and a due date on each milestone
 * (`fstp-domain` `proposal/intake.rs` `check_tasks`). `Submit` needs that
 * plan (R-SB-02 row DRAFT to SUBMITTED). The plan editor sends one amount
 * and a text, so no plan it sends can be recorded, and no draft can be
 * submitted through the interface.
 */
test('review_plan_editor_sends_tasks_with_dated_milestones', async ({ page }) => {
  const sent = await fakeCell(page, (method, path) =>
    method === 'GET' && path === '/api/v1/proposals/1'
      ? { proposal: '1', state: 'DRAFT', role: 'lead', title: 'T' }
      : { accepted: true },
  );
  await page.goto(`${ORIGIN}/app/proposals/1/plan`);
  // Fix round 1: the editor's first milestone of the first task. Its
  // start and due days are required, so the reproducer fills them.
  await page.locator('#plan-t1-m1-amount').fill('1500.50');
  await page.locator('#plan-t1-m1-start').fill('2027-03-01');
  await page.locator('#plan-t1-m1-due').fill('2027-06-30');
  await page.locator('#plan-description').fill('A synthetic work plan.');
  const put = page.waitForRequest((r) => r.method() === 'PUT' && new URL(r.url()).pathname === '/api/v1/proposals/1/plan');
  await page.locator('#plan-save').click();
  await put;
  const body = JSON.parse(sent.find((s) => s.method === 'PUT')?.body ?? 'null') as Record<string, unknown> | null;
  const tasks = body?.['tasks'];
  expect(Array.isArray(tasks) && tasks.length > 0, 'the plan carries at least one task').toBe(true);
  for (const task of tasks as readonly Record<string, unknown>[]) {
    const milestones = task['milestones'];
    expect(Array.isArray(milestones) && milestones.length > 0, 'each task has a milestone').toBe(true);
    for (const m of milestones as readonly Record<string, unknown>[]) {
      expect(typeof m['amount'], 'a milestone amount is an ADR-006 string').toBe('string');
      expect(m['start'], 'a milestone has a start date').toBeDefined();
      expect(m['due'], 'a milestone has a due date').toBeDefined();
    }
  }
});

/**
 * Design 2.2 J4 "Stage 2: ... revise: `AnswerQuestions`,
 * `RecordPlanVersion`, `SubmitRevision`" and R-EV-05 ("a revised plan
 * including budget changes"). `SubmitRevision` names a plan version of
 * origin "stage 2 revision", which needs tasks with dated milestones
 * like any plan. The revision form sends one amount only.
 */
test('review_stage2_revision_sends_a_plan_with_tasks', async ({ page }) => {
  const sent = await fakeCell(page, (method, path) => {
    if (method === 'GET' && path === '/api/v1/proposals/1') {
      return { proposal: '1', state: 'STAGE2', role: 'lead', title: 'T' };
    }
    if (method === 'GET' && path === '/api/v1/proposals/1/stage2') {
      return { questions: [] };
    }
    return { accepted: true };
  });
  await page.goto(`${ORIGIN}/app/proposals/1/stage2`);
  // Fix round 1: the revision form is the same plan editor, with the
  // work plan text, so the reproducer fills every required field.
  await page.locator('#stage2-plan-t1-m1-amount').fill('1400.00');
  await page.locator('#stage2-plan-t1-m1-start').fill('2027-03-01');
  await page.locator('#stage2-plan-t1-m1-due').fill('2027-06-30');
  await page.locator('#stage2-plan-description').fill('A synthetic revised work plan.');
  const post = page.waitForRequest(
    (r) => r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/proposals/1/stage2/revision',
  );
  await page.locator('#stage2-revise').click();
  await post;
  const body = JSON.parse(sent.find((s) => s.method === 'POST')?.body ?? 'null') as Record<string, unknown> | null;
  const tasks = body?.['tasks'];
  expect(Array.isArray(tasks) && tasks.length > 0, 'the revised plan carries its tasks').toBe(true);
});

/**
 * Design 8.7 `roles/<role>`: "allowed actions are present. Denied ones
 * are absent". The registry (`fstp-access` `registry.rs`) admits only
 * the lead to `proposal.withdraw`, `proposal.submit`,
 * `proposal.record_plan`, the two vault statements and
 * `proposal.request_copy`, as the domain does (`Withdraw`, `Submit`,
 * `RecordPlanVersion` are `ActorRule::Lead`). A team member's proposal
 * page offers all of them.
 */
test('review_team_member_page_offers_no_lead_only_action', async ({ page }) => {
  await fakeCell(page, (method, path) =>
    method === 'GET' && path === '/api/v1/proposals/1'
      ? { proposal: '1', state: 'DRAFT', role: 'member', title: 'T' }
      : { accepted: true },
  );
  await page.goto(`${ORIGIN}/app/proposals/1`);
  await expect(page.locator('#proposal-state')).toHaveAttribute('data-state', 'DRAFT');
  await expect(page.locator('#proposal-withdraw'), 'withdrawal is the lead\'s').toHaveCount(0);
  await expect(page.locator('a[href="/app/proposals/1/submit"]'), 'submission is the lead\'s').toHaveCount(0);
  await expect(page.locator('a[href="/app/proposals/1/plan"]'), 'the plan is the lead\'s').toHaveCount(0);
  await expect(page.locator('#copy-request'), 'the copy request is the lead\'s').toHaveCount(0);
});

/** The TypeScript sources of the applicant and call pages. */
function pageSources(): string {
  let all = '';
  for (const dir of ['applicant', 'calls']) {
    const d = join(WEB, 'src', dir);
    for (const f of readdirSync(d)) {
      if (f.endsWith('.ts')) all += readFileSync(join(d, f), 'utf8');
    }
  }
  return all;
}

/**
 * Design 2.2 J4 "Add team members, or a guardian for V | Team |
 * `proposal.add_member`, `proposal.add_guardian`". The guardian must be
 * added (`AddGuardian`) before V can pass the NEGOTIATION gate (I-18,
 * state-machine NOTE 14). No applicant page calls either operation.
 */
test('review_j4_team_page_calls_add_member_and_add_guardian', () => {
  const src = pageSources();
  expect(src.includes('"proposal.add_member"'), 'a page calls proposal.add_member').toBe(true);
  expect(src.includes('"proposal.add_guardian"'), 'a page calls proposal.add_guardian').toBe(true);
});

/**
 * CLAUDE.md "Every in-house parser gets a fuzz target from its first
 * commit" and design section 9 (TypeScript parsers, Q33). `wire.ts`
 * parses every server body of these pages, with the instant and day
 * grammars, in place of the generated validators. No target in
 * `web/fuzz/targets.ts` reaches it.
 */
test('review_wire_decoders_have_a_fuzz_target', () => {
  const targets = readFileSync(join(WEB, 'fuzz', 'targets.ts'), 'utf8');
  const files = readdirSync(join(WEB, 'fuzz')).filter((f) => f.endsWith('.fuzz.ts'));
  const reaches = files.some((f) => readFileSync(join(WEB, 'fuzz', f), 'utf8').includes('applicant/wire'));
  expect(reaches && /wire/i.test(targets), 'a listed fuzz target imports applicant/wire.js').toBe(true);
});

/**
 * Design 3.9 "Footer": "Every page shows the privacy notice, the
 * accessibility statement and the platform attribution (P-68, R-WL-04,
 * I-69 seam)". The `fstp-web` shell leaves these to the application
 * (`shell.rs`: "The footer's mandatory elements are the application's to
 * render"). The applicant frame renders no footer.
 */
test('review_r_wl_04_applicant_pages_show_the_mandatory_footer', async ({ page }) => {
  await fakeCell(page, (method, path) =>
    method === 'GET' && path === '/api/v1/proposals/1'
      ? { proposal: '1', state: 'DRAFT', role: 'lead', title: 'T' }
      : { accepted: true },
  );
  await page.goto(`${ORIGIN}/app/proposals/1`);
  await expect(page.locator('#proposal-state')).toHaveAttribute('data-state', 'DRAFT');
  await expect(page.getByRole('contentinfo'), 'the page has its footer landmark').toHaveCount(1);
});
