/**
 * Browser tests of the applicant pages against a fake cell (lane W4b, fix
 * round 1). They need no stack. A routed origin serves the compiled pages
 * from `web/dist` (run `web/node_modules/.bin/tsc -p web` first), an
 * operation table with the W3a paths (`gen/api.ts` on m4/app) of the
 * operations used, and a fake `/api/v1` that records what the pages send.
 *
 * Each test names the requirement, invariant or design rule it checks.
 */

import { expect, test, type Page } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';

const ORIGIN = 'https://a.fstp.test';
const DIST = join(resolve(__dirname, '..', '..', 'web'), 'dist');

/** The W3a table entries for the operations these tests use. */
const TABLE = `export const OPERATIONS = [
  { name: "proposal.view", method: "GET", path: "/proposals/{proposal}", base: "api" },
  { name: "proposal.withdraw", method: "POST", path: "/proposals/{proposal}/withdrawal", base: "api" },
  { name: "proposal.add_member", method: "POST", path: "/proposals/{proposal}/team", base: "api" },
  { name: "proposal.add_guardian", method: "POST", path: "/proposals/{proposal}/guardian", base: "api" },
  { name: "proposal.record_plan", method: "PUT", path: "/proposals/{proposal}/plan", base: "api" },
  { name: "stage2.view", method: "GET", path: "/proposals/{proposal}/stage2", base: "api" },
  { name: "negotiation.view", method: "GET", path: "/proposals/{proposal}/negotiation", base: "api" },
];`;

const SHELL =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>x</title></head>' +
  '<body><div id="app"></div><script type="module" src="/dist/applicant/main.js"></script></body></html>';

interface Sent {
  readonly method: string;
  readonly path: string;
  readonly body: string;
}

type Reply = (method: string, path: string) => unknown;

/** Serves the shell, the compiled modules and a fake API on ORIGIN. */
async function fakeCell(page: Page, reply: Reply): Promise<Sent[]> {
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
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reply(r.method(), path)) });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'text/html', body: SHELL });
  });
  return sent;
}

/** A fake cell whose proposal 1 is in `state` for a caller of `role`. */
function proposalIn(state: string, role: string | null): Reply {
  return (method, path) => {
    if (method === 'GET' && path === '/api/v1/proposals/1') {
      return role === null ? { proposal: '1', state, title: 'T' } : { proposal: '1', state, role, title: 'T' };
    }
    if (method === 'GET' && path === '/api/v1/proposals/1/stage2') {
      return { questions: [] };
    }
    if (method === 'GET' && path === '/api/v1/proposals/1/negotiation') {
      return { acknowledged: false };
    }
    return { accepted: true };
  };
}

/**
 * State-machine NOTE 14 and I-18: the guardian's consent opens at the
 * last IRC validation and in NEGOTIATION, so the guardian link is offered
 * there only. The team's reads stay with the guardian (registry TEAM).
 */
test('i18_guardian_link_is_offered_only_where_consent_is_open', async ({ page }) => {
  const reply = { state: 'DRAFT' };
  await fakeCell(page, (m, p) => proposalIn(reply.state, 'guardian')(m, p));
  for (const [state, offered] of [
    ['DRAFT', false],
    ['STAGE1', false],
    ['IRC_REVIEW', true],
    ['NEGOTIATION', true],
    ['WITHDRAWN', false],
  ] as const) {
    reply.state = state;
    await page.goto(`${ORIGIN}/app/proposals/1`);
    await expect(page.locator('#proposal-state')).toHaveAttribute('data-state', state);
    await expect(page.locator('a[href="/app/proposals/1/guardian"]'), state).toHaveCount(offered ? 1 : 0);
  }
  reply.state = 'NEGOTIATION';
  await page.goto(`${ORIGIN}/app/proposals/1`);
  await expect(page.locator('a[href="/app/proposals/1/negotiation"]'), 'the team reads the landing').toHaveCount(1);
  await expect(page.locator('#proposal-withdraw'), 'withdrawal is the lead\'s').toHaveCount(0);
});

/**
 * Design 8.7 `roles/<role>`: a proposal whose role the cell does not
 * send is the least-privileged case, so the page offers no lead action
 * and no team link.
 */
test('roles_missing_role_offers_no_action', async ({ page }) => {
  await fakeCell(page, proposalIn('DRAFT', null));
  await page.goto(`${ORIGIN}/app/proposals/1`);
  await expect(page.locator('#proposal-state')).toHaveAttribute('data-state', 'DRAFT');
  await expect(page.locator('#proposal-withdraw')).toHaveCount(0);
  await expect(page.locator('#copy-request')).toHaveCount(0);
  await expect(page.locator('#proposal-actions')).toHaveCount(0);
});

/**
 * R-EV-05: stage 2 questions exist only from STAGE2 on. Before that the
 * stage 2 page never reads `stage2.view`, and says stage 2 is not open
 * rather than showing a refusal.
 */
test('r_ev_05_stage2_page_reads_no_questions_before_stage2', async ({ page }) => {
  const sent = await fakeCell(page, proposalIn('SUBMITTED', 'lead'));
  await page.goto(`${ORIGIN}/app/proposals/1/stage2`);
  await expect(page.getByText('Stage 2 is not open for this proposal.')).toBeVisible();
  await expect(page.locator('#page-alert')).toBeHidden();
  expect(sent.filter((s) => s.path.endsWith('/stage2')), 'no stage 2 read').toEqual([]);
});

/**
 * Design 8.7 `roles/<role>`: only the lead answers and revises in stage
 * 2 (registry LEAD). A team member reads the questions and sees neither
 * form.
 */
test('roles_member_reads_stage2_without_answer_or_revision', async ({ page }) => {
  await fakeCell(page, proposalIn('STAGE2', 'member'));
  await page.goto(`${ORIGIN}/app/proposals/1/stage2`);
  await expect(page.getByText('No question has been asked.')).toBeVisible();
  await expect(page.locator('#stage2-answer')).toHaveCount(0);
  await expect(page.locator('#stage2-revise')).toHaveCount(0);
});

/**
 * Design 8.7 `roles/<role>`: only the lead acknowledges the negotiation
 * notice (registry LEAD). A team member reads the notice without the
 * control.
 */
test('roles_member_reads_the_negotiation_notice_without_acknowledging', async ({ page }) => {
  await fakeCell(page, proposalIn('NEGOTIATION', 'member'));
  await page.goto(`${ORIGIN}/app/proposals/1/negotiation`);
  await expect(page.locator('#negotiation-notice')).toBeVisible();
  await expect(page.locator('#negotiation-acknowledge')).toHaveCount(0);
});

/**
 * Journey J4 "Add team members, or a guardian for V": the lead invites
 * by email address only, to the W3a routes of `proposal.add_member` and
 * `proposal.add_guardian`, and the page asks for no identity attribute.
 * In NEGOTIATION only the guardian can be added (NOTE 14).
 */
test('r_ng_01_team_page_invites_members_and_adds_a_guardian', async ({ page }) => {
  const reply = { state: 'DRAFT' };
  const sent = await fakeCell(page, (m, p) => proposalIn(reply.state, 'lead')(m, p));
  await page.goto(`${ORIGIN}/app/proposals/1`);
  await page.locator('a[href="/app/proposals/1/team"]').click();
  await page.locator('#team-member-email').fill('member@example.org');
  await page.locator('#team-member-send').click();
  await expect(page.locator('#team-member-status')).toHaveAttribute('data-status', 'saved');
  await page.locator('#team-guardian-email').fill('guardian@example.org');
  await page.locator('#team-guardian-send').click();
  await expect(page.locator('#team-guardian-status')).toHaveAttribute('data-status', 'saved');
  const posts = sent.filter((s) => s.method === 'POST');
  expect(posts.map((s) => [s.path, JSON.parse(s.body)])).toEqual([
    ['/api/v1/proposals/1/team', { email: 'member@example.org' }],
    ['/api/v1/proposals/1/guardian', { email: 'guardian@example.org' }],
  ]);
  const inputs = await page.locator('main input, main select, main textarea').evaluateAll((els) => els.map((e) => e.id));
  expect(inputs.sort(), 'the page asks for the two addresses only').toEqual(['team-guardian-email', 'team-member-email']);

  reply.state = 'NEGOTIATION';
  await page.goto(`${ORIGIN}/app/proposals/1/team`);
  await expect(page.locator('#team-guardian-email')).toBeVisible();
  await expect(page.locator('#team-member-email')).toHaveCount(0);
});

/**
 * R-EV-05 and ADR-006: the plan editor adds a second task and a second
 * milestone, links each missing field from its error summary, and sends
 * every amount and day as a string, with no total computed in the
 * browser. The page shows the total only as the cell sent it.
 */
test('adr006_plan_editor_sends_tasks_and_shows_the_cell_total', async ({ page }) => {
  const sent = await fakeCell(page, (m, p) =>
    m === 'PUT' ? { accepted: true, total: '2500.00' } : proposalIn('DRAFT', 'lead')(m, p),
  );
  await page.goto(`${ORIGIN}/app/proposals/1/plan`);
  await page.locator('#plan-t1-add-milestone').click();
  await expect(page.locator('#plan-t1-m2-amount')).toBeFocused();
  await page.locator('#plan-add-task').click();
  await expect(page.locator('#plan-t2-m1-amount')).toBeFocused();
  await page.locator('#plan-save').click();
  const summary = page.locator('#plan-errors');
  await expect(summary).toBeVisible();
  await expect(summary).toBeFocused();
  // Three milestones with three fields each, and the work plan text.
  await expect(summary.locator('a')).toHaveCount(10);
  await summary.locator('a[href="#plan-t2-m1-due"]').click();
  await expect(page.locator('#plan-t2-m1-due')).toBeFocused();
  expect(sent.filter((s) => s.method === 'PUT'), 'nothing is sent with errors').toEqual([]);

  const rows: readonly [string, string, string, string][] = [
    ['plan-t1-m1', '1000.00', '2027-03-01', '2027-04-30'],
    ['plan-t1-m2', '500.00', '2027-05-01', '2027-06-30'],
    ['plan-t2-m1', '1000.00', '2027-03-01', '2027-03-01'],
  ];
  for (const [id, amount, start, due] of rows) {
    await page.locator(`#${id}-amount`).fill(amount);
    await page.locator(`#${id}-start`).fill(start);
    await page.locator(`#${id}-due`).fill(due);
  }
  await page.locator('#plan-description').fill('A synthetic work plan.');
  await page.locator('#plan-save').click();
  await expect(page.locator('#plan-status')).toHaveAttribute('data-status', 'saved');
  await expect(page.locator('#plan-total')).toHaveText('The platform computed the plan total: 2500.00 EUR.');
  const put = sent.filter((s) => s.method === 'PUT');
  expect(put).toHaveLength(1);
  expect(put[0]?.body).toBe(
    JSON.stringify({
      description: 'A synthetic work plan.',
      tasks: [
        {
          milestones: [
            { amount: '1000.00', due: '2027-04-30', start: '2027-03-01' },
            { amount: '500.00', due: '2027-06-30', start: '2027-05-01' },
          ],
        },
        { milestones: [{ amount: '1000.00', due: '2027-03-01', start: '2027-03-01' }] },
      ],
    }),
  );
});

/**
 * WCAG 2.2 SC 2.4.3: after a withdrawal the page is replaced, so focus
 * moves to its new heading rather than to a detached button (R-SB-03).
 */
test('r_sb_03_focus_moves_to_the_heading_after_withdrawal', async ({ page }) => {
  const reply = { state: 'DRAFT' };
  await fakeCell(page, (m, p) => {
    if (m === 'POST') {
      reply.state = 'WITHDRAWN';
    }
    return proposalIn(reply.state, 'lead')(m, p);
  });
  await page.goto(`${ORIGIN}/app/proposals/1`);
  await page.locator('#proposal-withdraw').click();
  await page.locator('#withdraw-confirm').click();
  await expect(page.locator('#proposal-state')).toHaveAttribute('data-state', 'WITHDRAWN');
  await expect(page.locator('h1')).toBeFocused();
});

/**
 * R-WL-04, P-68 and the I-69 seam: every applicant page's footer shows
 * the privacy notice, the accessibility statement and the platform
 * attribution, in the `contentinfo` landmark.
 */
test('r_wl_04_footer_holds_every_mandatory_element', async ({ page }) => {
  await fakeCell(page, proposalIn('DRAFT', 'lead'));
  for (const path of ['/app/proposals/1', '/app/proposals/1/plan', '/app/calls', '/app/no-such-page']) {
    await page.goto(`${ORIGIN}${path}`);
    const footer = page.getByRole('contentinfo');
    await expect(footer, path).toHaveCount(1);
    for (const id of ['#footer-privacy', '#footer-accessibility', '#footer-attribution']) {
      await expect(footer.locator(id), `${path} ${id}`).not.toBeEmpty();
    }
  }
});
