/**
 * Review reproducers for the Judging pages (lane W4c review, M4 W7
 * convention). Each test drives the tsc build of `web/src` in Chromium
 * against an in-memory fake of `/api/v1`, so it needs no e2e stack.
 *
 * The generated operation table in this worktree is the W0 stub, which
 * holds no operation. The fake serves its own `gen/api.js` with the
 * operations each test needs, named as design section 2.2 names them.
 *
 * Build first: web/node_modules/.bin/tsc -p web
 */

import { expect, test, type Page, type Route } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { join, normalize } from 'node:path';
import { REVIEW_PAGES, REVIEW_UI } from '../contract';
import { webDir } from './harness';

const ORIGIN = 'http://judging.test';

interface FakeOp {
  readonly name: string;
  readonly method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  readonly path: string;
}

/** A fake answer: the data of a completed call for `METHOD /api/v1/...`. */
type Answers = Readonly<Record<string, unknown>>;

const SHELL =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>t</title></head>' +
  '<body><div id="app"></div><script type="module" src="/entry.js"></script></body></html>';

const ENTRY =
  'import { mountJudging } from "/dist/reviewer/judging.js";\n' +
  'import { browserEnv } from "/dist/reviewer/kit.js";\n' +
  'const root = document.getElementById("app");\n' +
  'await mountJudging(browserEnv(root), location.pathname);\n' +
  'document.body.setAttribute("data-mounted", "1");\n';

/** Serves the built pages, a fake operation table and fake API answers. */
async function serve(page: Page, ops: readonly FakeOp[], answers: Answers): Promise<string[]> {
  const dist = join(webDir(), 'dist');
  if (!existsSync(join(dist, 'reviewer', 'judging.js'))) {
    throw new Error('web/dist is missing: build with web/node_modules/.bin/tsc -p web');
  }
  const writes: string[] = [];
  await page.route(`${ORIGIN}/**`, async (route: Route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const p = url.pathname;
    if (p === '/entry.js') {
      await route.fulfill({ contentType: 'text/javascript', body: ENTRY });
      return;
    }
    if (p === '/dist/gen/api.js') {
      await route.fulfill({
        contentType: 'text/javascript',
        body: `export const OPERATIONS = ${JSON.stringify(ops)};\n`,
      });
      return;
    }
    if (p.startsWith('/dist/')) {
      const file = normalize(join(dist, p.slice('/dist/'.length)));
      if (!file.startsWith(dist) || !existsSync(file)) {
        await route.fulfill({ status: 404, body: '' });
        return;
      }
      await route.fulfill({ contentType: 'text/javascript', body: readFileSync(file, 'utf8') });
      return;
    }
    if (p.startsWith('/api/v1/')) {
      const key = `${method} ${p}`;
      if (method !== 'GET') writes.push(`${key} ${route.request().postData() ?? ''}`);
      if (!Object.hasOwn(answers, key)) {
        await route.fulfill({ status: 404, contentType: 'application/json', body: '{"code":"not_found","rule":null}' });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'done', data: answers[key], seq: null }),
      });
      return;
    }
    await route.fulfill({ contentType: 'text/html', body: SHELL });
  });
  return writes;
}

async function open(page: Page, path: string): Promise<void> {
  await page.goto(`${ORIGIN}${path}`);
  await expect(page.locator('body[data-mounted="1"]')).toHaveCount(1);
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
}

test.describe('W4c review reproducers', () => {
  /**
   * NOTE 6 of `state-machine.md`, P-17 and R-EV-08: the committee breaks
   * a tie across the cut-off in the order of the cut-off, and records
   * the tie-break. Here x (11) and w (12) tie, and the committee decides
   * under P-17 that w goes within a cut-off at 1. The open-round form
   * must let the committee place w above x. Today it always sends the
   * server's order, so x is nominated whatever the tie-break says.
   */
  test('review_tied_rows_cannot_be_ordered_by_the_committee', async ({ page }) => {
    const row = (proposal: string) => ({
      proposal,
      recused: false,
      title: `Synthetic title ${proposal}`,
      neutral_summary: 'Synthetic summary.',
      rationale: 'Synthetic rationale.',
      effective: '80.00',
      criterion_scores: [],
      requested: '50000.00',
      remaining_budget: '60000.00',
    });
    await serve(
      page,
      [
        { name: 'committee.ranking', method: 'GET', path: '/calls/{call}/ranking' },
        { name: 'committee.open_round', method: 'POST', path: '/calls/{call}/cut-off-rounds' },
      ],
      { 'GET /api/v1/calls/5/ranking': [row('11'), row('12')] },
    );
    await open(page, REVIEW_PAGES.ranking('5'));
    // The page renders the view and its form, so the test fails for the right reason.
    await expect(page.locator(REVIEW_UI.ranking.table)).toBeVisible();
    await expect(page.locator(REVIEW_UI.ranking.open)).toBeVisible();
    await page.locator(REVIEW_UI.ranking.nominated).fill('1');

    const form = page.locator('#round-form');
    const orderControls = form.locator('button, select, input').filter({ hasText: /Proposal 12/ });
    const labelled = form.getByLabel(/Proposal 12/);
    const named = form.getByRole('button', { name: /Proposal 12/ });
    const count = (await orderControls.count()) + (await labelled.count()) + (await named.count());
    expect(count, 'the cut-off form offers a control that places the tied Proposal 12 in the order').toBeGreaterThan(0);
  });

  /**
   * R-CF-02, I-03 and design 2.7 of M2 (`declaration_open` in
   * `fstp-domain` `assignment.rs`): a conflict found after a no-conflict
   * declaration is declared on the active assignment, which releases it.
   * The reviewer page of an active assignment shows the content and the
   * score sheet but no way to declare that conflict.
   */
  test('review_active_reviewer_cannot_declare_a_conflict_found_while_reading', async ({ page }) => {
    await serve(
      page,
      [
        { name: 'me.assignments', method: 'GET', path: '/me/assignments' },
        { name: 'review.read_content', method: 'GET', path: '/proposals/{proposal}/content' },
        { name: 'review.score_sheet', method: 'GET', path: '/assignments/{assignment}/score-sheet' },
        { name: 'review.declare_assignment', method: 'POST', path: '/assignments/{assignment}/declaration' },
      ],
      {
        'GET /api/v1/me/assignments': [
          { assignment: '21', proposal: '11', call: '5', kind: 'reviewer', awaiting_declaration: false, active: true },
        ],
        'GET /api/v1/proposals/11/content': {
          proposal: '11',
          call: '5',
          state: 'STAGE1',
          title: 'Synthetic title',
          text: 'Synthetic content.',
        },
        'GET /api/v1/assignments/21/score-sheet': {
          stage: 'One',
          plan: '3',
          criteria: [{ id: '1', text: 'Synthetic criterion', max: 5 }],
          current: null,
        },
      },
    );
    await open(page, REVIEW_PAGES.assignment('21'));
    await expect(page.locator(REVIEW_UI.content)).toBeVisible();
    await expect(page.locator(REVIEW_UI.score.form)).toBeVisible();
    await expect(
      page.locator(REVIEW_UI.declaration.yes),
      'an active reviewer can still declare a conflict found while reading',
    ).toHaveCount(1);
  });

  /**
   * R-CF-02 and I-03 for the IRC: IRC review is among the acts a
   * conflict bars. An IRC member who declared no conflict and then finds
   * one while reading the case has no way to declare it on the page.
   */
  test('review_active_irc_member_cannot_declare_a_conflict_found_while_reading', async ({ page }) => {
    await serve(
      page,
      [
        { name: 'me.irc_cases', method: 'GET', path: '/me/irc-cases' },
        { name: 'irc.case', method: 'GET', path: '/irc-assignments/{irc_assignment}/case' },
        { name: 'irc.declare', method: 'POST', path: '/irc-assignments/{irc_assignment}/declaration' },
        { name: 'irc.review', method: 'POST', path: '/irc-assignments/{irc_assignment}/review' },
      ],
      {
        'GET /api/v1/me/irc-cases': [
          { assignment: '31', proposal: '11', call: '5', kind: 'irc', awaiting_declaration: false, active: true },
        ],
        'GET /api/v1/irc-assignments/31/case': {
          proposal: '11',
          state: 'IRC_REVIEW',
          title: 'Synthetic title',
          text: 'Synthetic content.',
          outcome: 'nominated',
        },
      },
    );
    await open(page, REVIEW_PAGES.ircCase('31'));
    await expect(page.locator(REVIEW_UI.irc.case)).toBeVisible();
    await expect(page.locator(REVIEW_UI.irc.submit)).toBeVisible();
    await expect(
      page.locator(REVIEW_UI.declaration.yes),
      'an active IRC member can still declare a conflict found while reading',
    ).toHaveCount(1);
  });
});
