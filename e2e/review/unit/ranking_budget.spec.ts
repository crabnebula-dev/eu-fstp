/**
 * The committee ranking check and the signed remaining budget (R-EV-08,
 * ADR-006; lane m4shapes, fix round 1).
 *
 * A call can be over-nominated, so its remaining budget is signed. An
 * amount never carries a sign, so the server sends a zero
 * `remaining_budget` and a positive `shortfall` for such a call. These
 * specs check that the page accepts exactly that spelling.
 *
 * Build first: web/node_modules/.bin/tsc -p web
 */

import { expect, test } from '@playwright/test';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { webDir } from './harness';

type Check = (v: unknown) => boolean;

async function rankingCheck(): Promise<Check> {
  const built = join(webDir(), 'dist', 'committee', 'models.js');
  if (!existsSync(built)) {
    throw new Error(`${built} is missing: build with web/node_modules/.bin/tsc -p web`);
  }
  const mod = (await import(pathToFileURL(built).href)) as Record<string, unknown>;
  const c = mod['isRankingView'];
  if (typeof c !== 'function') {
    throw new Error('web/src/committee/models.ts does not export isRankingView');
  }
  return c as Check;
}

function row(budget: Record<string, string>): Record<string, unknown> {
  return {
    proposal: '11',
    recused: false,
    title: 'Synthetic title',
    neutral_summary: null,
    rationale: 'Synthetic rationale.',
    effective: '80.00',
    criterion_scores: [{ criterion: '1', weighted: '40.00' }],
    requested: '50000.00',
    ...budget,
  };
}

test('r_ev_08_adr006_over_nominated_ranking_row_decodes_with_a_positive_shortfall', async () => {
  const check = await rankingCheck();
  expect(check([row({ remaining_budget: '0.00', shortfall: '500.00' })])).toBe(true);
  expect(check([row({ remaining_budget: '60000.00' })])).toBe(true);
  expect(check([row({ remaining_budget: '0.00' })])).toBe(true);
});

test('r_ev_08_adr006_ranking_row_refuses_every_other_budget_spelling', async () => {
  const check = await rankingCheck();
  // A sign, a zero shortfall, and a shortfall beside a budget left over.
  expect(check([row({ remaining_budget: '-500.00' })])).toBe(false);
  expect(check([row({ remaining_budget: '0.00', shortfall: '0.00' })])).toBe(false);
  expect(check([row({ remaining_budget: '100.00', shortfall: '500.00' })])).toBe(false);
  expect(check([row({ remaining_budget: '0.00', shortfall: '-500.00' })])).toBe(false);
  expect(check([row({ shortfall: '500.00' })])).toBe(false);
});
