/**
 * Page logic of the assigned reviewer's score sheet and ranking summary
 * (J6, M4 design section 2.2), against `web/src/reviewer/forms.ts`.
 *
 * - R-EV-02 and P-01 NOTE 6: every criterion is scored on an integer
 *   scale from 0 to N, and a score that leaves out a criterion is
 *   incomplete. No float ever stands for a score.
 * - I-23: a correction is a new record and carries its reason.
 * - R-EV-08: the ranking view shows the title, neutral summary and
 *   rationale that the assigned reviewers write.
 *
 * The references below are written from the spec text, independently of
 * the page code. The contract is in `../contract.ts`.
 */

import { expect, test } from '@playwright/test';
import type { CriterionSpec, FieldError, ScoreRead } from '../contract';
import { Rng, forAll, pageLogic } from './harness';

/** The canonical spelling of a score: `0`, or a non-zero digit and digits. */
const CANONICAL = /^(0|[1-9][0-9]*)$/;

/** Reference reading of one criterion field, by string comparison only. */
function refScore(text: string, max: number): ScoreRead {
  if (text === '') return { ok: false, reason: 'required' };
  if (!CANONICAL.test(text)) return { ok: false, reason: 'not_an_integer' };
  const top = String(max);
  const above = text.length > top.length || (text.length === top.length && text > top);
  if (above) return { ok: false, reason: 'above_scale' };
  return { ok: true, value: Number(text) };
}

/**
 * Characters that make a digit string non-canonical: separators, signs,
 * exponents, white space, and digits outside ASCII (full-width three,
 * Arabic-Indic three).
 */
const BAD_CHARS = [
  '.', ',', '-', '+', ' ', '\t', 'e', 'E', 'x', '_', ' ', '​', '３', '٣',
  '٫', 'n', 'I',
] as const;

/** A non-empty, non-canonical spelling built from a canonical integer. */
function nonCanonical(r: Rng, max: number): string {
  const base = String(r.int(0, max));
  switch (r.int(0, 3)) {
    case 0: {
      const at = r.int(0, base.length);
      return `${base.slice(0, at)}${r.pick(BAD_CHARS)}${base.slice(at)}`;
    }
    case 1:
      return `0${base}`;
    case 2:
      return `${base}.${r.pick(['0', '00', '5'])}`;
    default:
      return `${r.pick([' ', '\t', ' '])}${base}`;
  }
}

function criteriaOf(r: Rng): CriterionSpec[] {
  const n = r.int(1, 6);
  const ids = ['technical', 'impact', 'value', 'team', 'risk', 'openness'];
  return ids.slice(0, n).map((id) => ({ id, max: r.int(1, 10) }));
}

/** One input per criterion of a random kind, some left out, plus strays. */
function inputsFor(r: Rng, criteria: readonly CriterionSpec[]): Record<string, string> {
  const inputs: Record<string, string> = {};
  for (const c of criteria) {
    switch (r.int(0, 5)) {
      case 0:
        break;
      case 1:
        inputs[c.id] = '';
        break;
      case 2:
        inputs[c.id] = nonCanonical(r, c.max);
        break;
      case 3:
        inputs[c.id] = String(c.max + r.int(1, 100));
        break;
      default:
        inputs[c.id] = String(r.int(0, c.max));
    }
  }
  if (r.bool()) inputs['stray'] = String(r.int(0, 9));
  return inputs;
}

/** Reference reading of a whole sheet: values in P-01 order, or every error. */
function refSheet(
  criteria: readonly CriterionSpec[],
  inputs: Readonly<Record<string, string>>,
): { ok: true; value: number[] } | { ok: false; errors: FieldError[] } {
  const values: number[] = [];
  const errors: FieldError[] = [];
  for (const c of criteria) {
    const s = refScore(Object.hasOwn(inputs, c.id) ? (inputs[c.id] ?? '') : '', c.max);
    if (s.ok) values.push(s.value);
    else errors.push({ field: c.id, reason: s.reason });
  }
  return errors.length === 0 ? { ok: true, value: values } : { ok: false, errors };
}

test.describe('R-EV-02 score sheet (P-01 integer scale 0 to N)', () => {
  test('r_ev_02_every_integer_on_the_p01_scale_is_read_exactly', async () => {
    const m = await pageLogic('reviewer/forms');
    forAll(
      (r) => {
        const max = r.int(1, 20);
        return { max, v: r.int(0, max) };
      },
      ({ max, v }) => {
        expect(m.readCriterionScore(String(v), max)).toEqual({ ok: true, value: v });
      },
    );
  });

  test('r_ev_02_a_score_above_n_is_refused_however_long', async () => {
    const m = await pageLogic('reviewer/forms');
    forAll(
      (r) => {
        const max = r.int(1, 20);
        const text = r.bool()
          ? String(max + r.int(1, 1_000_000))
          : `${r.int(1, 9)}${'9'.repeat(r.int(16, 400))}`;
        return { max, text };
      },
      ({ max, text }) => {
        expect(m.readCriterionScore(text, max)).toEqual({ ok: false, reason: 'above_scale' });
      },
    );
  });

  test('r_ev_02_a_score_that_is_not_a_canonical_integer_is_refused', async () => {
    const m = await pageLogic('reviewer/forms');
    forAll(
      (r) => {
        const max = r.int(1, 20);
        return { max, text: nonCanonical(r, max) };
      },
      ({ max, text }) => {
        expect(CANONICAL.test(text), 'the generator builds non-canonical text').toBe(false);
        expect(m.readCriterionScore(text, max)).toEqual({ ok: false, reason: 'not_an_integer' });
      },
    );
  });

  test('r_ev_02_an_empty_score_is_required_never_zero', async () => {
    const m = await pageLogic('reviewer/forms');
    expect(m.readCriterionScore('', 5)).toEqual({ ok: false, reason: 'required' });
    expect(m.readCriterionScore('0', 5)).toEqual({ ok: true, value: 0 });
    expect(m.readCriterionScore('5', 5)).toEqual({ ok: true, value: 5 });
    expect(m.readCriterionScore('6', 5)).toEqual({ ok: false, reason: 'above_scale' });
    for (const text of ['3.5', '2.0', '-1', '+3', '03', '1e0', '0x3', 'NaN', 'Infinity', '３']) {
      expect(m.readCriterionScore(text, 5), text).toEqual({ ok: false, reason: 'not_an_integer' });
    }
  });

  test('r_ev_02_a_sheet_is_complete_only_with_every_criterion_scored', async () => {
    const m = await pageLogic('reviewer/forms');
    forAll(
      (r) => {
        const criteria = criteriaOf(r);
        return { criteria, inputs: inputsFor(r, criteria) };
      },
      ({ criteria, inputs }) => {
        expect(m.readScoreSheet(criteria, inputs)).toEqual(refSheet(criteria, inputs));
      },
    );
  });

  test('r_ev_02_sheet_values_follow_p01_order_not_input_order', async () => {
    const m = await pageLogic('reviewer/forms');
    const criteria = [
      { id: 'value', max: 5 },
      { id: 'technical', max: 5 },
      { id: 'impact', max: 5 },
    ];
    const inputs = { impact: '1', technical: '2', value: '3', stray: '4' };
    expect(m.readScoreSheet(criteria, inputs)).toEqual({ ok: true, value: [3, 2, 1] });
  });
});

test.describe('I-23 score correction', () => {
  test('i23_a_correction_needs_a_reason_and_keeps_it_as_typed', async () => {
    const m = await pageLogic('reviewer/forms');
    const criteria = [
      { id: 'technical', max: 5 },
      { id: 'impact', max: 5 },
    ];
    expect(m.readScoreCorrection(criteria, { technical: '4', impact: '2' }, '')).toEqual({
      ok: false,
      errors: [{ field: 'reason', reason: 'required' }],
    });
    expect(m.readScoreCorrection(criteria, { technical: '4' }, '')).toEqual({
      ok: false,
      errors: [
        { field: 'impact', reason: 'required' },
        { field: 'reason', reason: 'required' },
      ],
    });
    const reason = '  Misread the budget table.  ';
    expect(m.readScoreCorrection(criteria, { technical: '4', impact: '2' }, reason)).toEqual({
      ok: true,
      value: { values: [4, 2], reason },
    });
  });
});

test.describe('R-EV-08 ranking summary', () => {
  test('r_ev_08_ranking_summary_needs_title_summary_and_rationale', async () => {
    const m = await pageLogic('reviewer/forms');
    expect(m.readRankingSummary({ title: '', neutral_summary: '', rationale: '' })).toEqual({
      ok: false,
      errors: [
        { field: 'title', reason: 'required' },
        { field: 'neutral_summary', reason: 'required' },
        { field: 'rationale', reason: 'required' },
      ],
    });
    expect(m.readRankingSummary({ title: 'T', neutral_summary: '', rationale: 'R' })).toEqual({
      ok: false,
      errors: [{ field: 'neutral_summary', reason: 'required' }],
    });
    const full = { title: 'Open sensor kit', neutral_summary: 'A kit.', rationale: 'Strong plan.' };
    expect(m.readRankingSummary(full)).toEqual({ ok: true, value: full });
  });
});
