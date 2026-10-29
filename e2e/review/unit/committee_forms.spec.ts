/**
 * Page logic of the committee's cut-off round and ballot (J7, M4 design
 * section 2.2 and change D5), against `web/src/committee/forms.ts`.
 *
 * - R-EV-08: the committee sets a cut-off from the ranking view, and the
 *   rationale is recorded.
 * - P-02 NOTE 6: scores are percentages with two decimals, compared
 *   exactly, with no rounding. The page compares the server's text, never
 *   a float.
 * - NOTE 6 of `state-machine.md` and P-17: a tie across the cut-off is
 *   broken under P-17, and the tie-break is recorded. The reference
 *   mirrors the domain's `plan_cut_off` (`fstp-domain` `decision.rs`).
 * - R-EV-09 and Q4: each member casts their own ballot, with no preset
 *   vote.
 */

import { expect, test } from '@playwright/test';
import type { CutOffInput, CutOffRow, FieldError } from '../contract';
import { type Rng, forAll, pageLogic } from './harness';

const SCORE = /^(0|[1-9][0-9]*)\.[0-9]{2}$/;
const INTEGER = /^(0|[1-9][0-9]*)$/;

/** Reference comparison: the digits without the point, as a BigInt. */
function refCompare(a: string, b: string): -1 | 0 | 1 | null {
  if (!SCORE.test(a) || !SCORE.test(b)) return null;
  const x = BigInt(a.replace('.', ''));
  const y = BigInt(b.replace('.', ''));
  return x < y ? -1 : x > y ? 1 : 0;
}

/** The canonical text of `hundredths`, built from strings only. */
function scoreText(hundredths: number): string {
  const s = String(hundredths).padStart(3, '0');
  return `${s.slice(0, -2)}.${s.slice(-2)}`;
}

/** A canonical score, sometimes with a long integer part to catch rounding. */
function genScore(r: Rng): string {
  if (r.int(0, 7) === 0) {
    const digits = `${r.int(1, 9)}${Array.from({ length: r.int(15, 30) }, () => String(r.int(0, 9))).join('')}`;
    return `${digits}.${String(r.int(0, 99)).padStart(2, '0')}`;
  }
  return scoreText(r.int(0, 10_000));
}

/** The canonical score one hundredth above or below `a`, by BigInt digits. */
function neighbour(a: string, up: boolean): string {
  const x = BigInt(a.replace('.', ''));
  const y = up ? x + 1n : x === 0n ? 1n : x - 1n;
  const s = y.toString().padStart(3, '0');
  return `${s.slice(0, -2)}.${s.slice(-2)}`;
}

const NOT_CANONICAL = [
  '75.0', '075.00', '75.000', '-1.00', '1e2', '75', '', ' 75.00', '75.00 ', '75,00', '+75.00',
  '.50', '75.', '７５.00', '00.00',
] as const;

test.describe('P-02 exact score comparison', () => {
  test('r_ev_08_score_text_comparison_is_exact', async () => {
    const m = await pageLogic('committee/forms');
    forAll(
      (r) => {
        const a = genScore(r);
        // Equal texts and neighbours one hundredth away catch a rounded
        // comparison, which long integer parts expose.
        const k = r.int(0, 3);
        const b = k === 0 ? a : k === 1 ? neighbour(a, r.bool()) : genScore(r);
        return { a, b };
      },
      ({ a, b }) => {
        expect(m.compareScoreText(a, b)).toBe(refCompare(a, b));
      },
    );
  });

  test('r_ev_08_non_canonical_score_text_is_never_compared', async () => {
    const m = await pageLogic('committee/forms');
    for (const bad of NOT_CANONICAL) {
      expect(m.compareScoreText(bad, '75.00'), bad).toBeNull();
      expect(m.compareScoreText('75.00', bad), bad).toBeNull();
    }
    expect(m.compareScoreText('75.00', '75.01')).toBe(-1);
    expect(m.compareScoreText('100.00', '99.99')).toBe(1);
    expect(m.compareScoreText('12345678901234567.89', '12345678901234567.88')).toBe(1);
  });
});

/** Reference reading of the open-round form. */
function refCutOff(
  rows: readonly CutOffRow[],
  input: CutOffInput,
):
  | {
      ok: true;
      value: { order: string[]; nominated: number; rationale: string; tie_break: string | null };
    }
  | { ok: false; errors: FieldError[] } {
  const errors: FieldError[] = [];
  if (rows.length === 0) {
    errors.push({ field: 'order', reason: 'empty' });
  } else if (rows.some((row) => !SCORE.test(row.effective))) {
    errors.push({ field: 'order', reason: 'unreadable_score' });
  } else if (
    rows.some((row, i) => {
      const next = rows[i + 1];
      return next !== undefined && refCompare(row.effective, next.effective) === -1;
    })
  ) {
    errors.push({ field: 'order', reason: 'not_ordered' });
  }
  let n: number | null = null;
  const top = String(rows.length);
  if (input.nominated === '') {
    errors.push({ field: 'nominated', reason: 'required' });
  } else if (!INTEGER.test(input.nominated)) {
    errors.push({ field: 'nominated', reason: 'not_an_integer' });
  } else if (
    input.nominated.length > top.length ||
    (input.nominated.length === top.length && input.nominated > top)
  ) {
    errors.push({ field: 'nominated', reason: 'out_of_range' });
  } else {
    n = Number(input.nominated);
  }
  if (input.rationale === '') errors.push({ field: 'rationale', reason: 'required' });
  if (n !== null && n > 0) {
    const last = rows[n - 1];
    const first = rows[n];
    if (
      last !== undefined &&
      first !== undefined &&
      refCompare(last.effective, first.effective) === 0 &&
      input.tie_break === ''
    ) {
      errors.push({ field: 'tie_break', reason: 'required' });
    }
  }
  if (errors.length > 0 || n === null) return { ok: false, errors };
  return {
    ok: true,
    value: {
      order: rows.map((row) => row.proposal),
      nominated: n,
      rationale: input.rationale,
      tie_break: input.tie_break === '' ? null : input.tie_break,
    },
  };
}

/** Rows by non-increasing score with ties, sometimes spoiled. */
function genRows(r: Rng): CutOffRow[] {
  const count = r.int(0, 6);
  let v = r.int(5_000, 10_000);
  const rows: CutOffRow[] = [];
  for (let i = 0; i < count; i += 1) {
    rows.push({ proposal: `p${i}`, effective: scoreText(v) });
    if (r.bool()) v = Math.max(0, v - r.int(1, 900));
  }
  const spoil = r.int(0, 5);
  if (spoil === 0 && rows.length >= 2) {
    const i = r.int(0, rows.length - 2);
    const a = rows[i];
    const b = rows[i + 1];
    if (a !== undefined && b !== undefined) {
      rows[i] = { proposal: a.proposal, effective: b.effective };
      rows[i + 1] = { proposal: b.proposal, effective: a.effective };
    }
  } else if (spoil === 1 && rows.length >= 1) {
    const i = r.int(0, rows.length - 1);
    const a = rows[i];
    if (a !== undefined) rows[i] = { proposal: a.proposal, effective: r.pick(NOT_CANONICAL) };
  }
  return rows;
}

function genNominated(r: Rng, rows: number): string {
  switch (r.int(0, 5)) {
    case 0:
      return '';
    case 1:
      return r.pick(['1.0', '01', '-1', ' 2', '2 ', '+1', '1e0']);
    case 2:
      return String(rows + r.int(1, 3));
    default:
      return String(r.int(0, rows));
  }
}

test.describe('R-EV-08 cut-off round', () => {
  test('r_ev_08_cutoff_with_unbroken_tie_is_refused_by_the_form', async () => {
    const m = await pageLogic('committee/forms');
    forAll(
      (r) => {
        const rows = genRows(r);
        const input: CutOffInput = {
          nominated: genNominated(r, rows.length),
          rationale: r.int(0, 4) === 0 ? '' : 'Within the remaining budget.',
          tie_break: r.bool() ? '' : 'P-17: exceptional quality.',
        };
        return { rows, input };
      },
      ({ rows, input }) => {
        expect(m.readCutOffRound(rows, input)).toEqual(refCutOff(rows, input));
      },
      512,
    );
  });

  test('r_ev_08_a_tie_across_the_cut_off_needs_a_tie_break_and_no_other_does', async () => {
    const m = await pageLogic('committee/forms');
    const rows: CutOffRow[] = [
      { proposal: 'x', effective: '91.00' },
      { proposal: 'v', effective: '82.50' },
      { proposal: 'w', effective: '82.50' },
      { proposal: 'u', effective: '70.00' },
    ];
    const base = { rationale: 'Budget allows two.', tie_break: '' };
    expect(m.readCutOffRound(rows, { ...base, nominated: '2' })).toEqual({
      ok: false,
      errors: [{ field: 'tie_break', reason: 'required' }],
    });
    // The tie lies inside the nominated block, not across the cut-off.
    expect(m.readCutOffRound(rows, { ...base, nominated: '3' })).toEqual({
      ok: true,
      value: { order: ['x', 'v', 'w', 'u'], nominated: 3, rationale: base.rationale, tie_break: null },
    });
    expect(
      m.readCutOffRound(rows, { ...base, nominated: '2', tie_break: 'P-17 applied.' }),
    ).toEqual({
      ok: true,
      value: { order: ['x', 'v', 'w', 'u'], nominated: 2, rationale: base.rationale, tie_break: 'P-17 applied.' },
    });
  });

  test('r_ev_08_a_cut_off_needs_its_rationale', async () => {
    const m = await pageLogic('committee/forms');
    const rows: CutOffRow[] = [{ proposal: 'x', effective: '91.00' }];
    expect(m.readCutOffRound(rows, { nominated: '1', rationale: '', tie_break: '' })).toEqual({
      ok: false,
      errors: [{ field: 'rationale', reason: 'required' }],
    });
  });
});

test.describe('R-EV-09 ballot', () => {
  test('r_ev_09_a_ballot_has_no_preset_vote', async () => {
    const m = await pageLogic('committee/forms');
    expect(m.readBallot({ vote: null })).toEqual({
      ok: false,
      errors: [{ field: 'vote', reason: 'required' }],
    });
    for (const vote of ['for', 'against', 'abstain'] as const) {
      expect(m.readBallot({ vote })).toEqual({ ok: true, value: { vote } });
    }
  });
});
