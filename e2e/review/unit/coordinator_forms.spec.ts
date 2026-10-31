/**
 * Page logic of the conflict declaration (shared by the coordinator, the
 * assigned reviewers and the IRC members) and of the coordinator's
 * knock-out form (J5, J6, J8, M4 design section 2.2), against
 * `web/src/reviewer/declaration.ts` and `web/src/coordinator/forms.ts`.
 *
 * - R-CF-02: reviewers declare conflicts before accessing full content.
 *   The form presets no answer, so no declaration is made by default.
 * - R-CF-04: a notifiable conflict is a conflict that is recorded as
 *   notifiable.
 * - R-EV-01: a proposal failing any knock-out criterion receives no
 *   further review. Each P-09 criterion gets an explicit result, and a
 *   failure carries its reason (`RecordKnockOut`).
 */

import { expect, test } from '@playwright/test';
import type { FieldError, KnockOutChoice } from '../contract';
import { forAll, pageLogic } from './harness';

test.describe('R-CF-02 and R-CF-04 declaration', () => {
  test('r_cf_02_a_declaration_has_no_preset_answer', async () => {
    const m = await pageLogic('reviewer/declaration');
    expect(m.readDeclaration({ conflicted: null, notifiable: false })).toEqual({
      ok: false,
      errors: [{ field: 'conflicted', reason: 'required' }],
    });
    expect(m.readDeclaration({ conflicted: 'no', notifiable: false })).toEqual({
      ok: true,
      value: { conflicted: false, notifiable: false },
    });
    expect(m.readDeclaration({ conflicted: 'yes', notifiable: false })).toEqual({
      ok: true,
      value: { conflicted: true, notifiable: false },
    });
  });

  test('r_cf_04_only_a_declared_conflict_can_be_notifiable', async () => {
    const m = await pageLogic('reviewer/declaration');
    expect(m.readDeclaration({ conflicted: 'yes', notifiable: true })).toEqual({
      ok: true,
      value: { conflicted: true, notifiable: true },
    });
    expect(m.readDeclaration({ conflicted: 'no', notifiable: true })).toEqual({
      ok: false,
      errors: [{ field: 'notifiable', reason: 'needs_conflict' }],
    });
    expect(m.readDeclaration({ conflicted: null, notifiable: true })).toEqual({
      ok: false,
      errors: [
        { field: 'conflicted', reason: 'required' },
        { field: 'notifiable', reason: 'needs_conflict' },
      ],
    });
  });
});

/** Reference reading of the knock-out form, from the `RecordKnockOut` rules. */
function refKnockOut(
  criteria: readonly string[],
  results: Readonly<Record<string, KnockOutChoice>>,
  reason: string,
):
  | {
      ok: true;
      value: { outcomes: { criterion: string; passed: boolean }[]; reason: string | null };
    }
  | { ok: false; errors: FieldError[] } {
  const errors: FieldError[] = [];
  const outcomes: { criterion: string; passed: boolean }[] = [];
  for (const c of criteria) {
    const v = Object.hasOwn(results, c) ? results[c] : null;
    if (v === 'pass' || v === 'fail') outcomes.push({ criterion: c, passed: v === 'pass' });
    else errors.push({ field: c, reason: 'required' });
  }
  const failed = criteria.some((c) => Object.hasOwn(results, c) && results[c] === 'fail');
  if (failed && reason === '') errors.push({ field: 'reason', reason: 'required' });
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, value: { outcomes, reason: reason === '' ? null : reason } };
}

test.describe('R-EV-01 knock-out', () => {
  test('r_ev_01_knock_out_needs_a_result_per_p09_criterion_and_a_reason_on_failure', async () => {
    const m = await pageLogic('coordinator/forms');
    forAll(
      (r) => {
        const all = ['eligible_country', 'eligible_entity', 'complete', 'in_scope', 'on_time'];
        const criteria = all.slice(0, r.int(1, all.length));
        const results: Record<string, KnockOutChoice> = {};
        for (const c of criteria) {
          const k = r.int(0, 4);
          if (k === 0) continue;
          results[c] = k === 1 ? null : k === 2 ? 'fail' : 'pass';
        }
        if (r.bool()) results['unknown_criterion'] = r.bool() ? 'fail' : 'pass';
        const reason = r.bool() ? '' : r.pick(['Missing annex.', ' x ', 'Outside scope']);
        return { criteria, results, reason };
      },
      ({ criteria, results, reason }) => {
        expect(m.readKnockOut(criteria, { results, reason })).toEqual(
          refKnockOut(criteria, results, reason),
        );
      },
    );
  });

  test('r_ev_01_a_failed_criterion_without_reason_is_refused', async () => {
    const m = await pageLogic('coordinator/forms');
    const criteria = ['eligible_country', 'complete'];
    expect(
      m.readKnockOut(criteria, { results: { eligible_country: 'pass', complete: 'fail' }, reason: '' }),
    ).toEqual({ ok: false, errors: [{ field: 'reason', reason: 'required' }] });
    expect(
      m.readKnockOut(criteria, { results: { eligible_country: 'pass', complete: 'pass' }, reason: '' }),
    ).toEqual({
      ok: true,
      value: {
        outcomes: [
          { criterion: 'eligible_country', passed: true },
          { criterion: 'complete', passed: true },
        ],
        reason: null,
      },
    });
  });
});
