/**
 * Node-only tests of the creator and people page logic, and static
 * checks of their sources (M4 lane W4a, design sections 3.2, 3.9 and 8.1).
 *
 * Design section 8.1 places TypeScript unit tests on the in-house runner
 * of `web/test`. That directory belongs to lane W1c, outside this lane's
 * file scope, so these tests run under Playwright with no browser. They
 * import the pure modules of `web/src/{creator,people}` through
 * `modules.ts`, which states the exports they need. The lead may move
 * them to `web/test` without changing what they check.
 *
 * Red until lane W4a's page agent writes the modules and catalogues.
 */

import { expect, test } from '@playwright/test';
import { CREATOR_STEPS, REVIEW_STEP, ROLE_KEYS } from './contract';
import {
  WEB_SRC,
  catalogueProblems,
  forAll,
  load,
  type CreatorModel,
  type GateResult,
  type InvitationState,
  type PeopleModel,
} from './modules';
import { literalProblems, lookupProblems, looksLikeUserText, lookups, tsLiterals } from './scan';
import { superSafe } from './support';

const CREATOR_EXPORTS = ['CREATOR_STEPS', 'stepOfField', 'activationGate'] as const;

test.describe('creator page logic', () => {
  /** R-PG-01: the creator walks steps 1 to 10 of `programme-creator.md`, then the review (step 11). */
  test('r_pg_01_creator_model_lists_the_eleven_steps_of_the_spec_table', async () => {
    const m = await load<CreatorModel>('creator', 'model', CREATOR_EXPORTS);
    expect(m.CREATOR_STEPS.map((s) => s.id)).toEqual([...CREATOR_STEPS, REVIEW_STEP]);
    expect(m.CREATOR_STEPS.map((s) => s.number)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  });

  /**
   * R-PG-01: every field of the SuperSAFE fixture has its step page, the
   * step whose member holds it in the spec JSON. A key that names no
   * field has none.
   */
  test('r_pg_01_every_fixture_field_maps_to_its_creator_step', async () => {
    const m = await load<CreatorModel>('creator', 'model', CREATOR_EXPORTS);
    const f = superSafe();
    const wrong: string[] = [];
    for (const step of CREATOR_STEPS) {
      for (const member of Object.keys(f.spec[step] as object)) {
        const key = `${step}.${member}`;
        if (m.stepOfField(key) !== step) wrong.push(`${key} -> ${String(m.stepOfField(key))}`);
      }
    }
    expect(wrong).toEqual([]);
    for (const key of ['money.not_a_field', 'review.report', 'p05_recipient_cap', '', 'money.']) {
      expect(m.stepOfField(key), key).toBeNull();
    }
  });

  /**
   * I-66: the review page offers the activation request exactly when the
   * report shows no failure and every warning is acknowledged. An
   * acknowledgement never clears a failure.
   */
  test('i66_review_offers_the_activation_request_only_on_a_clean_report', async () => {
    const m = await load<CreatorModel>('creator', 'model', CREATOR_EXPORTS);
    forAll(
      (r) =>
        Array.from({ length: r.below(9) }, (): GateResult => ({
          severity: r.pick(['failure', 'warning'] as const),
          acknowledged: r.below(2) === 0,
        })),
      (results) => {
        const failures = results.filter((x) => x.severity === 'failure').length;
        const unacknowledged = results.filter((x) => x.severity === 'warning' && !x.acknowledged).length;
        expect(m.activationGate(results)).toEqual({
          canRequest: failures === 0 && unacknowledged === 0,
          failures,
          unacknowledged,
        });
      },
    );
  });
});

test.describe('people page logic', () => {
  /**
   * SoD-09 and J2: the grant is offered only for an invitee who accepted
   * the terms and verified identity, never twice, and while the
   * programme is a draft only for a programme manager (D1).
   */
  test('sod09_grant_is_offered_only_after_terms_and_verification', async () => {
    const m = await load<PeopleModel>('people', 'model', ['grantOffered']);
    const roles = Object.values(ROLE_KEYS);
    const states: readonly InvitationState[] = ['invited', 'accepted', 'verified', 'granted'];
    forAll(
      (r) => ({
        programme: r.pick(['draft', 'active'] as const),
        role: r.pick(roles),
        state: r.pick(states),
      }),
      ({ programme, role, state }) => {
        const expected = state === 'verified' && (programme === 'active' || role === ROLE_KEYS.programmeManager);
        expect(m.grantOffered(programme, role, state)).toBe(expected);
      },
    );
  });
});

test.describe('R-NF-04 creator and people sources', () => {
  for (const dir of ['creator', 'people'] as const) {
    /** R-NF-04 with the writing rules: the catalogue loads in core i18n, with no em dash and short sentences. */
    test(`r_nf_04_${dir}_catalogue_loads_in_core_i18n_and_follows_the_prose_rules`, async () => {
      expect((await catalogueProblems(dir)).problems).toEqual([]);
    });

    /** R-NF-04: no user-visible literal outside the catalogue. */
    test(`r_nf_04_${dir}_sources_have_no_literal_user_strings`, () => {
      expect(literalProblems(WEB_SRC, dir)).toEqual([]);
    });

    /** R-NF-04 and I-72: every label or approved id a page looks up is in its catalogue, of that kind. */
    test(`r_nf_04_${dir}_lookup_ids_are_in_the_catalogue`, async () => {
      const c = await catalogueProblems(dir);
      expect(lookupProblems(WEB_SRC, dir, c.labels, c.approved)).toEqual([]);
    });
  }

  /** R-NF-04: the scanner's own teeth. A page that spells text fails, and technical tokens pass. */
  test('r_nf_04_feature_scanner_flags_literals_and_spares_technical_tokens', () => {
    const found = tsLiterals(
      [
        "import { h } from '../core/dom.js';",
        "const x = 'Save this step';",
        'const y = `Step ${n} of eleven`;',
        "if (e.key === 'Escape') close();",
        "const re = /it's a regex/u;",
        "// 'In a comment'",
        "el.textContent = i18n.label('creator.step.save');",
        "const z = 'Continue';",
        "const attr = 'data-field';",
      ].join('\n'),
    )
      .filter((l) => looksLikeUserText(l.text))
      .map((l) => l.text.trim());
    expect(found).toEqual(['Save this step', 'Step', 'of eleven', 'Continue']);
    expect(lookups("i18n.label('creator.step.save'); i18n.approved(\"people.terms\"); label(id);")).toEqual([
      { kind: 'label', id: 'creator.step.save', line: 1 },
      { kind: 'approved', id: 'people.terms', line: 1 },
    ]);
  });
});
