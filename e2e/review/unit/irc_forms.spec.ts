/**
 * Page logic of the IRC verdict (J8, M4 design section 2.2), against
 * `web/src/irc/forms.ts`.
 *
 * - R-IR-01: IRC members review each nominated proposal and validate it
 *   or raise a concern (`RecordIrcReview`). No verdict is preset.
 * - R-IR-02: an IRC concern is sent to the applicant, so it carries its
 *   text. A validation carries none.
 */

import { expect, test } from '@playwright/test';
import { pageLogic } from './harness';

test.describe('R-IR-01 and R-IR-02 IRC verdict', () => {
  test('r_ir_01_a_verdict_has_no_preset', async () => {
    const m = await pageLogic('irc/forms');
    expect(m.readVerdict({ verdict: null, concern: '' })).toEqual({
      ok: false,
      errors: [{ field: 'verdict', reason: 'required' }],
    });
    expect(m.readVerdict({ verdict: null, concern: 'Budget looks high.' })).toEqual({
      ok: false,
      errors: [{ field: 'verdict', reason: 'required' }],
    });
  });

  test('r_ir_01_a_validation_carries_no_text', async () => {
    const m = await pageLogic('irc/forms');
    expect(m.readVerdict({ verdict: 'validate', concern: '' })).toEqual({
      ok: true,
      value: { verdict: 'validate' },
    });
    expect(m.readVerdict({ verdict: 'validate', concern: 'Typed, then changed my mind.' })).toEqual({
      ok: true,
      value: { verdict: 'validate' },
    });
  });

  test('r_ir_02_a_concern_needs_its_text_for_the_applicant', async () => {
    const m = await pageLogic('irc/forms');
    expect(m.readVerdict({ verdict: 'concern', concern: '' })).toEqual({
      ok: false,
      errors: [{ field: 'concern', reason: 'required' }],
    });
    const concern = ' The plan exceeds the frugality bar. ';
    expect(m.readVerdict({ verdict: 'concern', concern })).toEqual({
      ok: true,
      value: { verdict: 'concern', concern },
    });
  });
});
