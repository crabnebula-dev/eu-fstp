/**
 * Reviewer test (spec fidelity), TH-26, H-05 and the project rule that
 * every in-house parser gets a fuzz target from its first commit.
 *
 * `web/src/auth/next.ts` `isReturnPath` reads an untrusted `?next=`
 * query member: it decodes percent escapes, splits path segments and
 * decides where the login page redirects. It is the open-redirect guard
 * of the login page, the same kind of check as `safe_url`, which has a
 * fuzz target. No target under `web/fuzz/` drives it.
 */

import { expect, test } from '@playwright/test';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

test('review_fidelity_th26_return_path_check_has_a_fuzz_target', () => {
  const fuzz = resolve(__dirname, '..', '..', 'web', 'fuzz');
  const targets = readdirSync(fuzz).filter((f) => f.endsWith('.fuzz.ts'));
  const driving = targets.filter((f) => /auth\/next(\.js)?["']/.test(readFileSync(join(fuzz, f), 'utf8')));
  expect(driving, `a fuzz target under web/fuzz drives auth/next.ts; targets: ${targets.join(', ')}`).not.toEqual([]);
});
