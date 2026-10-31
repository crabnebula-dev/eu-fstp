/**
 * Node-only tests of the onboarding page logic, and static checks of its
 * sources (M4 lane W4a, design sections 3.5 and 3.9).
 *
 * These run under Playwright with no browser, for the reason given in
 * `creator/pages_logic.spec.ts`. Red until lane W4a's page agent writes
 * `web/src/onboarding/model.ts` and its catalogue.
 */

import { expect, test } from '@playwright/test';
import { ONBOARDING_STEPS } from './creator/contract';
import { WEB_SRC, catalogueProblems, forAll, load, type OnboardingModel, type StepStatusName } from './creator/modules';
import { literalProblems, lookupProblems } from './creator/scan';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const EXPORTS = ['ONBOARDING_STEPS', 'openableSteps'] as const;

const STATUSES: readonly StepStatusName[] = ['locked', 'open', 'saved', 'validated', 'skipped', 'unavailable'];

test.describe('onboarding page logic', () => {
  /** R-TN-01: the steps in the order of the onboarding table of `programme-creator.md`. */
  test('r_tn_01_onboarding_model_lists_the_steps_of_the_spec_table', async () => {
    const m = await load<OnboardingModel>('onboarding', 'model', EXPORTS);
    expect([...m.ONBOARDING_STEPS]).toEqual([...ONBOARDING_STEPS]);
  });

  /**
   * R-TN-01: "Each step validates before the next opens." A step can be
   * opened exactly when every earlier step is validated, or skipped as
   * Agreements is in a self-hosted cell.
   */
  test('r_tn_01_a_step_opens_only_after_every_earlier_step_validates', async () => {
    const m = await load<OnboardingModel>('onboarding', 'model', EXPORTS);
    forAll(
      (r) => {
        const statuses: Record<string, StepStatusName> = {};
        // Bias towards long validated prefixes, so later steps are reached.
        const prefix = r.below(ONBOARDING_STEPS.length + 1);
        ONBOARDING_STEPS.forEach((s, i) => {
          statuses[s] = i < prefix ? r.pick(['validated', 'validated', 'skipped'] as const) : r.pick(STATUSES);
        });
        return statuses;
      },
      (statuses) => {
        const expected: string[] = [];
        for (const s of ONBOARDING_STEPS) {
          expected.push(s);
          const st = statuses[s];
          if (st !== 'validated' && st !== 'skipped') break;
        }
        expect([...m.openableSteps(statuses)]).toEqual(expected);
      },
    );
  });
});

test.describe('R-NF-04 onboarding sources', () => {
  /** R-NF-04 with the writing rules: the catalogue loads in core i18n, with no em dash and short sentences. */
  test('r_nf_04_onboarding_catalogue_loads_in_core_i18n_and_follows_the_prose_rules', async () => {
    expect((await catalogueProblems('onboarding')).problems).toEqual([]);
  });

  /** R-NF-04: no user-visible literal outside the catalogue. */
  test('r_nf_04_onboarding_sources_have_no_literal_user_strings', () => {
    expect(literalProblems(WEB_SRC, 'onboarding')).toEqual([]);
  });

  /** R-NF-04 and I-72: every label or approved id a page looks up is in its catalogue, of that kind. */
  test('r_nf_04_onboarding_lookup_ids_are_in_the_catalogue', async () => {
    const c = await catalogueProblems('onboarding');
    expect(lookupProblems(WEB_SRC, 'onboarding', c.labels, c.approved)).toEqual([]);
  });
});

/** `web/src/onboarding/model.ts`, the set helpers and the P-74 role table. */
interface SetModel {
  nameSet(names: Iterable<string>): string[];
  accountSet(ids: Iterable<string>): string[] | null;
  readonly MCP_ROLES: readonly string[];
  roleSpecName(key: string): string;
  roleOfSpecName(name: string): string | null;
  mcpValue(
    enabled: boolean,
    publicTools: boolean,
    everyRole: boolean,
    roles: Iterable<string>,
  ): { readonly enabled: boolean; readonly public_tools: boolean; readonly roles: readonly string[] | null };
}

const SET_EXPORTS = ['nameSet', 'accountSet', 'MCP_ROLES', 'roleSpecName', 'roleOfSpecName', 'mcpValue'] as const;

/** The `Role::spec_name` spellings of `fstp-domain`, in the order of its match arms. */
function rustSpecNames(): string[] {
  const src = readFileSync(join(WEB_SRC, '..', '..', 'crates', 'fstp-domain', 'src', 'roles', 'mod.rs'), 'utf8');
  const body = src.slice(src.indexOf('pub const fn spec_name'));
  const end = body.indexOf('\n    }\n');
  const out: string[] = [];
  for (const m of body.slice(0, end).matchAll(/Role::[A-Za-z]+ => "([^"]+)"/g)) out.push(m[1] ?? '');
  return out;
}

/** Whether `xs` is strictly ascending by code unit, as `take_name_set` requires. */
function ascending(xs: readonly string[]): boolean {
  return xs.every((x, i) => i === 0 || (xs[i - 1] ?? '') < x);
}

test.describe('onboarding set values', () => {
  /**
   * R-LG-03, P-74: the page offers one checkbox per `fstp_domain` role,
   * and sends each in the spelling of `Role::spec_name`, which the
   * `fstp-tenant` codec takes. A missing role, or another spelling, would
   * drop or refuse a stored restriction.
   */
  test('r_lg_03_p74_roles_are_every_fstp_domain_role_in_codec_spelling', async () => {
    const m = await load<SetModel>('onboarding', 'model', SET_EXPORTS);
    const rust = rustSpecNames();
    expect(rust.length).toBe(14);
    expect(m.MCP_ROLES.map((k) => m.roleSpecName(k))).toEqual(rust);
    for (const k of m.MCP_ROLES) expect(m.roleOfSpecName(m.roleSpecName(k))).toBe(k);
    expect(m.roleOfSpecName('committee_member')).toBeNull();
  });

  /**
   * R-LG-03, P-74: only the explicit "every role" choice sends
   * `roles: null`. Any chosen roles, even none, go out as a strictly
   * ascending name set, so a save never widens a restriction.
   */
  test('r_lg_03_p74_value_is_null_only_for_an_explicit_every_role_choice', async () => {
    const m = await load<SetModel>('onboarding', 'model', SET_EXPORTS);
    const names = m.MCP_ROLES.map((k) => m.roleSpecName(k));
    forAll(
      (r) => ({ every: r.below(2) === 0, picked: names.filter(() => r.below(3) === 0) }),
      ({ every, picked }) => {
        const v = m.mcpValue(true, false, every, picked);
        if (every) {
          expect(v.roles).toBeNull();
        } else {
          expect(v.roles).not.toBeNull();
          expect(ascending(v.roles ?? [])).toBe(true);
          expect([...(v.roles ?? [])].sort()).toEqual([...new Set(picked)].sort());
        }
      },
    );
  });

  /**
   * R-TN-01 and R-LG-03: every name set a page sends is strictly
   * ascending by code unit and holds each chosen name once
   * (`take_name_set`), whatever order the checkboxes are in.
   */
  test('r_tn_01_name_sets_are_sent_strictly_ascending', async () => {
    const m = await load<SetModel>('onboarding', 'model', SET_EXPORTS);
    const pool = ['passkey', 'eudi_wallet', 'opaque', 'magic_link', 'document_upload', 'Committee member', 'Applicant'];
    forAll(
      (r) => Array.from({ length: r.below(8) }, () => r.pick(pool)),
      (xs) => {
        const out = m.nameSet(xs);
        expect(ascending(out)).toBe(true);
        expect(new Set(out)).toEqual(new Set(xs));
      },
    );
  });

  /**
   * R-TN-01: signatories and admins go out as account sets, strictly
   * ascending by numeric value (`take_accounts`), and a value that is
   * not a canonical decimal id sends nothing.
   */
  test('r_tn_01_account_sets_are_sent_numerically_ascending', async () => {
    const m = await load<SetModel>('onboarding', 'model', SET_EXPORTS);
    forAll(
      (r) => Array.from({ length: r.below(6) }, () => String(r.below(3) === 0 ? r.below(20) : r.next())),
      (xs) => {
        const out = m.accountSet(xs);
        expect(out).not.toBeNull();
        const nums = (out ?? []).map((x) => BigInt(x));
        expect(nums.every((n, i) => i === 0 || (nums[i - 1] ?? -1n) < n)).toBe(true);
        expect(new Set(out)).toEqual(new Set(xs));
      },
    );
    expect(m.accountSet(['10', '9'])).toEqual(['9', '10']);
    expect(m.accountSet(['07'])).toBeNull();
    expect(m.accountSet(['-1'])).toBeNull();
  });
});
