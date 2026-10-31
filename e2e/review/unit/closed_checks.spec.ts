/**
 * Seeded property checks of the closed response checks of the Judging
 * pages (lane W4c, fix round 1; M4 design section 3.9).
 *
 * The checks in `web/src/reviewer/kit.ts` and each `models.ts` parse the
 * server's JSON until the generated validators replace them. They are
 * the page's I-17 control: a read model with any member it does not name,
 * such as an identity attribute of an applicant, is refused whole. These
 * specs add or remove one member at a random depth of a valid read model
 * and check that the check refuses it.
 *
 * Interim, pending the lead: a libFuzzer target over the same checks
 * belongs in the web fuzz harness, which is outside this lane's files.
 *
 * Build first: web/node_modules/.bin/tsc -p web
 */

import { expect, test } from '@playwright/test';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { NotImplemented, forAll, webDir, type Rng } from './harness';

type Check = (v: unknown) => boolean;

interface Sample {
  readonly name: string;
  readonly check: Check;
  readonly value: unknown;
}

async function load(name: string): Promise<Record<string, unknown>> {
  const built = join(webDir(), 'dist', `${name}.js`);
  if (!existsSync(join(webDir(), 'src', `${name}.ts`))) {
    throw new NotImplemented(`web/src/${name}.ts does not exist yet`);
  }
  if (!existsSync(built)) {
    throw new Error(`web/dist/${name}.js is missing: build with web/node_modules/.bin/tsc -p web`);
  }
  return (await import(pathToFileURL(built).href)) as Record<string, unknown>;
}

function checkOf(mod: Record<string, unknown>, module: string, name: string): Check {
  const c = mod[name];
  if (typeof c !== 'function') {
    throw new NotImplemented(`web/src/${module}.ts does not export ${name}`);
  }
  return c as Check;
}

/** Every closed read model of the Judging pages, each with a valid sample that has every nested object. */
async function samples(): Promise<Sample[]> {
  const kit = await load('reviewer/kit');
  const rev = await load('reviewer/models');
  const com = await load('committee/models');
  const irc = await load('irc/models');
  const coo = await load('coordinator/models');
  const ranked = {
    proposal: '11',
    recused: false,
    title: 'Synthetic title',
    neutral_summary: null,
    rationale: 'Synthetic rationale.',
    effective: '80.00',
    criterion_scores: [{ criterion: '1', weighted: '40.00' }],
    requested: '50000.00',
    remaining_budget: '60000.00',
  };
  return [
    {
      name: 'AssignmentSummary',
      check: checkOf(kit, 'reviewer/kit', 'isAssignmentSummary'),
      value: { assignment: '21', proposal: '11', call: '5', kind: 'reviewer', awaiting_declaration: false, active: true },
    },
    {
      name: 'DeclarationView',
      check: checkOf(kit, 'reviewer/kit', 'isDeclarationView'),
      value: { title: 'Synthetic title', neutral_summary: 'Synthetic summary.' },
    },
    {
      name: 'ContentView',
      check: checkOf(kit, 'reviewer/kit', 'isContentView'),
      value: { proposal: '11', call: '5', state: 'STAGE1', title: 'Synthetic title', text: 'Synthetic text.' },
    },
    { name: 'Accepted', check: checkOf(kit, 'reviewer/kit', 'isAccepted'), value: { accepted: true } },
    {
      name: 'ScoreSheet',
      check: checkOf(rev, 'reviewer/models', 'isScoreSheet'),
      value: {
        stage: 'One',
        plan: '3',
        criteria: [{ id: '1', text: 'Synthetic criterion', max: 5 }],
        current: { score: '3', values: [4] },
      },
    },
    {
      name: 'Stage2Thread',
      check: checkOf(rev, 'reviewer/models', 'isStage2Thread'),
      value: {
        state: 'STAGE2',
        open: true,
        own_no_questions: false,
        entries: [{ kind: 'question', author: 'R-1', text: 'Synthetic question?' }],
      },
    },
    {
      name: 'RankingView',
      check: checkOf(com, 'committee/models', 'isRankingView'),
      value: [ranked, { proposal: '12', recused: true }],
    },
    { name: 'OpenedRound', check: checkOf(com, 'committee/models', 'isOpenedRound'), value: { round: '7' } },
    {
      name: 'RoundView',
      check: checkOf(com, 'committee/models', 'isRoundView'),
      value: {
        round: '7',
        call: '5',
        status: 'open',
        order: [{ proposal: '11', state: 'RANKED' }],
        nominated: 1,
        rationale: 'Synthetic rationale.',
        tie_break: null,
        ballots_cast: 0,
        viewer: { recused: false, own_vote: null, delegated_to: null },
        delegates: [{ account: '41', label: 'Synthetic member' }],
      },
    },
    {
      name: 'IrcCase',
      check: checkOf(irc, 'irc/models', 'isIrcCase'),
      value: { proposal: '11', state: 'IRC_REVIEW', title: 'Synthetic title', text: 'Synthetic text.', outcome: 'nominated' },
    },
    {
      name: 'IntakeQueue',
      check: checkOf(coo, 'coordinator/models', 'isIntakeQueue'),
      value: {
        knock_out: [{ id: '1', text: 'Synthetic criterion' }],
        proposals: [{ proposal: '11', state: 'SUBMITTED', title: 'Synthetic title' }],
      },
    },
    {
      name: 'Board',
      check: checkOf(coo, 'coordinator/models', 'isBoard'),
      value: [{ proposal: '11', state: 'STAGE1', title: 'Synthetic title' }],
    },
    {
      name: 'AssignmentView',
      check: checkOf(coo, 'coordinator/models', 'isAssignmentView'),
      value: {
        state: 'STAGE1',
        assigned: [{ assignment: '21', label: 'Synthetic reviewer' }],
        candidates: [{ account: '41', label: 'Synthetic member' }],
        checks: { p39: 'pass', proximity: 'fail' },
      },
    },
    {
      name: 'NotifiableList',
      check: checkOf(coo, 'coordinator/models', 'isNotifiableList'),
      value: [{ proposal: '11' }],
    },
  ];
}

type Path = readonly (string | number)[];

/** The path of every JSON object inside `v`, the root included. */
function objectPaths(v: unknown, at: Path = []): Path[] {
  if (Array.isArray(v)) {
    return v.flatMap((x, i) => objectPaths(x, [...at, i]));
  }
  if (typeof v === 'object' && v !== null) {
    const o = v as Record<string, unknown>;
    return [at, ...Object.keys(o).flatMap((k) => objectPaths(o[k], [...at, k]))];
  }
  return [];
}

function at(v: unknown, path: Path): Record<string, unknown> {
  let here: unknown = v;
  for (const step of path) {
    here = (here as Record<string | number, unknown>)[step];
  }
  return here as Record<string, unknown>;
}

/** Identity attribute names a Judging read model must never carry (I-17), and arbitrary names. */
const IDENTITY_NAMES = ['legal_name', 'name', 'email', 'country', 'affiliation', 'organisation', 'display_name', 'login'];

function genName(r: Rng, taken: readonly string[]): string {
  for (;;) {
    const name = r.bool()
      ? r.pick(IDENTITY_NAMES)
      : Array.from({ length: r.int(1, 12) }, () => r.pick([...'abcdefghijklmnopqrstuvwxyz_0123456789'])).join('');
    if (!taken.includes(name)) return name;
  }
}

function genValue(r: Rng): unknown {
  return r.pick<unknown>([null, true, false, 0, 7, '', 'Synthetic Person', 'synthetic@example.test', [], {}]);
}

interface Mutation {
  readonly sample: string;
  readonly path: Path;
  readonly member: string;
  readonly value: unknown;
}

let all: Sample[] = [];

test.describe('I-17 closed read model checks', () => {
  test.beforeAll(async () => {
    all = await samples();
  });

  /** The samples are valid, so a refusal below is caused by the mutation. */
  test('i17_every_closed_check_accepts_its_valid_sample', () => {
    for (const s of all) {
      expect(s.check(structuredClone(s.value)), s.name).toBe(true);
    }
  });

  /** I-17: an extra member on any object at any depth refuses the whole read model. */
  test('i17_an_extra_member_at_any_depth_refuses_the_read_model', () => {
    forAll(
      (r): Mutation => {
        const s = r.pick(all);
        const path = r.pick(objectPaths(s.value));
        const member = genName(r, Object.keys(at(s.value, path)));
        return { sample: s.name, path, member, value: genValue(r) };
      },
      (m) => {
        const s = all.find((x) => x.name === m.sample);
        if (s === undefined) throw new Error(`no sample ${m.sample}`);
        const v = structuredClone(s.value);
        at(v, m.path)[m.member] = m.value;
        expect(s.check(v)).toBe(false);
      },
    );
  });

  /** A missing member on any object at any depth refuses the whole read model, so none is assumed. */
  test('i17_a_missing_member_at_any_depth_refuses_the_read_model', () => {
    forAll(
      (r): { readonly sample: string; readonly path: Path; readonly member: string } => {
        const s = r.pick(all);
        const paths = objectPaths(s.value).filter((p) => Object.keys(at(s.value, p)).length > 0);
        const path = r.pick(paths);
        return { sample: s.name, path, member: r.pick(Object.keys(at(s.value, path))) };
      },
      (m) => {
        const s = all.find((x) => x.name === m.sample);
        if (s === undefined) throw new Error(`no sample ${m.sample}`);
        const v = structuredClone(s.value);
        delete at(v, m.path)[m.member];
        expect(s.check(v)).toBe(false);
      },
    );
  });
});
