/**
 * Unit and property tests of the applicant page logic (M4 design
 * sections 3.9 and 8.1, lane W4b). They need no stack and no browser.
 *
 * The lane's file scope is `web/src/{calls,applicant}/**` and
 * `e2e/applicant/**`, and `web/test/**` belongs to lane W1c. So these
 * tests live here and run under Playwright's Node.js runner. They load
 * the compiled modules from `web/dist` (`web/node_modules/.bin/tsc -p
 * web`). The lead may move them to `web/test/` later without changing
 * an assertion.
 *
 * # Module contract (lane W4b implementer)
 *
 * Interim, pending the W4b implementer and the lead.
 *
 * `web/src/applicant/rules.ts`, pure, no DOM:
 *
 * ```ts
 * export type ProposalState = 'DRAFT' | ... | 'TERMINATED'; // the 16 spec names
 * export const PROPOSAL_STATES: readonly ProposalState[];   // each once
 * export function parseProposalState(v: unknown): ProposalState | null; // exact spec name only
 * export function withdrawOffered(s: ProposalState): boolean; // state-machine NOTE 10
 * export function draftEditable(s: ProposalState): boolean;   // workspace, plan, eligibility, submit
 * export function stage2Open(s: ProposalState): boolean;      // answers and revision
 * export function negotiationOpen(s: ProposalState): boolean; // the negotiation landing
 * ```
 *
 * `web/src/applicant/autosave.ts`, pure, no DOM, its timer injected:
 *
 * ```ts
 * export type AutosaveStatus = 'idle' | 'pending' | 'saving' | 'saved' | 'failed';
 * export interface AutosaveDeps<T> {
 *   save(value: T): Promise<boolean>;          // true when the cell stored it; a rejection counts as false
 *   setTimer(fn: () => void, ms: number): number;
 *   clearTimer(handle: number): void;
 *   onStatus(status: AutosaveStatus): void;
 * }
 * export interface Autosave<T> {
 *   edit(value: T): void;                      // a save of the latest value follows after the delay
 *   flush(): Promise<boolean>;                 // saves the latest unsaved value now; true when it is stored
 * }
 * export function createAutosave<T>(deps: AutosaveDeps<T>, delayMs: number): Autosave<T>;
 * ```
 *
 * A missing module or export fails with an error named `NotImplemented`,
 * the red state of this lane.
 */

import { expect } from '@playwright/test';
import { existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from '../playwright.config';
import { STATES, WITHDRAWABLE, forbiddenField, type ControlFacts, type State } from './support';

// ---------------------------------------------------------------------------
// Loading the compiled modules
// ---------------------------------------------------------------------------

/** The production module or export a test needs does not exist yet. */
class NotImplemented extends Error {
  override readonly name = 'NotImplemented';
}

const WEB = resolve(__dirname, '..', '..', 'web');

async function load(name: 'rules' | 'autosave', exports: readonly string[]): Promise<Record<string, unknown>> {
  const src = join(WEB, 'src', 'applicant', `${name}.ts`);
  const out = join(WEB, 'dist', 'applicant', `${name}.js`);
  if (!existsSync(src)) {
    throw new NotImplemented(`web/src/applicant/${name}.ts does not exist yet (lane W4b implementer)`);
  }
  if (!existsSync(out) || statSync(out).mtimeMs < statSync(src).mtimeMs) {
    throw new Error(`web/dist/applicant/${name}.js is missing or older than its source: run tsc -p web first`);
  }
  const mod = (await import(pathToFileURL(out).href)) as Record<string, unknown>;
  const absent = exports.filter((e) => !(e in mod));
  if (absent.length > 0) {
    throw new NotImplemented(`web/src/applicant/${name}.ts does not export ${absent.join(', ')}`);
  }
  return mod;
}

interface Rules {
  readonly PROPOSAL_STATES: readonly string[];
  parseProposalState(v: unknown): string | null;
  withdrawOffered(s: string): boolean;
  draftEditable(s: string): boolean;
  stage2Open(s: string): boolean;
  negotiationOpen(s: string): boolean;
}

/** The role rules of `rules.ts` (fix round 1). */
interface RoleRules {
  leadActionsOffered(role: string | undefined): boolean;
  teamReadsOffered(role: string | undefined): boolean;
  teamEditable(s: string): boolean;
  guardianAddOffered(s: string): boolean;
  guardianConsentOpen(s: string): boolean;
  stage2Readable(s: string): boolean;
}

async function rules(): Promise<Rules> {
  return (await load('rules', [
    'PROPOSAL_STATES',
    'parseProposalState',
    'withdrawOffered',
    'draftEditable',
    'stage2Open',
    'negotiationOpen',
  ])) as unknown as Rules;
}

async function roleRules(): Promise<RoleRules> {
  return (await load('rules', [
    'leadActionsOffered',
    'teamReadsOffered',
    'teamEditable',
    'guardianAddOffered',
    'guardianConsentOpen',
    'stage2Readable',
  ])) as unknown as RoleRules;
}

type AutosaveStatus = 'idle' | 'pending' | 'saving' | 'saved' | 'failed';

interface AutosaveDeps<T> {
  save(value: T): Promise<boolean>;
  setTimer(fn: () => void, ms: number): number;
  clearTimer(handle: number): void;
  onStatus(status: AutosaveStatus): void;
}

interface Autosave<T> {
  edit(value: T): void;
  flush(): Promise<boolean>;
  unsaved?(): boolean;
}

type CreateAutosave = <T>(deps: AutosaveDeps<T>, delayMs: number) => Autosave<T>;

async function createAutosave(): Promise<CreateAutosave> {
  return (await load('autosave', ['createAutosave']))['createAutosave'] as CreateAutosave;
}

// ---------------------------------------------------------------------------
// Seeded properties (design section 8.1: one property per test)
// ---------------------------------------------------------------------------

/** A small seeded generator (xorshift32), so every failure replays. */
class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0 || 0x9e3779b9;
  }
  next(): number {
    let x = this.s;
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    this.s = x;
    return x;
  }
  below(n: number): number {
    return this.next() % n;
  }
}

const SEED = Number(process.env['FSTP_TEST_SEED'] ?? '1596530726') >>> 0;

/** Runs `check` over `runs` seeded cases, naming the case and seed on failure. */
async function forAll(runs: number, check: (r: Rng, i: number) => Promise<void> | void): Promise<void> {
  for (let i = 0; i < runs; i++) {
    const r = new Rng(SEED + i * 7919);
    try {
      await check(r, i);
    } catch (e) {
      if (e instanceof NotImplemented) throw e;
      throw new Error(`case ${i} (FSTP_TEST_SEED=${SEED}): ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// rules.ts
// ---------------------------------------------------------------------------

test.describe('applicant rules', () => {
  /**
   * R-SB-03 and state-machine NOTE 10: the proposal page offers
   * withdrawal in exactly DRAFT, SUBMITTED, STAGE1, STAGE2, RANKED,
   * IRC_REVIEW, DEFERRED and NEGOTIATION. The reference is written from
   * the spec text (`support.ts` WITHDRAWABLE), over all 16 states.
   */
  test('r_sb_03_withdraw_offered_exactly_in_the_note_10_states', async () => {
    const r = await rules();
    const wrong = STATES.filter((s) => r.withdrawOffered(s) !== WITHDRAWABLE.has(s));
    expect(wrong).toEqual([]);
  });

  /**
   * The 16 spec states, each once, and the parser takes exactly their
   * spec names. Case variants, padding, prefixes and other values are
   * refused, so a page never guesses a state.
   */
  test('state_machine_parse_takes_exactly_the_16_spec_names', async () => {
    const r = await rules();
    expect([...r.PROPOSAL_STATES].sort()).toEqual([...STATES].sort());
    for (const s of STATES) expect(r.parseProposalState(s)).toBe(s);
    const near = (s: string, k: number): string => {
      switch (k) {
        case 0:
          return s.toLowerCase();
        case 1:
          return ` ${s}`;
        case 2:
          return `${s}\u0000`;
        case 3:
          return s.slice(1);
        case 4:
          return `${s}_`;
        default:
          return s.replace('_', '-');
      }
    };
    await forAll(256, (g) => {
      const s = STATES[g.below(STATES.length)] ?? 'DRAFT';
      const v = near(s, g.below(6));
      if (v === s) return;
      expect(r.parseProposalState(v), JSON.stringify(v)).toBeNull();
    });
    for (const v of [null, undefined, 0, 1, true, {}, [], ['DRAFT'], { state: 'DRAFT' }, '']) {
      expect(r.parseProposalState(v), JSON.stringify(v) ?? 'undefined').toBeNull();
    }
  });

  /**
   * `state-machine.md`: the draft is the applicant workspace, so only
   * DRAFT edits it. Stage 2 answers and revisions belong to STAGE2, and
   * the negotiation landing to NEGOTIATION (R-EV-05, R-NG-06 entry).
   */
  test('state_machine_applicant_actions_follow_the_state', async () => {
    const r = await rules();
    const table = STATES.map((s: State) => [s, r.draftEditable(s), r.stage2Open(s), r.negotiationOpen(s)]);
    const expected = STATES.map((s: State) => [s, s === 'DRAFT', s === 'STAGE2', s === 'NEGOTIATION']);
    expect(table).toEqual(expected);
  });

  /**
   * Design section 8.7 `roles/<role>`: denied actions are absent. The
   * registry (`fstp-access` `registry.rs`) admits only the lead to the
   * lead's actions, and the lead, a team member and the guardian to the
   * team's reads. A missing role gets neither. Supporting test of the
   * fix round 1 finding on lead-only actions.
   */
  test('roles_lead_actions_for_the_lead_and_reads_for_the_team', async () => {
    const r = await roleRules();
    const roles: readonly (string | undefined)[] = ['lead', 'member', 'guardian', undefined, 'LEAD', 'owner', ''];
    const table = roles.map((x) => [String(x), r.leadActionsOffered(x), r.teamReadsOffered(x)]);
    const team = new Set(['lead', 'member', 'guardian']);
    const expected = roles.map((x) => [String(x), x === 'lead', x !== undefined && team.has(x)]);
    expect(table).toEqual(expected);
  });

  /**
   * I-18 and state-machine NOTE 14: guardian consent opens at the last
   * IRC validation (IRC_REVIEW) and in NEGOTIATION, and nowhere else. A
   * guardian can be added in every state before GRANTED that has an exit
   * (`fstp-domain` `proposal/draft.rs`), and team members in DRAFT only.
   */
  test('i18_guardian_consent_and_team_changes_follow_the_state', async () => {
    const r = await roleRules();
    const table = STATES.map((s: State) => [s, r.guardianConsentOpen(s), r.guardianAddOffered(s), r.teamEditable(s)]);
    const expected = STATES.map((s: State) => [
      s,
      s === 'IRC_REVIEW' || s === 'NEGOTIATION',
      WITHDRAWABLE.has(s),
      s === 'DRAFT',
    ]);
    expect(table).toEqual(expected);
  });

  /**
   * R-EV-05: stage 2 questions exist only once a proposal has passed
   * stage 1, so the stage 2 page reads them only from STAGE2 on. It
   * never reads them in DRAFT, SUBMITTED, INELIGIBLE, STAGE1,
   * NOT_SELECTED or WITHDRAWN.
   */
  test('r_ev_05_stage2_is_read_only_after_stage1', async () => {
    const r = await roleRules();
    const before = new Set(['DRAFT', 'SUBMITTED', 'INELIGIBLE', 'STAGE1', 'NOT_SELECTED', 'WITHDRAWN']);
    const wrong = STATES.filter((s) => r.stage2Readable(s) === before.has(s));
    expect(wrong).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// autosave.ts
// ---------------------------------------------------------------------------

/** A fake scheduler and a fake save whose calls resolve when told. */
class Harness {
  private nextHandle = 1;
  readonly timers = new Map<number, () => void>();
  readonly inFlight: { value: { n: number }; resolve: (ok: boolean) => void; reject: (e: unknown) => void }[] = [];
  readonly saved: number[] = [];
  readonly statuses: AutosaveStatus[] = [];
  maxInFlight = 0;

  deps(): AutosaveDeps<{ n: number }> {
    return {
      save: (value) =>
        new Promise<boolean>((resolve, reject) => {
          this.inFlight.push({
            value,
            resolve: (ok) => {
              if (ok) this.saved.push(value.n);
              resolve(ok);
            },
            reject,
          });
          this.maxInFlight = Math.max(this.maxInFlight, this.inFlight.length);
        }),
      setTimer: (fn) => {
        const h = this.nextHandle++;
        this.timers.set(h, fn);
        return h;
      },
      clearTimer: (h) => {
        this.timers.delete(h);
      },
      onStatus: (s) => {
        this.statuses.push(s);
      },
    };
  }

  /** Fires every timer due now, once each. */
  fire(): void {
    const due = [...this.timers.entries()];
    this.timers.clear();
    for (const [, fn] of due) fn();
  }

  /** Settles the oldest save in flight: stored, refused or thrown. */
  settle(outcome: 'ok' | 'refused' | 'throws'): void {
    const c = this.inFlight.shift();
    if (c === undefined) return;
    if (outcome === 'ok') c.resolve(true);
    else if (outcome === 'refused') c.resolve(false);
    else c.reject(new Error('network'));
  }
}

/** Lets every pending promise reaction run. */
async function yieldAll(): Promise<void> {
  for (let i = 0; i < 4; i++) await new Promise<void>((r) => setImmediate(r));
}

/** Fires timers and stores saves until nothing is left to do. */
async function drain(h: Harness): Promise<void> {
  for (let i = 0; i < 100 && (h.timers.size > 0 || h.inFlight.length > 0); i++) {
    h.fire();
    await yieldAll();
    while (h.inFlight.length > 0) {
      h.settle('ok');
      await yieldAll();
    }
  }
}

/** Runs a random interleaving of edits, timer firings and save outcomes. */
async function interleave(g: Rng, h: Harness, a: Autosave<{ n: number }>, failures: boolean): Promise<number> {
  let last = 0;
  const steps = 5 + g.below(30);
  for (let i = 0; i < steps; i++) {
    const k = g.below(4);
    if (k === 0 || k === 1) {
      last += 1;
      a.edit({ n: last });
    } else if (k === 2) {
      h.fire();
    } else {
      const o = failures ? (['ok', 'refused', 'throws'] as const)[g.below(3)] ?? 'ok' : 'ok';
      h.settle(o);
    }
    await yieldAll();
  }
  return last;
}

test.describe('applicant autosave', () => {
  /**
   * The workspace autosave never has two saves in flight, so an older
   * draft can never overwrite a newer one at the cell (journey J4,
   * I-21 workspace). Supporting test: no requirement names autosave.
   */
  test('autosave_never_has_two_saves_in_flight', async () => {
    const make = await createAutosave();
    await forAll(200, async (g) => {
      const h = new Harness();
      const a = make(h.deps(), 500);
      await interleave(g, h, a, true);
      await drain(h);
      expect(h.maxInFlight, 'saves in flight at once').toBeLessThanOrEqual(1);
    });
  });

  /**
   * Once every timer has fired and every save is stored, the last value
   * stored is the last edit, the status reads `saved`, and a flush with
   * nothing new resolves true without a further save.
   */
  test('autosave_stores_the_last_edit', async () => {
    const make = await createAutosave();
    await forAll(200, async (g) => {
      const h = new Harness();
      const a = make(h.deps(), 500);
      const last = await interleave(g, h, a, false);
      await drain(h);
      if (last > 0) {
        expect(h.saved[h.saved.length - 1], 'the last stored value, with no flush').toBe(last);
        expect(h.statuses[h.statuses.length - 1], 'the last status').toBe('saved');
      }
      const before = h.saved.length;
      const flushed = a.flush();
      await yieldAll();
      expect(h.inFlight, 'a flush with nothing new saves nothing').toHaveLength(0);
      expect(await flushed, 'and resolves true').toBe(true);
      expect(h.saved.length).toBe(before);
    });
  });

  /**
   * A refused or failed save reports `failed` and keeps the value: the
   * next flush saves the latest edit, so no draft text is lost.
   */
  test('autosave_keeps_a_failed_value_for_the_next_attempt', async () => {
    const make = await createAutosave();
    await forAll(200, async (g) => {
      const h = new Harness();
      const a = make(h.deps(), 500);
      const last = (await interleave(g, h, a, true)) + 1;
      await drain(h);
      a.edit({ n: last });
      h.fire();
      await yieldAll();
      expect(h.inFlight.map((x) => x.value.n), 'the timer saves the latest edit').toEqual([last]);
      h.settle(g.below(2) === 0 ? 'refused' : 'throws');
      await yieldAll();
      expect(h.statuses[h.statuses.length - 1], 'a failed save reports failed').toBe('failed');
      const flushed = a.flush();
      await yieldAll();
      expect(h.inFlight.map((c) => c.value.n), 'the flush saves the latest edit').toEqual([last]);
      h.settle('ok');
      expect(await flushed).toBe(true);
      expect(h.saved[h.saved.length - 1]).toBe(last);
    });
  });

  /**
   * A newer edit whose timer fired while a save was in flight was never
   * tried. When that save fails, the newer value is saved at once,
   * rather than left behind a `failed` status (fix round 1 regression).
   * A save of the latest value that fails is still not retried.
   */
  test('autosave_tries_a_newer_edit_after_a_failed_save', async () => {
    const make = await createAutosave();
    await forAll(50, async (g) => {
      const h = new Harness();
      const a = make(h.deps(), 500);
      a.edit({ n: 1 });
      h.fire();
      await yieldAll();
      a.edit({ n: 2 });
      h.fire();
      await yieldAll();
      expect(h.inFlight.map((x) => x.value.n), 'only the first save is in flight').toEqual([1]);
      h.settle(g.below(2) === 0 ? 'refused' : 'throws');
      await yieldAll();
      expect(h.inFlight.map((x) => x.value.n), 'the newer edit is saved next').toEqual([2]);
      expect(a.unsaved?.(), 'the newer edit is not stored yet').toBe(true);
      h.settle('refused');
      await yieldAll();
      expect(h.inFlight, 'a failed save of the latest edit is not retried').toHaveLength(0);
      expect(h.statuses[h.statuses.length - 1]).toBe('failed');
    });
  });
});

// ---------------------------------------------------------------------------
// The R-SB-01 predicate of support.ts
// ---------------------------------------------------------------------------

function c(o: Partial<ControlFacts>): ControlFacts {
  return { tag: 'input', type: 'text', id: '', name: '', autocomplete: '', label: '', ...o };
}

test.describe('R-SB-01 predicate', () => {
  /**
   * R-SB-01: the predicate the field scan uses flags date of birth,
   * identity document, payment and file controls, and spares the
   * applicant's own form controls. Teeth for `forbiddenFieldsOn`.
   */
  test('r_sb_01_predicate_flags_forbidden_fields_and_spares_the_form', () => {
    const flagged = [
      c({ type: 'date', id: 'x' }),
      c({ autocomplete: 'bday' }),
      c({ id: 'lead-dob' }),
      c({ label: 'Date of birth' }),
      c({ label: 'Passport number' }),
      c({ name: 'national_id' }),
      c({ autocomplete: 'cc-number' }),
      c({ label: 'IBAN' }),
      c({ id: 'bank-account' }),
      c({ type: 'file', id: 'annex' }),
      // A date control outside the plan editor, even one whose words name
      // a start or a due day, counts as a date of birth.
      c({ type: 'date', id: 'start-date', label: 'Start' }),
      c({ type: 'date', id: 'due', name: 'due' }),
      c({ type: 'date', id: 'plan-start', label: 'Start day' }),
      c({ type: 'date', id: 'plan-t1-m1-start', label: 'Date of birth' }),
    ];
    expect(flagged.filter((x) => forbiddenField(x) === null)).toEqual([]);
    const spared = [
      c({ id: 'ws-title', label: 'Proposal title' }),
      c({ tag: 'textarea', id: 'ws-summary', label: 'Neutral summary. Do not identify yourself.' }),
      c({ tag: 'textarea', id: 'ws-narrative', label: 'Narrative' }),
      c({ id: 'plan-amount', label: 'Requested amount (EUR)' }),
      c({ tag: 'select', id: 'elig-country', label: 'Country of residence or establishment' }),
      c({ tag: 'textarea', id: 'elig-affiliations', label: 'Declared affiliations' }),
      c({ type: 'checkbox', id: 'submit-notice-read', label: 'I have read the data protection notice' }),
      c({ type: 'radio', id: 'ethics-none', label: 'No ethics issue' }),
      c({ type: 'email', id: 'copy-email', label: 'Email address for a copy', autocomplete: 'email' }),
      c({ tag: 'textarea', id: 'stage2-answer', label: 'Your answer' }),
      c({ type: 'date', id: 'plan-t1-m1-start', label: 'Start day' }),
      c({ type: 'date', id: 'stage2-plan-t2-m3-due', label: 'Due day' }),
    ];
    expect(spared.filter((x) => forbiddenField(x) !== null).map((x) => x.id)).toEqual([]);
  });
});
