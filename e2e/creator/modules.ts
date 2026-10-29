/**
 * Loads the page logic modules of lane W4a for the Node-only specs, and
 * states the exports those specs need (M4 design section 3.9).
 *
 * The specs were written before the modules. A module or export that
 * does not exist yet throws an error named `NotImplemented`, so the spec
 * is red for that reason and not for a compile error. The exports below
 * are interim readings of this lane, pending Daniel.
 *
 * The modules are pure: they import nothing that needs a DOM, so Node can
 * load them as Playwright transpiles them.
 */

import { expect } from '@playwright/test';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

/** The web source root. */
export const WEB_SRC = join(__dirname, '..', '..', 'web', 'src');

/** A step status as the onboarding pages name it (`fstp_tenant::StepStatus`). */
export type StepStatusName = 'locked' | 'open' | 'saved' | 'validated' | 'skipped' | 'unavailable';

/** `web/src/onboarding/model.ts`. */
export interface OnboardingModel {
  /** The onboarding steps in the order of the spec table, spelled as in routes. */
  readonly ONBOARDING_STEPS: readonly string[];
  /**
   * The steps a person may open, in order: those whose every earlier step
   * is validated or skipped (R-TN-01).
   */
  openableSteps(statuses: Readonly<Record<string, StepStatusName>>): readonly string[];
}

/** One validation result as the review page consumes it. */
export interface GateResult {
  readonly severity: 'failure' | 'warning';
  readonly acknowledged: boolean;
}

/** `web/src/creator/model.ts`. */
export interface CreatorModel {
  /** Steps 1 to 10 of `programme-creator.md` and the review, with their route segment and number. */
  readonly CREATOR_STEPS: readonly { readonly id: string; readonly number: number }[];
  /** The step id of field `<step>.<member>`, or null for a key that names no field. */
  stepOfField(key: string): string | null;
  /** Whether the review page offers the activation request (I-66), with the counts it shows. */
  activationGate(results: readonly GateResult[]): {
    readonly canRequest: boolean;
    readonly failures: number;
    readonly unacknowledged: number;
  };
}

/** An invitation's state as the people pages show it. */
export type InvitationState = 'invited' | 'accepted' | 'verified' | 'granted';

/** `web/src/people/model.ts`. */
export interface PeopleModel {
  /**
   * Whether the people admin page offers the grant: only for an invitee
   * who accepted the terms and verified identity (J2, SoD-09), and on a
   * draft only for a programme manager (D1).
   */
  grantOffered(programme: 'draft' | 'active', role: string, state: InvitationState): boolean;
}

/** `web/src/<feature>/messages.en.ts`: `CATALOGUE` in the core `CatalogueInput` form. */
export interface CatalogueModule {
  readonly CATALOGUE: {
    readonly locale: string;
    readonly labels: Readonly<Record<string, string>>;
    readonly approved: Readonly<Record<string, string>>;
  };
}

/** `web/src/core/i18n.ts`, the parts the catalogue test uses. */
export interface CoreI18n {
  createI18n(opts: { readonly catalogues: readonly CatalogueModule['CATALOGUE'][]; readonly locale: string }): {
    label(id: string, args?: Readonly<Record<string, string>>): string;
    approved(id: string, args?: Readonly<Record<string, string>>): string;
  };
}

/** Thrown when a module or export a spec needs does not exist yet. */
export class NotImplemented extends Error {
  override readonly name = 'NotImplemented';
}

/**
 * Imports `web/src/<dir>/<name>.ts` and checks that it has `exports`.
 * Missing either throws [`NotImplemented`].
 */
export async function load<T>(dir: string, name: string, exports: readonly string[]): Promise<T> {
  const source = join(WEB_SRC, dir, `${name}.ts`);
  if (!existsSync(source)) {
    throw new NotImplemented(`web/src/${dir}/${name}.ts does not exist yet (lane W4a page agent)`);
  }
  const mod = (await import(join(WEB_SRC, dir, `${name}.js`))) as Record<string, unknown>;
  const absent = exports.filter((e) => !(e in mod));
  if (absent.length > 0) {
    throw new NotImplemented(`web/src/${dir}/${name}.ts does not export ${absent.join(', ')}`);
  }
  return mod as unknown as T;
}

/** A small seeded generator for the property checks, so a failure replays. */
export class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0 || 1;
  }
  /** The next 32-bit value (xorshift32). */
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
  /** A value in `[0, n)`. */
  below(n: number): number {
    return this.next() % n;
  }
  /** One element of `xs`. */
  pick<T>(xs: readonly T[]): T {
    const v = xs[this.below(xs.length)];
    if (v === undefined) throw new Error('pick from an empty list');
    return v;
  }
}

/** The property seed: `FSTP_TEST_SEED` when set, else a fixed value. */
export function seed(): number {
  const raw = process.env['FSTP_TEST_SEED'];
  return raw !== undefined && /^[0-9]{1,10}$/.test(raw) ? Number(raw) >>> 0 : 0x5eed2026;
}

/**
 * Runs `check` on `runs` generated cases. A failure names the case and
 * the seed. A test runs one property.
 */
export function forAll<T>(gen: (r: Rng) => T, check: (t: T) => void, runs = 512): void {
  const s = seed();
  const r = new Rng(s);
  for (let i = 0; i < runs; i++) {
    const input = gen(r);
    try {
      check(input);
    } catch (e) {
      throw new Error(
        `property failed at case ${i} (FSTP_TEST_SEED=${s}) on ${JSON.stringify(input)}: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
}

/** The sentences of a catalogue text, split after `.`, `!` or `?`. */
export function sentences(text: string): string[] {
  return text
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

/** The words of a sentence, ignoring placeholders. */
export function wordCount(sentence: string): number {
  return sentence
    .replace(/\{[a-z][a-z0-9_]*\}/g, 'x')
    .split(/\s+/)
    .filter((w) => /\p{L}|\p{N}/u.test(w)).length;
}

/**
 * Loads `web/src/<dir>/messages.en.ts`, builds it with core's
 * `createI18n`, and checks the prose rules of `.claude/CLAUDE.md` on every
 * text: no em dash, and every sentence under 40 words.
 */
export async function catalogueProblems(dir: string): Promise<{ problems: string[]; labels: Set<string>; approved: Set<string> }> {
  const { CATALOGUE } = await load<CatalogueModule>(dir, 'messages.en', ['CATALOGUE']);
  const { createI18n } = await load<CoreI18n>('core', 'i18n', ['createI18n']);
  const problems: string[] = [];
  expect(CATALOGUE.locale, `web/src/${dir} catalogue locale`).toBe('en');
  try {
    createI18n({ catalogues: [CATALOGUE], locale: 'en' });
  } catch (e) {
    problems.push(`web/src/${dir}: core createI18n refuses the catalogue: ${e instanceof Error ? e.message : String(e)}`);
  }
  const labels = new Set(Object.keys(CATALOGUE.labels));
  const approved = new Set(Object.keys(CATALOGUE.approved));
  if (labels.size === 0) problems.push(`web/src/${dir}: the catalogue has no labels`);
  for (const [kind, texts] of [
    ['label', CATALOGUE.labels],
    ['approved', CATALOGUE.approved],
  ] as const) {
    for (const [id, text] of Object.entries(texts)) {
      if (text.trim() === '') problems.push(`web/src/${dir}: ${kind} ${id} is empty`);
      if (text.includes('\u2014')) problems.push(`web/src/${dir}: ${kind} ${id} has an em dash`);
      for (const s of sentences(text)) {
        if (wordCount(s) >= 40) problems.push(`web/src/${dir}: ${kind} ${id} has a sentence of ${wordCount(s)} words`);
      }
    }
  }
  return { problems, labels, approved };
}
