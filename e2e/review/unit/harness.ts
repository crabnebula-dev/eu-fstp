/**
 * The harness of the review page-logic unit specs: a loader for the tsc
 * build of `web/src/<feature>` and a seeded property check.
 *
 * The specs need no stack and no browser. They import the compiled
 * modules from `web/dist`, which `web/node_modules/.bin/tsc -p web`
 * writes. Run them from `e2e/`:
 *
 *   web/node_modules/.bin/tsc -p web
 *   (cd e2e && node_modules/.bin/playwright test review/unit)
 *
 * A module or export that does not exist yet fails with an error named
 * `NotImplemented`, so a red spec says which piece is missing. The
 * conventions of `web/test/support/harness.ts` carry over: every random
 * choice comes from a seed, `FSTP_TEST_SEED` changes it, a failure
 * prints the seed it needs, and a test runs at most one property.
 */

import { test } from '@playwright/test';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { REQUIRED_EXPORTS, type PageLogicModules } from '../contract';

/** A missing page module or export. */
export class NotImplemented extends Error {
  constructor(what: string) {
    super(what);
    this.name = 'NotImplemented';
  }
}

/** The `web/` directory, from the Playwright project's test directory `e2e/`. */
export function webDir(): string {
  return join(test.info().project.testDir, '..', 'web');
}

function missingModule(e: unknown): boolean {
  return (
    typeof e === 'object' &&
    e !== null &&
    (e as { code?: unknown }).code === 'ERR_MODULE_NOT_FOUND'
  );
}

/**
 * The compiled page-logic module `name`, with every export the contract
 * requires. Missing source gives `NotImplemented`. Source without a build
 * fails with the command that builds it.
 */
export async function pageLogic<K extends keyof PageLogicModules>(
  name: K,
): Promise<PageLogicModules[K]> {
  const web = webDir();
  const source = join(web, 'src', `${name}.ts`);
  if (!existsSync(source)) {
    throw new NotImplemented(`web/src/${name}.ts does not exist yet (lane W4c page agent)`);
  }
  const built = join(web, 'dist', `${name}.js`);
  if (!existsSync(built)) {
    throw new Error(`web/dist/${name}.js is missing: build with web/node_modules/.bin/tsc -p web`);
  }
  let mod: Record<string, unknown>;
  try {
    mod = (await import(pathToFileURL(built).href)) as Record<string, unknown>;
  } catch (e) {
    if (missingModule(e)) {
      throw new Error(`web/dist/${name}.js imports a module that is not built: ${String(e)}`);
    }
    throw e;
  }
  const absent = REQUIRED_EXPORTS[name].filter((k) => typeof mod[k] !== 'function');
  if (absent.length > 0) {
    throw new NotImplemented(`web/src/${name}.ts does not export ${absent.join(', ')} yet`);
  }
  return mod as unknown as PageLogicModules[K];
}

/** Every `.ts` file below `web/src/<folder>`, as absolute paths. */
export function sourcesOf(folder: string): string[] {
  const root = join(webDir(), 'src', folder);
  const out: string[] = [];
  const walk = (dir: string): void => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir).sort()) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) walk(p);
      else if (entry.endsWith('.ts')) out.push(p);
    }
  };
  walk(root);
  return out;
}

// ---------------------------------------------------------------------------
// Seeded property checks
// ---------------------------------------------------------------------------

/** A 32-bit xorshift generator. Integer arithmetic only, no float. */
export class Rng {
  private s: number;

  constructor(seed: number) {
    this.s = seed >>> 0 || 0x9e3779b9;
  }

  /** The next 32-bit value. */
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

  /** An integer from `lo` to `hi`, both included. `hi - lo` stays below 2^32. */
  int(lo: number, hi: number): number {
    const span = hi - lo + 1;
    return lo + (this.next() % span);
  }

  bool(): boolean {
    return (this.next() & 1) === 1;
  }

  pick<T>(xs: readonly T[]): T {
    const v = xs[this.int(0, xs.length - 1)];
    if (v === undefined) throw new Error('pick from an empty list');
    return v;
  }
}

/** FNV-1a over the UTF-16 units of `s`, mixed with `base`. */
function hashSeed(s: string, base: number): number {
  let h = (0x811c9dc5 ^ base) >>> 0;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

/** The base seed: `FSTP_TEST_SEED` when set, else a fixed value. */
export function baseSeed(): number {
  const raw = process.env['FSTP_TEST_SEED'];
  if (raw !== undefined && /^[0-9]{1,10}$/.test(raw)) {
    return Number(raw) >>> 0;
  }
  return 0x5eed2026;
}

const propsByTest = new Map<string, number>();

/**
 * Checks `check` over `runs` generated cases, seeded from the base seed
 * and the test title. One property per test. A `NotImplemented` error is
 * passed on unchanged, so a missing module stays red for that reason.
 */
export function forAll<T>(gen: (r: Rng) => T, check: (t: T) => void, runs = 256): void {
  const title = test.info().titlePath.join(' > ');
  const n = (propsByTest.get(title) ?? 0) + 1;
  propsByTest.set(title, n);
  if (n > 1) {
    throw new Error(`${title} runs more than one property; one forAll per test`);
  }
  const seed = hashSeed(title, baseSeed());
  const rng = new Rng(seed);
  for (let i = 0; i < runs; i += 1) {
    const input = gen(rng);
    try {
      check(input);
    } catch (e) {
      if (e instanceof Error && e.name === 'NotImplemented') throw e;
      const why = e instanceof Error ? e.message : String(e);
      throw new Error(
        `property failed at case ${i} (FSTP_TEST_SEED=${baseSeed()}, test seed ${seed}) on input ${JSON.stringify(input)}: ${why}`,
      );
    }
  }
}
