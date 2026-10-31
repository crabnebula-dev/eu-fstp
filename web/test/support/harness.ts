// The in-house TypeScript test runner's registry, assertions and property
// checks (M4 design section 8.1, ADR-014).
//
// Conventions carried over from the Rust suites (m2-design 6.1):
// - every test name starts with the identifier it verifies, such as
//   `adr006_`, `r_nf_04_`, `i72_` or `th26_` (checked at registration);
// - one `forAll` per test function;
// - every random choice comes from a seed, so each failure replays.

import { Rng, hashSeed } from "./rng.js";

/** A test body. It fails by throwing. */
export type TestFn = () => void | Promise<void>;

/** One registered test. */
export interface TestCase {
  readonly name: string;
  readonly file: string;
  readonly fn: TestFn;
}

/**
 * The test names the runner accepts: an ADR, R-, I-, TH- or H- identifier,
 * then an underscore and a description.
 */
export const TEST_NAME = /^(adr\d{3}|r_[a-z]{2}_\d{2}|i\d{2,3}|th\d{2}|h\d{2})_[a-z0-9_]+$/;

const registry: TestCase[] = [];
let currentFile = "";
let currentTest = "";
let propsInTest = 0;

/**
 * Thrown when the production module or export a test needs does not exist
 * yet. The runner reports it as red, not as a broken test.
 */
export class NotImplemented extends Error {
  constructor(what: string) {
    super(what);
    this.name = "NotImplemented";
  }
}

/** Thrown by a failed assertion. */
export class AssertionFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssertionFailed";
  }
}

/** Called by the runner before it imports each test file. */
export function setCurrentFile(file: string): void {
  currentFile = file;
}

/** Called by the runner before it runs each test. */
export function setCurrentTest(name: string): void {
  currentTest = name;
  propsInTest = 0;
}

/** Registers a test. Names must carry an identifier and be unique. */
export function test(name: string, fn: TestFn): void {
  if (!TEST_NAME.test(name)) {
    throw new Error(`test name ${name} does not start with an identifier such as adr006_ or r_nf_04_`);
  }
  if (registry.some((t) => t.name === name)) {
    throw new Error(`test name ${name} is registered twice`);
  }
  registry.push({ name, file: currentFile, fn });
}

/** Every registered test, in registration order. */
export function registered(): readonly TestCase[] {
  return registry;
}

/** A printable form of any value, with escapes, for failure messages. */
export function show(v: unknown): string {
  if (v === undefined) {
    return "undefined";
  }
  if (typeof v === "function") {
    return "[function]";
  }
  if (typeof v === "bigint") {
    return `${v.toString()}n`;
  }
  try {
    const s = JSON.stringify(v);
    return s === undefined ? String(v) : s;
  } catch {
    return String(v);
  }
}

/** Fails with `message` unless `cond` holds. */
export function assert(cond: boolean, message: string): asserts cond {
  if (!cond) {
    throw new AssertionFailed(message);
  }
}

/** Structural equality over plain data: primitives, arrays and plain objects. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) {
    return true;
  }
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) {
    return false;
  }
  if (Array.isArray(a) !== Array.isArray(b)) {
    return false;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) {
      return false;
    }
    for (let i = 0; i < a.length; i += 1) {
      if (!deepEqual(a[i], b[i])) {
        return false;
      }
    }
    return true;
  }
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  if (!deepEqual(ka, kb)) {
    return false;
  }
  const ra = a as Record<string, unknown>;
  const rb = b as Record<string, unknown>;
  return ka.every((k) => deepEqual(ra[k], rb[k]));
}

/** Fails unless `actual` and `expected` are structurally equal. */
export function eq(actual: unknown, expected: unknown, message: string): void {
  if (!deepEqual(actual, expected)) {
    throw new AssertionFailed(`${message}: expected ${show(expected)}, got ${show(actual)}`);
  }
}

/**
 * Runs `fn` and returns what it threw. Fails if it returned normally. A
 * `NotImplemented` error is passed on, so a missing module stays red for
 * that reason.
 */
export function thrown(fn: () => unknown, message: string): unknown {
  try {
    fn();
  } catch (e) {
    if (e instanceof Error && e.name === "NotImplemented") {
      throw e;
    }
    return e;
  }
  throw new AssertionFailed(`${message}: expected a refusal, but the call returned`);
}

/** The async form of `thrown`. */
export async function thrownAsync(fn: () => Promise<unknown>, message: string): Promise<unknown> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof Error && e.name === "NotImplemented") {
      throw e;
    }
    return e;
  }
  throw new AssertionFailed(`${message}: expected a refusal, but the call returned`);
}

/** The base seed: `FSTP_TEST_SEED` when set, else a fixed value. */
export function baseSeed(): number {
  const raw = process.env["FSTP_TEST_SEED"];
  if (raw !== undefined && /^[0-9]{1,10}$/.test(raw)) {
    return Number(raw) >>> 0;
  }
  return 0x5eed2026;
}

/** Options of a property check. */
export interface PropOptions {
  readonly runs: number;
}

/**
 * Checks `check` over `runs` generated cases. The seed is derived from the
 * base seed and the test name, so a failure replays under the same seed. A
 * test calls `forAll` at most once.
 */
export function forAll<T>(gen: (r: Rng) => T, check: (t: T) => void, opts: PropOptions = { runs: 256 }): void {
  propsInTest += 1;
  if (propsInTest > 1) {
    throw new Error(`test ${currentTest} runs more than one property; one forAll per test`);
  }
  const seed = hashSeed(currentTest, baseSeed());
  const rng = new Rng(seed);
  for (let i = 0; i < opts.runs; i += 1) {
    const input = gen(rng);
    try {
      check(input);
    } catch (e) {
      if (e instanceof Error && e.name === "NotImplemented") {
        throw e;
      }
      const why = e instanceof Error ? `${e.name}: ${e.message}` : show(e);
      throw new AssertionFailed(
        `property failed at case ${i} (FSTP_TEST_SEED=${baseSeed()}, test seed ${seed}) on input ${show(input)}: ${why}`,
      );
    }
  }
}
