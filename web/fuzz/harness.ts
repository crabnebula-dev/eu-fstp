// The in-house TypeScript fuzz harness (M4 design section 9, Q33 interim:
// a seeded harness with differential corpora shared with the Rust
// targets, and no coverage feedback). TH-26, H-05.
//
// Each target names its seeds and a token dictionary, and `prepare` loads
// the production module and returns a checker. The checker throws when a
// property fails. The harness first runs every seed as it is, then mutates
// seeds with byte-level and token-level mutations from a seeded generator.
// A failure carries the seed and iteration, so it replays exactly.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { Rng } from "../test/support/rng.js";
import { REPO_DIR, WEB_DIR } from "../test/support/paths.js";

/** Checks one input. Throws when a property fails. */
export type Checker = (input: string) => void;

/** One fuzz target. */
export interface FuzzTarget {
  /** The target name, as in design section 9 without `.fuzz.ts`. */
  readonly name: string;
  /** The starting corpus. */
  seeds(): readonly string[];
  /** Tokens the token-level mutations insert. */
  readonly dictionary: readonly string[];
  /** Loads the production code and returns the checker. */
  prepare(): Promise<Checker>;
}

/** One run's outcome. */
export type FuzzOutcome =
  | { readonly ok: true; readonly runs: number }
  | {
      readonly ok: false;
      readonly iteration: number;
      readonly input: string;
      readonly message: string;
    };

/** Upper bound on a mutated input, in UTF-16 code units. */
export const MAX_INPUT = 4096;

/** Code units that parsers in this repository treat specially. */
const INTERESTING: readonly number[] = [
  0x00, 0x09, 0x0a, 0x0d, 0x20, 0x22, 0x23, 0x25, 0x2b, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x39, 0x3a, 0x3f, 0x40, 0x5c,
  0x7b, 0x7d, 0x7f, 0x80, 0xa0, 0xff, 0x2028, 0xd800, 0xdfff, 0xfeff, 0xff0e, 0xff11, 0x0661,
];

function randomUnit(r: Rng): string {
  return String.fromCharCode(r.oneIn(4) ? r.below(0x10000) : r.pick(INTERESTING));
}

/** One mutation of `s`. */
export function mutate(s: string, r: Rng, dictionary: readonly string[], corpus: readonly string[]): string {
  const at = (): number => r.below(s.length + 1);
  switch (r.below(9)) {
    case 0: {
      if (s.length === 0) {
        return randomUnit(r);
      }
      const i = r.below(s.length);
      return s.slice(0, i) + randomUnit(r) + s.slice(i + 1);
    }
    case 1: {
      const i = at();
      return s.slice(0, i) + randomUnit(r) + s.slice(i);
    }
    case 2: {
      const i = at();
      const j = Math.min(s.length, i + 1 + r.below(4));
      return s.slice(0, i) + s.slice(j);
    }
    case 3: {
      const i = at();
      const j = Math.min(s.length, i + 1 + r.below(8));
      return s.slice(0, j) + s.slice(i, j) + s.slice(j);
    }
    case 4:
    case 5: {
      if (dictionary.length === 0) {
        return s;
      }
      const i = at();
      return s.slice(0, i) + r.pick(dictionary) + s.slice(i);
    }
    case 6: {
      if (corpus.length === 0) {
        return s;
      }
      const other = r.pick(corpus);
      return s.slice(0, at()) + other.slice(r.below(other.length + 1));
    }
    case 7:
      return s.slice(0, at());
    default: {
      let out = "";
      for (const c of s) {
        out += r.oneIn(3) ? (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) : c;
      }
      return out;
    }
  }
}

function describe(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

/**
 * Runs `target` for `iterations` mutated inputs after its seeds. A
 * `NotImplemented` error from `prepare` is passed on, so a missing module
 * stays red for that reason.
 */
export async function runTarget(target: FuzzTarget, seed: number, iterations: number): Promise<FuzzOutcome> {
  const check = await target.prepare();
  const seeds = target.seeds();
  const pool: string[] = [...seeds];
  const attempt = (iteration: number, input: string): FuzzOutcome | null => {
    try {
      check(input);
      return null;
    } catch (e) {
      if (e instanceof Error && e.name === "NotImplemented") {
        throw e;
      }
      return { ok: false, iteration, input, message: describe(e) };
    }
  };
  for (const s of seeds) {
    const bad = attempt(-1, s);
    if (bad !== null) {
      return bad;
    }
  }
  const r = new Rng(seed);
  for (let i = 0; i < iterations; i += 1) {
    let input = pool.length > 0 ? r.pick(pool) : "";
    const n = 1 + r.below(4);
    for (let k = 0; k < n; k += 1) {
      input = mutate(input, r, target.dictionary, pool);
    }
    if (input.length > MAX_INPUT) {
      input = input.slice(0, MAX_INPUT);
    }
    const bad = attempt(i, input);
    if (bad !== null) {
      return bad;
    }
    if (pool.length < 512 && r.oneIn(16)) {
      pool.push(input);
    }
  }
  return { ok: true, runs: seeds.length + iterations };
}

/** One line of an `expect.tsv` corpus: a verdict and a JSON string input. */
export interface Expectation {
  readonly verdict: string;
  readonly input: string;
  readonly extra: string | null;
  readonly line: number;
}

/**
 * Reads `web/fuzz/seeds/<target>/expect.tsv`. Each line is
 * `<verdict>\t<JSON string>[\t<extra>]`. Lines starting with `#` and empty
 * lines are skipped. The JSON string form lets the corpus hold control
 * characters, and lets the Rust side read the same file with fstp-json.
 */
export function readExpectations(target: string): Expectation[] {
  const path = join(WEB_DIR, "fuzz", "seeds", target, "expect.tsv");
  const out: Expectation[] = [];
  const lines = readFileSync(path, "utf8").split("\n");
  lines.forEach((text, i) => {
    if (text === "" || text.startsWith("#")) {
      return;
    }
    const cols = text.split("\t");
    const verdict = cols[0];
    const raw = cols[1];
    if (verdict === undefined || raw === undefined || cols.length > 3) {
      throw new Error(`${path}:${i + 1}: expected <verdict>\\t<JSON string>[\\t<extra>]`);
    }
    const input: unknown = JSON.parse(raw);
    if (typeof input !== "string") {
      throw new Error(`${path}:${i + 1}: the input column is not a JSON string`);
    }
    out.push({ verdict, input, extra: cols[2] ?? null, line: i + 1 });
  });
  return out;
}

/**
 * The seed files of a Rust cargo-fuzz project, such as
 * `crates/fstp-money/fuzz/seeds/amount_parse`, read as UTF-8. Missing
 * directories give no seeds, since some Rust targets have none yet.
 */
export function readRustSeeds(relDir: string): string[] {
  const dir = join(REPO_DIR, relDir);
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .sort()
    .map((f) => join(dir, f))
    .filter((p) => statSync(p).isFile())
    .map((p) => readFileSync(p, "utf8"));
}
