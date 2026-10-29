// A seeded pseudo-random generator for the in-house test runner and the
// fuzz harness (M4 design sections 8.1 and 9, Q33 interim).
//
// It uses 32-bit integer operations only, through `Math.imul` and `>>> 0`.
// No floating-point value is ever produced, so every run with the same seed
// replays exactly.

/** FNV-1a over the UTF-16 code units of `text`, mixed with `base`. */
export function hashSeed(text: string, base: number): number {
  let h = (0x811c9dc5 ^ (base >>> 0)) >>> 0;
  for (let i = 0; i < text.length; i += 1) {
    h = (h ^ text.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** A small, fast generator (mulberry32). */
export class Rng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  /** The next value in [0, 2^32). */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }

  /** A value in [0, n). `n` must be a positive integer below 2^32. */
  below(n: number): number {
    if (!Number.isInteger(n) || n <= 0 || n > 0xffffffff) {
      throw new RangeError("Rng.below needs a positive 32-bit integer bound");
    }
    return this.next() % n;
  }

  /** A value in [lo, hi], both integers. */
  between(lo: number, hi: number): number {
    return lo + this.below(hi - lo + 1);
  }

  /** True about one time in `n`. */
  oneIn(n: number): boolean {
    return this.below(n) === 0;
  }

  /** A fair coin. */
  bool(): boolean {
    return (this.next() & 1) === 1;
  }

  /** One element of a non-empty list. */
  pick<T>(xs: readonly T[]): T {
    const x = xs[this.below(xs.length)];
    if (x === undefined) {
      throw new RangeError("Rng.pick needs a non-empty list");
    }
    return x;
  }

  /** A string of up to `maxLen` characters drawn from `alphabet`. */
  stringFrom(alphabet: readonly string[], maxLen: number): string {
    const n = this.below(maxLen + 1);
    let out = "";
    for (let i = 0; i < n; i += 1) {
      out += this.pick(alphabet);
    }
    return out;
  }

  /** A string of arbitrary UTF-16 code units, lone surrogates included. */
  codeUnits(maxLen: number): string {
    const n = this.below(maxLen + 1);
    let out = "";
    for (let i = 0; i < n; i += 1) {
      out += String.fromCharCode(this.below(0x10000));
    }
    return out;
  }
}
