#!/usr/bin/env node
// Generates number-vectors.txt, the reference for RFC 8785 number formatting.
//
// Each output line is "<bits> <text>". <bits> is the IEEE 754 double as 16
// lowercase hex digits. <text> is what node's JSON.stringify writes for it,
// which is ECMAScript Number::toString. The Rust test
// tests/number_vectors.rs asserts that fstp-json writes the same text.
//
// The doubles are deterministic: a fixed list of edge cases, then families
// built from a seeded splitmix64 generator. Run from the crate directory:
//
//   node testdata/gen-number-vectors.mjs > testdata/number-vectors.txt

const MASK = (1n << 64n) - 1n;
const view = new DataView(new ArrayBuffer(8));

function fromBits(bits) {
  view.setBigUint64(0, bits & MASK);
  return view.getFloat64(0);
}

function toBits(x) {
  view.setFloat64(0, x);
  return view.getBigUint64(0);
}

// splitmix64, seeded so the output never changes between runs.
let state = 0x0f57_9e3d_2026_1024n;
function next64() {
  state = (state + 0x9e3779b97f4a7c15n) & MASK;
  let z = state;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;
  return z ^ (z >> 31n);
}

function below(n) {
  return Number(next64() % BigInt(n));
}

const seen = new Set();
const lines = [];

function add(x) {
  if (!Number.isFinite(x)) {
    return;
  }
  const hex = toBits(x).toString(16).padStart(16, "0");
  if (seen.has(hex)) {
    return;
  }
  seen.add(hex);
  lines.push(`${hex} ${JSON.stringify(x)}`);
}

function addBits(bits) {
  add(fromBits(bits));
}

// Adds x, its negation and its neighbours up to `ulps` steps away.
function addAround(x, ulps) {
  const bits = toBits(x);
  for (let d = -ulps; d <= ulps; d++) {
    const b = bits + BigInt(d);
    if (b >= 0n && b <= MASK) {
      addBits(b);
    }
  }
  add(-x);
}

// RFC 8785 appendix B and other classic edge cases.
for (const b of [
  0x0000000000000000n, 0x8000000000000000n, 0x0000000000000001n,
  0x8000000000000001n, 0x7fefffffffffffffn, 0xffefffffffffffffn,
  0x4340000000000000n, 0xc340000000000000n, 0x4430000000000000n,
  0x44b52d02c7e14af5n, 0x44b52d02c7e14af6n, 0x44b52d02c7e14af7n,
  0x444b1ae4d6e2ef4en, 0x444b1ae4d6e2ef4fn, 0x444b1ae4d6e2ef50n,
  0x3eb0c6f7a0b5ed8cn, 0x3eb0c6f7a0b5ed8dn, 0x41b3de4355555553n,
  0x41b3de4355555554n, 0x41b3de4355555555n, 0x41b3de4355555556n,
  0x41b3de4355555557n, 0xbecbf647612f3696n, 0x43143ff3c1cb0959n,
  0x000fffffffffffffn, 0x0010000000000000n, 0x3ff0000000000000n,
  0x3fb999999999999an, 0x3fd5555555555555n, 0x400921fb54442d18n,
]) {
  addBits(b);
}
for (const x of [
  Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, Number.EPSILON,
  0.1, 0.2, 0.30000000000000004, 1 / 3, 2 / 3, 123.456, 1e21, 1e-6, 1e-7,
]) {
  addAround(x, 2);
}

// Small integers and short decimals.
for (let i = -100; i <= 100; i++) {
  add(i);
  add(i / 10);
  add(i / 100);
}

// Powers of ten across the whole range, with neighbours.
for (let e = -325; e <= 308; e++) {
  addAround(Number(`1e${e}`), 1);
}

// Every power of two; neighbours for every eighth.
for (let e = -1074; e <= 1023; e++) {
  const x = 2 ** e;
  if (e % 8 === 0) {
    addAround(x, 1);
  } else {
    add(x);
  }
}

// The boundaries where ECMAScript switches between plain and exponent form.
for (const x of [1e21, 1e-6, 1e-7, 1e20, 1e-5]) {
  addAround(x, 40);
}

// Uniformly random bit patterns: every exponent, mostly 17-digit outputs.
for (let i = 0; i < 6000; i++) {
  addBits(next64());
}

// Short random decimals, which exercise the shortest-digit choice.
for (let i = 0; i < 4000; i++) {
  const digits = 1 + below(17);
  let m = String(1 + below(9));
  for (let j = 1; j < digits; j++) {
    m += String(below(10));
  }
  const e = below(61) - 30;
  const x = Number(`${m}e${e}`);
  add(below(2) === 0 ? x : -x);
}

// Random integers below 2^53 and large integers up to about 1e25.
for (let i = 0; i < 1000; i++) {
  add(Number(next64() >> 11n));
}
for (let i = 0; i < 500; i++) {
  add(Number(next64()) * 10 ** below(7));
}

// Random subnormals.
for (let i = 0; i < 500; i++) {
  addBits(next64() & 0x800fffffffffffffn);
}

process.stdout.write(lines.join("\n") + "\n");
