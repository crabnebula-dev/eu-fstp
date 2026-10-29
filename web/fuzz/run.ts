// The command line of the in-house TypeScript fuzz harness (M4 design
// section 9, Q33 interim, TH-26, H-05).
//
// Build and run, from the repository root:
//
//   web/node_modules/.bin/tsc -p web/test
//   node web/dist/test-build/fuzz/run.js [--target <name>] [--seed <n>] [--iterations <n>]
//   node web/dist/test-build/fuzz/run.js --target <name> --input '<JSON string>'
//
// Without `--target`, every target runs. A failure prints the target, the
// seed, the iteration and the input as a JSON string, so `--input` or the
// same seed and iteration count replays it. The exit code is 0 only when
// every selected target holds.

import { type FuzzOutcome, runTarget } from "./harness.js";
import { TARGETS } from "./targets.js";

function flag(args: readonly string[], name: string): string | null {
  const i = args.indexOf(name);
  if (i < 0) {
    return null;
  }
  const v = args[i + 1];
  if (v === undefined) {
    throw new Error(`${name} needs a value`);
  }
  return v;
}

function int(v: string | null, fallback: number): number {
  if (v === null) {
    return fallback;
  }
  if (!/^[0-9]{1,10}$/.test(v)) {
    throw new Error(`not a non-negative integer: ${v}`);
  }
  return Number(v);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const only = flag(args, "--target");
  const seed = int(flag(args, "--seed"), 1);
  const iterations = int(flag(args, "--iterations"), 20000);
  const input = flag(args, "--input");
  const selected = TARGETS.filter((t) => only === null || t.name === only);
  if (selected.length === 0) {
    throw new Error(`no target named ${String(only)}; targets: ${TARGETS.map((t) => t.name).join(", ")}`);
  }
  let failed = 0;
  for (const t of selected) {
    let outcome: FuzzOutcome;
    try {
      if (input !== null) {
        const text: unknown = JSON.parse(input);
        if (typeof text !== "string") {
          throw new Error("--input takes a JSON string");
        }
        const check = await t.prepare();
        check(text);
        outcome = { ok: true, runs: 1 };
      } else {
        outcome = await runTarget(t, seed, iterations);
      }
    } catch (e) {
      failed += 1;
      const what = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      const label = e instanceof Error && e.name === "NotImplemented" ? "red " : "FAIL";
      process.stdout.write(`${label} ${t.name}: ${what}\n`);
      continue;
    }
    if (outcome.ok) {
      process.stdout.write(`ok   ${t.name}: ${outcome.runs} inputs (seed ${seed})\n`);
    } else {
      failed += 1;
      process.stdout.write(
        `FAIL ${t.name}: ${outcome.message}\n     seed ${seed}, iteration ${outcome.iteration}, input ${JSON.stringify(outcome.input)}\n`,
      );
    }
  }
  process.exitCode = failed === 0 ? 0 : 1;
}

await main();
