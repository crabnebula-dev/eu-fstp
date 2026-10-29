// The in-house TypeScript test runner (M4 design section 8.1, ADR-014).
//
// Build and run, from the repository root:
//
//   web/node_modules/.bin/tsc -p web/test
//   node web/dist/test-build/test/runner.js [name-filter ...]
//
// It imports every `*.test.js` file next to it, runs each registered test
// in name order, and prints one line per test:
//
//   ok    <name>
//   red   <name>: <what is not implemented>
//   FAIL  <name>: <why>
//
// `red` means the production module or export does not exist yet, or a
// stub refused with an error named `NotImplemented`. The exit code is 0
// only when every selected test passes. `FSTP_TEST_SEED` changes the
// property seeds; each failure prints the seed it needs to replay.

import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { type TestCase, baseSeed, registered, setCurrentFile, setCurrentTest } from "./support/harness.js";
import { checkLayout } from "./support/paths.js";

type Verdict = "ok" | "red" | "FAIL";

function describe(e: unknown): string {
  if (e instanceof Error) {
    return `${e.name}: ${e.message}`;
  }
  return String(e);
}

async function runOne(t: TestCase): Promise<{ verdict: Verdict; detail: string }> {
  setCurrentTest(t.name);
  try {
    await t.fn();
    return { verdict: "ok", detail: "" };
  } catch (e) {
    if (e instanceof Error && e.name === "NotImplemented") {
      return { verdict: "red", detail: e.message };
    }
    return { verdict: "FAIL", detail: describe(e) };
  }
}

async function main(): Promise<void> {
  checkLayout();
  const here = dirname(fileURLToPath(import.meta.url));
  const files = readdirSync(here)
    .filter((f) => f.endsWith(".test.js"))
    .sort();
  for (const f of files) {
    setCurrentFile(f);
    await import(pathToFileURL(join(here, f)).href);
  }
  const filters = process.argv.slice(2);
  const tests = [...registered()]
    .filter((t) => filters.length === 0 || filters.some((p) => t.name.includes(p)))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const counts: Record<Verdict, number> = { ok: 0, red: 0, FAIL: 0 };
  for (const t of tests) {
    const { verdict, detail } = await runOne(t);
    counts[verdict] += 1;
    const pad = verdict.padEnd(5, " ");
    process.stdout.write(detail === "" ? `${pad} ${t.name}\n` : `${pad} ${t.name}: ${detail}\n`);
  }
  process.stdout.write(
    `\n${tests.length} tests from ${files.length} files: ${counts.ok} ok, ${counts.red} red (not implemented), ${counts.FAIL} failed. FSTP_TEST_SEED=${baseSeed()}\n`,
  );
  process.exitCode = counts.ok === tests.length && tests.length > 0 ? 0 : 1;
}

await main();
