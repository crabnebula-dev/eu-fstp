// Fuzz target `return_path` for `isReturnPath` and `landingAfterSignIn`
// in web/src/auth/next.ts (M4 design section 9, ADR-014, TH-26, H-05;
// review finding F2).
//
// The login page reads the untrusted `?next=` query member and decides
// where the browser goes after sign-in. Checks, for any string:
// - neither function throws;
// - an accepted value is a same-origin path below `/app/`: resolved
//   against the cell origin it keeps that origin, its path starts with
//   `/app/`, and no segment is dropped (no dot segment, no `//`);
// - the login page lands on an accepted value as given, and on the home
//   page for every other value;
// - it agrees with the reference reading of the rules on every input,
//   and with the verdicts of web/fuzz/seeds/return_path/expect.tsv.

import { assert, show } from "../test/support/harness.js";
import { HOME_PATH, isReturnPath, landingAfterSignIn } from "../src/auth/next.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

/** The functions of `auth/next.ts` this target drives. */
export interface ReturnPathModule {
  isReturnPath(path: unknown): boolean;
  landingAfterSignIn(search: string): string;
}

/** The production module. */
export const PRODUCTION: ReturnPathModule = { isReturnPath, landingAfterSignIn };

/** A synthetic cell origin to resolve accepted paths against. */
const ORIGIN = "https://cell-a.e2e.invalid";

/**
 * The reference reading of the module's rules, written apart from it: a
 * string of at most 512 characters, starting with `/app/`, of printable
 * ASCII without `"`, `#`, `?` or `\`, whose every `%` starts an escape,
 * with no escape of `.`, `/` or `\`, no `//` and no dot segment.
 */
export function refIsReturnPath(path: unknown): boolean {
  return (
    typeof path === "string" &&
    path.length <= 512 &&
    path.startsWith(HOME_PATH) &&
    /^[\x21\x24-\x3e\x40-\x5b\x5d-\x7e]*$/.test(path) &&
    !/%(?![0-9A-Fa-f]{2})/.test(path) &&
    !/%(2e|2f|5c)/i.test(path) &&
    !path.includes("//") &&
    !/(^|\/)\.\.?(\/|$)/.test(path)
  );
}

/** The checker over any module with the two functions. */
export function checkerFor(m: ReturnPathModule): Checker {
  return (input: string) => {
    // A string with a lone surrogate has no URL encoding, so no query can
    // carry it as given. It is not ASCII, so it must be refused.
    let search: string | null = null;
    try {
      search = `?next=${encodeURIComponent(input)}`;
    } catch {
      search = null;
    }
    let ok: boolean;
    let landing: string;
    try {
      ok = m.isReturnPath(input);
      landing = search === null ? HOME_PATH : m.landingAfterSignIn(search);
    } catch (e) {
      throw new Error(`the return path check threw on ${show(input)}: ${String(e)}`);
    }
    assert(search !== null || !ok, `${show(input)} has no URL encoding but was accepted`);
    if (ok) {
      const u = new URL(input, ORIGIN);
      assert(u.origin === ORIGIN, `${show(input)} was accepted but resolves to ${u.origin}`);
      assert(u.pathname.startsWith(HOME_PATH), `${show(input)} was accepted but resolves to ${u.pathname}`);
      assert(
        u.pathname.split("/").length === input.split("/").length,
        `${show(input)} was accepted but resolving it changes its segments to ${u.pathname}`,
      );
      assert(landing === input, `the login page landed on ${show(landing)} for the accepted ${show(input)}`);
    } else {
      assert(landing === HOME_PATH, `the login page landed on ${show(landing)} for the refused ${show(input)}`);
    }
    assert(ok === refIsReturnPath(input), `the module and the reference disagree on ${show(input)}: got ${ok}`);
  };
}

export const target: FuzzTarget = {
  name: "return_path",
  seeds: () => readExpectations("return_path").map((e) => e.input),
  dictionary: [
    "/",
    "//",
    "/app/",
    ".",
    "..",
    "%2e",
    "%2E",
    "%2f",
    "%2F",
    "%5c",
    "%41",
    "%",
    "\\",
    "?",
    "#",
    "@",
    ":",
    "evil.example",
    "https://",
    "\t",
    " ",
  ],
  prepare: async () => checkerFor(PRODUCTION),
};
