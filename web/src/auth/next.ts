// Where a person lands after signing in (M3 design section 11.2, M4
// design sections 2.2 and 3.9; Daniel's report of 2026-10-31).
//
// Interim, pending Daniel (design section 15.0, 2026-10-31): design
// section 2.2 names no landing after sign-in other than the account
// page. Every sign-in now lands on the home page `/app/`. A person who
// opened a deep `/app/` link without a session is sent to the login page
// with that path in `?next=`, and returns to it after signing in.
//
// The return path is never an open redirect. It is taken only when it
// is a same-origin path below `/app/`, written as the browser writes a
// path, with no query, no fragment, no backslash, no control character,
// no space, no `//` and no dot segment, plain or percent-encoded. Every
// other value lands on the home page. This module is pure: it touches
// no DOM, no storage and no network.
//
// The M3 cell serves the auth pages only, and no `/app/` page. Its shell
// says so with `<meta name="fstp-landing" content="/auth/account">`, so a
// sign-in there lands on the account page (Daniel, 2026-11-13, M3 exit
// audit section 7, item 9). The meta names the account page or nothing:
// any other value lands on the home page.

/** The home page of the web pages. */
export const HOME_PATH = "/app/";

/** The account page, the landing on a cell that serves no `/app/` page. */
export const ACCOUNT_PATH = "/auth/account";

/** The name of the shell's meta element that names the landing. */
export const LANDING_META = "fstp-landing";

/**
 * The page a sign-in lands on, from the content of the shell's
 * [`LANDING_META`] element, or null when the shell has none: the account
 * page when the content names it exactly, else the home page.
 */
export function homeOf(declared: unknown): string {
  return declared === ACCOUNT_PATH ? ACCOUNT_PATH : HOME_PATH;
}

/** The login page. */
export const LOGIN_PATH = "/auth/login";

/** The longest return path the login page takes. */
export const MAX_RETURN = 512;

/** The query member that carries the return path. */
const NEXT = "next";

/** Percent-encodings of `.`, `/` and `\`, which could form a segment or a dot segment. */
const ENCODED = /%(2e|2f|5c)/i;

/**
 * Whether `path` may be a return path after sign-in: a same-origin path
 * below `/app/` under the rules of the module documentation.
 */
export function isReturnPath(path: unknown): path is string {
  if (typeof path !== "string" || path.length > MAX_RETURN || !path.startsWith(HOME_PATH)) {
    return false;
  }
  for (let i = 0; i < path.length; i += 1) {
    const c = path.charCodeAt(i);
    // Controls, space, DEL, non-ASCII, `"`, `#`, `?` and `\`. A `%` must start an escape.
    if (c <= 0x20 || c >= 0x7f || c === 0x22 || c === 0x23 || c === 0x3f || c === 0x5c) {
      return false;
    }
    if (c === 0x25 && !/^%[0-9A-Fa-f]{2}$/.test(path.slice(i, i + 3))) {
      return false;
    }
  }
  if (ENCODED.test(path) || path.includes("//")) {
    return false;
  }
  return !path.split("/").some((s) => s === "." || s === "..");
}

/**
 * The page to open after a sign-in on a page whose query is `search`:
 * its `next` member when that is a return path, else the home page.
 * `home` is the landing of the serving cell ([`homeOf`]). A cell whose
 * landing is the account page serves no `/app/` page, so no return path
 * applies there.
 */
export function landingAfterSignIn(search: string, home: string = HOME_PATH): string {
  if (home !== HOME_PATH) {
    return homeOf(home);
  }
  let next: string | null = null;
  try {
    next = new URLSearchParams(search).get(NEXT);
  } catch {
    next = null;
  }
  return isReturnPath(next) ? next : HOME_PATH;
}

/**
 * The login page that returns to `path` after sign-in, or the plain login
 * page when `path` is the home page or no return path.
 */
export function loginPathFor(path: string): string {
  return isReturnPath(path) && path !== HOME_PATH
    ? `${LOGIN_PATH}?${NEXT}=${encodeURIComponent(path)}`
    : LOGIN_PATH;
}
