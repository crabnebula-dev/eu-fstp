// The caller's roles for the `/app/` shell (I-86; M4 design sections 3.6,
// 3.7 and 3.9; Daniel's report of 2026-10-31).
//
// Interim, pending Daniel (design section 15.0, 2026-10-31): the shell
// reads `me.roles` once per page load. The answer fills the role links
// of the site navigation and the home page. A person without a session
// on a page that needs one goes to the login page, which returns them to
// this page after sign-in (`auth/next.ts`). The public pages of
// `model.ts` `isPublicPage` stay readable without a session.
//
// `me.roles` is the caller's own object. Its reply holds the caller's
// own bindings and nothing about any other account (I-86). The reply
// counts only when the generated validator of `gen/api.ts` and the
// closed reader of `model.ts` both accept it.

import { loginPathFor } from "../auth/next.js";
import { type ApiClient, type ApiOutcome, createApi } from "../core/api.js";
import { OPERATIONS, VALIDATORS } from "../gen/api.js";
import { type MyRoles, isPublicPage, readMyRoles } from "./model.js";
import { showRoles } from "./nav.js";

/** What the read of the caller's roles gave. */
export type RolesAnswer =
  | { readonly kind: "roles"; readonly roles: MyRoles }
  | { readonly kind: "signed_out" }
  | { readonly kind: "failed" };

const FAILED: RolesAnswer = Object.freeze({ kind: "failed" });
const SIGNED_OUT: RolesAnswer = Object.freeze({ kind: "signed_out" });

let client: ApiClient | null = null;
let pending: Promise<RolesAnswer> | null = null;

async function load(): Promise<RolesAnswer> {
  const op = OPERATIONS.find((o) => o.name === "me.roles");
  const check = VALIDATORS["me.roles"];
  if (op === undefined || op.base !== "api" || check === undefined) {
    return FAILED;
  }
  const box: { roles: MyRoles | null } = { roles: null };
  const validate = (v: unknown): boolean => {
    box.roles = check(v) ? readMyRoles(v) : null;
    return box.roles !== null;
  };
  client ??= createApi({ fetch: (input, init) => globalThis.fetch(input, init) });
  let o: ApiOutcome;
  try {
    o = await client.call(op, {}, undefined, validate);
  } catch {
    return FAILED;
  }
  if (o.kind === "done" && box.roles !== null) {
    return Object.freeze({ kind: "roles", roles: box.roles });
  }
  if (o.kind === "refused" && o.code === "unauthenticated") {
    return SIGNED_OUT;
  }
  return FAILED;
}

/** The caller's roles, read once per page load. It never throws. */
export function myRoles(): Promise<RolesAnswer> {
  pending ??= load().catch(() => FAILED);
  return pending;
}

/**
 * Reads the caller's roles for the page at `path`: their links go into
 * the site navigation, and a person without a session on a page that
 * needs one goes to the login page, which brings them back here.
 */
export async function startSession(path: string): Promise<void> {
  const a = await myRoles();
  if (a.kind === "roles") {
    showRoles(a.roles);
  } else if (a.kind === "signed_out" && !isPublicPage(path)) {
    location.replace(loginPathFor(path));
  }
}
