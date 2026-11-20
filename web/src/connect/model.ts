// The model of the consent page `/app/connect#<handle>` (ADR-013
// amendment of 2026-11-20, lane L2). Pure: no DOM, no storage and no
// network, so the tests run it as it is.
//
// - The consent handle travels in the URL fragment, which no request
//   line carries. It is 43 characters of base64url, as `fstp-oauth`
//   draws it.
// - `agents.consent_request` answers what the page shows: the client, its
//   own name as unverified text, the redirect host, the scopes and the
//   expiry. It names no account (I-86).
// - The approval is `agents.consent` through core `withStepUp`, so a
//   passkey step-up bound to the request runs first (I-78). A magic-link
//   session is refused with I-77, and the page asks for a passkey
//   sign-in. Only an approval that the server answered `done` leaves the
//   page, to the client's redirect URI.
// - The redirect leaves the platform only for an `https` URL, or an
//   `http` URL to a loopback host on the person's own device (RFC 8252),
//   with no user information. Anything else stays on the page.

import type { ApiOutcome } from "../core/api.js";

/** The consent page. */
export const CONNECT_PATH = "/app/connect";

/** The key of the tab's session storage that keeps the handle across a sign-in. */
export const HANDLE_KEY = "fstp.connect.consent";

/** The route of the person's denial (`fstp_cell::oauth::routes`). */
export const DENY_ROUTE = "/oauth/deny";

/** The scopes the authorisation server issues, as ADR-013 names them. */
export const SCOPES: readonly string[] = [
  "calls:read",
  "proposals:read",
  "proposals:draft",
  "proposals:binding",
  "stage2:draft",
  "review:read",
  "review:draft",
  "ranking:read",
  "findings:read",
  "creator:draft",
  "calls:draft",
  "audit:read",
  "tenant:draft",
];

const HANDLE = /^[A-Za-z0-9_-]{43}$/;

/** `s` when it is a consent handle: 43 characters of base64url. */
export function consentHandle(s: unknown): string | null {
  return typeof s === "string" && HANDLE.test(s) ? s : null;
}

/** What the page shows of a pending consent. */
export interface ConsentView {
  /** The client's number. */
  readonly client: string;
  /** The client's own name: untrusted text, shown as unverified. */
  readonly name: string | null;
  /** The host the browser goes back to. */
  readonly redirectHost: string;
  /** Whether that host is a loopback host on the person's own device. */
  readonly loopback: boolean;
  /** The scopes asked for, each one of [`SCOPES`]. */
  readonly scopes: readonly string[];
  /** When the request expires, microseconds as a decimal string. */
  readonly expires: string;
}

function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

/** The view of an `agents.consent_request` reply, or null for any other shape. */
export function readConsentView(v: unknown): ConsentView | null {
  const o = record(v);
  if (o === null) {
    return null;
  }
  const client = o["client"];
  const name = o["name"];
  const host = o["redirect_host"];
  const loopback = o["loopback"];
  const scopes = o["scopes"];
  const expires = o["expires"];
  if (
    typeof client !== "string" ||
    !/^[0-9]{1,39}$/.test(client) ||
    (name !== undefined && typeof name !== "string") ||
    typeof host !== "string" ||
    host === "" ||
    typeof loopback !== "boolean" ||
    !Array.isArray(scopes) ||
    scopes.length === 0 ||
    typeof expires !== "string" ||
    !/^-?[0-9]{1,20}$/.test(expires)
  ) {
    return null;
  }
  const list: string[] = [];
  for (const s of scopes as unknown[]) {
    if (typeof s !== "string" || !SCOPES.includes(s) || list.includes(s)) {
      return null;
    }
    list.push(s);
  }
  return {
    client,
    name: typeof name === "string" ? name : null,
    redirectHost: host,
    loopback,
    scopes: list,
    expires,
  };
}

const LOOPBACK = new Set(["127.0.0.1", "[::1]", "localhost"]);

/**
 * `v` when the browser may leave for it after a decision: an `https`
 * URL, or an `http` URL to a loopback host (RFC 8252), with no user
 * information. Anything else is null.
 */
export function clientRedirect(v: unknown): string | null {
  if (typeof v !== "string" || v.length > 2048) {
    return null;
  }
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return null;
  }
  if (u.username !== "" || u.password !== "") {
    return null;
  }
  if (u.protocol === "https:" || (u.protocol === "http:" && LOOPBACK.has(u.hostname))) {
    return v;
  }
  return null;
}

/** What an approval or a denial leads to. */
export type Decision =
  | { readonly kind: "redirect"; readonly to: string }
  | { readonly kind: "passkey_needed" }
  | { readonly kind: "step_up_cancelled" }
  | { readonly kind: "expired" }
  | { readonly kind: "refused"; readonly rule: string | null }
  | { readonly kind: "unavailable" };

/**
 * The decision of an `agents.consent` outcome. A completed approval with
 * a safe redirect leaves for it. A session that is not phishing-resistant
 * is asked for a passkey sign-in (I-77). A step-up that did not complete
 * sends nothing (I-78). A handle the server no longer holds is expired.
 */
export function approval(o: ApiOutcome | { readonly kind: "unavailable" }): Decision {
  switch (o.kind) {
    case "done": {
      const to = clientRedirect(record(o.body)?.["redirect"]);
      return to === null ? { kind: "unavailable" } : { kind: "redirect", to };
    }
    case "strong_method_required":
      return { kind: "passkey_needed" };
    case "step_up_required":
      return { kind: "step_up_cancelled" };
    case "refused":
      if (o.rule === "I-77") {
        return { kind: "passkey_needed" };
      }
      if (o.rule === "Input") {
        return { kind: "expired" };
      }
      return { kind: "refused", rule: o.rule };
    case "pending":
      // An approval is never prepared: it is web only (I-85).
      return { kind: "refused", rule: "I-85" };
    case "failed":
    case "unavailable":
      return { kind: "unavailable" };
  }
}

/** The decision of a `POST /oauth/deny` reply with `status` and parsed `body`. */
export function denial(status: number, body: unknown): Decision {
  if (status === 200) {
    const to = clientRedirect(record(body)?.["redirect"]);
    return to === null ? { kind: "unavailable" } : { kind: "redirect", to };
  }
  if (status === 400) {
    return { kind: "expired" };
  }
  return status === 403 ? { kind: "refused", rule: null } : { kind: "unavailable" };
}

/** The sign-in page that returns to the consent page (`auth/next.ts`). */
export function signInPath(): string {
  return `/auth/login?next=${encodeURIComponent(CONNECT_PATH)}`;
}
