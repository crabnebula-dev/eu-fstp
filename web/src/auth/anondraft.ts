// The anonymous draft this browser keeps (ADR-032, Daniel 2026-11-22).
//
// A person may start a draft for an open call without an account. The
// draft lives on the platform under a secret resume link,
// `/auth/draft#<token>`. The browser keeps the token and the call in its
// local storage, so the draft page and the claim page find it again.
// The token is a bearer secret: it travels in the URL fragment and in
// JSON bodies only, never in a path or query (R-NF-02).
//
// This module is pure apart from the three storage helpers, which never
// throw: a browser that refuses storage simply keeps nothing.

/** The page of an anonymous draft. */
export const DRAFT_PATH = '/auth/draft';

/** The local storage key of the kept draft. */
export const STORE_KEY = 'fstp.anondraft';

/** The draft this browser keeps: its resume token and its call. */
export interface Kept {
  /** 64 lowercase hexadecimal characters. */
  readonly token: string;
  /** The call id, as a canonical decimal. */
  readonly call: string;
}

/** Whether `s` is a resume token: exactly 64 lowercase hex characters. */
export function isToken(s: unknown): s is string {
  return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}

/** Whether `s` is a canonical decimal id of at most 39 digits. */
export function isCallId(s: unknown): s is string {
  return typeof s === 'string' && /^(0|[1-9][0-9]{0,38})$/.test(s);
}

/** The kept draft that `raw` holds, or null for anything else. */
export function parseKept(raw: string | null): Kept | null {
  if (raw === null || raw.length > 256) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).length !== 2) return null;
  const token = o['token'];
  const call = o['call'];
  return isToken(token) && isCallId(call) ? { token, call } : null;
}

/** The stored form of `k`. */
export function encodeKept(k: Kept): string {
  return JSON.stringify({ call: k.call, token: k.token });
}

/** The resume link of `token` on `origin`: the token in the fragment. */
export function resumeLink(origin: string, token: string): string {
  return `${origin}${DRAFT_PATH}#${token}`;
}

/** The page of the signed-in app that moves the draft of `call` into the account. */
export function claimPath(call: string): string {
  return `/app/calls/${call}/claim`;
}

/** The draft page that starts a draft for `call`. */
export function startPath(call: string): string {
  return `${DRAFT_PATH}?call=${call}`;
}

/** The call named in the query `search`, or null. */
export function callOfQuery(search: string): string | null {
  let call: string | null = null;
  try {
    call = new URLSearchParams(search).get('call');
  } catch {
    call = null;
  }
  return isCallId(call) ? call : null;
}

/** Keeps `k` in local storage. A refusal keeps nothing. */
export function keep(k: Kept): void {
  try {
    globalThis.localStorage.setItem(STORE_KEY, encodeKept(k));
  } catch {
    // Storage refused: the resume link is the only copy.
  }
}

/** The kept draft, or null. */
export function kept(): Kept | null {
  try {
    return parseKept(globalThis.localStorage.getItem(STORE_KEY));
  } catch {
    return null;
  }
}

/** Forgets the kept draft. */
export function forget(): void {
  try {
    globalThis.localStorage.removeItem(STORE_KEY);
  } catch {
    // Nothing kept.
  }
}
