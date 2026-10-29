// Same-origin calls of the auth pages to the cell routes (M3 design
// sections 8.2 and 8.7).
//
// - Every call is same-origin, with the session cookie, no cache and no
//   redirect. The browser adds the `Origin` header the cell checks.
// - A POST body is canonical JSON with `Content-Type: application/json`,
//   the one form the cell accepts. State-changing calls also send
//   `X-FSTP-Request: 1` (M4 design section 3.9 CSRF rule).
// - A JSON reply is read by the browser's `JSON.parse` only. Each page
//   checks the shape it needs before it uses a member.

import { canonical, type Json } from './encoding.js';

/** The status and the parsed JSON body of one reply. */
export interface Reply {
  /** The HTTP status, or 0 when the request did not complete. */
  readonly status: number;
  /** The parsed body of a JSON reply, else undefined. */
  readonly body: unknown;
}

const JSON_TYPE = 'application/json';

async function send(method: 'GET' | 'POST' | 'DELETE', path: string, body?: Json): Promise<Reply> {
  const headers: Record<string, string> = {};
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers,
  };
  if (method !== 'GET') {
    headers['x-fstp-request'] = '1';
  }
  if (body !== undefined) {
    headers['content-type'] = JSON_TYPE;
    init.body = canonical(body);
  }
  let r: Response;
  try {
    r = await fetch(path, init);
  } catch {
    return { status: 0, body: undefined };
  }
  let parsed: unknown;
  const type = r.headers.get('content-type') ?? '';
  if (type === JSON_TYPE || type.startsWith(`${JSON_TYPE};`)) {
    try {
      parsed = await r.json();
    } catch {
      parsed = undefined;
    }
  }
  return { status: r.status, body: parsed };
}

/** `GET path`. */
export function get(path: string): Promise<Reply> {
  return send('GET', path);
}

/** `POST path` with canonical JSON `body`. */
export function post(path: string, body: Json): Promise<Reply> {
  return send('POST', path, body);
}

/** `DELETE path`, with no body. */
export function del(path: string): Promise<Reply> {
  return send('DELETE', path);
}

/** Whether `status` is a 2xx status. */
export function ok(r: Reply): boolean {
  return r.status >= 200 && r.status < 300;
}

/** `v` as a plain object, or null. */
export function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Readonly<Record<string, unknown>>)
    : null;
}
