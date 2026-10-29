// The client of `/api/v1` (M4 design sections 3.7 and 3.9, ADR-014
// "CSRF").
//
// Every request goes to a same-origin path below `/api/v1/`, carries
// `X-FSTP-Request: 1` and sends credentials to the same origin only. The
// browser adds `Origin`, which the server compares with the tenant origin.
// Each parameter fills exactly one path segment. A response body counts
// only after the generated validator of its operation accepts it.

/** The fetch the API client calls: the page's `fetch`, or a test fake. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** An operation of the generated table. */
export interface OperationRef {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
}

/** What one API call gives. It is returned, never thrown. */
export type ApiOutcome =
  | { readonly kind: "done"; readonly body: unknown }
  | { readonly kind: "pending"; readonly confirmPath: string; readonly expires: string }
  | { readonly kind: "step_up_required"; readonly challenge: unknown }
  | { readonly kind: "strong_method_required" }
  | { readonly kind: "refused"; readonly code: string; readonly rule: string | null }
  | { readonly kind: "failed"; readonly reason: "network" | "invalid_response" | "request" };

/** The API client. */
export interface ApiClient {
  /**
   * Calls `op` with its `{name}` segments filled from `params`. A body
   * other than `undefined` is sent as JSON. `validate` is the generated
   * validator of the operation's response.
   */
  call(
    op: OperationRef,
    params: Readonly<Record<string, string>>,
    body: unknown,
    validate: (v: unknown) => boolean,
  ): Promise<ApiOutcome>;
}

/** The prefix of every API path. */
export const API_PREFIX = "/api/v1/";
/** The CSRF header of ADR-014 and its value. */
export const CSRF_HEADER = "X-FSTP-Request";
export const CSRF_VALUE = "1";

const METHODS: ReadonlySet<string> = new Set(["GET", "POST", "PUT", "DELETE"]);
const PARAM = /^\{([a-z][a-z0-9_]*)\}$/;
/** A literal segment of an operation path: unreserved characters only. */
const LITERAL = /^[A-Za-z0-9._~-]+$/;

const FAILED_REQUEST: ApiOutcome = Object.freeze({ kind: "failed", reason: "request" });
const FAILED_NETWORK: ApiOutcome = Object.freeze({ kind: "failed", reason: "network" });
const FAILED_RESPONSE: ApiOutcome = Object.freeze({ kind: "failed", reason: "invalid_response" });

function isHex(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
}

/**
 * Whether `v` can travel as one path segment that the server's router
 * decodes back to `v`. Under the HTTP router decision of 2026-10-25
 * (HANDOFF.md), the server refuses a segment that decodes to `/`, `\` or a
 * control character, or still holds `%XX`. Its control check is Rust's
 * `char::is_control`: C0, DEL and C1. This client refuses the same,
 * and also an empty value, `.`, `..` and lone surrogates, so a parameter
 * never adds a segment, a query or a fragment.
 */
function segmentValue(v: unknown): string | null {
  if (typeof v !== "string" || v === "" || v === "." || v === "..") {
    return null;
  }
  for (let i = 0; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c === 0x2f || c === 0x5c) {
      return null;
    }
    if (c === 0x25 && isHex(v.charCodeAt(i + 1)) && isHex(v.charCodeAt(i + 2))) {
      return null;
    }
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = v.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return null;
      }
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return null;
    }
  }
  return encodeURIComponent(v);
}

/** The filled path of `op`, or null when the template or a parameter is refused. */
function fillPath(path: unknown, params: Readonly<Record<string, string>>): string | null {
  if (typeof path !== "string" || !path.startsWith(API_PREFIX)) {
    return null;
  }
  if (typeof params !== "object" || params === null) {
    return null;
  }
  const out: string[] = [];
  for (const seg of path.slice(1).split("/")) {
    const m = PARAM.exec(seg);
    if (m !== null && m[1] !== undefined) {
      const name = m[1];
      const value = segmentValue(Object.hasOwn(params, name) ? params[name] : undefined);
      if (value === null) {
        return null;
      }
      out.push(value);
    } else if (LITERAL.test(seg) && seg !== "." && seg !== "..") {
      out.push(seg);
    } else {
      return null;
    }
  }
  return `/${out.join("/")}`;
}

/**
 * Whether the response says it carries JSON: its media type, without
 * parameters and in any case, is `application/json`.
 *
 * Interim, pending Daniel: a body counts as JSON only when the response
 * declares it. So a 2xx answer without that type is never `done`, and a
 * 4xx answer without it is never `refused`.
 */
function isJson(res: Response): boolean {
  const type = res.headers.get("content-type");
  if (type === null) {
    return false;
  }
  const semi = type.indexOf(";");
  return (semi < 0 ? type : type.slice(0, semi)).trim().toLowerCase() === "application/json";
}

function parseJson(text: string): { readonly ok: true; readonly value: unknown } | { readonly ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

/**
 * A refusal body, `{"code": "...", "rule": "..." | null}` and nothing
 * else, as design section 3.7 shows `ApiError`. Interim, pending Daniel
 * and the wire format of lanes W3b and W4e.
 */
function refusal(v: unknown): ApiOutcome | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const r = v as Record<string, unknown>;
  const keys = Object.keys(r);
  if (!keys.every((k) => k === "code" || k === "rule")) {
    return null;
  }
  const code = r["code"];
  const rule = Object.hasOwn(r, "rule") ? r["rule"] : null;
  if (typeof code !== "string" || code === "" || (rule !== null && typeof rule !== "string")) {
    return null;
  }
  return Object.freeze({ kind: "refused", code, rule });
}

/**
 * The client over `opts.fetch`.
 *
 * - A missing, empty or refused parameter, an operation path outside
 *   `/api/v1/`, or a body that is not JSON makes no request and gives
 *   `failed` with reason `request`. So does a body on a GET.
 * - A thrown `fetch`, or a body that cannot be read, gives `failed` with
 *   reason `network`.
 * - A 2xx response is `done` only when it declares `application/json`,
 *   its body parses, and `validate` accepts it. Otherwise it gives
 *   `failed` with reason `invalid_response`. Interim, pending Daniel:
 *   the declared type is required (see `isJson`).
 * - A 4xx JSON response in the refusal shape gives `refused`. Interim,
 *   pending Daniel: the wire format of step-up, pending actions and other
 *   statuses waits for lanes W3b and W4e, so every other response gives
 *   `failed` with reason `invalid_response`.
 */
export function createApi(opts: { readonly fetch: FetchLike }): ApiClient {
  const fetchFn = opts.fetch;
  if (typeof fetchFn !== "function") {
    throw new TypeError("createApi needs a fetch function");
  }
  return Object.freeze({
    async call(
      op: OperationRef,
      params: Readonly<Record<string, string>>,
      body: unknown,
      validate: (v: unknown) => boolean,
    ): Promise<ApiOutcome> {
      if (typeof op !== "object" || op === null || !METHODS.has(op.method) || typeof validate !== "function") {
        return FAILED_REQUEST;
      }
      const url = fillPath(op.path, params);
      if (url === null) {
        return FAILED_REQUEST;
      }
      const headers: Record<string, string> = { [CSRF_HEADER]: CSRF_VALUE, Accept: "application/json" };
      const init: RequestInit = {
        method: op.method,
        headers,
        credentials: "same-origin",
        mode: "same-origin",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      };
      if (body !== undefined) {
        if (op.method === "GET") {
          return FAILED_REQUEST;
        }
        let text: string | undefined;
        try {
          text = JSON.stringify(body);
        } catch {
          return FAILED_REQUEST;
        }
        if (typeof text !== "string") {
          return FAILED_REQUEST;
        }
        headers["Content-Type"] = "application/json";
        init.body = text;
      }
      let res: Response;
      let text: string;
      try {
        res = await fetchFn(url, init);
        text = await res.text();
      } catch {
        return FAILED_NETWORK;
      }
      const parsed = isJson(res) ? parseJson(text) : { ok: false as const };
      if (res.status >= 200 && res.status <= 299) {
        if (!parsed.ok) {
          return FAILED_RESPONSE;
        }
        let accepted: unknown;
        try {
          accepted = validate(parsed.value);
        } catch {
          return FAILED_RESPONSE;
        }
        return accepted === true ? Object.freeze({ kind: "done", body: parsed.value }) : FAILED_RESPONSE;
      }
      if (res.status >= 400 && res.status <= 499 && parsed.ok) {
        return refusal(parsed.value) ?? FAILED_RESPONSE;
      }
      return FAILED_RESPONSE;
    },
  });
}
