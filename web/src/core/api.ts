// The client of `/api/v1` (M4 design sections 3.7 and 3.9, ADR-014
// "CSRF").
//
// Every request goes to a same-origin path below `/api/v1/`, carries
// `X-FSTP-Request: 1` and sends credentials to the same origin only. The
// browser adds `Origin`, which the server compares with the tenant origin.
// Each parameter fills exactly one path segment. A response body counts
// only after the generated validator of its operation accepts it.
//
// The answers of design section 3.7 `OpResult`, on the wire. Interim,
// pending Daniel and lanes W3b and W4e, which build the server side:
//
// - `Done`: a 2xx JSON body, which is the operation's read model itself.
// - `Pending`: a 2xx `PendingReceipt` of `gen/api.ts`,
//   `{"status":"awaiting_confirmation","confirm_path","expires"}`.
// - `StepUpRequired`: a 4xx `{"code":"step_up_required","challenge":C}`.
//   `C` is `{"challenge_id","digest","public_key"}`: the M3 step-up
//   options `{challenge_id, public_key}` of a challenge bound to the
//   action digest `digest` (`StepUp::begin`).
// - `StrongMethodRequired`: a 4xx `{"code":"strong_method_required"}`.
// - A refusal: a 4xx `ApiErrorBody` of `gen/api.ts`,
//   `{"code","rule"?,"values"?}`. `values` maps each parameter id the
//   rule names to its ADR-006 string, such as both values of I-50.
//
// This module reads those shapes itself and imports nothing from
// `gen/api.ts`. So a page test that serves its own operation table still
// loads it.

/** The fetch the API client calls: the page's `fetch`, or a test fake. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/**
 * An operation of the generated table, or of a test. The generated
 * `Operation` of `gen/api.ts` is one. With `base` `"api"`, `path` is
 * relative to `/api/v1`, as the generator writes it. A `"page"` operation
 * is a public page, never an API call. Without `base`, `path` is the full
 * path below `/api/v1/`.
 */
export interface OperationRef {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
  readonly base?: "api" | "page";
}

/**
 * A step-up challenge bound to one action digest (design section 3.7
 * step 7, `StepUpChallenge`). The M3 ceremony of `stepup.ts` answers it.
 */
export interface StepUpChallenge {
  /** The M3 challenge id, 16 bytes in lowercase hex. */
  readonly challengeId: string;
  /** The action digest the challenge is bound to, 32 bytes in lowercase hex. */
  readonly digest: string;
  /** The WebAuthn request options in their JSON form, for the browser's own parser. */
  readonly publicKey: Readonly<Record<string, unknown>>;
}

/** What one API call gives. It is returned, never thrown. */
export type ApiOutcome =
  | { readonly kind: "done"; readonly body: unknown }
  | { readonly kind: "pending"; readonly confirmPath: string; readonly expires: string }
  | { readonly kind: "step_up_required"; readonly challenge: StepUpChallenge }
  | { readonly kind: "strong_method_required" }
  | {
      readonly kind: "refused";
      readonly code: string;
      readonly rule: string | null;
      /** The values the rule names, by parameter id, such as P-05 and P-58 of I-50. */
      readonly values?: Readonly<Record<string, string>>;
    }
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

/**
 * The full path template of `op` below `/api/v1/`, or null. A generated
 * operation with `base` `"api"` has a path relative to `/api/v1`, which
 * starts with one `/`. A `"page"` operation, or any other base, is null.
 */
function fullPath(op: OperationRef): string | null {
  const path: unknown = op.path;
  const base: unknown = Object.hasOwn(op, "base") ? op.base : undefined;
  if (typeof path !== "string") {
    return null;
  }
  if (base === undefined) {
    return path.startsWith(API_PREFIX) ? path : null;
  }
  if (base !== "api" || !path.startsWith("/") || path.startsWith("//")) {
    return null;
  }
  return `${API_PREFIX.slice(0, -1)}${path}`;
}

/** The filled path of `op`, or null when the template or a parameter is refused. */
function fillPath(op: OperationRef, params: Readonly<Record<string, string>>): string | null {
  const path = fullPath(op);
  if (path === null) {
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

/** `v` as a plain JSON object, or null. */
function plain(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

/** Whether `o` has exactly the members `names`. */
function exactly(o: Readonly<Record<string, unknown>>, names: readonly string[]): boolean {
  const keys = Object.keys(o);
  return keys.length === names.length && names.every((n) => Object.hasOwn(o, n));
}

/** Whether `v` is lowercase hex of exactly `bytes` bytes. */
function hexOf(v: unknown, bytes: number): v is string {
  return typeof v === "string" && v.length === 2 * bytes && /^[0-9a-f]*$/.test(v);
}

/** The WebAuthn JSON form of a challenge: unpadded base64url, not empty. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * The challenge of a step-up answer, or null. It is exactly
 * `{"challenge_id","digest","public_key"}`: a 16-byte and a 32-byte
 * lowercase hex string, and request options whose `challenge` is
 * base64url. The browser's WebAuthn parser checks the options in full.
 */
function challengeOf(v: unknown): StepUpChallenge | null {
  const o = plain(v);
  if (o === null || !exactly(o, ["challenge_id", "digest", "public_key"])) {
    return null;
  }
  const challengeId = o["challenge_id"];
  const digest = o["digest"];
  const publicKey = plain(o["public_key"]);
  if (!hexOf(challengeId, 16) || !hexOf(digest, 32) || publicKey === null) {
    return null;
  }
  const inner = publicKey["challenge"];
  if (typeof inner !== "string" || !BASE64URL.test(inner)) {
    return null;
  }
  return Object.freeze({ challengeId, digest, publicKey });
}

const STRONG_METHOD: ApiOutcome = Object.freeze({ kind: "strong_method_required" });

/**
 * A step-up answer, or null when the body names neither step-up code. A
 * body that names one in any other shape is a malformed response, never a
 * plain refusal, so a page never shows it as one.
 */
function stepUpAnswer(v: unknown): ApiOutcome | null {
  const o = plain(v);
  const code = o?.["code"];
  if (o === null || (code !== "step_up_required" && code !== "strong_method_required")) {
    return null;
  }
  if (code === "strong_method_required") {
    return exactly(o, ["code"]) ? STRONG_METHOD : FAILED_RESPONSE;
  }
  const challenge = exactly(o, ["code", "challenge"]) ? challengeOf(o["challenge"]) : null;
  return challenge === null ? FAILED_RESPONSE : Object.freeze({ kind: "step_up_required", challenge });
}

/**
 * A same-origin path to confirm a pending action at: it starts with one
 * `/` and holds printable ASCII other than `\` only.
 */
function confirmPathOf(v: unknown): string | null {
  if (typeof v !== "string" || !v.startsWith("/") || v.startsWith("//")) {
    return null;
  }
  for (let i = 0; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    if (c < 0x21 || c > 0x7e || c === 0x5c) {
      return null;
    }
  }
  return v;
}

/**
 * A pending receipt of a 2xx answer (I-85), or null when the body is
 * none. A receipt is `PendingReceipt` of `gen/api.ts`: exactly `status`
 * `"awaiting_confirmation"`, `confirm_path` and `expires`, both strings.
 * A body that names that status in any other shape, or whose path is not
 * same-origin, is a malformed response.
 */
function pendingAnswer(v: unknown): ApiOutcome | null {
  const o = plain(v);
  if (o === null || o["status"] !== "awaiting_confirmation") {
    return null;
  }
  const expires = o["expires"];
  const confirmPath = confirmPathOf(o["confirm_path"]);
  if (!exactly(o, ["status", "confirm_path", "expires"]) || confirmPath === null || typeof expires !== "string") {
    return FAILED_RESPONSE;
  }
  return Object.freeze({ kind: "pending", confirmPath, expires });
}

/**
 * A refusal body, `{"code": "...", "rule": "..." | null}` and nothing
 * else, as design section 3.7 shows `ApiError`. Interim, pending Daniel
 * and the wire format of lanes W3b and W4e. A refusal whose rule names
 * values also has `"values"`, an object of strings by parameter id (I-50
 * at save, Daniel's answer of 2026-10-31, M4 design section 15.0).
 */
function refusal(v: unknown): ApiOutcome | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const r = v as Record<string, unknown>;
  const keys = Object.keys(r);
  if (!keys.every((k) => k === "code" || k === "rule" || k === "values")) {
    return null;
  }
  const code = r["code"];
  const rule = Object.hasOwn(r, "rule") ? r["rule"] : null;
  if (typeof code !== "string" || code === "" || (rule !== null && typeof rule !== "string")) {
    return null;
  }
  if (!Object.hasOwn(r, "values")) {
    return Object.freeze({ kind: "refused", code, rule });
  }
  const values = stringValues(r["values"]);
  if (values === null) {
    return null;
  }
  return Object.freeze({ kind: "refused", code, rule, values });
}

/** `v` as a frozen object of strings, or null if it is anything else. */
function stringValues(v: unknown): Readonly<Record<string, string>> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const entries = Object.entries(v);
  if (!entries.every(([, x]) => typeof x === "string")) {
    return null;
  }
  // `fromEntries` defines own members, so a `__proto__` key stays data.
  return Object.freeze(Object.fromEntries(entries) as Record<string, string>);
}

/**
 * The client over `opts.fetch`.
 *
 * - A missing, empty or refused parameter, an operation path outside
 *   `/api/v1/`, or a body that is not JSON makes no request and gives
 *   `failed` with reason `request`. So does a body on a GET.
 * - A thrown `fetch`, or a body that cannot be read, gives `failed` with
 *   reason `network`.
 * - A 2xx response must declare `application/json` and its body must
 *   parse. A pending receipt gives `pending`, when its confirmation path
 *   is a same-origin path. Any other body is `done` only when `validate`
 *   accepts it. Otherwise it gives `failed` with reason
 *   `invalid_response`. Interim, pending Daniel: the declared type is
 *   required (see `isJson`).
 * - A 4xx JSON response that names `step_up_required` with a well-formed
 *   challenge gives `step_up_required`, and exactly
 *   `{"code":"strong_method_required"}` gives `strong_method_required`.
 *   Any other shape that names either code is `invalid_response`, never
 *   a refusal. A response in the refusal shape gives `refused`.
 * - Every other response gives `failed` with reason `invalid_response`.
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
      const url = fillPath(op, params);
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
        const pending = pendingAnswer(parsed.value);
        if (pending !== null) {
          return pending;
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
        return stepUpAnswer(parsed.value) ?? refusal(parsed.value) ?? FAILED_RESPONSE;
      }
      return FAILED_RESPONSE;
    },
  });
}
