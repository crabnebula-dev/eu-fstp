// api.ts: the client of /api/v1 (M4 design sections 3.7 and 3.9, ADR-014
// "CSRF"). Requests are same-origin and carry `X-FSTP-Request: 1`; a
// response body is used only after its generated validator accepts it.

import { createApi } from "../src/core/api.js";
import { OPERATIONS } from "../src/gen/api.js";
import type { ApiOutcome, FetchLike, OperationRef } from "./support/contract.js";
import { assert, eq, show, test } from "./support/harness.js";
import { core } from "./support/load.js";

interface Sent {
  readonly url: string;
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly credentials: string | undefined;
  readonly body: string | null;
}

function recorder(status: number, body: string): { fetch: FetchLike; sent: Sent[] } {
  const sent: Sent[] = [];
  const fetch: FetchLike = async (url, init) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    sent.push({
      url: String(url),
      method: (init.method ?? "GET").toUpperCase(),
      headers,
      credentials: init.credentials,
      body: typeof init.body === "string" ? init.body : null,
    });
    return new Response(body, { status, headers: { "content-type": "application/json" } });
  };
  return { fetch, sent };
}

const READ: OperationRef = { method: "GET", path: "/api/v1/programmes/{programme}/draft" };
const WRITE: OperationRef = { method: "POST", path: "/api/v1/programmes/{programme}/draft/fields/{field}" };
const always = (): boolean => true;

function sameOriginPath(url: string): boolean {
  return url.startsWith("/") && !url.startsWith("//") && !url.includes("\\") && !/^[a-z][a-z0-9+.-]*:/i.test(url);
}

/** ADR-014, CSRF: every request goes to a same-origin path with `X-FSTP-Request: 1` and no cross-origin credentials. */
test("adr014_csrf_every_request_carries_header_and_same_origin_path", async () => {
  const api = await core("api");
  for (const op of [READ, WRITE, { method: "PUT", path: "/api/v1/x" } as const, { method: "DELETE", path: "/api/v1/x" } as const]) {
    const { fetch, sent } = recorder(200, "{}");
    const client = api.createApi({ fetch });
    await client.call(op, { programme: "supersafe", field: "P-04" }, op.method === "GET" ? undefined : { value: "1234.50" }, always);
    eq(sent.length, 1, `${op.method}: one request`);
    const s = sent[0];
    assert(s !== undefined, "request recorded");
    eq(s.method, op.method, "method");
    assert(sameOriginPath(s.url), `${op.method}: ${show(s.url)} is not a same-origin path`);
    assert(s.url.startsWith("/api/v1/"), `${op.method}: ${show(s.url)} is outside /api/v1`);
    eq(s.headers["x-fstp-request"], "1", `${op.method}: X-FSTP-Request`);
    assert(s.credentials === undefined || s.credentials === "same-origin", `${op.method}: credentials ${show(s.credentials)}`);
  }
});

/** ADR-014: a parameter fills exactly one segment, so it can never add segments, a query or a fragment. */
test("adr014_api_params_stay_inside_their_segment", async () => {
  const api = await core("api");
  const nasty = ["../../admin", "a/b", "?x=1", "#top", "..", ".", "a\\b", "%2F", "p 1", "é", "", "\u0000", "a\u0085b", "\u009f"];
  for (const v of nasty) {
    const { fetch, sent } = recorder(200, "{}");
    const out = await api.createApi({ fetch }).call(READ, { programme: v }, undefined, always);
    if (sent.length === 0) {
      assert(out.kind !== "done", `${show(v)}: no request, yet the call is done`);
      continue;
    }
    const url = sent[0]?.url ?? "";
    assert(sameOriginPath(url), `${show(v)}: ${show(url)} is not a same-origin path`);
    assert(!url.includes("?") && !url.includes("#"), `${show(v)}: ${show(url)} gained a query or fragment`);
    const segs = url.split("/");
    eq(segs.length, READ.path.split("/").length, `${show(v)}: segment count of ${show(url)}`);
    assert(!segs.slice(1).some((s) => s === "" || s === "." || s === ".."), `${show(v)}: ${show(url)} has an empty or dot segment`);
    eq(decodeURIComponent(segs[4] ?? ""), v, `${show(v)}: the parameter decodes back`);
  }
});

/**
 * ADR-014, HANDOFF 2026-10-25: a parameter the server's router refuses
 * makes no request. That covers C0, DEL and C1 controls (Rust's
 * `char::is_control`) and a value still holding `%XX`.
 */
test("adr014_api_param_refused_by_server_router_makes_no_request", async () => {
  const api = await core("api");
  for (const v of ["\u0000", "a\u001fb", "\u007f", "\u0080", "a\u0085b", "\u009f", "%41", "a%2Fb"]) {
    const { fetch, sent } = recorder(200, "{}");
    const out = await api.createApi({ fetch }).call(READ, { programme: v }, undefined, always);
    eq(sent.length, 0, `${show(v)}: no request`);
    eq(out, { kind: "failed", reason: "request" }, `${show(v)}: outcome`);
  }
});

/** ADR-014: a missing parameter makes no request. */
test("adr014_api_missing_param_makes_no_request", async () => {
  const api = await core("api");
  const { fetch, sent } = recorder(200, "{}");
  const out = await api.createApi({ fetch }).call(WRITE, { programme: "supersafe" }, {}, always);
  eq(sent.length, 0, "no request");
  eq(out, { kind: "failed", reason: "request" }, "outcome");
});

/** ADR-014: a body that is not JSON, or that the generated validator refuses, is never `done`. */
test("adr014_api_invalid_response_is_never_done", async () => {
  const api = await core("api");
  const cases: readonly [string, (v: unknown) => boolean][] = [
    ["not json", always],
    ["{\"a\":1}", () => false],
    ["", always],
    ["{\"a\":", always],
  ];
  for (const [body, validate] of cases) {
    const { fetch } = recorder(200, body);
    const out: ApiOutcome = await api.createApi({ fetch }).call(READ, { programme: "supersafe" }, undefined, validate);
    eq(out, { kind: "failed", reason: "invalid_response" }, `body ${show(body)}`);
  }
});

/** ADR-014: a JSON body the validator accepts is `done`, with the parsed value. */
test("adr014_api_validated_body_is_done", async () => {
  const api = await core("api");
  const { fetch } = recorder(200, "{\"cap\":\"400000.00\",\"state\":\"DRAFT\"}");
  let seen: unknown = undefined;
  const out = await api.createApi({ fetch }).call(READ, { programme: "supersafe" }, undefined, (v) => {
    seen = v;
    return true;
  });
  eq(seen, { cap: "400000.00", state: "DRAFT" }, "the validator saw the parsed body");
  eq(out, { kind: "done", body: { cap: "400000.00", state: "DRAFT" } }, "outcome");
});

/** ADR-014: a network failure is reported, never thrown at the page. */
test("adr014_api_network_failure_is_reported", async () => {
  const api = await core("api");
  const fetch: FetchLike = async () => {
    throw new TypeError("network down");
  };
  const out = await api.createApi({ fetch }).call(READ, { programme: "supersafe" }, undefined, always);
  eq(out, { kind: "failed", reason: "network" }, "outcome");
});

// ------------------------------------------------- the generated table and OpResult

const CHALLENGE_WIRE = {
  challenge_id: "0123456789abcdef0123456789abcdef",
  digest: "ab".repeat(32),
  public_key: { challenge: "c3RlcC11cA", rpId: "a.fstp.test", userVerification: "required" },
};

function replying(status: number, body: unknown): { fetch: FetchLike; sent: Sent[] } {
  return recorder(status, JSON.stringify(body));
}

/** The value of each `{name}` of `path`: `v-<name>`. */
function fill(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of path.matchAll(/\{([a-z][a-z0-9_]*)\}/g)) {
    const name = m[1];
    if (name !== undefined) {
      out[name] = `v-${name}`;
    }
  }
  return out;
}

/**
 * ADR-014, design section 3.9: every operation of the generated table is
 * called at `/api/v1` and its own path, with its own method. A public
 * page of the table is never called through the API client.
 */
test("adr014_api_generated_operations_are_called_below_api_v1", async () => {
  for (const op of OPERATIONS) {
    const { fetch, sent } = recorder(200, "{}");
    const body = op.method === "GET" ? undefined : {};
    const out = await createApi({ fetch }).call(op, fill(op.path), body, always);
    if (op.base === "page") {
      eq(sent.length, 0, `${op.name}: a public page makes no API request`);
      eq(out, { kind: "failed", reason: "request" }, `${op.name}: outcome`);
      continue;
    }
    eq(sent.length, 1, `${op.name}: one request`);
    const want = `/api/v1${op.path.replace(/\{([a-z][a-z0-9_]*)\}/g, "v-$1")}`;
    eq(sent[0]?.url, want, `${op.name}: url`);
    eq(sent[0]?.method, op.method, `${op.name}: method`);
    eq(out, { kind: "done", body: {} }, `${op.name}: outcome`);
  }
});

/** ADR-014: a relative path with base `api` must start with exactly one `/`. */
test("adr014_api_relative_path_must_be_rooted", async () => {
  for (const path of ["programmes", "//evil.example/x", "", "/"]) {
    const { fetch, sent } = recorder(200, "{}");
    const out = await createApi({ fetch }).call({ method: "GET", path, base: "api" }, {}, undefined, always);
    eq(sent.length, 0, `${show(path)}: no request`);
    eq(out, { kind: "failed", reason: "request" }, `${show(path)}: outcome`);
  }
});

/**
 * I-78, design section 3.7 step 7: a step-up answer gives
 * `step_up_required` with the challenge bound to the action digest.
 */
test("i78_api_step_up_answer_carries_the_digest_bound_challenge", async () => {
  for (const status of [401, 403]) {
    const { fetch } = replying(status, { code: "step_up_required", challenge: CHALLENGE_WIRE });
    const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, () => {
      throw new Error("a step-up answer never reaches the validator");
    });
    eq(
      out,
      {
        kind: "step_up_required",
        challenge: {
          challengeId: CHALLENGE_WIRE.challenge_id,
          digest: CHALLENGE_WIRE.digest,
          publicKey: CHALLENGE_WIRE.public_key,
        },
      },
      `status ${status}`,
    );
  }
});

/**
 * I-78: a step-up answer in any other shape is a malformed response,
 * never a refusal and never a step-up without its challenge.
 */
test("i78_api_malformed_step_up_answer_is_invalid_response", async () => {
  const c = CHALLENGE_WIRE;
  const bodies: readonly unknown[] = [
    { code: "step_up_required" },
    { code: "step_up_required", rule: "I-78" },
    { code: "step_up_required", challenge: c, extra: 1 },
    { code: "step_up_required", challenge: "00" },
    { code: "step_up_required", challenge: { ...c, extra: 1 } },
    { code: "step_up_required", challenge: { digest: c.digest, public_key: c.public_key } },
    { code: "step_up_required", challenge: { ...c, challenge_id: c.challenge_id.toUpperCase() } },
    { code: "step_up_required", challenge: { ...c, challenge_id: "00" } },
    { code: "step_up_required", challenge: { ...c, digest: c.digest.slice(2) } },
    { code: "step_up_required", challenge: { ...c, digest: `${c.digest.slice(2)}zz` } },
    { code: "step_up_required", challenge: { ...c, public_key: [] } },
    { code: "step_up_required", challenge: { ...c, public_key: null } },
    { code: "step_up_required", challenge: { ...c, public_key: { rpId: "a.fstp.test" } } },
    { code: "step_up_required", challenge: { ...c, public_key: { challenge: "a+b/c=" } } },
    { code: "step_up_required", challenge: { ...c, public_key: { challenge: "" } } },
    { code: "strong_method_required", rule: "I-77" },
    { code: "strong_method_required", challenge: c },
  ];
  for (const body of bodies) {
    const { fetch } = replying(403, body);
    const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, always);
    eq(out, { kind: "failed", reason: "invalid_response" }, show(body));
  }
});

/** I-77, design section 3.7 step 7: no phishing-resistant method gives `strong_method_required`. */
test("i77_api_strong_method_answer_is_read", async () => {
  const { fetch } = replying(403, { code: "strong_method_required" });
  const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, always);
  eq(out, { kind: "strong_method_required" }, "outcome");
});

/** I-85, design section 3.7 step 6: a pending receipt gives `pending`, and the validator never sees it. */
test("i85_api_pending_receipt_is_pending", async () => {
  const receipt = { status: "awaiting_confirmation", confirm_path: "/app/pending/42", expires: "2026-10-30T10:00:00Z" };
  for (const status of [200, 202]) {
    const { fetch } = replying(status, receipt);
    const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, () => false);
    eq(out, { kind: "pending", confirmPath: "/app/pending/42", expires: "2026-10-30T10:00:00Z" }, `status ${status}`);
  }
  for (const path of ["https://evil.example/x", "//evil.example/x", "app/pending/42", "/a b", "/a\\b"]) {
    const { fetch } = replying(202, { ...receipt, confirm_path: path });
    const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, always);
    eq(out, { kind: "failed", reason: "invalid_response" }, `confirm path ${show(path)}`);
  }
  for (const body of [
    { status: "awaiting_confirmation" },
    { ...receipt, extra: 1 },
    { ...receipt, expires: 1 },
    { status: "awaiting_confirmation", confirm_path: "/app/pending/42" },
  ]) {
    const { fetch } = replying(202, body);
    const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, always);
    eq(out, { kind: "failed", reason: "invalid_response" }, `receipt ${show(body)}`);
  }
});

/** Design section 3.7: a refusal names the rule only, and a step-up code never reads as one. */
test("adr014_api_refusal_is_read_after_step_up_codes", async () => {
  const { fetch } = replying(403, { code: "refused", rule: "I-67" });
  const out = await createApi({ fetch }).call(WRITE, { programme: "p", field: "f" }, {}, always);
  eq(out, { kind: "refused", code: "refused", rule: "I-67" }, "outcome");
});
