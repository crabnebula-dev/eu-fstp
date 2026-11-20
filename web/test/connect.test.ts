// The consent page of an agent connection, `/app/connect#<handle>`
// (ADR-013 amendment of 2026-11-20, lane L2). The page's decisions are
// pure functions of `web/src/connect/model.ts`, run here with the
// approval going through core `withStepUp`, as the page sends it.

import type { ApiOutcome } from "../src/core/api.js";
import { withStepUp } from "../src/core/stepup.js";
import {
  CONNECT_PATH,
  SCOPES,
  approval,
  clientRedirect,
  consentHandle,
  denial,
  readConsentView,
  signInPath,
} from "../src/connect/model.js";
import { CONNECT_ROUTES } from "../src/connect/routes.js";
import { CATALOGUE } from "../src/connect/messages.en.js";
import { assert, eq, test } from "./support/harness.js";

const HANDLE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";
const REDIRECT = "http://127.0.0.1:8765/callback?code=c0de&state=s1&iss=https%3A%2F%2Fcell.example";
const CHALLENGE = { challengeId: "00".repeat(16), digest: "11".repeat(32), publicKey: {} };

/** A scripted API: each attempt answers the next outcome. */
function script(outcomes: readonly ApiOutcome[]): { attempt: () => Promise<ApiOutcome>; calls: () => number } {
  let n = 0;
  return {
    attempt: async () => {
      const o = outcomes[Math.min(n, outcomes.length - 1)];
      n += 1;
      if (o === undefined) {
        throw new Error("script has no outcome");
      }
      return o;
    },
    calls: () => n,
  };
}

/** ADR-013 amendment: a consent handle is 43 characters of base64url, and nothing else. */
test("adr013_connect_handle_is_43_base64url", () => {
  eq(consentHandle(HANDLE), HANDLE, "a handle");
  for (const bad of ["", HANDLE.slice(1), `${HANDLE}A`, `${HANDLE.slice(1)}=`, `${HANDLE.slice(1)}.`, 42, null]) {
    eq(consentHandle(bad), null, `refused: ${String(bad)}`);
  }
});

/** I-86: the view holds the client, its unverified name, the host and the scopes only. */
test("i86_consent_view_reads_the_request_and_no_identity", () => {
  const reply = {
    client: "7",
    name: "Claude Code (fstp)",
    redirect_host: "127.0.0.1",
    loopback: true,
    scopes: ["calls:read", "creator:draft"],
    expires: "600000000",
    account: "123",
  };
  const v = readConsentView(reply);
  assert(v !== null, "a reply of the shape is read");
  eq(Object.keys(v ?? {}).sort(), ["client", "expires", "loopback", "name", "redirectHost", "scopes"], "members");
  eq(v?.scopes, ["calls:read", "creator:draft"], "scopes");
  eq(readConsentView({ ...reply, scopes: ["openid"] }), null, "an unknown scope");
  eq(readConsentView({ ...reply, scopes: ["calls:read", "calls:read"] }), null, "a repeated scope");
  eq(readConsentView({ ...reply, scopes: [] }), null, "no scope");
  eq(readConsentView({ ...reply, loopback: "yes" }), null, "a loopback that is not a boolean");
  eq(readConsentView({ ...reply, name: undefined })?.name, null, "no name");
});

/** ADR-013 "Consent texts": every issued scope has its plain-language text. */
test("adr013_every_scope_has_consent_text", () => {
  for (const s of SCOPES) {
    const text = CATALOGUE.labels[`connect.scope.${s}`];
    assert(typeof text === "string" && text.length > 0, `text of ${s}`);
  }
});

/** I-78: approving links a device, so the approval runs the passkey step-up and is retried once. */
test("i78_consent_needs_passkey_step_up", async () => {
  const s = script([{ kind: "step_up_required", challenge: CHALLENGE }, { kind: "done", body: { redirect: REDIRECT } }]);
  const seen: unknown[] = [];
  const o = await withStepUp(s.attempt, {
    ceremony: async (c) => {
      seen.push(c);
      return true;
    },
    addPasskey: () => undefined,
  });
  eq(s.calls(), 2, "the approval is sent again after the ceremony");
  eq(seen, [CHALLENGE], "one ceremony, for the challenge of the answer");
  eq(approval(o), { kind: "redirect", to: REDIRECT }, "the browser goes back to the agent");

  const cancelled = script([{ kind: "step_up_required", challenge: CHALLENGE }]);
  const c = await withStepUp(cancelled.attempt, { ceremony: async () => false, addPasskey: () => undefined });
  eq(cancelled.calls(), 1, "nothing is sent again");
  eq(approval(c), { kind: "step_up_cancelled" }, "no redirect without a step-up");
});

/** I-77: a magic-link session cannot connect an agent. The page asks for a passkey sign-in and never redirects. */
test("i77_magic_link_session_cannot_consent", async () => {
  eq(approval({ kind: "refused", code: "forbidden", rule: "I-77" }), { kind: "passkey_needed" }, "refused under I-77");
  let enrol = 0;
  const strong = await withStepUp(script([{ kind: "strong_method_required" }]).attempt, {
    ceremony: async () => true,
    addPasskey: () => {
      enrol += 1;
    },
  });
  eq(approval(strong), { kind: "passkey_needed" }, "strong method required");
  eq(enrol, 1, "the person is sent to add a passkey");
});

/** ADR-013: a handle the server no longer holds is expired; any other refusal names its rule. */
test("adr013_consent_refusals_stay_on_the_page", () => {
  eq(approval({ kind: "refused", code: "not_found", rule: "Input" }), { kind: "expired" }, "expired");
  eq(approval({ kind: "refused", code: "forbidden", rule: "I-85" }), { kind: "refused", rule: "I-85" }, "web only");
  eq(approval({ kind: "failed", reason: "network" }), { kind: "unavailable" }, "network");
  eq(approval({ kind: "done", body: { redirect: "javascript:alert(1)" } }), { kind: "unavailable" }, "unsafe redirect");
});

/** TW-4, RFC 8252: the browser leaves only for https, or http to a loopback host, with no user information. */
test("adr013_client_redirect_is_https_or_loopback", () => {
  for (const ok of [REDIRECT, "https://claude.ai/api/mcp/auth_callback?code=x", "http://localhost:3000/cb", "http://[::1]:9/cb"]) {
    eq(clientRedirect(ok), ok, ok);
  }
  for (const bad of [
    "http://agent.example/cb",
    "javascript:alert(1)",
    "data:text/html,x",
    "https://user:pw@agent.example/cb",
    "//agent.example/cb",
    "/app/",
    "",
    7,
  ]) {
    eq(clientRedirect(bad), null, String(bad));
  }
});

/** RFC 6749 section 4.1.2.1: a denial redirects only on the server's 200 with a safe URL. */
test("adr013_denial_redirects_only_on_200", () => {
  const to = "https://agent.example/cb?error=access_denied&iss=x";
  eq(denial(200, { redirect: to }), { kind: "redirect", to }, "200");
  eq(denial(400, { code: "expired" }), { kind: "expired" }, "400");
  eq(denial(403, { code: "forbidden" }), { kind: "refused", rule: null }, "403");
  eq(denial(503, {}), { kind: "unavailable" }, "503");
  eq(denial(200, { redirect: "javascript:x" }), { kind: "unavailable" }, "unsafe");
});

/** SA-09: the page is one route with no segment, and sign-in returns to it. */
test("adr013_connect_route_and_sign_in_return", () => {
  eq(
    CONNECT_ROUTES.map((r) => [r.name, r.pattern]),
    [["connect.consent", CONNECT_PATH]],
    "one route",
  );
  eq(signInPath(), "/auth/login?next=%2Fapp%2Fconnect", "the return path is the page");
});
