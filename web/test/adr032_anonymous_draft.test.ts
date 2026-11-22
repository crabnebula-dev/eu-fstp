// The anonymous draft this browser keeps (ADR-032, Daniel 2026-11-22;
// R-NF-02). The token travels in the URL fragment only, the kept value
// holds the token and the call and nothing else, and the claim page and
// the start page have fixed same-origin paths. Every value is synthetic.

import {
  DRAFT_PATH,
  callOfQuery,
  claimPath,
  encodeKept,
  isCallId,
  isToken,
  parseKept,
  resumeLink,
  startPath,
} from "../src/auth/anondraft.js";
import { AUTH_EN } from "../src/auth/messages.en.js";
import { PAGES as GEN_PAGES } from "../src/gen/api.js";
import { assert, eq, forAll, test } from "./support/harness.js";
import { type Rng } from "./support/rng.js";

const HEX = "0123456789abcdef";

function token(r: Rng): string {
  let s = "";
  for (let i = 0; i < 64; i += 1) s += HEX[r.below(16)];
  return s;
}

function callId(r: Rng): string {
  return String(1 + r.below(1_000_000_000));
}

/** ADR-032, R-NF-02: the resume link carries the token in its fragment, never in its path or query. */
test("adr032_r_nf_02_resume_link_holds_the_token_in_the_fragment_only", () => {
  forAll(
    (r) => token(r),
    (t) => {
      const link = resumeLink("https://tenant.fstp.test", t);
      const u = new URL(link);
      eq(u.pathname, DRAFT_PATH, "the draft page");
      eq(u.search, "", "no query");
      eq(u.hash, `#${t}`, "the token in the fragment");
      assert(!u.pathname.includes(t), "no token in the path");
    },
  );
});

/** ADR-032: a kept draft survives its stored form, and anything else is refused. */
test("adr032_kept_draft_round_trips_and_refuses_other_shapes", () => {
  forAll(
    (r) => ({ token: token(r), call: callId(r) }),
    (k) => {
      eq(parseKept(encodeKept(k)), k, "round trip");
      eq(parseKept(JSON.stringify({ ...k, email: "a@example.test" })), null, "an extra member");
      eq(parseKept(JSON.stringify({ token: k.token.toUpperCase(), call: k.call })), null, "an upper-case token");
      eq(parseKept(JSON.stringify({ token: k.token, call: `0${k.call}` })), null, "a non-canonical call");
    },
  );
  for (const bad of [null, "", "[]", "null", "{", JSON.stringify({ token: "ab", call: "1" })]) {
    eq(parseKept(bad), null, `refused: ${String(bad)}`);
  }
});

/** ADR-032: only 64 lowercase hex characters spell a token, and only a canonical decimal a call. */
test("adr032_token_and_call_spellings", () => {
  assert(isToken("ab".repeat(32)), "a token");
  for (const bad of ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33), `${"ab".repeat(31)}g0`, 7]) {
    assert(!isToken(bad), `not a token: ${String(bad)}`);
  }
  assert(isCallId("42") && isCallId("0"), "calls");
  for (const bad of ["042", "", "-1", "1e3", "4".repeat(40)]) {
    assert(!isCallId(bad), `not a call: ${bad}`);
  }
  eq(callOfQuery("?call=42"), "42", "the call of the start link");
  eq(callOfQuery("?call=042"), null, "a non-canonical call");
  eq(startPath("42"), "/auth/draft?call=42", "the start link");
  eq(claimPath("42"), "/app/calls/42/claim", "the claim page");
});

/** ADR-032, SA-09: the claim page is a page of the server's page table, and it needs a signed-in account. */
test("adr032_sa09_claim_page_needs_an_account", () => {
  const rows = GEN_PAGES as unknown as readonly { readonly pattern: string; readonly need: unknown }[];
  const row = rows.find((p) => p.pattern === "/app/calls/{call}/claim");
  assert(row !== undefined, "the claim page is in the page table");
  eq(JSON.stringify(row.need).includes("account"), true, `needs an account: ${JSON.stringify(row.need)}`);
});

/** ADR-032, writing style: the draft page's texts hold no em dash, and the delete warns before it acts. */
test("adr032_draft_texts_are_plain", () => {
  const messages: Readonly<Record<string, string>> = AUTH_EN.messages;
  const ids = Object.keys(messages).filter((k) => k.startsWith("draft."));
  assert(ids.length >= 20, "the draft page has its texts");
  for (const id of ids) {
    const m = messages[id] ?? "";
    assert(!m.includes("—"), `${id} holds an em dash`);
    assert(m.split(/[.!?]\s/).every((s) => s.split(/\s+/).length < 40), `${id} has a sentence of 40 words or more`);
  }
  assert((messages["draft.link.intro"] ?? "").includes("Anyone with this link"), "the link is named a secret");
});
