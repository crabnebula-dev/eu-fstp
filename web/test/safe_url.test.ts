// `safeUrl` in dom.ts: same-origin paths and `https:` only (M4 design
// section 3.9, ADR-014 "DOM"). The grammar is the interim one in
// support/contract.ts, pending Daniel and the fstp-oauth URL subset.

import { readExpectations } from "../fuzz/harness.js";
import { installFakeDom } from "./support/fakedom.js";
import { urlish } from "./support/gen.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { core } from "./support/load.js";
import { refSafeUrl, sameOriginOrHttps } from "./reference/safe_url_ref.js";

async function safeUrl(): Promise<(input: unknown) => string | null> {
  installFakeDom();
  const d = await core("dom");
  return (input) => d.safeUrl(input);
}

/** ADR-014: same-origin paths and https: URLs of the shared corpus pass, unchanged. */
test("adr014_safe_url_accepts_same_origin_paths_and_https", async () => {
  const f = await safeUrl();
  const accepted = readExpectations("safe_url").filter((e) => e.verdict === "accept");
  assert(accepted.length > 0, "the corpus has accepted lines");
  for (const e of accepted) {
    eq(f(e.input), e.input, `line ${e.line}`);
  }
});

/**
 * ADR-014: every other scheme and shape is refused: script and data URLs
 * in any case or spacing, http:, protocol-relative and backslash paths,
 * userinfo, malformed escapes, controls and non-ASCII.
 */
test("adr014_safe_url_refuses_every_other_scheme_and_shape", async () => {
  const f = await safeUrl();
  const refused = readExpectations("safe_url").filter((e) => e.verdict === "refuse");
  for (const e of refused) {
    eq(f(e.input), null, `line ${e.line}: ${show(e.input)}`);
  }
});

/** ADR-014: a value that is not a string is refused, URL objects included. */
test("adr014_safe_url_refuses_non_strings", async () => {
  const f = await safeUrl();
  const values: readonly unknown[] = [
    null,
    undefined,
    1,
    {},
    ["/app/"],
    new URL("https://example.org/"),
    { toString: () => "/app/" },
    Object("/app/"),
  ];
  for (const v of values) {
    eq(f(v), null, `value ${show(String(v))}`);
  }
});

/** ADR-014: on strings near URLs, `safeUrl` agrees with the reference and only passes the two shapes. */
test("adr014_safe_url_agrees_with_reference_on_generated_strings", async () => {
  const f = await safeUrl();
  forAll(
    urlish,
    (s) => {
      const got = f(s);
      if (got !== null) {
        eq(got, s, "accepted input returned unchanged");
        assert(sameOriginOrHttps(got), `${show(s)} passed but is neither a same-origin path nor https:`);
      }
      eq(got !== null, refSafeUrl(s), `verdict on ${show(s)}`);
    },
    { runs: 3000 },
  );
});
