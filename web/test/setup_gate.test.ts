// The setup gate of ADR-021 as the pages see it: a refusal under the
// rule `ADR-021` is the organisation still being set up, and every page
// that meets it says so in the same plain words. Every value here is
// synthetic.

import { APPLICANT_LABELS } from "../src/applicant/messages.en.js";
import { failureText } from "../src/applicant/ui.js";
import { CALLS_LABELS } from "../src/calls/messages.en.js";
import { SETUP_NOTICE, SETUP_RULE, isSetupRefusal } from "../src/core/setup.js";
import { CATALOGUE } from "../src/creator/messages.en.js";
import { HOME_LABELS } from "../src/home/messages.en.js";
import { assert, eq, test } from "./support/harness.js";

/** ADR-021: the rule the cell names, and only a `refused` code with it, is the setup gate. */
test("adr021_setup_refusal_is_the_rule_adr_021", () => {
  eq(SETUP_RULE, "ADR-021", "the rule of fstp_access::SETUP_RULE");
  assert(isSetupRefusal("refused", "ADR-021"), "the gate's refusal");
  for (const [code, rule] of [
    ["refused", "SoD-18"],
    ["refused", null],
    ["refused", ""],
    ["unauthenticated", "ADR-021"],
    ["not_found", "ADR-021"],
  ] as const) {
    assert(!isSetupRefusal(code, rule), `${code} ${String(rule)} is not the gate`);
  }
});

/** ADR-021: the home page, the open-calls page and every refusal text say the same plain notice. */
test("adr021_every_page_shows_the_same_setup_notice", () => {
  eq(HOME_LABELS["home.setup_notice"], SETUP_NOTICE, "the home page notice");
  eq(CALLS_LABELS["calls.list.setup"], SETUP_NOTICE, "the open-calls page notice");
  eq(APPLICANT_LABELS["error.setup"], SETUP_NOTICE, "the applicant pages' refusal text");
  eq(CATALOGUE.labels["outcome.setup"], SETUP_NOTICE, "the creator pages' refusal text");
  assert(!SETUP_NOTICE.includes(SETUP_RULE), "the notice names no rule id");
  eq(
    String(failureText({ kind: "refused", code: "refused", rule: SETUP_RULE })),
    SETUP_NOTICE,
    "a refused read under ADR-021 shows the notice",
  );
});
