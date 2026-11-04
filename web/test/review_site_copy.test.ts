// Review reproducer (lane m4/site, independent review of 2026-11-04). It
// fails against the lane's working tree and passes once fixed.
//
// r_jv_07_review_deferred_panel_names_the_original_rules: the deferred
// panel of the applicant's proposal page (`outcome.deferred.text`) says
// the proposal "may be considered again under that call's rules", where
// "that call" is the later call. State machine NOTE 8 says the opposite:
// the original call's frozen policy keeps governing a deferred proposal,
// and `03-applicant-screens.md` (Q5) shows "Rules of {original call}".
// The copy must not tell the applicant that the later call's rules
// apply.

import { assert, test } from "./support/harness.js";
import { APPLICANT_LABELS } from "../src/applicant/messages.en.js";

/** R-JV-07, state machine NOTE 8: the deferred panel never puts the proposal under the later call's rules. */
test("r_jv_07_review_deferred_panel_names_the_original_rules", () => {
  const text = APPLICANT_LABELS["outcome.deferred.text"];
  assert(typeof text === "string", "outcome.deferred.text exists");
  assert(
    !/under that call's rules/i.test(text),
    `NOTE 8: the original call's frozen rules govern a deferred proposal, not the later call's: "${text}"`,
  );
  assert(
    /original call|call it was submitted to|same rules/i.test(text),
    `NOTE 8: the deferred panel says the original call's rules keep applying: "${text}"`,
  );
});
