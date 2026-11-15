// The current roles of the people admin page (J1, lane
// m4/ops-roles-agents): the `roles.list` reader and the actions offered
// on each binding. Every value here is synthetic.

import { SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { CATALOGUE } from "../src/people/messages.en.js";
import { bindingActions, readBindings, reinstateBody, type BindingRow } from "../src/people/model.js";
import { assert, eq, show, test } from "./support/harness.js";

const SAMPLE = [
  { binding: "11", account: "201", role: "fstp_coordinator", start: "5", state: "active" },
  { binding: "12", account: "225", role: "irc_member", start: "5", end: "9", state: "suspended", rule: "I-06" },
  { binding: "13", account: "301", role: "committee_member", start: "5", state: "voided", rule: "I-04" },
];

/** TH-26, I-17: the sample fits the generated `roles.list` schema, and the reader keeps each row by account id. */
test("th26_i17_people_bindings_reader_reads_each_row", () => {
  const check = VALIDATORS["roles.list"];
  assert(check !== undefined && SCHEMAS["roles.list"] !== undefined, "gen/api.ts holds roles.list");
  assert(check(SAMPLE), "the sample fits its generated validator");
  const rows = readBindings(SAMPLE);
  eq(rows?.length, 3, "three rows");
  eq(rows?.[1]?.end, "9", "a scheduled end");
  eq(rows?.[1]?.rule, "I-06", "the rule of a suspension");
  eq(rows?.[0]?.end, null, "an open end");
  for (const bad of [
    { rows: [] },
    [{ ...SAMPLE[0], account: "x2" }],
    [{ ...SAMPLE[0], state: "ended" }],
    [{ ...SAMPLE[0], start: undefined }],
    [{ ...SAMPLE[0], email: undefined, role: "Programme Manager" }],
  ]) {
    eq(readBindings(bad), null, `refused ${show(bad)}`);
  }
});

/** I-06: an active role can be ended, a suspended one reinstated or ended, and a voided one neither. */
test("i06_people_binding_actions_follow_the_state", () => {
  const rows = readBindings(SAMPLE) ?? [];
  const actions = rows.map((r: BindingRow) => bindingActions(r));
  eq(actions, [["end"], ["reinstate", "end"], []], "actions by state");
  eq(reinstateBody("  synthetic reason "), { reason: "synthetic reason" }, "a trimmed reason");
  eq(reinstateBody("   "), null, "no empty reason");
  for (const key of Object.keys(CATALOGUE.labels).filter((k) => k.startsWith("people.bindings."))) {
    const label = CATALOGUE.labels[key];
    assert(typeof label === "string" && label !== "", `${key} has text`);
  }
});
