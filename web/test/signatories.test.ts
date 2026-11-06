// The onboarding readers of the signatory roles and the organisation's
// activation (SA-01, SA-02; `SPEC/02-domain/roles-and-sod.md` NOTE 5,
// SoD-14, SoD-15 and SoD-18). Every value here is synthetic.

import { SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { ROLE_NAMES } from "../src/home/model.js";
import { CATALOGUE } from "../src/onboarding/messages.en.js";
import {
  CHANNELS_VALUES,
  MCP_ROLES,
  SIGNATORY_ROLES,
  missingSignatories,
  readActivation,
  readSignatories,
  type SignatoryRow,
} from "../src/onboarding/model.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { type Rng } from "./support/rng.js";

/** NOTE 5: the signatory roles are roles of the wire and of P-74, with a label on the onboarding pages. */
test("r_tn_01_note5_signatory_roles_are_wire_roles_with_labels", () => {
  for (const r of SIGNATORY_ROLES) {
    assert((ROLE_NAMES as readonly string[]).includes(r), `${r} is not a me.roles role name`);
    assert((MCP_ROLES as readonly string[]).includes(r), `${r} is not a P-74 role`);
    const label = CATALOGUE.labels[`onboarding.signatory.role.${r}`];
    assert(typeof label === "string" && label !== "", `${r} has no label`);
  }
  for (const rule of ["SoD-07", "SoD-14", "SoD-15", "SoD-17", "SoD-18"]) {
    const label = CATALOGUE.labels[`onboarding.refusal.${rule}`];
    assert(typeof label === "string" && label !== "", `${rule} has no plain explanation`);
  }
});

/** NOTE 5, SoD-16: the signatory list reads each row with its account, role and handle, one account in both roles. */
test("r_tn_01_note5_sod16_signatory_list_reads_each_row", () => {
  const body = {
    signatories: [
      { account: "2817", role: "financial_signatory", handle: "synthetic-s1" },
      { account: "2817", role: "legal_signatory", handle: "synthetic-s1" },
    ],
  };
  const check = VALIDATORS["tenant.list_signatories"];
  assert(check !== undefined && SCHEMAS["tenant.list_signatories"] !== undefined, "gen/api.ts holds tenant.list_signatories");
  assert(check(body), "the sample fits its generated validator");
  const rows = readSignatories(body);
  eq(rows?.length, 2, "two rows");
  eq(missingSignatories(rows ?? []), [], "SoD-16: one account holds both roles");
  for (const bad of [
    { signatories: [{ account: "2817", role: "contract_signatory", handle: "x" }] },
    { signatories: [{ account: "02x", role: "legal_signatory", handle: "x" }] },
    { signatories: [{ account: "2817", role: "legal_signatory" }] },
    { rows: [] },
  ]) {
    eq(readSignatories(bad), null, `refused ${show(bad)}`);
  }
});

/** One synthetic signatory row. */
function row(r: Rng): SignatoryRow {
  return { account: String(r.between(1, 9)), role: r.pick(SIGNATORY_ROLES), handle: "synthetic" };
}

/** SoD-14, SoD-15: the missing roles are exactly those with no holder, Financial first. */
test("r_tn_01_sod14_sod15_missing_roles_are_those_with_no_holder", () => {
  forAll(
    (r) => Array.from({ length: r.between(0, 4) }, () => row(r)),
    (rows) => {
      const want = SIGNATORY_ROLES.filter((role) => !rows.some((x) => x.role === role));
      eq(missingSignatories(rows), want, `rows ${show(rows)}`);
    },
  );
});

/** A synthetic activation body: any state with any member set or null. */
function activation(r: Rng): Record<string, unknown> {
  const id = (): string | null => (r.bool() ? String(r.between(1, 99)) : null);
  return {
    state: r.pick(["not_requested", "requested", "active", "unknown"]),
    request: id(),
    requested_by: id(),
    approved_by: id(),
  };
}

/** SoD-18: the activation read takes a request and a requester from `requested` on, and an approver only once `active`. */
test("r_tn_01_sod18_activation_read_fits_its_state", () => {
  forAll(activation, (v) => {
    const has = (k: string): boolean => v[k] !== null;
    const fits =
      (v["state"] === "not_requested" && !has("request") && !has("requested_by") && !has("approved_by")) ||
      (v["state"] === "requested" && has("request") && has("requested_by") && !has("approved_by")) ||
      (v["state"] === "active" && has("request") && has("requested_by") && has("approved_by"));
    const got = readActivation(v);
    eq(got !== null, fits, `body ${show(v)}`);
    if (got !== null) {
      eq(got.state, v["state"], "state");
      eq(got.requestedBy, v["requested_by"], "requester");
      eq(got.approvedBy, v["approved_by"], "approver");
      const check = VALIDATORS["tenant.get_activation"];
      assert(check !== undefined && check(v), `the generated validator refuses ${show(v)}`);
    }
  });
});

/**
 * P-32, B-03, B-05 (design section 15.0, "Roles lane questions",
 * 2026-11-06): the Channels step sends no Matrix or WhatsApp value. The
 * save carries no homeserver and no WhatsApp account, the only form the
 * tenant codec takes for "none", and the page names both channels as
 * coming later from the catalogue.
 */
test("r_tn_01_p32_channels_step_sends_no_matrix_or_whatsapp_value", () => {
  eq({ ...CHANNELS_VALUES }, { matrix_homeserver: null, whatsapp: false }, "no channel value");
  eq(Object.keys(CHANNELS_VALUES).sort(), ["matrix_homeserver", "whatsapp"], "the codec members only");
  assert(Object.isFrozen(CHANNELS_VALUES), "the values cannot change");
  for (const k of ["later_title", "matrix", "whatsapp", "coming_later"]) {
    const label = CATALOGUE.labels[`onboarding.channels.${k}`];
    assert(typeof label === "string" && label !== "", `onboarding.channels.${k} is in the catalogue`);
  }
  assert(/later/i.test(CATALOGUE.labels["onboarding.channels.coming_later"] ?? ""), "the note says coming later");
});
