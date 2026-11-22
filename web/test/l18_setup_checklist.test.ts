// The setup checklist of the onboarding summary (ADR-026 record of lane
// L18; R-TN-01, SoD-07, SoD-14, SoD-15, SoD-18). Every value here is
// synthetic.

import { CATALOGUE } from "../src/onboarding/messages.en.js";
import {
  CHECKLIST_ITEMS,
  ONBOARDING_STEPS,
  accountNumber,
  checklist,
  type ActivationView,
  type AdminRow,
  type SignatoryRow,
  type StepStatus,
} from "../src/onboarding/model.js";
import { assert, eq, test } from "./support/harness.js";

/** `eq` with the call site as its message. */
function same<T>(got: T, want: T): void {
  eq(got, want, "the checklist value");
}

const A1: AdminRow = { account: "41", handle: "synthetic-a1", verified: false };
const A2: AdminRow = { account: "42", handle: "synthetic-a2", verified: false };
const NONE: ActivationView = { state: "not_requested", request: null, requestedBy: null, approvedBy: null };

function steps(status: StepStatus): Record<string, StepStatus> {
  const out: Record<string, StepStatus> = {};
  for (const s of ONBOARDING_STEPS) out[s] = status;
  return out;
}

function both(): SignatoryRow[] {
  return [
    { account: "42", role: "financial_signatory", handle: "synthetic-a2" },
    { account: "42", role: "legal_signatory", handle: "synthetic-a2" },
  ];
}

/** SoD-07, R-TN-01: a sole first admin's next step is the second admin, which the web admin does. */
test("adr026_sod07_checklist_starts_with_the_second_admin", () => {
  const { rows, next } = checklist({ admins: [A1], signatories: [], statuses: steps("open"), activation: NONE });
  same(next, "second_admin");
  same(rows.map((r) => r.item), [...CHECKLIST_ITEMS]);
  assert(rows.every((r) => !r.done), "nothing is done yet");
});

/** SoD-07: once two admins exist, the next step is their verification, which the technical admin does on the host. */
test("adr026_sod07_checklist_names_the_host_for_verification", () => {
  const { rows, next } = checklist({ admins: [A1, A2], signatories: [], statuses: steps("open"), activation: NONE });
  same(next, "verified");
  same(rows.find((r) => r.item === "verified")?.actor, "host");
});

/** SoD-14, SoD-15, SoD-18: the items follow in order, and the approval is the other admin's. */
test("adr026_sod18_checklist_ends_with_the_other_admins_approval", () => {
  const verified = [
    { ...A1, verified: true },
    { ...A2, verified: true },
  ];
  same(checklist({ admins: verified, signatories: [], statuses: steps("open"), activation: NONE }).next, "signatories");
  same(checklist({ admins: verified, signatories: both(), statuses: steps("open"), activation: NONE }).next, "steps");
  same(checklist({ admins: verified, signatories: both(), statuses: steps("validated"), activation: NONE }).next, "activation_requested");
  const requested: ActivationView = { state: "requested", request: "7", requestedBy: "41", approvedBy: null };
  const r = checklist({ admins: verified, signatories: both(), statuses: steps("validated"), activation: requested });
  same(r.next, "activation_approved");
  same(r.rows.find((x) => x.item === "activation_approved")?.actor, "other_admin");
  const active: ActivationView = { state: "active", request: "7", requestedBy: "41", approvedBy: "42" };
  same(checklist({ admins: verified, signatories: both(), statuses: steps("validated"), activation: active }).next, null);
});

/** ADR-026 record of lane L18: the account number is the form `fstp-vault verify-first-admin` takes. */
test("adr026_l18_account_number_is_the_verify_first_admin_form", () => {
  same(accountNumber("1"), "00000000-0000-0000-0000-000000000001");
  same(accountNumber("340282366920938463463374607431768211455"), "ffffffff-ffff-ffff-ffff-ffffffffffff");
  same(accountNumber("340282366920938463463374607431768211456"), null);
  same(accountNumber("-1"), null);
  same(accountNumber("0x1"), null);
});

/** R-NF-04: every checklist item and next step has a plain label. */
test("r_nf_04_checklist_labels_exist", () => {
  for (const i of CHECKLIST_ITEMS) {
    for (const key of [`onboarding.checklist.item.${i}`, `onboarding.checklist.next.${i}`]) {
      const label = CATALOGUE.labels[key];
      assert(typeof label === "string" && label !== "", `${key} has no label`);
    }
  }
});
