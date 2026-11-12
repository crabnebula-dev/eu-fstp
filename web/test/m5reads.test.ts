// The M5 reads follow-up on the post-grant pages (docs/handoff/m5-ui.md):
// the grant list (`grant.list_mine`), the contracts awaiting the caller's
// signature (`contract.awaiting_me`) and the milestones of
// `grant.overview`. Each page reaches its work by clicking, with no
// proposal number typed (R-NF-03). Amounts come from the cell as
// strings; the browser computes none (ADR-006).

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { mountPostGrant } from "../src/grant/routes.js";
import { decodeDetermination, decodeGrantList, decodeLineReview, decodeOverview, decodeToSign } from "../src/grant/models.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { VALIDATORS } from "../src/gen/api.js";
import { assert, test } from "./support/harness.js";
import { fakeDocument, freshDom, FakeElement } from "./support/fakedom.js";

const g = globalThis as unknown as Record<string, unknown>;

function env(replies: Readonly<Record<string, unknown>>, sent: string[]): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, _body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      sent.push(`${op.method} ${path}`);
      const r = replies[`${op.method} ${path}`];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "test" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

function text(): string {
  return fakeDocument.body.textContent ?? "";
}

function prepare(path: string): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
  g["location"] = { protocol: "http:", hostname: "cell.localhost", port: "8650", pathname: path };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

const GRANTS = [
  { proposal: "3", call: "2", state: "IN_EXECUTION", amount: "1000.00", paid: "100.00", contract: "5", via: "team" },
  { proposal: "8", call: "2", state: "NEGOTIATION", amount: null, paid: "0.00", contract: null, via: "programme_manager" },
];

const TO_SIGN = [{ proposal: "8", contract: "12", version: 1, field: "signatory", role: "signatory", state: "signed_by_grantee", digest: "ab".repeat(32) }];

const OVERVIEW = {
  proposal: "3",
  state: "IN_EXECUTION",
  determination: "4",
  amount: "1000.00",
  paid: "100.00",
  contract: "5",
  requests: 1,
  plan: "6",
  milestones: [
    { milestone: "9", amount: "600.00", due: "2027-03-01", paid: "100.00", pending: "50.00", available: "450.00", closed: false },
    { milestone: "10", amount: "400.00", due: "2027-06-01", paid: "0.00", pending: "0.00", available: "0.00", closed: true },
  ],
};

/** R-AC-01, I-86: the generated validators accept the cell's list replies and the overview with milestones. */
test("r_ac_01_generated_validators_accept_the_new_replies", () => {
  for (const [name, v] of [
    ["grant.list_mine", GRANTS],
    ["contract.awaiting_me", TO_SIGN],
    ["grant.overview", OVERVIEW],
  ] as const) {
    const check = (VALIDATORS as Readonly<Record<string, (x: unknown) => boolean>>)[name];
    assert(check !== undefined, `${name} has a validator`);
    assert(check?.(v) === true, `${name} validates`);
  }
});

/** R-AC-01: the list decoders read the rows and refuse a malformed one. */
test("r_ac_01_list_decoders_read_rows_and_refuse_bad_ones", () => {
  const list = decodeGrantList(GRANTS);
  assert(list !== null && list.length === 2 && list[0]?.via === "team", "grant list");
  assert(decodeGrantList([{ ...GRANTS[0], paid: 100 }]) === null, "a number amount is refused (ADR-006)");
  assert(decodeGrantList([{ ...GRANTS[0], via: "anyone" }]) === null, "an unknown via is refused");
  const sign = decodeToSign(TO_SIGN);
  assert(sign !== null && sign[0]?.contract === "12" && sign[0]?.role === "signatory", "signing list");
  assert(decodeToSign([{ ...TO_SIGN[0], state: "effective" }]) === null, "only sent or signed_by_grantee waits");
});

/** R-PR-07, I-58: the overview decoder keeps the cell's available, pending and closed values. */
test("r_pr_07_overview_decoder_keeps_the_cells_available_amount", () => {
  const o = decodeOverview(OVERVIEW);
  assert(o !== null && o.agreedPlan === "6", "the plan");
  const m = o?.milestones[0];
  assert(m?.available === "450.00" && m?.pending === "50.00" && m?.closed === false, JSON.stringify(m));
  assert(o?.milestones[1]?.closed === true, "closed milestone");
});

/** R-NF-03, R-AC-01: the grants page lists the caller's grants and contracts to sign as links, from the cell's lists. */
test("r_nf_03_grants_page_lists_grants_and_contracts_to_sign", async () => {
  prepare("/app/grants");
  const sent: string[] = [];
  await mountPostGrant(env({ "GET /me/grants": GRANTS, "GET /me/contracts-awaiting-signature": TO_SIGN }, sent), "/app/grants");
  await settle();
  assert(sent.includes("GET /me/grants"), sent.join(", "));
  assert(sent.includes("GET /me/contracts-awaiting-signature"), sent.join(", "));
  assert(!sent.some((s) => s.startsWith("GET /calls/")), "no call board walk is needed");
  const t = text();
  assert(t.includes("Your grants") && t.includes("Proposal 3"), t.slice(0, 400));
  assert(t.includes("Grants in your programmes") && t.includes("Proposal 8"), t.slice(0, 400));
  assert(t.includes("IN_EXECUTION"), "the formal state is shown");
  assert(t.includes("Contracts awaiting your signature"), t.slice(0, 600));
});

/** R-NF-03, P-30: the operations page lists the contracts awaiting the caller's signature and the caller's grants. */
test("r_nf_03_operations_page_lists_contracts_awaiting_signature", async () => {
  prepare("/app/operations");
  const sent: string[] = [];
  await mountPostGrant(
    env({ "GET /me/payment-queue": [], "GET /me/grants": GRANTS, "GET /me/contracts-awaiting-signature": TO_SIGN }, sent),
    "/app/operations",
  );
  await settle();
  const t = text();
  assert(sent.includes("GET /me/contracts-awaiting-signature"), sent.join(", "));
  assert(t.includes("Contract of proposal 8"), t.slice(0, 600));
  assert(t.includes("signed_by_grantee"), "the version state is shown");
  assert(t.includes("Proposal 8"), "the grant list is shown");
});

/** R-PR-07, I-58, ADR-006: "Fill available" writes the cell's available amount, and a closed milestone offers no fill. */
test("r_pr_07_payment_form_fills_the_cells_available_amount", async () => {
  prepare("/app/grants/3/payments/new");
  const sent: string[] = [];
  await mountPostGrant(env({ "GET /grants/3": OVERVIEW }, sent), "/app/grants/3/payments/new");
  await settle();
  const select = fakeDocument.getElementById("pay-milestone-1") as unknown as { value: string } | null;
  const amount = fakeDocument.getElementById("pay-amount-1") as unknown as { value: string } | null;
  const fill = fakeDocument.getElementById("pay-fill-1");
  assert(select !== null && amount !== null && fill !== null, "the form has its controls");
  if (select === null || amount === null || fill === null) {
    return;
  }
  assert(text().includes("450.00"), `the available amount is shown: ${text().slice(0, 600)}`);
  select.value = "9";
  fill.click();
  assert(amount.value === "450.00", `filled ${amount.value}`);
  amount.value = "";
  select.value = "10";
  fill.click();
  assert(amount.value === "", "a closed milestone fills nothing");
});

/** R-NG-03: the assigned reviewer, refused the overview, reaches the determination form through the determination view, with the plan filled in. */
test("r_ng_03_reviewer_reaches_the_determination_form_by_clicking", async () => {
  prepare("/app/grants/3");
  const sent: string[] = [];
  const view = { proposal: "3", state: "NEGOTIATION", determination: null, plan: "6", plan_total: "1000.00", granted: null };
  await mountPostGrant(env({ "GET /grants/3/determination": view }, sent), "/app/grants/3");
  await settle();
  assert(sent.includes("GET /grants/3"), "the overview is asked first");
  assert(sent.includes("GET /grants/3/determination"), sent.join(", "));
  const t = text();
  assert(t.includes("Determine the grant amount"), `the determination form: ${t.slice(0, 400)}`);
  assert(t.includes("1000.00") && t.includes("NEGOTIATION"), "plan total and state");
  assert(!t.includes("Payment requests"), "no payment link on the reviewer view");
  const plan = fakeDocument.getElementById("grant-determine-plan") as unknown as { value: string } | null;
  assert(plan?.value === "6", `the plan is filled: ${plan?.value ?? "none"}`);
});

/** R-NG-03: the determination view decoder refuses a number amount (ADR-006). */
test("r_ng_03_determination_decoder_refuses_number_amounts", () => {
  const ok = decodeDetermination({ proposal: "3", state: "NEGOTIATION", determination: "4", plan: "6", plan_total: "1000.00", granted: "900.00" });
  assert(ok !== null && ok.agreedPlan === "6" && ok.granted === "900.00", "decoded");
  assert(decodeDetermination({ proposal: "3", state: "NEGOTIATION", determination: null, plan: "6", plan_total: 1000, granted: null }) === null, "number refused");
});

const LINE_REVIEW = {
  request: "9",
  proposal: "3",
  status: "UNDER_REVIEW",
  kind: "milestone",
  submission_checks: true,
  acceptance_checks: false,
  lines: [
    {
      line: "11",
      milestone: "7",
      requested: "60000.00",
      approved: null,
      location: "https://forge.example/synthetic/repo",
      release: "v1.0.0",
      licence: "MIT",
      report: "SYNTHETIC DELIVERY REPORT",
    },
  ],
};

/** R-PR-08, I-86: the generated validator and the page decoder accept the line review view, evidence and all. */
test("r_pr_08_line_review_view_decodes", () => {
  const check = (VALIDATORS as Readonly<Record<string, (x: unknown) => boolean>>)["payment.line_review_view"];
  assert(check !== undefined && check(LINE_REVIEW), "the generated validator accepts the view");
  const v = decodeLineReview(LINE_REVIEW);
  assert(v !== null && v.request.lines.length === 1 && v.evidence[0]?.licence === "MIT", "decoded");
  assert(decodeLineReview({ ...LINE_REVIEW, lines: [{ ...LINE_REVIEW.lines[0], requested: 60000 }] }) === null, "ADR-006: a number amount is refused");
});

/** R-PR-08, R-AC-01: the assigned reviewer, refused the payment status, reaches the line review of the request through the line review view. */
test("r_pr_08_reviewer_reaches_the_line_review_by_clicking", async () => {
  prepare("/app/grants/3/payments/9");
  const sent: string[] = [];
  await mountPostGrant(env({ "GET /grants/3/payment-requests/9/line-review": LINE_REVIEW }, sent), "/app/grants/3/payments/9");
  await settle();
  assert(sent.includes("GET /grants/3/payment-requests"), "the payment status is asked first");
  assert(sent.includes("GET /grants/3/payment-requests/9/line-review"), sent.join(", "));
  const t = text();
  assert(t.includes("Payment request for milestone 7"), `the request label: ${t.slice(0, 400)}`);
  assert(t.includes("Reference 9"), "the muted reference");
  assert(t.includes("https://forge.example/synthetic/repo") && t.includes("MIT") && t.includes("SYNTHETIC DELIVERY REPORT"), "the evidence");
  assert(t.includes("Line review"), "the line review section");
  assert(fakeDocument.getElementById("pay-review-form-11") !== null, "the decision form of line 11");
  assert(t.includes("Back to Operations"), "the way back is Operations, not the payments list");
  assert(!/bank|iban|payee/i.test(t), "I-86: nothing about bank details");
});
