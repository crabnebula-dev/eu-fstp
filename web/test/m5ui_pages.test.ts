// A smoke test of the post-grant pages over the fake DOM (R-NF-03): each
// page mounts against canned replies of the cell, renders its role's
// actions and sends the bodies that `fstp-api-core` reads. Nothing here
// replaces the browser run of `e2e/`.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { mountPostGrant } from "../src/grant/routes.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { assert, test } from "./support/harness.js";
import { fakeDocument, freshDom } from "./support/fakedom.js";
import { FakeElement } from "./support/fakedom.js";

const g = globalThis as unknown as Record<string, unknown>;

interface Sent {
  readonly path: string;
  readonly body: unknown;
}

function env(replies: Readonly<Record<string, unknown>>, sent: Sent[]): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      sent.push({ path: `${op.method} ${path}`, body });
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

function prepare(): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement"]) {
    g[n] = FakeElement;
  }
  g["location"] = { protocol: "http:", hostname: "cell.localhost", port: "8650", pathname: "/app/grants/3" };
}

const OVERVIEW = { proposal: "3", state: "NEGOTIATION", determination: null, amount: null, paid: "0.00", contract: null, requests: 0 };

/** R-NG-03: the grant page of a proposal in negotiation names its state and offers the amount determination. */
test("r_ng_03_grant_page_renders_state_and_determination_form", async () => {
  prepare();
  const sent: Sent[] = [];
  const ok = await mountPostGrant(env({ "GET /grants/3": OVERVIEW }, sent), "/app/grants/3");
  assert(ok, "the route is mounted");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("NEGOTIATION"), `the formal state is shown: ${text().slice(0, 200)}`);
  assert(text().includes("Determine the grant amount"), "the determination form is offered");
});

/** R-CT-04: the contract page of a not yet drafted contract says so, and the programme manager can draft it. */
test("r_ct_04_contract_page_says_not_drafted", async () => {
  prepare();
  const sent: Sent[] = [];
  await mountPostGrant(env({ "GET /grants/3/contract": { proposal: "3", contract: null, status: null, versions: [] } }, sent), "/app/grants/3/contract");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("The contract is not drafted yet."), text().slice(0, 300));
});

/** I-58: the payment list shows each request with its status and the checks-failed callout. */
test("i58_payment_list_shows_status_and_the_checks_failed_callout", async () => {
  prepare();
  const sent: Sent[] = [];
  const row = { request: "7", proposal: "3", status: "CHECKS_FAILED", kind: "milestone", submission_checks: false, acceptance_checks: false, lines: [{ line: "8", milestone: "9", requested: "100.00", approved: null }] };
  await mountPostGrant(env({ "GET /grants/3/payment-requests": [row] }, sent), "/app/grants/3/payments");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("Checks failed"), "the plain status is shown");
  assert(text().includes("CHECKS_FAILED"), "the formal state is beside it (I-96)");
  assert(text().includes("Resubmitting creates a new request reference"), "the callout");
});

/** SoD-04: the operations page lists the release queue with a link to each request and states the separation. */
test("r_nf_03_operations_page_lists_the_queue", async () => {
  prepare();
  const sent: Sent[] = [];
  const request = { request: "7", proposal: "3", status: "PAYMENT_APPROVED", kind: "milestone", submission_checks: true, acceptance_checks: true, lines: [] };
  await mountPostGrant(env({ "GET /me/payment-queue": [{ task: "release", request }] }, sent), "/app/operations");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("To release"), text().slice(0, 300));
  assert(text().includes("SoD-04"), "the separation is stated");
});

/** I-30 and P-30: a sent contract with an unsigned party of the caller offers the signature routes and the decline. */
test("i30_contract_page_offers_signing_and_decline_before_a_signature", async () => {
  prepare();
  const sent: Sent[] = [];
  const view = {
    proposal: "3",
    contract: "5",
    status: "sent",
    versions: [{ version: 1, state: "sent", parties: [{ field: "lead", role: "lead", signed: false, mine: true }, { field: "signatory", role: "signatory", signed: false, mine: false }], revisions: 1, digest: "00".repeat(32), open_changes: [] }],
  };
  await mountPostGrant(env({ "GET /grants/3/contract": view }, sent), "/app/grants/3/contract");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("Sign the contract"), "signing is offered");
  assert(text().includes("Decline the contract"), "decline is offered before any signature (R-NG-04)");
  assert(text().includes("A signed version never changes"), "immutability is stated");
});

/** I-32 and SoD-12: a request under review shows the line review form for the reviewer. */
test("i32_payment_request_page_shows_line_review", async () => {
  prepare();
  const sent: Sent[] = [];
  const row = { request: "7", proposal: "3", status: "UNDER_REVIEW", kind: "milestone", submission_checks: true, acceptance_checks: true, lines: [{ line: "8", milestone: "9", requested: "100.00", approved: null }] };
  await mountPostGrant(env({ "GET /grants/3/payment-requests": [row] }, sent), "/app/grants/3/payments/7");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("Line review"), text().slice(0, 300));
  assert(text().includes("Approver and releaser are different people"), "SoD-04 is stated");
});

/** R-RP-03: a report the caller generated cannot be approved by the caller. */
test("r_rp_03_report_page_holds_back_approval_of_own_report", async () => {
  prepare();
  const sent: Sent[] = [];
  const mk = (report: string, mine: boolean): unknown => ({ report, kind: "audit_file", call: "2", programme: null, document: "00".repeat(32), template: "horizon-europe/audit_file/1", generated_by_me: mine, approved: false });
  await mountPostGrant(env({ "GET /programmes/5/reports": [mk("11", true), mk("12", false)] }, sent), "/app/programmes/5/reports");
  await new Promise((r) => setTimeout(r, 20));
  assert(text().includes("Approve report 12"), "the other person's report can be approved");
  assert(!text().includes("Approve report 11"), "an own report cannot");
  assert(text().includes("you cannot approve it"), "the reason is shown");
});

/** R-NF-03, I-96: a payment request reads as an ordinal and a milestone, never as its 64-bit reference, and the chip shows one label. */
test("r_nf_03_payment_labels_are_human_and_the_chip_is_not_doubled", async () => {
  prepare();
  const sent: Sent[] = [];
  const id = "5563071439709405207";
  const row = { request: id, proposal: "1001", status: "UNDER_REVIEW", kind: "milestone", submission_checks: true, acceptance_checks: true, lines: [{ line: "8", milestone: "1", requested: "100.00", approved: null }] };
  await mountPostGrant(env({ "GET /grants/1001/payment-requests": [row] }, sent), "/app/grants/1001/payments");
  await new Promise((r) => setTimeout(r, 20));
  const t = text();
  assert(t.includes("Payment request 1 for milestone 1"), t.slice(0, 400));
  assert(!t.includes(id), "the reference is not a label");
  assert(!t.includes("Open request"), "no raw id label");
  assert(t.includes("Under review (UNDER_REVIEW)"), "one visible label, the code kept as hidden text");
});

/** R-NF-03: the operations queue labels a request by its milestone and shows a contract state as a translated chip. */
test("r_nf_03_operations_labels_have_no_raw_ids_or_enums", async () => {
  prepare();
  const sent: Sent[] = [];
  const request = { request: "5563071439709405207", proposal: "1001", status: "UNDER_REVIEW", kind: "milestone", submission_checks: true, acceptance_checks: true, lines: [{ line: "8", milestone: "1", requested: "100.00", approved: null }] };
  const toSign = [{ proposal: "1001", contract: "12", version: 1, field: "signatory", role: "signatory", state: "signed_by_grantee", digest: "ab".repeat(32) }];
  await mountPostGrant(env({ "GET /me/payment-queue": [{ task: "review", request }], "GET /me/contracts-awaiting-signature": toSign }, sent), "/app/operations");
  await new Promise((r) => setTimeout(r, 20));
  const t = text();
  assert(t.includes("Payment request for milestone 1 of proposal 1001"), t.slice(0, 500));
  assert(!t.includes("Request 5563071439709405207"), "no raw id label");
  assert(t.includes("Contract of proposal 1001") && t.includes("Signed by the grantee"), t.slice(0, 600));
  assert(!t.includes("signed_by_grantee signed_by_grantee"), "no doubled enum");
});
