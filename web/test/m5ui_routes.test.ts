// The routes and the links of the M5 post-grant screens (lanes L-UI1 and
// L-UI2; M5 design sections 1.2 and 6). A screen that exists but is not
// reachable by clicking from sign-in does not count (R-NF-03).

import { postGrantRouter } from "../src/grant/routes.js";
import { navOf, readMyRoles, workOf, type MyRoles } from "../src/home/model.js";
import { assert, eq, test } from "./support/harness.js";

const name = (c: string): string => `call ${c}`;
const untitled = (p: string): string => `Proposal ${p}`;

function roles(v: unknown): MyRoles {
  const r = readMyRoles(v);
  assert(r !== null, "me.roles reply");
  return r;
}

const base = { tenant_admin: false, calls: [], rounds: [], drafts: [], signatories: [] };

/** R-NF-03: every post-grant path of the design binds to one route, and a payment form is not read as a request id. */
test("r_nf_03_post_grant_routes_bind_every_screen_path", () => {
  const r = postGrantRouter();
  const cases: readonly (readonly [string, string])[] = [
    ["/app/grants", "grant.hub"],
    ["/app/grants/12", "grant.one"],
    ["/app/grants/12/contract", "contract.view"],
    ["/app/grants/12/payments", "pay.list"],
    ["/app/grants/12/payments/new", "pay.new"],
    ["/app/grants/12/payments/34", "pay.one"],
    ["/app/grants/12/payments/34/resubmit", "pay.resubmit"],
    ["/app/operations", "ops.home"],
    ["/app/programmes/5/reports", "ops.reports"],
  ];
  for (const [path, want] of cases) {
    eq(r.match(path)?.name, want, path);
  }
  eq(r.match("/app/grants/x")?.name, undefined, "a proposal id is digits");
  eq(r.match("/app/grants/12/payments/new/resubmit"), null, "no request called new");
});

/** R-NF-03: a lead reaches the grant by clicking the home page, and the grant list is in the navigation of everyone. */
test("r_nf_03_lead_reaches_the_grant_from_home_and_everyone_has_the_grants_nav", () => {
  const lead = roles({ ...base, roles: [{ role: "applicant", programme: "1", proposal: "1004", calls: ["1"] }] });
  const w = workOf(lead, [{ proposal: "1004", role: "lead", title: "Synthetic" }], name, untitled);
  const hrefs = w.items.map((i) => i.href);
  assert(hrefs.includes("/app/grants/1004"), `the grant of the lead: ${hrefs.join(" ")}`);
  assert(hrefs.includes("/app/grants"), "the grant list");
  assert(navOf(null).some((l) => l.href === "/app/grants"), "the grants link needs no roles");
  assert(!navOf(lead).some((l) => l.href === "/app/operations"), "a lead has no operations queue");
});

/** R-NF-03, SoD-04: the finance approver, payment releaser, contract signatory and programme manager reach the operations page by clicking. */
test("r_nf_03_operations_roles_reach_the_queues_from_home_and_nav", () => {
  for (const role of ["finance_approver", "payment_releaser", "contract_signatory", "programme_manager", "auditor"]) {
    const r = roles({ ...base, roles: [{ role, programme: "1", calls: ["1"] }] });
    assert(workOf(r, null, name, untitled).items.some((i) => i.href === "/app/operations"), `${role}: home`);
    assert(navOf(r).some((l) => l.href === "/app/operations"), `${role}: nav`);
  }
  const sig = roles({ ...base, roles: [], signatories: ["financial_signatory"] });
  assert(navOf(sig).some((l) => l.href === "/app/operations"), "the financial signatory approves reports");
  const reviewer = roles({ ...base, roles: [{ role: "committee_member", programme: "1", calls: ["1"] }] });
  assert(workOf(reviewer, null, name, untitled).items.some((i) => i.href === "/app/grants"), "the reviewer reaches the grants they review");
});
