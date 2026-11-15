// The funder profile panel of the funder reports page (M9 finish;
// R-RP-01, I-44, I-69). The panel names the pinned profile, its version,
// file hash, outputs and visibility elements, or says that none is pinned.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { VALIDATORS } from "../src/gen/api.js";
import { mountPostGrant } from "../src/grant/routes.js";
import { decodeFunderProfile } from "../src/operations/profile.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { readMyRoles, workOf } from "../src/home/model.js";
import { fakeDocument, freshDom, FakeElement } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const g = globalThis as unknown as Record<string, unknown>;

const HE = {
  programme: "1",
  profile: {
    id: "horizon-europe",
    version: "1",
    digest: "ab".repeat(32),
    outputs: ["call_publication_record", "open_call_package", "periodic_reporting_data", "audit_file", "deliverable_draft"],
    visibility_elements: ["acknowledgement", "emblem"],
  },
  // 2026-01-01 to 2027-06-30, report due by 2027-08-31 (UTC microseconds).
  reporting_periods: [{ period: "1", start: "1767225600000000", end: "1814400000000000", deadline: "1819756800000000" }],
};

/** R-RP-01: the generated validator and the decoder accept the cell's reply, and refuse other shapes. */
test("r_rp_01_funder_profile_view_validates_and_decodes", () => {
  const check = VALIDATORS["programme.funder_profile.view"];
  assert(check?.(HE) === true, "the generated validator accepts the view");
  assert(check?.({ programme: "1", profile: null, reporting_periods: [] }) === true, "and the view of no pinned profile");
  eq(decodeFunderProfile(HE)?.profile?.visibility, ["acknowledgement", "emblem"], "the keys");
  eq(decodeFunderProfile({ programme: "1", profile: null, reporting_periods: [] })?.profile, null, "no profile");
  assert(decodeFunderProfile({ ...HE, profile: { ...HE.profile, outputs: ["portal_upload"] } }) === null, "an unknown output is refused");
  assert(decodeFunderProfile({ ...HE, profile: { ...HE.profile, digest: "AB" } }) === null, "a malformed digest is refused");
});

function env(replies: Readonly<Record<string, unknown>>): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, _body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      const r = replies[`${op.method} ${path}`];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "R-AC-01" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

function prepare(path: string): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
  g["location"] = { protocol: "http:", hostname: "cell.localhost", port: "8650", pathname: path };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

/** R-RP-01, I-69: the reports page shows the pinned profile and its visibility elements. */
test("r_rp_01_reports_page_shows_the_pinned_funder_profile", async () => {
  prepare("/app/programmes/1/reports");
  await mountPostGrant(env({ "GET /programmes/1/reports": [], "GET /programmes/1/funder-profile": HE }), "/app/programmes/1/reports");
  await settle();
  const text = fakeDocument.body.textContent ?? "";
  assert(text.includes("funder profile horizon-europe, version 1"), text.slice(0, 900));
  assert(text.includes("acknowledgement, emblem"), "the visibility elements");
  const kinds = fakeDocument.body.descendants().filter((e) => e.getAttribute("data-kind") !== null);
  eq(kinds.length, 5, "the five outputs");
});

/** R-RP-01: a programme with no shipped profile says so, and a refused read leaves one line. */
test("r_rp_01_reports_page_says_when_no_profile_is_pinned", async () => {
  prepare("/app/programmes/1/reports");
  await mountPostGrant(env({ "GET /programmes/1/reports": [], "GET /programmes/1/funder-profile": { programme: "1", profile: null, reporting_periods: [] } }), "/app/programmes/1/reports");
  await settle();
  assert(fakeDocument.getElementById("ops-profile-none") !== null, "the no-profile line");
  prepare("/app/programmes/1/reports");
  await mountPostGrant(env({ "GET /programmes/1/reports": [] }), "/app/programmes/1/reports");
  await settle();
  assert(fakeDocument.getElementById("ops-profile-unread") !== null, "the unread line");
  assert(fakeDocument.getElementById("ops-reports-none") !== null, "the page still shows its reports");
});

/** R-RP-01 (Daniel, 2026-11-15 late): the read-only profile page of a programme shows the pinned profile and no action. */
test("r_rp_01_profile_page_is_read_only", async () => {
  prepare("/app/programmes/1/funder-profile");
  const mounted = await mountPostGrant(env({ "GET /programmes/1/funder-profile": HE }), "/app/programmes/1/funder-profile");
  await settle();
  assert(mounted, "the page has a route");
  assert(fakeDocument.getElementById("ops-profile-read-only") !== null, "the read-only note");
  assert(fakeDocument.getElementById("ops-profile-pinned") !== null, "the pinned profile");
  eq(fakeDocument.body.descendants().filter((e) => e.tagName === "BUTTON" || e.tagName === "FORM").length, 0, "nothing that changes it");
});

/** R-RP-01 (Daniel, 2026-11-15 late): every programme staff role, and a tenant admin, is linked to the profile page; a Receiving role is not. */
test("r_rp_01_home_links_programme_staff_to_the_funder_profile", () => {
  const staff = readMyRoles({
    tenant_admin: false,
    roles: [
      { role: "irc_member", programme: "3", calls: [] },
      { role: "applicant", programme: "4", proposal: "1001", calls: ["9"] },
    ],
    calls: [],
    rounds: [],
    drafts: [],
    signatories: [],
  });
  assert(staff !== null, "the roles decode");
  const hrefs = workOf(staff, [], (c) => c, (p) => p).items.map((i) => i.href);
  assert(hrefs.includes("/app/programmes/3/funder-profile"), hrefs.join(" "));
  assert(!hrefs.includes("/app/programmes/4/funder-profile"), "no link from a Receiving binding");
  const admin = readMyRoles({ tenant_admin: true, roles: [], calls: [], rounds: [], drafts: [], signatories: [] });
  assert(admin !== null, "the admin roles decode");
  const adminHrefs = workOf(admin, [], (c) => c, (p) => p, ["2"]).items.map((i) => i.href);
  assert(adminHrefs.includes("/app/programmes/2/funder-profile"), adminHrefs.join(" "));
});

/** P-57 (Daniel, 2026-11-15 late): the panel lists each reporting period with its last day and report deadline, and the decoder refuses a malformed period. */
test("r_rp_01_p57_profile_panel_lists_the_reporting_periods", async () => {
  eq(decodeFunderProfile(HE)?.periods.length, 1, "one period");
  assert(decodeFunderProfile({ ...HE, reporting_periods: [{ period: "1", start: "-1", end: "1", deadline: "1" }] }) === null, "a negative instant is refused");
  assert(decodeFunderProfile({ ...HE, reporting_periods: [{ period: "1", start: "1", end: "1", deadline: "1", extra: "1" }] }) === null, "an extra member is refused");
  assert(decodeFunderProfile({ programme: "1", profile: null }) === null, "the periods are required");
  prepare("/app/programmes/1/funder-profile");
  await mountPostGrant(env({ "GET /programmes/1/funder-profile": HE }), "/app/programmes/1/funder-profile");
  await settle();
  const text = fakeDocument.body.textContent ?? "";
  assert(text.includes("2027-06-30") && text.includes("2027-08-31"), text.slice(0, 900));
  assert(fakeDocument.getElementById("ops-profile-periods") !== null, "the periods table");
});
