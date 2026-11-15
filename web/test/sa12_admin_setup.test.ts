// SA-12 (Daniel, 2026-11-15 night): tenant admins help set up
// programmes. A tenant admin reaches every set-up page of each programme
// that holds a creator draft from home, the pages are gated rows of the
// page table, and the Programme editor links the other set-up pages.

import { PAGES } from "../src/gen/api.js";
import { readMyRoles, workOf } from "../src/home/model.js";
import { appPatterns } from "../src/shell/routes.js";
import { STUDIO_PATHS } from "../src/studio/view.js";
import { assert, eq, test } from "./support/harness.js";

/** A tenant admin with no binding, as `me.roles` answers SA-12: every draft of the tenant. */
const ADMIN = {
  tenant_admin: true,
  roles: [],
  calls: [],
  rounds: [],
  drafts: ["3", "12"],
  signatories: [],
};

/** The set-up pages of programme `p` the home links for a tenant admin. */
function setUpPages(p: string): string[] {
  return [
    `/app/programmes/${p}/studio`,
    `/app/programmes/${p}/setup/progress`,
    `/app/programmes/${p}/setup/programme`,
    `/app/programmes/${p}/creator/review`,
    `/app/programmes/${p}/studio/knock-outs`,
    `/app/programmes/${p}/people`,
  ];
}

/** Whether `path` matches the route pattern `pattern`, an id per `{name}`. */
function matches(pattern: string, path: string): boolean {
  const a = pattern.split("/");
  const b = path.split("/");
  return a.length === b.length && a.every((s, i) => s === b[i] || (s.startsWith("{") && s.endsWith("}")));
}

/** SA-12, R-NF-03: the admin's home links each set-up page of every draft, in the tenant admin card. */
test("r_nf_03_sa12_admin_home_links_every_set_up_page_of_each_draft", () => {
  const r = readMyRoles(ADMIN);
  assert(r !== null, "the roles read");
  if (r === null) return;
  const name = (c: string): string => c;
  const w = workOf(r, [], name, name, ["3", "12", "40"]);
  for (const p of ["3", "12"]) {
    for (const href of setUpPages(p)) {
      const item = w.items.find((i) => i.href === href);
      assert(item !== undefined, `the admin's home links ${href}`);
      eq(item?.group, "tenant_admin", `${href} sits in the tenant admin card`);
    }
  }
  // A programme with no creator draft has no set-up page to open.
  assert(!w.items.some((i) => i.href === "/app/programmes/40/studio"), "no editor without a draft");
});

/** SA-12: an admin with no draft to set up gets no set-up link, and a manager's links are unchanged. */
test("r_nf_03_sa12_admin_without_drafts_gets_no_set_up_link", () => {
  const r = readMyRoles({ ...ADMIN, drafts: [] });
  assert(r !== null, "the roles read");
  if (r === null) return;
  const name = (c: string): string => c;
  const w = workOf(r, [], name, name, ["3"]);
  assert(!w.items.some((i) => i.href.endsWith("/studio")), "no editor link");
  assert(w.items.some((i) => i.href === "/app/setup/new"), "the first-time path stays");
});

/** SA-12, SA-09: every set-up page the home links is a gated row of the page table and a client route. */
test("r_nf_03_sa12_sa09_set_up_pages_are_gated_rows_and_routes", () => {
  const routes = appPatterns();
  for (const href of [...setUpPages("3"), STUDIO_PATHS.setupProgress("3"), "/app/programmes/3/creator/start"]) {
    const row = PAGES.find((r) => matches(r.pattern, href));
    assert(row !== undefined, `a page row for ${href}`);
    eq(row?.need.kind, "reads", `${href} is gated on a read`);
    assert(routes.some((p) => matches(p, href)), `a client route for ${href}`);
  }
  eq(STUDIO_PATHS.setupProgress("3"), "/app/programmes/3/setup/progress", "the editor's set-up link");
  eq(STUDIO_PATHS.knockOuts("3"), "/app/programmes/3/studio/knock-outs", "the editor's knock-out link");
});
