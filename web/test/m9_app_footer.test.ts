// The programme footer of the `/app/` shell (Daniel, 2026-11-15 late;
// I-69, M9 design section 2.4): a page inside one programme shows the
// funder visibility elements of that programme's pinned profile, and a
// tenant-wide page shows none. The wording stays the TODO(legal)
// placeholder.

import { programmeOfPath, profileElements } from "../src/shell/brand.js";
import { assert, eq, test } from "./support/harness.js";

const HE = {
  programme: "7",
  profile: { id: "horizon-europe", version: "1", digest: "ab".repeat(32), outputs: [], visibility: ["acknowledgement", "emblem"] },
  periods: [],
};

/** I-69: a programme page gets one element per visibility key of its programme's profile, with placeholder wording. */
test("i69_programme_page_footer_shows_its_profile_elements", () => {
  eq(programmeOfPath("/app/programmes/7/reports"), "7", "a programme page");
  eq(programmeOfPath("/app/programmes/7"), "7", "the programme root");
  const got = profileElements("/app/programmes/7/audit", "7", HE);
  eq(
    got.map((e) => e.key),
    ["funder_visibility.acknowledgement", "funder_visibility.emblem"],
    "the keys",
  );
  assert(got.every((e) => e.text.includes("approved wording is pending") && e.text.includes("horizon-europe")), "placeholder wording");
});

/** I-69: a tenant-wide page, a page of another programme and a programme with no profile show no element. */
test("i69_tenant_wide_page_footer_shows_no_profile_element", () => {
  for (const path of ["/app/", "/app/mailbox", "/app/admin/branding", "/app/grants/7", "/app/programmesx/7"]) {
    eq(programmeOfPath(path), null, path);
    eq(profileElements(path, "7", HE).length, 0, path);
  }
  eq(profileElements("/app/programmes/8/reports", "7", HE).length, 0, "another programme");
  eq(profileElements("/app/programmes/7/reports", "7", { ...HE, profile: null }).length, 0, "no profile pinned");
  eq(programmeOfPath("/app/programmes/07/reports"), null, "a non-canonical id");
});
