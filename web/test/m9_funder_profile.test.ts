// The funder profile panel of the funder reports page (M9 finish;
// R-RP-01, I-44, I-69). The panel names the pinned profile, its version,
// file hash, outputs and visibility elements, or says that none is pinned.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { VALIDATORS } from "../src/gen/api.js";
import { mountPostGrant } from "../src/grant/routes.js";
import { decodeFunderProfile } from "../src/operations/profile.js";
import type { PageEnv } from "../src/reviewer/kit.js";
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
};

/** R-RP-01: the generated validator and the decoder accept the cell's reply, and refuse other shapes. */
test("r_rp_01_funder_profile_view_validates_and_decodes", () => {
  const check = VALIDATORS["programme.funder_profile.view"];
  assert(check?.(HE) === true, "the generated validator accepts the view");
  assert(check?.({ programme: "1", profile: null }) === true, "and the view of no pinned profile");
  eq(decodeFunderProfile(HE)?.profile?.visibility, ["acknowledgement", "emblem"], "the keys");
  eq(decodeFunderProfile({ programme: "1", profile: null })?.profile, null, "no profile");
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
  await mountPostGrant(env({ "GET /programmes/1/reports": [], "GET /programmes/1/funder-profile": { programme: "1", profile: null } }), "/app/programmes/1/reports");
  await settle();
  assert(fakeDocument.getElementById("ops-profile-none") !== null, "the no-profile line");
  prepare("/app/programmes/1/reports");
  await mountPostGrant(env({ "GET /programmes/1/reports": [] }), "/app/programmes/1/reports");
  await settle();
  assert(fakeDocument.getElementById("ops-profile-unread") !== null, "the unread line");
  assert(fakeDocument.getElementById("ops-reports-none") !== null, "the page still shows its reports");
});
