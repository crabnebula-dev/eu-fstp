// Tenant copies of funder profiles (Daniel, 2026-11-15 late; R-RP-01):
// the page's reply decoder, the copy and save bodies, and the latest
// version of each tenant profile.

import { VALIDATORS } from "../src/gen/api.js";
import { copyBody, decodeProfiles, isTenantId, latestTenant, saveBody } from "../src/admin/profiles/model.js";
import { assert, eq, test } from "./support/harness.js";

const HE = { id: "horizon-europe", version: "1", owner: "shipped", digest: "ab".repeat(32), source: null, text: "{}" };
const COPY = { id: "tenant-he", version: "1", owner: "tenant", digest: "cd".repeat(32), source: { profile: "horizon-europe", version: "1" }, text: "{\"id\":\"tenant-he\"}" };
const EDIT = { ...COPY, version: "2", source: null, digest: "ef".repeat(32) };

/** R-RP-01: the generated validator and the decoder accept the cell's reply and refuse other shapes. */
test("r_rp_01_tenant_profiles_reply_decodes_strictly", () => {
  const reply = { profiles: [HE, COPY, EDIT] };
  assert(VALIDATORS["tenant.funder_profiles"]?.(reply) === true, "the generated validator accepts the reply");
  eq(decodeProfiles(reply)?.length, 3, "three versions");
  assert(decodeProfiles({ profiles: [{ ...HE, owner: "someone" }] }) === null, "an unknown owner");
  assert(decodeProfiles({ profiles: [{ ...HE, extra: 1 }] }) === null, "an extra member");
  assert(decodeProfiles({ profiles: [{ ...COPY, source: { profile: "horizon-europe" } }] }) === null, "a partial source");
  eq(latestTenant(decodeProfiles(reply) ?? []).map((r) => `${r.id} ${r.version}`), ["tenant-he 2"], "the latest tenant version");
});

/** R-RP-01: a tenant id starts with tenant-, so it never names a shipped profile; a save sends one JSON object. */
test("r_rp_01_tenant_profile_bodies_name_a_tenant_id", () => {
  assert(isTenantId("tenant-he") && !isTenantId("horizon-europe") && !isTenantId("tenant-") && !isTenantId("tenant-HE"), "the id rule");
  eq(copyBody("tenant-he", HE as never), { id: "tenant-he", from_profile: "horizon-europe", from_version: "1" }, "the copy body");
  eq(copyBody("horizon-europe", HE as never), null, "a shipped id");
  eq(saveBody("tenant-he", "{\"outputs\":[]}"), { id: "tenant-he", profile: { outputs: [] } }, "the save body");
  eq(saveBody("tenant-he", "[1]"), null, "an array");
  eq(saveBody("tenant-he", "{"), null, "not JSON");
});
