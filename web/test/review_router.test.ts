// Review regressions for router.ts (lane W1c review, fix round 1). Each
// test failed against the code before the fix and passes after it.
//
// The HTTP router decision of 2026-10-25 (HANDOFF.md) gives 400 to a path
// whose decoded segment still holds a percent-encoded triple, or holds a
// control character. `fstp_http::router::is_safe_segment` applies
// `char::is_control`, which covers C0, DEL and C1. router.ts says it
// decodes under that decision, so it must refuse the same paths.

import { TABLE } from "../fuzz/router_match.fuzz.js";
import { eq, test } from "./support/harness.js";
import { core } from "./support/load.js";

/** ADR-014, HANDOFF 2026-10-25: a double-encoded segment never reaches a page. */
test("adr014_review_router_refuses_double_encoded_segment", async () => {
  const router = await core("router");
  const r = router.createRouter(TABLE);
  // `%2541` decodes once to `%41`, which still holds `%XX`. The server
  // refuses this path with 400, and the client router must not bind it.
  eq(r.match("/search/%2541"), null, "/search/%2541");
  eq(r.match("/search/%252F"), null, "/search/%252F");
});

/** ADR-014, HANDOFF 2026-10-25: a segment decoding to a C1 control never reaches a page. */
test("adr014_review_router_refuses_c1_control_segment", async () => {
  const router = await core("router");
  const r = router.createRouter(TABLE);
  // `%C2%85` decodes to U+0085 (NEL), a C1 control that the server refuses.
  eq(r.match("/search/a%C2%85b"), null, "/search/a%C2%85b");
});
