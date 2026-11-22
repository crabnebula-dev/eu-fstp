// The tenant admin's erasure page (P-41, ADR-007; Daniel, 2026-11-15
// late; lane m5/retention). The page reads `admin.erasures`, lists the
// grants whose retention ended and the erasure log, and requests an
// erasure with its cause through `admin.request_erasure`.

import { ERASURE_CAUSES, dayOf, decodeErasures, requestBody } from "../src/admin/erasures/model.js";
import { ADMIN_ERASURE_LABELS } from "../src/admin/erasures/messages.en.js";
import { ADMIN_ERASURE_PAGES } from "../src/admin/erasures/page.js";
import { OPERATIONS, PAGES, VALIDATORS } from "../src/gen/api.js";
import { MAILBOX_ROUTES } from "../src/mailbox/model.js";
import { MAILBOX_LABELS } from "../src/mailbox/messages.en.js";
import { assert, eq, test } from "./support/harness.js";

const REPLY = {
  erasures: [
    { text: "7", cause: "retention_expiry", grant: "8", requested_at: "1794700800000000", completed_at: "1794700800000000", kind: "text", destroyed_epoch: "3" },
    { text: "9", cause: "verification_completed", grant: null, requested_at: "3", completed_at: null, kind: "display_name", destroyed_epoch: null },
  ],
  retention_ended: [{ grant: "8", programme: "4", start: "1573862400000000", end: "1794700800000000" }],
};

/** ADR-007, P-41: the reply decodes, and any other shape is refused. */
test("adr007_p41_erasures_reply_decodes_strictly", () => {
  const r = decodeErasures(REPLY);
  assert(r !== null, "the reply decodes");
  eq(r?.erasures.length, 2, "two log rows");
  eq(r?.erasures[1]?.grant, null, "a row without a grant");
  eq(r?.erasures[0]?.destroyedEpoch, "3", "I-81: the epoch that died");
  eq(r?.erasures[1]?.kind, "display_name", "ADR-007 (lane L33): a replaced display name");
  eq(r?.retentionEnded[0]?.grant, "8", "the grant whose retention ended");
  eq(dayOf("1794700800000000"), "2026-11-15", "an instant shows as its UTC day");
  for (const bad of [
    null,
    {},
    { erasures: [], retention_ended: [{ grant: 8, programme: "4", start: "1", end: "2" }] },
    { erasures: [{ ...REPLY.erasures[0], cause: "other" }], retention_ended: [] },
    { erasures: [{ ...REPLY.erasures[0], text: "07" }], retention_ended: [] },
    // Lane L33: the kind and the destroyed epoch are closed too.
    { erasures: [{ ...REPLY.erasures[0], kind: "name" }], retention_ended: [] },
    { erasures: [{ ...REPLY.erasures[0], destroyed_epoch: 3 }], retention_ended: [] },
  ]) {
    eq(decodeErasures(bad), null, JSON.stringify(bad));
  }
});

/** ADR-007 (Daniel, 2026-11-15): all four causes are offered, each with a label, and a request names a cause and a grant id. */
test("adr007_request_body_names_a_cause_and_a_grant", () => {
  eq([...ERASURE_CAUSES], ["retention_expiry", "erasure_request", "cell_erasure", "verification_completed"], "the four causes");
  for (const c of ERASURE_CAUSES) {
    assert(typeof ADMIN_ERASURE_LABELS[`admin.erasures.cause.${c}`] === "string", `the label of ${c}`);
    eq(requestBody(c, "8"), { cause: c, grant: "8" }, c);
  }
  eq(requestBody("purge", "8"), null, "an unknown cause");
  eq(requestBody("retention_expiry", ""), null, "no grant");
  eq(requestBody("retention_expiry", "x1"), null, "a grant that is no id");
});

/** P-41, SA-09, I-78: the page, its gate row, its operations and the mailbox notice that links to it. */
test("adr007_p41_erasure_page_is_gated_and_linked_from_the_mailbox", () => {
  eq(ADMIN_ERASURE_PAGES.map((p) => p.route.pattern), ["/app/admin/erasures"], "one page");
  const row = PAGES.find((p) => p.pattern === "/app/admin/erasures");
  assert(row !== undefined, "the page gate lists the page");
  const read = OPERATIONS.find((o) => o.name === "admin.erasures");
  const request = OPERATIONS.find((o) => o.name === "admin.request_erasure");
  eq(read?.method, "GET", "the read");
  eq(request?.method, "POST", "the request");
  eq(request?.highRisk, true, "the request needs a step-up");
  const validate = VALIDATORS["admin.erasures"];
  assert(validate !== undefined && validate(REPLY), "the generated validator accepts the reply");
  eq(MAILBOX_ROUTES["admin.retention_ended"], "/app/admin/erasures", "the notice links to the page");
  assert(typeof MAILBOX_LABELS["mailbox.kind.admin.retention_ended"] === "string", "the notice has a label");
});

/** ADR-007 (lane L33): every kind has a label, and a row names its kind and, once known, its destroyed key epoch. */
test("adr007_l33_erasure_kinds_have_labels", () => {
  for (const k of ["text", "display_name"]) {
    assert(typeof ADMIN_ERASURE_LABELS[`admin.erasures.kind.${k}`] === "string", `the label of ${k}`);
  }
  assert(typeof ADMIN_ERASURE_LABELS["admin.erasures.log.epoch"] === "string", "the epoch sentence");
});
