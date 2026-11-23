// The tenant admin's erasure page (P-41, ADR-007; Daniel, 2026-11-15
// late; lane m5/retention). The page reads `admin.erasures`, lists the
// grants whose retention ended and the erasure log, and requests an
// erasure with its cause through `admin.request_erasure`.

import { ERASURE_CAUSES, ERASURE_KINDS, MAX_REASON, dayOf, decodeErasures, eraseBody, requestBody } from "../src/admin/erasures/model.js";
import { ADMIN_ERASURE_LABELS } from "../src/admin/erasures/messages.en.js";
import { ADMIN_ERASURE_PAGES } from "../src/admin/erasures/page.js";
import { OPERATIONS, PAGES, VALIDATORS } from "../src/gen/api.js";
import { MAILBOX_ROUTES } from "../src/mailbox/model.js";
import { MAILBOX_LABELS } from "../src/mailbox/messages.en.js";
import { assert, eq, test } from "./support/harness.js";

const REPLY = {
  erasures: [
    { text: "7", cause: "retention_expiry", grant: "8", requested_at: "1794700800000000", completed_at: "1794700800000000", kind: "text", destroyed_epoch: "3", authoriser: "account", reason: null },
    { text: "9", cause: "verification_completed", grant: null, requested_at: "3", completed_at: null, kind: "display_name", destroyed_epoch: null, authoriser: "account", reason: null },
  ],
  retention_ended: [{ grant: "8", programme: "4", start: "1573862400000000", end: "1794700800000000" }],
  documents: [],
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
    { erasures: [], retention_ended: [{ grant: 8, programme: "4", start: "1", end: "2" }], documents: [] },
    { erasures: [{ ...REPLY.erasures[0], cause: "other" }], retention_ended: [], documents: [] },
    { erasures: [{ ...REPLY.erasures[0], text: "07" }], retention_ended: [], documents: [] },
    // Lane L33: the kind and the destroyed epoch are closed too.
    { erasures: [{ ...REPLY.erasures[0], kind: "name" }], retention_ended: [], documents: [] },
    { erasures: [{ ...REPLY.erasures[0], destroyed_epoch: 3 }], retention_ended: [], documents: [] },
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

/** R-KY-02, I-81, ADR-007 (lane L37): a document erasure is a kind of its own, with a label, and its row decodes. */
test("adr007_l37_document_kind_has_a_label", () => {
  assert((ERASURE_KINDS as readonly string[]).includes("document"), "the document kind");
  eq(ERASURE_KINDS.length, new Set(ERASURE_KINDS).size, "each kind once");
  for (const k of ERASURE_KINDS) {
    assert(typeof ADMIN_ERASURE_LABELS[`admin.erasures.kind.${k}`] === "string", `the label of ${k}`);
  }
  const row = { ...REPLY.erasures[0], kind: "document", destroyed_epoch: "5" };
  const r = decodeErasures({ erasures: [row], retention_ended: [], documents: [] });
  eq(r?.erasures[0]?.kind, "document", "a document row decodes");
  const validate = VALIDATORS["admin.erasures"];
  assert(validate !== undefined && validate({ erasures: [row], retention_ended: [], documents: [] }), "the generated validator accepts it");
});

/**
 * F-017 (ADR-026 section "Written by the M10 fix lane"): an erased
 * workspace is a log row of its own kind, which names its grant. The page
 * labels it, the model decodes it and the generated validator accepts it.
 */
test("adr026_m10_f017_workspace_kind_has_a_label", () => {
  assert((ERASURE_KINDS as readonly string[]).includes("workspace"), "the workspace kind");
  assert(typeof ADMIN_ERASURE_LABELS["admin.erasures.kind.workspace"] === "string", "its label");
  const row = { ...REPLY.erasures[0], kind: "workspace", grant: "41", destroyed_epoch: "6" };
  const r = decodeErasures({ erasures: [row], retention_ended: [], documents: [] });
  eq(r?.erasures[0]?.kind, "workspace", "a workspace row decodes");
  const validate = VALIDATORS["admin.erasures"];
  assert(validate !== undefined && validate({ erasures: [row], retention_ended: [], documents: [] }), "the generated validator accepts it");
});

/**
 * ADR-007 (Daniel, 2026-11-23, decisions 1c and 3; lane L39): the reply
 * lists the import documents a tenant admin may erase, each row of the
 * log names whether the system or an account authorised it (never which
 * account, R-CF-03) and the reason, and the erasure body is a reason of
 * 1 to MAX_REASON characters after trimming. The operation needs no
 * step-up.
 */
test("adr007_l39_documents_and_authoriser_decode", () => {
  const doc = { document: "12", programme: "4", media: "text/markdown", erased: false };
  const row = { ...REPLY.erasures[0], kind: "document", cause: "retention_expiry", authoriser: "system", reason: null };
  const manual = { ...REPLY.erasures[0], text: "13", kind: "document", cause: "erasure_request", reason: "Synthetic reason" };
  const reply = { erasures: [row, manual], retention_ended: [], documents: [doc] };
  const r = decodeErasures(reply);
  assert(r !== null, "the reply decodes");
  eq(r?.documents[0]?.document, "12", "the document id");
  eq(r?.documents[0]?.erased, false, "not erased yet");
  eq(r?.erasures[0]?.authoriser, "system", "the system authorised it");
  eq(r?.erasures[1]?.reason, "Synthetic reason", "the stated reason");
  const validate = VALIDATORS["admin.erasures"];
  assert(validate !== undefined && validate(reply), "the generated validator accepts it");
  for (const bad of [
    { ...reply, documents: undefined },
    { ...reply, documents: [{ ...doc, erased: "no" }] },
    { ...reply, documents: [{ ...doc, document: "x" }] },
    { ...reply, erasures: [{ ...row, authoriser: "admin" }] },
    { ...reply, erasures: [{ ...row, reason: 7 }] },
  ]) {
    eq(decodeErasures(bad), null, JSON.stringify(bad));
  }
  eq(eraseBody("  Synthetic reason  "), { reason: "Synthetic reason" }, "trimmed");
  eq(eraseBody("   "), null, "a reason is required");
  eq(eraseBody("x".repeat(MAX_REASON)), { reason: "x".repeat(MAX_REASON) }, "the longest reason");
  eq(eraseBody("x".repeat(MAX_REASON + 1)), null, "too long");
  const op = OPERATIONS.find((o) => o.name === "admin.erase_document");
  eq(op?.method, "POST", "the erasure");
  eq(op?.highRisk, false, "no step-up: no invariant asks for one");
  for (const k of ["admin.erasures.documents.heading", "admin.erasures.documents.erase", "admin.erasures.documents.reason", "admin.erasures.authoriser.system", "admin.erasures.authoriser.account"]) {
    assert(typeof ADMIN_ERASURE_LABELS[k] === "string", `the label ${k}`);
  }
});
