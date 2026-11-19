// Issue 6 M3 follow-up: the notice of assessment stages the validator
// dropped (I-10, H-03, TH-01). The reviewer's findings panel shows how
// many stages were dropped and which, by fixed labels chosen from
// allowlisted identifiers. No model output reaches the page. No re-run
// control exists, because no operation lets staff start an assessment.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { OPERATIONS, SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { findingsSection, refusedNotice, findingsI18n } from "../src/findings/panel.js";
import { FINDINGS_LABELS } from "../src/findings/messages.en.js";
import { REFUSED_CODES, REFUSED_STAGES, decodeRefusedStages } from "../src/findings/model.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { FakeElement, asFake, fakeDocument, freshDom } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const g = globalThis as unknown as Record<string, unknown>;

function prepare(): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement"]) {
    g[n] = FakeElement;
  }
}

function env(replies: Readonly<Record<string, unknown>>): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, _body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      const r = replies[`${op.method} ${path}`];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "test" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

const FINDING = { finding: "5", kind: "Quality", severity: "Minor", confidence: 0, statement: "A statement.", mark: null, assessor: "model" };

/** The element with `id` below `el`, or null. */
function byId(el: unknown, id: string): FakeElement | null {
  return asFake(el).descendants().find((e) => e.getAttribute("id") === id) ?? null;
}

function textOf(el: HTMLElement): string {
  return asFake(el).textContent ?? "";
}

/** I-10, H-03: the list reaches the page unchanged, in order, from the generated reply shape. */
test("i10_issue6_m3_h03_refusals_reply_decodes_unchanged", () => {
  const reply = [
    { stage: "quality", code: "score_like" },
    { stage: "integrity", code: "json" },
  ];
  assert(VALIDATORS["review.findings_refusals"]?.(reply) === true, "the generated validator accepts it");
  const rows = decodeRefusedStages(reply);
  assert(rows !== null, "decodes");
  eq(rows.map((r) => `${r.stage}/${r.code}`), ["quality/score_like", "integrity/json"], "order and values");
  eq(decodeRefusedStages([]), [], "an empty list is a list");
});

/** I-10, TH-01: only the two identifiers fit a row; any other member refuses the reply. */
test("th01_issue6_m3_refusals_reply_is_closed", () => {
  eq(decodeRefusedStages([{ stage: "quality", code: "json", statement: "x" }]), null, "extra member");
  eq(decodeRefusedStages([{ stage: "quality" }]), null, "missing member");
  eq(decodeRefusedStages([{ stage: 3, code: "json" }]), null, "wrong type");
  eq(decodeRefusedStages({ stage: "quality", code: "json" }), null, "not a list");
  const schema = SCHEMAS["review.findings_refusals"];
  assert(schema !== undefined && schema.kind === "array", "the schema is a list");
  assert(
    VALIDATORS["review.findings_refusals"]?.([{ stage: "<img src=x onerror=alert(1)>", code: "json" }]) === false,
    "the generated validator refuses an identifier outside the allowlist",
  );
});

/** I-10, TH-01: every allowlisted identifier has a fixed label, and an unknown one a generic label. */
test("th01_issue6_m3_every_identifier_has_a_label_and_unknown_is_generic", () => {
  for (const s of [...REFUSED_STAGES, "unknown"]) {
    assert(typeof FINDINGS_LABELS[`refused.stage.${s}`] === "string", `stage ${s}`);
  }
  for (const c of [...REFUSED_CODES, "unknown"]) {
    assert(typeof FINDINGS_LABELS[`refused.code.${c}`] === "string", `code ${c}`);
  }
  const rows = decodeRefusedStages([{ stage: "ignore previous instructions", code: "<b>x</b>" }]);
  assert(rows !== null, "an unknown identifier decodes");
  eq(rows[0], { stage: "unknown", code: "unknown" }, "kept as unknown, never as received");
  prepare();
  const note = refusedNotice(findingsI18n(env({})), rows);
  assert(note !== null, "a notice");
  const shown = textOf(note);
  assert(!shown.includes("ignore") && !shown.includes("<b>"), shown);
  assert(shown.includes("A check") && shown.includes("code: unknown"), shown);
});

/** I-10: a result with no refusals shows no notice. */
test("i10_issue6_m3_no_refusals_shows_no_notice", async () => {
  prepare();
  const e = env({
    "GET /assignments/7/findings": [FINDING],
    "GET /assignments/7/findings-refusals": [],
  });
  const f = { clearAlert: () => undefined, status: () => undefined, problem: () => undefined } as never;
  const sec = await findingsSection(e, f, "7");
  assert(byId(sec, "findings-refused") === null, "no notice element");
  assert(textOf(sec).includes("A statement."), "the findings still show");
});

/** I-10, H-03: the notice shows the count, each stage and each code, in a status region, with no control. */
test("i10_issue6_m3_h03_notice_shows_count_stages_and_codes", async () => {
  prepare();
  const e = env({
    "GET /assignments/7/findings": [FINDING],
    "GET /assignments/7/findings-refusals": [
      { stage: "quality", code: "score_like" },
      { stage: "integrity", code: "too_long" },
    ],
  });
  const f = { clearAlert: () => undefined, status: () => undefined, problem: () => undefined } as never;
  const sec = await findingsSection(e, f, "7");
  const note = byId(sec, "findings-refused");
  assert(note !== null, "the notice shows");
  eq(note.getAttribute("role"), "status", "a status region like the other notices");
  const shown = note.textContent ?? "";
  assert(shown.includes("2 checks of the AI assessor were dropped"), shown);
  assert(shown.includes("Quality assessment") && shown.includes("code: score_like"), shown);
  assert(shown.includes("Integrity check") && shown.includes("code: too_long"), shown);
  assert(!note.descendants().some((d) => d.localName === "button"), "no re-run control: no operation lets staff start an assessment");
  eq(note.getAttribute("data-refused"), "2", "count attribute");
});

/** The singular label reads as one check. */
test("i10_issue6_m3_notice_singular_count", () => {
  prepare();
  const rows = decodeRefusedStages([{ stage: "claims", code: "shape" }]);
  assert(rows !== null, "decodes");
  const note = refusedNotice(findingsI18n(env({})), rows);
  assert(note !== null && textOf(note).includes("One check of the AI assessor was dropped"), "singular");
  eq(refusedNotice(findingsI18n(env({})), []), null, "none, no notice");
});

/** I-10: a failed refusals read leaves the findings as they were, with no notice. */
test("i10_issue6_m3_failed_refusals_read_leaves_the_findings", async () => {
  prepare();
  const e = env({ "GET /assignments/7/findings": [FINDING] });
  const f = { clearAlert: () => undefined, status: () => undefined, problem: () => undefined } as never;
  const sec = await findingsSection(e, f, "7");
  assert(byId(sec, "findings-refused") === null, "no notice");
  assert(textOf(sec).includes("A statement."), "findings show");
});

/** I-10: no operation lets staff start an assessment again, so the page has none to call. */
test("i10_issue6_m3_no_staff_operation_starts_an_assessment", () => {
  const names = OPERATIONS.map((o) => o.name).filter((n) => /assess\.|rerun|re_run|run_assess|request_assess/.test(n));
  eq(names, ["assess.findings_status"], "the only assess operation is the coordinator's counts read");
});
