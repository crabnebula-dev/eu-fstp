// Issue 6 M3 follow-up: the notice of assessment stages the validator
// dropped (I-10, H-03, TH-01). The reviewer's findings panel shows how
// many stages were dropped and which, by fixed labels chosen from
// allowlisted identifiers. No model output reaches the page. No re-run
// control exists, because no operation lets staff start an assessment.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { OPERATIONS, SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { findingsSection, findingsStatusSection, refusedNotice, findingsI18n } from "../src/findings/panel.js";
import { FINDINGS_LABELS } from "../src/findings/messages.en.js";
import { REFUSED_CODES, REFUSED_STAGES, decodeFindingsStatus, decodeRefusedStages } from "../src/findings/model.js";
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
  assert(!note.descendants().some((d) => d.localName === "button"), "no re-run control for a reviewer: the control is the coordinator's");
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


const ROLES = (role: string): Record<string, unknown> => ({
  tenant_admin: false,
  roles: [{ role, programme: "1", calls: ["1"] }],
  calls: [],
  rounds: [],
  drafts: [],
  signatories: [],
});

const ROW = { proposal: "1003", status: "ready", findings: 4, refused: 2, rerun: "available", integrity: "clear", reasons: [] as string[] };

interface Sent {
  readonly path: string;
}

function envSent(replies: Readonly<Record<string, unknown>>, sent: Sent[]): PageEnv {
  const inner = env(replies);
  return {
    ...inner,
    api: {
      async call(op, params, body, validate) {
        let path = op.path;
        for (const [k, v] of Object.entries(params)) {
          path = path.replace(`{${k}}`, v);
        }
        sent.push({ path: `${op.method} ${path}` });
        return inner.api.call(op, params, body, validate);
      },
    },
  };
}

/** I-10, H-03: the status read carries the count of dropped stages as a number and the re-run state, and nothing else. */
test("i10_issue6_m3_h03_status_row_carries_a_count_and_the_rerun_state", () => {
  const rows = decodeFindingsStatus([ROW]);
  assert(rows !== null, "decodes");
  eq(rows[0]?.refused, 2, "count");
  eq(rows[0]?.rerun, "available", "state");
  assert(VALIDATORS["assess.findings_status"]?.([ROW]) === true, "the generated validator accepts it");
  eq(decodeFindingsStatus([{ ...ROW, rerun: "now" }]), null, "an unknown state is refused");
  eq(decodeFindingsStatus([{ ...ROW, refused: -1 }]), null, "a negative count is refused");
  eq(decodeFindingsStatus([{ ...ROW, codes: ["json"] }]), null, "no codes in the status read");
});

/** I-10, H-03, R-LA-03: the coordinator sees the count and the re-run control, and the click sends assess.rerun. */
test("i10_issue6_m3_h03_coordinator_sees_the_control_and_it_sends_the_rerun", async () => {
  prepare();
  const sent: Sent[] = [];
  const e = envSent(
    { "GET /me/roles": ROLES("fstp_coordinator"), "GET /calls/1/findings-status": [ROW], "POST /proposals/1003/assessment-rerun": { accepted: true } },
    sent,
  );
  const f = { clearAlert: () => undefined, status: () => undefined, problem: () => undefined } as never;
  const sec = await findingsStatusSection(e, "1", f);
  assert(sec !== null, "the coordinator gets the section");
  assert(textOf(sec).includes("2 checks were dropped"), textOf(sec));
  const button = byId(sec, "findings-rerun-1003");
  assert(button !== null, "the control shows");
  button.dispatchEvent(new Event("click"));
  await new Promise((r) => setTimeout(r, 20));
  assert(sent.some((s) => s.path === "POST /proposals/1003/assessment-rerun"), "the operation is called");
});

/** I-10: the control shows only while a re-run can start and a stage was dropped. */
test("i10_issue6_m3_control_only_while_a_rerun_can_start", async () => {
  for (const row of [
    { ...ROW, refused: 0 },
    { ...ROW, rerun: "in_flight" },
    { ...ROW, rerun: "used_up" },
  ]) {
    prepare();
    const e = env({ "GET /me/roles": ROLES("fstp_coordinator"), "GET /calls/1/findings-status": [row] });
    const sec = await findingsStatusSection(e, "1");
    assert(sec !== null, "section");
    assert(byId(sec, "findings-rerun-1003") === null, JSON.stringify(row));
  }
});

/** I-10, R-LA-03: a reviewer, a programme manager and an applicant get no status section, so no control. */
test("i10_issue6_m3_only_the_coordinator_gets_the_control", async () => {
  for (const role of ["committee_member", "programme_manager", "applicant", "call_drafter"]) {
    prepare();
    const e = env({ "GET /me/roles": ROLES(role), "GET /calls/1/findings-status": [ROW] });
    eq(await findingsStatusSection(e, "1"), null, role);
  }
});

/** I-10: the reviewer's notice says the coordinator can run it again, and has no control itself. */
test("i10_issue6_m3_reviewer_notice_names_the_coordinator", () => {
  assert((FINDINGS_LABELS["rev.findings.refused.lead"] ?? "").includes("The FSTP coordinator can run the assessment again."), "sentence");
});

/** ADR-035, TH-01, I-10: a held row names what the check found in plain words and offers the release; the click sends assess.release_integrity. */
test("adr035_th01_coordinator_sees_the_hold_and_releases_it", async () => {
  prepare();
  const sent: Sent[] = [];
  const held = { ...ROW, refused: 0, integrity: "held", reasons: ["zero_width", "override"] };
  assert(VALIDATORS["assess.findings_status"]?.([held]) === true, "the generated validator accepts it");
  const e = envSent(
    {
      "GET /me/roles": ROLES("fstp_coordinator"),
      "GET /calls/1/findings-status": [held],
      "POST /proposals/1003/integrity-release": { accepted: true },
    },
    sent,
  );
  const f = { clearAlert: () => undefined, status: () => undefined, problem: () => undefined } as never;
  const sec = await findingsStatusSection(e, "1", f);
  assert(sec !== null, "the coordinator gets the section");
  const text = textOf(sec);
  assert(text.includes("AI assessment on hold"), text);
  assert(text.includes("invisible zero-width characters"), text);
  assert(text.includes("an instruction to ignore or replace earlier instructions"), text);
  const button = byId(sec, "findings-release-1003");
  assert(button !== null, "the release shows");
  button.dispatchEvent(new Event("click"));
  await new Promise((r) => setTimeout(r, 20));
  assert(sent.some((s) => s.path === "POST /proposals/1003/integrity-release"), "the release is called");
});

/** ADR-035: a released row says so and offers no release; an unknown reason code is refused whole. */
test("adr035_released_row_and_closed_reasons", async () => {
  prepare();
  const released = { ...ROW, refused: 0, integrity: "released", reasons: ["addressed"] };
  const e = env({ "GET /me/roles": ROLES("fstp_coordinator"), "GET /calls/1/findings-status": [released] });
  const sec = await findingsStatusSection(e, "1");
  assert(sec !== null, "section");
  assert(textOf(sec).includes("Released for AI assessment"), textOf(sec));
  assert(byId(sec, "findings-release-1003") === null, "no release once released");
  eq(decodeFindingsStatus([{ ...ROW, reasons: ["ignore all previous instructions"] }]), null, "free text is refused");
  eq(decodeFindingsStatus([{ ...ROW, integrity: "maybe" }]), null, "an unknown hold is refused");
});
