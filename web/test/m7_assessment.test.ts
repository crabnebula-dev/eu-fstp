// The assessment panels' read models (M7 design sections 4 and 7):
// closed decoders, so no score, band or confidence reaches the
// applicant (TH-02), and no statement reaches the coordinator (I-10).
// The disclosure labels exist (R-LA-08).

import { FINDINGS_LABELS } from "../src/findings/messages.en.js";
import {
  canRun,
  decodeFindingsStatus,
  decodePrecheckView,
  decodeReviewFindings,
  instantText,
} from "../src/findings/model.js";
import { assert, eq, test } from "./support/harness.js";

function view(): Record<string, unknown> {
  return {
    assessor: "synthetic",
    remaining: { proposal_today: 1, proposal_call: 5, account_call: 5, next: null },
    runs: [
      {
        run: "3",
        requested: "1793350800000000",
        state: "done",
        findings: [
          {
            kind: "completeness",
            criterion: null,
            element: "team_experience",
            severity: "minor",
            statement: "SYNTHETIC: the team section is missing.",
            evidence: [{ section: "narrative", quote: "Problem" }],
          },
        ],
      },
    ],
  };
}

/** R-LA-06: the pre-check reply decodes with its findings and counts. */
test("r_la_06_precheck_view_decodes", () => {
  const v = decodePrecheckView(view());
  assert(v !== null, "the reply decodes");
  eq(v.assessor, "synthetic", "assessor");
  eq(v.runs.length, 1, "one run");
  eq(v.runs[0]?.findings[0]?.statement, "SYNTHETIC: the team section is missing.", "statement");
  assert(canRun(v), "a check is left");
});

/** TH-02, T-LLM-ORACLE: a score, band or confidence member at any level refuses the reply. */
test("th02_precheck_reply_with_a_score_member_is_refused", () => {
  for (const member of ["score", "band", "confidence", "weight"]) {
    const top = { ...view(), [member]: 7 };
    eq(decodePrecheckView(top), null, `top-level ${member}`);
    const v = view();
    const runs = v["runs"] as Record<string, unknown>[];
    const run = runs[0] as Record<string, unknown>;
    (run["findings"] as Record<string, unknown>[])[0] = {
      ...((run["findings"] as Record<string, unknown>[])[0] as Record<string, unknown>),
      [member]: 0.9,
    };
    eq(decodePrecheckView(v), null, `finding-level ${member}`);
  }
});

/** TH-29: with no check left, the page offers none and shows when the next one comes. */
test("th29_no_check_left_offers_none", () => {
  const v = decodePrecheckView({
    ...view(),
    remaining: { proposal_today: 0, proposal_call: 4, account_call: 4, next: "1793437200000000" },
  });
  assert(v !== null, "decodes");
  assert(!canRun(v), "no check is left");
  eq(instantText(v.remaining.next ?? "0"), "2026-10-31 09:00 UTC", "next instant");
});

/** I-10, M7 design section 7: the coordinator's status carries counts only. */
test("i10_findings_status_refuses_a_statement", () => {
  const ok = decodeFindingsStatus([{ proposal: "1001", status: "ready", findings: 9 }]);
  eq(ok?.length, 1, "decodes");
  eq(decodeFindingsStatus([{ proposal: "1001", status: "ready", findings: 9, statement: "x" }]), null, "statement refused");
});

/** R-LA-03: reviewer rows decode with their mark; the confidence is dropped, never shown. */
test("r_la_03_review_findings_decode_and_drop_confidence", () => {
  const rows = decodeReviewFindings([
    {
      finding: "50001001",
      kind: "Integrity",
      severity: "Major",
      confidence: 0,
      statement: "The text addresses an assessor or a model. It is treated as data.",
      mark: null,
      assessor: "synthetic",
    },
  ]);
  assert(rows !== null, "decodes");
  eq(rows[0]?.kind, "integrity", "kind");
  assert(!("confidence" in (rows[0] ?? {})), "no confidence member is kept");
  eq(decodeReviewFindings([{ finding: "1", kind: "Quality" }]), null, "a partial row is refused");
});

/** R-LA-08: the disclosure and the demo note exist; the pre-check promises no score. */
test("r_la_08_disclosure_labels_exist", () => {
  assert((FINDINGS_LABELS["ai.disclosure"] ?? "").includes("AI system"), "disclosure");
  assert((FINDINGS_LABELS["ai.synthetic"] ?? "").includes("Synthetic assessor (demo)"), "demo note");
  assert((FINDINGS_LABELS["pre.intro"] ?? "").includes("never a score"), "no score");
});
