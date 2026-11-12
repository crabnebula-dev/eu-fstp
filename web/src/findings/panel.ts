// The assessment panels of the Judging pages (M7 design section 7;
// R-LA-03, R-LA-08, I-10).
//
// - The reviewer's findings panel, `#findings`, on the assignment page:
//   each finding's kind, severity and statement, and "Agree" and
//   "Dispute" buttons (`review.mark_finding`). A mark feeds calibration
//   and never changes the proposal (I-10). No confidence and no score is
//   shown.
// - The coordinator's assessment status, `#findings-status`, on the call
//   board: per proposal "Findings pending" or a count, never a statement.
// - Both carry the AI disclosure, and a synthetic demo run says so.
//
// Statements are untrusted data and reach the page as text nodes only.

import { h, type Child } from "../core/dom.js";
import type { I18n, Label } from "../core/i18n.js";
import { buttonEl, callOp, guarded, pageI18n, whileBusy, writeOp, type Frame, type PageEnv } from "../reviewer/kit.js";
import { readMyRoles } from "../home/model.js";
import { FINDINGS_LABELS } from "./messages.en.js";
import {
  decodeFindingsStatus,
  decodeReviewFindings,
  type Assessor,
  type FindingsStatus,
  type ReviewFinding,
} from "./model.js";

/** The labels of the panels, under the page's terminology. */
export function findingsI18n(env: PageEnv): I18n {
  return pageI18n(env, FINDINGS_LABELS);
}

/** The AI disclosure (R-LA-08), and the demo note for a synthetic run. */
export function disclosure(t: I18n, assessor: Assessor | null): HTMLElement {
  const parts: Child[] = [t.label("ai.disclosure")];
  if (assessor !== null) {
    parts.push(" ", t.label(assessor === "synthetic" ? "ai.synthetic" : "ai.model"));
  }
  return h("p", { class: "fstp-hint ai-disclosure", "data-assessor": assessor ?? "unknown" }, parts);
}

function markText(t: I18n, m: ReviewFinding["mark"]): Label {
  return t.label(m === null ? "rev.findings.mark.none" : `rev.findings.mark.${m}`);
}

/**
 * The reviewer's findings panel for `assignment`. It reads
 * `review.findings` itself and re-reads after each mark.
 */
export async function findingsSection(env: PageEnv, f: Frame, assignment: string): Promise<HTMLElement> {
  const t = findingsI18n(env);
  const section = h("section", { id: "findings", "aria-labelledby": "findings-heading" });
  const render = async (): Promise<void> => {
    const answer = await callOp(env, "review.findings", { assignment }, undefined, (v): v is unknown =>
      decodeReviewFindings(v) !== null,
    );
    const rows = answer.ok ? decodeReviewFindings(answer.data) : null;
    const children: Child[] = [h("h2", { id: "findings-heading" }, [t.label("rev.findings.heading")])];
    if (rows === null) {
      children.push(disclosure(t, null), h("p", { id: "findings-unavailable" }, [t.label("rev.findings.unavailable")]));
      section.replaceChildren(...children);
      return;
    }
    children.push(disclosure(t, rows[0]?.assessor ?? null));
    if (rows.length === 0) {
      children.push(h("p", { id: "findings-none" }, [t.label("rev.findings.none")]));
      section.replaceChildren(...children);
      return;
    }
    children.push(h("p", {}, [t.label("rev.findings.lead")]));
    const items = rows.map((r, i) => {
      const n = String(i + 1);
      const agree = buttonEl(`finding-agree-${r.finding}`, "button", t.label("rev.findings.agree"));
      const dispute = buttonEl(`finding-dispute-${r.finding}`, "button", t.label("rev.findings.dispute"));
      agree.setAttribute("aria-label", t.label("rev.findings.agree_named", { n }));
      dispute.setAttribute("aria-label", t.label("rev.findings.dispute_named", { n }));
      agree.setAttribute("aria-pressed", r.mark === "Agreed" ? "true" : "false");
      dispute.setAttribute("aria-pressed", r.mark === "Disputed" ? "true" : "false");
      const mark = (m: "Agreed" | "Disputed", b: HTMLButtonElement): void => {
        b.addEventListener("click", () => {
          void guarded(f, () =>
            whileBusy(b, async () => {
              f.clearAlert();
              const done = await writeOp(env, "review.mark_finding", { finding: r.finding }, { mark: m });
              if (!done.ok) {
                f.problem(done.problem);
                return;
              }
              f.status(t.label("rev.findings.marked"));
              await render();
            }),
          );
        });
      };
      mark("Agreed", agree);
      mark("Disputed", dispute);
      return h(
        "li",
        {
          class: "finding",
          "data-finding": r.finding,
          "data-kind": r.kind,
          "data-severity": r.severity,
          "data-mark": r.mark ?? "none",
        },
        [
          h("h3", {}, [
            t.label("rev.findings.item", { n }),
            ": ",
            t.label(`kind.${r.kind}`),
            ", ",
            t.label(`severity.${r.severity}`),
          ]),
          h("p", { class: "finding-statement" }, [r.statement]),
          h("p", { class: "finding-mark" }, [markText(t, r.mark)]),
          h("p", {}, [agree, " ", dispute]),
        ],
      );
    });
    children.push(h("ol", { id: "findings-list" }, items));
    section.replaceChildren(...children);
  };
  await render();
  return section;
}

function statusText(t: I18n, s: FindingsStatus): Label {
  if (s.status === "pending") {
    return t.label("coord.findings.pending");
  }
  return s.findings === 1
    ? t.label("coord.findings.count_one")
    : t.label("coord.findings.count_other", { count: String(s.findings) });
}

/**
 * The coordinator's assessment status of `call`: per submitted proposal,
 * "Findings pending" or a count. Never a statement (I-10).
 */
export async function findingsStatusSection(env: PageEnv, call: string): Promise<HTMLElement | null> {
  // The read is the coordinator's alone (M7 design section 7). Other
  // readers of the call board, such as the programme manager, would only
  // be refused, so the section is left out for them.
  const me = await callOp(env, "me.roles", {}, undefined, (v): v is unknown => readMyRoles(v) !== null);
  const roles = me.ok ? readMyRoles(me.data) : null;
  const coordinates =
    roles !== null &&
    roles.roles.some((b) => b.role === "fstp_coordinator" && b.proposal === null && b.calls.includes(call));
  if (!coordinates) {
    return null;
  }
  const t = findingsI18n(env);
  const answer = await callOp(env, "assess.findings_status", { call }, undefined, (v): v is unknown =>
    decodeFindingsStatus(v) !== null,
  );
  const rows = answer.ok ? decodeFindingsStatus(answer.data) : null;
  const children: Child[] = [
    h("h2", { id: "findings-status-heading" }, [t.label("coord.findings.heading")]),
    disclosure(t, null),
    h("p", {}, [t.label("coord.findings.lead")]),
  ];
  if (rows === null) {
    children.push(h("p", {}, [t.label("coord.findings.unavailable")]));
  } else if (rows.length === 0) {
    children.push(h("p", {}, [t.label("coord.findings.none")]));
  } else {
    children.push(
      h("table", { id: "findings-status-table" }, [
        h("caption", {}, [t.label("coord.findings.caption")]),
        h("thead", {}, [
          h("tr", {}, [
            h("th", { scope: "col" }, [t.label("coord.findings.col_proposal")]),
            h("th", { scope: "col" }, [t.label("coord.findings.col_status")]),
          ]),
        ]),
        h(
          "tbody",
          {},
          rows.map((r) =>
            h("tr", { "data-findings-proposal": r.proposal, "data-findings-status": r.status }, [
              h("th", { scope: "row" }, [t.label("coord.findings.proposal", { id: r.proposal })]),
              h("td", {}, [statusText(t, r)]),
            ]),
          ),
        ),
      ]),
    );
  }
  return h("section", { id: "findings-status", "aria-labelledby": "findings-status-heading" }, children);
}
