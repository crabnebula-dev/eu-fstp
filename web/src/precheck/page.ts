// The applicant's pre-check page, `/app/proposals/{proposal}/precheck`
// (M7 design section 4; R-LA-06, R-LA-08, I-21, TH-02, TH-29).
//
// - The page says that an AI system reads the draft (R-LA-08), and a
//   synthetic demo run says so too.
// - "Check my draft now" runs `proposal.precheck` on the draft as last
//   saved. The reply holds findings and the remaining P-23 checks, never
//   a score, a band or a confidence (TH-02). Its decoder is closed, so a
//   reply with such a member is refused rather than shown.
// - The remaining checks are per day and per call on this proposal, and
//   per account across the person's drafts in the call (TH-29). With none
//   left, the button is disabled and the next instant is shown.
// - Only the team of a draft reaches this page's reads (I-21).
//
// Statements and quotes are untrusted data, shown as text nodes only.

import { h, type Child } from "../core/dom.js";
import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { call } from "../applicant/client.js";
import { loadProposal } from "../applicant/load.js";
import { draftEditable, teamReadsOffered } from "../applicant/rules.js";
import { APP, button, clearAlert, frame, run, setStatus, showFailure, statusRegion, type Frame } from "../applicant/ui.js";
import { FINDINGS_LABELS } from "../findings/messages.en.js";
import { canRun, decodePrecheckView, instantText, type PrecheckRun, type PrecheckView } from "../findings/model.js";

let catalogue: I18n | null = null;

/** The labels of the pre-check page. */
export function precheckI18n(): I18n {
  catalogue ??= createI18n({ catalogues: [{ locale: "en", labels: FINDINGS_LABELS, approved: {} }], locale: "en" });
  return catalogue;
}

function l(id: string, args?: Readonly<Record<string, string>>): Label {
  return precheckI18n().label(id, args);
}

/** The path of the pre-check page of `proposal`. */
export function precheckPath(proposal: string): string {
  return `/app/proposals/${proposal}/precheck`;
}

/** The "Check my draft" link of the draft page, with what it does. */
export function precheckLink(proposal: string): HTMLElement {
  return h("section", { id: "precheck-link", "aria-label": l("pre.link") }, [
    h("p", {}, [h("a", { href: precheckPath(proposal), id: "precheck-open" }, [l("pre.link")])]),
    h("p", { class: "fstp-hint" }, [l("pre.link_hint")]),
  ]);
}

/** The AI disclosure of the page (R-LA-08). */
function disclosure(assessor: PrecheckView["assessor"] | null): HTMLElement {
  const parts: Child[] = [l("ai.disclosure")];
  if (assessor !== null) {
    parts.push(" ", l(assessor === "synthetic" ? "ai.synthetic" : "ai.model"));
  }
  return h("p", { id: "precheck-disclosure", class: "fstp-hint ai-disclosure", "data-assessor": assessor ?? "unknown" }, parts);
}

/** The remaining checks, the only numbers the page shows. */
function remaining(v: PrecheckView): HTMLElement[] {
  const out = [
    h("p", { id: "precheck-remaining" }, [
      l("pre.remaining", {
        today: String(v.remaining.proposalToday),
        call: String(v.remaining.proposalCall),
        account: String(v.remaining.accountCall),
      }),
    ]),
  ];
  if (!canRun(v)) {
    const parts: Child[] = [l("pre.limit")];
    if (v.remaining.next !== null) {
      parts.push(" ", l("pre.next", { at: instantText(v.remaining.next) }));
    }
    out.push(h("p", { id: "precheck-limit" }, parts));
  }
  return out;
}

function runSection(r: PrecheckRun, first: boolean): HTMLElement {
  const body: Child[] = [h("h3", {}, [l("pre.run_heading", { at: instantText(r.requested) })])];
  if (r.state !== "done") {
    body.push(h("p", { class: "precheck-state" }, [l(`pre.state.${r.state}`)]));
  } else if (r.findings.length === 0) {
    body.push(h("p", {}, [l("pre.no_findings")]));
  } else {
    body.push(
      h(
        "ul",
        { class: "precheck-findings" },
        r.findings.map((f) =>
          h("li", { class: "precheck-finding", "data-kind": f.kind, "data-severity": f.severity }, [
            h("p", {}, [
              h("strong", {}, [l(`kind.${f.kind}`), ", ", l(`severity.${f.severity}`)]),
              ...(f.criterion === null ? [] : [" (", l("pre.criterion", { id: f.criterion }), ")"]),
            ]),
            h("p", { class: "finding-statement" }, [f.statement]),
            ...f.evidence
              .filter((e) => e.quote.trim() !== "")
              .map((e) =>
                h("blockquote", {}, [
                  h("p", {}, [l("pre.evidence", { section: l(`pre.section.${e.section}`) })]),
                  h("p", {}, [e.quote]),
                ]),
              ),
          ]),
        ),
      ),
    );
  }
  return h("section", { class: "precheck-run", "data-run": r.run, "data-state": r.state, ...(first ? { id: "precheck-latest" } : {}) }, body);
}

function render(f: Frame, id: string, slot: HTMLElement, v: PrecheckView, status: HTMLElement): void {
  const runBtn = button("precheck-run", l("pre.run"));
  runBtn.disabled = !canRun(v);
  runBtn.addEventListener("click", () => {
    runBtn.disabled = true;
    clearAlert(f);
    setStatus(status, "saving", l("pre.running"));
    void (async () => {
      const r = await call("proposal.precheck", { proposal: id }, {}, decodePrecheckView);
      if (!r.ok) {
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        const again = await call("proposal.precheck_runs", { proposal: id }, undefined, decodePrecheckView);
        if (again.ok) {
          render(f, id, slot, again.value, status);
        } else {
          runBtn.disabled = false;
        }
        return;
      }
      setStatus(status, "saved", l("pre.done"));
      render(f, id, slot, r.value, status);
    })();
  });
  slot.replaceChildren(
    disclosure(v.assessor),
    h("p", {}, [l("pre.intro")]),
    ...remaining(v),
    h("p", {}, [runBtn]),
    h("h2", {}, [l("pre.runs")]),
    ...(v.runs.length === 0 ? [h("p", { id: "precheck-none" }, [l("pre.none")])] : v.runs.map((r, i) => runSection(r, i === 0))),
  );
}

/** Mounts the pre-check page of draft `id`. */
export function mountPrecheck(id: string): void {
  const f = frame(l("pre.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.workspace(id) }, [l("pre.back")])]));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!teamReadsOffered(p.role) || !draftEditable(p.state)) {
      f.main.append(h("p", {}, [l("pre.team_only")]));
      return;
    }
    const v = await call("proposal.precheck_runs", { proposal: id }, undefined, decodePrecheckView);
    if (!v.ok) {
      f.main.append(disclosure(null));
      showFailure(f, v.failure);
      return;
    }
    const status = statusRegion("precheck-status");
    const slot = h("div", { id: "precheck" });
    f.main.append(status, slot);
    render(f, id, slot, v.value, status);
  });
}
