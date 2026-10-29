// Stage 2 (`stage2.view`, `stage2.answer`, `stage2.revise`; R-EV-05,
// TH-08, P-11).
//
// Questions show their authors' pseudonymous handles and the day they
// were asked, never a name and never a time of day. The whole team reads
// them once the proposal has reached stage 2. In STAGE2 the lead answers
// and can submit a revised plan (`planform.ts`): tasks with dated
// milestones, each amount an ADR-006 string. Only the lead answers and
// revises (registry LEAD), so no one else sees those forms.

import { h } from "../core/dom.js";
import { call } from "./client.js";
import { loadProposal } from "./load.js";
import { planForm } from "./planform.js";
import { leadActionsOffered, stage2Open, stage2Readable, teamReadsOffered } from "./rules.js";
import {
  APP,
  type Frame,
  type SummaryItem,
  button,
  clearAlert,
  dayTime,
  errorSummary,
  fieldError,
  frame,
  run,
  setStatus,
  showFailure,
  statusRegion,
  t,
  textArea,
} from "./ui.js";
import { type Question, decodeAccepted, decodePlanSaved, decodeStage2 } from "./wire.js";

function questionList(questions: readonly Question[]): HTMLElement {
  if (questions.length === 0) {
    return h("p", {}, [t("stage2.none")]);
  }
  return h(
    "ol",
    { id: "stage2-questions", class: "fstp-list" },
    questions.map((q) =>
      h("li", { "data-handle": q.handle }, [
        h("p", { class: "fstp-meta" }, [t("stage2.from", { handle: q.handle }), " ", t("stage2.asked"), " ", dayTime(q.asked)]),
        h("p", { class: "fstp-text" }, [q.text]),
      ]),
    ),
  );
}

function answerForm(f: Frame, id: string, status: HTMLElement): HTMLElement {
  const answer = textArea("stage2-answer", t("stage2.answer"), { rows: 10 });
  const send = button("stage2-answer-send", t("stage2.answer_send"), "submit");
  const form = h("form", { novalidate: true, "aria-label": t("stage2.answer") }, [answer.root, h("p", {}, [send])]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const text = answer.control.value;
    if (text.trim() === "") {
      fieldError(answer.control, answer.error, t("stage2.answer_required"));
      answer.control.focus();
      return;
    }
    fieldError(answer.control, answer.error, null);
    send.disabled = true;
    setStatus(status, "saving", "");
    run(f, async () => {
      const r = await call("stage2.answer", { proposal: id }, { text }, decodeAccepted);
      send.disabled = false;
      if (!r.ok) {
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        return;
      }
      setStatus(status, "saved", t("stage2.answer_sent"));
    });
  });
  return form;
}

function revisionForm(f: Frame, id: string, status: HTMLElement): HTMLElement {
  const summary = errorSummary("stage2-plan-errors");
  const plan = planForm("stage2-plan");
  const description = textArea("stage2-plan-description", t("plan.description"), { rows: 8 });
  const total = h("p", { id: "stage2-plan-total", hidden: true });
  const revise = button("stage2-revise", t("stage2.revise"), "submit");
  const form = h("form", { novalidate: true, "aria-labelledby": "stage2-revision" }, [
    summary.root,
    h("p", {}, [t("stage2.revision.intro")]),
    plan.root,
    description.root,
    h("p", {}, [revise]),
  ]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const read = plan.read();
    const text = description.control.value;
    const textMessage = text.trim() === "" ? t("plan.description_required") : null;
    fieldError(description.control, description.error, textMessage);
    const errors: SummaryItem[] = read.ok ? [] : [...read.errors];
    if (textMessage !== null) {
      errors.push({ target: description.control, message: textMessage });
    }
    if (!read.ok || errors.length > 0) {
      summary.show(errors);
      return;
    }
    summary.clear();
    revise.disabled = true;
    setStatus(status, "saving", "");
    run(f, async () => {
      const r = await call(
        "stage2.revise",
        { proposal: id },
        { description: text, tasks: read.tasks },
        decodePlanSaved,
      );
      revise.disabled = false;
      if (!r.ok) {
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        return;
      }
      setStatus(status, "saved", t("stage2.revised"));
      if (r.value.total === undefined) {
        total.hidden = true;
        total.textContent = "";
      } else {
        total.textContent = t("plan.total", { amount: r.value.total });
        total.hidden = false;
      }
    });
  });
  return h("section", { "aria-labelledby": "stage2-revision" }, [
    h("h2", { id: "stage2-revision" }, [t("stage2.revision.heading")]),
    form,
    total,
  ]);
}

/** Mounts the stage 2 page of proposal `id`. */
export function mountStage2(id: string): void {
  const f = frame(t("stage2.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]));
  run(f, async () => {
    // The proposal comes first: stage 2 is read only in the states where
    // its questions can exist, so an earlier state never shows a refusal.
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!stage2Readable(p.state) || !teamReadsOffered(p.role)) {
      f.main.append(h("p", {}, [t("stage2.closed")]));
      return;
    }
    const s = await call("stage2.view", { proposal: id }, undefined, decodeStage2);
    if (!s.ok) {
      showFailure(f, s.failure);
      return;
    }
    f.main.append(questionList(s.value));
    if (!stage2Open(p.state)) {
      f.main.append(h("p", {}, [t("stage2.answers_closed")]));
      return;
    }
    if (!leadActionsOffered(p.role)) {
      f.main.append(h("p", {}, [t("stage2.lead_answers")]));
      return;
    }
    const status = statusRegion("stage2-status");
    f.main.append(answerForm(f, id, status), revisionForm(f, id, status), status);
  });
}
