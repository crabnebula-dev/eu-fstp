// The plan editor (`proposal.record_plan`; journey J4, ADR-006).
//
// The lead records a plan version: its tasks, each with dated milestones
// and their amounts (`planform.ts`), and the work plan text. A field in
// error is marked on the field and listed in an error summary with a
// link to it, and nothing is sent (WCAG 2.2 SC 3.3.1). The browser
// computes no money: the page shows the plan total only when the cell
// sends one.
//
// Only the lead records a plan (`ActorRule::Lead`; registry LEAD), so the
// page shows no form to anyone else.

import { h } from "../core/dom.js";
import { call } from "./client.js";
import { loadProposal } from "./load.js";
import { planForm } from "./planform.js";
import { draftEditable, leadActionsOffered } from "./rules.js";
import {
  APP,
  type SummaryItem,
  button,
  clearAlert,
  errorSummary,
  fieldError,
  frame,
  run,
  setStatus,
  showFailure,
  statusRegion,
  proposalHeading,
  proposalSteps,
  t,
  textArea,
} from "./ui.js";
import { decodePlanSaved } from "./wire.js";

/** Mounts the plan editor of proposal `id`. */
export function mountPlan(id: string): void {
  const f = frame(t("plan.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!draftEditable(p.state)) {
      f.main.append(h("p", {}, [t("plan.readonly")]));
      return;
    }
    if (!leadActionsOffered(p.role)) {
      f.main.append(h("p", {}, [t("lead.only")]));
      return;
    }
    proposalHeading(f, p.state);
    f.main.append(proposalSteps(id, "plan"), h("h2", { id: "plan-heading" }, [t("steps.plan")]));
    const summary = errorSummary("plan-errors");
    const plan = planForm("plan");
    const description = textArea("plan-description", t("plan.description"), { rows: 10 });
    const save = button("plan-save", t("plan.save"), "submit");
    const status = statusRegion("plan-status");
    const total = h("p", { id: "plan-total", hidden: true });
    const form = h("form", { novalidate: true, "aria-label": t("plan.title") }, [
      summary.root,
      h("p", {}, [t("plan.intro")]),
      plan.root,
      description.root,
      h("p", {}, [save]),
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
      save.disabled = true;
      setStatus(status, "saving", "");
      run(f, async () => {
        const r = await call(
          "proposal.record_plan",
          { proposal: id },
          { description: text, tasks: read.tasks },
          decodePlanSaved,
        );
        save.disabled = false;
        if (!r.ok) {
          setStatus(status, "failed", "");
          showFailure(f, r.failure);
          return;
        }
        setStatus(status, "saved", t("plan.saved"));
        if (r.value.total === undefined) {
          total.hidden = true;
          total.textContent = "";
        } else {
          total.textContent = t("plan.total", { amount: r.value.total });
          total.hidden = false;
        }
      });
    });
    f.main.append(form, status, total);
  });
}
