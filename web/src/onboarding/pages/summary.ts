// The onboarding summary, `/app/admin/onboarding/summary` (R-TN-01,
// SoD-07, SoD-14 to SoD-18; M4 design sections 2.2 J0 and 3.5).
//
// It lists every step with its status. `#onboarding-complete` finishes
// onboarding (`tenant.complete`). The server completes it only when
// every step is validated and at least two tenant admins have verified
// their identity (SoD-07, Q2). Otherwise the refusal shows in the alert.
// Completing onboarding does not activate the organisation.
//
// `#activation` activates it (`./signatories.ts`): one tenant admin
// requests activation, and a tenant admin other than the requester
// approves it (SoD-18). Each needs a holder of Financial signatory and of
// Legal signatory (SoD-14, SoD-15).

import { h } from "../../core/dom.js";
import { busy, frame, hush } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { t } from "../i18n.js";
import { ONBOARDING_STEPS, readAdmins } from "../model.js";
import { PATHS, link, loadSteps, statusText, statusesOf, stepName, stepNav } from "./common.js";
import { activationSection, loadActivation, loadSignatories } from "./signatories.js";

/** Mounts the onboarding summary. */
export function mount(): void {
  let nav = stepNav("summary", null);
  const { main, alert } = frame({ title: t.label("onboarding.summary.title"), alertId: "onboarding-error", nav });
  const list = h("ul", { id: "onboarding-summary", "aria-labelledby": "summary-title" });
  const outcome = h("p", { id: "onboarding-complete-outcome", role: "status", class: "fstp-status" });
  const complete = h("button", { id: "onboarding-complete", type: "button", class: "fstp-primary" }, [
    t.label("onboarding.summary.complete"),
  ]);
  complete.addEventListener(
    "click",
    busy(complete, async () => {
      hush(alert);
      outcome.removeAttribute("data-outcome");
      outcome.textContent = "";
      const o = await call("tenant.complete", [], {}, anyObject);
      if (report(alert, o)) return;
      outcome.setAttribute("data-outcome", "completed");
      outcome.textContent = t.label("onboarding.summary.completed");
    }),
  );
  const activation = h("div", { id: "activation-box" });
  main.append(
    h("p", {}, [t.label("onboarding.summary.intro")]),
    h("h2", { id: "summary-title" }, [t.label("onboarding.summary.steps")]),
    list,
    complete,
    outcome,
    activation,
  );
  const drawActivation = async (): Promise<boolean> => {
    const admins = await call("tenant.list_admins", [], undefined, (v) => readAdmins(v) !== null);
    if (report(alert, admins) || admins.kind !== "done") return false;
    const rows = await loadSignatories(alert);
    const view = await loadActivation(alert);
    if (rows === null || view === null) return false;
    activation.replaceChildren(
      activationSection(alert, readAdmins(admins.body) ?? [], view, rows, async () => {
        await drawActivation();
      }),
    );
    return true;
  };
  void (async () => {
    const steps = await loadSteps(alert);
    if (steps === null) return;
    const statuses = statusesOf(steps);
    const fresh = stepNav("summary", statuses);
    nav.replaceWith(fresh);
    nav = fresh;
    list.replaceChildren(
      ...ONBOARDING_STEPS.map((s) =>
        h("li", { "data-summary-step": s, "data-status": statuses[s] ?? "" }, [
          link(PATHS.step(s), t.label("onboarding.nav.item", { name: stepName(s), status: statusText(statuses[s]) })),
        ]),
      ),
    );
    if (!(await drawActivation())) return;
    main.setAttribute("data-ready", "true");
  })();
}
