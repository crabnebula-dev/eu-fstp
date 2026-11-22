// The onboarding summary, `/app/admin/onboarding/summary` (R-TN-01,
// SoD-07, SoD-14 to SoD-18; M4 design sections 2.2 J0 and 3.5).
//
// It opens with the setup checklist (ADR-026 record of lane L18): each
// item done or not, who does it, and one plain sentence for the next
// step. The second admin is invited from here, since the Administrators
// step opens only after every earlier step. The account numbers of the
// admins are shown in the form `fstp-vault verify-first-admin` takes, so
// the web admin can pass them to the technical admin.
//
// It then lists every step with its status. `#onboarding-complete`
// finishes onboarding (`tenant.complete`). The server completes it only
// when every step is validated and at least two tenant admins have
// verified their identity (SoD-07, Q2). Otherwise the refusal shows in
// the alert. Completing onboarding does not activate the organisation.
//
// `#activation` activates it (`./signatories.ts`): one tenant admin
// requests activation, and a tenant admin other than the requester
// approves it (SoD-18). Each needs a holder of Financial signatory and of
// Legal signatory (SoD-14, SoD-15).

import { h } from "../../core/dom.js";
import type { Label } from "../../core/i18n.js";
import { busy, frame, hush, warn } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { t } from "../i18n.js";
import {
  ONBOARDING_STEPS,
  accountNumber,
  checklist,
  openableSteps,
  passes,
  readAdmins,
  type ActivationView,
  type AdminRow,
  type ChecklistRow,
  type SignatoryRow,
  type StepStatus,
} from "../model.js";
import { PATHS, link, loadSteps, statusText, statusesOf, stepName, stepNav } from "./common.js";
import { activationSection, loadActivation, loadSignatories, signatorySection } from "./signatories.js";

/** The label of a checklist item. */
function itemText(r: ChecklistRow): Label {
  return t.label(`onboarding.checklist.item.${r.item}`);
}

/** The invitation form of the second admin (SoD-07, J0). */
function inviteForm(alert: HTMLElement, reload: () => Promise<void>): HTMLElement {
  const email = h("input", { id: "checklist-invite-email", type: "email", autocomplete: "off", spellcheck: "false" });
  const submit = h("button", { id: "checklist-invite", type: "button", class: "fstp-primary" }, [
    t.label("onboarding.checklist.invite"),
  ]);
  const status = h("p", { id: "checklist-invite-status", role: "status", class: "fstp-status" });
  submit.addEventListener(
    "click",
    busy(submit, async () => {
      hush(alert);
      const address = email instanceof HTMLInputElement ? email.value.trim() : "";
      if (!/^[^\s@]+@[^\s@]+$/.test(address)) {
        warn(alert, t.label("onboarding.admin.email_invalid"));
        email.focus();
        return;
      }
      const o = await call("tenant.invite_admin", [], { email: address }, anyObject);
      if (report(alert, o)) return;
      if (email instanceof HTMLInputElement) email.value = "";
      status.textContent = t.label("onboarding.admin.invited", { email: address });
      await reload();
    }),
  );
  return h("div", { id: "checklist-invite-form" }, [
    h("div", { class: "fstp-control" }, [
      h("label", { for: "checklist-invite-email" }, [t.label("onboarding.checklist.email")]),
      email,
    ]),
    submit,
    status,
  ]);
}

/** The checklist section of the four reads. */
function checklistSection(
  alert: HTMLElement,
  admins: readonly AdminRow[],
  signatories: readonly SignatoryRow[],
  statuses: Readonly<Record<string, StepStatus>>,
  activation: ActivationView,
  reload: () => Promise<void>,
): HTMLElement {
  const { rows, next } = checklist({ admins, signatories, statuses, activation });
  const list = h(
    "ol",
    { id: "checklist", "aria-labelledby": "checklist-title" },
    rows.map((r) =>
      h("li", { "data-item": r.item, "data-done": r.done ? "true" : "false", "data-actor": r.actor }, [
        h("strong", {}, [r.done ? t.label("onboarding.checklist.done") : t.label("onboarding.checklist.todo")]),
        " ",
        itemText(r),
        ...(r.done || r.actor === "web"
          ? []
          : [
              " ",
              r.actor === "host"
                ? t.label("onboarding.checklist.by_host")
                : t.label("onboarding.checklist.by_other"),
            ]),
      ]),
    ),
  );
  const parts: HTMLElement[] = [
    h("h2", { id: "checklist-title" }, [t.label("onboarding.checklist.title")]),
    h("p", {}, [t.label("onboarding.checklist.intro")]),
    list,
  ];
  if (next === null) {
    parts.push(h("p", { id: "checklist-next", class: "callout" }, [t.label("onboarding.checklist.all_done")]));
  } else {
    parts.push(
      h("p", { id: "checklist-next", class: "callout", "data-next": next }, [
        t.label("onboarding.checklist.next", { text: t.label(`onboarding.checklist.next.${next}`) }),
      ]),
    );
  }
  if (next === "second_admin") parts.push(inviteForm(alert, reload));
  if (next === "steps") {
    const open = openableSteps(statuses);
    const first = open.find((s) => !passes(statuses[s]));
    if (first !== undefined) {
      parts.push(
        h("p", {}, [link(PATHS.step(first), t.label("onboarding.checklist.open_step", { name: stepName(first) }))]),
      );
    }
  }
  // The account numbers, for `fstp-vault verify-first-admin`.
  const numbers = admins.flatMap((a) => {
    const n = accountNumber(a.account);
    return n === null
      ? []
      : [h("li", { "data-account": a.account }, [t.label("onboarding.checklist.account", { handle: a.handle, number: n })])];
  });
  if (numbers.length > 0 && rows.some((r) => r.item === "verified" && !r.done)) {
    parts.push(
      h("h3", { id: "checklist-accounts-title" }, [t.label("onboarding.checklist.accounts")]),
      h("ul", { id: "checklist-accounts", "aria-labelledby": "checklist-accounts-title" }, numbers),
    );
  }
  return h("section", { id: "setup-checklist", "aria-labelledby": "checklist-title" }, parts);
}

/** Mounts the onboarding summary. */
export function mount(): void {
  let nav = stepNav("summary", null);
  const { main, alert } = frame({ title: t.label("onboarding.summary.title"), alertId: "onboarding-error", nav });
  const checklistBox = h("div", { id: "checklist-box" });
  const list = h("ul", { id: "onboarding-summary", "aria-labelledby": "summary-title" });
  const outcome = h("p", { id: "onboarding-complete-outcome", role: "status", class: "fstp-status" });
  const complete = h("button", { id: "onboarding-complete", type: "button", class: "fstp-primary" }, [
    t.label("onboarding.summary.complete"),
  ]);
  const signatoryBox = h("div", { id: "signatory-box" });
  const activation = h("div", { id: "activation-box" });
  main.append(
    checklistBox,
    h("p", {}, [t.label("onboarding.summary.intro")]),
    h("h2", { id: "summary-title" }, [t.label("onboarding.summary.steps")]),
    list,
    complete,
    outcome,
    signatoryBox,
    activation,
  );
  const draw = async (): Promise<boolean> => {
    const steps = await loadSteps(alert);
    if (steps === null) return false;
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
    const admins = await call("tenant.list_admins", [], undefined, (v) => readAdmins(v) !== null);
    if (report(alert, admins) || admins.kind !== "done") return false;
    const adminRows = readAdmins(admins.body) ?? [];
    const rows = await loadSignatories(alert);
    const view = await loadActivation(alert);
    if (rows === null || view === null) return false;
    const reload = async (): Promise<void> => {
      await draw();
    };
    checklistBox.replaceChildren(checklistSection(alert, adminRows, rows, statuses, view, reload));
    signatoryBox.replaceChildren(signatorySection(alert, adminRows, rows, reload));
    activation.replaceChildren(activationSection(alert, adminRows, view, rows, reload));
    return true;
  };
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
      await draw();
    }),
  );
  void (async () => {
    if (!(await draw())) return;
    main.setAttribute("data-ready", "true");
  })();
}
