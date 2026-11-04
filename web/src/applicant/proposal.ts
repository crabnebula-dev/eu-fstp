// One proposal (`proposal.view`): its state, what the applicant can do in
// that state, withdrawal (`proposal.withdraw`, R-SB-03) and the copy
// request (`proposal.request_copy`, R-SB-04).
//
// An action the state or the caller's role does not allow has no control
// on the page (design section 8.7 `roles/<role>`). The lead's actions are
// offered to the lead only, and the team's reads to the whole team,
// guardian included (`rules.ts`). The withdrawal asks for confirmation
// in a modal dialog before it sends anything (WCAG 2.2 SC 3.3.4). Cancel
// and Escape close it.

import { h } from "../core/dom.js";
import { call } from "./client.js";
import { isEmail } from "./email.js";
import { loadProposal } from "./load.js";
import {
  draftEditable,
  guardianAddOffered,
  guardianConsentOpen,
  leadActionsOffered,
  negotiationOpen,
  stage2Open,
  stage2Readable,
  teamEditable,
  teamReadsOffered,
  type ProposalState,
  withdrawOffered,
} from "./rules.js";
import {
  APP,
  type Frame,
  button,
  clearAlert,
  fieldError,
  focusHeading,
  frame,
  run,
  setStatus,
  showFailure,
  stateLabel,
  statusRegion,
  t,
  textInput,
} from "./ui.js";
import { type ProposalInfo, decodeAccepted } from "./wire.js";

function actions(p: ProposalInfo): HTMLElement | null {
  const links: [string, string][] = [];
  const lead = leadActionsOffered(p.role);
  const team = teamReadsOffered(p.role);
  if (team && draftEditable(p.state)) {
    links.push([APP.workspace(p.proposal), "proposal.link.workspace"]);
  }
  if (lead && draftEditable(p.state)) {
    links.push(
      [APP.plan(p.proposal), "proposal.link.plan"],
      [APP.eligibility(p.proposal), "proposal.link.eligibility"],
      [APP.submit(p.proposal), "proposal.link.submit"],
    );
  }
  if (lead && (teamEditable(p.state) || guardianAddOffered(p.state))) {
    links.push([APP.team(p.proposal), "proposal.link.team"]);
  }
  if (team && stage2Readable(p.state)) {
    const answers = lead && stage2Open(p.state);
    links.push([APP.stage2(p.proposal), answers ? "proposal.link.stage2" : "proposal.link.stage2_read"]);
  }
  if (team && negotiationOpen(p.state)) {
    links.push([APP.negotiation(p.proposal), "proposal.link.negotiation"]);
  }
  if (p.role === "guardian" && guardianConsentOpen(p.state)) {
    links.push([APP.guardian(p.proposal), "proposal.link.guardian"]);
  }
  if (links.length === 0) {
    return null;
  }
  return h("section", { "aria-labelledby": "proposal-actions" }, [
    h("h2", { id: "proposal-actions" }, [t("proposal.actions")]),
    h(
      "ul",
      { class: "fstp-list" },
      links.map(([href, label]) => h("li", {}, [h("a", { href }, [t(label)])])),
    ),
  ]);
}

/** Opens the withdrawal dialog for `p`. Focus returns to `trigger` when it closes. */
function openWithdraw(f: Frame, p: ProposalInfo, trigger: HTMLButtonElement): void {
  const confirm = button("withdraw-confirm", t("withdraw.confirm"));
  const cancel = button("withdraw-cancel", t("withdraw.cancel"));
  const failure = h("p", { id: "withdraw-error", role: "alert", class: "fstp-alert", hidden: true });
  const dialog = h(
    "div",
    {
      id: "withdraw-dialog",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "withdraw-title",
      "aria-describedby": "withdraw-text",
      class: "fstp-dialog",
    },
    [
      h("h2", { id: "withdraw-title" }, [t("withdraw.title")]),
      h("p", { id: "withdraw-text" }, [t("withdraw.text")]),
      failure,
      h("p", { class: "fstp-actions" }, [cancel, " ", confirm]),
    ],
  );
  const backdrop = h("div", { class: "fstp-backdrop" }, [dialog]);
  const behind = Array.from(f.root.children).filter((c): c is HTMLElement => c instanceof HTMLElement);
  let busy = false;

  // `restore` is false when the page is about to be replaced, which then
  // moves focus to its new heading itself.
  const close = (restore: boolean): void => {
    document.removeEventListener("keydown", onKey, true);
    backdrop.remove();
    for (const el of behind) {
      el.inert = false;
    }
    if (restore) {
      trigger.focus();
    }
  };
  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Escape" && !busy) {
      e.preventDefault();
      close(true);
    } else if (e.key === "Tab") {
      // Keep focus inside the dialog: its two buttons, in order.
      const order = [cancel, confirm];
      const at = order.indexOf(document.activeElement as HTMLButtonElement);
      const next = e.shiftKey ? (at <= 0 ? order.length - 1 : at - 1) : at < 0 || at >= order.length - 1 ? 0 : at + 1;
      e.preventDefault();
      order[next]?.focus();
    }
  };

  cancel.addEventListener("click", () => {
    if (!busy) {
      close(true);
    }
  });
  confirm.addEventListener("click", () => {
    if (busy) {
      return;
    }
    busy = true;
    cancel.disabled = true;
    confirm.disabled = true;
    run(f, async () => {
      const r = await call("proposal.withdraw", { proposal: p.proposal }, {}, decodeAccepted);
      busy = false;
      if (!r.ok) {
        cancel.disabled = false;
        confirm.disabled = false;
        showFailure(f, r.failure);
        failure.textContent = f.alert.textContent;
        failure.hidden = false;
        cancel.focus();
        return;
      }
      close(false);
      mountProposal(p.proposal, t("withdraw.done"));
    });
  });

  for (const el of behind) {
    el.inert = true;
  }
  document.addEventListener("keydown", onKey, true);
  f.root.append(backdrop);
  cancel.focus();
}

function copyForm(f: Frame, p: ProposalInfo): HTMLElement {
  const email = textInput("copy-email", t("copy.email"), { type: "email", autocomplete: "email", maxlength: 254 });
  const send = button("copy-request", t("copy.request"), "submit");
  const status = statusRegion("copy-status");
  const form = h("form", { novalidate: true, "aria-labelledby": "copy-heading" }, [email.root, h("p", {}, [send])]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const to = email.control.value.trim();
    if (!isEmail(to)) {
      fieldError(email.control, email.error, t("copy.invalid"));
      email.control.focus();
      return;
    }
    fieldError(email.control, email.error, null);
    send.disabled = true;
    run(f, async () => {
      const r = await call("proposal.request_copy", { proposal: p.proposal }, { email: to }, decodeAccepted);
      send.disabled = false;
      if (!r.ok) {
        showFailure(f, r.failure);
        return;
      }
      setStatus(status, "saved", t("copy.done"));
    });
  });
  return h("section", { "aria-labelledby": "copy-heading" }, [
    h("h2", { id: "copy-heading" }, [t("copy.heading")]),
    h("p", {}, [t("copy.intro")]),
    form,
    status,
  ]);
}

/**
 * The outcome panel of a proposal in a final or paused state
 * (`end-states` prototype). It names the outcome in words beside its
 * formal state (I-96) and carries no score or comment (O-54: none is
 * read here). A state with no panel gives none.
 *
 * Interim, pending the lead: the "on hold" panel of a minor's proposal
 * held in IRC_REVIEW (I-18) needs a hold member that `proposal.view`
 * does not carry, so this page shows none for it.
 */
function outcomePanel(state: ProposalState): HTMLElement[] {
  const key =
    state === "INELIGIBLE"
      ? "ineligible"
      : state === "NOT_SELECTED"
        ? "not_selected"
        : state === "DEFERRED"
          ? "deferred"
          : null;
  if (key === null) {
    return [];
  }
  return [
    h("section", { id: "proposal-outcome", class: "card", "aria-labelledby": "proposal-outcome-heading" }, [
      h("p", { class: "card-kicker" }, [t(`outcome.${key}.kicker`)]),
      h("h2", { id: "proposal-outcome-heading" }, [t(`outcome.${key}.title`)]),
      h("p", { class: "state-name" }, [t("outcome.formal", { state })]),
      h("p", {}, [t(`outcome.${key}.text`)]),
      ...(key === "deferred" ? [] : [h("p", {}, [h("a", { href: APP.calls }, [t("outcome.other_calls")])])]),
    ]),
  ];
}

/**
 * Mounts the page of proposal `id`. `done`, when given, is the outcome of
 * the action that led here, shown in a status region.
 */
export function mountProposal(id: string, done?: string): void {
  const f = frame(t("proposal.title"));
  const outcome = statusRegion("proposal-status");
  f.main.append(outcome);
  if (done !== undefined) {
    setStatus(outcome, "saved", done);
    // The page that held the focus is gone, so focus starts at the new heading.
    focusHeading(f);
  }
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    const title = h("h2", { id: "proposal-title" }, [p.title === "" ? t("proposal.untitled") : p.title]);
    const state = h("p", {}, [
      t("proposal.state"),
      " ",
      h("strong", { id: "proposal-state", class: "badge badge--info", "data-state": p.state }, [stateLabel(p.state)]),
      " ",
      h("span", { class: "state-name" }, [p.state]),
    ]);
    f.main.append(title, state, ...outcomePanel(p.state));
    if (p.call !== undefined) {
      f.main.append(h("p", {}, [h("a", { href: APP.call(p.call) }, [t("proposal.call_link")])]));
    }
    const next = actions(p);
    if (next !== null) {
      f.main.append(next);
    }
    if (leadActionsOffered(p.role)) {
      if (withdrawOffered(p.state)) {
        const w = button("proposal-withdraw", t("proposal.withdraw"));
        w.addEventListener("click", () => {
          openWithdraw(f, p, w);
        });
        f.main.append(h("p", {}, [w]));
      }
      f.main.append(copyForm(f, p));
    }
  });
}
