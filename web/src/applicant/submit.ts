// Submission (`proposal.submit`; journey J4, R-NG-06, R-SB-05, R-SB-01,
// R-SB-02).
//
// The page shows the data protection notice with its version, and the
// submission names that version. The ethics self-declaration is required:
// "no ethics issue", or a declared issue with its description. A refused
// form shows an error summary as an alert, with a link to each field in
// error, and sends nothing (WCAG 2.2 SC 3.3.1). The form holds no
// identity, birth date, payment or file field, and asks for no guardian.

import { linkError, clearError } from "../core/a11y.js";
import { h } from "../core/dom.js";
import { call } from "./client.js";
import { loadProposal } from "./load.js";
import { NOTICE_VERSIONS } from "./messages.en.js";
import { draftEditable, leadActionsOffered } from "./rules.js";
import {
  APP,
  type Frame,
  approved,
  button,
  clearAlert,
  fieldError,
  frame,
  run,
  setStatus,
  showAlert,
  showFailure,
  stateLabel,
  statusRegion,
  t,
  textArea,
  proposalHeading,
  proposalSteps,
} from "./ui.js";
import { type Body, decodeAccepted, decodeCall } from "./wire.js";

/** One error of the summary: the field to focus and the message. */
interface SummaryItem {
  readonly target: HTMLElement;
  readonly message: string;
}

function notice(): HTMLElement {
  return h(
    "section",
    { id: "submit-notice", "data-notice-version": NOTICE_VERSIONS.submission, "aria-labelledby": "submit-notice-heading" },
    [h("h2", { id: "submit-notice-heading" }, [t("submit.notice.heading")]), h("p", {}, [approved("notice.submission")])],
  );
}

function radio(id: string, value: string, label: string): { readonly root: HTMLElement; readonly input: HTMLInputElement } {
  const input = h("input", { id, name: "ethics", type: "radio", value });
  if (!(input instanceof HTMLInputElement)) {
    throw new TypeError("the document did not create an input");
  }
  return { root: h("div", { class: "fstp-choice" }, [input, " ", h("label", { for: id }, [label])]), input };
}

function form(f: Frame, id: string, done: (ethics: "none" | "declared") => void): HTMLElement {
  const summaryList = h("ul", {});
  const summary = h(
    "div",
    { id: "submit-errors", role: "alert", tabindex: "-1", class: "fstp-summary", "aria-labelledby": "submit-errors-heading", hidden: true },
    [h("h2", { id: "submit-errors-heading" }, [t("submit.errors.heading")]), summaryList],
  );

  const read = h("input", { id: "submit-notice-read", name: "submit-notice-read", type: "checkbox" });
  if (!(read instanceof HTMLInputElement)) {
    throw new TypeError("the document did not create an input");
  }
  const readError = h("p", { id: "submit-notice-read-error", class: "fstp-error", hidden: true });
  const readRoot = h("div", { class: "fstp-choice" }, [
    readError,
    read,
    " ",
    h("label", { for: "submit-notice-read" }, [t("submit.notice_read")]),
  ]);

  const none = radio("ethics-none", "none", t("submit.ethics.none"));
  const declared = radio("ethics-declared", "declared", t("submit.ethics.declared"));
  const details = textArea("ethics-details", t("submit.ethics.details"), { rows: 5 });
  details.root.hidden = true;
  const ethicsError = h("p", { id: "submit-ethics-error", class: "fstp-error", hidden: true });
  const ethics = h("fieldset", { id: "submit-ethics" }, [
    h("legend", {}, [t("submit.ethics.legend")]),
    ethicsError,
    none.root,
    declared.root,
    details.root,
  ]);
  const showDetails = (): void => {
    details.root.hidden = !declared.input.checked;
  };
  none.input.addEventListener("change", showDetails);
  declared.input.addEventListener("change", showDetails);

  const confirm = button("submit-confirm", t("submit.confirm"), "submit");
  const el = h("form", { novalidate: true, "aria-label": t("submit.title") }, [
    summary,
    readRoot,
    ethics,
    h("p", {}, [confirm]),
  ]);

  const setGroupError = (message: string | null): void => {
    if (message === null) {
      ethicsError.textContent = "";
      ethicsError.hidden = true;
      clearError(ethics, ethicsError);
    } else {
      ethicsError.textContent = message;
      ethicsError.hidden = false;
      linkError(ethics, ethicsError);
    }
  };

  el.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const items: SummaryItem[] = [];
    const readMessage = read.checked ? null : t("submit.notice_required");
    fieldError(read, readError, readMessage);
    if (readMessage !== null) {
      items.push({ target: read, message: readMessage });
    }
    const answered = none.input.checked || declared.input.checked;
    const ethicsMessage = answered ? null : t("submit.ethics_required");
    setGroupError(ethicsMessage);
    if (ethicsMessage !== null) {
      items.push({ target: none.input, message: ethicsMessage });
    }
    const issue = details.control.value;
    const detailsMessage = declared.input.checked && issue.trim() === "" ? t("submit.ethics_details_required") : null;
    fieldError(details.control, details.error, detailsMessage);
    if (detailsMessage !== null) {
      items.push({ target: details.control, message: detailsMessage });
    }
    if (items.length > 0) {
      summaryList.replaceChildren(
        ...items.map((i) => {
          const a = h("a", { href: `#${i.target.id}` }, [i.message]);
          a.addEventListener("click", (ev) => {
            ev.preventDefault();
            i.target.focus();
          });
          return h("li", {}, [a]);
        }),
      );
      summary.hidden = false;
      summary.focus();
      return;
    }
    summary.hidden = true;
    summaryList.replaceChildren();
    const body: Body = declared.input.checked
      ? { ethics: "declared", ethics_details: issue, notice_version: NOTICE_VERSIONS.submission }
      : { ethics: "none", notice_version: NOTICE_VERSIONS.submission };
    confirm.disabled = true;
    run(f, async () => {
      const r = await call("proposal.submit", { proposal: id }, body, decodeAccepted);
      confirm.disabled = false;
      if (!r.ok) {
        showFailure(f, r.failure);
        return;
      }
      done(declared.input.checked ? "declared" : "none");
    });
  });
  return el;
}

/** What the receipt shows of a submission the cell accepted. */
interface Receipt {
  readonly title: string;
  readonly ethics: "none" | "declared";
}

/**
 * The submission receipt (`submission-receipt` prototype; R-SB-05,
 * R-NG-06): the status, the proposal, the notice version shown and
 * acknowledged, the ethics self-declaration, and what happens next. The
 * reply of `proposal.submit` carries no time or ledger sequence, so the
 * receipt names neither.
 */
function mountReceipt(id: string, r: Receipt): void {
  const f = frame(t("receipt.title"));
  const status = statusRegion("submit-status");
  f.main.prepend(status);
  setStatus(status, "saved", t("submit.done"));
  f.main.append(
    h("section", { class: "card", "aria-labelledby": "receipt-heading" }, [
      h("h2", { id: "receipt-heading" }, [r.title === "" ? t("proposal.untitled") : r.title]),
      h("dl", { class: "facts" }, [
        h("dt", {}, [t("receipt.proposal")]),
        h("dd", { class: "pid" }, [id]),
        h("dt", {}, [t("receipt.state")]),
        h("dd", {}, [h("span", { class: "badge badge--success" }, [stateLabel("SUBMITTED")]), " ", h("span", { class: "state-name" }, ["SUBMITTED"])]),
        h("dt", {}, [t("receipt.notice")]),
        h("dd", {}, [t("receipt.notice_version", { version: NOTICE_VERSIONS.submission })]),
        h("dt", {}, [t("receipt.ethics")]),
        h("dd", {}, [t(r.ethics === "declared" ? "receipt.ethics_declared" : "receipt.ethics_none")]),
      ]),
    ]),
    h("section", { class: "card", "aria-labelledby": "receipt-next-heading" }, [
      h("h2", { id: "receipt-next-heading" }, [t("receipt.next")]),
      h("p", {}, [t("receipt.next_check")]),
      h("p", {}, [t("receipt.next_withdraw")]),
      h("p", {}, [h("a", { href: APP.proposal(id) }, [t("receipt.open")])]),
    ]),
  );
}

/**
 * Mounts the submit page of proposal `id`. `done`, when given, is the
 * outcome of the submission that led here.
 */
export function mountSubmit(id: string, done?: Receipt): void {
  if (done !== undefined) {
    mountReceipt(id, done);
    return;
  }
  const f = frame(t("submit.title"));
  const status = statusRegion("submit-status");
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]), status);
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (p.title !== "") {
      f.main.append(h("p", { class: "fstp-meta" }, [p.title]));
    }
    if (!draftEditable(p.state)) {
      showAlert(f, t("submit.not_draft", { state: stateLabel(p.state) }));
      return;
    }
    if (!leadActionsOffered(p.role)) {
      f.main.append(h("p", {}, [t("lead.only")]));
      return;
    }
    proposalHeading(f, p.state);
    f.main.append(proposalSteps(id, "submit"), h("h2", { id: "submit-heading" }, [t("steps.submit")]));
    if (p.call !== undefined) {
      const c = await call("calls.get", { call: p.call }, undefined, decodeCall);
      if (c.ok && !c.value.open) {
        showAlert(f, t("submit.closed"));
        return;
      }
    }
    f.main.append(
      notice(),
      form(f, id, (ethics) => {
        mountSubmit(id, { title: p.title, ethics });
      }),
    );
  });
}
