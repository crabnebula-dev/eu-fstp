// The step-up dialog of a high-risk action (I-78, R-LG-03; M4 design
// sections 3.7 step 7 and 3.9, ADR-014 "Step-up").
//
// Core `withStepUp` calls `ceremony` with the challenge of a
// `step_up_required` answer. This module shows the modal `dialog#stepup`
// of the M3 page contract. Its confirm button runs the M3 WebAuthn
// assertion over the challenge and sends it to the M3 step-up route,
// which records a proof bound to the action's digest (`StepUp::finish`).
// Escape or cancel closes the dialog and nothing is sent. The action is
// then retried once by core, and the server takes the proof (`StepUp::take`).
//
// The challenge is the one core `api.ts` read from the answer, and core
// `proveStepUp` runs the M3 ceremony for it: the assertion of
// `web/src/auth`, then the M3 route `POST /auth/stepup`. So this module
// holds no WebAuthn code of its own. Interim, pending Daniel and lanes W3b
// and W4e, as core `stepup.ts` says.
//
// Core `h` has no `dialog` tag, so the one dialog element is made with
// `document.createElement`. Its attributes and children go through core
// `h` and `setAttribute` with constant values only.
//
// A remount of the page replaces the body. `frame` then closes an open
// dialog first, so its ceremony settles as cancelled. A dialog removed
// any other way settles as cancelled at the next ceremony.

import { type FailureCode, Failure } from "../auth/webauthn.js";
import type { StepUpChallenge } from "../core/api.js";
import { h } from "../core/dom.js";
import { proveStepUp } from "../core/stepup.js";
import type { Label } from "../core/i18n.js";
import { hush, warn } from "./frame.js";
import { t } from "./i18n.js";

interface Dialog {
  readonly dialog: HTMLDialogElement;
  readonly confirm: HTMLButtonElement;
  readonly alert: HTMLElement;
}

let shared: Dialog | null = null;
/** The challenge of the open dialog and how to finish it. */
let pending: {
  readonly challenge: StepUpChallenge;
  readonly settle: (done: boolean) => void;
  /** The dialog this ceremony opened, so only its own close settles it. */
  readonly dialog: HTMLDialogElement;
} | null = null;

function failureText(code: FailureCode): Label {
  switch (code) {
    case "cancelled":
      return t.label("stepup.error.cancelled");
    case "unsupported":
      return t.label("stepup.error.unsupported");
    case "session":
      return t.label("stepup.error.session");
    case "refused":
    case "link":
      return t.label("stepup.error.refused");
    case "unavailable":
      return t.label("stepup.error.unavailable");
    case "malformed":
      return t.label("stepup.error.malformed");
  }
}

/** Settles the open ceremony of dialog `d`. A ceremony of another dialog is left alone. */
function settle(d: HTMLDialogElement, done: boolean): void {
  const p = pending;
  if (p === null || p.dialog !== d) {
    return;
  }
  pending = null;
  p.settle(done);
}

function dialog(): Dialog {
  if (shared !== null && shared.dialog.isConnected) {
    return shared;
  }
  if (shared !== null) {
    // A page remount removed the dialog without a close event: its ceremony is cancelled.
    settle(shared.dialog, false);
    shared = null;
  }
  const d = document.createElement("dialog");
  d.setAttribute("id", "stepup");
  d.setAttribute("aria-labelledby", "stepup-title");
  d.setAttribute("aria-describedby", "stepup-intro");
  const confirm = h("button", { id: "stepup-confirm", type: "button", class: "fstp-primary" }, [
    t.label("stepup.confirm"),
  ]);
  const cancel = h("button", { id: "stepup-cancel", type: "button" }, [t.label("stepup.cancel")]);
  const alert = h("p", { id: "stepup-error", role: "alert", class: "fstp-alert" });
  if (!(confirm instanceof HTMLButtonElement)) {
    throw new TypeError(t.label("error.internal"));
  }
  d.append(
    h("h2", { id: "stepup-title" }, [t.label("stepup.title")]),
    h("p", { id: "stepup-intro" }, [t.label("stepup.intro")]),
    alert,
    h("div", { class: "fstp-actions" }, [confirm, cancel]),
  );
  cancel.addEventListener("click", () => d.close());
  d.addEventListener("close", () => {
    hush(alert);
    settle(d, false);
  });
  confirm.addEventListener("click", () => {
    const p = pending;
    if (p === null || confirm.getAttribute("aria-busy") === "true") {
      return;
    }
    confirm.setAttribute("aria-busy", "true");
    confirm.setAttribute("aria-disabled", "true");
    hush(alert);
    proveStepUp(p.challenge)
      .then(
        () => {
          // A dialog closed during the ceremony already settled as cancelled.
          if (pending === p) {
            settle(d, true);
            d.close();
          }
        },
        (e: unknown) => {
          warn(alert, failureText(e instanceof Failure ? e.code : "malformed"));
        },
      )
      .finally(() => {
        confirm.removeAttribute("aria-busy");
        confirm.removeAttribute("aria-disabled");
        if (d.open) {
          confirm.focus();
        }
      });
  });
  document.body.append(d);
  shared = { dialog: d, confirm, alert };
  return shared;
}

/**
 * The ceremony for core `withStepUp`: opens the dialog for `challenge`
 * and resolves true once the proof is recorded, or false when the person
 * closes the dialog. A failed assertion shows in the dialog, which stays
 * open for another try or cancel.
 */
export function ceremony(challenge: StepUpChallenge): Promise<boolean> {
  if (pending !== null && !pending.dialog.isConnected) {
    settle(pending.dialog, false);
  }
  const d = dialog();
  if (d.dialog.open || pending !== null) {
    return Promise.resolve(false);
  }
  return new Promise<boolean>((resolve) => {
    pending = { challenge, settle: resolve, dialog: d.dialog };
    hush(d.alert);
    d.dialog.showModal();
    d.confirm.focus();
  });
}
