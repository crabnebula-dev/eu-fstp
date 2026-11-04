// One call (`calls.get`) with its Guide link and the button that starts
// a proposal (`proposal.create`). Journey J4, the Guide's "Call at a
// glance", ADR-006 and R-LA-08.
//
// Amounts are the cell's ADR-006 texts, shown byte for byte. The browser
// computes no money (design section 3.9). The deadline is a `time`
// element with the RFC 3339 instant, shown in the call's own zone with
// the zone's name.

import { call } from "../applicant/client.js";
import {
  APP,
  type Frame,
  approved,
  button,
  clearAlert,
  frame,
  instantTime,
  run,
  showAlert,
  showFailure,
  t,
} from "../applicant/ui.js";
import { CALL_AMOUNT_KINDS, type CallDetail, decodeCall, decodeCreated } from "../applicant/wire.js";
import { h } from "../core/dom.js";
import { navigate } from "../core/router.js";

function glance(c: CallDetail): HTMLElement {
  const deadline = h("p", { id: "call-deadline" }, [
    h("strong", {}, [t("call.deadline")]),
    " ",
    instantTime(c.deadline, c.zone),
    " ",
    t("call.zone", { zone: c.zone }),
  ]);
  const rows: HTMLElement[] = [];
  for (const k of CALL_AMOUNT_KINDS) {
    const a = c.amounts[k];
    if (a !== undefined) {
      rows.push(h("dt", {}, [t(`call.amount.${k}`)]), h("dd", {}, [t("call.amount.value", { amount: a, currency: c.currency })]));
    }
  }
  const amounts = h("section", { id: "call-amounts", "aria-labelledby": "call-amounts-heading" }, [
    h("h3", { id: "call-amounts-heading" }, [t("call.amounts")]),
    h("dl", {}, rows),
  ]);
  return h("section", { "aria-labelledby": "call-glance" }, [
    h("h2", { id: "call-glance" }, [t("call.glance")]),
    deadline,
    amounts,
  ]);
}

function disclosure(): HTMLElement {
  return h("section", { id: "call-ai-disclosure", "aria-labelledby": "call-ai-heading" }, [
    h("h2", { id: "call-ai-heading" }, [t("call.ai.heading")]),
    h("p", {}, [approved("call.ai.text")]),
  ]);
}

async function start(f: Frame, c: CallDetail, b: HTMLButtonElement): Promise<void> {
  clearAlert(f);
  b.disabled = true;
  // The minor flag never comes from the applicant (state-machine NOTE 14),
  // so the new draft carries no member.
  const r = await call("proposal.create", { call: c.call }, {}, decodeCreated);
  if (!r.ok) {
    b.disabled = false;
    showFailure(f, r.failure);
    return;
  }
  navigate(APP.workspace(r.value));
}

/** Mounts the page of call `id`. */
export function mountCall(id: string): void {
  const f = frame(t("call.title"));
  f.heading.setAttribute("id", "call-title");
  run(f, async () => {
    const r = await call("calls.get", { call: id }, undefined, decodeCall);
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    const c = r.value;
    const title = c.title === "" ? t("calls.untitled", { id: c.call }) : c.title;
    f.heading.textContent = title;
    document.title = t("app.document_title", { page: title });
    f.main.append(
      glance(c),
      disclosure(),
      h("p", {}, [h("a", { id: "call-guide-link", href: APP.guide(c.call) }, [t("call.guide_link")])]),
    );
    if (!c.open) {
      showAlert(f, t("call.closed"));
      return;
    }
    const b = button("proposal-start", t("call.start"));
    b.addEventListener("click", () => {
      run(f, () => start(f, c, b));
    });
    f.main.append(h("p", {}, [b]));
  });
}
