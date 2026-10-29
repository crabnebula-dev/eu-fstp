// Country of residence or establishment, and declared affiliations
// (`proposal.state_country`, `proposal.declare_affiliations`; R-NG-01,
// design section 2.2 `VaultBound<T>`).
//
// Each statement goes to its vault route and to no other. The page never
// reads either back, and it never shows them after a save: the fields
// start empty on every visit.

import { h } from "../core/dom.js";
import { call } from "./client.js";
import { countryChoices } from "./countries.js";
import { loadProposal } from "./load.js";
import { draftEditable, leadActionsOffered } from "./rules.js";
import {
  APP,
  type Frame,
  button,
  clearAlert,
  fieldError,
  frame,
  locale,
  run,
  setStatus,
  showFailure,
  statusRegion,
  t,
  textArea,
} from "./ui.js";
import { decodeAccepted } from "./wire.js";

function countryForm(f: Frame, id: string, status: HTMLElement): HTMLElement {
  const options = [
    h("option", { value: "" }, [t("elig.country_choose")]),
    ...countryChoices(locale()).map((c) => h("option", { value: c.code }, [c.name])),
  ];
  const select = h("select", { id: "elig-country", name: "elig-country", "aria-describedby": "elig-intro" }, options);
  if (!(select instanceof HTMLSelectElement)) {
    throw new TypeError("the document did not create a select");
  }
  const error = h("p", { id: "elig-country-error", class: "fstp-error", hidden: true });
  const save = button("elig-country-save", t("elig.country_save"), "submit");
  const form = h("form", { novalidate: true, "aria-label": t("elig.country") }, [
    h("div", { class: "fstp-field" }, [h("label", { for: "elig-country" }, [t("elig.country")]), error, select]),
    h("p", {}, [save]),
  ]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const country = select.value;
    if (country === "") {
      fieldError(select, error, t("elig.country_required"));
      select.focus();
      return;
    }
    fieldError(select, error, null);
    save.disabled = true;
    setStatus(status, "saving", "");
    run(f, async () => {
      const r = await call("proposal.state_country", { proposal: id }, { country }, decodeAccepted);
      save.disabled = false;
      if (!r.ok) {
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        return;
      }
      setStatus(status, "saved", t("elig.country_saved"));
    });
  });
  return form;
}

function affiliationsForm(f: Frame, id: string, status: HTMLElement): HTMLElement {
  const text = textArea("elig-affiliations", t("elig.affiliations"), { hint: t("elig.affiliations_hint"), rows: 5 });
  const save = button("elig-affiliations-save", t("elig.affiliations_save"), "submit");
  const form = h("form", { novalidate: true, "aria-label": t("elig.affiliations") }, [text.root, h("p", {}, [save])]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const affiliations = text.control.value;
    if (affiliations.trim() === "") {
      fieldError(text.control, text.error, t("elig.affiliations_required"));
      text.control.focus();
      return;
    }
    fieldError(text.control, text.error, null);
    save.disabled = true;
    setStatus(status, "saving", "");
    run(f, async () => {
      const r = await call("proposal.declare_affiliations", { proposal: id }, { affiliations }, decodeAccepted);
      save.disabled = false;
      if (!r.ok) {
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        return;
      }
      setStatus(status, "saved", t("elig.affiliations_saved"));
    });
  });
  return form;
}

/** Mounts the eligibility statements of proposal `id`. */
export function mountEligibility(id: string): void {
  const f = frame(t("elig.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!draftEditable(p.state)) {
      f.main.append(h("p", {}, [t("elig.readonly")]));
      return;
    }
    if (!leadActionsOffered(p.role)) {
      f.main.append(h("p", {}, [t("lead.only")]));
      return;
    }
    const status = statusRegion("elig-status");
    f.main.append(
      h("p", { id: "elig-intro" }, [t("elig.intro")]),
      countryForm(f, id, status),
      affiliationsForm(f, id, status),
      status,
    );
  });
}
