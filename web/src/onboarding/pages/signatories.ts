// The signatory roles and the activation of the organisation (SA-01,
// SA-02; `SPEC/02-domain/roles-and-sod.md` NOTE 5, SoD-07 and SoD-14 to
// SoD-18).
//
// - `#signatories` lists who holds Financial signatory and Legal
//   signatory (`tenant.list_signatories`). A binding is tenant-wide, so
//   no row names a programme. A tenant admin grants either role
//   (`tenant.grant_signatory`) or ends a binding (`tenant.end_signatory`).
//   Each changes an Operations role, so each needs the passkey step-up,
//   which `call` runs (I-78).
// - `#activation` shows the activation request, who made it and the
//   second tenant admin's approval (`tenant.get_activation`). One tenant
//   admin requests activation (`tenant.request_activation`) and another
//   approves it (`tenant.approve_activation`). Neither is high-risk (interim).
// - A refusal that names SoD-07, SoD-14, SoD-15, SoD-17 or SoD-18 is
//   explained in plain words from the catalogue. Every other outcome
//   shows as `report` shows it.
//
// What the signatories later approve, such as payment instructions and
// contracts, arrives in M5. These pages name none of those acts.

import { h } from "../../core/dom.js";
import type { Label } from "../../core/i18n.js";
import { busy, hush, warn } from "../../creator/frame.js";
import { anyObject, call, report, type Outcome } from "../../creator/ops.js";
import { t } from "../i18n.js";
import {
  SIGNATORY_ROLES,
  missingSignatories,
  readActivation,
  readSignatories,
  type ActivationView,
  type AdminRow,
  type SignatoryRole,
  type SignatoryRow,
} from "../model.js";

/** The rules whose refusals the catalogue explains in plain words. */
const EXPLAINED: ReadonlySet<string> = new Set(["SoD-07", "SoD-14", "SoD-15", "SoD-17", "SoD-18"]);

/**
 * Shows the outcome of a call that did not complete in `alert`, and
 * returns true. A refusal under a signatory or activation rule is
 * explained in plain words. A done call shows nothing and returns false.
 */
export function explain(alert: HTMLElement, o: Outcome): boolean {
  if (o.kind === "refused" && o.rule !== null && EXPLAINED.has(o.rule)) {
    warn(alert, t.label(`onboarding.refusal.${o.rule}`), o.rule);
    return true;
  }
  return report(alert, o);
}

/** The name of signatory role `r`. */
export function roleName(r: SignatoryRole): Label {
  return t.label(`onboarding.signatory.role.${r}`);
}

/** The handle of `account` among `admins`, else its account number. */
function who(account: string, admins: readonly AdminRow[]): Label {
  const a = admins.find((x) => x.account === account);
  return a === undefined
    ? t.label("onboarding.signatory.account", { account })
    : t.label("onboarding.admin.item", { handle: a.handle });
}

/** Reads the signatory bindings, or shows why not in `alert`. */
export async function loadSignatories(alert: HTMLElement): Promise<SignatoryRow[] | null> {
  const o = await call("tenant.list_signatories", [], undefined, (v) => readSignatories(v) !== null);
  if (explain(alert, o) || o.kind !== "done") return null;
  return readSignatories(o.body);
}

/** Reads the activation of the organisation, or shows why not in `alert`. */
export async function loadActivation(alert: HTMLElement): Promise<ActivationView | null> {
  const o = await call("tenant.get_activation", [], undefined, (v) => readActivation(v) !== null);
  if (explain(alert, o) || o.kind !== "done") return null;
  return readActivation(o.body);
}

/** The text that says which signatory roles still need a holder, or null when both have one. */
function missingText(rows: readonly SignatoryRow[]): Label | null {
  const missing = missingSignatories(rows);
  if (missing.length === 0) return null;
  return t.label("onboarding.signatory.missing", { roles: missing.map(roleName).join(", ") });
}

/**
 * The signatory section of the Administrators step: the holders of each
 * role, a control to end each binding, and a form to grant either role.
 * `reload` draws the page again after a change.
 */
export function signatorySection(
  alert: HTMLElement,
  admins: readonly AdminRow[],
  rows: readonly SignatoryRow[],
  reload: () => Promise<void>,
): HTMLElement {
  const status = h("p", { id: "signatory-status", role: "status", class: "fstp-status" });
  const groups = SIGNATORY_ROLES.map((role) => {
    const held = rows.filter((r) => r.role === role);
    const items = held.map((r) => {
      const end = h("button", { type: "button", "data-end-role": role, "data-end-account": r.account }, [
        t.label("onboarding.signatory.end", { role: roleName(role) }),
      ]);
      end.addEventListener(
        "click",
        busy(end, async () => {
          hush(alert);
          const o = await call("tenant.end_signatory", [role, r.account], undefined, anyObject);
          if (explain(alert, o)) return;
          status.textContent = t.label("onboarding.signatory.ended", { role: roleName(role) });
          await reload();
        }),
      );
      return h("li", { "data-account": r.account, "data-role": role }, [
        t.label("onboarding.admin.item", { handle: r.handle }),
        " ",
        end,
      ]);
    });
    return h("section", { "data-signatory-role": role, "aria-labelledby": `signatory-${role}-title` }, [
      h("h4", { id: `signatory-${role}-title` }, [roleName(role)]),
      items.length === 0
        ? h("p", { "data-empty": "true" }, [t.label("onboarding.signatory.none")])
        : h("ul", {}, items),
    ]);
  });
  const missing = missingText(rows);

  // The grant form: a tenant admin chosen from the list, or any account by number.
  const pick = h("select", { id: "signatory-account" }, [
    h("option", { value: "" }, [t.label("onboarding.signatory.pick")]),
    ...admins.map((a) => h("option", { value: a.account }, [t.label("onboarding.admin.item", { handle: a.handle })])),
  ]);
  const other = h("input", {
    id: "signatory-account-other",
    type: "text",
    inputmode: "numeric",
    autocomplete: "off",
    spellcheck: "false",
  });
  const roleChoices = SIGNATORY_ROLES.map((role, i) =>
    h("div", { class: "fstp-check" }, [
      h("input", { id: `signatory-role.${role}`, type: "radio", name: "signatory-role", value: role, checked: i === 0 }),
      h("label", { for: `signatory-role.${role}` }, [roleName(role)]),
    ]),
  );
  const grant = h("button", { id: "signatory-grant", type: "button" }, [t.label("onboarding.signatory.grant")]);
  grant.addEventListener(
    "click",
    busy(grant, async () => {
      hush(alert);
      const typed = other instanceof HTMLInputElement ? other.value.trim() : "";
      const picked = pick instanceof HTMLSelectElement ? pick.value : "";
      const account = typed !== "" ? typed : picked;
      if (!/^(0|[1-9][0-9]{0,38})$/.test(account)) {
        warn(alert, t.label("onboarding.signatory.account_invalid"));
        return;
      }
      let role: SignatoryRole | null = null;
      for (const r of SIGNATORY_ROLES) {
        const el = document.getElementById(`signatory-role.${r}`);
        if (el instanceof HTMLInputElement && el.checked) role = r;
      }
      if (role === null) {
        warn(alert, t.label("onboarding.signatory.role_missing"));
        return;
      }
      const o = await call("tenant.grant_signatory", [], { account, role }, anyObject);
      if (explain(alert, o)) return;
      if (other instanceof HTMLInputElement) other.value = "";
      status.textContent = t.label("onboarding.signatory.granted", { role: roleName(role), who: who(account, admins) });
      await reload();
    }),
  );
  return h("section", { id: "signatories", "aria-labelledby": "signatories-title" }, [
    h("h3", { id: "signatories-title" }, [t.label("onboarding.signatory.title")]),
    h("p", {}, [t.label("onboarding.signatory.intro")]),
    ...groups,
    missing === null ? h("p", { "data-complete": "true" }, [t.label("onboarding.signatory.complete")]) : h("p", { id: "signatory-missing" }, [missing]),
    h("h4", {}, [t.label("onboarding.signatory.grant_title")]),
    h("p", {}, [t.label("onboarding.signatory.grant_intro")]),
    h("div", { class: "fstp-control" }, [h("label", { for: "signatory-account" }, [t.label("onboarding.signatory.account_pick")]), pick]),
    h("div", { class: "fstp-control" }, [
      h("label", { for: "signatory-account-other" }, [t.label("onboarding.signatory.account_other")]),
      other,
    ]),
    h("fieldset", { class: "fstp-group" }, [h("legend", {}, [t.label("onboarding.signatory.role")]), ...roleChoices]),
    grant,
    status,
  ]);
}

/** The words of an activation state. */
function stateText(v: ActivationView, admins: readonly AdminRow[]): Label {
  switch (v.state) {
    case "not_requested":
      return t.label("onboarding.activation.not_requested");
    case "requested":
      return t.label("onboarding.activation.requested", { requester: who(v.requestedBy ?? "", admins) });
    case "active":
      return t.label("onboarding.activation.active", {
        requester: who(v.requestedBy ?? "", admins),
        approver: who(v.approvedBy ?? "", admins),
      });
  }
}

/**
 * The activation section of the summary: the state, the holders still
 * missing, and the action the state allows. Before a request any tenant
 * admin requests activation. While a request is open, a tenant admin
 * other than its requester approves it (SoD-18). `reload` draws the page
 * again after a change.
 */
export function activationSection(
  alert: HTMLElement,
  admins: readonly AdminRow[],
  view: ActivationView,
  rows: readonly SignatoryRow[],
  reload: () => Promise<void>,
): HTMLElement {
  const status = h("p", { id: "activation-outcome", role: "status", class: "fstp-status" });
  const parts: HTMLElement[] = [
    h("h2", { id: "activation-title" }, [t.label("onboarding.activation.title")]),
    h("p", {}, [t.label("onboarding.activation.intro")]),
    h("p", { id: "activation-state", "data-state": view.state }, [stateText(view, admins)]),
  ];
  const missing = missingText(rows);
  if (missing !== null && view.state !== "active") parts.push(h("p", { id: "activation-missing" }, [missing]));
  if (view.state === "not_requested") {
    const ask = h("button", { id: "activation-request", type: "button", class: "fstp-primary" }, [
      t.label("onboarding.activation.request"),
    ]);
    ask.addEventListener(
      "click",
      busy(ask, async () => {
        hush(alert);
        const o = await call("tenant.request_activation", [], {}, anyObject);
        if (explain(alert, o)) return;
        status.setAttribute("data-outcome", "requested");
        status.textContent = t.label("onboarding.activation.request_sent");
        await reload();
      }),
    );
    parts.push(ask);
  }
  const request = view.request;
  if (view.state === "requested" && request !== null) {
    parts.push(h("p", {}, [t.label("onboarding.activation.approve_intro")]));
    const approve = h("button", { id: "activation-approve", type: "button", class: "fstp-primary" }, [
      t.label("onboarding.activation.approve"),
    ]);
    approve.addEventListener(
      "click",
      busy(approve, async () => {
        hush(alert);
        const o = await call("tenant.approve_activation", [], { request }, anyObject);
        if (explain(alert, o)) return;
        status.setAttribute("data-outcome", "active");
        status.textContent = t.label("onboarding.activation.approved");
        await reload();
      }),
    );
    parts.push(approve);
  }
  parts.push(status);
  return h("section", { id: "activation", "aria-labelledby": "activation-title" }, parts);
}

