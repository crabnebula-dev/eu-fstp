// The invitations of the creator's People step, step 9 (J1, SoD-01 to
// SoD-13, D3; M4 design sections 2.2 and 3.2).
//
// `#invite-form` invites one person to one role (`creator.invite`).
// `#invitations` lists every invitation of the programme with its state
// and the live separation of duties check: `pass`, `fail`, or
// `unchecked` while the invitee has no account yet. A failed check names
// the rule only, never an account (R-CF-03). The grant itself happens on
// the people admin page, with its own step-up.

import { h } from "../core/dom.js";
import { hush, warn } from "../creator/frame.js";
import { anyObject, call, report } from "../creator/ops.js";
import { ROLES, plausibleEmail, readInvitations, type InvitationRow } from "./model.js";
import { roleLabel, t } from "./i18n.js";

/** The `li` of one invitation, with its state and SoD check as attributes and text. */
export function invitationItem(row: InvitationRow): HTMLElement {
  const sod =
    row.sod === "pass"
      ? t.label("people.sod.pass")
      : row.sod === "fail"
        ? row.rule === null
          ? t.label("people.sod.fail")
          : t.label("people.sod.fail_rule", { rule: row.rule })
        : t.label("people.sod.unchecked");
  const state =
    row.state === "invited"
      ? t.label("people.state.invited")
      : row.state === "accepted"
        ? t.label("people.state.accepted")
        : row.state === "verified"
          ? t.label("people.state.verified")
          : t.label("people.state.granted");
  return h(
    "li",
    { "data-invitation": row.id, "data-email": row.email, "data-sod": row.sod, "data-state": row.state },
    [
      h("span", { class: "fstp-email" }, [row.email]),
      " ",
      t.label("people.invitation.summary", { role: roleLabel(row.role), state, sod }),
    ],
  );
}

/** Reads the invitations of `p` into `list`. False when the read failed, shown in `alert`. */
export async function loadInvitations(
  p: string,
  alert: HTMLElement,
  list: HTMLElement,
  item: (row: InvitationRow) => HTMLElement = invitationItem,
): Promise<InvitationRow[] | null> {
  const o = await call("creator.list_invitations", [p], undefined, (v) => readInvitations(v) !== null);
  if (report(alert, o) || o.kind !== "done") return null;
  const rows = readInvitations(o.body) ?? [];
  list.replaceChildren(...rows.map(item));
  if (rows.length === 0) {
    list.append(h("li", {}, [t.label("people.invitations.none")]));
  }
  return rows;
}

/** The invitation form and list of programme `p`. Refusals show in `alert`. */
export function inviteSection(p: string, alert: HTMLElement): HTMLElement {
  const list = h("ul", { id: "invitations", "aria-labelledby": "invitations-title" });
  const email = h("input", { id: "invite-email", type: "email", autocomplete: "off", spellcheck: "false", required: true });
  const role = h("select", { id: "invite-role" }, ROLES.map((r) => h("option", { value: r }, [roleLabel(r)])));
  const organisation = h("input", { id: "invite-organisation", type: "text", inputmode: "numeric", autocomplete: "off" });
  const submit = h("button", { id: "invite-submit", type: "submit" }, [t.label("people.invite.submit")]);
  const status = h("p", { id: "invite-status", role: "status", class: "fstp-status" });
  const form = h("form", { id: "invite-form", novalidate: true }, [
    h("div", { class: "fstp-control" }, [h("label", { for: "invite-email" }, [t.label("people.invite.email")]), email]),
    h("div", { class: "fstp-control" }, [h("label", { for: "invite-role" }, [t.label("people.invite.role")]), role]),
    h("div", { class: "fstp-control" }, [
      h("label", { for: "invite-organisation" }, [t.label("people.invite.organisation")]),
      organisation,
      h("p", { class: "fstp-hint", id: "invite-organisation-hint" }, [t.label("people.invite.organisation_hint")]),
    ]),
    submit,
  ]);
  organisation.setAttribute("aria-describedby", "invite-organisation-hint");
  let sending = false;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (sending) return;
    const address = email instanceof HTMLInputElement ? email.value.trim() : "";
    const chosen = role instanceof HTMLSelectElement ? role.value : "";
    const org = organisation instanceof HTMLInputElement ? organisation.value.trim() : "";
    hush(alert);
    if (!plausibleEmail(address)) {
      warn(alert, t.label("people.invite.email_invalid"));
      email.setAttribute("aria-invalid", "true");
      email.focus();
      return;
    }
    if (org !== "" && !/^[0-9]{1,39}$/.test(org)) {
      warn(alert, t.label("people.invite.organisation_invalid"));
      organisation.focus();
      return;
    }
    email.removeAttribute("aria-invalid");
    sending = true;
    submit.setAttribute("aria-busy", "true");
    const body: Record<string, string> = { email: address, role: chosen };
    if (org !== "") body["organisation"] = org;
    void (async () => {
      try {
        const o = await call("creator.invite", [p], body, anyObject);
        if (report(alert, o)) return;
        status.textContent = t.label("people.invite.sent", { email: address });
        if (email instanceof HTMLInputElement) email.value = "";
        await loadInvitations(p, alert, list);
      } finally {
        sending = false;
        submit.removeAttribute("aria-busy");
      }
    })();
  });
  void loadInvitations(p, alert, list);
  return h("section", { id: "people-invitations", "aria-labelledby": "invite-title" }, [
    h("h2", { id: "invite-title" }, [t.label("people.invite.title")]),
    h("p", {}, [t.label("people.invite.intro")]),
    form,
    status,
    h("h3", { id: "invitations-title" }, [t.label("people.invitations.title")]),
    list,
  ]);
}
