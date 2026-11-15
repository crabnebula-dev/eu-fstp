// The people admin page, `/app/programmes/{p}/people` (J1, J2, SoD-09,
// D1, R-LG-03; M4 design section 2.2).
//
// A tenant admin grants each role here, one by one. The grant is offered
// only for an invitee who accepted the confidentiality terms and
// verified identity, and while the programme is a draft only for a
// programme manager (`grantOffered`). Granting a role is high-risk, so
// the server asks for a step-up for each grant.
//
// A tenant admin's grant of a role to their own account needs a second
// admin's approval first (SoD-07). That admin approves it in the approval
// inbox (`admin.approve_self_grant`). The grant then names the approval
// the invitation row carries (`grantBody`), and the server consumes it.
// Without one, the server refuses the grant and names SoD-07.
//
// "Current roles" lists the programme's staff bindings by account id
// (`roles.list`, tenant admins only). An active role can be ended
// (`roles.end`) and a suspended one reinstated with a reason
// (`roles.reinstate`). Both are high-risk, so each asks for a step-up.
// For anyone else the section stays hidden.

import { h } from "../../core/dom.js";
import { busy, frame, hush, ready, warn } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { loadDraft } from "../../creator/pages/common.js";
import { invitationItem, loadInvitations } from "../invite.js";
import {
  bindingActions,
  grantBody,
  grantOffered,
  readBindings,
  reinstateBody,
  type BindingRow,
  type InvitationRow,
} from "../model.js";
import { roleLabel, t } from "../i18n.js";

/** Mounts the people admin page of programme `p`. */
export function mount(p: string): void {
  const { main, alert } = frame({ title: t.label("people.admin.title"), alertId: "people-error" });
  const list = h("ul", { id: "invitations", "aria-labelledby": "invitations-title" });
  let programme: "draft" | "active" = "draft";

  const item = (row: InvitationRow): HTMLElement => {
    const li = invitationItem(row);
    if (!grantOffered(programme, row.role, row.state)) {
      return li;
    }
    const grant = h("button", { type: "button", "data-action": "grant", class: "fstp-primary" }, [
      t.label("people.admin.grant", { role: roleLabel(row.role), email: row.email }),
    ]);
    grant.addEventListener(
      "click",
      busy(grant, async () => {
        hush(alert);
        const o = await call("roles.grant", [p], grantBody(row), anyObject);
        if (report(alert, o)) return;
        await loadInvitations(p, alert, list, item);
        await loadBindings();
        const again = list.querySelector(`li[data-invitation="${row.id}"]`);
        if (again instanceof HTMLElement) {
          again.setAttribute("tabindex", "-1");
          again.focus();
        }
      }),
    );
    li.append(" ", grant);
    return li;
  };

  main.append(
    h("p", {}, [t.label("people.admin.intro")]),
    h("h2", { id: "invitations-title" }, [t.label("people.invitations.title")]),
    list,
  );

  const bindings = h("ul", { id: "bindings", "aria-labelledby": "bindings-title" });
  const section = h("section", { id: "bindings-section", "aria-labelledby": "bindings-title", hidden: true }, [
    h("h2", { id: "bindings-title" }, [t.label("people.bindings.title")]),
    h("p", {}, [t.label("people.bindings.intro")]),
    bindings,
  ]);
  main.append(section);

  const refocus = (id: string): void => {
    const again = bindings.querySelector(`li[data-binding="${id}"]`);
    if (again instanceof HTMLElement) {
      again.setAttribute("tabindex", "-1");
      again.focus();
    }
  };

  const bindingItem = (row: BindingRow): HTMLElement => {
    const role = roleLabel(row.role);
    const state =
      row.state === "active"
        ? t.label("people.bindings.active")
        : row.state === "suspended"
          ? row.rule === null
            ? t.label("people.bindings.suspended")
            : t.label("people.bindings.suspended_rule", { rule: row.rule })
          : row.rule === null
            ? t.label("people.bindings.voided")
            : t.label("people.bindings.voided_rule", { rule: row.rule });
    const li = h("li", { "data-binding": row.binding, "data-account": row.account, "data-state": row.state }, [
      t.label("people.bindings.summary", { role, account: row.account, state }),
    ]);
    for (const action of bindingActions(row)) {
      if (action === "end") {
        const end = h("button", { type: "button", "data-action": "end" }, [
          t.label("people.bindings.end", { role, account: row.account }),
        ]);
        end.addEventListener(
          "click",
          busy(end, async () => {
            hush(alert);
            const o = await call("roles.end", [p, row.binding], {}, anyObject);
            if (report(alert, o)) return;
            await loadBindings();
            refocus(row.binding);
          }),
        );
        li.append(" ", end);
      } else {
        const inputId = `reason-${row.binding}`;
        const reason = h("input", { id: inputId, type: "text", autocomplete: "off" });
        const reinstate = h("button", { type: "button", "data-action": "reinstate" }, [
          t.label("people.bindings.reinstate", { role, account: row.account }),
        ]);
        reinstate.addEventListener(
          "click",
          busy(reinstate, async () => {
            hush(alert);
            const body = reinstateBody(reason instanceof HTMLInputElement ? reason.value : "");
            if (body === null) {
              warn(alert, t.label("people.bindings.reason_missing"));
              reason.focus();
              return;
            }
            const o = await call("roles.reinstate", [p, row.binding], body, anyObject);
            if (report(alert, o)) return;
            await loadBindings();
            refocus(row.binding);
          }),
        );
        li.append(
          " ",
          h("span", { class: "fstp-control" }, [
            h("label", { for: inputId }, [t.label("people.bindings.reason", { account: row.account })]),
            reason,
          ]),
          " ",
          reinstate,
        );
      }
    }
    return li;
  };

  // Only a tenant admin reads the bindings. A refusal keeps the section
  // hidden and shows no alert, so a programme manager sees the page as
  // before.
  async function loadBindings(): Promise<void> {
    const o = await call("roles.list", [p], undefined, (v) => readBindings(v) !== null);
    if (o.kind !== "done") return;
    const rows = readBindings(o.body) ?? [];
    bindings.replaceChildren(...rows.map(bindingItem));
    if (rows.length === 0) {
      bindings.append(h("li", {}, [t.label("people.bindings.none")]));
    }
    section.hidden = false;
  }

  void (async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    programme = d.status;
    const loaded = await loadInvitations(p, alert, list, item);
    await loadBindings();
    if (loaded !== null) ready(main);
  })();
}
