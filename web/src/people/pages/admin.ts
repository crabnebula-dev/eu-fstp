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

import { h } from "../../core/dom.js";
import { busy, frame, hush, ready } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { loadDraft } from "../../creator/pages/common.js";
import { invitationItem, loadInvitations } from "../invite.js";
import { grantBody, grantOffered, type InvitationRow } from "../model.js";
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

  void (async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    programme = d.status;
    if ((await loadInvitations(p, alert, list, item)) !== null) ready(main);
  })();
}
