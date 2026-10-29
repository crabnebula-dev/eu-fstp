// The approval inbox of tenant admins, `/app/admin/approvals` (R-PG-03,
// I-66, I-67, SoD-07; M4 design sections 2.2 J1 and J2, and 3.2).
//
// - An activation request shows as
//   `li[data-approval="activation"][data-programme]`. Approving it is
//   high-risk, so the server asks for a step-up. A builder of the draft
//   is never offered the approval (I-67), and the server refuses one
//   anyway, before any step-up.
// - A tenant admin's grant of a role to their own account shows as
//   `li[data-approval="self_grant"][data-id]`. A second admin approves it
//   with step-up (`admin.approve_self_grant`, SoD-07). The requesting
//   admin is never offered the approval, and the server refuses one
//   anyway. The grant on the people admin page then names the approval.
// - A refusal shows in `#approval-error` with the rule it names.
//
// The recovery and break-glass approvals of J10 belong to lane W4d, so
// this page lists activation and self-grant requests only.
//
// Interim, pending Daniel and lane W3a: the self-grant row and the empty
// body of `POST /admin/approvals/{a}` are this lane's reading. The
// server knows the grant an approval belongs to, so the page sends none.

import { h } from "../../core/dom.js";
import { roleLabel } from "../../people/i18n.js";
import { busy, frame, hush, ready } from "../frame.js";
import { t } from "../i18n.js";
import { readApprovals, type ApprovalRow } from "../model.js";
import { anyObject, call, report } from "../ops.js";
import { PATHS, link, loadDraft } from "./common.js";

/** Mounts the approval inbox. */
export function mount(): void {
  const { main, alert } = frame({ title: t.label("creator.approvals.title"), alertId: "approval-error" });
  const list = h("ul", { id: "approvals", "aria-labelledby": "approvals-title" });
  const grants = h("ul", { id: "self-grants", "aria-labelledby": "self-grants-title" });

  const activation = (row: ApprovalRow): HTMLElement => {
    const name = row.name ?? row.programme;
    const state = h("p", { role: "status", class: "fstp-status" });
    const li = h("li", { "data-approval": "activation", "data-programme": row.programme }, [
      h("h3", {}, [t.label("creator.approvals.activation", { name })]),
      h("p", {}, [link(PATHS.step(row.programme, "review"), t.label("creator.approvals.review", { name }))]),
    ]);
    if (!row.approvable) {
      li.append(h("p", {}, [t.label("creator.approvals.builder")]));
      return li;
    }
    const approve = h("button", { type: "button", "data-action": "approve", class: "fstp-primary" }, [
      t.label("creator.approvals.approve", { name }),
    ]);
    approve.addEventListener(
      "click",
      busy(approve, async () => {
        hush(alert);
        let revision = row.revision;
        if (revision === null) {
          const d = await loadDraft(row.programme, alert);
          if (d === null) return;
          revision = d.revision;
        }
        const o = await call("creator.approve_activation", [row.programme], { revision }, anyObject);
        if (report(alert, o)) return;
        approve.remove();
        li.setAttribute("data-status", "approved");
        state.textContent = t.label("creator.approvals.approved");
      }),
    );
    li.append(approve, state);
    return li;
  };

  const selfGrant = (row: ApprovalRow, approval: string, role: string, grantee: string): HTMLElement => {
    const name = row.name ?? row.programme;
    const roleName = roleLabel(role);
    const state = h("p", { role: "status", class: "fstp-status" });
    const li = h("li", { "data-approval": "self_grant", "data-id": approval, "data-programme": row.programme }, [
      h("h3", {}, [t.label("creator.approvals.self_grant", { handle: grantee, role: roleName, name })]),
    ]);
    if (!row.approvable) {
      li.append(h("p", {}, [t.label("creator.approvals.own_grant")]));
      return li;
    }
    const approve = h("button", { type: "button", "data-action": "approve", class: "fstp-primary" }, [
      t.label("creator.approvals.approve_grant", { handle: grantee, role: roleName }),
    ]);
    approve.addEventListener(
      "click",
      busy(approve, async () => {
        hush(alert);
        const o = await call("admin.approve_self_grant", [approval], {}, anyObject);
        if (report(alert, o)) return;
        approve.remove();
        li.setAttribute("data-status", "approved");
        state.textContent = t.label("creator.approvals.grant_approved", { handle: grantee });
      }),
    );
    li.append(approve, state);
    return li;
  };

  main.append(
    h("p", {}, [t.label("creator.approvals.intro")]),
    h("h2", { id: "approvals-title" }, [t.label("creator.approvals.pending")]),
    list,
    h("h2", { id: "self-grants-title" }, [t.label("creator.approvals.self_grants")]),
    h("p", {}, [t.label("creator.approvals.self_grants_intro")]),
    grants,
  );

  void (async () => {
    const o = await call("admin.list_approvals", [], undefined, (v) => readApprovals(v) !== null);
    if (report(alert, o) || o.kind !== "done") return;
    const rows = readApprovals(o.body) ?? [];
    const activations = rows.filter((r) => r.kind === "activation");
    list.replaceChildren(...activations.map(activation));
    if (activations.length === 0) {
      list.append(h("li", {}, [t.label("creator.approvals.none")]));
    }
    const own: HTMLElement[] = [];
    for (const r of rows) {
      if (r.kind === "self_grant" && r.approval !== null && r.role !== null && r.grantee !== null) {
        own.push(selfGrant(r, r.approval, r.role, r.grantee));
      }
    }
    grants.replaceChildren(...own);
    if (own.length === 0) {
      grants.append(h("li", {}, [t.label("creator.approvals.no_self_grants")]));
    }
    ready(main);
  })();
}
