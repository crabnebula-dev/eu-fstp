// The team of a proposal (`proposal.add_member`, `proposal.add_guardian`,
// `proposal.team_invitations`, `proposal.withdraw_team_invitation`;
// journey J4, I-18, R-NG-01, state-machine NOTE 14, F-079, ADR-038).
//
// The lead invites team members while the draft is written, and invites
// the guardian whose consent a minor-flagged proposal needs before
// NEGOTIATION and before GRANTED. Only the lead invites (registry LEAD;
// `ActorRule::Lead`), so the page shows no form to anyone else.
//
// The page asks only for what an invitation needs: the invitee's email
// address. It asks for no identity attribute, such as a name, a birth
// date or a document. Nobody joins until they sign in with that address
// and accept the invitation on `/app/team-invitations` (Daniel,
// 2026-11-23). The invitation's answer is the same whatever the address
// names, and the list reads only `open`, `joined` or `not_joined`, so the
// page learns nothing else about the people it invites (TH-08, R-AN-01).

import { h } from "../core/dom.js";
import { type ApplicantOp, call } from "./client.js";
import { isEmail } from "./email.js";
import { type LeadInvitation, decodeLeadInvitations } from "./invitations.js";
import { loadProposal } from "./load.js";
import { guardianAddOffered, leadActionsOffered, teamEditable } from "./rules.js";
import {
  APP,
  type Frame,
  button,
  clearAlert,
  fieldError,
  frame,
  instantTime,
  run,
  setStatus,
  showFailure,
  statusRegion,
  t,
  textInput,
} from "./ui.js";
import { decodeAccepted } from "./wire.js";

/** One invitation form: its operation and the ids and texts it uses. */
interface Invite {
  readonly op: Extract<ApplicantOp, "proposal.add_member" | "proposal.add_guardian">;
  /** The id prefix of its elements. */
  readonly prefix: string;
  /** The message key prefix of its texts. */
  readonly keys: string;
}

const MEMBER: Invite = { op: "proposal.add_member", prefix: "team-member", keys: "team.member" };
const GUARDIAN: Invite = { op: "proposal.add_guardian", prefix: "team-guardian", keys: "team.guardian" };

function inviteForm(f: Frame, id: string, invite: Invite, reload: () => void): HTMLElement {
  const heading = `${invite.prefix}-heading`;
  const email = textInput(`${invite.prefix}-email`, t(`${invite.keys}.email`), {
    type: "email",
    autocomplete: "off",
    maxlength: 254,
  });
  const send = button(`${invite.prefix}-send`, t(`${invite.keys}.send`), "submit");
  const status = statusRegion(`${invite.prefix}-status`);
  const form = h("form", { novalidate: true, "aria-labelledby": heading }, [email.root, h("p", {}, [send])]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearAlert(f);
    const to = email.control.value.trim();
    if (!isEmail(to)) {
      fieldError(email.control, email.error, t("team.email_invalid"));
      email.control.focus();
      return;
    }
    fieldError(email.control, email.error, null);
    send.disabled = true;
    setStatus(status, "saving", "");
    run(f, async () => {
      const r = await call(invite.op, { proposal: id }, { email: to }, decodeAccepted);
      send.disabled = false;
      if (!r.ok) {
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        return;
      }
      // The address is not kept in the form once the invitation is sent.
      email.control.value = "";
      setStatus(status, "saved", t(`${invite.keys}.sent`));
      reload();
    });
  });
  return h("section", { "aria-labelledby": heading }, [
    h("h2", { id: heading }, [t(`${invite.keys}.heading`)]),
    h("p", {}, [t(`${invite.keys}.intro`)]),
    form,
    status,
  ]);
}

/** The browser's zone, for the expiry. */
function zone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "UTC";
  }
}

/** One row of the lead's invitations, with Withdraw while it is open. */
function invitationRow(f: Frame, id: string, i: LeadInvitation, reload: () => void): HTMLElement {
  const kids: (HTMLElement | string)[] = [
    h("span", { "data-email": "" }, [i.email]),
    " ",
    t(`team.invitations.role.${i.role}`),
    " ",
    h("span", { class: "badge", "data-state": i.state }, [t(`team.invitations.state.${i.state}`)]),
  ];
  const row = h("li", { "data-invitation": i.invitation }, kids);
  if (i.state === "open") {
    row.append(" ", h("span", { class: "fstp-meta" }, [t("team.invitations.expires"), " ", instantTime(i.expires, zone())]));
    const withdraw = button(`team-invitation-${i.invitation}-withdraw`, t("team.invitations.withdraw"));
    withdraw.addEventListener("click", () => {
      clearAlert(f);
      withdraw.disabled = true;
      run(f, async () => {
        const r = await call(
          "proposal.withdraw_team_invitation",
          { proposal: id, invitation: i.invitation },
          {},
          decodeAccepted,
        );
        if (!r.ok) {
          withdraw.disabled = false;
          showFailure(f, r.failure);
          return;
        }
        reload();
      });
    });
    row.append(" ", withdraw);
  }
  return row;
}

/** The lead's invitations of proposal `id`, reloaded after each change. */
function invitationsSection(f: Frame, id: string): { readonly root: HTMLElement; readonly reload: () => void } {
  const list = h("ul", { id: "team-invitations", class: "stack" }, []);
  const reload = (): void => {
    run(f, async () => {
      const r = await call("proposal.team_invitations", { proposal: id }, undefined, decodeLeadInvitations);
      if (!r.ok) {
        showFailure(f, r.failure);
        return;
      }
      list.replaceChildren(
        ...(r.value.length === 0
          ? [h("li", {}, [t("team.invitations.none")])]
          : r.value.map((i) => invitationRow(f, id, i, reload))),
      );
    });
  };
  const root = h("section", { "aria-labelledby": "team-invitations-heading" }, [
    h("h2", { id: "team-invitations-heading" }, [t("team.invitations.heading")]),
    list,
  ]);
  return { root, reload };
}

/** Mounts the team page of proposal `id`. */
export function mountTeam(id: string): void {
  const f = frame(t("team.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!leadActionsOffered(p.role)) {
      f.main.append(h("p", {}, [t("lead.only")]));
      return;
    }
    const invitations = invitationsSection(f, id);
    const members = teamEditable(p.state);
    const guardian = guardianAddOffered(p.state);
    if (!members && !guardian) {
      f.main.append(h("p", {}, [t("team.closed")]), invitations.root);
      invitations.reload();
      return;
    }
    f.main.append(h("p", {}, [t("team.intro")]));
    if (members) {
      f.main.append(inviteForm(f, id, MEMBER, invitations.reload));
    }
    if (guardian) {
      f.main.append(inviteForm(f, id, GUARDIAN, invitations.reload));
    }
    f.main.append(invitations.root);
    invitations.reload();
  });
}
