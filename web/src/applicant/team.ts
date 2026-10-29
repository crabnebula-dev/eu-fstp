// The team of a proposal (`proposal.add_member`, `proposal.add_guardian`;
// journey J4, I-18, R-NG-01, state-machine NOTE 14).
//
// The lead invites team members while the draft is written, and adds the
// guardian whose consent a minor-flagged proposal needs before
// NEGOTIATION and before GRANTED. Only the lead adds people (registry
// LEAD; `ActorRule::Lead`), so the page shows no form to anyone else.
//
// The page asks only for what an invitation needs: the invitee's email
// address. It asks for no identity attribute, such as a name, a birth
// date or a document, and it reads nothing back about the people it
// invites. The cell and the vault do the rest.
//
// Interim, pending lanes W3b and W5: both bodies are `{email}`. The cell
// resolves or invites the account, then binds it with `AddTeamMember` or
// `AddGuardian`, and answers `{accepted: true}`.

import { h } from "../core/dom.js";
import { type ApplicantOp, call } from "./client.js";
import { isEmail } from "./email.js";
import { loadProposal } from "./load.js";
import { guardianAddOffered, leadActionsOffered, teamEditable } from "./rules.js";
import {
  APP,
  type Frame,
  button,
  clearAlert,
  fieldError,
  frame,
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

function inviteForm(f: Frame, id: string, invite: Invite): HTMLElement {
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
      // The address is not kept on the page once the invitation is sent.
      email.control.value = "";
      setStatus(status, "saved", t(`${invite.keys}.sent`));
    });
  });
  return h("section", { "aria-labelledby": heading }, [
    h("h2", { id: heading }, [t(`${invite.keys}.heading`)]),
    h("p", {}, [t(`${invite.keys}.intro`)]),
    form,
    status,
  ]);
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
    const members = teamEditable(p.state);
    const guardian = guardianAddOffered(p.state);
    if (!members && !guardian) {
      f.main.append(h("p", {}, [t("team.closed")]));
      return;
    }
    f.main.append(h("p", {}, [t("team.intro")]));
    if (members) {
      f.main.append(inviteForm(f, id, MEMBER));
    }
    if (guardian) {
      f.main.append(inviteForm(f, id, GUARDIAN));
    }
  });
}
