// Team invitations (F-079, ADR-038; I-17, TH-08, R-AN-01).
//
// A person joins the team of a proposal, or becomes its guardian, only
// by accepting an invitation. The lead invites an email address on the
// team page. The person signs in with that address and answers here, on
// `/app/team-invitations` (`me.team_invitations`,
// `me.accept_team_invitation`, `me.decline_team_invitation`).
//
// Only an acceptance runs the checks of the binding. A refusal is shown
// to the person on this page and nowhere else. The lead reads only
// whether the person joined.

import { h } from "../core/dom.js";
import { call } from "./client.js";
import {
  APP,
  type Frame,
  button,
  clearAlert,
  frame,
  instantTime,
  run,
  setStatus,
  showFailure,
  statusRegion,
  t,
} from "./ui.js";
import { type Instant, decodeAccepted, instantOfMicros, isId } from "./wire.js";

/** The role an invitation offers. */
export type InvitedRole = "team_member" | "guardian";

/** One open invitation addressed to the caller. */
export interface OwnInvitation {
  readonly invitation: string;
  readonly proposal: string;
  readonly role: InvitedRole;
  readonly expires: Instant;
}

/** One invitation as the lead reads it. */
export interface LeadInvitation {
  readonly invitation: string;
  readonly email: string;
  readonly role: InvitedRole;
  readonly state: "open" | "joined" | "not_joined";
  readonly expires: Instant;
}

type Rec = Readonly<Record<string, unknown>>;

function rec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}

function rows(v: unknown): readonly Rec[] | null {
  const list = rec(v)?.["invitations"];
  if (!Array.isArray(list)) {
    return null;
  }
  const out: Rec[] = [];
  for (const r of list) {
    const o = rec(r);
    if (o === null) {
      return null;
    }
    out.push(o);
  }
  return out;
}

function role(v: unknown): InvitedRole | null {
  return v === "team_member" || v === "guardian" ? v : null;
}

/** Decodes `me.team_invitations`, or null for any other shape. */
export function decodeOwnInvitations(v: unknown): readonly OwnInvitation[] | null {
  const list = rows(v);
  if (list === null) {
    return null;
  }
  const out: OwnInvitation[] = [];
  for (const o of list) {
    const r = role(o["role"]);
    const expires = instantOfMicros(o["expires"]);
    const invitation = o["invitation"];
    const proposal = o["proposal"];
    if (r === null || expires === null || !isId(invitation) || !isId(proposal)) {
      return null;
    }
    out.push(Object.freeze({ invitation, proposal, role: r, expires }));
  }
  return Object.freeze(out);
}

/** Decodes `proposal.team_invitations`, or null for any other shape. */
export function decodeLeadInvitations(v: unknown): readonly LeadInvitation[] | null {
  const list = rows(v);
  if (list === null) {
    return null;
  }
  const out: LeadInvitation[] = [];
  for (const o of list) {
    const r = role(o["role"]);
    const expires = instantOfMicros(o["expires"]);
    const invitation = o["invitation"];
    const email = o["email"];
    const state = o["state"];
    if (
      r === null ||
      expires === null ||
      !isId(invitation) ||
      typeof email !== "string" ||
      (state !== "open" && state !== "joined" && state !== "not_joined")
    ) {
      return null;
    }
    out.push(Object.freeze({ invitation, email, role: r, state, expires }));
  }
  return Object.freeze(out);
}

/** The browser's zone, for the expiry. */
function zone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "UTC";
  }
}

/** The number of open invitations addressed to the caller, or null. */
export async function teamInvitationCount(): Promise<number | null> {
  const r = await call("me.team_invitations", {}, undefined, decodeOwnInvitations);
  return r.ok ? r.value.length : null;
}

/** One invitation with its two answers. */
function invitationItem(f: Frame, i: OwnInvitation, reload: () => void): HTMLElement {
  const status = statusRegion(`invitation-${i.invitation}-status`);
  const accept = button(`invitation-${i.invitation}-accept`, t("invitations.accept"));
  const decline = button(`invitation-${i.invitation}-decline`, t("invitations.decline"));
  const answer = (op: "me.accept_team_invitation" | "me.decline_team_invitation"): void => {
    clearAlert(f);
    accept.disabled = true;
    decline.disabled = true;
    setStatus(status, "saving", "");
    run(f, async () => {
      const r = await call(op, { invitation: i.invitation }, {}, decodeAccepted);
      if (!r.ok) {
        accept.disabled = false;
        decline.disabled = false;
        setStatus(status, "failed", "");
        showFailure(f, r.failure);
        return;
      }
      if (op === "me.accept_team_invitation") {
        status.replaceChildren(
          h("a", { href: APP.proposal(i.proposal), "data-joined": i.proposal }, [t("invitations.accepted")]),
        );
        return;
      }
      reload();
    });
  };
  accept.addEventListener("click", () => answer("me.accept_team_invitation"));
  decline.addEventListener("click", () => answer("me.decline_team_invitation"));
  return h("li", { "data-invitation": i.invitation }, [
    h("p", {}, [t(`invitations.role.${i.role}`), " ", t("invitations.proposal", { id: i.proposal })]),
    h("p", { class: "fstp-meta" }, [t("invitations.expires"), " ", instantTime(i.expires, zone())]),
    h("p", {}, [accept, " ", decline]),
    status,
  ]);
}

/** Mounts `/app/team-invitations`. */
export function mountTeamInvitations(): void {
  const f = frame(t("invitations.title"));
  f.main.append(h("p", {}, [t("invitations.intro")]));
  const list = h("ul", { id: "team-invitations", class: "stack" }, []);
  f.main.append(list);
  const load = (): void => {
    run(f, async () => {
      const r = await call("me.team_invitations", {}, undefined, decodeOwnInvitations);
      if (!r.ok) {
        showFailure(f, r.failure);
        return;
      }
      if (r.value.length === 0) {
        list.replaceChildren(h("li", {}, [t("invitations.none")]));
        return;
      }
      list.replaceChildren(...r.value.map((i) => invitationItem(f, i, load)));
    });
  };
  load();
}
