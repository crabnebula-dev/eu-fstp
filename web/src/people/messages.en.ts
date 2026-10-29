// The English catalogue of the people pages (R-NF-04, I-72). Every
// user-visible string of `web/src/people` comes from here. The
// confidentiality terms are approved text, which no terminology override
// reaches.

import type { CatalogueInput } from "../core/i18n.js";

const LABELS: Readonly<Record<string, string>> = {
  // Roles.
  "people.role.unnamed": "Role {role}",
  "people.role.programme_manager": "Programme manager",
  "people.role.call_drafter": "Call drafter",
  "people.role.fstp_coordinator": "FSTP coordinator",
  "people.role.committee_member": "Committee member",
  "people.role.committee_chair": "Committee chair",
  "people.role.irc_member": "IRC member",

  // The invitation form of the People step.
  "people.invite.title": "Invitations",
  "people.invite.intro":
    "Invite each person to one role. The separation of duties check runs as soon as the invitee has an account.",
  "people.invite.email": "Email address",
  "people.invite.email_invalid": "Enter an email address in the form name@example.org.",
  "people.invite.role": "Role",
  "people.invite.organisation": "Organisation, for committee members (optional)",
  "people.invite.organisation_hint": "The identifier of the organisation the person reviews for.",
  "people.invite.organisation_invalid": "An organisation identifier is a number.",
  "people.invite.submit": "Send the invitation",
  "people.invite.sent": "An invitation is on its way to {email}.",

  // The invitation list.
  "people.invitations.title": "Invited people",
  "people.invitations.none": "No one is invited yet.",
  "people.invitation.summary": "{role}. {state}. {sod}",
  "people.state.invited": "Invited",
  "people.state.accepted": "Terms accepted, identity not verified yet",
  "people.state.verified": "Terms accepted and identity verified",
  "people.state.granted": "Role granted",
  "people.sod.pass": "Separation of duties check passed.",
  "people.sod.fail": "Separation of duties check failed.",
  "people.sod.fail_rule": "Separation of duties check failed under rule {rule}.",
  "people.sod.unchecked": "Separation of duties check waits for an account.",

  // The people admin page.
  "people.admin.title": "People of this programme",
  "people.admin.intro":
    "Grant each role once the invitee accepted the terms and verified identity. Each grant needs your passkey.",
  "people.admin.grant": "Grant {role} to {email}",

  // The invitation landing.
  "people.invitation.title": "Your invitation",
  "people.invitation.intro": "Read the terms below. Accepting them is the first step to your role.",
  "people.invitation.bad_link": "This invitation link is incomplete. Open the whole link from your email.",
  "people.invitation.terms_title": "Confidentiality terms for the role of {role}",
  "people.invitation.accept": "Accept the terms",
  "people.invitation.enrolling": "Creating a passkey for your new account.",
  "people.invitation.enrol_failed": "Your passkey could not be created. Try again.",
  "people.invitation.accepted": "You accepted the terms.",
  "people.invitation.verify_intro":
    "Verify your identity next. A tenant admin can grant your role only after that.",
  "people.invitation.verify": "Start identity verification",
  "people.invitation.verification_started": "Your identity verification has started.",
  "people.invitation.verification_continue": "Continue the verification",
  "people.invitation.undecided":
    "The programme has not made every choice these terms state yet, so they cannot be accepted. Open this link again later.",
};

// TODO(legal): the confidentiality terms below are placeholders until
// Daniel supplies the approved wording (design section 2.2, J2). They
// state the programme's P-75 and P-77 choices, as J2 requires for
// Judging roles, and no other legal content.
const APPROVED: Readonly<Record<string, string>> = {
  "people.terms.body": "Confidentiality terms for the role of {role}, version {version}. The approved wording is pending.",
  "people.terms.p75_on": "In this programme, reviewers' agents may read full proposal content (P-75).",
  "people.terms.p75_off": "In this programme, reviewers' agents may not read full proposal content (P-75).",
  "people.terms.p77_allowed": "In this programme, agents may take binding actions for you (P-77).",
  "people.terms.p77_draft_only": "In this programme, agents may only prepare binding actions for you to confirm (P-77).",
  "people.terms.p75_undecided":
    "This programme has not decided yet whether reviewers' agents may read full proposal content (P-75).",
  "people.terms.p77_undecided": "This programme has not decided yet whether agents may take binding actions for you (P-77).",
};

/** The English catalogue of the people pages. */
export const CATALOGUE: CatalogueInput = { locale: "en", labels: LABELS, approved: APPROVED };
