// The English catalogue of the home page and the site navigation
// (R-NF-04; M4 design sections 2.2 and 3.9). Every user-visible string of
// `web/src/home` comes from here. Labels may take tenant terminology.
//
// The navigation and home copy follows the approved design
// `docs/design/01-navigation-home.md` (2026-11-01). Plain grant language
// leads every label. The Voyage pack is optional per tenant (O-55 as
// amended on 2026-11-01), so no Voyage label appears here.

/** The interface strings of the home page and the site navigation. */
export const HOME_LABELS: Readonly<Record<string, string>> = Object.freeze({
  "home.document_title": "{page} | FSTP",

  "nav.skip_to_main": "Skip to main content",
  "nav.brand": "FSTP",
  "nav.brand_home": ", FSTP home",
  "nav.label": "Main navigation",
  "nav.section_label": "Navigation",
  "nav.role_chip": "Signed in as {roles}",
  "nav.role_chip_none": "Signed in",
  "nav.role_join": ", ",
  "nav.notifications": "Notifications",
  "nav.home": "Home",
  "nav.account": "Account",
  "nav.my_assignments": "My assignments",
  "nav.my_cases": "My cases",
  "nav.onboarding": "Onboarding",
  "nav.programme_setup": "Programme set-up",
  "nav.approvals": "Approvals",
  "nav.my_applications": "My applications",
  "nav.open_calls": "Open calls",

  "home.title": "Your work",
  "home.loading": "Loading your work.",
  "home.intro": "Each link opens one piece of your work. Pages that every role uses are in the navigation.",
  "home.no_role":
    "You hold no role on this platform yet. You can read the open calls and start a proposal in one of them.",
  "home.failed": "Your work could not be loaded. Reload the page to try again.",
  "home.signed_out": "You are not signed in. Opening the sign-in page.",
  "home.primary.kicker": "Start here",
  "home.primary.title": "Your next step",
  "home.other.title": "Other roles",
  "home.other.item": "{role} in programme {programme}. This release has no page for this role yet.",

  "home.group.applicant": "Your applications",
  "home.group.guardian": "Guardian consent",
  "home.group.tenant_admin": "Tenant administration",
  "home.group.programme": "Programme management",
  "home.group.coordinator": "Coordination",
  "home.group.committee": "Committee review",
  "home.group.irc": "Independent review",
  "home.group.everyone": "Open calls",

  "home.call": "Call {id}",
  "home.proposal": "Proposal {id}",
  "home.work.proposal": "Your proposal: {title}",
  "home.work.proposals": "All your proposals",
  "home.work.guardian": "Guardian consent for {title}",
  "home.work.onboarding": "Onboarding of your organisation: steps and their status",
  "home.work.creator_new": "Open a new programme draft",
  "home.work.approvals": "Approvals waiting for a tenant admin",
  "home.work.creator": "Programme set-up of programme {programme}",
  "home.work.people": "People and invitations of programme {programme}",
  "home.work.board": "Call board of {call}",
  "home.work.intake": "Intake queue of {call}",
  "home.work.notifiable": "Notifiable conflicts of {call}",
  "home.work.assignments": "Your review assignments",
  "home.work.ranking": "Ranking of {call}",
  "home.work.round": "Open cut-off round of {call}",
  "home.work.irc_cases": "Your IRC cases",
  "home.work.open_calls": "See open calls",

  "role.programme_manager": "Programme manager",
  "role.call_drafter": "Call drafter",
  "role.fstp_coordinator": "FSTP coordinator",
  "role.committee_member": "Committee member",
  "role.committee_chair": "Committee chair",
  "role.irc_member": "IRC member",
  "role.applicant": "Applicant",
  "role.applicant_team_member": "Applicant team member",
  "role.guardian": "Guardian",
  "role.tenant_admin": "Tenant admin",
  "role.finance_approver": "Finance approver",
  "role.payment_releaser": "Payment releaser",
  "role.contract_signatory": "Contract signatory",
  "role.auditor": "Auditor",
});
