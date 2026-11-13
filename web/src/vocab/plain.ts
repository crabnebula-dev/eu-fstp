// The plain vocabulary pack, label by label (`docs/design/07-vocabulary-pack.md`;
// O-55, I-72). It repeats `crates/fstp-journey/vocab/plain.v1.json`, and
// `FIXED_LABEL_KEYS` repeats the keys of `fstp_journey::vocab::FIXED`.
// `web/test/m9p2_admin_branding.test.ts` fails if either differs. The
// terminology screen lists these keys, and no other, so a tenant pack
// can name only an interface label (I-72, I-94).

/** The plain label of every label key a pack may name, in key order. */
export const PLAIN_LABELS: Readonly<Record<string, string>> = Object.freeze({
  "home.activity.open_full": "Open the full activity log",
  "home.applicant.answer_questions": "Answer reviewer questions",
  "home.applicant.empty.body": "Pick an open call and start a proposal. You can save it as a draft and come back later.",
  "home.applicant.empty.title": "You have no applications yet",
  "home.primary.kicker.applicant": "Your next step",
  "home.recent_activity": "Recent activity",
  "journey.diary.anchor_pending": "Anchor pending",
  "journey.map.reenter": "re-enters at the stage it left",
  "journey.map.status.complete": "Completed",
  "journey.map.status.current": "Current stage",
  "journey.map.status.end": "Possible final outcome",
  "journey.map.status.upcoming": "Upcoming",
  "journey.map.title": "Application progress",
  "journey.map.withdraw_bracket": "Withdraw: possible in any state before GRANTED, including DEFERRED",
  "journey.node.completed": "Completed",
  "journey.node.declined": "Declined",
  "journey.node.deferred": "Deferred to the next call",
  "journey.node.draft": "Draft",
  "journey.node.granted": "Granted",
  "journey.node.in_execution": "Project in progress",
  "journey.node.ineligible": "Not eligible",
  "journey.node.irc_review": "Independent review",
  "journey.node.negotiation": "Negotiation",
  "journey.node.not_selected": "Not selected",
  "journey.node.ranked": "Ranked, awaiting committee decision",
  "journey.node.stage1": "Stage 1 evaluation",
  "journey.node.stage2": "Stage 2 questions",
  "journey.node.submitted": "Submitted",
  "journey.node.terminated": "Grant terminated",
  "journey.node.withdrawn": "Withdrawn",
  "journey.strip.title": "Proposal status",
  "journey.withdraw.action": "Withdraw this proposal",
  "nav.audit_trail": "Audit trail",
  "nav.history_export": "History export",
  "nav.my_applications": "My applications",
  "nav.programme_setup": "Programme set-up",
  "nav.tenant_settings": "Tenant settings",
  "place.chronicle": "Proposal history (PDF)",
  "place.diary": "Activity log",
  "place.onboarding": "Tenant onboarding",
  "place.route_map": "Application progress (progress map)",
  "place.seal": "Approval and publication",
  "place.strip": "Proposal status",
  "place.studio": "Programme set-up",
  "place.studio.group1": "Funder and identity",
  "place.studio.group2": "Eligibility and scope",
  "place.studio.group3": "Evaluation, money and contract",
  "place.studio.group4": "Support, people and communications",
  "place.studio.group5": "Review and approval",
  "role.applicant": "Applicant",
  "role.committee": "Committee",
  "role.irc": "IRC",
  "role.planner": "Programme manager",
  "role.reviewer": "Reviewer",
  "vocab.audit_trail": "Audit trail",
  "vocab.call": "Call",
  "vocab.committee": "Committee / Independent Review Committee",
  "vocab.contract": "Grant agreement",
  "vocab.guide": "Guide for Applicants",
  "vocab.hardship": "Hardship contribution",
  "vocab.knock_out": "Eligibility check (knock-out)",
  "vocab.milestone": "Milestone",
  "vocab.negotiation": "Negotiation",
  "vocab.payment_request": "Payment request",
  "vocab.pre_check": "Pre-submission check",
  "vocab.proposal_draft": "Your proposal",
  "vocab.review_stages": "Stage 1 evaluation, Stage 2 questions",
  "vocab.submission": "Submission",
  "vocab.team": "Team",
  "vocab.timeline": "Deadlines",
});

/**
 * The keys whose wording is fixed: the negative outcomes and the
 * withdrawal action (design 07 content rule 6). A tenant pack may not
 * change them, so the terminology screen shows them without a field.
 */
export const FIXED_LABEL_KEYS: readonly string[] = Object.freeze([
  "journey.node.ineligible",
  "journey.node.not_selected",
  "journey.node.declined",
  "journey.node.withdrawn",
  "journey.node.terminated",
  "journey.withdraw.action",
]);
