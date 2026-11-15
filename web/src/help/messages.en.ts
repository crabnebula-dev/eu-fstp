// The English catalogue of field help (SA-13, R-NF-04, I-72). One text
// per field a tenant admin or programme manager fills in: the creator
// fields by their catalogue key (`creator/fields.ts`), and the wizard,
// invitation and import fields by name.
//
// Each text says, in plain language, what the field means, a typical
// value and what it affects. The content comes from the SPEC:
// `02-domain/policy-parameters.md`, `02-domain/programme-creator.md`, the
// Guide for Applicants sections and the domain pages each text names.
// Typical values are the SuperSAFE defaults of the policy table. A text
// that would need a legal explanation says TODO(legal) instead of one;
// the list is in `web/test/sa13_field_help.test.ts`.

import type { CatalogueInput } from "../core/i18n.js";

const LABELS: Readonly<Record<string, string>> = {
  // The accessible name of every "i" button.
  "help.about": "About {field}",

  // Step 1, funder and instrument.
  "help.field.funder.p53_funder_profile":
    "The funder rules this programme follows, and their version (P-53). Typical value: Horizon Europe, version 1. The profile sets the bounds later steps are checked against, such as the per-recipient ceiling. It freezes when a call publishes.",
  "help.field.funder.action_number":
    "The number the funder gave the action that pays for this programme. Copy it from the grant agreement. Documents the platform generates use it to name the action.",
  "help.field.funder.action_acronym":
    "The short name of the funded action, such as SuperSAFE. Documents the platform generates use it next to the action number.",
  "help.field.funder.coordinator_name":
    "The organisation that coordinates the action and runs its calls. Write the name as the grant agreement spells it.",
  "help.field.funder.p56_fstp_budget":
    "The total the action may give to third parties as financial support (P-56). Typical value: the FSTP line of the action's estimated budget, such as 2000000.00 euro. Unclaimed milestone balances can return to it at grant end (P-67).",
  "help.field.funder.p57_action_dates":
    "The start and end of the funded action, and each reporting period with its end and report deadline (P-57). Take them from the funder's Data Sheet. Grant milestones must fall within the action (I-46), and the creator checks that the dates hold together.",
  "help.field.funder.p58_recipient_ceiling":
    "The most one recipient may receive from the action under the funder's rules (P-58). Typical value: the ceiling in the Data Sheet, such as 400000.00 euro. The programme's own cap (P-05) may not exceed it (I-50).",
  "help.field.funder.p41_funder_retention":
    "How long records are kept after the action's final payment, as the funder requires (P-41). Take the value from the signed grant agreement (L-06). Trace retention (P-22) can end with it. TODO(legal): explain the retention duty and its source.",
  "help.field.funder.p22_trace_retention":
    "How long the full traces of submission assessments stay in this organisation's cell (P-22). Typical value: until the funder retention period ends (P-41). The traces support appeals and calibration. A scheduled job deletes them afterwards.",
  "help.field.funder.p46_switch_retrieval_period":
    "How many days the organisation can still retrieve its data after it asks to switch provider (P-46). Typical value: 30 days. TODO(legal): confirm the statutory minimum and explain the switching right.",
  "help.field.funder.p43_licence_grace_period":
    "For self-hosted cells only: how many days the platform keeps working after a licence refresh fails (P-43). Typical value: 30 days. Expiry never interrupts a published call, payment processing or export.",

  // Step 2, programme identity.
  "help.field.identity.name":
    "The programme's name as applicants and staff see it, such as SuperSAFE. Applicants find it on the public pages and in the Guide for Applicants.",
  "help.field.identity.narrative":
    "A short description of what the programme supports and why. It fills the section About the programme of the Guide for Applicants. After a call publishes, a change needs a numbered corrigendum (I-53).",
  "help.field.identity.scope":
    "The topics the programme funds, in a phrase or a few sentences. Typical value: the Open Internet Stack and the SuperSAFE vision. It appears with the narrative in the Guide for Applicants.",
  "help.field.identity.public_slug":
    "The last part of the programme's public web address. Use lower-case letters, digits and hyphens, at most 63 characters, starting and ending with a letter or digit. Typical value: supersafe.",
  "help.field.identity.p25_language":
    "The language of the programme's calls and Guide for Applicants, as a language code (P-25). Typical value: en, for English. The Guide shows it under Call at a glance. It freezes when a call publishes.",

  // Step 3, eligibility.
  "help.field.eligibility.persons_supported":
    "Who may apply: the persons and kinds of organisation the programme supports. It fills the section Who can apply of the Guide for Applicants.",
  "help.field.eligibility.minors":
    "Whether minors may apply, and how a guardian consents for them. It appears under Who can apply in the Guide. A minor's contract includes the guardian as a signing party (R-CT-02). TODO(legal): explain the age rules and the consent wording.",
  "help.field.eligibility.p13_excluded_classes":
    "Groups of people and organisations that may not receive funding from this programme (P-13). Typical value: consortium partners, their affiliated entities and staff; IRC members, their employers, co-workers and relatives. Adding a class ends the receiving roles of anyone now in it.",
  "help.field.eligibility.p17_tie_break":
    "Which proposals rank first when scores tie (P-17). Typical value: EU and associated countries first, with an exception for exceptional quality and unique expertise. The identity vault answers the country condition, so reviewers never see an applicant's country.",
  "help.field.eligibility.p18_verification_methods":
    "The ways people prove who they are (P-18). Typical value: EUDI Wallet, and document upload with a manual check. It covers identity checks only. Signing has its own cascade in the Contract step (P-30).",
  "help.field.eligibility.p19_document_retention":
    "How long uploaded identity documents are kept after the check (P-19). Typical value: none, so a document is deleted once verification completes, including from backups (R-ID-03). TODO(legal): explain the data protection basis of this period.",
  "help.field.eligibility.p45_relying_party_mode":
    "How the platform is registered to read EUDI Wallets (P-45). Choose the organisation's own registration, or CrabNebula as an intermediary. Self-hosted cells use their own registration only.",

  // Step 4, what we fund.
  "help.field.funding.p55_activity_types":
    "The closed list of activities the programme funds (P-55). Every grant milestone references an item of this list (I-47). The Guide shows it under What we fund. It freezes when a call publishes.",
  "help.field.funding.p26_licences":
    "The licences deliverables may use (P-26). Typical value: recognised free and open source licences, such as Apache-2.0 or MIT. Each payment request names the licence of its deliverable (P-34).",

  // Step 5, evaluation.
  "help.field.evaluation.p01_criteria":
    "The criteria reviewers score, their weights and the highest score (P-01). Typical value: Technical excellence 30, Relevance and impact 40, Value for money 30, each scored 0 to 5. Every reviewer scores every criterion. It freezes when a call publishes.",
  "help.field.evaluation.p02_threshold":
    "The stage 1 pass mark, as a percentage of the maximum score with two decimals (P-02). Typical value: 75.00. A proposal passes only when its score is strictly above it, so exactly 75.00% does not pass.",
  "help.field.evaluation.p03_reviewers":
    "The fewest reviewers assigned to each proposal (P-03). Typical value: 2. The review warns when the team has fewer committee members than this.",
  "help.field.evaluation.p06_cadence":
    "How often the programme opens a call (P-06). Typical value: quarterly. Overruns move proposals into the next call, so leave some slack.",
  "help.field.evaluation.p07_stage2_window":
    "How many days applicants have to answer the stage 2 questions (P-07). Typical value: 28 days. It freezes when a call publishes.",
  "help.field.evaluation.p08_notification_deadline":
    "Within how many working days after the decision applicants who were not selected are told (P-08). Typical value: 5 working days. Working days follow the working-day calendar (P-40).",
  "help.field.evaluation.p09_knock_outs":
    "Yes or no conditions every proposal must meet before scoring (P-09). Typical value: aligned with the programme's vision, research and development as the primary objective, and English. The FSTP coordinator checks them. A change after a call is approved returns that call to draft.",
  "help.field.evaluation.p10_read_access":
    "Who can read full proposals in stages 1 and 2 (P-10). Choose assigned reviewers only, all committee members, or operator staff only. The default, assigned reviewers only, is the narrowest.",
  "help.field.evaluation.p11_anonymity":
    "Whether applicants see the names of their reviewers (P-11). Typical value: anonymous. The Guide states it under How proposals are evaluated.",
  "help.field.evaluation.p14_irc_exemptions":
    "Kinds of grant amendment that skip review by the independent review committee (P-14). Typical value: team change, plan change without a budget change, and extra tasks in scope at equal rates under 100000.00 euro. The programme manager decides whether one applies.",
  "help.field.evaluation.p15_irc_members":
    "The fewest IRC members who review each proposal (P-15). Typical value: 2. The review warns when the team has fewer IRC members than this.",
  "help.field.evaluation.p16_voting":
    "How the committee decides (P-16). Typical value: a majority of the votes cast, vote delegation allowed, and a casting vote for the chair on a tie. A vote needs more than half of the members who are not recused.",
  "help.field.evaluation.p21_inference":
    "The AI provider and the pinned model that assess submissions, with an ordered list of fallback models (P-21). They are pinned when a call publishes. A replacement takes the next fallback and regenerates every finding of the call at once.",
  "help.field.evaluation.p23_precheck":
    "Whether applicants can run the automated pre-submission check, and how often (P-23). Typical value: on, once a day and 5 times per call for each proposal, counted across the drafts of one account. The Guide states these limits.",
  "help.field.evaluation.p24_effective_score":
    "Which score counts after stage 2 (P-24). Typical value: the higher of the original and the revised score.",
  "help.field.evaluation.p28_rubric_bands":
    "Whether reviewers see the indicative score bands of the AI assessment (P-28). Typical value: off, so model output does not anchor human scores.",
  "help.field.evaluation.p39_reviewer_organisations":
    "The fewest different organisations among the reviewers of each proposal (P-39). Typical value: 2. It may not exceed the reviewers per proposal (P-03). Each committee member's home organisation is set when they are invited.",
  "help.field.evaluation.p42_calibration_consent":
    "Whether applicants are asked, after the outcome notice, to consent to pseudonymised use of their proposal for calibrating the assessor (P-42). Typical value: on. The use stays within this organisation.",
  "help.field.evaluation.p75_agent_content_reads":
    "Whether reviewers' AI agents may read full proposal content through the platform (P-75). Typical value: off. When on, proposal content goes to each reviewer's own AI provider, outside this organisation's cell. The Guide and the reviewer terms say so.",
  "help.field.evaluation.p77_mcp_binding_actions":
    "Whether AI agents may complete binding actions, or only draft them for a person to confirm (P-77). Typical value: draft only. Allowing them needs an acknowledgement in the review. TODO(legal): explain the AI Act position.",

  // Step 6, money.
  "help.field.money.amount_criteria":
    "How the exact grant amount of a proposal is set. It fills the section How the amount is set of the Guide for Applicants. Take it from the funding document.",
  "help.field.money.p04_grant_range":
    "The smallest and the largest grant one proposal can receive (P-04). Typical value: 5000.00 to 100000.00 euro. The largest may not exceed the per-recipient cap (P-05). The Guide shows it under Call at a glance.",
  "help.field.money.p05_recipient_cap":
    "The most one recipient can receive from this programme over its lifetime (P-05). Typical value: 400000.00 euro. It may not exceed the funder's ceiling (P-58, I-50). Lowering it after a call publishes produces a numbered corrigendum.",
  "help.field.money.p27_hardship_contribution":
    "Whether grantees can ask for a hardship contribution (P-27). Typical value: on. The Guide explains it under Contract and payments.",
  "help.field.money.p34_payment_evidence":
    "What a grantee provides with each payment request (P-34). Typical value: the public location, the release identifier, the SPDX licence and a report. A request is paid only when the evidence is complete.",
  "help.field.money.p36_bank_change_hold":
    "How many days payments wait after a grantee changes bank details (P-36). Typical value: 7 days. No payment is released until the new details are verified and this period has passed (I-33).",
  "help.field.money.p59_payment_target":
    "The target number of days from payment approval to payment (P-59). Typical value: 15 days. The Guide states it under Contract and payments.",
  "help.field.money.p65_partial_claim_evidence":
    "What a grantee provides to claim part of a milestone (P-65). Choose public deliverables, as for a full claim, or a progress report with the deliverables at the final claim. Typical value: public deliverables.",
  "help.field.money.p66_reallocation":
    "Whether amounts can move between milestones of the same task without amending the contract (P-66). Typical value: on, with approval by an assigned reviewer. The contract then includes a reallocation clause.",
  "help.field.money.p67_unclaimed_balances":
    "What happens to unclaimed milestone money when a grant ends (P-67). Choose return to the FSTP budget, or lapse and report as unspent. Typical value: return to the FSTP budget.",

  // Step 7, contract.
  "help.field.contract.p29_instrument":
    "The kind of contract each grantee signs, and the template version it is generated from (P-29). Typical value: a memorandum of understanding from the annex template, version 1. It freezes when a call publishes.",
  "help.field.contract.p30_signature_cascade":
    "The signature routes in the order the platform offers them (P-30). Typical value: qualified signature with the EUDI Wallet, then remote qualified signature, then an approved advanced signature. A fallback is approved and recorded. TODO(legal): explain the legal effect of each level.",
  "help.field.contract.p44_payment_nature":
    "The legal nature of payments, as the funder's instrument sets it (P-44). Typical value: financial support to third parties as a grant. Contracts, payment records and messages use this wording. TODO(legal): confirm the wording for each instrument.",
  "help.field.contract.p47_seal_level":
    "The electronic seal level of contractual notices (P-47). Typical value: advanced, with qualified as an option. TODO(legal): explain the difference in legal effect.",
  "help.field.contract.p48_sealed_pdf":
    "Whether notice emails attach the sealed PDF of the notice (P-48). Typical value: on.",
  "help.field.contract.p49_signing_provider":
    "The qualified trust service provider for remote signing (P-49). The organisation chooses it. It serves the remote qualified signature route of the cascade (P-30).",
  "help.field.contract.flow_down":
    "The grant agreement obligations every contract passes on to its recipient. Under the Horizon Europe profile each one is required, and no contract is generated without the full set (I-49). Clause wording comes from the signed grant agreement and legal review. TODO(legal): explain each obligation.",

  // Step 8, support and complaints.
  "help.field.support.p60_support_programme":
    "What grantees receive besides funding (P-60). Typical value: mentoring by consortium experts, presenting results to the consortium, promotion and visibility, and CRA compliance guidance. It fills the section Support programme of the Guide.",
  "help.field.support.p61_complaint_window":
    "How many working days an applicant has to complain after a procedural decision is notified (P-61). Proposed value: 10 working days. The Guide explains complaints under Complaints.",
  "help.field.support.p62_coordinator_response":
    "How many working days the coordinator has to answer a complaint (P-62). Proposed value: 15 working days.",
  "help.field.support.p63_escalation_window":
    "How many working days an applicant has to escalate to the IRC after the coordinator's answer (P-63). Proposed value: 10 working days.",
  "help.field.support.p64_irc_response":
    "How many working days the IRC has to answer an escalated complaint (P-64). Proposed value: 20 working days.",

  // Step 9, people.
  "help.field.people.p12_cooling_off":
    "How many calls a person waits before switching between the Drafting, Judging and Receiving groups (P-12). Typical value: 1. With 1, the first call published after a role ends is still barred. 0 is allowed.",

  // Step 10, communications.
  "help.field.comms.message_templates":
    "The texts of messages the platform sends. Each item has a kind, such as reminder, and the text people receive.",
  "help.field.comms.faq":
    "Frequently asked questions and their answers. They fill the section Contact and FAQ of the Guide for Applicants. After a call publishes, a change needs a numbered corrigendum (I-53).",
  "help.field.comms.contact":
    "How applicants reach the programme, such as an email address. It appears in the section Contact and FAQ of the Guide for Applicants.",
  "help.field.comms.p31_reminder_offsets":
    "When reminders go out, in days relative to a due date (P-31). Typical value: -14, -3 and 0, so 14 days before, 3 days before, and on the due date.",
  "help.field.comms.p32_channels":
    "The channels the platform uses to reach people (P-32). This release offers email only. Matrix and WhatsApp are deferred.",
  "help.field.comms.p33_escalation":
    "When an overdue item is escalated, and to whom (P-33). Typical value: after 7 days, to the programme manager.",
  "help.field.comms.p35_group_removal_delay":
    "How soon a person leaves a messaging group after their role ends (P-35). Typical value: immediate.",
  "help.field.comms.p37_inbound_messages":
    "What the platform does with messages people send into a group (P-37). Typical value: not stored, so the platform passes them on and keeps none.",
  "help.field.comms.p38_proximity_lists":
    "For each partner organisation, the affiliations its reviewers may not review (P-38). A reviewer is never assigned a proposal that declares an affiliation on the list of the reviewer's organisation (SoD-11). Each partner declares its list at programme start.",
  "help.field.comms.p40_working_calendar":
    "The weekend days and public holidays that are not working days (P-40). Typical value: Saturday and Sunday, plus the organisation's holidays. Deadlines in working days, such as P-08 and P-61, follow it.",
  "help.field.comms.p50_funded_visibility":
    "The most a funded grant may show publicly when its grantee opts in (P-50). The levels are Hidden, Project, Project and grantee, and Full. Typical value: Full. Every grant stays hidden until its grantee chooses a level.",
  "help.field.comms.p51_finished_visibility":
    "The most a finished grant may show publicly when its grantee opts in, including accepted deliverables (P-51). Typical value: Full. Every grant stays hidden until its grantee chooses a level.",
  "help.field.comms.p52_public_feed":
    "Whether a machine-readable feed of the public data is available (P-52). Typical value: on. The feed applies the same filter as the public pages.",
  "help.field.comms.p54_aggregate_minimum":
    "The fewest grants behind any public figure, such as the number of grants or the total per call (P-54). Typical value: 3. Smaller groups are not shown, so no single grant can be inferred.",
  "help.field.comms.p76_directory_listing":
    "Whether the programme's open calls appear in the platform-wide directory of open calls (P-76). Typical value: off. The directory holds public call data only.",
  "help.field.comms.p79_public_milestones":
    "Whether grants shown at the Full level also show milestone status (P-79). It shows each milestone's title, whether it is completed, and a month, never an amount. Typical value: off.",

  // The set-up wizard.
  "help.wizard.programme_name":
    "The programme's name as applicants and staff see it. A working title is fine. The programme manager can change it in stage 2.",
  "help.wizard.manager_email":
    "The full email address of the person who will build the programme as its programme manager. They receive an invitation by email and accept it from there. Accounts of other organisations are never searched or shown.",
  "help.wizard.team_email":
    "The full email address of the person to add. They receive an invitation by email and accept it from there. Accounts of other organisations are never searched or shown.",
  "help.wizard.role":
    "The one role the person takes in this programme. Roles are grouped as Drafting, Judging and Operations, as the separation of duties rules group them. The live checks below show whether this person may hold it.",
  "help.wizard.organisation":
    "For committee members: the number that identifies the organisation the person reviews for. The reviewers of each proposal come from at least as many organisations as P-39 sets. Leave it empty for other roles.",
  "help.wizard.role_start":
    "The first day the person holds the role. A role never starts before a tenant admin grants it, so a date that has passed starts the role at the grant.",
  "help.wizard.role_end":
    "The last day the person holds the role. Leave it empty for no end date. After a Drafting or Judging role ends, the cooling-off period (P-12) can bar the person from some calls.",

  // Invitations.
  "help.invite.email":
    "The full email address of the person to invite. They receive an email with a link to accept. Accounts of other organisations are never searched or shown (I-19, I-20).",
  "help.invite.role":
    "The role the person holds in this programme once a tenant admin grants it. Separation of duties rules decide which roles one person may combine.",
  "help.invite.organisation":
    "For committee members: the number that identifies the organisation the person reviews for. It spreads the reviewers of each proposal across organisations (P-39). Leave it empty for other roles.",

  // Imports and other starting points.
  "help.import.file":
    "The funding document that describes the programme, such as an FSTP annex, as Markdown or plain text. The assessor proposes values from it, each with a pointer to its evidence. Nothing takes effect until a programme manager confirms each value (I-65).",
  "help.import.clone_source":
    "Another programme of this organisation to copy values from. Every step of this draft still validates before activation.",
  "help.import.conflict_ack":
    "This proposed value conflicts with the funder profile, such as a cap above the funder's ceiling. The conflict is flagged, never adjusted. Tick the box to confirm you read it before you accept or edit the value (I-65).",
};

/** The help catalogue in the one M4 locale. */
export const HELP_CATALOGUE: CatalogueInput = { locale: "en", labels: LABELS, approved: {} };
