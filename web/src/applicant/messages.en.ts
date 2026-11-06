// The English catalogue of the applicant pages (R-NF-04; M4 design
// sections 2.2 J4 and 3.9). Every user-visible string of
// `web/src/applicant` comes from here. Labels may take tenant
// terminology. Approved texts never do (I-72 seam).
//
// No label of a form control names an identity document, a date of birth
// or a payment detail (R-SB-01).

/** The interface strings of the applicant pages. */
export const APPLICANT_LABELS: Readonly<Record<string, string>> = Object.freeze({
  "app.document_title": "{page} | FSTP",
  "app.not_found": "Page not found",
  "app.loading": "Loading.",
  "steps.label": "Proposal steps",
  "steps.title": "Your proposal",
  "steps.current": ", current step",
  "steps.workspace": "Proposal text",
  "steps.plan": "1. Plan",
  "steps.eligibility": "2. Eligibility",
  "steps.submit": "3. Submit",
  "app.not_found_text": "This address names no page.",

  "nav.label": "Applicant pages",
  "nav.calls": "Open calls",
  "nav.proposals": "My proposals",
  "nav.notices": "Notices",

  "state.DRAFT": "Draft",
  "state.SUBMITTED": "Submitted",
  "state.INELIGIBLE": "Ineligible",
  "state.STAGE1": "Stage 1 evaluation",
  "state.NOT_SELECTED": "Not selected",
  "state.STAGE2": "Stage 2 questions",
  "state.RANKED": "Ranked",
  "state.IRC_REVIEW": "Independent review",
  "state.DEFERRED": "Deferred to a later call",
  "state.DECLINED": "Declined",
  "state.NEGOTIATION": "Negotiation",
  "state.WITHDRAWN": "Withdrawn",
  "state.GRANTED": "Granted",
  "state.IN_EXECUTION": "In execution",
  "state.COMPLETED": "Completed",
  "state.TERMINATED": "Terminated",

  "error.unavailable": "This action is not available yet.",
  "error.refused": "The platform refused this request ({code}).",
  "error.refused_rule": "The platform refused this request ({code}): {rule}",
  "error.network": "The platform could not be reached. Check your connection and try again.",
  "error.invalid": "The platform sent an answer this page cannot read.",
  "error.request": "This request could not be made.",
  "error.step_up": "This action needs a fresh confirmation with your passkey. Start it again from your account page.",
  "error.pending": "This action now waits for your confirmation in the platform.",
  "form.errors.heading": "There is a problem",
  "lead.only": "Only the applicant lead can do this on this proposal.",
  "team.only": "Only the team of this proposal can open this page.",

  "proposals.title": "My proposals",
  "proposals.empty": "You have no proposal yet. Open a call to start one.",
  "proposal.title": "Proposal",
  "proposal.untitled": "Untitled proposal",
  "proposal.state": "State:",
  "proposal.call_link": "Read the call",
  "proposal.actions": "What you can do now",
  "proposal.link.workspace": "Write the proposal",
  "proposal.link.plan": "Record the plan and the requested amount",
  "proposal.link.eligibility": "State your country and affiliations",
  "proposal.link.submit": "Submit the proposal",
  "proposal.link.team": "Invite team members or a guardian",
  "proposal.link.stage2": "Answer the stage 2 questions",
  "proposal.link.stage2_read": "Read the stage 2 questions",
  "proposal.link.negotiation": "Open the negotiation",
  "proposal.link.guardian": "Give guardian consent",
  "proposal.back": "Back to the proposal",
  "proposal.withdraw": "Withdraw the proposal",
  "withdraw.title": "Withdraw this proposal?",
  "withdraw.text": "A withdrawn proposal leaves the call for good. This cannot be undone.",
  "withdraw.confirm": "Withdraw",
  "withdraw.cancel": "Keep the proposal",
  "withdraw.done": "The proposal is withdrawn.",
  "copy.heading": "Get a copy of your application",
  "copy.intro": "We send a copy of your application to the email address you give here.",
  "copy.email": "Email address for a copy",
  "copy.request": "Request a copy",
  "copy.invalid": "Enter an email address in the form name@example.org.",
  "copy.done": "Your request for a copy is recorded.",

  "workspace.title": "Proposal workspace",
  "workspace.intro": "Only your team can read this workspace. It saves as you type.",
  "workspace.readonly": "This proposal is no longer a draft, so its workspace cannot be changed.",
  "ws.title": "Proposal title",
  "ws.summary": "Neutral summary. Do not identify yourself.",
  "ws.summary_hint":
    "Up to {max} characters. Reviewers read the title and this summary before they declare any conflict of interest.",
  "ws.narrative": "Narrative",
  "ws.status.idle": "No change yet.",
  "ws.status.pending": "Changes are not saved yet.",
  "ws.status.saving": "Saving.",
  "ws.status.saved": "All changes are saved.",
  "ws.status.failed": "Your last changes are not saved. They stay on this page.",
  "ws.retry": "Save now",
  "ws.leave_failed":
    "Your last changes could not be saved, so this page stays open. Use Save now to try again. To leave without them, open the other page again.",

  "plan.title": "Plan and requested amount",
  "plan.intro":
    "Split the work into tasks. Each task has one or more milestones, each with its amount, a start date and a due date. The platform computes the totals.",
  "plan.task": "Task {task}",
  "plan.milestone": "Task {task}, milestone {milestone}",
  "plan.add_task": "Add a task",
  "plan.add_milestone": "Add a milestone to task {task}",
  "plan.remove_task": "Remove task {task}",
  "plan.remove_milestone": "Remove milestone {milestone} of task {task}",
  "plan.ms.amount": "Amount (EUR)",
  "plan.ms.start": "Start date",
  "plan.ms.due": "Due date",
  "plan.dates_hint": "Dates are calendar days, such as 2027-03-31.",
  "plan.err.amount": "Task {task}, milestone {milestone}: write the amount with two decimals and no separators, such as 1500.00.",
  "plan.err.start": "Task {task}, milestone {milestone}: enter a start date.",
  "plan.err.due": "Task {task}, milestone {milestone}: enter a due date.",
  "plan.err.due_before_start": "Task {task}, milestone {milestone}: the due date cannot be before the start date.",
  "plan.total": "The platform computed the plan total: {amount} EUR.",
  "plan.amount_hint": "Write the amount with two decimals and no separators, such as 1500.00.",
  "plan.description": "Work plan",
  "plan.description_required": "Describe the work plan.",
  "plan.save": "Save the plan",
  "plan.saved": "The plan is saved as a new version.",
  "plan.readonly": "This proposal is no longer a draft, so its plan cannot be changed here.",

  "elig.title": "Country and affiliations",
  "elig.intro":
    "These statements go only to the identity vault. Evaluators never see them, and this page never shows them again.",
  "elig.country": "Country of residence or establishment",
  "elig.country_choose": "Choose a country",
  "elig.country_save": "Save the country",
  "elig.country_required": "Choose a country.",
  "elig.country_saved": "Your country is stored in the identity vault.",
  "elig.affiliations": "Declared affiliations",
  "elig.affiliations_hint": "Name the organisations you are affiliated with, one per line.",
  "elig.affiliations_save": "Save the affiliations",
  "elig.affiliations_required": "Write your affiliations.",
  "elig.affiliations_saved": "Your affiliations are stored in the identity vault.",
  "elig.readonly": "This proposal is no longer a draft, so these statements cannot be changed here.",

  "submit.title": "Submit the proposal",
  "outcome.formal": "Formal state: {state}",
  "outcome.other_calls": "See other open calls",
  "outcome.ineligible.kicker": "Final outcome",
  "outcome.ineligible.title": "Not eligible",
  "outcome.ineligible.text": "Your proposal did not meet one of the call's eligibility rules. It cannot continue in this call.",
  "outcome.not_selected.kicker": "Final outcome",
  "outcome.not_selected.title": "Not selected",
  "outcome.not_selected.text": "Your proposal was not selected in this call. Thank you for the work you put into it. You may apply to a later call.",
  "outcome.deferred.kicker": "Paused, not final",
  "outcome.deferred.title": "Your proposal has been deferred",
  "outcome.deferred.text":
    "Your proposal waits for the next call of the programme instead of ending here. It keeps the rules of the call it was submitted to.",
  "receipt.title": "Submission receipt",
  "receipt.proposal": "Proposal",
  "receipt.state": "State",
  "receipt.notice": "Data protection notice",
  "receipt.notice_version": "Version {version} shown and acknowledged.",
  "receipt.ethics": "Ethics self-declaration",
  "receipt.ethics_none": "Recorded: no ethics issue.",
  "receipt.ethics_declared": "Recorded, with the issue you described.",
  "receipt.next": "What happens next",
  "receipt.next_check": "Your application is now with the FSTP coordinator for an eligibility check.",
  "receipt.next_withdraw": "You can still withdraw it before a grant is awarded.",
  "receipt.open": "Open your proposal",
  "submit.notice.heading": "Data protection notice",
  "submit.notice_read": "I have read the data protection notice",
  "submit.notice_required": "Confirm that you have read the data protection notice.",
  "submit.ethics.legend": "Ethics self-declaration",
  "submit.ethics.none": "No ethics issue",
  "submit.ethics.declared": "I declare an ethics issue",
  "submit.ethics.details": "Describe the ethics issue",
  "submit.ethics_required": "Answer the ethics self-declaration.",
  "submit.ethics_details_required": "Describe the ethics issue you declare.",
  "submit.errors.heading": "There is a problem",
  "submit.confirm": "Submit the proposal",
  "submit.done": "The proposal is submitted.",
  "submit.not_draft": "Only a draft can be submitted. This proposal is in the state {state}.",
  "submit.closed": "The call deadline has passed, so this proposal cannot be submitted.",
  // Q23 B (design section 15.0, 2026-11-06): the date of birth goes to
  // the identity vault only, which answers one bit: whether the lead is
  // under 18 at the call deadline. TODO(legal): L-02, Daniel supplies the
  // wording of the legal basis for collecting it before NEGOTIATION, and
  // whether Article 8 GDPR applies. These texts state facts only.
  "submit.dob.heading": "Date of birth, for the identity vault",
  "submit.dob.intro":
    "Your date of birth goes to the identity vault only. The platform learns only whether you are under 18 at the call deadline. Without it, the proposal needs a guardian's consent before negotiation.",
  "submit.dob": "Date of birth",
  "submit.dob_save": "Send the date of birth to the identity vault",
  "submit.dob_required": "Enter a date of birth.",
  "submit.dob_saved": "Your date of birth is stored in the identity vault.",

  "stage2.title": "Stage 2 questions",
  "stage2.from": "Question from {handle}",
  "stage2.asked": "Asked on",
  "stage2.none": "No question has been asked.",
  "stage2.answer": "Your answer",
  "stage2.answer_send": "Send the answer",
  "stage2.answer_required": "Write your answer.",
  "stage2.answer_sent": "Your answer is sent.",
  "stage2.revision.heading": "Revised plan",
  "stage2.revision.intro": "The revised plan replaces your plan with a new version, which can change the budget.",
  "stage2.answers_closed": "Stage 2 answers are closed for this proposal.",
  "stage2.lead_answers": "The applicant lead answers the questions and submits the revised plan.",
  "stage2.revise": "Submit the revised plan",
  "stage2.revised": "Your revised plan is submitted.",
  "stage2.closed": "Stage 2 is not open for this proposal.",

  "notices.title": "Notices",
  "notices.empty": "You have no notice.",
  "notice.ProposalOutcome": "There is an outcome for your proposal.",
  "notice.IrcConcern": "The independent review committee raised a concern about your proposal.",
  "notice.other": "There is a notice about your proposal.",
  "notice.open": "Open the proposal",
  "notice.day": "Recorded on",

  "negotiation.title": "Negotiation",
  "negotiation.notice.heading": "Data protection notice",
  "negotiation.acknowledge": "I acknowledge the data protection notice",
  "negotiation.acknowledged": "You acknowledged this notice.",
  "negotiation.next.heading": "Next steps",
  "negotiation.next.identity": "Verify your identity in the identity vault.",
  "negotiation.next.guardian": "If the applicant lead is under 18, the guardian gives consent in the identity vault.",
  "negotiation.next.amount": "The grant amount is determined, then accepted and approved.",
  "negotiation.next.contract": "The contract is drafted and signed.",
  "negotiation.closed": "This proposal is not in negotiation.",
  "negotiation.lead_acknowledges": "The applicant lead acknowledges this notice.",

  "guardian.title": "Guardian consent",
  "guardian.intro":
    "You are named as the guardian of the applicant lead of this proposal. You give your consent in the identity vault, on its own site. This page asks for nothing about you.",
  "guardian.start": "Continue to the identity vault",
  "guardian.bad_redirect": "The platform sent a link this page does not follow.",
  "guardian.closed": "Guardian consent is not open for this proposal, or you are not its guardian.",

  "team.title": "Team",
  "team.intro": "Invite people by email address. The invitation asks them to sign in. This page asks nothing else about them.",
  "team.closed": "No one can be added to this proposal in its current state.",
  "team.email_invalid": "Enter an email address in the form name@example.org.",
  "team.member.heading": "Invite a team member",
  "team.member.intro": "Team members can read and write the draft with you.",
  "team.member.email": "Email address of the team member",
  "team.member.send": "Invite the team member",
  "team.member.sent": "The invitation to the team member is recorded.",
  "team.guardian.heading": "Add a guardian",
  "team.guardian.intro":
    "If you are under 18, your guardian gives consent in the identity vault before the proposal can enter negotiation.",
  "team.guardian.email": "Email address of the guardian",
  "team.guardian.send": "Add the guardian",
  "team.guardian.sent": "The invitation to the guardian is recorded.",
});

/**
 * Approved wording of the applicant pages, with the notice versions the
 * pages send (R-NG-06). A version names exactly one text, so a changed
 * text needs a new version.
 *
 * TODO(legal): Daniel supplies the approved wording of both data
 * protection notices. Until then each text says that its wording is
 * pending and names the scope that R-NG-06 sets. Interim, pending Daniel
 * and lanes W3b and W5: the cell accepts version "1" of each notice.
 */
export const APPLICANT_APPROVED: Readonly<Record<string, string>> = Object.freeze({
  "notice.submission":
    "Wording pending legal review. This notice covers the transfer of recipient data to the granting authority and refers to the Portal Privacy Statement.",
  "notice.negotiation":
    "Wording pending legal review. This notice covers the transfer of recipient data to the granting authority and refers to the Portal Privacy Statement.",
});

/**
 * The footer's mandatory elements on every applicant and call page (M4
 * design section 3.9 "Footer"; P-68, R-WL-04, I-69 seam).
 *
 * TODO(legal): Daniel supplies the approved wording of the privacy
 * notice and the accessibility statement. Until then each says that its
 * wording is pending. Interim, pending Daniel: the platform attribution
 * names the platform only, since P-68 fixes no wording.
 */
export const FOOTER_APPROVED: Readonly<Record<string, string>> = Object.freeze({
  "footer.privacy": "Privacy notice: wording pending legal review.",
  "footer.accessibility": "Accessibility statement: wording pending legal review.",
  "footer.attribution": "This service runs on the FSTP platform.",
});

/** The notice version each approved notice text carries (R-NG-06). */
export const NOTICE_VERSIONS = Object.freeze({ submission: "1", negotiation: "1" });
