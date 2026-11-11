// The English catalogue of the assessment panels (M7 design sections 4
// and 7; R-LA-03, R-LA-08). Every user-visible string of
// `web/src/findings` and `web/src/precheck` comes from here.
//
// TODO(legal): the AI disclosure wording (AI Act Article 50 and the
// tenant's DPA) is a placeholder for Daniel. It states only what the
// platform does: an AI system produced the findings, and it never decides.

/** The interface strings of the findings and pre-check panels. */
export const FINDINGS_LABELS: Readonly<Record<string, string>> = Object.freeze({
  "ai.disclosure": "These findings come from an AI system. They support people and never decide.",
  "ai.synthetic": "Synthetic assessor (demo). No language model ran.",
  "ai.model": "AI assessor.",

  "kind.completeness": "Completeness",
  "kind.quality": "Quality",
  "kind.accuracy": "Accuracy",
  "kind.integrity": "Integrity",
  "severity.info": "Info",
  "severity.minor": "Minor",
  "severity.major": "Major",

  "rev.findings.heading": "Assessor findings",
  "rev.findings.lead": "Mark each finding as agreed or disputed. A mark feeds calibration and never changes the proposal.",
  "rev.findings.none": "No findings yet. The assessment is pending.",
  "rev.findings.unavailable": "The findings cannot be shown on this page now.",
  "rev.findings.agree": "Agree",
  "rev.findings.dispute": "Dispute",
  "rev.findings.agree_named": "Agree with finding {n}",
  "rev.findings.dispute_named": "Dispute finding {n}",
  "rev.findings.mark.Agreed": "You agreed.",
  "rev.findings.mark.Disputed": "You disputed.",
  "rev.findings.mark.none": "Not marked.",
  "rev.findings.marked": "Your mark is recorded.",
  "rev.findings.item": "Finding {n}",

  "coord.findings.heading": "AI assessment",
  "coord.findings.lead": "Counts only. Reviewers read the findings themselves.",
  "coord.findings.caption": "Assessor findings by proposal",
  "coord.findings.col_proposal": "Proposal",
  "coord.findings.col_status": "Findings",
  "coord.findings.pending": "Findings pending",
  "coord.findings.count_one": "1 finding",
  "coord.findings.count_other": "{count} findings",
  "coord.findings.none": "No submitted proposal yet.",
  "coord.findings.unavailable": "The assessment status cannot be shown now.",
  "coord.findings.proposal": "Proposal {id}",

  "pre.title": "Check my draft",
  "pre.link": "Check my draft",
  "pre.link_hint": "An AI system reads your saved draft and lists what may be missing or unclear. Only your team sees the result.",
  "pre.back": "Back to the proposal text",
  "pre.intro": "The check reads the draft as it was last saved. It gives findings, never a score.",
  "pre.run": "Check my draft now",
  "pre.running": "Checking the draft.",
  "pre.done": "The check is done. Its findings are below.",
  "pre.limit": "No check is left now.",
  "pre.remaining": "Checks left: {today} today on this proposal, {call} in this call, {account} across your drafts in this call.",
  "pre.next": "The next check is available from {at}.",
  "pre.runs": "Earlier checks",
  "pre.none": "No check has run on this draft yet.",
  "pre.run_heading": "Check of {at}",
  "pre.state.pending": "The check is running.",
  "pre.state.unavailable": "The AI system was not reachable. The check still counts.",
  "pre.no_findings": "This check found nothing to point out.",
  "pre.evidence": "From the {section}:",
  "pre.section.title": "title",
  "pre.section.summary": "summary",
  "pre.section.narrative": "narrative",
  "pre.criterion": "Criterion {id}",
  "pre.team_only": "Only the team of a draft can check it.",
});
