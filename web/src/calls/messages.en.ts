// The English catalogue of the call pages (R-NF-04, R-LA-08; M4 design
// sections 2.2 J4 and 3.9). Every user-visible string of `web/src/calls`
// comes from here. Labels may take tenant terminology. Approved texts
// never do (I-72 seam).

/** The interface strings of the call pages. */
export const CALLS_LABELS: Readonly<Record<string, string>> = Object.freeze({
  "calls.list.title": "Open calls",
  "calls.list.intro": "These calls accept proposals now. Open a call to read it and its Guide for Applicants.",
  "calls.list.empty": "No call is open at the moment.",
  "calls.untitled": "Call {id}",

  "call.title": "Call",
  "call.glance": "Call at a glance",
  "call.deadline": "Deadline",
  "call.zone": "({zone})",
  "call.amounts": "Amounts",
  "call.amount.budget": "Call budget",
  "call.amount.grant_min": "Smallest grant",
  "call.amount.grant_max": "Largest grant",
  "call.amount.recipient_max": "Maximum per recipient",
  "call.amount.value": "{amount} {currency}",
  "call.ai.heading": "Use of AI assessment",
  "call.guide_link": "Read the Guide for Applicants",
  "call.start": "Start a proposal",
  "call.closed": "This call is closed. No proposal can be started or submitted in it.",

  "guide.title": "Guide for Applicants",
  "guide.empty": "The Guide for Applicants of this call has no section yet.",
  "guide.back": "Back to the call",
});

/**
 * Approved wording of the call pages.
 *
 * Interim, pending Daniel: R-LA-08 asks that applicants are told in the
 * call text that AI assessment is used. Every published call carries an
 * LLM configuration (design section 3.5), so the call page always shows
 * this statement. The Guide's "How to apply" section holds the full
 * disclosure.
 */
export const CALLS_APPROVED: Readonly<Record<string, string>> = Object.freeze({
  "call.ai.text":
    "This call uses AI assessment to support the evaluation of proposals. A named person records every decision. The Guide for Applicants explains how AI assessment is used and what it does not do.",
});
