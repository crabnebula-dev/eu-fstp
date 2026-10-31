// Which applicant actions each proposal state allows (SPEC/02-domain
// state-machine.md; M4 design sections 2.2 J4 and 8.7).
//
// Pure and without DOM. A page offers an action only when its rule here
// says the state allows it. A refused action has no control on the page:
// it is absent, never only disabled. The cell enforces every guard again,
// so these rules decide what is shown, never what is allowed.

/** A proposal state, by its spec name. */
export type ProposalState =
  | "DRAFT"
  | "SUBMITTED"
  | "INELIGIBLE"
  | "STAGE1"
  | "NOT_SELECTED"
  | "STAGE2"
  | "RANKED"
  | "IRC_REVIEW"
  | "DEFERRED"
  | "DECLINED"
  | "NEGOTIATION"
  | "WITHDRAWN"
  | "GRANTED"
  | "IN_EXECUTION"
  | "COMPLETED"
  | "TERMINATED";

/** The 16 states of the state machine, each once, in the spec's order. */
export const PROPOSAL_STATES: readonly ProposalState[] = Object.freeze([
  "DRAFT",
  "SUBMITTED",
  "INELIGIBLE",
  "STAGE1",
  "NOT_SELECTED",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "DECLINED",
  "NEGOTIATION",
  "WITHDRAWN",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "TERMINATED",
]);

const KNOWN: ReadonlySet<string> = new Set(PROPOSAL_STATES);

/**
 * The state `v` names, or null. Only the exact spec name passes: no case
 * change, padding, prefix or other spelling, so a page never guesses.
 */
export function parseProposalState(v: unknown): ProposalState | null {
  return typeof v === "string" && KNOWN.has(v) ? (v as ProposalState) : null;
}

/**
 * State-machine NOTE 10: "Withdrawal is open in DRAFT, SUBMITTED, STAGE1,
 * STAGE2, RANKED, IRC_REVIEW, DEFERRED and NEGOTIATION." Terminal states
 * have no exits (R-SB-03).
 */
const WITHDRAWABLE: ReadonlySet<ProposalState> = new Set<ProposalState>([
  "DRAFT",
  "SUBMITTED",
  "STAGE1",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "NEGOTIATION",
]);

/** Whether the proposal page offers withdrawal in `s` (NOTE 10, R-SB-03). */
export function withdrawOffered(s: ProposalState): boolean {
  return WITHDRAWABLE.has(s);
}

/**
 * Whether the workspace, the plan, the eligibility statements and
 * submission are open. The draft is the applicant workspace, so only
 * DRAFT edits it.
 */
export function draftEditable(s: ProposalState): boolean {
  return s === "DRAFT";
}

/** Whether stage 2 answers and a revised plan are open (R-EV-05). */
export function stage2Open(s: ProposalState): boolean {
  return s === "STAGE2";
}

/** Whether the negotiation landing is open (R-NG-06 at negotiation). */
export function negotiationOpen(s: ProposalState): boolean {
  return s === "NEGOTIATION";
}

/**
 * The terminal states of the state machine. A proposal that reaches one
 * ends its team's Receiving bindings (`roles-and-sod.md`), so the team
 * reads its final state through its own list (R-SB-03, R-EV-04).
 */
const TERMINAL: ReadonlySet<ProposalState> = new Set<ProposalState>([
  "INELIGIBLE",
  "NOT_SELECTED",
  "DECLINED",
  "WITHDRAWN",
  "COMPLETED",
  "TERMINATED",
]);

/** Whether `s` is a terminal state, which has no exits. */
export function isTerminal(s: ProposalState): boolean {
  return TERMINAL.has(s);
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/** The caller's role on a proposal, as `fstp-api-core` names it. */
export type ProposalRole = "lead" | "member" | "guardian";

/**
 * Whether the caller may take the lead's actions: withdrawal, the plan,
 * the vault statements, submission, the copy request, the team, the
 * stage 2 answers and revision, and the negotiation acknowledgement.
 *
 * The registry (`fstp-access` `registry.rs`) admits only the lead to
 * each of them, as the domain does (`ActorRule::Lead`). A missing role is
 * the least-privileged case, so it gets none of them (design section
 * 8.7 `roles/<role>`: denied actions are absent).
 */
export function leadActionsOffered(role: ProposalRole | undefined): boolean {
  return role === "lead";
}

/**
 * Whether the caller is on the proposal's team: the lead, a team member
 * or the guardian. The registry's TEAM set reads the proposal, the
 * workspace, stage 2 and the negotiation landing, and saves the
 * workspace. A missing role is not on the team.
 */
export function teamReadsOffered(role: ProposalRole | undefined): boolean {
  return role === "lead" || role === "member" || role === "guardian";
}

/**
 * Whether the lead may invite team members (`proposal.add_member`).
 *
 * Interim, pending Daniel and lane W3b: the domain sets no state guard
 * on `AddTeamMember`. The team is formed while the draft is written, so
 * the pages offer it in DRAFT only.
 */
export function teamEditable(s: ProposalState): boolean {
  return s === "DRAFT";
}

/**
 * Whether the lead may add a guardian (`proposal.add_guardian`).
 *
 * `fstp-domain` `proposal/draft.rs`: before the NEGOTIATION gate every
 * proposal is minor-flagged, so a guardian can be added. In NEGOTIATION
 * the cell asks the vault again (state-machine NOTE 14). So the pages
 * offer it in every state before GRANTED that has an exit, which are the
 * NOTE 10 states. Interim, pending Daniel.
 */
export function guardianAddOffered(s: ProposalState): boolean {
  return WITHDRAWABLE.has(s);
}

/**
 * Whether the guardian's consent can be started
 * (`guardian.begin_consent`). Consent opens at the last IRC validation
 * (IRC_REVIEW) and in NEGOTIATION (state-machine NOTE 14; M3 design
 * section 6.5).
 */
export function guardianConsentOpen(s: ProposalState): boolean {
  return s === "IRC_REVIEW" || s === "NEGOTIATION";
}

/**
 * The states in which a proposal has passed stage 1 into stage 2, so
 * stage 2 questions can exist. A WITHDRAWN proposal may have left before
 * stage 2, so it is not listed.
 */
const AFTER_STAGE1: ReadonlySet<ProposalState> = new Set<ProposalState>([
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "DECLINED",
  "NEGOTIATION",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "TERMINATED",
]);

/** Whether the stage 2 page reads the questions (`stage2.view`) in `s`. */
export function stage2Readable(s: ProposalState): boolean {
  return AFTER_STAGE1.has(s);
}
