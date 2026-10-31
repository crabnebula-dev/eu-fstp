// The read models of the FSTP coordinator's pages (J5, design section
// 3.6; lane W4c), with closed checks. Interim, pending Daniel and the
// read models of lane W3b: the members are this lane's reading of
// `GetIntakeQueue`, `GetCallBoard`, `ListNotifiableConflicts` and the
// assignment view. None carries an identity field of an applicant
// (I-17). Committee members appear by the label the programme gives
// them, and the SoD-10 and SoD-11 checks state pass or fail only
// (R-CF-03).

import { isId, isStateTag, isText, list, oneOf, record, type Guard, type StateTag } from "../reviewer/kit.js";

/** One P-09 knock-out criterion, in P-09 order. */
export interface KnockOutCriterion {
  readonly id: string;
  readonly text: string;
}

/** One proposal of the call, as "Proposal" plus its id, its state and its title. */
export interface ProposalRow {
  readonly proposal: string;
  readonly state: StateTag;
  readonly title: string;
}

const isProposalRow: Guard<ProposalRow> = record<ProposalRow>({ proposal: isId, state: isStateTag, title: isText });

/** `GetIntakeQueue`: the call's P-09 criteria and its submitted proposals. */
export interface IntakeQueue {
  readonly knock_out: readonly KnockOutCriterion[];
  readonly proposals: readonly ProposalRow[];
}

export const isIntakeQueue: Guard<IntakeQueue> = record<IntakeQueue>({
  knock_out: list(record<KnockOutCriterion>({ id: isId, text: isText })),
  proposals: list(isProposalRow),
});

/** `GetCallBoard`: the call's proposals in review. */
export const isBoard: Guard<readonly ProposalRow[]> = list(isProposalRow);

/** A pass or fail outcome, with no reason and no account (R-CF-03). */
export type CheckOutcome = "pass" | "fail";

/** The assignment view of one proposal. */
export interface AssignmentView {
  readonly state: StateTag;
  /** The active reviewer assignments. */
  readonly assigned: readonly { readonly assignment: string; readonly label: string }[];
  /** The committee members the coordinator may assign. */
  readonly candidates: readonly { readonly account: string; readonly label: string }[];
  /** SoD-10 (P-39 organisations) and SoD-11 (P-38 proximity) over the current assignees. */
  readonly checks: { readonly p39: CheckOutcome; readonly proximity: CheckOutcome };
}

const isOutcome = oneOf<CheckOutcome>("pass", "fail");

export const isAssignmentView: Guard<AssignmentView> = record<AssignmentView>({
  state: isStateTag,
  assigned: list(record<{ readonly assignment: string; readonly label: string }>({ assignment: isId, label: isText })),
  candidates: list(record<{ readonly account: string; readonly label: string }>({ account: isId, label: isText })),
  checks: record<{ readonly p39: CheckOutcome; readonly proximity: CheckOutcome }>({
    p39: isOutcome,
    proximity: isOutcome,
  }),
});

/** `ListNotifiableConflicts`: one draft per notifiable conflict (R-CF-04). */
export const isNotifiableList: Guard<readonly { readonly proposal: string }[]> = list(
  record<{ readonly proposal: string }>({ proposal: isId }),
);
