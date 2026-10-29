// The read model of the IRC case (J8, design section 3.6; lane W4c),
// with a closed check. Interim, pending Daniel and the read models of
// lane W3b: the members are this lane's reading of `GetIrcCase`.
//
// The case holds the nominated proposal and its outcome, and nothing of
// the committee's work (R-IR-03). The check is closed, so a case that
// carried any other member is refused whole, never shown. It carries no
// identity field of the applicant either (I-17).

import { isId, isStateTag, isText, oneOf, record, type Guard, type StateTag } from "../reviewer/kit.js";

/** The outcome that brought the proposal to the IRC. */
export type CaseOutcome = "nominated";

/** `GetIrcCase`: the nominated proposal and its outcome. */
export interface IrcCase {
  readonly proposal: string;
  readonly state: StateTag;
  readonly title: string;
  readonly text: string;
  readonly outcome: CaseOutcome;
}

export const isIrcCase: Guard<IrcCase> = record<IrcCase>({
  proposal: isId,
  state: isStateTag,
  title: isText,
  text: isText,
  outcome: oneOf<CaseOutcome>("nominated"),
});
