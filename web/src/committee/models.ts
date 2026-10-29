// The read models of the committee's pages (J7, design section 3.6 and
// change D5; lane W4c), with closed checks. Interim, pending Daniel and
// the read models of lanes W1b and W3b: the members are this lane's
// reading of `GetRankingView` and `GetCutOffRound`.
//
// - The ranking view is a list of rows in the server's order. A row
//   where the viewer has a conflict carries its proposal id and the
//   recusal only (Q16). Every other row follows the domain's
//   `RankingRow`: title, neutral summary and rationale written by the
//   assigned reviewers, weighted scores per criterion (D9), the
//   requested amount (D10) and the remaining call budget. It has no
//   findings field (`roles-and-sod.md`).
// - Scores are the server's text with two decimals (P-02 NOTE 6), and
//   amounts are ADR-006 strings. The page never computes either.
// - No row carries an identity field (I-17). A row with any other member
//   refuses the whole view.

import {
  either,
  isAmount,
  isBool,
  isCount,
  isId,
  isScoreText,
  isStateTag,
  isText,
  list,
  nullable,
  oneOf,
  record,
  type Guard,
  type StateTag,
} from "../reviewer/kit.js";

/** One criterion's weighted score: the mean over assigned reviewers of weight times score (D9). */
export interface CriterionScore {
  readonly criterion: string;
  readonly weighted: string;
}

/** A ranking row the viewer may read. */
export interface RankedRow {
  readonly proposal: string;
  readonly recused: false;
  readonly title: string | null;
  readonly neutral_summary: string | null;
  readonly rationale: string | null;
  /** The effective score, a percentage with two decimals. */
  readonly effective: string;
  readonly criterion_scores: readonly CriterionScore[];
  /** The requested total of the effective plan, in EUR. */
  readonly requested: string;
  /** The remaining call budget, in EUR. */
  readonly remaining_budget: string;
}

/** A ranking row where the viewer has a conflict: "recused" only (Q16). */
export interface RecusedRow {
  readonly proposal: string;
  readonly recused: true;
}

export type RankingRow = RankedRow | RecusedRow;

const isRankedRow: Guard<RankedRow> = record<RankedRow>({
  proposal: isId,
  recused: (v): v is false => v === false,
  title: nullable(isText),
  neutral_summary: nullable(isText),
  rationale: nullable(isText),
  effective: isScoreText,
  criterion_scores: list(record<CriterionScore>({ criterion: isId, weighted: isScoreText })),
  requested: isAmount,
  remaining_budget: isAmount,
});

const isRecusedRow: Guard<RecusedRow> = record<RecusedRow>({
  proposal: isId,
  recused: (v): v is true => v === true,
});

/** `GetRankingView`: the ranked proposals of the call, top first. */
export const isRankingView: Guard<readonly RankingRow[]> = list(either(isRecusedRow, isRankedRow));

/** What `OpenCutOffRound` answers: the drawn round id (D5). */
export const isOpenedRound: Guard<{ readonly round: string }> = record<{ readonly round: string }>({ round: isId });

/** A vote as the domain spells it. */
export type Vote = "For" | "Against" | "Abstain";

/** One proposal of the round's order, with its state. */
export interface RoundRow {
  readonly proposal: string;
  readonly state: StateTag;
}

/** The viewer's own part in the round. */
export interface RoundViewer {
  /** A conflict on any ranked proposal of the call recuses the member from the vote. */
  readonly recused: boolean;
  readonly own_vote: Vote | null;
  /** The member the viewer delegated to, by account id. */
  readonly delegated_to: string | null;
}

/** `GetCutOffRound`: one round of the cut-off vote (D5). */
export interface RoundView {
  readonly round: string;
  readonly call: string;
  readonly recorded: boolean;
  readonly order: readonly RoundRow[];
  readonly nominated: number;
  readonly rationale: string;
  readonly tie_break: string | null;
  readonly ballots_cast: number;
  readonly viewer: RoundViewer;
  /** The members a vote may be delegated to: none is recused (P-16 NOTE 8). */
  readonly delegates: readonly { readonly account: string; readonly label: string }[];
}

export const isRoundView: Guard<RoundView> = record<RoundView>({
  round: isId,
  call: isId,
  recorded: isBool,
  order: list(record<RoundRow>({ proposal: isId, state: isStateTag })),
  nominated: isCount,
  rationale: isText,
  tie_break: nullable(isText),
  ballots_cast: isCount,
  viewer: record<RoundViewer>({
    recused: isBool,
    own_vote: nullable(oneOf<Vote>("For", "Against", "Abstain")),
    delegated_to: nullable(isId),
  }),
  delegates: list(record<{ readonly account: string; readonly label: string }>({ account: isId, label: isText })),
});
