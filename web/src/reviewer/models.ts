// The read models of the assigned reviewers' pages (J6, design section
// 3.6; lane W4c), with closed checks. Interim, pending Daniel and the
// read models of lane W3b: the members are this lane's reading of
// `GetScoreSheet` and `GetStage2Thread`. None carries an identity field
// (I-17). Reviewers appear under their P-11 handles in the thread.

import { isCount, isId, isStateTag, isText, list, nullable, oneOf, record, isBool, type Guard, type StateTag } from "./kit.js";

/** One P-01 criterion of the sheet, in P-01 order. */
export interface SheetCriterion {
  readonly id: string;
  /** The criterion's wording. */
  readonly text: string;
  /** N of P-01: the top of the integer scale 0 to N. */
  readonly max: number;
}

/** The reviewer's latest valid score for the plan being scored. */
export interface CurrentScore {
  /** The score's path name for a correction: the plan version it scored. */
  readonly score: string;
  /** One value per criterion, in P-01 order. */
  readonly values: readonly number[];
}

/** `GetScoreSheet`: what the reviewer scores now. */
export interface ScoreSheet {
  readonly stage: "One" | "Two";
  /** The plan version being scored: the submitted plan, or the stage 2 revision. */
  readonly plan: string;
  readonly criteria: readonly SheetCriterion[];
  readonly current: CurrentScore | null;
}

const isCriterion: Guard<SheetCriterion> = record<SheetCriterion>({ id: isId, text: isText, max: isCount });

export const isScoreSheet: Guard<ScoreSheet> = record<ScoreSheet>({
  stage: oneOf("One", "Two"),
  plan: isId,
  criteria: list(isCriterion),
  current: nullable(record<CurrentScore>({ score: isId, values: list(isCount) })),
});

/** One entry of the stage 2 thread. */
export interface ThreadEntry {
  readonly kind: "question" | "answer";
  /** The reviewer's P-11 handle on a question, or null. */
  readonly author: string | null;
  readonly text: string;
}

/** `GetStage2Thread`: the questions and answers of stage 2 (R-EV-05). */
export interface Stage2Thread {
  readonly state: StateTag;
  /** Whether the question window is open (NOTE 4). */
  readonly open: boolean;
  /** Whether the caller recorded "no questions". */
  readonly own_no_questions: boolean;
  readonly entries: readonly ThreadEntry[];
}

export const isStage2Thread: Guard<Stage2Thread> = record<Stage2Thread>({
  state: isStateTag,
  open: isBool,
  own_no_questions: isBool,
  entries: list(
    record<ThreadEntry>({ kind: oneOf("question", "answer"), author: nullable(isText), text: isText }),
  ),
});
