/**
 * The contract of the review pages (M4 lane W4c, L-UI-REVIEW): the
 * coordinator, reviewer, committee and IRC pages of journeys J5 to J8 (M4
 * design section 2.2).
 *
 * The test author states it here, before the pages exist, as the W1c
 * test author did in `web/test/support/contract.ts`. Every page path,
 * element id, scenario route and page-logic export below is the test
 * author's reading of design sections 2, 3.6, 3.9 and 8.7. Interim,
 * pending Daniel, the lead and the page agent of this lane. The API
 * routes are the ones design section 2.2 names, below `/api/v1`.
 *
 * Three parts:
 *
 * 1. The e2e cell's review scenario (`POST /test/scenario/review`).
 * 2. The page paths and element ids the journey specs drive.
 * 3. The pure page-logic modules the unit specs in `unit/` import from
 *    the tsc build in `web/dist`.
 */

// ---------------------------------------------------------------------------
// 1. The review scenario of the e2e cell
// ---------------------------------------------------------------------------

/**
 * The control route that seeds a review scenario. Like the M3 negotiation
 * scenario, the e2e cell builds it from genesis through production
 * commands and returns only ids, invitation links and canaries.
 */
export const REVIEW_SCENARIO_ROUTE = '/test/scenario/review';

/**
 * Where the seeded call stands. The call is published and its deadline
 * has passed in each stage. People are granted their roles with accepted
 * confidentiality terms and a verified identity (SoD-09), so each
 * persona only enrols a passkey from its invitation link.
 *
 * - `submitted`: x, z, w and v are SUBMITTED. Nothing is declared.
 * - `stage1`: x and w are in STAGE1. R1, R2 and R3 are assigned to x,
 *   and R1 and R2 to w. No reviewer has declared.
 * - `stage1_scored`: as `stage1`, and every assignee declared no
 *   conflict and scored. x scores above P-02 and w at or below it.
 * - `stage2`: x is in STAGE2 with R1 and R2 assigned and declared.
 * - `ranked`: x, v and w are RANKED with ranking summaries, and their
 *   effective scores fall strictly in that order. Each summary repeats
 *   the proposal's seeded title and neutral summary, so the specs can
 *   find them in the ranking view. R4 declared a conflict
 *   on w, so R4 is recused from the cut-off vote. R1, R2, R3 and H1 are
 *   the committee members who are not recused.
 * - `ranked_tie`: x and w are RANKED with equal effective scores.
 * - `irc_review`: x, v and u are in IRC_REVIEW, with I1 and I2 assigned
 *   to each and no declaration made. v is minor-flagged without a
 *   verified consent record. A later call is published, so
 *   `future_call` is true. The cut-off round's rationale and tie-break
 *   hold the deliberation canaries.
 */
export type ReviewStage =
  | 'submitted'
  | 'stage1'
  | 'stage1_scored'
  | 'stage2'
  | 'ranked'
  | 'ranked_tie'
  | 'irc_review';

/** The personas of design section 2.1 that this lane's pages serve. */
export type PersonaKey = 'c1' | 'r1' | 'r2' | 'r3' | 'r4' | 'h1' | 'i1' | 'i2';

/** The proposals of design section 2.1, plus u, a further nominee. */
export type ProposalKey = 'x' | 'y' | 'z' | 'v' | 'w' | 'u';

/** One persona: an invitation to enrol a passkey on the cell origin. */
export interface Persona {
  /** `<origin>/auth/invite#<token>`, as the M3 invitation pages take it. */
  readonly invite_url: string;
  /**
   * The synthetic name the pages show for this Judging member, such as
   * in the reviewer and delegation choices. It is no applicant's
   * identity attribute.
   */
  readonly label: string;
}

/** One P-01 criterion, in P-01 order. */
export interface SeededCriterion {
  readonly id: string;
  /** N of P-01: the top of the integer scale 0 to N. */
  readonly max: number;
}

/** One seeded proposal. Absent keys are proposals the stage does not hold. */
export interface SeededProposal {
  readonly id: string;
  /** The state tag, such as `STAGE1`, as `state-machine.md` names it. */
  readonly state: string;
  /** The title and the applicant-written neutral summary (Q9). */
  readonly title: string;
  readonly neutral_summary: string;
  /** Reviewer assignment ids by persona. */
  readonly assignments: Readonly<Partial<Record<PersonaKey, string>>>;
  /** IRC assignment ids by persona. */
  readonly irc_assignments: Readonly<Partial<Record<PersonaKey, string>>>;
}

/** What `POST /test/scenario/review {stage}` returns. */
export interface ReviewScenario {
  readonly programme: string;
  readonly call: string;
  /** Whether a later call of the programme is published (NOTE 7). */
  readonly future_call: boolean;
  /** P-01 criteria in P-01 order. */
  readonly criteria: readonly SeededCriterion[];
  /** P-09 knock-out criterion ids, in P-09 order. */
  readonly knock_out: readonly string[];
  readonly people: Readonly<Record<PersonaKey, Persona>>;
  readonly proposals: Readonly<Partial<Record<ProposalKey, SeededProposal>>>;
  /**
   * Strings that only identity attributes of the applicants hold: the
   * vault's names, countries and declared affiliations, and the
   * applicants' login emails and display names. No Judging page may show
   * one before NEGOTIATION (I-17), and no response to a Judging page may
   * carry one.
   */
  readonly identity_canaries: readonly string[];
  /**
   * Strings that only committee deliberation holds: cut-off rationale,
   * tie-break text, ballots. The IRC case never shows one (R-IR-03).
   * Empty before `irc_review`.
   */
  readonly deliberation_canaries: readonly string[];
  /** A string in the full content of x, shown only after a declaration. */
  readonly content_canary: string;
}

// ---------------------------------------------------------------------------
// 2. Pages and element ids
// ---------------------------------------------------------------------------

/**
 * The page paths below `/app/` (design section 3.9: one shell, routed by
 * `web/src/core/router.ts`). Each builder takes an id from the scenario.
 */
export const REVIEW_PAGES = {
  // J5, the FSTP coordinator.
  intake: (call: string) => `/app/calls/${call}/intake`,
  coordinatorDeclaration: (proposal: string) => `/app/proposals/${proposal}/declaration`,
  knockOut: (proposal: string) => `/app/proposals/${proposal}/knock-out`,
  assignments: (proposal: string) => `/app/proposals/${proposal}/assignments`,
  board: (call: string) => `/app/calls/${call}/board`,
  notifiableConflicts: (call: string) => `/app/calls/${call}/notifiable-conflicts`,
  // J6, assigned reviewers.
  myAssignments: () => '/app/me/assignments',
  assignment: (assignment: string) => `/app/assignments/${assignment}`,
  rankingSummary: (assignment: string) => `/app/assignments/${assignment}/summary`,
  stage2: (assignment: string) => `/app/assignments/${assignment}/stage2`,
  // J7, the committee.
  ranking: (call: string) => `/app/calls/${call}/ranking`,
  round: (round: string) => `/app/cut-off-rounds/${round}`,
  // J8, the IRC.
  myIrcCases: () => '/app/me/irc-cases',
  ircCase: (assignment: string) => `/app/irc-assignments/${assignment}`,
} as const;

/** The API routes of design section 2.2 that the specs call from a page. */
export const REVIEW_API = {
  content: (proposal: string) => `/api/v1/proposals/${proposal}/content`,
  declarationView: (proposal: string) => `/api/v1/proposals/${proposal}/declaration-view`,
  scores: (assignment: string) => `/api/v1/assignments/${assignment}/scores`,
  assignmentsOf: (proposal: string) => `/api/v1/proposals/${proposal}/assignments`,
  admission: (proposal: string) => `/api/v1/proposals/${proposal}/admission`,
  ranking: (call: string) => `/api/v1/calls/${call}/ranking`,
  ballot: (round: string) => `/api/v1/cut-off-rounds/${round}/ballot`,
  delegation: (round: string) => `/api/v1/cut-off-rounds/${round}/delegation`,
  cutOffRounds: (call: string) => `/api/v1/calls/${call}/cut-off-rounds`,
  ircCase: (assignment: string) => `/api/v1/irc-assignments/${assignment}/case`,
  ircReview: (assignment: string) => `/api/v1/irc-assignments/${assignment}/review`,
} as const;

/**
 * Element ids and attributes of the pages. Each control also has an
 * accessible name from the message catalogue (R-NF-03, R-NF-04).
 *
 * - The state of the proposal a page shows is the `data-state` attribute
 *   of `#proposal-state`, as a `state-machine.md` tag such as `STAGE1`.
 * - A refusal or failure shows an element with `role="alert"`. It names
 *   the rule only, never an account (design section 3.7).
 * - A completed action shows its outcome in `#page-status`, which has
 *   `role="status"`.
 * - While a page loads its data, its `main` holds an element with
 *   `aria-busy="true"`. Once loaded, none is left.
 * - A field error sets `aria-invalid="true"` on the control and links
 *   the message through `aria-describedby` (`web/src/core/a11y.ts`).
 */
export const REVIEW_UI = {
  state: '#proposal-state',
  status: '#page-status',
  declaration: {
    form: '#declare-form',
    title: '#declaration-title',
    summary: '#declaration-summary',
    no: '#declare-conflicted-no',
    yes: '#declare-conflicted-yes',
    notifiable: '#declare-notifiable',
    submit: '#declare-submit',
  },
  content: '#proposal-content',
  score: {
    form: '#score-form',
    input: (criterion: string) => `#score-${criterion}`,
    submit: '#score-submit',
    errors: '#score-errors',
    correct: '#score-correct',
    reason: '#score-reason',
  },
  summary: {
    title: '#summary-title',
    neutral: '#summary-neutral',
    rationale: '#summary-rationale',
    submit: '#summary-submit',
  },
  stage2: {
    question: '#question-text',
    ask: '#question-submit',
    noQuestions: '#no-questions',
    thread: '#stage2-thread',
    rank: '#rank-submit',
  },
  knockOut: {
    pass: (criterion: string) => `#knockout-${criterion}-pass`,
    fail: (criterion: string) => `#knockout-${criterion}-fail`,
    reason: '#knockout-reason',
    submit: '#knockout-submit',
  },
  assign: {
    reviewer: '#assign-reviewer',
    submit: '#assign-submit',
    /** Each check shows `data-check="pass"` or `data-check="fail"` only (R-CF-03). */
    p39: '#check-p39',
    proximity: '#check-proximity',
    admit: '#admit-submit',
  },
  board: {
    /** One row per proposal, with the proposal's state tag in `data-state`. */
    row: (proposal: string) => `tr[data-proposal="${proposal}"]`,
    close: (proposal: string) => `#close-stage1-${proposal}`,
  },
  notifiable: {
    list: '#notifiable-list',
    /** One draft per notifiable conflict, marked with its proposal (R-CF-04). */
    item: (proposal: string) => `#notifiable-list [data-proposal="${proposal}"]`,
  },
  /**
   * Lists link to their pages by path: the intake queue to each
   * declaration page, and the assignment and IRC case lists to each
   * assignment page, as `a[href="<path>"]`.
   */
  link: (path: string) => `a[href="${path}"]`,
  ranking: {
    table: '#ranking-table',
    /**
     * One row per RANKED proposal, in the server's order. A recused row
     * has `data-recused="true"` and shows nothing but its position and
     * the word (Q16). Every other row has one cell per P-01 criterion,
     * marked `data-criterion="<id>"`, with the weighted score (D9).
     */
    row: (proposal: string) => `tr[data-proposal="${proposal}"]`,
    remainingBudget: '#remaining-budget',
    findings: '#findings',
    nominated: '#round-nominated',
    rationale: '#round-rationale',
    tieBreak: '#round-tie-break',
    open: '#round-submit',
  },
  round: {
    /**
     * One row per proposal of the round's order, with its state tag in
     * `data-state` once the cut-off is recorded.
     */
    row: (proposal: string) => `tr[data-proposal="${proposal}"]`,
    for: '#ballot-for',
    against: '#ballot-against',
    abstain: '#ballot-abstain',
    cast: '#ballot-submit',
    delegateTo: '#delegate-to',
    delegate: '#delegate-submit',
    record: '#record-cutoff',
  },
  irc: {
    case: '#irc-case',
    outcome: '#irc-outcome',
    validate: '#verdict-validate',
    concern: '#verdict-concern',
    concernText: '#concern-text',
    submit: '#verdict-submit',
  },
} as const;

// ---------------------------------------------------------------------------
// 3. Page-logic modules (unit specs, from `web/dist`)
// ---------------------------------------------------------------------------

/**
 * A field error of a page form. `field` is a criterion id or the form
 * field's name. The page shows each in its error summary, linked to its
 * control (R-NF-03).
 */
export interface FieldError {
  readonly field: string;
  readonly reason: string;
}

/** A form read: the value to send, or every field error in form order. */
export type FormRead<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly FieldError[] };

/**
 * What one criterion field reads. Interim, pending Daniel: a score is
 * the canonical ASCII decimal text of an integer from 0 to N (P-01
 * NOTE 6), `0` or a non-zero digit followed by digits. The field never
 * rewrites what the user typed, so `03`, ` 3` and `3.0` are refused
 * rather than normalised.
 */
export type ScoreRead =
  | { readonly ok: true; readonly value: number }
  | { readonly ok: false; readonly reason: 'required' | 'not_an_integer' | 'above_scale' };

/** One P-01 criterion as the score sheet takes it. */
export interface CriterionSpec {
  readonly id: string;
  /** N, a safe integer of at least 1. */
  readonly max: number;
}

/** A ranking summary as `RecordRankingSummary` takes it. */
export interface RankingSummary {
  readonly title: string;
  readonly neutral_summary: string;
  readonly rationale: string;
}

/**
 * `web/src/reviewer/forms.ts`: the score sheet and the ranking summary
 * (J6).
 *
 * - `readCriterionScore`: `""` gives `required`. Text that is not
 *   canonical gives `not_an_integer`. A canonical integer above `max`
 *   gives `above_scale`, however many digits it has.
 * - `readScoreSheet`: one value per criterion in P-01 order (NOTE 6:
 *   every reviewer scores every criterion). A missing input reads as
 *   `""`. Inputs that name no criterion are ignored. Errors list every
 *   failing criterion in P-01 order, with the criterion id as `field`
 *   and the `ScoreRead` reason.
 * - `readScoreCorrection`: the sheet plus a reason, which `CorrectScore`
 *   requires (I-23: a correction is a new record with its reason). An
 *   empty reason gives `{field: "reason", reason: "required"}` after the
 *   criterion errors. The reason is passed on exactly as typed.
 * - `readRankingSummary`: every field is required. Errors use the field
 *   names `title`, `neutral_summary` and `rationale`, in that order, with
 *   reason `required`. Values are passed on exactly as typed.
 */
export interface ReviewerFormsModule {
  readCriterionScore(text: string, max: number): ScoreRead;
  readScoreSheet(
    criteria: readonly CriterionSpec[],
    inputs: Readonly<Record<string, string>>,
  ): FormRead<readonly number[]>;
  readScoreCorrection(
    criteria: readonly CriterionSpec[],
    inputs: Readonly<Record<string, string>>,
    reason: string,
  ): FormRead<{ readonly values: readonly number[]; readonly reason: string }>;
  readRankingSummary(input: RankingSummary): FormRead<RankingSummary>;
}

/** What the declaration form holds. `null` is no choice yet. */
export interface DeclarationInput {
  readonly conflicted: 'yes' | 'no' | null;
  readonly notifiable: boolean;
}

/**
 * `web/src/reviewer/declaration.ts`: the one declaration form of the
 * coordinator, the assigned reviewers and the IRC members (R-CF-02).
 *
 * - No answer is preset: `conflicted: null` gives
 *   `{field: "conflicted", reason: "required"}`.
 * - A notifiable conflict is a conflict (R-CF-04): `notifiable` with
 *   `conflicted: "no"` gives `{field: "notifiable", reason:
 *   "needs_conflict"}`.
 */
export interface DeclarationModule {
  readDeclaration(
    input: DeclarationInput,
  ): FormRead<{ readonly conflicted: boolean; readonly notifiable: boolean }>;
}

/** One knock-out result as the form holds it. */
export type KnockOutChoice = 'pass' | 'fail' | null;

/**
 * `web/src/coordinator/forms.ts`: the knock-out form (J5).
 *
 * - Every P-09 criterion needs an explicit result, with no preset:
 *   `{field: <criterion>, reason: "required"}` per missing one, in P-09
 *   order. Choices for unknown criteria are ignored.
 * - A failed criterion needs a reason (`RecordKnockOut`):
 *   `{field: "reason", reason: "required"}` after the criterion errors.
 * - The value lists one outcome per criterion in P-09 order. `reason` is
 *   the text as typed, or null when it is empty.
 */
export interface CoordinatorFormsModule {
  readKnockOut(
    criteria: readonly string[],
    input: {
      readonly results: Readonly<Record<string, KnockOutChoice>>;
      readonly reason: string;
    },
  ): FormRead<{
    readonly outcomes: readonly { readonly criterion: string; readonly passed: boolean }[];
    readonly reason: string | null;
  }>;
}

/** One row of the ranking as the cut-off form orders it, top first. */
export interface CutOffRow {
  readonly proposal: string;
  /** The effective score as the server sends it: a percentage with two decimals. */
  readonly effective: string;
}

/** What the open-round form holds. */
export interface CutOffInput {
  readonly nominated: string;
  readonly rationale: string;
  readonly tie_break: string;
}

/** A vote as the ballot form holds it. */
export type VoteChoice = 'for' | 'against' | 'abstain' | null;

/**
 * `web/src/committee/forms.ts`: the cut-off round and the ballot (J7).
 *
 * - `compareScoreText`: exact comparison of two effective scores, each
 *   canonical `(0|[1-9][0-9]*)\.[0-9]{2}`, with no rounding and no float
 *   (P-02 NOTE 6). Null when either is not canonical.
 * - `readCutOffRound`, mirroring the domain's `plan_cut_off`, with every
 *   error in this field order:
 *   - `order`: `empty` for no rows, `unreadable_score` for a row whose
 *     score is not canonical, and `not_ordered` when a later row scores
 *     higher than an earlier one.
 *   - `nominated`: the rank position, a canonical integer from 0 to the
 *     number of rows. `required`, `not_an_integer` or `out_of_range`.
 *   - `rationale`: required (R-EV-08).
 *   - `tie_break`: required when the rows at positions `nominated` and
 *     `nominated + 1` tie (P-17, NOTE 6). Never required otherwise.
 *   The value carries the order as proposal ids, the position, the
 *   rationale as typed, and the tie-break as typed or null when empty.
 * - `readBallot`: a vote has no preset (R-EV-09):
 *   `{field: "vote", reason: "required"}`.
 */
export interface CommitteeFormsModule {
  compareScoreText(a: string, b: string): -1 | 0 | 1 | null;
  readCutOffRound(
    rows: readonly CutOffRow[],
    input: CutOffInput,
  ): FormRead<{
    readonly order: readonly string[];
    readonly nominated: number;
    readonly rationale: string;
    readonly tie_break: string | null;
  }>;
  readBallot(input: { readonly vote: VoteChoice }): FormRead<{
    readonly vote: 'for' | 'against' | 'abstain';
  }>;
}

/** What the IRC verdict form holds. */
export interface VerdictInput {
  readonly verdict: 'validate' | 'concern' | null;
  readonly concern: string;
}

/**
 * `web/src/irc/forms.ts`: the IRC verdict (J8).
 *
 * - No verdict is preset: `{field: "verdict", reason: "required"}`.
 * - A concern needs its text, which goes to the applicant (R-IR-02):
 *   `{field: "concern", reason: "required"}`.
 * - A validation carries no text, even when the concern field holds
 *   some, so text meant for a concern is never sent with a validation.
 */
export interface IrcFormsModule {
  readVerdict(
    input: VerdictInput,
  ): FormRead<{ readonly verdict: 'validate' } | { readonly verdict: 'concern'; readonly concern: string }>;
}

/** The page-logic modules by their path below `web/src`, without `.ts`. */
export interface PageLogicModules {
  'reviewer/forms': ReviewerFormsModule;
  'reviewer/declaration': DeclarationModule;
  'coordinator/forms': CoordinatorFormsModule;
  'committee/forms': CommitteeFormsModule;
  'irc/forms': IrcFormsModule;
}

/** The exports each module must have. */
export const REQUIRED_EXPORTS: { readonly [K in keyof PageLogicModules]: readonly string[] } = {
  'reviewer/forms': [
    'readCriterionScore',
    'readScoreSheet',
    'readScoreCorrection',
    'readRankingSummary',
  ],
  'reviewer/declaration': ['readDeclaration'],
  'coordinator/forms': ['readKnockOut'],
  'committee/forms': ['compareScoreText', 'readCutOffRound', 'readBallot'],
  'irc/forms': ['readVerdict'],
};

/** The feature folders of this lane (ADR-014, design section 3.9). */
export const JUDGING_FOLDERS = ['coordinator', 'reviewer', 'committee', 'irc'] as const;
