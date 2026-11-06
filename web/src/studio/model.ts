// The page logic of the Planning Studio, "Programme set-up" in the plain
// pack (`SPEC/12-journey-ui.md` section 8.2, R-PG-01 to R-PG-04, R-PC-03,
// I-12, I-65 to I-67; `docs/design/05-programme-staff-studio.md`).
//
// This module is pure: it touches no DOM, so Node can load it.
//
// - The 11 creator steps stay the source of truth (`creator/model.ts`
//   `CREATOR_STEPS`). The five studios only group them for navigation.
// - Every state here comes from a server read: the creator's validation
//   report, the import proposals, the impact read, `me.roles` and
//   `calls.get`. The page never runs a check of its own.

import { CREATOR_STEPS, REVIEW_STEP, isProgrammeId, record, stepOfResult, type CreatorStep, type ProposalRow, type Report } from "../creator/model.js";
import { byId, type MyRoles } from "../home/model.js";

/** The route segment of a creator step, the review included. */
export type StepId = CreatorStep["id"];

/** The five studios of section 8.2. */
export type StudioId = "territory" | "border" | "instruments" | "crew" | "seal";

/** One studio and the creator steps it groups. */
export interface Studio {
  readonly id: StudioId;
  readonly steps: readonly StepId[];
}

/** The grouping of section 8.2, in the order of the creator steps. */
export const STUDIOS: readonly Studio[] = [
  { id: "territory", steps: ["funder", "identity"] },
  { id: "border", steps: ["eligibility", "funding"] },
  { id: "instruments", steps: ["evaluation", "money", "contract"] },
  { id: "crew", steps: ["support", "people", "comms"] },
  { id: "seal", steps: ["review"] },
];

/** The studio that holds `step`, or null for a segment that names no step. */
export function studioOf(step: string): Studio | null {
  return STUDIOS.find((s) => s.steps.some((x) => x === step)) ?? null;
}

/**
 * What the report says of a step: no result, only acknowledged
 * warnings, unacknowledged warnings, failures, or no report read.
 */
export type Condition = "valid" | "warnings" | "failures" | "unknown";

/** One step as the studio shows it. */
export interface StepState {
  readonly id: StepId;
  readonly number: number;
  readonly condition: Condition;
  readonly failures: number;
  /** Warnings not yet acknowledged at the report's revision. */
  readonly warnings: number;
  /** Whether the step opens: every step before it validated. */
  readonly open: boolean;
  /** The first earlier step that did not validate, while locked. */
  readonly waitsFor: StepId | null;
}

/**
 * The state of each creator step from the creator's report (R-PG-01).
 * A result shows on the step its field or check belongs to, else on the
 * review. A step opens only when every step before it has no failure.
 * Warnings never lock a step: they are acknowledged on the review
 * (I-66). Without a report every condition is unknown and only step 1
 * opens.
 */
export function stepStates(report: Report | null): readonly StepState[] {
  let waitsFor: StepId | null = null;
  return CREATOR_STEPS.map((s) => {
    let failures = 0;
    let warnings = 0;
    for (const r of report?.results ?? []) {
      const home = stepOfResult(r) ?? REVIEW_STEP;
      if (home !== s.id) continue;
      if (r.severity === "failure") {
        failures += 1;
      } else if (!r.acknowledged) {
        warnings += 1;
      }
    }
    const condition: Condition =
      report === null ? "unknown" : failures > 0 ? "failures" : warnings > 0 ? "warnings" : "valid";
    const state: StepState = { id: s.id, number: s.number, condition, failures, warnings, open: waitsFor === null, waitsFor };
    if (waitsFor === null && (condition === "failures" || condition === "unknown")) {
      waitsFor = s.id;
    }
    return state;
  });
}

/** The edit key of a call's text, beside the creator's field keys. */
export const CALL_TEXT = "call.text";

/** The edits that return an approved call to DRAFT (R-PC-03 NOTE): the call text, P-01 and P-09. */
const RETURNS_TO_DRAFT: ReadonlySet<string> = new Set([CALL_TEXT, "evaluation.p01_criteria", "evaluation.p09_knock_outs"]);

/** Whether saving an edit of `key` after approval returns the call to DRAFT. */
export function returnsCallToDraft(key: string): boolean {
  return RETURNS_TO_DRAFT.has(key);
}

/** A call state of `state-machine.md`. Open and closed are not states. */
export type CallState = "DRAFT" | "APPROVED" | "PUBLISHED";

/** One call as the studio lists it. */
export interface CallRow {
  readonly call: string;
  readonly state: CallState;
  /** Whether the cell says the call is open now, from its own clock. */
  readonly open: boolean;
  readonly title: string | null;
}

const CALL_STATES: Readonly<Record<string, CallState>> = { draft: "DRAFT", approved: "APPROVED", published: "PUBLISHED" };

/** Reads the `call`, `status`, `open` and `title` members of a `calls.get` reply. Null otherwise. */
export function readCallState(v: unknown): CallRow | null {
  const o = record(v);
  if (o === null) return null;
  const call = o["call"];
  const status = o["status"];
  const open = o["open"];
  const title = o["title"];
  if (typeof call !== "string" || !isProgrammeId(call) || typeof status !== "string" || typeof open !== "boolean") return null;
  const state = Object.hasOwn(CALL_STATES, status) ? CALL_STATES[status] : undefined;
  if (state === undefined) return null;
  if (title !== undefined && typeof title !== "string") return null;
  return { call, state, open, title: title ?? null };
}

/** The published calls the caller's programme bindings on `p` reach, ascending. */
export function programmeCalls(r: MyRoles, p: string): string[] {
  const out = new Set<string>();
  for (const b of r.roles) {
    if (b.proposal === null && b.programme === p) {
      for (const c of b.calls) out.add(c);
    }
  }
  return [...out].sort(byId);
}

/**
 * Whether the page offers the call approval to the caller: a programme
 * manager of `p`, the role `call.approve` acts as. A caller who only
 * drafts calls is offered none (R-PC-03). The server refuses a drafter
 * of the call in any case, so this only keeps the page honest.
 */
export function mayApproveCalls(r: MyRoles, p: string): boolean {
  return r.roles.some((b) => b.proposal === null && b.programme === p && b.role === "programme_manager");
}

/** The import proposals no programme manager has resolved yet (I-65), in server order. */
export function awaitingConfirmation(rows: readonly ProposalRow[]): ProposalRow[] {
  return rows.filter((r) => r.resolution === null);
}

/** Reads `{calls: [{call}]}` of `creator.impact` (R-PG-04). Null otherwise. */
export function readImpact(v: unknown): string[] | null {
  const list = record(v)?.["calls"];
  if (!Array.isArray(list)) return null;
  const out: string[] = [];
  for (const x of list as unknown[]) {
    const c = record(x)?.["call"];
    if (typeof c !== "string" || !isProgrammeId(c)) return null;
    out.push(c);
  }
  return out;
}
