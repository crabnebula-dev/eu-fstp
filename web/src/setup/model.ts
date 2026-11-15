// The page logic of the programme set-up wizard and the set-up progress
// page (`docs/design/11-programme-setup-wizard.md`; R-PG-01, I-66, I-67,
// SoD-01 to SoD-09, R-PC-03, ADR-021).
//
// This module is pure: it touches no DOM, so Node can load it.
//
// - The wizard adds no domain concept and no rule. Its seven stages only
//   group the 11 creator steps, which stay the source of truth
//   (`creator/model.ts` `CREATOR_STEPS`). A stage is done when the
//   creator's report validates each of its steps (`studio/model.ts`
//   `stepStates`).
// - Every check the wizard shows is a projection. The server checks every
//   rule again at each command (I-92). The live separation of duties
//   lines here read only the team the invitation list already shows.
// - The progress page is built from the existing reads: the draft, the
//   report, the invitation list and the programme's calls. It adds no
//   read of its own.

import { type Report } from "../creator/model.js";
import { type InvitationRow, type InvitationState } from "../people/model.js";
import { stepStates, type StepId } from "../studio/model.js";

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

/** The seven stages of the wizard, in order (design doc 11 section 5). */
export type StageId = "start" | "programme" | "applicants" | "evaluation" | "team" | "communications" | "review";

/** One stage and the creator steps it groups. */
export interface Stage {
  readonly id: StageId;
  readonly number: number;
  readonly steps: readonly StepId[];
}

/** The grouping of design doc 11 section 5. Stage 1 opens the draft and holds no step. */
export const STAGES: readonly Stage[] = [
  { id: "start", number: 1, steps: [] },
  { id: "programme", number: 2, steps: ["funder", "identity"] },
  { id: "applicants", number: 3, steps: ["eligibility", "funding"] },
  { id: "evaluation", number: 4, steps: ["evaluation", "money", "contract", "support"] },
  { id: "team", number: 5, steps: ["people"] },
  { id: "communications", number: 6, steps: ["comms"] },
  { id: "review", number: 7, steps: ["review"] },
];

/** The stages a route of one programme names: every stage but the start. */
export type DraftStageId = Exclude<StageId, "start">;

/** Whether `s` is the route segment of a stage of a draft. */
export function isDraftStage(s: string): s is DraftStageId {
  return s !== "start" && STAGES.some((x) => x.id === s);
}

/** The stage that holds creator step `step`, or null. */
export function stageOfStep(step: string): Stage | null {
  return STAGES.find((s) => s.steps.some((x) => x === step)) ?? null;
}

/** The stage after `id`, or null after the review. */
export function nextStage(id: StageId): StageId | null {
  const i = STAGES.findIndex((s) => s.id === id);
  return STAGES[i + 1]?.id ?? null;
}

/** The stage before `id`, or null before the start. */
export function previousStage(id: StageId): StageId | null {
  const i = STAGES.findIndex((s) => s.id === id);
  return i <= 0 ? null : (STAGES[i - 1]?.id ?? null);
}

/** The page paths of the wizard and the progress page. */
export const SETUP_PATHS = {
  start: "/app/setup/new",
  stage: (p: string, stage: DraftStageId): string => `/app/programmes/${p}/setup/${stage}`,
  progress: (p: string): string => `/app/programmes/${p}/setup/progress`,
} as const;

/**
 * How a stage stands: `done` once the report validates each of its steps
 * (warnings left for the review count as done), `open` when every stage
 * before it is done, else `locked`.
 */
export type StageCondition = "done" | "open" | "locked";

/** One stage as the stage bar and the summary panel show it. */
export interface StageState {
  readonly id: StageId;
  readonly number: number;
  readonly condition: StageCondition;
  /** Failures of the report on the stage's steps. */
  readonly failures: number;
  /** Warnings not acknowledged yet on the stage's steps. */
  readonly warnings: number;
}

/**
 * The state of each stage from the creator's report (R-PG-01). The start
 * is done once a draft exists, and open before. The review is done once activation is
 * requested, since it holds no field. A stage is done, or open, only when
 * each stage before it is done, as a creator step opens only after the steps before
 * it validate. Without a report only the first open stage opens.
 */
export function stageStates(report: Report | null, draftExists: boolean, requested: boolean): readonly StageState[] {
  const steps = stepStates(report);
  let blocked = false;
  return STAGES.map((s) => {
    let failures = 0;
    let warnings = 0;
    let valid = true;
    for (const id of s.steps) {
      const st = steps.find((x) => x.id === id);
      if (st === undefined) continue;
      failures += st.failures;
      warnings += st.warnings;
      if (st.condition === "failures" || st.condition === "unknown") valid = false;
    }
    const done =
      !blocked &&
      (s.id === "start" ? draftExists : s.id === "review" ? draftExists && requested : draftExists && report !== null && valid);
    const condition: StageCondition = done ? "done" : blocked ? "locked" : "open";
    if (!done) blocked = true;
    return { id: s.id, number: s.number, condition, failures, warnings };
  });
}

/** The number of done stages. */
export function doneCount(states: readonly StageState[]): number {
  return states.filter((s) => s.condition === "done").length;
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/** Microseconds in one day. */
const DAY_MICROS = 86_400_000_000;

/** A date as a date control holds it: `YYYY-MM-DD`. */
const DATE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;

/** The UTC midnight of `date`, in milliseconds, or null for no real date. */
function utcMillis(date: string): number | null {
  const m = DATE.exec(date);
  if (m === null) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  const ms = Date.UTC(y, mo - 1, d);
  const back = new Date(ms);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null;
  return ms;
}

/**
 * The start instant of a role that starts on `date`: its UTC midnight in
 * microseconds, as the `start` member of `creator.invite` spells it (design
 * doc 11, Q3). Null for anything that is not a real date after 1970.
 */
export function startMicros(date: string): string | null {
  const ms = utcMillis(date);
  return ms === null || ms < 0 ? null : (BigInt(ms) * 1000n).toString();
}

/**
 * The end instant of a role that ends on `date`: the UTC midnight after
 * it, so the role holds through that whole day. Null for no real date.
 */
export function endMicros(date: string): string | null {
  const ms = utcMillis(date);
  return ms === null || ms < 0 ? null : ((BigInt(ms) + 86_400_000n) * 1000n).toString();
}

/** The `YYYY-MM-DD` UTC date of an instant in microseconds, or null. */
function dateOfMicros(micros: bigint): string | null {
  const ms = Number(micros / 1000n);
  if (!Number.isSafeInteger(ms)) return null;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

/** A canonical decimal string of microseconds, as a bigint, or null. */
function micros(s: string | null): bigint | null {
  return s !== null && /^(0|[1-9][0-9]{0,18})$/.test(s) ? BigInt(s) : null;
}

/** The date a role starts on, from the start instant of an invitation. */
export function startDate(start: string | null): string | null {
  const m = micros(start);
  return m === null ? null : dateOfMicros(m);
}

/** The last day of a role, from the end instant of an invitation: the day before the end. */
export function endDate(end: string | null): string | null {
  const m = micros(end);
  return m === null || m < BigInt(DAY_MICROS) ? null : dateOfMicros(m - BigInt(DAY_MICROS));
}

/** Today's date in UTC, `YYYY-MM-DD`, from `now` in milliseconds. */
export function todayOf(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Why the role dates of the Team form cannot be sent, or null when they
 * can: a start is needed, and an end must not lie before the start. The
 * server checks again (`CreatorRefusal::InvitationDates`).
 */
export function datesProblem(start: string, end: string): "start" | "end" | "order" | null {
  if (startMicros(start) === null) return "start";
  if (end === "") return null;
  if (endMicros(end) === null) return "end";
  return end < start ? "order" : null;
}

// ---------------------------------------------------------------------------
// The team
// ---------------------------------------------------------------------------

/** The role groups of the Team stage, in Daniel's order (design doc 11 section 6.3). */
export type RoleGroup = "drafting" | "judging" | "operations";

/** The roles of each group, as the wire spells them. Assigned reviewer is not offered. */
export const ROLE_GROUPS: readonly { readonly group: RoleGroup; readonly roles: readonly string[] }[] = [
  { group: "drafting", roles: ["programme_manager", "call_drafter"] },
  { group: "judging", roles: ["fstp_coordinator", "committee_member", "committee_chair", "irc_member"] },
  { group: "operations", roles: ["finance_approver", "payment_releaser", "contract_signatory", "auditor"] },
];

/** The group of `role`, or null for a role the Team stage does not offer. */
export function groupOf(role: string): RoleGroup | null {
  return ROLE_GROUPS.find((g) => g.roles.includes(role))?.group ?? null;
}

/**
 * What a team row shows as its status. An Operations role is `planned`
 * until it is granted: a tenant admin grants it after activation, and it
 * needs no identity check (Daniel, 2026-11-15, design doc 11 Q2).
 */
export type TeamStatus = InvitationState | "planned";

/** The status of `row` on the Team stage and the progress page. */
export function teamStatus(row: InvitationRow): TeamStatus {
  return groupOf(row.role) === "operations" && row.state !== "granted" ? "planned" : row.state;
}

/** The rows of each role group, in group order. A group with no row is listed empty. */
export function teamByGroup(rows: readonly InvitationRow[]): { readonly group: RoleGroup; readonly rows: readonly InvitationRow[] }[] {
  return ROLE_GROUPS.map((g) => ({ group: g.group, rows: rows.filter((r) => groupOf(r.role) === g.group) }));
}

/** An email address as the team compares it: trimmed and lower case. */
function same(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** The badge of one separation of duties line (design doc 11 section 6.4). */
export type SodBadge = "passed" | "not_affected" | "waiting" | "refused";

/** One line of the live separation of duties checks. */
export interface SodLine {
  readonly rule: "SoD-01" | "SoD-02" | "SoD-03" | "SoD-04" | "SoD-05" | "SoD-07" | "SoD-09";
  readonly badge: SodBadge;
  /** The message id of the line's text. */
  readonly text: string;
  /** The role on this team that blocks the choice, for a refusal that roles here explain. */
  readonly blocking: string | null;
}

/**
 * The live separation of duties lines for adding `email` as `role`, from
 * the team the invitation list shows (design doc 11 section 6.4). A
 * refusal names the rule and the role on this team that blocks it. It
 * never names another account (R-CF-03). The identity check of SoD-09
 * waits for the invitee and runs again at the grant. SoD-07 waits for
 * the grant, where a tenant admin's own grant needs a second admin.
 */
export function sodLines(role: string, email: string, team: readonly InvitationRow[]): SodLine[] {
  const group = groupOf(role);
  const mine = email.trim() === "" ? [] : team.filter((r) => same(r.email, email));
  const holds = (pred: (r: InvitationRow) => boolean): InvitationRow | null => mine.find(pred) ?? null;
  const out: SodLine[] = [];

  // SoD-01: no role from another of Drafting, Judging and Receiving here.
  if (group === "drafting" || group === "judging") {
    const other = holds((r) => {
      const g = groupOf(r.role);
      return (g === "drafting" || g === "judging") && g !== group;
    });
    out.push(
      other === null
        ? { rule: "SoD-01", badge: "passed", text: "setup.sod.01.passed", blocking: null }
        : { rule: "SoD-01", badge: "refused", text: "setup.sod.01.refused", blocking: other.role },
    );
  } else {
    out.push({ rule: "SoD-01", badge: "not_affected", text: "setup.sod.01.not_affected", blocking: null });
  }

  // SoD-02: an IRC member holds no other Judging role here.
  if (group === "judging") {
    const other =
      role === "irc_member"
        ? holds((r) => groupOf(r.role) === "judging" && r.role !== "irc_member")
        : holds((r) => r.role === "irc_member");
    out.push(
      other === null
        ? { rule: "SoD-02", badge: "passed", text: "setup.sod.02.passed", blocking: null }
        : { rule: "SoD-02", badge: "refused", text: "setup.sod.02.refused", blocking: other.role },
    );
  } else {
    out.push({ rule: "SoD-02", badge: "not_affected", text: "setup.sod.02.not_affected", blocking: null });
  }

  // SoD-03: an Operations role does not combine with a Receiving role. A
  // draft has no proposal yet, so no Receiving role exists here.
  out.push(
    group === "operations"
      ? { rule: "SoD-03", badge: "passed", text: "setup.sod.03.passed", blocking: null }
      : { rule: "SoD-03", badge: "not_affected", text: "setup.sod.03.not_affected", blocking: null },
  );

  // SoD-04: finance approver and payment releaser stay two people for
  // each payment. One person in both, with nobody else in the other
  // role, cannot handle a payment.
  if (role === "finance_approver" || role === "payment_releaser") {
    const counterpart = role === "finance_approver" ? "payment_releaser" : "finance_approver";
    const self = holds((r) => r.role === counterpart);
    const others = team.some((r) => r.role === counterpart && !same(r.email, email));
    out.push(
      self !== null && !others
        ? { rule: "SoD-04", badge: "refused", text: "setup.sod.04.refused", blocking: counterpart }
        : { rule: "SoD-04", badge: "passed", text: "setup.sod.04.passed", blocking: null },
    );
  } else {
    out.push({ rule: "SoD-04", badge: "not_affected", text: "setup.sod.04.not_affected", blocking: null });
  }

  // SoD-05: no cooling-off bar applies (P-12). A draft has no ended role.
  out.push(
    group === "operations"
      ? { rule: "SoD-05", badge: "not_affected", text: "setup.sod.05.not_affected", blocking: null }
      : { rule: "SoD-05", badge: "passed", text: "setup.sod.05.passed", blocking: null },
  );

  // SoD-07: a tenant admin's grant to their own account needs a second admin.
  out.push({ rule: "SoD-07", badge: "waiting", text: "setup.sod.07.waiting", blocking: null });

  // SoD-09: a verified identity for Drafting and Judging, checked again at the grant.
  out.push(
    group === "operations"
      ? { rule: "SoD-09", badge: "not_affected", text: "setup.sod.09.not_affected", blocking: null }
      : { rule: "SoD-09", badge: "waiting", text: "setup.sod.09.waiting", blocking: null },
  );
  return out;
}

/** The first refused line, which disables "Add to team", or null. */
export function refusedLine(lines: readonly SodLine[]): SodLine | null {
  return lines.find((l) => l.badge === "refused") ?? null;
}

/** The programme managers on the team, granted or not. */
export function managers(rows: readonly InvitationRow[]): number {
  return new Set(rows.filter((r) => r.role === "programme_manager").map((r) => r.email.trim().toLowerCase())).size;
}

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

/** A milestone of the progress page (design doc 11 section 8). */
export type MilestoneId =
  | "drafted"
  | "validated"
  | "invited"
  | "requested"
  | "approved"
  | "granted"
  | "call_drafted"
  | "call_approved"
  | "call_published";

/** The nine milestones, in order. */
export const MILESTONES: readonly MilestoneId[] = [
  "drafted",
  "validated",
  "invited",
  "requested",
  "approved",
  "granted",
  "call_drafted",
  "call_approved",
  "call_published",
];

/** How a milestone stands. Exactly one is current until the last is done. */
export type MilestoneCondition = "done" | "current" | "upcoming";

/** One milestone with its condition. */
export interface Milestone {
  readonly id: MilestoneId;
  readonly number: number;
  readonly condition: MilestoneCondition;
}

/** What the progress page reads, each from an existing read. */
export interface ProgressFacts {
  /** The draft exists (`creator.get_draft`). */
  readonly drafted: boolean;
  /** The report has no failure and every warning is acknowledged (I-66). */
  readonly clean: boolean;
  /** The team rows of `creator.invitations`, or null when the read failed. */
  readonly team: readonly InvitationRow[] | null;
  /** An activation request stands, or the programme is active. */
  readonly requested: boolean;
  /** The programme is active. */
  readonly active: boolean;
  /** The programme's call states from `call.list`, or null when unread. */
  readonly calls: readonly ("DRAFT" | "APPROVED" | "PUBLISHED")[] | null;
}

/**
 * The nine milestones from the facts (design doc 11 section 8). Each is
 * done when its own fact holds, and the first that is not done is
 * current. A later milestone is never done before an earlier one counts
 * as done, except that an active programme counts every milestone up to
 * its activation as done, since activation needed each of them (I-66).
 */
export function milestones(f: ProgressFacts): Milestone[] {
  const team = f.team ?? [];
  const calls = f.calls ?? [];
  const facts: Record<MilestoneId, boolean> = {
    drafted: f.drafted,
    validated: f.active || (f.drafted && f.clean),
    invited: f.active || team.length > 0,
    requested: f.active || f.requested,
    approved: f.active,
    granted: f.active && team.length > 0 && team.every((r) => r.state === "granted"),
    call_drafted: calls.length > 0,
    call_approved: calls.some((c) => c !== "DRAFT"),
    call_published: calls.some((c) => c === "PUBLISHED"),
  };
  let current = false;
  return MILESTONES.map((id, i) => {
    let condition: MilestoneCondition;
    if (facts[id] && !current) {
      condition = "done";
    } else if (!current) {
      condition = "current";
      current = true;
    } else {
      condition = "upcoming";
    }
    return { id, number: i + 1, condition };
  });
}

/** The cell of one team status column (design doc 11 section 8). */
export type StatusCell = "done" | "waiting" | "not_needed";

/** One person's row on the progress page. */
export interface StatusRow {
  readonly invited: StatusCell;
  readonly accepted: StatusCell;
  readonly verified: StatusCell;
  readonly granted: StatusCell;
  /** The message id of the next action. */
  readonly next: string;
}

/**
 * The status columns of `row`. Operations rows need no identity check
 * (SoD-09 names Drafting and Judging only). The invitee still accepts
 * the invitation, which binds their account, so its terms column counts.
 * Interim reading, recorded in design doc 11 section 15.
 */
export function statusRow(row: InvitationRow, active: boolean): StatusRow {
  const ops = groupOf(row.role) === "operations";
  const order: readonly InvitationState[] = ["invited", "accepted", "verified", "granted"];
  const at = order.indexOf(row.state);
  const reached = (s: InvitationState): StatusCell => (at >= order.indexOf(s) ? "done" : "waiting");
  const accepted = reached("accepted");
  const verified: StatusCell = ops ? "not_needed" : reached("verified");
  const granted = reached("granted");
  let next: string;
  if (granted === "done") {
    next = "setup.next.none";
  } else if (accepted === "waiting") {
    next = "setup.next.accept";
  } else if (verified === "waiting") {
    next = "setup.next.verify";
  } else if (!active && row.role !== "programme_manager") {
    next = "setup.next.after_activation";
  } else {
    next = "setup.next.grant";
  }
  return { invited: "done", accepted, verified, granted, next };
}
