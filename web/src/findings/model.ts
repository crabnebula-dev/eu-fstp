// The read models of the assessment panels (M7 design sections 4 and 7).
//
// Each decoder is closed: an unknown or missing member refuses the whole
// value, so a member a panel must never show, such as a score, a band or
// a confidence, is refused rather than ignored (TH-02, I-10). Statements
// and quotes are untrusted data and reach the page only as text nodes.

export type FindingKind = "completeness" | "quality" | "accuracy" | "integrity";
export type Severity = "info" | "minor" | "major";
export type Assessor = "synthetic" | "model";
export type Mark = "Agreed" | "Disputed";
export type Element =
  | "problem"
  | "approach"
  | "ois_relevance"
  | "team_experience"
  | "deliverables_licence"
  | "milestones"
  | "budget_justification";

/** The rubric v1 element tags (M7 design section 2, reading 1). */
export const ELEMENTS: readonly Element[] = [
  "problem",
  "approach",
  "ois_relevance",
  "team_experience",
  "deliverables_licence",
  "milestones",
  "budget_justification",
];

const ID = /^(0|[1-9][0-9]{0,38})$/;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Whether `o` holds exactly the members `keys`. */
function exactly(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(o);
  return own.length === keys.length && own.every((k) => keys.includes(k));
}

function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function isCount(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function oneOf<T extends string>(v: unknown, values: readonly T[]): T | null {
  return typeof v === "string" && (values as readonly string[]).includes(v) ? (v as T) : null;
}

const KINDS: readonly FindingKind[] = ["completeness", "quality", "accuracy", "integrity"];
const SEVERITIES: readonly Severity[] = ["info", "minor", "major"];
const ASSESSORS: readonly Assessor[] = ["synthetic", "model"];

// ---------------------------------------------------------------------------
// review.findings
// ---------------------------------------------------------------------------

/** One finding on the reviewer's proposal. */
export interface ReviewFinding {
  readonly finding: string;
  readonly kind: FindingKind;
  readonly severity: Severity;
  readonly statement: string;
  readonly mark: Mark | null;
  readonly assessor: Assessor;
}

const REVIEW_KEYS = ["finding", "kind", "severity", "confidence", "statement", "mark", "assessor"] as const;

/**
 * One `review.findings` row, or null. The registry reply carries the
 * model-reported confidence; the panel drops it and never shows it, so
 * the reviewer reads the statement, not a number.
 */
export function decodeReviewFinding(v: unknown): ReviewFinding | null {
  if (!isObject(v) || !exactly(v, REVIEW_KEYS)) {
    return null;
  }
  const kind = oneOf(typeof v["kind"] === "string" ? v["kind"].toLowerCase() : null, KINDS);
  const severity = oneOf(typeof v["severity"] === "string" ? v["severity"].toLowerCase() : null, SEVERITIES);
  const assessor = oneOf(v["assessor"], ASSESSORS);
  const mark = v["mark"] === null ? null : oneOf(v["mark"], ["Agreed", "Disputed"] as const);
  if (
    !isId(v["finding"]) ||
    kind === null ||
    severity === null ||
    assessor === null ||
    !isCount(v["confidence"]) ||
    typeof v["statement"] !== "string" ||
    (v["mark"] !== null && mark === null)
  ) {
    return null;
  }
  return Object.freeze({ finding: v["finding"], kind, severity, statement: v["statement"], mark, assessor });
}

/** The `review.findings` reply, or null. */
export function decodeReviewFindings(v: unknown): readonly ReviewFinding[] | null {
  if (!Array.isArray(v)) {
    return null;
  }
  const out: ReviewFinding[] = [];
  for (const x of v) {
    const f = decodeReviewFinding(x);
    if (f === null) {
      return null;
    }
    out.push(f);
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------
// assess.findings_status
// ---------------------------------------------------------------------------

/** One proposal's assessment status: counts only (I-10). */
export interface FindingsStatus {
  readonly proposal: string;
  readonly status: "pending" | "ready";
  readonly findings: number;
}

/** The `assess.findings_status` reply, or null. */
export function decodeFindingsStatus(v: unknown): readonly FindingsStatus[] | null {
  if (!Array.isArray(v)) {
    return null;
  }
  const out: FindingsStatus[] = [];
  for (const x of v) {
    if (!isObject(x) || !exactly(x, ["proposal", "status", "findings"])) {
      return null;
    }
    const status = oneOf(x["status"], ["pending", "ready"] as const);
    if (!isId(x["proposal"]) || status === null || !isCount(x["findings"])) {
      return null;
    }
    out.push(Object.freeze({ proposal: x["proposal"], status, findings: x["findings"] }));
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------
// proposal.precheck and proposal.precheck_runs
// ---------------------------------------------------------------------------

/** One quote of a pre-check finding. */
export interface PrecheckEvidence {
  readonly section: "title" | "summary" | "narrative";
  readonly quote: string;
}

/** One pre-check finding: no confidence and no number (TH-02). */
export interface PrecheckFinding {
  readonly kind: FindingKind;
  readonly criterion: string | null;
  readonly element: Element | null;
  readonly severity: Severity;
  readonly statement: string;
  readonly evidence: readonly PrecheckEvidence[];
}

/** One pre-check run. */
export interface PrecheckRun {
  readonly run: string;
  readonly requested: string;
  readonly state: "pending" | "done" | "unavailable";
  readonly findings: readonly PrecheckFinding[];
}

/** The pre-check reply: runs and remaining checks. */
export interface PrecheckView {
  readonly assessor: Assessor;
  readonly remaining: {
    readonly proposalToday: number;
    readonly proposalCall: number;
    readonly accountCall: number;
    readonly next: string | null;
  };
  readonly runs: readonly PrecheckRun[];
}

function decodeEvidence(v: unknown): PrecheckEvidence | null {
  if (!isObject(v) || !exactly(v, ["section", "quote"])) {
    return null;
  }
  const section = oneOf(v["section"], ["title", "summary", "narrative"] as const);
  if (section === null || typeof v["quote"] !== "string") {
    return null;
  }
  return Object.freeze({ section, quote: v["quote"] });
}

function decodePrecheckFinding(v: unknown): PrecheckFinding | null {
  if (!isObject(v) || !exactly(v, ["kind", "criterion", "element", "severity", "statement", "evidence"])) {
    return null;
  }
  const kind = oneOf(v["kind"], KINDS);
  const severity = oneOf(v["severity"], SEVERITIES);
  const criterion = v["criterion"];
  const evidence = v["evidence"];
  const element = v["element"] === null ? null : oneOf(v["element"], ELEMENTS);
  if (
    (v["element"] !== null && element === null) ||
    kind === null ||
    severity === null ||
    (criterion !== null && !isId(criterion)) ||
    typeof v["statement"] !== "string" ||
    !Array.isArray(evidence)
  ) {
    return null;
  }
  const ev: PrecheckEvidence[] = [];
  for (const e of evidence) {
    const d = decodeEvidence(e);
    if (d === null) {
      return null;
    }
    ev.push(d);
  }
  return Object.freeze({
    kind,
    criterion: criterion === null ? null : (criterion as string),
    element,
    severity,
    statement: v["statement"],
    evidence: Object.freeze(ev),
  });
}

function decodeRun(v: unknown): PrecheckRun | null {
  if (!isObject(v) || !exactly(v, ["run", "requested", "state", "findings"])) {
    return null;
  }
  const state = oneOf(v["state"], ["pending", "done", "unavailable"] as const);
  const findings = v["findings"];
  const requested = v["requested"];
  if (!isId(v["run"]) || typeof requested !== "string" || !/^[0-9]{1,20}$/.test(requested)) {
    return null;
  }
  if (state === null || !Array.isArray(findings)) {
    return null;
  }
  const out: PrecheckFinding[] = [];
  for (const f of findings) {
    const d = decodePrecheckFinding(f);
    if (d === null) {
      return null;
    }
    out.push(d);
  }
  return Object.freeze({ run: v["run"], requested, state, findings: Object.freeze(out) });
}

/** The `proposal.precheck` and `proposal.precheck_runs` reply, or null. */
export function decodePrecheckView(v: unknown): PrecheckView | null {
  if (!isObject(v) || !exactly(v, ["assessor", "remaining", "runs"])) {
    return null;
  }
  const assessor = oneOf(v["assessor"], ASSESSORS);
  const r = v["remaining"];
  const runs = v["runs"];
  if (assessor === null || !isObject(r) || !exactly(r, ["proposal_today", "proposal_call", "account_call", "next"])) {
    return null;
  }
  const next = r["next"];
  if (
    !isCount(r["proposal_today"]) ||
    !isCount(r["proposal_call"]) ||
    !isCount(r["account_call"]) ||
    (next !== null && (typeof next !== "string" || !/^[0-9]{1,20}$/.test(next))) ||
    !Array.isArray(runs)
  ) {
    return null;
  }
  const out: PrecheckRun[] = [];
  for (const x of runs) {
    const d = decodeRun(x);
    if (d === null) {
      return null;
    }
    out.push(d);
  }
  return Object.freeze({
    assessor,
    remaining: Object.freeze({
      proposalToday: r["proposal_today"],
      proposalCall: r["proposal_call"],
      accountCall: r["account_call"],
      next: next === null ? null : (next as string),
    }),
    runs: Object.freeze(out),
  });
}

/** Whether a run may be requested now (P-23). */
export function canRun(v: PrecheckView): boolean {
  return v.remaining.proposalToday > 0 && v.remaining.proposalCall > 0 && v.remaining.accountCall > 0;
}

/** A microsecond instant as an ISO 8601 UTC minute, for display. */
export function instantText(micros: string): string {
  const ms = Number(BigInt(micros) / 1000n);
  return `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
