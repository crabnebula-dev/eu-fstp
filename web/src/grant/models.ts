// The read models and request bodies of the M5 post-grant screens
// (lanes L-UI1 and L-UI2; M5 design sections 5 and 6).
//
// The spellings follow `fstp-api-core` `grant.rs` (replies) and
// `forms.rs` (bodies). Decoders read values that `JSON.parse` gave and
// return null for a value they do not accept, so a page shows nothing
// from an answer it cannot read. Amounts are ADR-006 strings the cell
// formatted. The browser never computes money (ADR-006, I-86): a body
// carries the amount the person typed, and the cell decides.
//
// Interim, pending the lead: `grant.overview` does not yet name the
// agreed plan or the milestones of the plan (`docs/handoff/m5-ui.md`).
// The decoder reads both when the cell sends them (`plan`,
// `milestones`) and the pages ask for the numbers otherwise.

import { parseAmount } from "../core/money.js";

type Rec = Readonly<Record<string, unknown>>;

/** A decimal id, as the server spells ids. */
const ID = /^(0|[1-9][0-9]{0,38})$/;

/** Whether `s` is a canonical decimal id. */
export function isIdText(s: unknown): s is string {
  return typeof s === "string" && ID.test(s);
}

function rec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}

function amount(v: unknown): v is string {
  return typeof v === "string" && parseAmount(v, "EUR").ok;
}

function text(v: unknown): v is string {
  return typeof v === "string";
}

function count(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function hex64(v: unknown): v is string {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function nullOr<T>(v: unknown, ok: (x: unknown) => x is T): T | null | undefined {
  if (v === null) {
    return null;
  }
  return ok(v) ? v : undefined;
}

function each<T>(v: unknown, f: (x: unknown) => T | null): readonly T[] | null {
  if (!Array.isArray(v)) {
    return null;
  }
  const out: T[] = [];
  for (const x of v as readonly unknown[]) {
    const y = f(x);
    if (y === null) {
      return null;
    }
    out.push(y);
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------
// grant.overview
// ---------------------------------------------------------------------------

/** One milestone of the agreed plan, when the cell names it. */
export interface MilestoneInfo {
  readonly milestone: string;
  readonly amount: string;
  readonly paid: string | null;
  readonly due: string | null;
}

/** `grant.overview`. */
export interface Overview {
  readonly proposal: string;
  readonly state: string;
  readonly determination: string | null;
  readonly amount: string | null;
  readonly paid: string;
  readonly contract: string | null;
  readonly requests: number;
  /** The agreed plan, when the cell names it. */
  readonly agreedPlan: string | null;
  readonly milestones: readonly MilestoneInfo[];
}

function milestoneInfo(v: unknown): MilestoneInfo | null {
  const o = rec(v);
  if (o === null || !isIdText(o["milestone"]) || !amount(o["amount"])) {
    return null;
  }
  const paid = nullOr(o["paid"], amount);
  const due = nullOr(o["due"], text);
  if (paid === undefined || due === undefined) {
    return null;
  }
  return Object.freeze({ milestone: o["milestone"], amount: o["amount"], paid, due });
}

/** Decodes `grant.overview`. */
export function decodeOverview(v: unknown): Overview | null {
  const o = rec(v);
  if (o === null || !isIdText(o["proposal"]) || !text(o["state"]) || !amount(o["paid"]) || !count(o["requests"])) {
    return null;
  }
  const determination = nullOr(o["determination"], isIdText);
  const amt = nullOr(o["amount"], amount);
  const contract = nullOr(o["contract"], isIdText);
  const plan = o["plan"] === undefined ? null : nullOr(o["plan"], isIdText);
  const ms = o["milestones"] === undefined ? Object.freeze([]) : each(o["milestones"], milestoneInfo);
  if (determination === undefined || amt === undefined || contract === undefined || plan === undefined || ms === null) {
    return null;
  }
  return Object.freeze({
    proposal: o["proposal"],
    state: o["state"],
    determination,
    amount: amt,
    paid: o["paid"],
    contract,
    requests: o["requests"],
    agreedPlan: plan,
    milestones: ms,
  });
}

// ---------------------------------------------------------------------------
// contract.view
// ---------------------------------------------------------------------------

/** One party of a contract version, by field and role (I-86). */
export interface Party {
  readonly field: string;
  readonly role: "lead" | "team_member" | "guardian" | "signatory";
  readonly signed: boolean;
  readonly mine: boolean;
}

/** One version of a contract. */
export interface Version {
  readonly version: number;
  readonly state: string;
  readonly parties: readonly Party[];
  readonly revisions: number;
  readonly digest: string | null;
  readonly open_changes: readonly number[];
}

/** `contract.view`. */
export interface ContractView {
  readonly proposal: string;
  readonly contract: string | null;
  readonly status: string | null;
  readonly versions: readonly Version[];
}

const ROLES: readonly string[] = ["lead", "team_member", "guardian", "signatory"];

function party(v: unknown): Party | null {
  const o = rec(v);
  if (o === null || !text(o["field"]) || typeof o["role"] !== "string" || !ROLES.includes(o["role"])) {
    return null;
  }
  if (typeof o["signed"] !== "boolean" || typeof o["mine"] !== "boolean") {
    return null;
  }
  return Object.freeze({ field: o["field"], role: o["role"] as Party["role"], signed: o["signed"], mine: o["mine"] });
}

function version(v: unknown): Version | null {
  const o = rec(v);
  if (o === null || !count(o["version"]) || !text(o["state"]) || !count(o["revisions"])) {
    return null;
  }
  const parties = each(o["parties"], party);
  const digest = nullOr(o["digest"], hex64);
  const open = each(o["open_changes"], (x) => (count(x) ? x : null));
  if (parties === null || digest === undefined || open === null) {
    return null;
  }
  return Object.freeze({
    version: o["version"],
    state: o["state"],
    parties,
    revisions: o["revisions"],
    digest,
    open_changes: open,
  });
}

/** Decodes `contract.view`. */
export function decodeContract(v: unknown): ContractView | null {
  const o = rec(v);
  if (o === null || !isIdText(o["proposal"])) {
    return null;
  }
  const contract = nullOr(o["contract"], isIdText);
  const status = nullOr(o["status"], text);
  const versions = each(o["versions"], version);
  if (contract === undefined || status === undefined || versions === null) {
    return null;
  }
  return Object.freeze({ proposal: o["proposal"], contract, status, versions });
}

// ---------------------------------------------------------------------------
// payment.status, payment.queue, report.list
// ---------------------------------------------------------------------------

/** The statuses of `payment-requests.md`. */
export const REQUEST_STATUSES = [
  "DRAFT",
  "SUBMITTED",
  "CHECKS_FAILED",
  "UNDER_REVIEW",
  "CHANGES_REQUESTED",
  "ACCEPTED",
  "PAYMENT_APPROVED",
  "RELEASED",
  "PAID",
  "REJECTED",
  "WITHDRAWN",
  "CLOSED",
] as const;

/** One line of a payment request. */
export interface Line {
  readonly line: string;
  readonly milestone: string;
  readonly requested: string;
  readonly approved: string | null;
}

/** One payment request of a grant. */
export interface RequestRow {
  readonly request: string;
  readonly proposal: string;
  readonly status: (typeof REQUEST_STATUSES)[number];
  readonly kind: "milestone" | "hardship";
  readonly submission_checks: boolean;
  readonly acceptance_checks: boolean;
  readonly lines: readonly Line[];
}

function line(v: unknown): Line | null {
  const o = rec(v);
  if (o === null || !isIdText(o["line"]) || !isIdText(o["milestone"]) || !amount(o["requested"])) {
    return null;
  }
  const approved = nullOr(o["approved"], amount);
  return approved === undefined
    ? null
    : Object.freeze({ line: o["line"], milestone: o["milestone"], requested: o["requested"], approved });
}

function requestRow(v: unknown): RequestRow | null {
  const o = rec(v);
  if (o === null || !isIdText(o["request"]) || !isIdText(o["proposal"])) {
    return null;
  }
  const status = (REQUEST_STATUSES as readonly unknown[]).includes(o["status"]) ? (o["status"] as RequestRow["status"]) : null;
  const kind = o["kind"] === "milestone" || o["kind"] === "hardship" ? o["kind"] : null;
  const lines = each(o["lines"], line);
  if (
    status === null ||
    kind === null ||
    lines === null ||
    typeof o["submission_checks"] !== "boolean" ||
    typeof o["acceptance_checks"] !== "boolean"
  ) {
    return null;
  }
  return Object.freeze({
    request: o["request"],
    proposal: o["proposal"],
    status,
    kind,
    submission_checks: o["submission_checks"],
    acceptance_checks: o["acceptance_checks"],
    lines,
  });
}

/** Decodes `payment.status`. */
export function decodePayments(v: unknown): readonly RequestRow[] | null {
  return each(v, requestRow);
}

/** What the caller does with a queued request. */
export type QueueTask = "review" | "approve" | "release" | "confirm";

/** One item of the caller's payment work queue. */
export interface QueueRow {
  readonly task: QueueTask;
  readonly request: RequestRow;
}

/** Decodes `payment.queue`. */
export function decodeQueue(v: unknown): readonly QueueRow[] | null {
  return each(v, (x) => {
    const o = rec(x);
    if (o === null) {
      return null;
    }
    const t = o["task"];
    const task = t === "review" || t === "approve" || t === "release" || t === "confirm" ? t : null;
    const request = requestRow(o["request"]);
    return task === null || request === null ? null : Object.freeze({ task, request });
  });
}

/** One funder report of a programme. */
export interface ReportRow {
  readonly report: string;
  readonly kind: string;
  readonly call: string | null;
  readonly programme: string | null;
  readonly document: string;
  readonly template: string;
  readonly generatedByMe: boolean;
  readonly approved: boolean;
}

/** Decodes `report.list`. */
export function decodeReports(v: unknown): readonly ReportRow[] | null {
  return each(v, (x) => {
    const o = rec(x);
    if (o === null || !isIdText(o["report"]) || !text(o["kind"]) || !hex64(o["document"]) || !text(o["template"])) {
      return null;
    }
    const call = nullOr(o["call"], isIdText);
    const programme = nullOr(o["programme"], isIdText);
    if (call === undefined || programme === undefined) {
      return null;
    }
    if (typeof o["generated_by_me"] !== "boolean" || typeof o["approved"] !== "boolean") {
      return null;
    }
    return Object.freeze({
      report: o["report"],
      kind: o["kind"],
      call,
      programme,
      document: o["document"],
      template: o["template"],
      generatedByMe: o["generated_by_me"],
      approved: o["approved"],
    });
  });
}

/** The `{redirect}` of a vault ticket op. */
export function decodeRedirect(v: unknown): string | null {
  const o = rec(v);
  return o !== null && typeof o["redirect"] === "string" ? o["redirect"] : null;
}

/** An id the cell drew, such as `{contract}` or `{report}`, named `key`. */
export function decodeDrawn(v: unknown, key: string): string | null {
  const o = rec(v);
  return o !== null && isIdText(o[key]) ? o[key] : null;
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/** A body, or the reason there is none. */
export type Built<T> = { readonly ok: true; readonly value: T } | { readonly ok: false };

const BAD: { readonly ok: false } = Object.freeze({ ok: false });

function good<T>(value: T): Built<T> {
  return Object.freeze({ ok: true, value });
}

/** A free text of the body: not blank. */
function filled(s: string): boolean {
  return s.trim() !== "";
}

/** `grant.determine_amount` (R-NG-03, I-13). */
export function determineBody(
  plan: string,
  deductions: readonly { readonly amount: string; readonly reason: string }[],
): Built<Rec> {
  if (!isIdText(plan) || deductions.some((d) => !amount(d.amount) || !filled(d.reason))) {
    return BAD;
  }
  return good({
    agreed: plan,
    currency: "EUR",
    deductions: deductions.map((d) => ({ amount: d.amount, reason: d.reason.trim() })),
  });
}

/** The body of `grant.accept` and `grant.approve`: they name the current determination (NOTE 9). */
export function determinationBody(determination: string): Rec {
  return { determination };
}

/** A body with one reason, or null when the reason is blank. */
export function reasonBody(reason: string): Rec | null {
  return filled(reason) ? { reason: reason.trim() } : null;
}

/** `milestone.close`: the reason is required. */
export function closeBody(reason: string): Rec | null {
  return reasonBody(reason);
}

/** A clause number: a whole number from 1. */
export function parseClause(s: string): number | null {
  if (!/^[1-9][0-9]{0,8}$/.test(s.trim())) {
    return null;
  }
  return Number(s.trim());
}

/** `contract.propose_change` (R-CT-04). */
export function changeBody(clause: number, body: string): Rec {
  return { clause, text: body.trim() };
}

/** `contract.decide_change`. */
export function decideBody(accept: boolean): Rec {
  return { accept };
}

/** The signature routes of P-30, in cascade order. */
export const ROUTES = ["wallet_qes", "qtsp_remote_qes", "advanced"] as const;

/** One signature route. */
export type Route = (typeof ROUTES)[number];

/** `contract.sign`. */
export function signBody(route: Route): Rec {
  return { route };
}

/** `contract.approve_advanced` (P-30 step 3): the party and a recorded reason. */
export function advancedBody(party: string, reason: string): Built<Rec> {
  return party.trim() !== "" && filled(reason) ? good({ party: party.trim(), reason: reason.trim() }) : BAD;
}

/** The evidence of one payment line (P-34). */
export interface Evidence {
  readonly location: string;
  readonly release: string;
  readonly licence: string;
  readonly report: string;
}

/** One line of a payment body. */
export interface LineBody {
  readonly milestone: string;
  readonly amount: string;
  readonly evidence: Evidence;
}

/** A payment line (I-58, R-PR-07). */
export function lineBody(milestone: string, amt: string, e: Evidence): Built<LineBody> {
  if (!isIdText(milestone) || !amount(amt)) {
    return BAD;
  }
  if (![e.location, e.release, e.licence, e.report].every(filled)) {
    return BAD;
  }
  return good({
    milestone,
    amount: amt,
    evidence: { location: e.location.trim(), release: e.release.trim(), licence: e.licence.trim(), report: e.report.trim() },
  });
}

/** `payment.submit` and `payment.resubmit`: a milestone claim. */
export function paymentBody(lines: readonly LineBody[]): Rec {
  return { kind: { type: "Milestone" }, currency: "EUR", lines };
}

/** `payment.review_line` (I-32): the approved amount, and a reason when it is lower. */
export function reviewBody(approved: string, reason: string): Rec {
  return filled(reason) ? { approved, currency: "EUR", reason: reason.trim() } : { approved, currency: "EUR" };
}

/** Whether `s` is an ADR-006 EUR amount. */
export function isAmountText(s: string): boolean {
  return amount(s);
}

/** Canonical JSON text of a body: members sorted, as the cell takes it (RFC 8785). */
export function canonicalBody(v: unknown): unknown {
  if (Array.isArray(v)) {
    return (v as readonly unknown[]).map(canonicalBody);
  }
  if (typeof v === "object" && v !== null) {
    const o = v as Rec;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) {
      out[k] = canonicalBody(o[k]);
    }
    return out;
  }
  return v;
}
