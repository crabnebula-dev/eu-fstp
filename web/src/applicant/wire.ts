// The read models the applicant and call pages take from `/api/v1`, and
// the request bodies they send (M4 design sections 2.2 J4, 3.7 and 3.9).
//
// Interim, pending the lead and lanes W3a and W3b: neither the registry
// nor `fstp-api-core` fixes the body schemas of these operations yet,
// and the generated file has no response validators for them. So this
// module states the members each page reads. It follows `fstp-api-core`
// where that lane has a model: ids, instants and amounts are strings,
// instants are decimal microseconds since the Unix epoch, members are
// snake_case, and lists are top-level arrays. Each decoder below names
// the members it needs. A missing or mistyped member refuses the whole
// body. A member the page does not read is ignored and never shown.
//
// These decoders read values that `JSON.parse` already produced. They do
// not parse text, except the instant and day strings, which are checked
// against fixed grammars.

import { parseAmount } from "../core/money.js";
import { type ProposalRole, type ProposalState, parseProposalState } from "./rules.js";

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

type Rec = Readonly<Record<string, unknown>>;

function rec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}

function member(o: Rec, k: string): unknown {
  return Object.hasOwn(o, k) ? o[k] : undefined;
}

/**
 * An id as it travels in a path segment and a link. Interim, pending the
 * generated segment checks: ASCII letters, digits, `_` and `-`, at most
 * 64 of them. `fstp-api-core` writes ids as decimal strings, which pass.
 */
const ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Whether `v` is an id this page may put in a path or a link. */
export function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function id(o: Rec, k: string): string | null {
  const v = member(o, k);
  return isId(v) ? v : null;
}

function text(o: Rec, k: string): string | null {
  const v = member(o, k);
  return typeof v === "string" ? v : null;
}

/** A string member, or `""` when it is absent. Any other type refuses (null). */
function optText(o: Rec, k: string): string | null {
  const v = member(o, k);
  if (v === undefined) {
    return "";
  }
  return typeof v === "string" ? v : null;
}

/** An optional id: the id, `undefined` when absent or null, or null when malformed. */
function optId(o: Rec, k: string): string | undefined | null {
  const v = member(o, k);
  if (v === undefined || v === null) {
    return undefined;
  }
  return isId(v) ? v : null;
}

function list<T>(v: unknown, item: (x: unknown) => T | null): readonly T[] | null {
  if (!Array.isArray(v)) {
    return null;
  }
  const out: T[] = [];
  for (const x of v as readonly unknown[]) {
    const y = item(x);
    if (y === null) {
      return null;
    }
    out.push(y);
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------
// Instants, days and amounts
// ---------------------------------------------------------------------------

/** An instant: its RFC 3339 text in UTC and its whole milliseconds since the epoch. */
export interface Instant {
  readonly rfc3339: string;
  readonly ms: number;
}

const MICROS = /^(?:0|[1-9][0-9]{0,17})$/;
/** 9999-12-31T23:59:59.999999Z in microseconds, the last instant RFC 3339 writes with four year digits. */
const MAX_MICROS = 253402300799999999n;

/**
 * The instant of a decimal string of microseconds since the Unix epoch,
 * as `fstp-api-core` writes instants, or null. The arithmetic is on
 * integers only (BigInt), so no float is involved.
 */
export function instantOfMicros(v: unknown): Instant | null {
  if (typeof v !== "string" || !MICROS.test(v)) {
    return null;
  }
  const micros = BigInt(v);
  if (micros > MAX_MICROS) {
    return null;
  }
  const ms = Number(micros / 1000n);
  const whole = new Date(ms).toISOString().slice(0, 19);
  const frac = micros % 1000000n;
  const rfc3339 = frac === 0n ? `${whole}Z` : `${whole}.${frac.toString().padStart(6, "0")}Z`;
  return Object.freeze({ rfc3339, ms });
}

/** A calendar day, `YYYY-MM-DD`, with its parts. */
export interface Day {
  readonly text: string;
  readonly year: number;
  readonly month: number;
  readonly day: number;
}

const DAY = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;

/**
 * The day of a `YYYY-MM-DD` string that names a real calendar day, or
 * null. A time of day is refused, so a page that shows days only can
 * never show one (TH-08, P-11).
 */
export function dayOf(v: unknown): Day | null {
  if (typeof v !== "string") {
    return null;
  }
  const m = DAY.exec(v);
  if (m === null || m[1] === undefined || m[2] === undefined || m[3] === undefined) {
    return null;
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const d = new Date(Date.UTC(year, month - 1, day));
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) {
    return null;
  }
  return Object.freeze({ text: v, year, month, day });
}

/** An ADR-006 EUR amount text, checked by `money.ts`, or null. */
function amount(v: unknown): string | null {
  const r = parseAmount(v, "EUR");
  return r.ok ? r.amount.text : null;
}

/** An optional amount: the text, `undefined` when absent or null, or null when malformed. */
function optAmount(o: Rec, k: string): string | undefined | null {
  const v = member(o, k);
  if (v === undefined || v === null) {
    return undefined;
  }
  return amount(v);
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

/** One open call in `calls.list_open`. */
export interface CallItem {
  readonly call: string;
  /** The call title, or `""` when the cell sends none. */
  readonly title: string;
  readonly deadline: Instant | null;
  readonly zone: string;
}

/** `calls.list_open`: an array of `{call, title?, deadline?, deadline_zone?}`. */
export function decodeOpenCalls(v: unknown): readonly CallItem[] | null {
  return list(v, (x) => {
    const o = rec(x);
    if (o === null) {
      return null;
    }
    const call = id(o, "call");
    const title = optText(o, "title");
    const zone = optText(o, "deadline_zone");
    const d = member(o, "deadline");
    const deadline = d === undefined ? null : instantOfMicros(d);
    if (call === null || title === null || zone === null || (d !== undefined && deadline === null)) {
      return null;
    }
    return Object.freeze({ call, title, deadline, zone });
  });
}

/** The amount kinds a call page shows, in their order on the page. */
export const CALL_AMOUNT_KINDS = ["budget", "grant_min", "grant_max", "recipient_max"] as const;

/** One amount kind. */
export type CallAmountKind = (typeof CALL_AMOUNT_KINDS)[number];

/** One call, `calls.get`. */
export interface CallDetail {
  readonly call: string;
  readonly title: string;
  readonly deadline: Instant;
  /** The IANA zone the call states its deadline in. */
  readonly zone: string;
  readonly currency: "EUR";
  /** The ADR-006 texts the cell sent, by kind. The budget is always there. */
  readonly amounts: Readonly<Partial<Record<CallAmountKind, string>>>;
  /** Whether the call is open at the instant the cell read it. */
  readonly open: boolean;
}

/** An IANA zone name as the call record holds it: letters, digits, `/`, `_`, `+` and `-`. */
const ZONE = /^[A-Za-z][A-Za-z0-9_+/-]{0,63}$/;

/**
 * `calls.get`: `{call, title?, deadline, deadline_zone, budget, currency,
 * open, grant_min?, grant_max?, recipient_max?}`. Every amount is an
 * ADR-006 string, refused when not canonical. `currency` is `EUR`, the
 * one currency with a fixed scale here.
 *
 * Interim, pending lane W1c and Daniel: the domain has a currency per
 * programme, but `money.ts` holds the ADR-006 scale of EUR only. This
 * decoder follows `money.ts`, so a call in another currency is refused
 * as unreadable rather than shown with a wrong scale. It widens when
 * `money.ts` gains the scales of other currencies.
 */
export function decodeCall(v: unknown): CallDetail | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  const call = id(o, "call");
  const title = optText(o, "title");
  const deadline = instantOfMicros(member(o, "deadline"));
  const zone = text(o, "deadline_zone");
  const open = member(o, "open");
  if (call === null || title === null || deadline === null || zone === null || !ZONE.test(zone)) {
    return null;
  }
  if (member(o, "currency") !== "EUR" || typeof open !== "boolean") {
    return null;
  }
  const budget = amount(member(o, "budget"));
  if (budget === null) {
    return null;
  }
  const amounts: Partial<Record<CallAmountKind, string>> = { budget };
  for (const k of ["grant_min", "grant_max", "recipient_max"] as const) {
    const a = optAmount(o, k);
    if (a === null) {
      return null;
    }
    if (a !== undefined) {
      amounts[k] = a;
    }
  }
  return Object.freeze({ call, title, deadline, zone, currency: "EUR", amounts: Object.freeze(amounts), open });
}

/** One block of a Guide section. */
export type GuideBlock =
  | { readonly kind: "paragraph"; readonly text: string }
  | { readonly kind: "list"; readonly items: readonly string[] }
  | { readonly kind: "table"; readonly head: readonly string[]; readonly rows: readonly (readonly string[])[] };

/** One Guide section: a heading and its blocks. */
export interface GuideSection {
  readonly heading: string;
  readonly blocks: readonly GuideBlock[];
}

/** The Guide for Applicants of a call, `calls.guide`. */
export interface Guide {
  readonly sections: readonly GuideSection[];
}

function strings(v: unknown): readonly string[] | null {
  return list(v, (x) => (typeof x === "string" ? x : null));
}

function guideBlock(v: unknown): GuideBlock | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  switch (member(o, "kind")) {
    case "paragraph": {
      const t = text(o, "text");
      return t === null ? null : Object.freeze({ kind: "paragraph", text: t });
    }
    case "list": {
      const items = strings(member(o, "items"));
      return items === null ? null : Object.freeze({ kind: "list", items });
    }
    case "table": {
      const head = strings(member(o, "head"));
      const rows = list(member(o, "rows"), strings);
      return head === null || rows === null ? null : Object.freeze({ kind: "table", head, rows });
    }
    default:
      return null;
  }
}

/**
 * `calls.guide`: `{sections: [{heading, blocks: [block]}]}`, where a
 * block is `{kind: "paragraph", text}`, `{kind: "list", items}` or
 * `{kind: "table", head, rows}`. Interim, pending lanes W2c and W3b:
 * the cell sends the Guide as structured text, so the browser parses no
 * Markdown and builds every element itself.
 */
export function decodeGuide(v: unknown): Guide | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  const sections = list(member(o, "sections"), (x) => {
    const s = rec(x);
    if (s === null) {
      return null;
    }
    const heading = text(s, "heading");
    const blocks = list(member(s, "blocks"), guideBlock);
    return heading === null || blocks === null ? null : Object.freeze({ heading, blocks });
  });
  return sections === null ? null : Object.freeze({ sections });
}

// ---------------------------------------------------------------------------
// Proposals
// ---------------------------------------------------------------------------

function role(v: unknown): ProposalRole | undefined | null {
  if (v === undefined || v === null) {
    return undefined;
  }
  return v === "lead" || v === "member" || v === "guardian" ? v : null;
}

/** One proposal as `proposal.list_own` and `proposal.view` give it. */
export interface ProposalInfo {
  readonly proposal: string;
  readonly call: string | undefined;
  readonly state: ProposalState;
  /**
   * The caller's role. `undefined` when the cell sends none, which the
   * pages treat as the least-privileged case (`rules.ts`).
   */
  readonly role: ProposalRole | undefined;
  /** The proposal title, or `""` when none is written or sent. */
  readonly title: string;
}

function proposalInfo(v: unknown): ProposalInfo | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  const proposal = id(o, "proposal");
  const call = optId(o, "call");
  const state = parseProposalState(member(o, "state"));
  const r = role(member(o, "role"));
  const title = optText(o, "title");
  if (proposal === null || call === null || state === null || r === null || title === null) {
    return null;
  }
  return Object.freeze({ proposal, call, state, role: r, title });
}

/** `proposal.list_own`: an array of `{proposal, call?, state, role?, title?}`. */
export function decodeOwnProposals(v: unknown): readonly ProposalInfo[] | null {
  return list(v, proposalInfo);
}

/** `proposal.view`: `{proposal, call?, state, role?, title?}`. */
export function decodeProposal(v: unknown): ProposalInfo | null {
  return proposalInfo(v);
}

/** `proposal.create`: `{proposal}`, the new draft. */
export function decodeCreated(v: unknown): string | null {
  const o = rec(v);
  return o === null ? null : id(o, "proposal");
}

/** The private workspace (I-21). */
export interface Workspace {
  readonly title: string;
  readonly summary: string;
  readonly narrative: string;
}

/** `proposal.get_workspace`: `{title?, summary?, narrative?}`, each a string. */
export function decodeWorkspace(v: unknown): Workspace | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  const title = optText(o, "title");
  const summary = optText(o, "summary");
  const narrative = optText(o, "narrative");
  if (title === null || summary === null || narrative === null) {
    return null;
  }
  return Object.freeze({ title, summary, narrative });
}

/** A completed command: `{accepted: true}`, as `fstp-api-core` answers one. */
export function decodeAccepted(v: unknown): true | null {
  const o = rec(v);
  return o !== null && member(o, "accepted") === true ? true : null;
}

/** A recorded plan version, with the total the cell computed, if it sent one. */
export interface PlanSaved {
  /** The plan total as an ADR-006 text. The browser never computes it (design section 3.9). */
  readonly total: string | undefined;
}

/**
 * `proposal.record_plan` and `stage2.revise`: `{accepted: true, total?}`,
 * where `total` is the cell's ADR-006 plan total. Interim, pending lanes
 * W3b and W5: the cell may answer with `accepted` alone.
 */
export function decodePlanSaved(v: unknown): PlanSaved | null {
  const o = rec(v);
  if (o === null || member(o, "accepted") !== true) {
    return null;
  }
  const total = optAmount(o, "total");
  return total === null ? null : Object.freeze({ total });
}

/** `guardian.begin_consent`: `{redirect}`, where the browser goes next. */
export function decodeRedirect(v: unknown): string | null {
  const o = rec(v);
  return o === null ? null : text(o, "redirect");
}

// ---------------------------------------------------------------------------
// Stage 2, notices and negotiation
// ---------------------------------------------------------------------------

/** One stage 2 question, under its author's handle (P-11). */
export interface Question {
  readonly handle: string;
  /** The day it was asked. Never a time of day (TH-08). */
  readonly asked: Day;
  readonly text: string;
}

/** A P-11 handle: a short token of letters, digits, `-` and `_`. */
const HANDLE = /^[A-Za-z0-9_-]{1,32}$/;

/**
 * `stage2.view`: `{questions: [{handle, asked, text}]}`, where `asked` is
 * a `YYYY-MM-DD` day. A question carrying a time of day is refused.
 */
export function decodeStage2(v: unknown): readonly Question[] | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  return list(member(o, "questions"), (x) => {
    const q = rec(x);
    if (q === null) {
      return null;
    }
    const handle = text(q, "handle");
    const asked = dayOf(member(q, "asked"));
    const t = text(q, "text");
    if (handle === null || !HANDLE.test(handle) || asked === null || t === null) {
      return null;
    }
    return Object.freeze({ handle, asked, text: t });
  });
}

/** One notice of the caller (`me.notices`). */
export interface Notice {
  /** The outbox record kind, such as `ProposalOutcome` or `IrcConcern`. */
  readonly kind: string;
  readonly proposal: string | undefined;
  readonly day: Day | undefined;
}

/** A notice kind: an upper-case letter, then letters and digits. */
const KIND = /^[A-Z][A-Za-z0-9]{0,63}$/;

/** `me.notices`: an array of `{kind, proposal?, day?}`. */
export function decodeNotices(v: unknown): readonly Notice[] | null {
  return list(v, (x) => {
    const o = rec(x);
    if (o === null) {
      return null;
    }
    const kind = text(o, "kind");
    const proposal = optId(o, "proposal");
    const d = member(o, "day");
    const day = d === undefined || d === null ? undefined : dayOf(d);
    if (kind === null || !KIND.test(kind) || proposal === null || day === null) {
      return null;
    }
    return Object.freeze({ kind, proposal, day });
  });
}

/** `negotiation.view`: `{acknowledged}`, whether the caller acknowledged the notice. */
export function decodeNegotiation(v: unknown): { readonly acknowledged: boolean } | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  const a = member(o, "acknowledged");
  return typeof a === "boolean" ? Object.freeze({ acknowledged: a }) : null;
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/** A JSON value the pages send: strings, booleans, null, arrays and objects. No number. */
export type Body = string | boolean | null | readonly Body[] | { readonly [k: string]: Body };

/**
 * `v` with the members of every object in UTF-16 code unit order, as the
 * cell's canonical JSON (RFC 8785) requires. `JSON.stringify` keeps that
 * order, since no member name here is an array index.
 */
export function canonical(v: Body): Body {
  if (Array.isArray(v)) {
    return (v as readonly Body[]).map(canonical);
  }
  if (typeof v === "object" && v !== null) {
    const o = v as { readonly [k: string]: Body };
    const out: Record<string, Body> = {};
    for (const k of Object.keys(o).sort()) {
      const x = o[k];
      if (x !== undefined) {
        out[k] = canonical(x);
      }
    }
    return out;
  }
  return v;
}
