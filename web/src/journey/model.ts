// The voyager surface model: the progress map's list and help panels,
// the "where is this proposal" strip and the activity log, built from the
// `proposal.journey` and `proposal.diary` reads (`SPEC/12-journey-ui.md`
// sections 6, 7 and 8; `docs/design/02-voyager-route-diary.md`; I-93,
// I-96, I-97, R-JV-01, R-JV-03 to R-JV-05, R-JV-11, R-JV-12, O-56 to
// O-60).
//
// Every visibility decision comes from the reads: these functions shape
// what a reply holds and never leave an entry out (I-93). Every sentence
// is a catalogue key with arguments, built at read time (I-97). Amounts
// stay the canonical ADR-006 strings the read gave (R-JV-12).
//
// Interim readings, pending Daniel:
//
// - A node the viewer is at is "current stage", whatever its kind. A node
//   on a leg the viewer may see is "completed". Every other node takes
//   its kind's words. The renderer of `fstp_html::route` reads the same.
// - The submission entry, the leg into SUBMITTED, is the receipt. The
//   read carries no audit-log anchor yet, so every receipt is "anchor
//   pending" (O-56) and no anchor value is ever shown.
// - The diary carries no guardian handle (I-86), so the guardian's
//   sentence names none.

import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { VALIDATORS } from "../gen/api.js";
import { JOURNEY_LABELS } from "./messages.en.js";

/** A formal state name of the proposal state machine (I-96). */
export type StateName =
  | "DRAFT"
  | "SUBMITTED"
  | "INELIGIBLE"
  | "STAGE1"
  | "NOT_SELECTED"
  | "STAGE2"
  | "RANKED"
  | "IRC_REVIEW"
  | "DEFERRED"
  | "DECLINED"
  | "NEGOTIATION"
  | "WITHDRAWN"
  | "GRANTED"
  | "IN_EXECUTION"
  | "COMPLETED"
  | "TERMINATED";

/** A catalogue message with its arguments. */
export interface Msg {
  readonly key: string;
  readonly args: Readonly<Record<string, string>>;
}

/** One completed leg of `proposal.journey`. */
export interface Leg {
  readonly from: StateName;
  readonly to: StateName;
  /** Microseconds since the epoch in UTC, as a decimal string. */
  readonly at: string;
  readonly seq: string;
}

/** The overlay of `proposal.journey` (section 5.5). */
export interface JourneyOverlay {
  readonly policy: string;
  readonly stage2WindowDays: number;
  readonly anonymity: "anonymous" | "named";
  readonly ircConcern: "deferred" | "declined";
}

/** The `proposal.journey` reply, read. */
export interface Journey {
  readonly proposal: string;
  readonly state: StateName;
  readonly since: string;
  readonly seq: string;
  readonly legs: readonly Leg[];
  /** Whether the caller's role gets the route strip (section 8.3, O-58). */
  readonly strip: boolean;
  readonly overlay: JourneyOverlay | null;
}

/** A node status of the design's "Node styling" table. */
export type NodeStatus = "completed" | "current" | "upcoming" | "pause" | "positive_end" | "negative_end";

/** One item of "Progress as a list" (R-JV-05). */
export interface RouteItem {
  readonly state: StateName;
  readonly status: NodeStatus;
  /** The plain label, `journey.node.<state>`. */
  readonly label: Msg;
  /** The status words. */
  readonly statusWords: Msg;
  /** The link to the node's help panel: `{page}#node-STATE`. */
  readonly href: string;
}

/** The help panel of one node (design "Help panel per node"). */
export interface HelpPanel {
  readonly state: StateName;
  /** The element id the node links target: `node-STATE`. */
  readonly id: string;
  /** "{plain label} ({STATE})". */
  readonly heading: Msg;
  readonly what: Msg;
  readonly who: Msg;
  readonly deadline: Msg;
  readonly can: Msg;
  /** What the viewer cannot see, such as reviewer identity under P-11. */
  readonly cannot: Msg;
  /** Whether the panel shows with no target: the current node's. */
  readonly open: boolean;
}

/** One item of the "where is this proposal" strip (section 8.3). */
export interface StripItem {
  readonly state: StateName;
  readonly status: "done" | "current" | "next";
  readonly label: Msg;
}

/** One sentence parameter of a diary entry. */
export type DiaryParam =
  | { readonly state: StateName }
  | { readonly amount: string }
  | { readonly seq: string }
  | { readonly score: readonly number[] }
  | { readonly outcome: boolean }
  | { readonly time: string };

/** One text reference of a diary entry: live, or erased (section 7.3). */
export type DiaryText =
  | { readonly text: string; readonly digest: string }
  | { readonly erasedOn: string; readonly cause: number };

/** The wire kinds of a diary entry (`fstp_access::ENTRY_KIND_NAMES`). */
export type EntryKind =
  | "state_transition"
  | "deadline_set"
  | "notice_sent"
  | "clarification"
  | "reviewer_score"
  | "conflict"
  | "vault_outcome"
  | "contract"
  | "milestone_payment"
  | "complaint"
  | "agent_action"
  | "guardian_step";

/** One entry of the `proposal.diary` reply, read. */
export interface DiaryEntry {
  readonly entry: string;
  readonly seq: string;
  readonly kind: EntryKind;
  readonly subject: "proposal" | "call" | "payment_request";
  readonly subjectId: string;
  readonly key: string;
  readonly at: string;
  readonly zone: string | null;
  readonly supersedes: string | null;
  readonly params: readonly DiaryParam[];
  readonly texts: readonly DiaryText[];
}

/** The `proposal.diary` reply, read. */
export interface Diary {
  readonly proposal: string;
  readonly entries: readonly DiaryEntry[];
}

/** One entry of the activity log page (design "Entry anatomy"). */
export interface LogEntry {
  readonly entry: string;
  readonly seq: string;
  readonly kind: EntryKind;
  /** The badge, the kind in words. */
  readonly badge: Msg;
  /** The glyph of the icon circle, hidden from screen readers. */
  readonly glyph: string;
  /** The body sentences, built at read time (I-97). */
  readonly body: readonly Msg[];
  /** The muted footnote, if any. */
  readonly footnote: Msg | null;
  /** Microseconds since the epoch in UTC, for the `<time>` element. */
  readonly at: string;
  /** Whether a text of the entry was erased (R-JV-11). */
  readonly erased: boolean;
  /** Whether the entry is a receipt whose anchor is not witnessed (O-56, R-JV-04). */
  readonly anchorPending: boolean;
}

/**
 * The class of the list item of `e`. Design 02 "Text erased" sets the
 * placeholder in italics and muted, which the tokens apply through
 * `.diary-entry--erased .diary-body` (R-JV-11).
 */
export function entryClass(e: LogEntry): string {
  return e.erased ? "diary-entry diary-entry--erased" : "diary-entry";
}

/** One page of the activity log. */
export interface LogPage {
  readonly entries: readonly LogEntry[];
  /** From 1. */
  readonly page: number;
  readonly pages: number;
}

// ---------------------------------------------------------------------------
// The route
// ---------------------------------------------------------------------------

/** The node kinds of the styling table. */
type Kind = "stage" | "pause" | "positive_end" | "negative_end";

/** The sixteen states in route order: main line, pause, final outcomes. */
export const ROUTE_ORDER: readonly StateName[] = Object.freeze([
  "DRAFT",
  "SUBMITTED",
  "STAGE1",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "NEGOTIATION",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "DEFERRED",
  "INELIGIBLE",
  "NOT_SELECTED",
  "DECLINED",
  "WITHDRAWN",
  "TERMINATED",
]);

/** The main line of the strip (section 8.3): DRAFT to COMPLETED. */
export const MAIN_LINE: readonly StateName[] = Object.freeze(ROUTE_ORDER.slice(0, 10));

/** The states WITHDRAWN is reachable from (NOTE 10). */
const WITHDRAW_FROM: ReadonlySet<StateName> = new Set<StateName>([
  "DRAFT",
  "SUBMITTED",
  "STAGE1",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "NEGOTIATION",
]);

const NEGATIVE: ReadonlySet<StateName> = new Set<StateName>(["INELIGIBLE", "NOT_SELECTED", "DECLINED", "WITHDRAWN", "TERMINATED"]);

/** The kind of `s` in the styling table. */
export function kindOf(s: StateName): Kind {
  if (s === "DEFERRED") {
    return "pause";
  }
  if (s === "COMPLETED") {
    return "positive_end";
  }
  return NEGATIVE.has(s) ? "negative_end" : "stage";
}

const STATES: ReadonlySet<string> = new Set<string>(ROUTE_ORDER);

function isState(v: unknown): v is StateName {
  return typeof v === "string" && STATES.has(v);
}

/** The catalogue key of the plain label of `s`. */
export function nodeKey(s: StateName): string {
  return `journey.node.${s.toLowerCase()}`;
}

function msg(key: string, args: Readonly<Record<string, string>> = {}): Msg {
  return Object.freeze({ key, args: Object.freeze({ ...args }) });
}

/** The transition table of section 5.1 in definition order, without the WITHDRAWN rule (I-95). */
export const PROPOSAL_EDGES: readonly (readonly [StateName, StateName])[] = Object.freeze([
  ["DRAFT", "SUBMITTED"],
  ["SUBMITTED", "INELIGIBLE"],
  ["SUBMITTED", "STAGE1"],
  ["STAGE1", "NOT_SELECTED"],
  ["STAGE1", "STAGE2"],
  ["STAGE2", "RANKED"],
  ["STAGE2", "DEFERRED"],
  ["RANKED", "NOT_SELECTED"],
  ["RANKED", "IRC_REVIEW"],
  ["IRC_REVIEW", "NEGOTIATION"],
  ["IRC_REVIEW", "DEFERRED"],
  ["IRC_REVIEW", "DECLINED"],
  ["DEFERRED", "STAGE2"],
  ["DEFERRED", "IRC_REVIEW"],
  ["NEGOTIATION", "GRANTED"],
  ["NEGOTIATION", "DECLINED"],
  ["GRANTED", "IN_EXECUTION"],
  ["GRANTED", "TERMINATED"],
  ["IN_EXECUTION", "COMPLETED"],
  ["IN_EXECUTION", "TERMINATED"],
] as const);

/**
 * Whether every route from DRAFT to `t` passes `k` over the transition
 * table: `k` dominates `t`. RANKED does not dominate IRC_REVIEW, since a
 * proposal can reach it from STAGE2 through DEFERRED.
 */
function dominates(k: StateName, t: StateName): boolean {
  if (k === t) {
    return false;
  }
  if (k === "DRAFT") {
    return true;
  }
  const seen = new Set<StateName>(["DRAFT"]);
  const todo: StateName[] = ["DRAFT"];
  for (let at = todo.pop(); at !== undefined; at = todo.pop()) {
    for (const [f, to] of PROPOSAL_EDGES) {
      if (f === at && to !== k && !seen.has(to)) {
        seen.add(to);
        todo.push(to);
      }
    }
  }
  return !seen.has(t);
}

/**
 * Whether the stage `s` is certainly behind the route of `j`: it lies on
 * every route to the position or to an end of a visible leg. A "grants
 * only" reader sees the legs of the grant alone (J2-R5), and the stages
 * before them are still passed. WITHDRAWN is reachable from many states,
 * so it proves nothing.
 */
function passed(j: Journey, s: StateName): boolean {
  if (kindOf(s) !== "stage") {
    return false;
  }
  const ends: StateName[] = [j.state];
  for (const l of j.legs) {
    ends.push(l.from, l.to);
  }
  return ends.some((t) => t !== "WITHDRAWN" && dominates(s, t));
}

/**
 * The status of `s` for the viewer of `j`. The legs stay as the read gave
 * them; a stage that every route to a point shown passes is completed.
 */
export function statusOf(j: Journey, s: StateName): NodeStatus {
  if (s === j.state) {
    return "current";
  }
  if (j.legs.some((l) => l.from === s || l.to === s) || passed(j, s)) {
    return "completed";
  }
  const k = kindOf(s);
  return k === "stage" ? "upcoming" : k;
}

// ---------------------------------------------------------------------------
// The readers
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Readonly<Record<string, unknown>> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(o: Readonly<Record<string, unknown>>, k: string): string {
  const v = o[k];
  return typeof v === "string" ? v : "";
}

/** Reads a `proposal.journey` reply, or null when it is outside its shape. */
export function readJourney(v: unknown): Journey | null {
  const check = VALIDATORS["proposal.journey"];
  if (check === undefined || !check(v) || !isRecord(v)) {
    return null;
  }
  const state = v["state"];
  const legsIn = v["legs"];
  if (!isState(state) || !Array.isArray(legsIn)) {
    return null;
  }
  const legs: Leg[] = [];
  for (const l of legsIn as readonly unknown[]) {
    if (!isRecord(l) || !isState(l["from"]) || !isState(l["to"])) {
      return null;
    }
    legs.push(Object.freeze({ from: l["from"], to: l["to"], at: str(l, "at"), seq: str(l, "seq") }));
  }
  const o = v["overlay"];
  let overlay: JourneyOverlay | null = null;
  if (isRecord(o)) {
    const days = o["stage2_window_days"];
    const anonymity = o["anonymity"];
    const irc = o["irc_concern"];
    if (typeof days !== "number" || !Number.isSafeInteger(days) || days < 0) {
      return null;
    }
    if ((anonymity !== "anonymous" && anonymity !== "named") || (irc !== "deferred" && irc !== "declined")) {
      return null;
    }
    overlay = Object.freeze({ policy: str(o, "policy"), stage2WindowDays: days, anonymity, ircConcern: irc });
  }
  return Object.freeze({
    proposal: str(v, "proposal"),
    state,
    since: str(v, "since"),
    seq: str(v, "seq"),
    legs: Object.freeze(legs),
    strip: v["strip"] === true,
    overlay,
  });
}

/** An ADR-006 canonical decimal string: no sign, no leading zero, two decimals. */
const CANONICAL_AMOUNT = /^(?:0|[1-9][0-9]*)\.[0-9]{2}$/;

function readParam(p: unknown): DiaryParam | null {
  if (!isRecord(p)) {
    return null;
  }
  const keys = Object.keys(p);
  if (keys.length !== 1) {
    return null;
  }
  const v = p[keys[0] ?? ""];
  switch (keys[0]) {
    case "state":
      return isState(v) ? Object.freeze({ state: v }) : null;
    case "amount":
      return typeof v === "string" && CANONICAL_AMOUNT.test(v) ? Object.freeze({ amount: v }) : null;
    case "seq":
      return typeof v === "string" ? Object.freeze({ seq: v }) : null;
    case "score":
      return Array.isArray(v) && v.every((n) => typeof n === "number" && Number.isSafeInteger(n))
        ? Object.freeze({ score: Object.freeze([...(v as number[])]) })
        : null;
    case "outcome":
      return typeof v === "boolean" ? Object.freeze({ outcome: v }) : null;
    case "time":
      return typeof v === "string" ? Object.freeze({ time: v }) : null;
    default:
      return null;
  }
}

function readText(t: unknown): DiaryText | null {
  if (!isRecord(t)) {
    return null;
  }
  if (typeof t["erased_on"] === "string" && typeof t["cause"] === "number") {
    return Object.freeze({ erasedOn: t["erased_on"], cause: t["cause"] });
  }
  if (typeof t["text"] === "string" && typeof t["digest"] === "string") {
    return Object.freeze({ text: t["text"], digest: t["digest"] });
  }
  return null;
}

/** Reads a `proposal.diary` reply, or null when it is outside its shape (R-JV-12: amounts canonical). */
export function readDiary(v: unknown): Diary | null {
  const check = VALIDATORS["proposal.diary"];
  if (check === undefined || !check(v) || !isRecord(v) || !Array.isArray(v["entries"])) {
    return null;
  }
  const entries: DiaryEntry[] = [];
  for (const e of v["entries"] as readonly unknown[]) {
    if (!isRecord(e) || !Array.isArray(e["params"]) || !Array.isArray(e["texts"])) {
      return null;
    }
    const params: DiaryParam[] = [];
    for (const p of e["params"] as readonly unknown[]) {
      const r = readParam(p);
      if (r === null) {
        return null;
      }
      params.push(r);
    }
    const texts: DiaryText[] = [];
    for (const t of e["texts"] as readonly unknown[]) {
      const r = readText(t);
      if (r === null) {
        return null;
      }
      texts.push(r);
    }
    entries.push(
      Object.freeze({
        entry: str(e, "entry"),
        seq: str(e, "seq"),
        kind: e["kind"] as EntryKind,
        subject: e["subject"] as DiaryEntry["subject"],
        subjectId: str(e, "subject_id"),
        key: str(e, "key"),
        at: str(e, "at"),
        zone: typeof e["zone"] === "string" ? e["zone"] : null,
        supersedes: typeof e["supersedes"] === "string" ? e["supersedes"] : null,
        params: Object.freeze(params),
        texts: Object.freeze(texts),
      }),
    );
  }
  return Object.freeze({ proposal: str(v, "proposal"), entries: Object.freeze(entries) });
}

// ---------------------------------------------------------------------------
// Progress as a list, help panels, withdrawal and the strip
// ---------------------------------------------------------------------------

/** The link of node `s` on `page`: `{page}#node-STATE`. */
export function nodeHref(page: string, s: StateName): string {
  return `${page}#node-${s}`;
}

/** "Progress as a list": every node in route order, linked into `page` (R-JV-05). */
export function routeItems(j: Journey, page: string): readonly RouteItem[] {
  return Object.freeze(
    ROUTE_ORDER.map((s) => {
      const status = statusOf(j, s);
      return Object.freeze({
        state: s,
        status,
        label: msg(nodeKey(s)),
        statusWords: msg(`journey.route.status.${status}`),
        href: nodeHref(page, s),
      });
    }),
  );
}

/** The five parts of the help panel of `s`, reading the overlay where the stage depends on it. */
function helpParts(j: Journey, s: StateName): Pick<HelpPanel, "what" | "who" | "deadline" | "can" | "cannot"> {
  const base = `journey.help.${s.toLowerCase()}`;
  let deadline = msg(`${base}.deadline`);
  let cannot = msg(`${base}.cannot`);
  if (s === "STAGE2") {
    // R-JV-07: the overlay of the original call's policy. P-07 sets the
    // window and P-11 whether reviewers are anonymous.
    deadline =
      j.overlay === null
        ? msg("journey.help.stage2.deadline_unknown")
        : msg("journey.help.stage2.deadline", { days: String(j.overlay.stage2WindowDays) });
    cannot = j.overlay !== null && j.overlay.anonymity === "named" ? msg("journey.help.stage2.cannot_named") : cannot;
  }
  return { what: msg(`${base}.what`), who: msg(`${base}.who`), deadline, can: msg(`${base}.can`), cannot };
}

/** The sixteen help panels, the current node's open. */
export function helpPanels(j: Journey): readonly HelpPanel[] {
  return Object.freeze(
    ROUTE_ORDER.map((s) =>
      Object.freeze({
        state: s,
        id: `node-${s}`,
        heading: msg("journey.help.heading", { label: say(msg(nodeKey(s))), state: s }),
        ...helpParts(j, s),
        open: s === j.state,
      }),
    ),
  );
}

/** Whether the "Withdraw this proposal" control shows (NOTE 10, R-SB-03). */
export function canWithdraw(j: Journey): boolean {
  return WITHDRAW_FROM.has(j.state);
}

/** The strip of the main line, or null when the reply gives no strip (O-58). */
export function stripOf(j: Journey): readonly StripItem[] | null {
  if (!j.strip) {
    return null;
  }
  return Object.freeze(
    MAIN_LINE.map((s) => {
      const st = statusOf(j, s);
      const status: StripItem["status"] = st === "current" ? "current" : st === "completed" ? "done" : "next";
      return Object.freeze({ state: s, status, label: msg(nodeKey(s)) });
    }),
  );
}

// ---------------------------------------------------------------------------
// The activity log
// ---------------------------------------------------------------------------

/** Entries per page of the activity log (design "Activity log"). */
export const LOG_PAGE_SIZE = 20;

/** The decimal string `s` as a bigint, or -1 when it is not one. */
function big(s: string): bigint {
  return /^[0-9]{1,30}$/.test(s) ? BigInt(s) : -1n;
}

/** The UTC day of microseconds since the epoch, `YYYY-MM-DD`, or the input when it is no time. */
export function dayOf(micros: string): string {
  const iso = isoOf(micros);
  return iso === null ? micros : iso.slice(0, 10);
}

/** The ISO 8601 UTC time of microseconds since the epoch, or null. */
export function isoOf(micros: string): string | null {
  if (!/^-?[0-9]{1,19}$/.test(micros)) {
    return null;
  }
  const ms = Number(BigInt(micros) / 1000n);
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function param<K extends "state" | "amount" | "seq" | "time">(e: DiaryEntry, k: K): string | null {
  for (const p of e.params) {
    if (k in p) {
      const v = (p as Readonly<Record<string, unknown>>)[k];
      return typeof v === "string" ? v : null;
    }
  }
  return null;
}

function states(e: DiaryEntry): StateName[] {
  const out: StateName[] = [];
  for (const p of e.params) {
    if ("state" in p) {
      out.push(p.state);
    }
  }
  return out;
}

/** The glyphs of the icon circle, hidden from screen readers (design "Layout per entry kind"). */
const GLYPHS = Object.freeze({
  arrow: "→",
  stopwatch: "⏱",
  question: "?",
  answer: "A",
  check: "✓",
  cross: "✗",
  receipt: "R",
  star: "★",
  coin: "¤",
  envelope: "✉",
  erased: "∅",
  shield: "⛨",
  dot: "•",
});

/** The sentence key of summary key `key`, such as `journey.diary.sentence.deadline_set`. */
function sentenceKey(key: string): string {
  const k = key.startsWith("journey.") ? key.slice("journey.".length).replace(/\./g, "_") : "";
  const id = `journey.diary.sentence.${k}`;
  return k !== "" && typeof JOURNEY_LABELS[id] === "string" ? id : "journey.diary.sentence.other";
}

/** The badge, glyph, body and footnote of one entry, by its kind (design "Layout per entry kind"). */
function shape(e: DiaryEntry): Pick<LogEntry, "badge" | "glyph" | "body" | "footnote" | "anchorPending"> {
  const plain = { anchorPending: false, footnote: null };
  const sentence = msg(sentenceKey(e.key));
  switch (e.kind) {
    case "state_transition": {
      const [from, to] = states(e);
      if (from === undefined || to === undefined) {
        return { ...plain, badge: msg("journey.diary.kind.state_transition"), glyph: GLYPHS.arrow, body: [sentence] };
      }
      if (to === "WITHDRAWN") {
        // Q3, O-54: one stage-aware sentence, never a score or a comment.
        const body =
          from === "DRAFT"
            ? msg("journey.diary.withdrawn_draft")
            : msg("journey.diary.withdrawn_after", { label: say(msg(nodeKey(from))), state: from });
        return { ...plain, badge: msg("journey.diary.kind.withdrawn"), glyph: GLYPHS.arrow, body: [body] };
      }
      const moved = msg("journey.diary.state_change", {
        from_label: say(msg(nodeKey(from))),
        from,
        to_label: say(msg(nodeKey(to))),
        to,
      });
      if (to === "SUBMITTED") {
        // O-56, R-JV-04: the submission receipt with its ledger sequence.
        return {
          badge: msg("journey.diary.kind.receipt"),
          glyph: GLYPHS.receipt,
          body: [moved, msg("journey.diary.receipt", { seq: e.seq })],
          footnote: msg("journey.diary.anchor_note"),
          anchorPending: true,
        };
      }
      return { ...plain, badge: msg("journey.diary.kind.state_transition"), glyph: GLYPHS.arrow, body: [moved] };
    }
    case "deadline_set": {
      const t = param(e, "time");
      const iso = t === null ? null : isoOf(t);
      const body = iso === null ? [sentence] : [sentence, msg("journey.diary.deadline_at", { time: iso.slice(0, 16).replace("T", " ") })];
      return { ...plain, badge: msg("journey.diary.kind.deadline_set"), glyph: GLYPHS.stopwatch, body };
    }
    case "notice_sent":
      return { ...plain, badge: msg("journey.diary.kind.notice_sent"), glyph: GLYPHS.envelope, body: [sentence] };
    case "clarification": {
      const answer = e.key === "journey.clarification.answer";
      const question = e.key === "journey.clarification.question";
      const badge = answer ? "journey.diary.kind.answer" : question ? "journey.diary.kind.question" : "journey.diary.kind.clarification";
      return { ...plain, badge: msg(badge), glyph: answer ? GLYPHS.answer : GLYPHS.question, body: [sentence] };
    }
    case "reviewer_score": {
      // The read gives a score only where O-54 allows it.
      const scores = e.params.flatMap((p) => ("score" in p ? [p.score.join(", ")] : []));
      const body = scores.length === 0 ? [sentence] : [sentence, msg("journey.diary.scores", { scores: scores.join("; ") })];
      return { ...plain, badge: msg("journey.diary.kind.reviewer_score"), glyph: GLYPHS.star, body };
    }
    case "conflict":
      return { ...plain, badge: msg("journey.diary.kind.conflict"), glyph: GLYPHS.dot, body: [sentence] };
    case "vault_outcome": {
      const o = e.params.find((p) => "outcome" in p);
      const passed = o !== undefined && "outcome" in o ? o.outcome : null;
      const body = passed === null ? [sentence] : [msg(passed ? "journey.diary.outcome_yes" : "journey.diary.outcome_no")];
      return { ...plain, badge: msg("journey.diary.kind.vault_outcome"), glyph: passed === false ? GLYPHS.cross : GLYPHS.check, body };
    }
    case "contract":
      return { ...plain, badge: msg("journey.diary.kind.contract"), glyph: GLYPHS.envelope, body: [sentence] };
    case "milestone_payment": {
      const milestone = e.key.startsWith("journey.milestone.");
      const body: Msg[] = [sentence];
      const seq = param(e, "seq");
      if (seq !== null && !milestone) {
        body.push(msg("journey.diary.request", { seq }));
      }
      const amount = param(e, "amount");
      if (amount !== null) {
        // R-JV-12: the canonical ADR-006 string, unchanged.
        body.push(msg("journey.diary.amount", { amount }));
      }
      return {
        ...plain,
        badge: msg(milestone ? "journey.diary.kind.milestone" : "journey.diary.kind.payment"),
        glyph: milestone ? GLYPHS.star : GLYPHS.coin,
        body,
      };
    }
    case "complaint":
      return { ...plain, badge: msg("journey.diary.kind.complaint"), glyph: GLYPHS.dot, body: [sentence] };
    case "agent_action":
      return { ...plain, badge: msg("journey.diary.kind.agent_action"), glyph: GLYPHS.dot, body: [sentence] };
    case "guardian_step":
      // O-60: only the guardian's read holds this entry.
      return { ...plain, badge: msg("journey.diary.kind.guardian_step"), glyph: GLYPHS.shield, body: [msg("journey.diary.guardian_consent")] };
    default:
      return { ...plain, badge: msg("journey.diary.kind.state_transition"), glyph: GLYPHS.dot, body: [sentence] };
  }
}

/** The log entry of `e`. An erased text gives the placeholder of section 7.3 in place of the body. */
function logEntry(e: DiaryEntry): LogEntry {
  const erased = e.texts.find((t): t is { readonly erasedOn: string; readonly cause: number } => "erasedOn" in t);
  const s = shape(e);
  if (erased !== undefined) {
    const cause = `journey.diary.erase_cause.${erased.cause}`;
    const reason = say(msg(typeof JOURNEY_LABELS[cause] === "string" ? cause : "journey.diary.erase_cause.other"));
    return Object.freeze({
      entry: e.entry,
      seq: e.seq,
      kind: e.kind,
      badge: s.badge,
      glyph: GLYPHS.erased,
      body: Object.freeze([msg("journey.diary.erased", { date: dayOf(erased.erasedOn), reason })]),
      footnote: msg("journey.diary.erased_note"),
      at: e.at,
      erased: true,
      anchorPending: s.anchorPending,
    });
  }
  return Object.freeze({
    entry: e.entry,
    seq: e.seq,
    kind: e.kind,
    badge: s.badge,
    glyph: s.glyph,
    body: Object.freeze([...s.body]),
    footnote: s.footnote,
    at: e.at,
    erased: false,
    anchorPending: s.anchorPending,
  });
}

/** Page `page` (from 1) of the activity log of `d`, newest first. */
export function activityLog(d: Diary, page: number): LogPage {
  const sorted = [...d.entries].sort((a, b) => {
    const x = big(a.seq);
    const y = big(b.seq);
    return x === y ? 0 : x > y ? -1 : 1;
  });
  const pages = Math.max(1, Math.ceil(sorted.length / LOG_PAGE_SIZE));
  const at = Number.isSafeInteger(page) ? Math.min(Math.max(page, 1), pages) : 1;
  const slice = sorted.slice((at - 1) * LOG_PAGE_SIZE, at * LOG_PAGE_SIZE);
  return Object.freeze({ entries: Object.freeze(slice.map(logEntry)), page: at, pages });
}

// ---------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------

let catalogue: I18n | null = null;

function i18n(): I18n {
  catalogue ??= createI18n({ catalogues: [{ locale: "en", labels: JOURNEY_LABELS, approved: {} }], locale: "en" });
  return catalogue;
}

/** The English text of `m` from the journey catalogue, as an interface string. */
export function label(m: Msg): Label {
  return Object.keys(m.args).length === 0 ? i18n().label(m.key) : i18n().label(m.key, m.args);
}

/** The English text of `m` from the journey catalogue. */
export function say(m: Msg): string {
  return label(m);
}
