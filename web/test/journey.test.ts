// The voyager surface of the web app: the progress map's list and help
// panels, the strip and the activity log (lane j3; `SPEC/12-journey-ui.md`
// sections 6 to 8; `docs/design/02-voyager-route-diary.md`;
// `docs/design/04-reviewer-committee-irc.md` "Proposal status" strip).
//
// Every reply here is synthetic and fits the generated validators of
// `proposal.journey` and `proposal.diary`. The references (route order,
// plain labels, transitions, sentences) restate the design text.
//
// Lane j3 test author. Red until the implementer builds
// `web/src/journey/model.ts`, its catalogue and its routes: the stubs
// throw `NotImplemented`.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { createRouter } from "../src/core/router.js";
import { VALIDATORS } from "../src/gen/api.js";
import { JOURNEY_LABELS } from "../src/journey/messages.en.js";
import {
  LOG_PAGE_SIZE,
  type Diary,
  type DiaryEntry,
  type Journey,
  type LogEntry,
  type Msg,
  type StateName,
  activityLog,
  canWithdraw,
  entryClass,
  helpPanels,
  readDiary,
  readJourney,
  routeItems,
  say,
  stripOf,
} from "../src/journey/model.js";
import { JOURNEY_PATHS, JOURNEY_ROUTES, journeyLinks } from "../src/journey/routes.js";
import { assert, eq, forAll, show, test } from "./support/harness.js";
import { WEB_DIR } from "./support/paths.js";
import { type Rng } from "./support/rng.js";

// ---------------------------------------------------------------------------
// The design's route, as a reference
// ---------------------------------------------------------------------------

/** The sixteen states in route order, with their plain labels (design "Node labels"). */
const ROUTE: readonly (readonly [StateName, string])[] = [
  ["DRAFT", "Draft"],
  ["SUBMITTED", "Submitted"],
  ["STAGE1", "Stage 1 evaluation"],
  ["STAGE2", "Stage 2 questions"],
  ["RANKED", "Ranked, awaiting committee decision"],
  ["IRC_REVIEW", "Independent review"],
  ["NEGOTIATION", "Negotiation"],
  ["GRANTED", "Granted"],
  ["IN_EXECUTION", "Project in progress"],
  ["COMPLETED", "Completed"],
  ["DEFERRED", "Deferred to the next call"],
  ["INELIGIBLE", "Not eligible"],
  ["NOT_SELECTED", "Not selected"],
  ["DECLINED", "Declined"],
  ["WITHDRAWN", "Withdrawn"],
  ["TERMINATED", "Grant terminated"],
];

const PLAIN: ReadonlyMap<StateName, string> = new Map(ROUTE);
const MAIN_LINE: readonly StateName[] = ROUTE.slice(0, 10).map(([s]) => s);
const NEGATIVE_ENDS: readonly StateName[] = ["INELIGIBLE", "NOT_SELECTED", "DECLINED", "WITHDRAWN", "TERMINATED"];
const TERMINAL: readonly StateName[] = [...NEGATIVE_ENDS, "COMPLETED"];

/** The transition table of section 5.1, without the WITHDRAWN rule. */
const EDGES: readonly (readonly [StateName, StateName])[] = [
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
];

/** The states WITHDRAWN is reachable from (NOTE 10). */
const WITHDRAW_FROM: readonly StateName[] = [
  "DRAFT",
  "SUBMITTED",
  "STAGE1",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "NEGOTIATION",
];

/** The page the map sits on. */
const PAGE = "/app/proposals/1001/progress";

/** The expected status of `s` on a route at `at` with `legs`. */
function statusOf(s: StateName, at: StateName, legs: readonly (readonly [StateName, StateName])[]): string {
  if (s === at) {
    return "current";
  }
  if (legs.some(([f, t]) => f === s || t === s)) {
    return "completed";
  }
  if (s === "DEFERRED") {
    return "pause";
  }
  if (s === "COMPLETED") {
    return "positive_end";
  }
  return NEGATIVE_ENDS.includes(s) ? "negative_end" : "upcoming";
}

/** The list words of each status (design "Text alternative"). */
const LIST_WORDS: Readonly<Record<string, string>> = {
  completed: "Completed",
  current: "Current stage",
  upcoming: "Upcoming",
  pause: "Possible pause",
  positive_end: "Upcoming, final outcome",
  negative_end: "Possible final outcome",
};

// ---------------------------------------------------------------------------
// Synthetic replies
// ---------------------------------------------------------------------------

/** A random walk from DRAFT over the transition table. */
function walk(r: Rng): { readonly legs: (readonly [StateName, StateName])[]; readonly at: StateName } {
  let at: StateName = "DRAFT";
  const legs: (readonly [StateName, StateName])[] = [];
  const steps = r.between(0, 12);
  for (let i = 0; i < steps && !TERMINAL.includes(at); i += 1) {
    const next: StateName[] = EDGES.filter(([f]) => f === at).map(([, t]) => t);
    if (WITHDRAW_FROM.includes(at)) {
      next.push("WITHDRAWN");
    }
    const to = r.pick(next);
    legs.push([at, to]);
    at = to;
  }
  return { legs, at };
}

/** A `proposal.journey` reply of a walk. */
function journeyBody(
  legs: readonly (readonly [StateName, StateName])[],
  at: StateName,
  strip: boolean,
  overlay: unknown = null,
): Record<string, unknown> {
  return {
    proposal: "1001",
    state: at,
    since: "1793750400000000",
    seq: String(legs.length + 10),
    legs: legs.map(([from, to], i) => ({ from, to, at: String(1793750400000000 + i * 60_000_000), seq: String(i + 11) })),
    strip,
    map: false,
    withdraw: false,
    overlay,
  };
}

const OVERLAY = {
  policy: "3",
  stage2_window_days: 14,
  anonymity: "anonymous",
  irc_concern: "deferred",
  agent_actions: "draft_only",
  wording: ["P-20"],
};

function journey(v: Record<string, unknown>): Journey {
  const check = VALIDATORS["proposal.journey"];
  assert(check !== undefined && check(v), `the sample fits the generated validator: ${show(v)}`);
  const j = readJourney(v);
  assert(j !== null, `readJourney refused ${show(v)}`);
  return j;
}

/** The STAGE2 reply of the design's prototype. */
function stage2(strip = false): Journey {
  return journey(
    journeyBody(
      [
        ["DRAFT", "SUBMITTED"],
        ["SUBMITTED", "STAGE1"],
        ["STAGE1", "STAGE2"],
      ],
      "STAGE2",
      strip,
      OVERLAY,
    ),
  );
}

/** One diary entry on the wire. */
function wireEntry(seq: number, kind: string, key: string, params: unknown[] = [], texts: unknown[] = []): Record<string, unknown> {
  return {
    entry: seq.toString(16).padStart(32, "0"),
    seq: String(seq),
    kind,
    subject: "proposal",
    subject_id: "1001",
    key,
    at: String(1793750400000000 + seq * 60_000_000),
    params,
    texts,
  };
}

function transition(seq: number, from: StateName, to: StateName): Record<string, unknown> {
  return wireEntry(seq, "state_transition", "journey.state.transitioned", [{ state: from }, { state: to }]);
}

function diary(entries: readonly Record<string, unknown>[]): Diary {
  const v = { proposal: "1001", entries };
  const check = VALIDATORS["proposal.diary"];
  assert(check !== undefined && check(v), `the sample fits the generated validator: ${show(v)}`);
  const d = readDiary(v);
  assert(d !== null, `readDiary refused ${show(v)}`);
  return d;
}

/** Every entry of every page of the log of `d`. */
function allPages(d: Diary): LogEntry[] {
  const first = activityLog(d, 1);
  const out = [...first.entries];
  for (let p = 2; p <= first.pages; p += 1) {
    out.push(...activityLog(d, p).entries);
  }
  return out;
}

/** The English text of a message, which must have a catalogue entry. */
function text(m: Msg): string {
  assert(typeof JOURNEY_LABELS[m.key] === "string", `the catalogue holds ${m.key}`);
  return say(m);
}

function bodyText(e: LogEntry): string {
  return e.body.map(text).join(" ");
}

// ---------------------------------------------------------------------------
// The readers
// ---------------------------------------------------------------------------

/** I-97, TH-26: the journey reader takes the generated shape, and both refuse the same bodies. */
test("i97_journey_reader_takes_the_generated_shape", () => {
  const check = VALIDATORS["proposal.journey"];
  assert(check !== undefined, "gen/api.ts holds proposal.journey");
  const good = journeyBody([["DRAFT", "SUBMITTED"]], "SUBMITTED", false, OVERLAY);
  assert(check(good) && readJourney(good) !== null, "a full reply reads");
  assert(readJourney(journeyBody([], "DRAFT", true)) !== null, "a reply with no overlay reads");
  const bad: unknown[] = [
    { ...good, state: "STAGE3" },
    { ...good, title: "Synthetic title" },
    { ...good, legs: [{ from: "DRAFT", to: "SUBMITTED", at: "1", seq: "1", reason: "free text" }] },
    { ...good, strip: "yes" },
    { ...good, overlay: { ...OVERLAY, p11_text: "Reviewers are anonymous" } },
  ];
  for (const v of bad) {
    eq(check(v), false, `the generated validator refuses ${show(v)}`);
    eq(readJourney(v), null, `the reader refuses ${show(v)}`);
  }
});

/** R-JV-12, ADR-006: the diary reader refuses an amount that is not a canonical decimal string. */
test("r_jv_12_diary_reader_refuses_non_canonical_amounts", () => {
  const ok = wireEntry(40, "milestone_payment", "journey.milestone.closed", [{ amount: "1500.50" }]);
  assert(readDiary({ proposal: "1001", entries: [ok] }) !== null, "a canonical amount reads");
  for (const amount of ["1500.5", "1,500.50", "1500", "01500.50", "1e3", "+1500.50", " 1500.50", "1500.500"]) {
    const v = { proposal: "1001", entries: [wireEntry(40, "milestone_payment", "journey.milestone.closed", [{ amount }])] };
    eq(readDiary(v), null, `the reader refuses ${amount}`);
  }
});

// ---------------------------------------------------------------------------
// Progress as a list and help panels
// ---------------------------------------------------------------------------

/**
 * R-JV-05, R-JV-01, I-96: the list holds every node in route order, each
 * linked to its help panel, with its plain label and the status words of
 * the design, over generated routes.
 */
test("r_jv_05_list_items_follow_the_route_in_order", () => {
  forAll(walk, ({ legs, at }) => {
    const items = routeItems(journey(journeyBody(legs, at, false)), PAGE);
    eq(
      items.map((i) => i.state),
      ROUTE.map(([s]) => s),
      "route order",
    );
    for (const i of items) {
      eq(i.href, `${PAGE}#node-${i.state}`, `${i.state} links to its panel`);
      eq(text(i.label), PLAIN.get(i.state), `${i.state} plain label`);
      const want = statusOf(i.state, at, legs);
      eq(i.status, want, `${i.state} status`);
      eq(text(i.statusWords), LIST_WORDS[want], `${i.state} status words`);
    }
  });
});

/**
 * Design "Help panel per node", `SPEC/12-journey-ui.md` section 6: one
 * panel per node with the id the links target, a heading with the plain
 * label and the formal state, and the five parts from catalogue keys.
 * Only the current node's panel is open with no target.
 */
test("r_jv_05_help_panel_per_node_names_what_who_deadline_can_and_cannot", () => {
  const panels = helpPanels(stage2());
  eq(
    panels.map((p) => p.state),
    ROUTE.map(([s]) => s),
    "one panel per node, in route order",
  );
  for (const p of panels) {
    eq(p.id, `node-${p.state}`, `${p.state} panel id`);
    eq(text(p.heading), `${PLAIN.get(p.state)} (${p.state})`, `${p.state} heading`);
    for (const part of [p.what, p.who, p.deadline, p.can, p.cannot]) {
      assert(part.key.startsWith("journey.help."), `${p.state}: ${part.key} is a help key`);
      assert(text(part).trim() !== "", `${p.state}: ${part.key} has text`);
    }
    eq(p.open, p.state === "STAGE2", `${p.state} open with no target`);
  }
});

/**
 * Design "DEFERRED re-entry" and "Help panel per node", R-JV-07: the
 * STAGE2 panel says that the proposal moves to DEFERRED when the P-07
 * window passes with no answers, and its deadline names the window
 * length from the overlay. Under P-11 "anonymous", the STAGE2 panel says
 * the viewer cannot see who the reviewers are.
 */
test("r_jv_07_stage2_panel_reads_the_overlay", () => {
  const p = helpPanels(stage2()).find((x) => x.state === "STAGE2");
  assert(p !== undefined, "a STAGE2 panel");
  assert(text(p.what).includes("DEFERRED") || text(p.deadline).includes("DEFERRED"), `STAGE2 names DEFERRED: ${text(p.what)}`);
  assert(text(p.deadline).includes("14"), `the deadline names the 14-day window: ${text(p.deadline)}`);
  assert(/reviewer/i.test(text(p.cannot)), `STAGE2 says reviewer identity is hidden: ${text(p.cannot)}`);
});

/** NOTE 10, R-SB-03: the withdraw control shows in every non-terminal state before GRANTED, DEFERRED included, and nowhere else. */
test("r_jv_05_withdraw_control_follows_note_10", () => {
  for (const [s] of ROUTE) {
    const j = journey(journeyBody([], s, false));
    eq(canWithdraw(j), WITHDRAW_FROM.includes(s), `withdraw at ${s}`);
  }
});

// ---------------------------------------------------------------------------
// The strip of the judging roles
// ---------------------------------------------------------------------------

/**
 * Section 8.3, O-58: a reply whose `strip` is false, as the IRC member's
 * is, gives no strip. The web never decides this itself.
 */
test("r_jv_03_o58_no_strip_when_the_read_gives_none", () => {
  forAll(walk, ({ legs, at }) => {
    eq(stripOf(journey(journeyBody(legs, at, false))), null, "no strip");
  });
});

/**
 * Section 8.3, design "Proposal status" strip: for a reviewer or a
 * committee member the strip is the main line with plain labels, done
 * stages, the current one and the next ones, and no end state.
 */
test("r_jv_01_strip_shows_the_main_line_with_the_current_stage", () => {
  forAll(
    (r) => r.between(0, 8),
    (i) => {
      const at = MAIN_LINE[i] ?? "DRAFT";
      const legs: (readonly [StateName, StateName])[] = [];
      for (let k = 0; k < i; k += 1) {
        legs.push([MAIN_LINE[k] ?? "DRAFT", MAIN_LINE[k + 1] ?? "DRAFT"]);
      }
      const strip = stripOf(journey(journeyBody(legs, at, true)));
      assert(strip !== null, "a strip");
      eq(
        strip.map((s) => s.state),
        [...MAIN_LINE],
        "the main line only",
      );
      strip.forEach((s, k) => {
        eq(s.status, k < i ? "done" : k === i ? "current" : "next", `${s.state} status`);
        eq(text(s.label), PLAIN.get(s.state), `${s.state} label`);
      });
    },
  );
});

// ---------------------------------------------------------------------------
// The activity log
// ---------------------------------------------------------------------------

/**
 * I-93, R-JV-03: the log shows every entry the read gave, once, newest
 * first, twenty to a page. The web never leaves one out.
 */
test("i93_activity_log_shows_every_entry_newest_first", () => {
  forAll(
    (r) => {
      const n = r.between(0, 65);
      const seqs = new Set<number>();
      while (seqs.size < n) {
        seqs.add(r.between(1, 5000));
      }
      return [...seqs];
    },
    (seqs) => {
      const d = diary(seqs.map((s) => transition(s, "DRAFT", "SUBMITTED")));
      const first = activityLog(d, 1);
      eq(first.page, 1, "page 1");
      eq(first.pages, Math.max(1, Math.ceil(seqs.length / LOG_PAGE_SIZE)), "page count");
      const shown = allPages(d);
      eq(shown.length, seqs.length, "every entry once");
      eq(
        shown.map((e) => Number(e.seq)),
        [...seqs].sort((a, b) => b - a),
        "newest first",
      );
      assert(first.entries.length <= LOG_PAGE_SIZE, "at most twenty to a page");
    },
  );
});

/** Design "Layout per entry kind", I-96: a state change names both states by plain label and formal name. */
test("i96_state_change_entry_names_both_states", () => {
  const [e] = activityLog(diary([transition(12, "STAGE1", "STAGE2")]), 1).entries;
  assert(e !== undefined, "one entry");
  eq(text(e.badge), "State change", "badge");
  const body = bodyText(e);
  assert(
    body.includes("from Stage 1 evaluation (STAGE1) to Stage 2 questions (STAGE2)"),
    `the sentence names both states: ${body}`,
  );
});

/** Design "Withdrawal entries (Q3)", O-54: the stage-aware withdrawal sentences, with no score or comment. */
test("r_jv_11_withdrawal_entries_are_stage_aware", () => {
  const d = diary([transition(20, "DRAFT", "WITHDRAWN"), transition(30, "STAGE2", "WITHDRAWN")]);
  const byseq = new Map(activityLog(d, 1).entries.map((e) => [e.seq, e]));
  const draft = byseq.get("20");
  const later = byseq.get("30");
  assert(draft !== undefined && later !== undefined, "both entries");
  eq(text(draft.badge), "Withdrawn", "badge");
  eq(bodyText(draft), "You withdrew this draft before submitting it.", "from DRAFT");
  eq(
    bodyText(later),
    "You withdrew this proposal at Stage 2 questions (STAGE2). Reviewers were told it is no longer under review.",
    "after submission",
  );
  for (const e of [draft, later]) {
    assert(!/score|comment/i.test(bodyText(e)), "no scores or comments");
  }
});

/**
 * R-JV-11, I-97, section 7.3: an erased text shows "Entry text erased on
 * <date>, reason: <cause>." with the note that the entry stays, keeps its
 * time and kind, and never shows the reference or a blank.
 */
test("r_jv_11_erased_text_shows_the_placeholder", () => {
  const erasedOn = String(Date.UTC(2026, 10, 1) * 1000);
  const d = diary([
    wireEntry(50, "clarification", "journey.clarification.question", [], [{ erased_on: erasedOn, cause: 1 }]),
    wireEntry(51, "clarification", "journey.clarification.question", [], [{ text: "77", digest: "ab".repeat(32) }]),
  ]);
  const byseq = new Map(activityLog(d, 1).entries.map((e) => [e.seq, e]));
  const erased = byseq.get("50");
  const live = byseq.get("51");
  assert(erased !== undefined && live !== undefined, "both entries");
  eq(erased.erased, true, "erased");
  eq(live.erased, false, "live");
  eq(erased.at, wireEntry(50, "clarification", "x")["at"], "the entry keeps its time");
  eq(erased.kind, "clarification", "the entry keeps its kind");
  const body = bodyText(erased);
  assert(body.startsWith("Entry text erased on 2026-11-01, reason: "), `the placeholder: ${body}`);
  assert(!body.endsWith("reason: .") && body.endsWith("."), `the reason is named: ${body}`);
  assert(erased.footnote !== null && text(erased.footnote).startsWith("The entry stays so the order of events is kept."), "the note");
  for (const e of [erased, live]) {
    const all = bodyText(e) + (e.footnote === null ? "" : text(e.footnote));
    assert(!all.includes("ab".repeat(32)) && !/\b77\b/.test(all), `no reference shows: ${all}`);
  }
});

/**
 * R-JV-04, O-56, section 7.4: the submission entry is a receipt with its
 * ledger sequence and an "Anchor pending" badge, since no anchor is
 * witnessed yet. It never shows a placeholder value as an anchor. No
 * other entry is a pending receipt.
 */
test("r_jv_04_submission_receipt_shows_anchor_pending", () => {
  const d = diary([transition(7, "DRAFT", "SUBMITTED"), transition(9, "SUBMITTED", "STAGE1")]);
  const entries = activityLog(d, 1).entries;
  const pending = entries.filter((e) => e.anchorPending);
  eq(
    pending.map((e) => e.seq),
    ["7"],
    "only the submission is a pending receipt",
  );
  const r = pending[0];
  assert(r !== undefined, "the receipt");
  const all = [bodyText(r), r.footnote === null ? "" : text(r.footnote)].join(" ");
  assert(/\b7\b/.test(all), `the receipt names its ledger sequence: ${all}`);
  eq(text({ key: "journey.diary.anchor_pending", args: {} }), "Anchor pending", "the badge words");
  assert(!/anchor:\s*\S|0{16,}/i.test(all), `no placeholder anchor value: ${all}`);
});

/**
 * O-60, I-93: a guardian step the read gives (only the guardian's read
 * holds one) shows as the guardian's consent sentence, and the log adds
 * no guardian entry the read did not give.
 */
test("i93_o60_guardian_step_shows_only_when_the_read_gives_it", () => {
  const guardian = diary([wireEntry(60, "guardian_step", "journey.guardian.added"), transition(61, "NEGOTIATION", "GRANTED")]);
  const g = activityLog(guardian, 1).entries.find((e) => e.kind === "guardian_step");
  assert(g !== undefined, "the guardian sees the step");
  const body = bodyText(g);
  assert(body.startsWith("Your consent") && body.endsWith("was recorded."), `the guardian sentence: ${body}`);
  const applicant = diary([transition(61, "NEGOTIATION", "GRANTED")]);
  eq(
    activityLog(applicant, 1).entries.filter((e) => e.kind === "guardian_step").length,
    0,
    "no guardian step without the read",
  );
});

/** R-JV-12, ADR-006: an amount shows as the canonical decimal string the read gave, unchanged. */
test("r_jv_12_log_amounts_are_canonical_strings", () => {
  forAll(
    (r) => `${r.between(0, 999_999)}.${String(r.between(0, 99)).padStart(2, "0")}`,
    (amount) => {
      const [e] = activityLog(diary([wireEntry(70, "milestone_payment", "journey.milestone.closed", [{ amount }])]), 1).entries;
      assert(e !== undefined, "one entry");
      const body = bodyText(e);
      assert(body.includes(amount), `the body holds ${amount}: ${body}`);
      assert(!/\d[ ,']\d{3}/.test(body.replace(amount, "")), `no other spelling: ${body}`);
    },
  );
});

/** Design "Entry anatomy": each kind has a badge and a glyph from the catalogue, never empty. */
test("r_jv_03_every_entry_kind_has_a_badge_and_a_glyph", () => {
  const kinds: readonly (readonly [string, string])[] = [
    ["state_transition", "journey.state.transitioned"],
    ["deadline_set", "journey.deadline.set"],
    ["notice_sent", "journey.notice.outcome"],
    ["clarification", "journey.clarification.question"],
    ["clarification", "journey.clarification.answer"],
    ["reviewer_score", "journey.score.recorded"],
    ["vault_outcome", "journey.contract.effective"],
    ["contract", "journey.contract.effective"],
    ["milestone_payment", "journey.payment.released"],
    ["guardian_step", "journey.guardian.added"],
  ];
  const d = diary(
    kinds.map(([kind, key], i) =>
      kind === "state_transition"
        ? transition(100 + i, "STAGE1", "STAGE2")
        : wireEntry(100 + i, kind, key, kind === "milestone_payment" ? [{ amount: "10.00" }, { seq: "4" }] : []),
    ),
  );
  const entries = activityLog(d, 1).entries;
  eq(entries.length, kinds.length, "every entry");
  for (const e of entries) {
    assert(text(e.badge).trim() !== "", `${e.kind} has a badge`);
    assert(e.glyph !== "", `${e.kind} has a glyph`);
    assert(e.body.length > 0 && bodyText(e).trim() !== "", `${e.kind} has a body`);
  }
});

// ---------------------------------------------------------------------------
// Routes and links
// ---------------------------------------------------------------------------

/** R-JV-05, ADR-014: the progress map and the activity log have their own `/app/` routes. */
test("r_jv_05_progress_and_activity_routes", () => {
  const r = createRouter(JOURNEY_ROUTES);
  eq(r.match(JOURNEY_PATHS.progress("1001")), { name: "journey.progress", params: { proposal: "1001" } }, "progress");
  eq(r.match(JOURNEY_PATHS.activity("1001")), { name: "journey.activity", params: { proposal: "1001" } }, "activity");
  eq(r.match("/app/proposals/x1/progress"), null, "a bad id");
  eq(r.match("/app/proposals/1001"), null, "the proposal page is not a journey page");
});

/** R-JV-01, design "Purpose and audience": the home and proposal pages offer "Progress" and "Activity". */
test("r_jv_01_proposal_links_reach_progress_and_activity", () => {
  const links = journeyLinks("1001");
  eq(
    links.map((l) => l.href),
    [JOURNEY_PATHS.progress("1001"), JOURNEY_PATHS.activity("1001")],
    "both links",
  );
  eq(
    links.map((l) => text(l.label)),
    ["Progress", "Activity"],
    "their words",
  );
});

// ---------------------------------------------------------------------------
// Reduced motion
// ---------------------------------------------------------------------------

/** Every `.css` file below `dir`. */
function sheets(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      out.push(...sheets(p));
    } else if (name.endsWith(".css")) {
      out.push(p);
    }
  }
  return out;
}

/** The text of the first `{ ... }` block at or after `from`. */
function blockAt(css: string, from: number): string {
  const open = css.indexOf("{", from);
  let depth = 0;
  for (let i = open; i >= 0 && i < css.length; i += 1) {
    if (css[i] === "{") {
      depth += 1;
    } else if (css[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        return css.slice(open + 1, i);
      }
    }
  }
  return "";
}

/**
 * R-NF-03, `SPEC/12-journey-ui.md` section 6, design "Reduced motion":
 * the current ring pulses, and every sheet that animates a journey class
 * stops it under `prefers-reduced-motion: reduce`, where the ring turns
 * into a static dashed ring. No other journey class moves.
 */
test("r_nf_03_reduced_motion_stops_every_journey_animation", () => {
  const problems: string[] = [];
  let animated = 0;
  for (const f of sheets(join(WEB_DIR, "src"))) {
    const css = readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    const reduce: string[] = [];
    for (const m of css.matchAll(/@media\s*\(\s*prefers-reduced-motion\s*:\s*reduce\s*\)/g)) {
      reduce.push(blockAt(css, m.index ?? 0));
    }
    const outside = reduce.reduce((acc, b) => acc.replace(b, ""), css);
    for (const m of outside.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      const selector = (m[1] ?? "").trim();
      const body = m[2] ?? "";
      if (!/(^|[\s;])animation(-name)?\s*:/.test(body) || /animation(-name)?\s*:\s*none/.test(body)) {
        continue;
      }
      if (!/current-ring|journey|route|svg-|edge|strip|diary/.test(selector)) {
        continue;
      }
      if (selector !== ".current-ring") {
        problems.push(`${f}: ${selector} moves, but only the current ring may`);
      }
      animated += 1;
      const stopped = reduce.some((b) => {
        const rule = b.match(/\.current-ring\s*\{([^}]*)\}/);
        const universal = /\*[^{]*\{[^}]*animation\s*:\s*none/.test(b);
        return (rule !== null && /animation\s*:\s*none/.test(rule[1] ?? "")) || universal;
      });
      const dashed = reduce.some((b) => /\.current-ring\s*\{[^}]*stroke-dasharray/.test(b));
      if (!stopped || !dashed) {
        problems.push(`${f}: ${selector} is not stopped and dashed under reduced motion`);
      }
    }
  }
  assert(animated > 0, "a sheet below web/src animates the current ring (design: the ring pulses)");
  eq(problems, [], "reduced motion");
});

/**
 * R-JV-01, R-JV-05, J2-R5 (review finding J3-R4): a "grants only" reader
 * gets the legs of the grant alone. The stages every route to them passes
 * are completed in the list and the strip, never upcoming, and the legs
 * stay as the read gave them. RANKED stays upcoming, since a proposal can
 * reach IRC_REVIEW from STAGE2 through DEFERRED.
 */
test("r_jv_01_stages_behind_hidden_legs_are_completed", () => {
  const j = journey(
    journeyBody(
      [
        ["NEGOTIATION", "GRANTED"],
        ["GRANTED", "IN_EXECUTION"],
      ],
      "IN_EXECUTION",
      true,
    ),
  );
  const status = new Map(routeItems(j, "/app/proposals/1001/progress").map((i) => [i.state, i.status]));
  for (const s of ["DRAFT", "SUBMITTED", "STAGE1", "STAGE2", "IRC_REVIEW", "NEGOTIATION", "GRANTED"] as const) {
    eq(status.get(s), "completed", `${s} is passed`);
  }
  eq(status.get("RANKED"), "upcoming", "RANKED is not certainly passed");
  eq(status.get("IN_EXECUTION"), "current", "the position");
  const strip = stripOf(j);
  assert(strip !== null, "a strip");
  eq(strip.find((s) => s.state === "STAGE1")?.status, "done", "the strip agrees");
  eq(j.legs.length, 2, "the legs stay as the read gave them");
});

/**
 * R-JV-11, design 02 "Text erased" (review finding J3-R5): an erased
 * entry's list item carries `diary-entry--erased`, and the shipped tokens
 * set its body in italics through `.diary-entry--erased .diary-body`.
 */
test("r_jv_11_erased_entry_takes_the_erased_style", () => {
  const erasedOn = String(Date.UTC(2026, 10, 1) * 1000);
  const d = diary([
    wireEntry(60, "clarification", "journey.clarification.question", [], [{ erased_on: erasedOn, cause: 1 }]),
    wireEntry(61, "clarification", "journey.clarification.question", [], [{ text: "77", digest: "ab".repeat(32) }]),
  ]);
  const byseq = new Map(activityLog(d, 1).entries.map((e) => [e.seq, e]));
  const erased = byseq.get("60");
  const live = byseq.get("61");
  assert(erased !== undefined && live !== undefined, "both entries");
  eq(entryClass(erased).split(" ").includes("diary-entry--erased"), true, "the erased item");
  eq(entryClass(live).split(" ").includes("diary-entry--erased"), false, "the live item");
  const css = readFileSync(join(WEB_DIR, "src", "site", "tokens.css"), "utf8");
  const rule = /\.diary-entry--erased\s+\.diary-body\s*\{([^}]*)\}/.exec(css);
  assert(rule !== null && /font-style:\s*italic/.test(rule[1] ?? ""), "the tokens style the erased body");
});
