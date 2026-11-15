// The DOM builders of the set-up wizard and the set-up progress page
// (`docs/design/11-programme-setup-wizard.md` sections 2, 6, 8 and 11).
//
// - The stage bar is a `nav` named "Set-up stages" with an ordered list.
//   The current item has `aria-current="step"`. Each item carries a
//   hidden status word. Done stages link back. Upcoming stages are not
//   links.
// - The summary panel is an `aside` named "Your set-up so far", so a
//   screen reader can jump to it.
// - The live checks are a polite live region. Each badge has a glyph and
//   a word, so colour is never the only signal.
// - Every value of a reply is shown as text, never as markup.

import { h, safeUrl } from "../core/dom.js";
import { VISUALLY_HIDDEN_CLASS } from "../core/a11y.js";
import type { Label } from "../core/i18n.js";
import { fieldLabel } from "../creator/editor.js";
import { draftValue, type Draft } from "../creator/model.js";
import { roleLabel } from "../people/i18n.js";
import type { InvitationRow } from "../people/model.js";
import { t } from "./i18n.js";
import {
  STAGES,
  SETUP_PATHS,
  doneCount,
  endDate,
  startDate,
  statusRow,
  teamByGroup,
  teamStatus,
  type Milestone,
  type SodLine,
  type StageId,
  type StageState,
  type StatusCell,
} from "./model.js";

/** A same-origin link with visible text. */
export function link(path: string, text: Label, attrs: Readonly<Record<string, string>> = {}): HTMLElement {
  const href = safeUrl(path);
  return href === null ? h("span", attrs, [text]) : h("a", { ...attrs, href }, [text]);
}

/** Text only a screen reader reads. */
function hidden(text: string): HTMLElement {
  return h("span", { class: VISUALLY_HIDDEN_CLASS }, [text]);
}

/** The name of stage `id`. */
export function stageName(id: StageId): Label {
  return t.label(`setup.stage.${id}`);
}

/** "2. Programme". */
export function numberedName(id: StageId): Label {
  const s = STAGES.find((x) => x.id === id);
  return t.label("setup.stage.numbered", { n: String(s?.number ?? 0), name: stageName(id) });
}

/** The path of stage `id` of programme `p`, or null for the start, which a draft never returns to. */
function stagePath(p: string | null, id: StageId): string | null {
  return p === null || id === "start" ? null : SETUP_PATHS.stage(p, id);
}

/**
 * The stage bar `nav#setup-stages`: one `li[data-stage]` per stage with
 * its condition. Done stages other than the current one link back.
 */
export function stageBar(p: string | null, states: readonly StageState[], current: StageId): HTMLElement {
  const items = states.map((s) => {
    const isCurrent = s.id === current;
    const cls = isCurrent ? "is-current" : s.condition === "done" ? "is-done" : "is-upcoming";
    const mark = s.condition === "done" && !isCurrent ? "✓" : isCurrent ? String(s.number) : "○";
    const word = isCurrent ? t.label("setup.stage.current") : s.condition === "done" ? t.label("setup.stage.done") : t.label("setup.stage.upcoming");
    const inner = [h("span", { class: "stage-mark", "aria-hidden": "true" }, [mark]), h("span", { class: "stage-name" }, [numberedName(s.id)]), hidden(word)];
    const path = stagePath(p, s.id);
    const body =
      s.condition === "done" && !isCurrent && path !== null && safeUrl(path) !== null
        ? h("a", { href: path }, inner)
        : h("span", { class: "stage-static" }, inner);
    const attrs: Record<string, string> = { class: cls, "data-stage": s.id, "data-condition": s.condition };
    if (isCurrent) attrs["aria-current"] = "step";
    return h("li", attrs, [body]);
  });
  return h("nav", { id: "setup-stages", "aria-label": t.label("setup.stages.nav") }, [h("ol", { class: "stage-bar" }, items)]);
}

/** "Stage 4 of 7. Creator steps 5 to 8 of 11". */
export function stageKicker(id: StageId): Label {
  const s = STAGES.find((x) => x.id === id);
  const n = String(s?.number ?? 0);
  if (s === undefined || s.steps.length === 0) {
    return t.label("setup.stage.kicker", { n, what: t.label("setup.stage.kicker.start") });
  }
  const numbers = s.steps.map((x) => STEP_NUMBERS[x] ?? 0);
  const from = Math.min(...numbers);
  const to = Math.max(...numbers);
  const what = from === to ? t.label("setup.stage.kicker.step", { n: String(from) }) : t.label("setup.stage.kicker.steps", { from: String(from), to: String(to) });
  return t.label("setup.stage.kicker", { n, what });
}

const STEP_NUMBERS: Readonly<Record<string, number>> = {
  funder: 1,
  identity: 2,
  eligibility: 3,
  funding: 4,
  evaluation: 5,
  money: 6,
  contract: 7,
  support: 8,
  people: 9,
  comms: 10,
  review: 11,
};

/** A short text of a draft value for the summary panel. */
export function shortValue(v: unknown): Label {
  if (v === null || v === undefined) return t.label("setup.summary.value.unset");
  if (typeof v === "string") return (v.length > 60 ? `${v.slice(0, 57)}...` : v) as Label;
  if (typeof v === "number") return String(v) as Label;
  if (typeof v === "boolean") return v ? t.label("setup.summary.value.yes") : t.label("setup.summary.value.no");
  if (Array.isArray(v)) return t.label("setup.summary.value.list", { n: String(v.length) });
  return t.label("setup.summary.value.set");
}

/** The draft fields each stage's summary names. */
const SUMMARY_FIELDS: Readonly<Record<string, readonly string[]>> = {
  programme: ["identity.name", "funder.action_number", "identity.p25_language"],
  applicants: ["eligibility.persons_supported", "eligibility.minors", "funding.p55_activity_types"],
  evaluation: ["evaluation.p01_criteria", "evaluation.p03_reviewers", "money.p05_recipient_cap", "contract.p29_instrument"],
  communications: ["comms.p31_reminder_offsets", "comms.contact"],
};

/** What the summary panel reads. */
export interface SummaryFacts {
  readonly programme: string | null;
  readonly draft: Draft | null;
  readonly team: readonly InvitationRow[] | null;
}

/** The summary panel `aside#setup-summary`, "Your set-up so far". */
export function summaryPanel(states: readonly StageState[], facts: SummaryFacts, current: StageId): HTMLElement {
  const p = facts.programme;
  const sections = states.map((s) => {
    const mark = s.condition === "done" ? "✓" : s.id === current ? "●" : "○";
    const path = stagePath(p, s.id);
    const change =
      s.condition === "done" && path !== null && s.id !== current
        ? [link(path, t.label("setup.summary.change"), { "aria-label": t.label("setup.summary.change_named", { stage: stageName(s.id) }) })]
        : [];
    const head = h("h3", { id: `sum-${s.id}` }, [
      h("span", {}, [h("span", { class: "sum-mark", "aria-hidden": "true" }, [mark]), stageName(s.id)]),
      ...change,
    ]);
    return h("section", { "aria-labelledby": `sum-${s.id}`, "data-summary": s.id }, [head, summaryBody(s, facts)]);
  });
  return h("aside", { id: "setup-summary", class: "summary card", "aria-labelledby": "setup-summary-title" }, [
    h("h2", { id: "setup-summary-title" }, [t.label("setup.summary.title")]),
    h("p", { class: "text-sm" }, [t.label("setup.summary.count", { done: String(doneCount(states)) })]),
    ...sections,
  ]);
}

/** The key values of one stage, or "Not yet set". */
export function summaryBody(s: StageState, facts: SummaryFacts): HTMLElement {
  const rows = summaryRows(s, facts);
  return rows.length === 0
    ? h("p", { class: "not-set" }, [t.label("setup.summary.not_set")])
    : h("dl", {}, rows.flatMap(([k, v]) => [h("dt", {}, [k]), h("dd", {}, [v])]));
}

/** The label and value pairs of one stage in the summary. */
function summaryRows(s: StageState, f: SummaryFacts): [Label, string][] {
  const d = f.draft;
  if (s.id === "start") {
    if (f.programme === null) return [];
    const pms = (f.team ?? []).filter((r) => r.role === "programme_manager").map((r) => r.email);
    return [
      [t.label("setup.summary.programme"), t.label("setup.summary.programme_value", { programme: f.programme })],
      [t.label("setup.summary.profile"), t.label("setup.summary.profile_value")],
      [t.label("setup.summary.managers"), pms.length === 0 ? t.label("setup.summary.managers_none") : pms.join(", ")],
    ];
  }
  if (d === null) return [];
  if (s.id === "team") {
    const team = f.team ?? [];
    if (team.length === 0) return [];
    const granted = team.filter((r) => r.state === "granted").length;
    return [[t.label("setup.summary.people"), t.label("setup.summary.people_value", { people: String(team.length), granted: String(granted) })]];
  }
  if (s.id === "review") {
    const v = d.status === "active" ? "active" : d.activationRequested ? "requested" : "draft";
    return [[t.label("setup.summary.activation"), t.label(`setup.summary.activation.${v}`)]];
  }
  if (s.condition !== "done") return [];
  return (SUMMARY_FIELDS[s.id] ?? []).map((k) => [fieldLabel(k), shortValue(draftValue(d, k))]);
}

/** The wizard layout: the stage section beside the summary panel. */
export function wizardLayout(stage: HTMLElement, summary: HTMLElement): HTMLElement {
  return h("div", { class: "wizard" }, [stage, summary]);
}

/** The I-67 notice on who approves activation. */
export function approverNotice(): HTMLElement {
  return h("p", { id: "setup-approver", class: "callout callout--info" }, [
    h("strong", {}, [t.label("setup.approver.title")]),
    " ",
    t.label("setup.approver.body"),
  ]);
}

/**
 * The place where the tenant admin override of I-67 will go. Lane
 * m4/i67-override adds the form: a tenant admin overrides the builder
 * rule, with a reason and a ledger record. This lane builds no part of
 * it, so the slot stays empty and hidden.
 */
export function approverOverrideSlot(): HTMLElement {
  return h("section", { id: "setup-approver-override", "data-slot": "i67-override", hidden: true });
}

// ---------------------------------------------------------------------------
// The team
// ---------------------------------------------------------------------------

/** A `YYYY-MM-DD` date as the pages show it, such as "3 Nov 2026", in UTC. */
export function shownDate(date: string): string {
  const d = new Date(`${date}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? date : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

/** The dates of a team row. */
export function datesText(row: InvitationRow): Label {
  const s = startDate(row.start);
  const e = endDate(row.end);
  const start = s === null ? null : shownDate(s);
  const end = e === null ? null : shownDate(e);
  if (start === null) return t.label("setup.dates.unknown");
  return end === null ? t.label("setup.dates.from", { start }) : t.label("setup.dates.range", { start, end });
}

/** A badge with its word, and a glyph for state. */
export function badge(kind: "success" | "warning" | "error" | "info" | "neutral", text: string, glyph: string | null = null): HTMLElement {
  const attrs: Record<string, string> = { class: `badge badge--${kind}` };
  if (glyph !== null) attrs["data-glyph"] = glyph;
  return h("span", attrs, [text]);
}

/** The status badge of a team row. */
export function statusBadge(row: InvitationRow): HTMLElement {
  const s = teamStatus(row);
  const text = t.label(`setup.status.${s}`);
  switch (s) {
    case "granted":
      return badge("success", text);
    case "verified":
      return badge("info", text, "✓");
    case "accepted":
      return badge("info", text, "●");
    default:
      return badge("neutral", text, "○");
  }
}

/** The check badge of a team row: the server's live check (D3). A refusal names the rule only (R-CF-03). */
export function checkBadge(row: InvitationRow): HTMLElement {
  if (row.sod === "pass") return badge("success", t.label("setup.check.pass"));
  if (row.sod === "fail") return badge("error", row.rule === null ? t.label("setup.check.fail") : t.label("setup.check.fail_rule", { rule: row.rule }));
  return badge("warning", t.label("setup.check.unchecked"));
}

/** The team tables `#setup-team-tables`, one per role group. */
export function teamTables(rows: readonly InvitationRow[]): HTMLElement {
  const tables = teamByGroup(rows).map((g) => {
    const name = t.label(`setup.team.group.${g.group}`);
    const head = h("thead", {}, [
      h("tr", {}, ["person", "role", "dates", "status", "checks"].map((c) => h("th", { scope: "col" }, [t.label(`setup.team.col.${c}`)]))),
    ]);
    const body =
      g.rows.length === 0
        ? [h("tr", {}, [h("td", { colspan: "5" }, [t.label("setup.team.empty")])])]
        : g.rows.map((r) =>
            h("tr", { "data-invitation": r.id, "data-role": r.role, "data-status": teamStatus(r) }, [
              h("td", { class: "pid" }, [r.email]),
              h("td", {}, [roleLabel(r.role)]),
              h("td", { class: "dates" }, [datesText(r)]),
              h("td", {}, [statusBadge(r)]),
              h("td", {}, [checkBadge(r)]),
            ]),
          );
    return h("table", { class: "team-table", "data-group": g.group }, [
      h("caption", {}, [t.label("setup.team.caption", { group: name, n: String(g.rows.length) })]),
      head,
      h("tbody", {}, body),
    ]);
  });
  return h("div", { id: "setup-team-tables" }, tables.map((x) => h("div", { class: "table-wrap" }, [x])));
}

/** The badge kind of a separation of duties line. */
function sodKind(b: SodLine["badge"]): "success" | "neutral" | "warning" | "error" {
  return b === "passed" ? "success" : b === "refused" ? "error" : b === "waiting" ? "warning" : "neutral";
}

/** The items of the live checks list. */
export function sodItems(lines: readonly SodLine[]): HTMLElement[] {
  return lines.map((l) =>
    h("li", { "data-rule": l.rule, "data-badge": l.badge }, [
      badge(sodKind(l.badge), t.label(`setup.sod.badge.${l.badge}`)),
      " ",
      h("span", {}, [
        h("strong", {}, [l.rule]),
        " ",
        l.blocking === null ? t.label(l.text) : t.label(l.text, { role: roleLabel(l.blocking) }),
      ]),
    ]),
  );
}

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

/** The compact strip of the nine milestones. */
export function milestoneStrip(ms: readonly Milestone[]): HTMLElement {
  return h(
    "ol",
    { id: "setup-strip", class: "strip", "aria-label": t.label("setup.progress.strip") },
    ms.map((m) => {
      const attrs: Record<string, string> = {
        class: m.condition === "done" ? "is-done" : m.condition === "current" ? "is-current" : "is-next",
        "data-milestone": m.id,
        "data-condition": m.condition,
      };
      if (m.condition === "current") attrs["aria-current"] = "step";
      return h("li", attrs, [t.label(`setup.milestone.short.${m.id}`)]);
    }),
  );
}

/** The journey list of the nine milestones, each with its next action and who acts. */
export function milestoneList(ms: readonly Milestone[]): HTMLElement {
  return h(
    "ol",
    { id: "setup-milestones", class: "journey-list milestones" },
    ms.map((m) => {
      const node = m.condition === "done" ? "complete" : m.condition === "current" ? "current" : "upcoming";
      const b =
        m.condition === "done"
          ? badge("success", t.label("setup.progress.badge.done"))
          : m.condition === "current"
            ? badge("info", t.label("setup.progress.badge.current"), "●")
            : badge("neutral", t.label("setup.progress.badge.upcoming"), "○");
      const next = m.condition === "done" ? t.label("setup.milestone.next.none") : t.label(`setup.milestone.next.${m.id}`);
      const attrs: Record<string, string> = { class: `journey-node journey-node--${node}`, "data-milestone": m.id, "data-condition": m.condition };
      if (m.condition === "current") attrs["aria-current"] = "step";
      return h("li", attrs, [
        h("div", {}, [
          h("h3", {}, [`${m.number}. `, t.label(`setup.milestone.${m.id}`), " ", b]),
          h("p", {}, [t.label("setup.progress.next", { action: next })]),
          h("p", { class: "text-sm" }, [t.label("setup.progress.who", { who: t.label(`setup.milestone.who.${m.id}`) })]),
        ]),
      ]);
    }),
  );
}

/** One status cell: a glyph for sighted readers and the word for everyone. */
function cell(c: StatusCell): HTMLElement {
  const glyph = c === "done" ? "✓" : c === "waiting" ? "○" : "·";
  return h("td", { "data-cell": c }, [h("span", { "aria-hidden": "true" }, [glyph]), " ", t.label(`setup.progress.cell.${c}`)]);
}

/** The team status table `#setup-team-status`, grouped by Drafting, Judging and Operations. */
export function statusTable(rows: readonly InvitationRow[], active: boolean): HTMLElement {
  const cols = ["person", "role"].map((c) => t.label(`setup.team.col.${c}`));
  const more = ["invited", "accepted", "verified", "granted", "next"].map((c) => t.label(`setup.progress.col.${c}`));
  const body: HTMLElement[] = [];
  for (const g of teamByGroup(rows)) {
    if (g.rows.length === 0) continue;
    body.push(h("tr", { class: "group-row" }, [h("th", { scope: "colgroup", colspan: "7" }, [t.label(`setup.team.group.${g.group}`)])]));
    for (const r of g.rows) {
      const s = statusRow(r, active);
      body.push(
        h("tr", { "data-invitation": r.id, "data-role": r.role }, [
          h("td", { class: "pid" }, [r.email]),
          h("td", {}, [roleLabel(r.role)]),
          cell(s.invited),
          cell(s.accepted),
          cell(s.verified),
          cell(s.granted),
          h("td", {}, [t.label(s.next)]),
        ]),
      );
    }
  }
  return h("div", { class: "table-wrap" }, [
    h("table", { id: "setup-team-status", class: "status-table" }, [
      h("caption", {}, [t.label("setup.progress.team_caption", { n: String(rows.length) })]),
      h("thead", {}, [h("tr", {}, [...cols, ...more].map((c) => h("th", { scope: "col" }, [c])))]),
      h("tbody", {}, body),
    ]),
  ]);
}
