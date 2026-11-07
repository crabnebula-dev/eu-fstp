// The voyager pages: the progress map with its list and help panels,
// the activity log, and the "Proposal status" strip of the judging
// roles (`SPEC/12-journey-ui.md` sections 6 to 8;
// `docs/design/02-voyager-route-diary.md`; R-JV-01, R-JV-03 to R-JV-05,
// R-JV-11, R-JV-12, O-56 to O-60).
//
// Every visibility decision comes from the `proposal.journey` and
// `proposal.diary` reads (I-93). A refused read shows its refusal and
// nothing else, so a coordinator who has not declared sees no route
// (O-57), and a reply whose `strip` is false gives no strip (O-58). The
// kind filter of the log only narrows what the read already gave.
//
// Every element is built with `h`, and the map is the server's checked
// tree of `proposal.route_map`, built with `createElementNS` (`tree.ts`),
// so no string reaches an HTML parser (ADR-014).

import { createApi, type ApiClient, type ApiOutcome } from "../core/api.js";
import { h } from "../core/dom.js";
import { navigate } from "../core/router.js";
import { OPERATIONS } from "../gen/api.js";
import { frame, showFailure, run, type Frame } from "../applicant/ui.js";
import type { Failure } from "../applicant/client.js";
import {
  type Diary,
  type EntryKind,
  type Journey,
  type LogEntry,
  type Msg,
  type RouteMap,
  activityLog,
  entryClass,
  helpPanels,
  isoOf,
  label,
  readDiary,
  readJourney,
  readRouteMap,
  mapItems,
  stripOf,
} from "./model.js";
import { buildRouteTree } from "./svg.js";

/** The paths of the voyager pages of proposal `p`. */
export const JOURNEY_PAGE = Object.freeze({
  proposal: (p: string): string => `/app/proposals/${p}`,
  progress: (p: string): string => `/app/proposals/${p}/progress`,
  activity: (p: string): string => `/app/proposals/${p}/activity`,
});

let client: ApiClient | null = null;

function api(): ApiClient {
  client ??= createApi({ fetch: (input, init) => globalThis.fetch(input, init) });
  return client;
}

type Read<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: Failure };

function failureOf(o: ApiOutcome): Failure {
  switch (o.kind) {
    case "refused":
      return { kind: "refused", code: o.code, rule: o.rule };
    case "failed":
      return { kind: "failed", reason: o.reason };
    case "step_up_required":
    case "strong_method_required":
      return { kind: "step_up" };
    case "pending":
      return { kind: "pending" };
    default:
      return { kind: "failed", reason: "invalid_response" };
  }
}

/** Calls the read `name` of proposal `p` and decodes its reply. It never throws. */
async function read<T>(name: "proposal.journey" | "proposal.diary" | "proposal.route_map" | "me.assignments", params: Readonly<Record<string, string>>, decode: (v: unknown) => T | null): Promise<Read<T>> {
  const op = OPERATIONS.find((o) => o.name === name);
  if (op === undefined || op.base === "page") {
    return { ok: false, failure: { kind: "unavailable" } };
  }
  const box: { value: T | null } = { value: null };
  let o: ApiOutcome;
  try {
    o = await api().call(op, params, undefined, (v) => {
      box.value = decode(v);
      return box.value !== null;
    });
  } catch {
    return { ok: false, failure: { kind: "failed", reason: "network" } };
  }
  return o.kind === "done" && box.value !== null ? { ok: true, value: box.value } : { ok: false, failure: failureOf(o) };
}

function text(m: Msg): string {
  return label(m);
}

function k(key: string, args: Readonly<Record<string, string>> = {}): string {
  return label({ key, args });
}

/** The links between the proposal page and its voyager pages. */
function pageLinks(p: string, here: "progress" | "activity"): HTMLElement {
  const other =
    here === "progress"
      ? h("a", { href: JOURNEY_PAGE.activity(p) }, [k("journey.route.activity")])
      : h("a", { href: JOURNEY_PAGE.progress(p) }, [k("journey.route.title")]);
  return h("p", { class: "journey-links" }, [h("a", { href: JOURNEY_PAGE.proposal(p) }, [k("journey.route.back")]), " | ", other]);
}

// ---------------------------------------------------------------------------
// The progress map
// ---------------------------------------------------------------------------

/** The help panel elements, one per node; only `open` shows. */
function panels(j: Journey): HTMLElement[] {
  return helpPanels(j).map((p) =>
    h(
      "section",
      {
        id: p.id,
        class: "help-panel",
        tabindex: "-1",
        "aria-labelledby": `${p.id}-heading`,
        hidden: !p.open,
      },
      [
        h("h3", { id: `${p.id}-heading` }, [text(p.heading)]),
        h("h4", {}, [k("journey.help.what")]),
        h("p", {}, [text(p.what)]),
        h("h4", {}, [k("journey.help.who")]),
        h("p", {}, [text(p.who)]),
        h("h4", {}, [k("journey.help.deadline")]),
        h("p", {}, [text(p.deadline)]),
        h("h4", {}, [k("journey.help.can")]),
        h("p", {}, [text(p.can)]),
        h("h4", {}, [k("journey.help.cannot")]),
        h("p", {}, [text(p.cannot)]),
      ],
    ),
  );
}

/** Shows the panel `id` and hides the others. False when no panel has that id. */
function openPanel(all: readonly HTMLElement[], id: string): boolean {
  const target = all.find((p) => p.id === id);
  if (target === undefined) {
    return false;
  }
  for (const p of all) {
    p.hidden = p !== target;
  }
  return true;
}

/** The node id a link names on this page, such as `node-STAGE2`, or null. */
function nodeTarget(a: Element, page: string): string | null {
  const href = a.getAttribute("href") ?? "";
  const at = href.indexOf("#");
  if (at < 0 || (at > 0 && href.slice(0, at) !== page)) {
    return null;
  }
  const id = href.slice(at + 1);
  return /^node-[A-Z0-9_]+$/.test(id) ? id : null;
}

function progressBody(f: Frame, j: Journey, m: RouteMap, page: string): void {
  // The server's checked tree and node statuses: the page lays out
  // nothing of its own (ADR-015 amendment of 2026-11-06, R-JV-05).
  const map = buildRouteTree(m.tree);
  const list = h(
    "ol",
    { class: "journey-list" },
    mapItems(m, page).map((i) => {
      const cls = {
        completed: "journey-node--complete",
        current: "journey-node--current",
        upcoming: "journey-node--upcoming",
        pause: "journey-node--upcoming",
        positive_end: "journey-node--terminal-positive",
        negative_end: "journey-node--terminal-negative",
      }[i.status];
      const attrs: Record<string, string> = { class: `journey-node ${cls}` };
      if (i.status === "current") {
        attrs["aria-current"] = "step";
      }
      return h("li", attrs, [
        h("a", { href: i.href }, [text(i.label), " ", h("span", { class: "state-name" }, [`(${i.state})`])]),
        h("span", {}, [": ", text(i.statusWords)]),
      ]);
    }),
  );
  const all = panels(j);
  // The read says whether the caller sees the withdrawal: the lead, in a
  // state NOTE 10 leaves open (registry LEAD on `proposal.withdraw`).
  const withdraw = j.withdraw
    ? [
        h("section", { id: "journey-withdraw", "aria-labelledby": "journey-withdraw-heading" }, [
          h("h2", { id: "journey-withdraw-heading" }, [k("journey.withdraw.title")]),
          h("p", {}, [k("journey.withdraw.body")]),
          h("p", {}, [h("a", { class: "btn btn--danger", href: JOURNEY_PAGE.proposal(j.proposal) }, [k("journey.withdraw.action")])]),
        ]),
      ]
    : [];
  const body = h("div", { class: "journey-page" }, [
    h("section", { id: "journey-map", "aria-labelledby": "journey-map-heading" }, [
      h("h2", { id: "journey-map-heading" }, [k("journey.route.map_heading")]),
      h("p", {}, [k("journey.route.map_hint")]),
      h("div", { class: "route-frame" }, [map]),
    ]),
    h("section", { id: "journey-list", "aria-labelledby": "journey-list-heading" }, [
      h("h2", { id: "journey-list-heading" }, [k("journey.route.list_title")]),
      list,
    ]),
    h("section", { id: "journey-help", "aria-labelledby": "journey-help-heading" }, [
      h("h2", { id: "journey-help-heading" }, [k("journey.route.help_title")]),
      ...all,
    ]),
    ...withdraw,
  ]);
  // A node or list link opens its help panel in place, with no reload and
  // no history entry, and moves focus to it (design "Help panel per
  // node"). Without a target the current node's panel shows.
  body.addEventListener("click", (e) => {
    const t = e.target;
    const a = t instanceof Element ? t.closest("a") : null;
    if (a === null || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return;
    }
    const id = nodeTarget(a, page);
    if (id === null || !openPanel(all, id)) {
      return;
    }
    e.preventDefault();
    const panel = all.find((p) => p.id === id);
    panel?.focus();
    panel?.scrollIntoView({ block: "start" });
  });
  const wanted = location.hash.startsWith("#node-") ? location.hash.slice(1) : "";
  if (wanted !== "") {
    openPanel(all, wanted);
  }
  f.main.append(body);
}

/** Mounts the progress map of proposal `p`. */
export function mountProgress(p: string): void {
  const f = frame(label({ key: "journey.route.title", args: {} }));
  f.main.append(
    h("p", { class: "voyage-label" }, [k("journey.route.subtitle")]),
    h("p", { class: "state-name" }, [k("journey.route.proposal", { proposal: p })]),
    pageLinks(p, "progress"),
  );
  run(f, async () => {
    const r = await read("proposal.journey", { proposal: p }, readJourney);
    if (!r.ok) {
      showFailure(f, r.failure);
      f.main.append(h("p", {}, [k("journey.route.unavailable")]));
      return;
    }
    // The full map, its list and its help panels are the team's (section
    // 8.1, review J3-R2). The read says so in `map`: the cell decides,
    // never this page. Judging roles keep the strip (section 8.3), and IRC
    // members get neither (O-58).
    if (!r.value.map) {
      const strip = stripElement(r.value);
      f.main.append(...(strip === null ? [] : [strip]), h("p", {}, [k("journey.route.unavailable")]));
      return;
    }
    const page = JOURNEY_PAGE.progress(p);
    const m = await read("proposal.route_map", { proposal: p }, (v) => readRouteMap(v, page));
    if (!m.ok) {
      showFailure(f, m.failure);
      f.main.append(h("p", {}, [k("journey.route.unavailable")]));
      return;
    }
    progressBody(f, r.value, m.value, page);
  });
}

// ---------------------------------------------------------------------------
// The activity log
// ---------------------------------------------------------------------------

const KINDS: readonly EntryKind[] = [
  "state_transition",
  "deadline_set",
  "notice_sent",
  "clarification",
  "reviewer_score",
  "conflict",
  "vault_outcome",
  "contract",
  "milestone_payment",
  "complaint",
  "agent_action",
  "guardian_step",
];

function isKind(v: string): v is EntryKind {
  return (KINDS as readonly string[]).includes(v);
}

/** The display time of microseconds since the epoch: `YYYY-MM-DD HH:MM UTC`. */
function shown(micros: string): string {
  const iso = isoOf(micros);
  return iso === null ? micros : `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

function entryEl(e: LogEntry): HTMLElement {
  const iso = isoOf(e.at);
  const time = iso === null ? h("span", {}, [e.at]) : h("time", { datetime: iso }, [shown(e.at)]);
  const kids: HTMLElement[] = [
    h("p", { class: "diary-meta" }, [h("span", { class: "badge badge--info" }, [text(e.badge)]), " ", time]),
    h("p", { class: "diary-body" }, [e.body.map(text).join(" ")]),
  ];
  if (e.anchorPending) {
    kids.push(
      h("p", {}, [
        h("span", { class: "badge badge--warning" }, [h("span", { "aria-hidden": "true" }, ["… "]), k("journey.diary.anchor_pending")]),
      ]),
    );
  }
  if (e.footnote !== null) {
    kids.push(h("p", { class: "diary-note" }, [text(e.footnote)]));
  }
  return h("li", { class: entryClass(e), id: `entry-${e.seq}` }, [
    h("span", { class: "diary-icon", "aria-hidden": "true" }, [e.glyph]),
    h("div", {}, kids),
  ]);
}

function filterForm(p: string, kinds: readonly EntryKind[], chosen: EntryKind | null): HTMLElement {
  const select = h(
    "select",
    { id: "diary-kind", name: "kind" },
    [
      h("option", chosen === null ? { value: "", selected: true } : { value: "" }, [k("journey.diary.filter_all")]),
      ...kinds.map((x) => h("option", x === chosen ? { value: x, selected: true } : { value: x }, [k(`journey.diary.kind.${x}`)])),
    ],
  );
  const form = h("form", { class: "diary-filter", method: "get", action: JOURNEY_PAGE.activity(p) }, [
    h("label", { for: "diary-kind" }, [k("journey.diary.filter")]),
    " ",
    select,
    " ",
    h("button", { type: "submit", class: "btn" }, [k("journey.diary.filter_apply")]),
  ]);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const v = (select as HTMLSelectElement).value;
    navigate(v === "" ? JOURNEY_PAGE.activity(p) : `${JOURNEY_PAGE.activity(p)}?kind=${encodeURIComponent(v)}`);
  });
  return form;
}

function logBody(f: Frame, d: Diary, p: string): void {
  const q = new URLSearchParams(location.search);
  const kindParam = q.get("kind") ?? "";
  const chosen = isKind(kindParam) ? kindParam : null;
  const pageParam = Number(q.get("page") ?? "1");
  const present = KINDS.filter((x) => d.entries.some((e) => e.kind === x));
  const shownDiary: Diary = chosen === null ? d : { proposal: d.proposal, entries: d.entries.filter((e) => e.kind === chosen) };
  const log = activityLog(shownDiary, Number.isSafeInteger(pageParam) ? pageParam : 1);
  f.main.append(filterForm(p, present, chosen));
  if (log.entries.length === 0) {
    f.main.append(h("p", {}, [k("journey.diary.empty")]));
    return;
  }
  f.main.append(h("ol", { class: "diary" }, log.entries.map(entryEl)));
  if (log.pages > 1) {
    const href = (n: number): string => {
      const s = new URLSearchParams();
      if (chosen !== null) {
        s.set("kind", chosen);
      }
      s.set("page", String(n));
      return `${JOURNEY_PAGE.activity(p)}?${s.toString()}`;
    };
    const items: HTMLElement[] = [];
    if (log.page > 1) {
      items.push(h("li", {}, [h("a", { href: href(log.page - 1) }, [k("journey.diary.newer")])]));
    }
    for (let n = 1; n <= log.pages; n += 1) {
      items.push(h("li", {}, [h("a", n === log.page ? { href: href(n), "aria-current": "page" } : { href: href(n) }, [String(n)])]));
    }
    if (log.page < log.pages) {
      items.push(h("li", {}, [h("a", { href: href(log.page + 1) }, [k("journey.diary.older")])]));
    }
    f.main.append(
      h("nav", { "aria-label": k("journey.diary.pagination") }, [
        h("p", {}, [k("journey.diary.page", { page: String(log.page), pages: String(log.pages) })]),
        h("ul", { class: "pagination" }, items),
      ]),
    );
  }
}

/** Mounts the activity log of proposal `p`. */
export function mountActivity(p: string): void {
  const f = frame(label({ key: "journey.diary.title", args: {} }));
  f.main.append(
    h("p", {}, [k("journey.diary.subtitle")]),
    h("p", { class: "state-name" }, [k("journey.route.proposal", { proposal: p })]),
    pageLinks(p, "activity"),
  );
  run(f, async () => {
    const r = await read("proposal.diary", { proposal: p }, readDiary);
    if (!r.ok) {
      showFailure(f, r.failure);
      f.main.append(h("p", {}, [k("journey.diary.unavailable")]));
      return;
    }
    logBody(f, r.value, p);
  });
}

// ---------------------------------------------------------------------------
// The "Proposal status" strip of the judging roles (section 8.3)
// ---------------------------------------------------------------------------

/** The strip element of `j`, or null when the read gives none (O-58). */
export function stripElement(j: Journey): HTMLElement | null {
  const items = stripOf(j);
  if (items === null) {
    return null;
  }
  return h("section", { id: "journey-strip", class: "journey-strip", "aria-labelledby": "journey-strip-heading" }, [
    h("h2", { id: "journey-strip-heading" }, [k("journey.strip.title")]),
    h(
      "ol",
      { class: "strip" },
      items.map((i) => {
        const attrs: Record<string, string> = { class: `is-${i.status}` };
        if (i.status === "current") {
          attrs["aria-current"] = "step";
        }
        return h("li", attrs, [
          k("journey.strip.item", { label: text(i.label), state: i.state }),
          h("span", { class: "sr-only" }, [`, ${k(`journey.strip.${i.status}`)}`]),
        ]);
      }),
    ),
  ]);
}

/** The proposal a judging page of `path` is about, or null for a page with none. */
async function proposalOf(path: string): Promise<string | null> {
  const reviewer = /^\/app\/assignments\/([0-9]{1,20})(?:\/summary|\/stage2)?$/.exec(path);
  if (reviewer === null) {
    return null;
  }
  const id = reviewer[1] ?? "";
  const r = await read("me.assignments", {}, (v) =>
    Array.isArray(v) ? (v as readonly unknown[]) : null,
  );
  if (!r.ok) {
    return null;
  }
  for (const a of r.value) {
    if (typeof a !== "object" || a === null) {
      continue;
    }
    const row = a as Readonly<Record<string, unknown>>;
    // An assignment still awaiting its declaration, or no longer active,
    // reads no route (R-CF-02): the journey read refuses it, so the page
    // asks for none. Review J3-R3 was refuted by the skeptic on this
    // ground, and the site crawl caught the refused reads it caused.
    if (
      row["assignment"] === id &&
      row["kind"] === "reviewer" &&
      row["active"] === true &&
      row["awaiting_declaration"] === false
    ) {
      const p = row["proposal"];
      return typeof p === "string" ? p : null;
    }
  }
  return null;
}

/**
 * Adds the "Proposal status" strip below the heading of the judging page
 * of `path` that the shell has just mounted: a reviewer's assignment
 * pages. The design gives the strip to
 * reviewers and committee members only (`docs/design/04-reviewer-committee-irc.md`
 * "Proposal status" strip), so coordinator and IRC pages get none (O-57,
 * O-58). The strip shows only when `proposal.journey` admits the caller
 * and gives `strip` (section 8.3); a refusal adds nothing.
 */
export async function addJudgingStrip(path: string): Promise<void> {
  const p = await proposalOf(path);
  if (p === null) {
    return;
  }
  const r = await read("proposal.journey", { proposal: p }, readJourney);
  if (!r.ok || location.pathname !== path) {
    return;
  }
  const strip = stripElement(r.value);
  const main = document.querySelector("main");
  const heading = main?.querySelector("h1") ?? null;
  if (strip === null || main === null || heading === null) {
    return;
  }
  document.getElementById("journey-strip")?.remove();
  heading.after(strip);
}
