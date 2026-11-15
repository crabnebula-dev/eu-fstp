// The audit log page `/app/programmes/{programme}/audit` (R-AU-01, I-24,
// ADR-007, ADR-022, ADR-023), built from the approved prototype
// `design/prototypes/audit-log.html`: an event type filter, then one
// table of entries, newest first, with time, event type, actor role,
// object and hash.
//
// - The auditor of the programme, every tenant admin and the FSTP
//   coordinator of the programme read its ledger entries
//   (`audit.entries`) and the vault answers its decisions used
//   (`audit.vault_outcomes`), read-only (SA-08, Daniel 2026-11-15).
// - The auditor and the tenant admins read the unmask records
//   (`audit.unmasks`, ADR-023 reading 11). The page asks for them only
//   when the caller's roles may read them (`readsUnmasks`), so the
//   coordinator gets no refused read. A reader the cell refuses the
//   entries sees a note saying whose they are.
// - ADR-007: a text appears by its id only. Every server value is shown
//   as text through `h`, so no string reaches an HTML parser (ADR-014).

import { h, type Child } from "../core/dom.js";
import type { I18n, Label } from "../core/i18n.js";
import {
  frame,
  guarded,
  idRoute,
  pageI18n,
  readOp,
  selectEl,
  type Answer,
  type Frame,
  type JudgingPage,
  type PageEnv,
} from "../reviewer/kit.js";
import { myRoles } from "../home/session.js";
import { AUDIT_LABELS } from "./messages.en.js";
import {
  KIND_LABELS,
  filterRows,
  isAuditLog,
  isOutcomes,
  isUnmasks,
  kindsOf,
  readsUnmasks,
  shortHash,
  utcMinute,
  type AuditLog,
  type AuditRow,
  type Outcomes,
  type Unmasks,
} from "./model.js";

/** The unmask records of a caller whose roles may not read them: never asked for. */
const NOT_ASKED: Answer<Unmasks> = Object.freeze({
  ok: false,
  problem: Object.freeze({ kind: "refused", code: "not_asked", rule: null }),
});

/** The label of `id` when the catalogue holds it, else `fallback` as plain text. */
function labelOr(t: I18n, id: string, fallback: string, args?: Readonly<Record<string, string>>): string {
  return Object.prototype.hasOwnProperty.call(AUDIT_LABELS, id) ? t.label(id, args) : fallback;
}

function time(t: I18n, micros: string): string {
  return utcMinute(micros) ?? t.label("audit.time_unknown");
}

/** The words of a record kind, or its record name. */
export function kindText(t: I18n, kind: string): string {
  const id = KIND_LABELS[kind];
  return id === undefined ? kind : labelOr(t, id, kind);
}

function roleText(t: I18n, role: string): string {
  return labelOr(t, `audit.role.${role}`, role);
}

function actorCell(t: I18n, r: AuditRow): string {
  const role = roleText(t, r.actor_role);
  return r.actor === null ? role : t.label("audit.actor", { role, account: r.actor });
}

function objectCell(t: I18n, r: AuditRow): string {
  return r.object_type === null || r.object === null ? "" : t.label("audit.object", { type: r.object_type, id: r.object });
}

function textsCell(t: I18n, r: AuditRow): string {
  return r.texts.length === 0 ? t.label("audit.no_texts") : r.texts.map((id) => t.label("audit.text_ref", { id })).join(", ");
}

function th(text: Label): HTMLElement {
  return h("th", { scope: "col" }, [text]);
}

/** The table of entries, `shown` of `total`, newest first. */
export function entriesTable(t: I18n, shown: readonly AuditRow[], total: number): HTMLElement {
  const caption =
    shown.length === total
      ? t.label("audit.caption", { count: String(total) })
      : t.label("audit.caption_filtered", { count: String(shown.length), total: String(total) });
  return h("table", { id: "audit-table" }, [
    h("caption", {}, [caption]),
    h("thead", {}, [
      h("tr", {}, [
        th(t.label("audit.col.time")),
        th(t.label("audit.col.kind")),
        th(t.label("audit.col.actor")),
        th(t.label("audit.col.object")),
        th(t.label("audit.col.texts")),
        th(t.label("audit.col.hash")),
      ]),
    ]),
    h(
      "tbody",
      {},
      shown.map((r) =>
        h("tr", { "data-seq": r.seq, "data-kind": r.kind }, [
          h("td", {}, [time(t, r.at)]),
          h("td", {}, [kindText(t, r.kind)]),
          h("td", {}, [actorCell(t, r)]),
          h("td", { class: "pid" }, [objectCell(t, r)]),
          h("td", {}, [textsCell(t, r)]),
          h("td", { class: "hash", "data-hash": r.hash, title: r.hash }, [shortHash(r.hash)]),
        ]),
      ),
    ),
  ]);
}

/** The entries section: the event type filter and the table. */
function entriesSection(t: I18n, log: AuditLog): HTMLElement {
  if (log.entries.length === 0) {
    return h("section", { id: "audit-entries" }, [h("p", {}, [t.label("audit.none")])]);
  }
  const options: Child[] = [h("option", { value: "" }, [t.label("audit.filter.all")])];
  for (const k of kindsOf(log.entries)) {
    options.push(h("option", { value: k }, [kindText(t, k)]));
  }
  const select = selectEl({ id: "audit-kind", name: "kind" }, options);
  const slot = h("div", { id: "audit-table-slot" }, [entriesTable(t, log.entries, log.entries.length)]);
  select.addEventListener("change", () => {
    slot.replaceChildren(entriesTable(t, filterRows(log.entries, select.value), log.entries.length));
  });
  const form = h("form", { class: "filters", "aria-label": t.label("audit.filter") }, [
    h("div", { class: "field" }, [h("label", { for: "audit-kind" }, [t.label("audit.filter.kind")]), select]),
  ]);
  form.addEventListener("submit", (e) => e.preventDefault());
  return h("section", { id: "audit-entries" }, [form, slot]);
}

/** The unmask records, oldest first (ADR-023 reading 11). */
export function unmasksSection(t: I18n, u: Unmasks): HTMLElement {
  const body: Child[] = [
    h("h2", { id: "audit-unmasks-heading" }, [t.label("audit.unmasks.heading")]),
    h("p", { class: "fstp-hint" }, [t.label("audit.unmasks.intro")]),
  ];
  if (u.unmasks.length === 0) {
    body.push(h("p", {}, [t.label("audit.unmasks.none")]));
  } else {
    body.push(
      h("table", { id: "audit-unmasks" }, [
        h("caption", {}, [t.label("audit.unmasks.caption", { count: String(u.unmasks.length) })]),
        h("thead", {}, [
          h("tr", {}, [
            th(t.label("audit.col.time")),
            th(t.label("audit.unmasks.col.party")),
            th(t.label("audit.unmasks.col.subject")),
            th(t.label("audit.unmasks.col.by")),
            th(t.label("audit.unmasks.col.purpose")),
            th(t.label("audit.unmasks.col.conflict")),
          ]),
        ]),
        h(
          "tbody",
          {},
          u.unmasks.map((r) =>
            h("tr", { "data-conflict": String(r.conflict) }, [
              h("td", {}, [time(t, r.at)]),
              h("td", {}, [labelOr(t, `audit.party.${r.party}`, r.party)]),
              h("td", { class: "pid" }, [`${r.subject_type} ${r.subject}`]),
              h("td", { class: "pid" }, [r.by]),
              h("td", {}, [r.purpose]),
              h("td", {}, [t.label(r.conflict ? "audit.unmasks.conflict.yes" : "audit.unmasks.conflict.no")]),
            ]),
          ),
        ),
      ]),
    );
  }
  return h("section", { id: "audit-unmask-section", "aria-labelledby": "audit-unmasks-heading" }, body);
}

/** The vault answers, newest first (overview NOTE 5). */
export function outcomesSection(t: I18n, o: Outcomes): HTMLElement {
  const body: Child[] = [
    h("h2", { id: "audit-outcomes-heading" }, [t.label("audit.outcomes.heading")]),
    h("p", { class: "fstp-hint" }, [t.label("audit.outcomes.intro")]),
  ];
  if (o.outcomes.length === 0) {
    body.push(h("p", {}, [t.label("audit.outcomes.none")]));
  } else {
    body.push(
      h("table", { id: "audit-outcomes" }, [
        h("caption", {}, [t.label("audit.outcomes.caption", { count: String(o.outcomes.length) })]),
        h("thead", {}, [
          h("tr", {}, [
            th(t.label("audit.col.time")),
            th(t.label("audit.outcomes.col.query")),
            th(t.label("audit.outcomes.col.answer")),
            th(t.label("audit.outcomes.col.digest")),
          ]),
        ]),
        h(
          "tbody",
          {},
          o.outcomes.map((r) =>
            h("tr", { "data-seq": r.seq }, [
              h("td", {}, [time(t, r.at)]),
              h("td", {}, [r.query]),
              h("td", {}, [r.holds ? t.label("audit.yes") : t.label("audit.no")]),
              h("td", { class: "hash", "data-hash": r.digest, title: r.digest }, [shortHash(r.digest)]),
            ]),
          ),
        ),
      ]),
    );
  }
  return h("section", { id: "audit-outcome-section", "aria-labelledby": "audit-outcomes-heading" }, body);
}

async function mountAuditLog(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const programme = params["programme"] ?? "";
  const t = pageI18n(env, AUDIT_LABELS);
  const f: Frame = frame(env, t, t.label("audit.title", { programme }));
  await guarded(f, async () => {
    const roles = await myRoles();
    const asksUnmasks = readsUnmasks(roles.kind === "roles" ? roles.roles : null, programme);
    const [log, unmasks, outcomes] = await Promise.all([
      readOp(env, "audit.entries", { programme }, isAuditLog),
      asksUnmasks ? readOp(env, "audit.unmasks", { programme }, isUnmasks) : Promise.resolve(NOT_ASKED),
      readOp(env, "audit.vault_outcomes", { programme }, isOutcomes),
    ]);
    const parts: Child[] = [h("p", { class: "fstp-hint", id: "audit-intro" }, [t.label("audit.intro")])];
    if (log.ok) {
      parts.push(entriesSection(t, log.data));
    } else if (log.problem.kind === "refused") {
      parts.push(h("p", { id: "audit-not-auditor", class: "callout callout--info" }, [t.label("audit.not_auditor")]));
    } else {
      f.problem(log.problem);
    }
    if (unmasks.ok) {
      parts.push(unmasksSection(t, unmasks.data));
    }
    if (outcomes.ok) {
      parts.push(outcomesSection(t, outcomes.data));
    }
    if (!log.ok && !unmasks.ok) {
      f.problem(log.problem);
    }
    f.show(parts);
  });
}

/** The audit log page of a programme. */
export const AUDIT_PAGES: readonly JudgingPage[] = [
  { route: idRoute("audit.log", "/app/programmes/{programme}/audit", ["programme"]), mount: mountAuditLog },
];
