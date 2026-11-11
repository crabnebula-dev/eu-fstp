// The operations pages (lane L-UI2; M5 design sections 5 and 6;
// `docs/design/10-post-grant-screens.md` "Mentor and operations homes"
// and "Funder reporting and audit"): the queues of the Operations roles
// and the funder reports of a programme.
//
// - The payment queue is the caller's own `payment.queue`: line review,
//   approval, release and confirmation, each only for the role that holds
//   it (SoD-04, SoD-12).
// - R-RP-03: a report stays a draft until a Financial signatory who did
//   not generate it approves it. The page shows the rule from the cell.
// - I-44: a generation that does not reconcile fails. The page shows the
//   rule and the way on.
// - R-RP-04: the platform submits nothing to the funder portal.

import { h, type Child } from "../core/dom.js";
import type { I18n } from "../core/i18n.js";
import { frame, guarded, idRoute, readOp, selectEl, type JudgingPage } from "../reviewer/kit.js";
import {
  GRANT_PATHS,
  act,
  actionButton,
  anyObject,
  badge,
  buttonEl,
  can,
  formEl,
  labels,
  link,
  onSubmit,
  rolesOrNull,
  section,
  textField,
  type Frame,
  type PageEnv,
} from "../grant/kit.js";
import {
  decodeDrawn,
  decodeGrantList,
  decodeQueue,
  decodeReports,
  decodeToSign,
  isIdText,
  type GrantRow,
  type QueueRow,
  type ReportRow,
  type ToSignRow,
} from "../grant/models.js";
import { statusBadge } from "../payments/pages.js";

const TASKS = ["review", "approve", "release", "confirm"] as const;

function queueSection(t: I18n, rows: readonly QueueRow[]): HTMLElement {
  if (rows.length === 0) {
    return section("ops-queue", t.label("ops.queue.heading"), [h("p", { id: "ops-queue-none" }, [t.label("ops.queue.none")])]);
  }
  const groups: Child[] = [];
  for (const task of TASKS) {
    const mine = rows.filter((r) => r.task === task);
    if (mine.length === 0) {
      continue;
    }
    groups.push(
      h("h3", {}, [t.label(`ops.queue.task.${task}`), " ", h("span", { class: "text-sm" }, [t.label("ops.queue.count", { n: String(mine.length) })])]),
      h(
        "ul",
        { class: "fstp-list", "data-task": task },
        mine.map((r) =>
          h("li", { "data-request": r.request.request }, [
            h("a", { href: GRANT_PATHS.payment(r.request.proposal, r.request.request) }, [
              t.label("ops.queue.open", { id: r.request.request }),
            ]),
            " ",
            t.label("ops.queue.row", { id: r.request.request, proposal: r.request.proposal }),
            " ",
            statusBadge(t, r.request.status),
          ]),
        ),
      ),
    );
  }
  return section("ops-queue", t.label("ops.queue.heading"), groups);
}

function openByNumber(env: PageEnv, t: I18n, f: Frame): HTMLFormElement {
  const input = textField("ops-reports-number", t.label("ops.reports.open_label"), { inputmode: "numeric" });
  const submit = buttonEl("ops-reports-open", "submit", t.label("ops.reports.open_submit"));
  const form = formEl("ops-reports-form", [input.root, submit]);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const v = input.control.value.trim();
    if (!isIdText(v)) {
      f.alert(t.label("ops.reports.open_err"));
      return;
    }
    env.navigate(GRANT_PATHS.reports(v));
  });
  return form;
}

async function mountOperations(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f = frame(env, t, t.label("ops.title"));
  await guarded(f, async () => {
    const roles = await rolesOrNull();
    const body: Child[] = [h("p", {}, [t.label("ops.intro")]), h("p", { class: "text-sm" }, [t.label("ops.sod")])];
    const q = await readOp(env, "payment.queue", {}, (v): v is readonly QueueRow[] => decodeQueue(v) !== null);
    if (q.ok) {
      body.push(queueSection(t, decodeQueue(q.data) ?? []));
    } else {
      f.problem(q.problem);
    }
    // M5 reads follow-up: the contract versions awaiting the caller's own signature. The cell
    // lists a version for the signatory only once the grantee side signed (P-30).
    const s = await readOp(env, "contract.awaiting_me", {}, (v): v is readonly ToSignRow[] => decodeToSign(v) !== null);
    const toSign = s.ok ? (decodeToSign(s.data) ?? []) : [];
    if (toSign.length > 0 || can(roles, "contract_signatory")) {
      const rows = toSign.map((r) =>
        h("li", { "data-contract": r.contract }, [link(GRANT_PATHS.contract(r.proposal), t.label("ops.contracts.open", { id: r.proposal })), " ", badge(r.state, r.state)]),
      );
      body.push(
        section("ops-contracts", t.label("ops.contracts.heading"), [
          h("p", {}, [t.label("ops.contracts.intro")]),
          rows.length === 0 ? h("p", { id: "ops-contracts-none" }, [t.label("ops.contracts.none")]) : h("ul", { class: "fstp-list" }, rows),
        ]),
      );
    }
    // The grants the caller reads, each linked, so nobody types a proposal number.
    const g = await readOp(env, "grant.list_mine", {}, (v): v is readonly GrantRow[] => decodeGrantList(v) !== null);
    const grants = g.ok ? (decodeGrantList(g.data) ?? []) : [];
    if (grants.length > 0) {
      body.push(
        section("ops-grants", t.label("ops.grants.heading"), [
          h(
            "ul",
            { class: "fstp-list" },
            grants.map((r) => h("li", { "data-grant": r.proposal }, [link(GRANT_PATHS.grant(r.proposal), t.label("ops.grants.row", { id: r.proposal })), " ", badge(r.state, r.state)])),
          ),
        ]),
      );
    }
    // Funder reports of each programme the caller's bindings name.
    const programmes =
      roles === null ? [] : [...new Set(roles.roles.filter((b) => b.proposal === null).map((b) => b.programme))].sort((a, b) => (a.length === b.length ? (a < b ? -1 : 1) : a.length - b.length));
    body.push(
      section("ops-reports", t.label("ops.reports.heading"), [
        h("ul", { class: "fstp-list" }, programmes.map((p) => h("li", {}, [link(GRANT_PATHS.reports(p), t.label("ops.reports.programme", { id: p }))]))),
        openByNumber(env, t, f),
      ]),
    );
    body.push(h("p", { class: "text-sm" }, [t.label("ops.roles_callout"), " ", link("/app/admin/onboarding/summary", t.label("ops.roles_link"))]));
    f.show(body);
  });
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

const KINDS = ["audit_file", "call_publication_record", "periodic_reporting_data", "deliverable_draft", "open_call_package"] as const;

/** The microsecond instant of `YYYY-MM-DD` at 00:00 UTC, as a decimal string, or null. */
export function dayMicros(day: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
    return null;
  }
  const ms = Date.parse(`${day}T00:00:00Z`);
  return Number.isNaN(ms) ? null : String(ms * 1000);
}

function generateSection(env: PageEnv, t: I18n, f: Frame, programme: string, reload: () => Promise<void>): HTMLElement {
  const kind = selectEl(
    { id: "ops-gen-kind", name: "kind" },
    KINDS.map((k) => h("option", { value: k }, [t.label(`ops.reports.kind.${k}`)])),
  );
  const call = textField("ops-gen-call", t.label("ops.reports.generate.call"), { inputmode: "numeric" });
  const start = textField("ops-gen-start", t.label("ops.reports.generate.start"), { type: "date" });
  const end = textField("ops-gen-end", t.label("ops.reports.generate.end"), { type: "date" });
  const submit = buttonEl("ops-gen-submit", "submit", t.label("ops.reports.generate.submit"));
  const form = formEl("ops-gen-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "ops-gen-kind" }, [t.label("ops.reports.generate.kind")]), kind]),
    call.root,
    start.root,
    end.root,
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const body: Record<string, unknown> = { kind: kind.value };
    if (kind.value === "periodic_reporting_data") {
      const s = dayMicros(start.control.value);
      const e = dayMicros(end.control.value);
      if (s === null || e === null) {
        f.alert(t.label("ops.reports.generate.err"));
        return;
      }
      body["start"] = s;
      body["end"] = e;
    } else {
      const c = call.control.value.trim();
      if (!isIdText(c)) {
        f.alert(t.label("ops.reports.generate.err"));
        return;
      }
      body["call"] = c;
    }
    const r = await act(env, "report.generate", { programme }, body, (v) => decodeDrawn(v, "report"));
    if (!r.ok) {
      f.problem(r.problem);
      if (r.problem.kind === "refused" && r.problem.rule === "I-44") {
        f.show([]);
      }
      return;
    }
    await reload();
    f.status(t.label("ops.reports.generate.done"));
  });
  return section("ops-generate", t.label("ops.reports.generate.heading"), [form]);
}

async function mountReports(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const programme = params["programme"] ?? "";
  const f = frame(env, t, t.label("ops.reports.title", { id: programme }));
  const render = async (): Promise<void> => {
    const r = await readOp(env, "report.list", { programme }, (v): v is readonly ReportRow[] => decodeReports(v) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(GRANT_PATHS.operations, t.label("ops.reports.back"))])]);
      return;
    }
    const rows = decodeReports(r.data) ?? [];
    const roles = await rolesOrNull();
    const approver = can(roles, "financial_signatory");
    const body: Child[] = [
      h("p", {}, [link(GRANT_PATHS.operations, t.label("ops.reports.back"))]),
      h("p", { class: "text-sm" }, [t.label("ops.reports.no_submit")]),
    ];
    if (rows.length === 0) {
      body.push(h("p", { id: "ops-reports-none" }, [t.label("ops.reports.none")]));
    } else {
      body.push(
        h("table", { id: "ops-reports-table" }, [
          h("caption", {}, [t.label("ops.reports.caption")]),
          h("thead", {}, [
            h("tr", {}, [
              h("th", { scope: "col" }, [t.label("ops.reports.col_kind")]),
              h("th", { scope: "col" }, [t.label("ops.reports.col_scope")]),
              h("th", { scope: "col" }, [t.label("ops.reports.col_hash")]),
              h("th", { scope: "col" }, [t.label("ops.reports.col_template")]),
              h("th", { scope: "col" }, [t.label("ops.reports.col_state")]),
            ]),
          ]),
          h(
            "tbody",
            {},
            rows.map((x) => {
              const approve =
                approver && !x.approved && !x.generatedByMe
                  ? actionButton(`ops-report-approve-${x.report}`, t.label("ops.reports.approve", { id: x.report }), f, async () => {
                      f.clearAlert();
                      const a = await act(env, "report.approve", { report: x.report }, {}, anyObject);
                      if (!a.ok) {
                        f.problem(a.problem);
                        return;
                      }
                      await render();
                      f.status(t.label("ops.reports.approve_done"));
                    })
                  : null;
              return h("tr", { "data-report": x.report, "data-approved": String(x.approved) }, [
                h("th", { scope: "row" }, [t.label(`ops.reports.kind.${x.kind}`)]),
                h("td", {}, [x.call !== null ? t.label("ops.reports.scope_call", { id: x.call }) : t.label("ops.reports.scope_programme", { id: x.programme ?? programme })]),
                h("td", {}, [h("code", {}, [x.document])]),
                h("td", {}, [x.template]),
                h("td", {}, [
                  badge(x.approved ? t.label("ops.reports.approved") : t.label("ops.reports.draft"), x.approved ? "approved" : "draft"),
                  ...(approve !== null ? [" ", approve] : []),
                  ...(approver && !x.approved && x.generatedByMe ? [h("span", { class: "text-sm" }, [" ", t.label("ops.reports.mine")])] : []),
                ]),
              ]);
            }),
          ),
        ]),
      );
    }
    if (can(roles, "programme_manager")) {
      body.push(generateSection(env, t, f, programme, render));
      body.push(
        h("p", { class: "text-sm", id: "ops-reports-failure" }, [
          t.label("ops.reports.failure.body"),
          " ",
          h("span", {}, [t.label("ops.reports.failure.support"), " ", h("span", { class: "text-sm" }, [t.label("ops.reports.failure.support_note")])]),
        ]),
      );
    }
    f.show(body);
  };
  await guarded(f, render);
}

/** The operations pages, each with its route below `/app/`. */
export const OPERATIONS_PAGES: readonly JudgingPage[] = [
  { route: idRoute("ops.home", "/app/operations", []), mount: (env) => mountOperations(env) },
  { route: idRoute("ops.reports", "/app/programmes/{programme}/reports", ["programme"]), mount: (env, p) => mountReports(env, p) },
];
