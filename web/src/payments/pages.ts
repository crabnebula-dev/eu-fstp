// The payment pages (lane L-UI2; M5 design sections 1.2, 5 and 6;
// `docs/design/10-post-grant-screens.md` "Payment requests"): the status
// list, the request form, the request page with line review, approval,
// release and confirmation, and the resubmission.
//
// - I-58: each line names a milestone and an amount. The cell checks the
//   amount against what is available and refuses a line above it.
// - I-32: the checks are the cell's. The page shows their result.
// - I-05, I-31, I-33, SoD-04: the cell decides release. The page shows
//   the rule when it refuses.
// - ADR-006: amounts are strings. The browser adds nothing up.
// - I-86: the page shows no bank detail. The payee details open on the
//   vault page.

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
  facts,
  formEl,
  isVaultUrl,
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
  closeBody,
  decodeOverview,
  decodePayments,
  decodeRedirect,
  isAmountText,
  lineBody,
  paymentBody,
  reviewBody,
  type LineBody,
  type MilestoneInfo,
  type Overview,
  type RequestRow,
} from "../grant/models.js";

/** The state badge of a request: the plain label with the formal state beside it (I-96). */
export function statusBadge(t: I18n, s: string): HTMLElement {
  return badge(t.label(`pay.status.${s}`), s);
}

function total(t: I18n, r: RequestRow): HTMLElement[] {
  return r.lines.map((l) => h("div", {}, [`${l.milestone}: ${l.requested}`, l.approved === null ? "" : ` (${t.label("pay.detail.line_approved")} ${l.approved})`]));
}

function checks(t: I18n, r: RequestRow): HTMLElement {
  const one = (id: string, ok: boolean): HTMLElement =>
    h("div", {}, [t.label(id), ": ", t.label(ok ? "pay.checks.pass" : "pay.checks.fail")]);
  return h("div", {}, [one("pay.checks.sub", r.submission_checks), one("pay.checks.acc", r.acceptance_checks)]);
}

// ---------------------------------------------------------------------------
// The status list
// ---------------------------------------------------------------------------

async function mountList(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const proposal = params["proposal"] ?? "";
  const f = frame(env, t, t.label("pay.list.title", { id: proposal }));
  await guarded(f, async () => {
    const r = await readOp(env, "payment.status", { proposal }, (v): v is readonly RequestRow[] => decodePayments(v) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(GRANT_PATHS.grant(proposal), t.label("pay.list.back"))])]);
      return;
    }
    const rows = decodePayments(r.data) ?? [];
    const roles = await rolesOrNull();
    const body: Child[] = [
      h("p", {}, [link(GRANT_PATHS.grant(proposal), t.label("pay.list.back"))]),
      h("p", { class: "text-sm" }, [t.label("pay.callout.mode")]),
    ];
    if (can(roles, "applicant", proposal)) {
      body.push(h("p", {}, [link(GRANT_PATHS.paymentNew(proposal), t.label("pay.list.new"))]));
    }
    for (const x of rows) {
      if (x.status === "CHECKS_FAILED") {
        body.push(h("p", { class: "fstp-alert", "data-callout": "checks-failed" }, [t.label("pay.callout.checks_failed")]));
        break;
      }
    }
    for (const x of rows) {
      if (x.status === "CHANGES_REQUESTED") {
        body.push(h("p", { class: "fstp-alert", "data-callout": "changes-requested" }, [t.label("pay.callout.changes_requested")]));
        break;
      }
    }
    if (rows.length === 0) {
      body.push(h("p", { id: "pay-none" }, [t.label("pay.list.none")]));
    } else {
      body.push(
        h("table", { id: "pay-table" }, [
          h("caption", {}, [t.label("pay.list.caption")]),
          h("thead", {}, [
            h("tr", {}, [
              h("th", { scope: "col" }, [t.label("pay.list.col_request")]),
              h("th", { scope: "col" }, [t.label("pay.list.col_status")]),
              h("th", { scope: "col" }, [t.label("pay.list.col_kind")]),
              h("th", { scope: "col" }, [t.label("pay.list.col_requested")]),
              h("th", { scope: "col" }, [t.label("pay.list.col_checks")]),
            ]),
          ]),
          h(
            "tbody",
            {},
            rows.map((x) =>
              h("tr", { "data-request": x.request, "data-status": x.status }, [
                h("th", { scope: "row" }, [h("a", { href: GRANT_PATHS.payment(proposal, x.request) }, [t.label("pay.list.open", { id: x.request })])]),
                h("td", {}, [statusBadge(t, x.status)]),
                h("td", {}, [t.label(`pay.kind.${x.kind}`)]),
                h("td", {}, total(t, x)),
                h("td", {}, [checks(t, x)]),
              ]),
            ),
          ),
        ]),
      );
    }
    f.show(body);
  });
}

// ---------------------------------------------------------------------------
// The form
// ---------------------------------------------------------------------------

interface LineInputs {
  readonly root: HTMLElement;
  readonly milestone: HTMLInputElement | HTMLSelectElement;
  readonly amount: HTMLInputElement;
  readonly location: HTMLInputElement;
  readonly release: HTMLInputElement;
  readonly licence: HTMLInputElement;
  readonly report: HTMLInputElement;
}

function available(m: MilestoneInfo): string | null {
  // The cell names `paid` and `amount`. The available amount is the cell's to say: the page
  // offers "Fill available" only when the milestone is wholly unpaid (ADR-006).
  return m.paid === null || m.paid === "0.00" ? m.amount : null;
}

function lineInputs(t: I18n, n: number, milestones: readonly MilestoneInfo[]): LineInputs {
  const k = String(n);
  let milestone: HTMLInputElement | HTMLSelectElement;
  let mroot: HTMLElement;
  if (milestones.length > 0) {
    milestone = selectEl(
      { id: `pay-milestone-${k}`, name: "milestone" },
      milestones.map((m) => h("option", { value: m.milestone }, [t.label("pay.form.milestone_option", { id: m.milestone, amount: m.amount, due: m.due ?? "-" })])),
    );
    mroot = h("div", { class: "fstp-field" }, [h("label", { for: `pay-milestone-${k}` }, [t.label("pay.form.milestone_pick", { n: k })]), milestone]);
  } else {
    const m = textField(`pay-milestone-${k}`, t.label("pay.form.milestone", { n: k }), { inputmode: "numeric" });
    milestone = m.control;
    mroot = m.root;
  }
  const amount = textField(`pay-amount-${k}`, t.label("pay.form.amount", { n: k }), { inputmode: "decimal" });
  const location = textField(`pay-location-${k}`, t.label("pay.form.location", { n: k }), { inputmode: "url" });
  const release = textField(`pay-release-${k}`, t.label("pay.form.release", { n: k }));
  const licence = textField(`pay-licence-${k}`, t.label("pay.form.licence", { n: k }));
  const report = textField(`pay-report-${k}`, t.label("pay.form.report", { n: k }));
  const fill = buttonEl(`pay-fill-${k}`, "button", t.label("pay.form.fill", { n: k }));
  fill.addEventListener("click", () => {
    const m = milestones.find((x) => x.milestone === milestone.value);
    const a = m === undefined ? null : available(m);
    if (a !== null) {
      amount.control.value = a;
    }
  });
  return {
    root: h("fieldset", { class: "card" }, [mroot, amount.root, ...(milestones.length > 0 ? [fill] : []), location.root, release.root, licence.root, report.root]),
    milestone,
    amount: amount.control,
    location: location.control,
    release: release.control,
    licence: licence.control,
    report: report.control,
  };
}

async function mountForm(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const proposal = params["proposal"] ?? "";
  const resubmit = params["request"];
  const f = frame(env, t, resubmit === undefined ? t.label("pay.form.title", { id: proposal }) : t.label("pay.resubmit.title", { id: resubmit }));
  await guarded(f, async () => {
    const o = await readOp(env, "grant.overview", { proposal }, (v): v is Overview => decodeOverview(v) !== null);
    const milestones = o.ok ? (decodeOverview(o.data)?.milestones ?? []) : [];
    const rows: LineInputs[] = [];
    const slot = h("div", { id: "pay-lines" });
    const addRow = (): void => {
      const r = lineInputs(t, rows.length + 1, milestones);
      rows.push(r);
      slot.append(r.root);
    };
    addRow();
    const more = buttonEl("pay-add", "button", t.label("pay.form.add"));
    more.addEventListener("click", () => {
      if (rows.length < 8) {
        addRow();
      }
    });
    const submit = buttonEl("pay-submit", "submit", t.label("pay.form.submit"));
    const form = formEl("pay-form", [slot, more, h("p", { class: "text-sm" }, [t.label("pay.form.total_note")]), submit]);
    onSubmit(f, form, submit, async () => {
      f.clearAlert();
      const lines: LineBody[] = [];
      for (const [i, r] of rows.entries()) {
        const b = lineBody(r.milestone.value.trim(), r.amount.value.trim(), {
          location: r.location.value,
          release: r.release.value,
          licence: r.licence.value,
          report: r.report.value,
        });
        if (!b.ok) {
          f.alert(t.label("pay.form.err", { n: String(i + 1) }));
          return;
        }
        lines.push(b.value);
      }
      const done =
        resubmit === undefined
          ? await act(env, "payment.submit", { proposal }, paymentBody(lines), anyObject)
          : await act(env, "payment.resubmit", { request: resubmit }, paymentBody(lines), anyObject);
      if (!done.ok) {
        f.problem(done.problem);
        return;
      }
      f.status(t.label("pay.form.done"));
      env.navigate(GRANT_PATHS.payments(proposal));
    });
    f.show([h("p", {}, [link(GRANT_PATHS.payments(proposal), t.label("pay.list.back"))]), h("p", {}, [t.label("pay.form.intro")]), form]);
  });
}

// ---------------------------------------------------------------------------
// One request
// ---------------------------------------------------------------------------

function simple(
  env: PageEnv,
  t: I18n,
  f: Frame,
  key: "approve" | "release" | "paid" | "withdraw",
  op: string,
  r: RequestRow,
  reload: () => Promise<void>,
): HTMLElement {
  const b = actionButton(`pay-${key}-submit`, t.label(`pay.${key}.submit`), f, async () => {
    f.clearAlert();
    const a = await act(env, op, { request: r.request }, {}, anyObject);
    if (!a.ok) {
      f.problem(a.problem);
      return;
    }
    await reload();
    f.status(t.label(`pay.${key}.done`));
  });
  b.className = "fstp-primary";
  return section(`pay-${key}`, t.label(`pay.${key}.heading`), [h("p", {}, [t.label(`pay.${key}.intro`)]), b]);
}

function reviewSection(env: PageEnv, t: I18n, f: Frame, r: RequestRow, reload: () => Promise<void>): HTMLElement {
  const forms = r.lines.map((l) => {
    const approved = textField(`pay-review-amount-${l.line}`, t.label("pay.review.approved", { line: l.line }), { inputmode: "decimal", value: l.requested });
    const reason = textField(`pay-review-reason-${l.line}`, t.label("pay.review.reason", { line: l.line }));
    const submit = buttonEl(`pay-review-submit-${l.line}`, "submit", t.label("pay.review.submit", { line: l.line }));
    const form = formEl(`pay-review-form-${l.line}`, [approved.root, reason.root, submit]);
    onSubmit(f, form, submit, async () => {
      f.clearAlert();
      const v = approved.control.value.trim();
      if (!isAmountText(v)) {
        f.alert(t.label("pay.review.err"));
        return;
      }
      const a = await act(env, "payment.review_line", { request: r.request, line: l.line }, reviewBody(v, reason.control.value), anyObject);
      if (!a.ok) {
        f.problem(a.problem);
        return;
      }
      await reload();
      f.status(t.label("pay.review.done"));
    });
    return form;
  });
  const why = textField("pay-changes-reason", t.label("pay.changes.reason"));
  const ask = buttonEl("pay-changes-submit", "submit", t.label("pay.changes.submit"));
  const changes = formEl("pay-changes-form", [why.root, ask]);
  onSubmit(f, changes, ask, async () => {
    f.clearAlert();
    const b = closeBody(why.control.value);
    if (b === null) {
      f.alert(t.label("pay.changes.err"));
      return;
    }
    const a = await act(env, "payment.request_changes", { request: r.request }, b, anyObject);
    if (!a.ok) {
      f.problem(a.problem);
      return;
    }
    await reload();
    f.status(t.label("pay.changes.done"));
  });
  return section("pay-review", t.label("pay.review.heading"), [h("p", {}, [t.label("pay.review.intro")]), ...forms, h("h3", {}, [t.label("pay.changes.heading")]), changes]);
}

function payeeSection(env: PageEnv, t: I18n, f: Frame, r: RequestRow): HTMLElement {
  const b = actionButton("pay-payee-submit", t.label("pay.payee.submit"), f, async () => {
    f.clearAlert();
    const a = await act(env, "vault.bank.view_for_release", { request: r.request }, {}, decodeRedirect);
    if (!a.ok) {
      f.problem(a.problem);
      return;
    }
    if (!isVaultUrl(a.data, location)) {
      f.alert(t.label("pay.payee.bad"));
      return;
    }
    location.assign(a.data);
  });
  return section("pay-payee", t.label("pay.payee.heading"), [h("p", {}, [t.label("pay.payee.intro")]), b]);
}

function closeSection(env: PageEnv, t: I18n, f: Frame, r: RequestRow, reload: () => Promise<void>): HTMLElement {
  const reason = textField("pay-close-reason", t.label("pay.close.reason"));
  const submit = buttonEl("pay-close-submit", "submit", t.label("pay.close.submit"));
  const form = formEl("pay-close-form", [reason.root, submit]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const b = closeBody(reason.control.value);
    if (b === null) {
      f.alert(t.label("pay.close.err"));
      return;
    }
    const a = await act(env, "payment.close", { request: r.request }, b, anyObject);
    if (!a.ok) {
      f.problem(a.problem);
      return;
    }
    await reload();
    f.status(t.label("pay.close.done"));
  });
  return section("pay-close", t.label("pay.close.heading"), [form]);
}

async function mountRequest(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const proposal = params["proposal"] ?? "";
  const id = params["request"] ?? "";
  const f = frame(env, t, t.label("pay.detail.title", { id }));
  const render = async (): Promise<void> => {
    const res = await readOp(env, "payment.status", { proposal }, (v): v is readonly RequestRow[] => decodePayments(v) !== null);
    if (!res.ok) {
      f.problem(res.problem);
      f.show([h("p", {}, [link(GRANT_PATHS.payments(proposal), t.label("pay.detail.back"))])]);
      return;
    }
    const r = (decodePayments(res.data) ?? []).find((x) => x.request === id);
    if (r === undefined) {
      f.alert(t.label("pay.detail.not_found"));
      f.show([h("p", {}, [link(GRANT_PATHS.payments(proposal), t.label("pay.detail.back"))])]);
      return;
    }
    const roles = await rolesOrNull();
    const body: Child[] = [
      h("p", {}, [link(GRANT_PATHS.payments(proposal), t.label("pay.detail.back"))]),
      h("p", { id: "pay-status", "data-status": r.status }, [t.label("pay.detail.status"), ": ", statusBadge(t, r.status)]),
      facts([
        [t.label("pay.list.col_kind"), t.label(`pay.kind.${r.kind}`)],
        [t.label("pay.detail.checks"), checks(t, r)],
      ]),
      h("table", { id: "pay-lines-table" }, [
        h("caption", {}, [t.label("pay.detail.lines")]),
        h("thead", {}, [
          h("tr", {}, [
            h("th", { scope: "col" }, [t.label("pay.detail.line_milestone")]),
            h("th", { scope: "col" }, [t.label("pay.detail.line_requested")]),
            h("th", { scope: "col" }, [t.label("pay.detail.line_approved")]),
          ]),
        ]),
        h(
          "tbody",
          {},
          r.lines.map((l) =>
            h("tr", { "data-line": l.line }, [
              h("th", { scope: "row" }, [l.milestone]),
              h("td", {}, [l.requested]),
              h("td", {}, [l.approved ?? t.label("pay.detail.line_none")]),
            ]),
          ),
        ),
      ]),
      h("p", { class: "text-sm" }, [t.label("pay.sod")]),
    ];
    if (r.status === "CHECKS_FAILED") {
      body.push(
        section("pay-checks-failed", t.label("pay.detail.checks_failed_title"), [
          h("p", {}, [t.label("pay.callout.checks_failed")]),
          h("p", { class: "text-sm" }, [t.label("pay.detail.checks_failed_intro")]),
        ]),
      );
    }
    const lead = can(roles, "applicant", proposal);
    if (lead && (r.status === "CHECKS_FAILED" || r.status === "CHANGES_REQUESTED")) {
      body.push(h("p", {}, [h("a", { id: "pay-resubmit", href: GRANT_PATHS.resubmit(proposal, r.request) }, [t.label("pay.detail.edit")])]));
    }
    if (lead && ["SUBMITTED", "CHECKS_FAILED", "UNDER_REVIEW", "CHANGES_REQUESTED", "DRAFT"].includes(r.status)) {
      body.push(simple(env, t, f, "withdraw", "payment.withdraw", r, render));
    }
    if (r.status === "UNDER_REVIEW" && can(roles, "committee_member")) {
      body.push(reviewSection(env, t, f, r, render));
    }
    if (r.status === "ACCEPTED" && can(roles, "finance_approver")) {
      body.push(simple(env, t, f, "approve", "payment.approve", r, render));
    }
    if (r.status === "PAYMENT_APPROVED" && can(roles, "payment_releaser")) {
      body.push(simple(env, t, f, "release", "payment.release", r, render));
    }
    if (r.status === "RELEASED" && can(roles, "payment_releaser")) {
      body.push(payeeSection(env, t, f, r));
    }
    if (r.status === "RELEASED" && can(roles, "finance_approver")) {
      body.push(simple(env, t, f, "paid", "payment.confirm_paid", r, render));
    }
    if (["PAID", "REJECTED", "WITHDRAWN"].includes(r.status) && can(roles, "programme_manager")) {
      body.push(closeSection(env, t, f, r, render));
    }
    f.show(body);
  };
  await guarded(f, render);
}

/** The payment pages, each with its route below `/app/`. */
export const PAYMENT_PAGES: readonly JudgingPage[] = [
  { route: idRoute("pay.list", "/app/grants/{proposal}/payments", ["proposal"]), mount: (env, p) => mountList(env, p) },
  { route: idRoute("pay.new", "/app/grants/{proposal}/payments/new", ["proposal"]), mount: (env, p) => mountForm(env, p) },
  { route: idRoute("pay.one", "/app/grants/{proposal}/payments/{request}", ["proposal", "request"]), mount: (env, p) => mountRequest(env, p) },
  { route: idRoute("pay.resubmit", "/app/grants/{proposal}/payments/{request}/resubmit", ["proposal", "request"]), mount: (env, p) => mountForm(env, p) },
];
