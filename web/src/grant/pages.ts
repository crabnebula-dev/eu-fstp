// The grant pages (lane L-UI1; M5 design sections 1.2, 5 and 6): the list
// of grants a person reaches, and the overview of one grant with the
// negotiation actions: amount determination (R-NG-03), acceptance and
// approval (NOTE 9), milestone closure (I-64), termination, and the
// links to the contract, the payment requests and the vault pages for
// bank details and hardship evidence (I-33, R-PR-04).
//
// Every action shows only to the role that holds it. The cell decides
// each action again, so a refusal shows its rule and nothing else.

import { h, type Child } from "../core/dom.js";
import type { I18n } from "../core/i18n.js";
import { frame, guarded, idRoute, list, isAssignmentSummary, readOp, type JudgingPage } from "../reviewer/kit.js";
import { isBoard } from "../coordinator/models.js";
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
} from "./kit.js";
import {
  decodeOverview,
  decodeRedirect,
  closeBody,
  determinationBody,
  determineBody,
  isIdText,
  reasonBody,
  type Overview,
} from "./models.js";
import { isStateTag } from "../reviewer/kit.js";

// ---------------------------------------------------------------------------
// The list of grants
// ---------------------------------------------------------------------------

interface Row {
  readonly proposal: string;
  readonly title: string;
}

function rowsOf(t: I18n, group: string, rows: readonly Row[]): HTMLElement {
  return h("section", { class: "card", "aria-labelledby": `${group}-heading` }, [
    h("h2", { id: `${group}-heading` }, [t.label(`grant.hub.${group}`)]),
    h(
      "ul",
      { class: "fstp-list" },
      rows.map((r) =>
        h("li", { "data-grant": r.proposal }, [
          h("a", { href: GRANT_PATHS.grant(r.proposal) }, [
            r.title === "" ? t.label("grant.hub.row", { id: r.proposal }) : t.label("grant.hub.row_titled", { id: r.proposal, title: r.title }),
          ]),
        ]),
      ),
    ),
  ]);
}

/** Mounts `/app/grants`: the grants the caller reaches, and a form to open one by number. */
async function mountHub(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f = frame(env, t, t.label("grant.hub.title"));
  await guarded(f, async () => {
    const roles = await rolesOrNull();
    const mine: Row[] = [];
    const board: Row[] = [];
    const assigned: Row[] = [];
    const seen = new Set<string>();
    const add = (to: Row[], r: Row): void => {
      if (!seen.has(r.proposal)) {
        seen.add(r.proposal);
        to.push(r);
      }
    };
    if (roles !== null) {
      for (const b of roles.roles) {
        if (b.proposal !== null && (b.role === "applicant" || b.role === "applicant_team_member")) {
          add(mine, { proposal: b.proposal, title: "" });
        }
      }
      const calls = [...new Set(roles.roles.filter((b) => b.proposal === null).flatMap((b) => b.calls))];
      for (const c of calls) {
        const r = await readOp(env, "call.board", { call: c }, isBoard);
        if (r.ok) {
          for (const p of r.data) {
            if (p.state === "NEGOTIATION" || p.state === "GRANTED" || p.state === "IN_EXECUTION" || p.state === "COMPLETED") {
              add(board, { proposal: p.proposal, title: p.title });
            }
          }
        }
      }
    }
    const a = await readOp(env, "me.assignments", {}, list(isAssignmentSummary));
    if (a.ok) {
      for (const s of a.data.filter((x) => x.kind === "reviewer")) {
        add(assigned, { proposal: s.proposal, title: "" });
      }
    }
    const input = textField("grant-open-number", t.label("grant.hub.open_label"), { inputmode: "numeric" });
    const submit = buttonEl("grant-open-submit", "submit", t.label("grant.hub.open_submit"));
    const form = formEl("grant-open-form", [input.root, submit]);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const v = input.control.value.trim();
      if (!isIdText(v)) {
        f.alert(t.label("grant.hub.open_err"));
        return;
      }
      env.navigate(GRANT_PATHS.grant(v));
    });
    const body: Child[] = [h("p", {}, [t.label("grant.hub.intro")])];
    for (const [g, rows] of [["mine", mine], ["board", board], ["assigned", assigned]] as const) {
      if (rows.length > 0) {
        body.push(rowsOf(t, g, rows));
      }
    }
    if (mine.length + board.length + assigned.length === 0) {
      body.push(h("p", { id: "grant-hub-none" }, [t.label("grant.hub.none")]));
    }
    body.push(form);
    f.show(body);
  });
}

// ---------------------------------------------------------------------------
// One grant
// ---------------------------------------------------------------------------

function deductionRows(t: I18n, n: number): { readonly root: HTMLElement; readonly amount: HTMLInputElement; readonly reason: HTMLInputElement } {
  const a = textField(`grant-deduction-amount-${String(n)}`, t.label("grant.determine.deduction_amount", { n: String(n) }), { inputmode: "decimal" });
  const r = textField(`grant-deduction-reason-${String(n)}`, t.label("grant.determine.deduction_reason", { n: String(n) }));
  return { root: h("div", { class: "fstp-field-group" }, [a.root, r.root]), amount: a.control, reason: r.control };
}

function determineSection(env: PageEnv, t: I18n, f: Frame, o: Overview, reload: () => Promise<void>): HTMLElement {
  const plan = textField("grant-determine-plan", t.label("grant.determine.plan"), { inputmode: "numeric", value: o.agreedPlan ?? "" });
  const rows: ReturnType<typeof deductionRows>[] = [];
  const slot = h("div", { id: "grant-deductions" });
  const addRow = (): void => {
    const r = deductionRows(t, rows.length + 1);
    rows.push(r);
    slot.append(r.root);
  };
  const more = buttonEl("grant-determine-add", "button", t.label("grant.determine.add"));
  more.addEventListener("click", () => {
    if (rows.length < 4) {
      addRow();
    }
  });
  const submit = buttonEl("grant-determine-submit", "submit", t.label("grant.determine.submit"));
  const form = formEl("grant-determine-form", [plan.root, slot, more, submit]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const typed = rows.filter((r) => r.amount.value.trim() !== "" || r.reason.value.trim() !== "");
    const built = determineBody(
      plan.control.value.trim(),
      typed.map((r) => ({ amount: r.amount.value.trim(), reason: r.reason.value })),
    );
    if (!built.ok) {
      f.alert(isIdText(plan.control.value.trim()) ? t.label("grant.determine.err_deduction") : t.label("grant.determine.err_plan"));
      return;
    }
    const r = await act(env, "grant.determine_amount", { proposal: o.proposal }, built.value, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("grant.determine.done"));
  });
  return section("grant-determine", t.label("grant.determine.heading"), [h("p", {}, [t.label("grant.determine.intro")]), form]);
}

function confirmSection(
  env: PageEnv,
  t: I18n,
  f: Frame,
  o: Overview,
  kind: "accept" | "approve",
  reload: () => Promise<void>,
): HTMLElement {
  const b = actionButton(`grant-${kind}-submit`, t.label(`grant.${kind}.submit`), f, async () => {
    f.clearAlert();
    if (o.determination === null) {
      return;
    }
    const r = await act(env, `grant.${kind}`, { proposal: o.proposal }, determinationBody(o.determination), anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label(`grant.${kind}.done`));
  });
  b.className = "fstp-primary";
  return section(`grant-${kind}`, t.label(`grant.${kind}.heading`), [h("p", {}, [t.label(`grant.${kind}.intro`)]), b]);
}

function closeSection(env: PageEnv, t: I18n, f: Frame, o: Overview, reload: () => Promise<void>): HTMLElement {
  const ms = textField("grant-close-milestone", t.label("grant.close.milestone"), { inputmode: "numeric" });
  const reason = textField("grant-close-reason", t.label("grant.close.reason"));
  const submit = buttonEl("grant-close-submit", "submit", t.label("grant.close.submit"));
  const form = formEl("grant-close-form", [ms.root, reason.root, submit]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const body = closeBody(reason.control.value);
    const m = ms.control.value.trim();
    if (body === null || !isIdText(m)) {
      f.alert(t.label("grant.close.err"));
      return;
    }
    const r = await act(env, "milestone.close", { proposal: o.proposal, milestone: m }, body, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("grant.close.done"));
  });
  return section("grant-close", t.label("grant.close.heading"), [h("p", {}, [t.label("grant.close.intro")]), form]);
}

function terminateSection(env: PageEnv, t: I18n, f: Frame, o: Overview, reload: () => Promise<void>): HTMLElement {
  const reason = textField("grant-terminate-reason", t.label("grant.terminate.reason"));
  const submit = buttonEl("grant-terminate-submit", "submit", t.label("grant.terminate.submit"));
  const form = formEl("grant-terminate-form", [reason.root, submit]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const body = reasonBody(reason.control.value);
    if (body === null) {
      f.alert(t.label("grant.terminate.err"));
      return;
    }
    const r = await act(env, "grant.terminate", { proposal: o.proposal }, body, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("grant.terminate.done"));
  });
  return section("grant-terminate", t.label("grant.terminate.heading"), [h("p", {}, [t.label("grant.terminate.intro")]), form]);
}

/** A vault ticket button: asks for the ticket and opens the vault page (I-17, I-86). */
function vaultButton(env: PageEnv, t: I18n, f: Frame, id: string, op: string, o: Overview, labelId: string): HTMLButtonElement {
  return actionButton(id, t.label(labelId), f, async () => {
    f.clearAlert();
    const r = await act(env, op, { proposal: o.proposal }, {}, decodeRedirect);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    if (!isVaultUrl(r.data, location)) {
      f.alert(t.label("grant.bank.bad_redirect"));
      return;
    }
    f.status(t.label("grant.bank.opening"));
    location.assign(r.data);
  });
}

function bankSection(env: PageEnv, t: I18n, f: Frame, o: Overview, lead: boolean, finance: boolean): HTMLElement {
  const buttons: HTMLElement[] = [];
  if (lead) {
    buttons.push(vaultButton(env, t, f, "grant-bank-set", "vault.bank.set", o, "grant.bank.set"));
    buttons.push(vaultButton(env, t, f, "grant-bank-dispute", "vault.bank.dispute", o, "grant.bank.dispute"));
    buttons.push(vaultButton(env, t, f, "grant-hardship-submit", "vault.hardship.submit", o, "grant.bank.hardship_submit"));
  }
  if (finance) {
    buttons.push(vaultButton(env, t, f, "grant-bank-verify", "vault.bank.verify", o, "grant.bank.verify"));
    buttons.push(vaultButton(env, t, f, "grant-hardship-verify", "vault.hardship.verify", o, "grant.bank.hardship_verify"));
  }
  return section("grant-bank", t.label("grant.bank.heading"), [
    h("p", {}, [t.label("grant.bank.intro")]),
    h("div", { class: "fstp-actions" }, buttons),
  ]);
}

async function mountGrant(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const proposal = params["proposal"] ?? "";
  const f = frame(env, t, t.label("grant.title", { id: proposal }));
  const render = async (): Promise<void> => {
    const r = await readOp(env, "grant.overview", { proposal }, (v): v is Overview => decodeOverview(v) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(GRANT_PATHS.hub, t.label("grant.link_hub"))])]);
      return;
    }
    const o = decodeOverview(r.data);
    if (o === null) {
      return;
    }
    const roles = await rolesOrNull();
    const negotiation = o.state === "NEGOTIATION";
    const live = o.state === "GRANTED" || o.state === "IN_EXECUTION";
    const plain = isStateTag(o.state) ? t.label(`kit.state.${o.state}`) : o.state;
    const body: Child[] = [
      h("p", { id: "grant-state", "data-state": o.state }, [badge(plain, o.state)]),
      facts([
        [t.label("grant.determination"), o.determination === null ? t.label("grant.determination_none") : t.label("grant.determination_set", { id: o.determination })],
        [t.label("grant.amount"), o.amount ?? "-"],
        [t.label("grant.paid"), o.paid],
        [t.label("grant.requests"), String(o.requests)],
      ]),
      h("nav", { "aria-label": t.label("grant.links") }, [
        h("ul", { class: "fstp-list" }, [
          h("li", {}, [link(GRANT_PATHS.contract(proposal), t.label("grant.link_contract"))]),
          h("li", {}, [link(GRANT_PATHS.payments(proposal), t.label("grant.link_payments"))]),
          h("li", {}, [link(`/app/proposals/${proposal}/progress`, t.label("grant.link_progress"))]),
          h("li", {}, [link(GRANT_PATHS.hub, t.label("grant.link_hub"))]),
        ]),
      ]),
    ];
    const lead = can(roles, "applicant", proposal);
    if (negotiation && can(roles, "committee_member")) {
      body.push(determineSection(env, t, f, o, render));
    }
    if (negotiation && o.determination !== null && lead) {
      body.push(confirmSection(env, t, f, o, "accept", render));
    }
    if (negotiation && o.determination !== null && can(roles, "programme_manager")) {
      body.push(confirmSection(env, t, f, o, "approve", render));
    }
    if (live && can(roles, "programme_manager")) {
      body.push(closeSection(env, t, f, o, render));
    }
    if ((live || negotiation) && can(roles, "programme_manager")) {
      body.push(terminateSection(env, t, f, o, render));
    }
    const finance = can(roles, "finance_approver");
    if (live && (lead || finance)) {
      body.push(bankSection(env, t, f, o, lead, finance));
    }
    f.show(body);
  };
  await guarded(f, render);
}

/** The grant pages, each with its route below `/app/`. */
export const GRANT_PAGES: readonly JudgingPage[] = [
  { route: idRoute("grant.hub", "/app/grants", []), mount: (env) => mountHub(env) },
  { route: idRoute("grant.one", "/app/grants/{proposal}", ["proposal"]), mount: (env, p) => mountGrant(env, p) },
];
