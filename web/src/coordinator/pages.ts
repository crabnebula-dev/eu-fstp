// The FSTP coordinator's pages (J5, M4 design section 2.2; lane W4c):
// intake, the declaration, the knock-out check, reviewer assignment and
// admission, the call board with the stage 1 close, and the notifiable
// conflict drafts.
//
// - R-CF-02: the coordinator declares per proposal before the knock-out
//   read, and sees only the title and the neutral summary before that.
// - R-EV-01: a failed criterion needs its reason, and an ineligible
//   proposal is offered no assignment.
// - R-CF-03, SoD-10 and SoD-11: the assignment checks show pass or fail
//   only, with no account and no reason.
// - I-07, I-08 and NOTE 3: the board records the stage 1 close and has
//   no control that states its outcome.
// - R-CF-04: notifiable conflicts reach the coordinator as drafts.

import { declaredHere, markDeclared } from "./declared.js";
import { findingsStatusSection } from "../findings/panel.js";
import { h, type Child } from "../core/dom.js";
import type { I18n } from "../core/i18n.js";
import {
  FormErrors,
  buttonEl,
  contentSection,
  declarationBody,
  declarationForm,
  declarationViewSection,
  formEl,
  frame,
  guarded,
  idRoute,
  isContentView,
  isDeclarationView,
  pageI18n,
  proposalName,
  radio,
  readOp,
  selectEl,
  textArea,
  whileBusy,
  writeOp,
  type ContentView,
  type Frame,
  type JudgingPage,
  type PageEnv,
  type ShownError,
  type StateTag,
  stateChip,
  callName,
  titleWithCall,
} from "../reviewer/kit.js";
import { readKnockOut, type KnockOutChoice } from "./forms.js";
import { COORDINATOR_LABELS } from "./messages.en.js";
import {
  isAssignmentView,
  isBoard,
  isIntakeQueue,
  isNotifiableList,
  type AssignmentView,
  type ProposalRow,
} from "./models.js";

function param(params: Readonly<Record<string, string>>, name: string): string {
  return params[name] ?? "";
}

function headRow(t: I18n, ids: readonly string[]): HTMLElement {
  return h("thead", {}, [h("tr", {}, ids.map((id) => h("th", { scope: "col" }, [t.label(id)])))]);
}

// ---------------------------------------------------------------------------
// Intake
// ---------------------------------------------------------------------------

/**
 * The action links of one intake row, by its state (review finding U7):
 * the declaration and the knock-out check while the proposal is
 * SUBMITTED, and its reviewer assignments in every state where the
 * coordinator may read them (`fstp-access` `ASSIGNABLE`). An INELIGIBLE
 * proposal gets no link, since R-EV-01 gives it no further review.
 */
export function intakeActions(state: string): readonly ("declare" | "knock_out" | "assignments")[] {
  const out: ("declare" | "knock_out" | "assignments")[] = [];
  if (state === "SUBMITTED") {
    out.push("declare", "knock_out");
  }
  if (INTAKE_ASSIGNABLE.has(state)) {
    out.push("assignments");
  }
  return out;
}

/** The states in which the coordinator reads a proposal's assignments (`fstp-access` `ASSIGNABLE`). */
const INTAKE_ASSIGNABLE: ReadonlySet<string> = new Set([
  "SUBMITTED",
  "STAGE1",
  "NOT_SELECTED",
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "DECLINED",
  "NEGOTIATION",
  "WITHDRAWN",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "TERMINATED",
]);

/** The action links of one intake row, or a note that the row has none. */
function intakeLinks(t: I18n, proposal: string, state: string): HTMLElement {
  const paths = {
    declare: `/app/proposals/${proposal}/declaration`,
    knock_out: `/app/proposals/${proposal}/knock-out`,
    assignments: `/app/proposals/${proposal}/assignments`,
  } as const;
  const actions = intakeActions(state);
  if (actions.length === 0) {
    return h("p", {}, [t.label("coord.intake.no_action", { id: proposal })]);
  }
  // The content route refuses until the declaration is recorded, so the
  // knock-out check sits behind a disclosure button, "After your
  // declaration". It shows at once when this document recorded the
  // declaration (`declared.ts`).
  return h(
    "ul",
    {},
    actions.map((a) => {
      const link = h("a", { href: paths[a] }, [t.label(`coord.intake.${a}`, { id: proposal })]);
      if (a !== "knock_out" || declaredHere(proposal)) {
        return h("li", {}, [link]);
      }
      const id = `knock-out-${proposal}`;
      const shown = h("span", { id, hidden: true }, [link]);
      const toggle = h(
        "button",
        { type: "button", class: "btn--small", "aria-expanded": "false", "aria-controls": id },
        [t.label("coord.intake.after_declaration", { id: proposal })],
      );
      toggle.addEventListener("click", () => {
        const open = shown.hidden;
        shown.hidden = !open;
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      return h("li", {}, [toggle, " ", shown]);
    }),
  );
}

async function mountIntake(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COORDINATOR_LABELS);
  const call = param(params, "call");
  const f = frame(env, t, t.label("coord.intake.title"));
  await guarded(f, async () => {
    const queue = await readOp(env, "intake.queue", { call }, isIntakeQueue);
    if (!queue.ok) {
      f.problem(queue.problem);
      f.show([]);
      return;
    }
    const rows = queue.data.proposals;
    if (rows.length === 0) {
      f.show([h("p", {}, [t.label("coord.intake.none")])]);
      return;
    }
    f.show([
      h("table", { id: "intake-table" }, [
        h("caption", {}, [t.label("coord.intake.caption")]),
        headRow(t, ["coord.col_proposal", "coord.col_title", "coord.col_state", "coord.col_pages"]),
        h(
          "tbody",
          {},
          rows.map((r) =>
            h("tr", { "data-proposal": r.proposal, "data-state": r.state }, [
              h("th", { scope: "row" }, [proposalName(t, r.proposal)]),
              h("td", {}, [r.title]),
              h("td", {}, [stateChip(t, r.state)]),
              h("td", {}, [intakeLinks(t, r.proposal, r.state)]),
            ]),
          ),
        ),
      ]),
    ]);
  });
}

// ---------------------------------------------------------------------------
// Declaration (R-CF-02)
// ---------------------------------------------------------------------------

async function mountDeclaration(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COORDINATOR_LABELS);
  const proposal = param(params, "proposal");
  const f = frame(env, t, t.label("coord.decl.title", { id: proposal }));
  await guarded(f, async () => {
    const view = await readOp(env, "review.declaration_view", { proposal }, isDeclarationView);
    if (!view.ok) {
      f.problem(view.problem);
      f.show([]);
      return;
    }
    // The three steps of the eligibility check (`coordinator-conflict`
    // prototype). Reading and recording open on the knock-out page once
    // the declaration of no conflict is recorded (R-CF-02); the steps
    // change in place when it is.
    const section = declarationViewSection(t, view.data);
    const read = h("div", {}, [h("p", {}, [t.label("coord.decl.locked")])]);
    const record = h("div", {}, [h("p", {}, [t.label("coord.decl.locked")])]);
    const step = (id: string, label: string, body: Child[]): HTMLElement =>
      h("section", { id, "aria-labelledby": `${id}-heading` }, [h("h2", { id: `${id}-heading` }, [label]), ...body]);
    const declare = h("div", {}, [
      section,
      declarationForm(
        t,
        f,
        async (d) => {
          const answer = await writeOp(env, "review.declare_proposal", { proposal }, declarationBody(d));
          if (!answer.ok && !d.conflicted) {
            // A second declaration of no conflict is refused. The link
            // then says when it applies, and the page claims nothing.
            const ko = `/app/proposals/${proposal}/knock-out`;
            record.replaceChildren(
              h("p", {}, [h("a", { href: ko }, [t.label("coord.decl.declared_before", { id: proposal })])]),
            );
          }
          return answer;
        },
        async (d) => {
          declare.replaceChildren(section);
          if (!d.conflicted) {
            markDeclared(proposal);
          }
          if (d.conflicted) {
            read.replaceChildren(h("p", {}, [t.label("coord.decl.conflicted")]));
            record.replaceChildren(h("p", {}, [t.label("coord.decl.conflicted")]));
            return;
          }
          const ko = `/app/proposals/${proposal}/knock-out`;
          read.replaceChildren(h("p", {}, [h("a", { href: ko }, [t.label("coord.decl.read", { id: proposal })])]));
          record.replaceChildren(h("p", {}, [h("a", { href: ko }, [t.label("coord.decl.next", { id: proposal })])]));
        },
      ),
    ]);
    f.show([
      step("step-declare", t.label("coord.decl.step_declare"), [declare]),
      step("step-read", t.label("coord.decl.step_read"), [read]),
      step("step-record", t.label("coord.decl.step_record"), [record]),
    ]);
  });
}

// ---------------------------------------------------------------------------
// Knock-out (R-EV-01)
// ---------------------------------------------------------------------------

/**
 * The state of `proposal` after a knock-out: its row in the intake queue
 * of `call`, else the assignment view, which answers in INELIGIBLE too.
 * Null when neither holds it.
 */
async function stateAfterKnockOut(env: PageEnv, call: string, proposal: string): Promise<StateTag | null> {
  const queue = await readOp(env, "intake.queue", { call }, isIntakeQueue);
  const row: ProposalRow | undefined = queue.ok ? queue.data.proposals.find((r) => r.proposal === proposal) : undefined;
  if (row !== undefined) {
    return row.state;
  }
  const view = await readOp(env, "review.assignments", { proposal }, isAssignmentView);
  return view.ok ? view.data.state : null;
}

function knockOutForm(
  env: PageEnv,
  t: I18n,
  f: Frame,
  view: ContentView,
  criteria: readonly { readonly id: string; readonly text: string }[],
): HTMLFormElement {
  const groups = criteria.map((c) => {
    const pass = radio(`knockout-${c.id}-pass`, `knockout-${c.id}`, "pass", t.label("coord.ko.pass"));
    const fail = radio(`knockout-${c.id}-fail`, `knockout-${c.id}`, "fail", t.label("coord.ko.fail"));
    const legend = h("legend", {}, [c.text]);
    return { criterion: c, pass, fail, legend, root: h("fieldset", {}, [legend, pass.root, fail.root]) };
  });
  const reason = textArea("knockout-reason", t.label("coord.ko.reason"));
  const submit = buttonEl("knockout-submit", "submit", t.label("coord.ko.submit"));
  const form = formEl("knockout-form", [
    h("h2", { id: "knockout-heading" }, [t.label("coord.ko.heading")]),
    h("p", {}, [t.label("coord.ko.intro")]),
    ...groups.map((g) => g.root),
    reason.root,
    submit,
  ]);
  form.setAttribute("aria-labelledby", "knockout-heading");
  const errors = new FormErrors(form, "knockout-errors", t);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const results: Record<string, KnockOutChoice> = {};
        for (const g of groups) {
          results[g.criterion.id] = g.pass.control.checked ? "pass" : g.fail.control.checked ? "fail" : null;
        }
        const read = readKnockOut(
          criteria.map((c) => c.id),
          { results, reason: reason.control.value },
        );
        if (!read.ok) {
          errors.show(
            read.errors.map((e): ShownError => {
              const g = groups.find((x) => x.criterion.id === e.field);
              return g === undefined
                ? { control: reason.control, message: t.label("coord.ko.err_reason") }
                : {
                    control: g.pass.control,
                    message: t.label("coord.ko.err_choice", { text: g.criterion.text }),
                    after: g.legend,
                  };
            }),
          );
          return;
        }
        errors.clear();
        f.clearAlert();
        const answer = await writeOp(env, "review.knock_out", { proposal: view.proposal }, read.value);
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        f.status(t.label("coord.ko.recorded"));
        const state = await stateAfterKnockOut(env, view.call, view.proposal);
        if (state !== null) {
          f.state(state);
        }
        f.show([contentSection(t, view)]);
      }),
    );
  });
  return form;
}

async function mountKnockOut(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COORDINATOR_LABELS);
  const proposal = param(params, "proposal");
  const f = frame(env, t, t.label("coord.ko.title", { id: proposal }));
  await guarded(f, async () => {
    const content = await readOp(env, "review.read_content", { proposal }, isContentView);
    if (!content.ok) {
      f.problem(content.problem);
      f.show([
        h("p", {}, [
          h("a", { href: `/app/proposals/${proposal}/declaration` }, [t.label("coord.ko.declare_first")]),
        ]),
      ]);
      return;
    }
    const view = content.data;
    f.state(view.state);
    if (view.state !== "SUBMITTED") {
      f.show([contentSection(t, view)]);
      return;
    }
    const queue = await readOp(env, "intake.queue", { call: view.call }, isIntakeQueue);
    if (!queue.ok) {
      f.problem(queue.problem);
      f.show([contentSection(t, view)]);
      return;
    }
    f.show([contentSection(t, view), knockOutForm(env, t, f, view, queue.data.knock_out)]);
  });
}

// ---------------------------------------------------------------------------
// Assignment and admission (R-CF-03, SoD-10, SoD-11)
// ---------------------------------------------------------------------------

/** States in which reviewers may still be assigned. Interim, pending Daniel. */
const ASSIGNABLE: ReadonlySet<string> = new Set(["SUBMITTED", "STAGE1", "STAGE2"]);

function checksSection(t: I18n, v: AssignmentView): HTMLElement {
  const outcome = (o: "pass" | "fail") => (o === "pass" ? t.label("coord.assign.pass") : t.label("coord.assign.fail"));
  return h("section", { "aria-labelledby": "checks-heading" }, [
    h("h2", { id: "checks-heading" }, [t.label("coord.assign.checks")]),
    h("p", { id: "check-p39", "data-check": v.checks.p39 }, [
      t.label("coord.assign.p39", { outcome: outcome(v.checks.p39) }),
    ]),
    h("p", { id: "check-proximity", "data-check": v.checks.proximity }, [
      t.label("coord.assign.proximity", { outcome: outcome(v.checks.proximity) }),
    ]),
  ]);
}

async function mountAssignments(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COORDINATOR_LABELS);
  const proposal = param(params, "proposal");
  const f = frame(env, t, t.label("coord.assign.title", { id: proposal }));
  const render = async (): Promise<void> => {
    const view = await readOp(env, "review.assignments", { proposal }, isAssignmentView);
    if (!view.ok) {
      f.problem(view.problem);
      f.show([]);
      return;
    }
    const v = view.data;
    f.state(v.state);
    const parts: Child[] = [checksSection(t, v)];
    const open = ASSIGNABLE.has(v.state);
    const assigned = v.assigned.map((a) => {
      const item: Child[] = [a.label];
      if (open) {
        const remove = buttonEl(`unassign-${a.assignment}`, "button", t.label("coord.assign.remove", { member: a.label }));
        remove.addEventListener("click", () => {
          void guarded(f, () =>
            whileBusy(remove, async () => {
              f.clearAlert();
              const answer = await writeOp(env, "review.unassign", { assignment: a.assignment }, undefined);
              if (!answer.ok) {
                f.problem(answer.problem);
                return;
              }
              f.status(t.label("coord.assign.removed"));
              await render();
            }),
          );
        });
        item.push(" ", remove);
      }
      return h("li", {}, item);
    });
    parts.push(
      h("section", { "aria-labelledby": "assigned-heading" }, [
        h("h2", { id: "assigned-heading" }, [t.label("coord.assign.assigned")]),
        assigned.length === 0 ? h("p", {}, [t.label("coord.assign.none")]) : h("ul", { id: "assigned-list" }, assigned),
      ]),
    );
    if (!open) {
      parts.push(h("p", {}, [t.label("coord.assign.closed")]));
      f.show(parts);
      return;
    }
    const select = selectEl({ id: "assign-reviewer", name: "assign-reviewer" }, [
      h("option", { value: "" }, [t.label("coord.assign.choose")]),
      ...v.candidates.map((c) => h("option", { value: c.account }, [c.label])),
    ]);
    const submit = buttonEl("assign-submit", "submit", t.label("coord.assign.submit"));
    const form = formEl("assign-form", [
      h("div", { class: "fstp-field" }, [h("label", { for: "assign-reviewer" }, [t.label("coord.assign.reviewer")]), select]),
      submit,
    ]);
    const errors = new FormErrors(form, "assign-errors", t);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void guarded(f, () =>
        whileBusy(submit, async () => {
          const reviewer = select.value;
          if (reviewer === "") {
            errors.show([{ control: select, message: t.label("coord.assign.err_reviewer") }]);
            return;
          }
          errors.clear();
          f.clearAlert();
          const answer = await writeOp(env, "review.assign", { proposal }, { reviewer, kind: { type: "Reviewer" } });
          if (!answer.ok) {
            f.problem(answer.problem);
            return;
          }
          f.status(t.label("coord.assign.assigned_one"));
          await render();
        }),
      );
    });
    parts.push(form);
    if (v.state === "SUBMITTED") {
      const admit = buttonEl("admit-submit", "button", t.label("coord.assign.admit"));
      admit.addEventListener("click", () => {
        void guarded(f, () =>
          whileBusy(admit, async () => {
            f.clearAlert();
            const answer = await writeOp(env, "review.admit", { proposal }, {});
            if (!answer.ok) {
              f.problem(answer.problem);
              return;
            }
            f.status(t.label("coord.assign.admitted"));
            await render();
          }),
        );
      });
      parts.push(admit);
    }
    f.show(parts);
  };
  await guarded(f, render);
}

// ---------------------------------------------------------------------------
// Board and the stage 1 close (I-07, I-08, NOTE 3)
// ---------------------------------------------------------------------------

/**
 * The states a proposal reaches only after its selection for stage 2
 * (`02-domain/state-machine.md`): STAGE2 and every state after it.
 * NOT_SELECTED and WITHDRAWN are left out, since either may come before
 * or after the selection.
 */
const AFTER_SELECTION: ReadonlySet<StateTag> = new Set<StateTag>([
  "STAGE2",
  "RANKED",
  "IRC_REVIEW",
  "DEFERRED",
  "DECLINED",
  "NEGOTIATION",
  "GRANTED",
  "IN_EXECUTION",
  "COMPLETED",
  "TERMINATED",
]);

async function mountBoard(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COORDINATOR_LABELS);
  const call = param(params, "call");
  const f = frame(env, t, t.label("coord.board.title", { call: callName(t, call) }));
  titleWithCall(f, t, call, (name) => t.label("coord.board.title", { call: name }));
  const render = async (): Promise<void> => {
    const board = await readOp(env, "call.board", { call }, isBoard);
    if (!board.ok) {
      f.problem(board.problem);
      f.show([]);
      return;
    }
    if (board.data.length === 0) {
      f.show([h("p", {}, [t.label("coord.board.none")])]);
      return;
    }
    const rows = board.data.map((r) => {
      const action: Child[] = [];
      if (r.state === "STAGE1") {
        // NOTE 3: the coordinator records the close; the button states no outcome.
        const close = buttonEl(`close-stage1-${r.proposal}`, "button", t.label("coord.board.close", { id: r.proposal }));
        close.addEventListener("click", () => {
          void guarded(f, () =>
            whileBusy(close, async () => {
              f.clearAlert();
              const answer = await writeOp(env, "review.close_stage1", { proposal: r.proposal }, {});
              if (!answer.ok) {
                f.problem(answer.problem);
                return;
              }
              f.status(t.label("coord.board.closed", { id: r.proposal }));
              await render();
            }),
          );
        });
        action.push(close);
      }
      return h("tr", { "data-proposal": r.proposal, "data-state": r.state }, [
        h("th", { scope: "row" }, [proposalName(t, r.proposal)]),
        h("td", {}, [r.title]),
        h("td", {}, [stateChip(t, r.state)]),
        h("td", {}, action),
      ]);
    });
    // NOTE 3, R-EV-01: a selected proposal keeps counting as selected once
    // it moves past STAGE2. Each close is recorded on its own, so while a
    // proposal still waits for its close the page says the counts cover
    // the closes recorded so far, and are no final result yet.
    const selected = board.data.filter((r) => AFTER_SELECTION.has(r.state)).length;
    const notSelected = board.data.filter((r) => r.state === "NOT_SELECTED").length;
    const waiting = board.data.filter((r) => r.state === "STAGE1").length;
    const ranked = board.data.some((r) => AFTER_SELECTION.has(r.state) && r.state !== "STAGE2");
    // M7 lane L-UI: findings pending or a count per proposal, never a statement.
    const assessment = await findingsStatusSection(env, call);
    f.show([
      h("h2", { id: "board-summary" }, [
        t.label("coord.board.summary", { selected: String(selected), not_selected: String(notSelected) }),
      ]),
      ...(waiting > 0
        ? [
            h("p", { id: "board-pending", class: "fstp-hint" }, [
              t.label(waiting === 1 ? "coord.board.pending_one" : "coord.board.pending_other", { count: String(waiting) }),
            ]),
          ]
        : []),
      ...(ranked ? [h("p", { class: "fstp-hint" }, [t.label("coord.board.summary_note")])] : []),
      h("p", {}, [t.label("coord.board.note")]),
      h("table", { id: "board-table" }, [
        h("caption", {}, [t.label("coord.board.caption")]),
        headRow(t, ["coord.col_proposal", "coord.col_title", "coord.col_state", "coord.col_action"]),
        h("tbody", {}, rows),
      ]),
      assessment,
    ]);
  };
  await guarded(f, render);
}

// ---------------------------------------------------------------------------
// Notifiable conflicts (R-CF-04)
// ---------------------------------------------------------------------------

async function mountNotifiable(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COORDINATOR_LABELS);
  const call = param(params, "call");
  const f = frame(env, t, t.label("coord.notif.title", { call: callName(t, call) }));
  titleWithCall(f, t, call, (name) => t.label("coord.notif.title", { call: name }));
  await guarded(f, async () => {
    const drafts = await readOp(env, "review.notifiable_conflicts", { call }, isNotifiableList);
    if (!drafts.ok) {
      f.problem(drafts.problem);
      f.show([]);
      return;
    }
    const items = drafts.data.map((d) =>
      h("li", { "data-proposal": d.proposal }, [t.label("coord.notif.draft", { id: d.proposal })]),
    );
    f.show([
      h("p", {}, [t.label("coord.notif.intro")]),
      h("ul", { id: "notifiable-list" }, items),
      ...(items.length === 0 ? [h("p", {}, [t.label("coord.notif.none")])] : []),
    ]);
  });
}

/** The FSTP coordinator's pages (J5). */
export const COORDINATOR_PAGES: readonly JudgingPage[] = [
  { route: idRoute("coordinator.intake", "/app/calls/{call}/intake", ["call"]), mount: mountIntake },
  {
    route: idRoute("coordinator.declaration", "/app/proposals/{proposal}/declaration", ["proposal"]),
    mount: mountDeclaration,
  },
  { route: idRoute("coordinator.knock_out", "/app/proposals/{proposal}/knock-out", ["proposal"]), mount: mountKnockOut },
  {
    route: idRoute("coordinator.assignments", "/app/proposals/{proposal}/assignments", ["proposal"]),
    mount: mountAssignments,
  },
  { route: idRoute("coordinator.board", "/app/calls/{call}/board", ["call"]), mount: mountBoard },
  {
    route: idRoute("coordinator.notifiable", "/app/calls/{call}/notifiable-conflicts", ["call"]),
    mount: mountNotifiable,
  },
];
