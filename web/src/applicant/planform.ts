// The tasks and milestones of a plan version, shared by the plan editor
// (`proposal.record_plan`) and the stage 2 revision (`stage2.revise`).
// Journey J4, R-EV-05, ADR-006.
//
// `RecordPlanVersion` records a plan only with at least one task, a
// milestone in every task, and an amount, a start day and a due day on
// each milestone (`fstp-domain` `proposal/intake.rs` `check_tasks`). So
// the form starts with one task holding one milestone, and the applicant
// adds or removes rows with buttons. A task or milestone that is the
// only one of its kind has no remove button.
//
// Each amount is read by `money.ts` and sent as the ADR-006 string typed,
// never as a number. Each day is a `YYYY-MM-DD` string. The browser
// computes no money: the plan total is the cell's.
//
// Interim, pending lanes W3b and W5: the body is
// `{tasks: [{milestones: [{amount, start, due}]}]}`, every leaf a string.
// The cell assigns the milestone ids and reads each day as that day in
// the call's zone. Activity types and deliverables (P-55, I-47, I-15)
// arrive with the negotiated plan (M5).

import { h } from "../core/dom.js";
import { field, type FormField } from "../core/forms.js";
import { type Label } from "../core/i18n.js";
import { button, fieldError, type SummaryItem, t } from "./ui.js";
import { type Body, dayOf } from "./wire.js";

/**
 * The most tasks a form holds, and the most milestones a task holds.
 * Interim, pending Daniel: bounds that keep one plan on one page.
 */
export const MAX_TASKS = 20;
export const MAX_MILESTONES = 12;

/** One built control with its error element. */
interface Checked<E extends HTMLElement> {
  readonly control: E;
  readonly error: HTMLElement;
}

/** One milestone row. Its ids never change, so summary links stay valid. */
interface MilestoneRow {
  readonly root: HTMLFieldSetElement;
  readonly legend: HTMLElement;
  readonly amount: FormField & { readonly error: HTMLElement };
  readonly start: Checked<HTMLInputElement>;
  readonly due: Checked<HTMLInputElement>;
  readonly remove: HTMLButtonElement;
}

/** One task row. */
interface TaskRow {
  readonly root: HTMLFieldSetElement;
  readonly legend: HTMLElement;
  readonly list: HTMLElement;
  readonly milestones: MilestoneRow[];
  readonly add: HTMLButtonElement;
  readonly remove: HTMLButtonElement;
  /** The next milestone number for its ids. */
  next: number;
}

/** What reading the form gives: the tasks body, or the errors to show. */
export type PlanRead =
  | { readonly ok: true; readonly tasks: Body }
  | { readonly ok: false; readonly errors: readonly SummaryItem[] };

/** A built plan form. */
export interface PlanForm {
  /** The tasks, their milestones and the button that adds a task. */
  readonly root: HTMLElement;
  /** Checks every field, marks each error on its field, and gives the body or the errors. */
  read(): PlanRead;
}

function fieldset(id: string, legend: HTMLElement, kids: readonly HTMLElement[]): HTMLFieldSetElement {
  const el = h("fieldset", { id, class: "fstp-group" }, [legend, ...kids]);
  if (!(el instanceof HTMLFieldSetElement)) {
    throw new TypeError("the document did not create a fieldset");
  }
  return el;
}

/** A labelled date input with its error, described by the shared hint `hint`. */
function dateInput(id: string, label: Label, hint: string): { readonly root: HTMLElement } & Checked<HTMLInputElement> {
  const control = h("input", { id, name: id, type: "date", required: true, "aria-describedby": hint });
  if (!(control instanceof HTMLInputElement)) {
    throw new TypeError("the document did not create an input");
  }
  const error = h("p", { id: `${id}-error`, class: "fstp-error", hidden: true });
  return { root: h("div", { class: "fstp-field" }, [h("label", { for: id }, [label]), error, control]), control, error };
}

/**
 * A plan form whose ids start with `prefix`. A milestone's fields are
 * `<prefix>-t<task>-m<milestone>-{amount,start,due}`, numbered from 1
 * in the order the rows were added.
 */
export function planForm(prefix: string): PlanForm {
  const tasks: TaskRow[] = [];
  const list = h("div", { id: `${prefix}-tasks` });
  const addTask = button(`${prefix}-add-task`, t("plan.add_task"));
  let nextTask = 1;

  /** Writes the position of every row into its legend and button texts. */
  const renumber = (): void => {
    tasks.forEach((task, i) => {
      const n = String(i + 1);
      task.legend.textContent = t("plan.task", { task: n });
      task.add.textContent = t("plan.add_milestone", { task: n });
      task.remove.textContent = t("plan.remove_task", { task: n });
      task.remove.hidden = tasks.length === 1;
      task.add.hidden = task.milestones.length >= MAX_MILESTONES;
      task.milestones.forEach((m, j) => {
        const k = String(j + 1);
        m.legend.textContent = t("plan.milestone", { task: n, milestone: k });
        m.remove.textContent = t("plan.remove_milestone", { task: n, milestone: k });
        m.remove.hidden = task.milestones.length === 1;
      });
    });
    addTask.hidden = tasks.length >= MAX_TASKS;
  };

  const milestone = (task: TaskRow, id: string): MilestoneRow => {
    const hint = `${id}-dates-hint`;
    const amountField = field({ id: `${id}-amount`, label: t("plan.ms.amount"), kind: "amount", required: true });
    const amountHint = h("p", { id: `${id}-amount-hint`, class: "fstp-hint" }, [t("plan.amount_hint")]);
    const amountError = h("p", { id: `${id}-amount-error`, class: "fstp-error", hidden: true });
    amountField.control.setAttribute("aria-describedby", `${id}-amount-hint`);
    amountField.root.insertBefore(amountHint, amountField.control);
    amountField.root.insertBefore(amountError, amountField.control);
    const start = dateInput(`${id}-start`, t("plan.ms.start"), hint);
    const due = dateInput(`${id}-due`, t("plan.ms.due"), hint);
    const remove = button(`${id}-remove`, t("plan.remove_milestone", { task: "", milestone: "" }));
    const legend = h("legend", {});
    const root = fieldset(id, legend, [
      amountField.root,
      h("p", { id: hint, class: "fstp-hint" }, [t("plan.dates_hint")]),
      start.root,
      due.root,
      h("p", {}, [remove]),
    ]);
    const row: MilestoneRow = {
      root,
      legend,
      amount: { root: amountField.root, control: amountField.control, read: amountField.read, error: amountError },
      start,
      due,
      remove,
    };
    remove.addEventListener("click", () => {
      if (task.milestones.length <= 1) {
        return;
      }
      const at = task.milestones.indexOf(row);
      if (at < 0) {
        return;
      }
      task.milestones.splice(at, 1);
      root.remove();
      renumber();
      task.add.focus();
    });
    return row;
  };

  const addMilestone = (task: TaskRow): MilestoneRow | null => {
    if (task.milestones.length >= MAX_MILESTONES) {
      return null;
    }
    const m = milestone(task, `${task.root.id}-m${String(task.next)}`);
    task.next += 1;
    task.milestones.push(m);
    task.list.append(m.root);
    renumber();
    return m;
  };

  const newTask = (): TaskRow | null => {
    if (tasks.length >= MAX_TASKS) {
      return null;
    }
    const id = `${prefix}-t${String(nextTask)}`;
    nextTask += 1;
    const legend = h("legend", {});
    const ms = h("div", {});
    const add = button(`${id}-add-milestone`, t("plan.add_milestone", { task: "" }));
    const remove = button(`${id}-remove`, t("plan.remove_task", { task: "" }));
    const root = fieldset(id, legend, [ms, h("p", { class: "fstp-actions" }, [add, " ", remove])]);
    const task: TaskRow = { root, legend, list: ms, milestones: [], add, remove, next: 1 };
    add.addEventListener("click", () => {
      addMilestone(task)?.amount.control.focus();
    });
    remove.addEventListener("click", () => {
      if (tasks.length <= 1) {
        return;
      }
      const at = tasks.indexOf(task);
      if (at < 0) {
        return;
      }
      tasks.splice(at, 1);
      root.remove();
      renumber();
      addTask.focus();
    });
    tasks.push(task);
    list.append(root);
    addMilestone(task);
    return task;
  };

  addTask.addEventListener("click", () => {
    newTask()?.milestones[0]?.amount.control.focus();
  });
  newTask();

  const read = (): PlanRead => {
    const errors: SummaryItem[] = [];
    const out: Body[] = [];
    tasks.forEach((task, i) => {
      const milestones: Body[] = [];
      task.milestones.forEach((m, j) => {
        const where = { task: String(i + 1), milestone: String(j + 1) };
        const a = m.amount.read();
        const amountMessage = a.ok ? null : t("plan.err.amount", where);
        fieldError(m.amount.control, m.amount.error, amountMessage);
        if (amountMessage !== null) {
          errors.push({ target: m.amount.control, message: amountMessage });
        }
        const start = dayOf(m.start.control.value);
        const startMessage = start === null ? t("plan.err.start", where) : null;
        fieldError(m.start.control, m.start.error, startMessage);
        if (startMessage !== null) {
          errors.push({ target: m.start.control, message: startMessage });
        }
        const due = dayOf(m.due.control.value);
        // Two `YYYY-MM-DD` days compare as strings in calendar order.
        const dueMessage =
          due === null
            ? t("plan.err.due", where)
            : start !== null && due.text < start.text
              ? t("plan.err.due_before_start", where)
              : null;
        fieldError(m.due.control, m.due.error, dueMessage);
        if (dueMessage !== null) {
          errors.push({ target: m.due.control, message: dueMessage });
        }
        if (a.ok && start !== null && due !== null) {
          milestones.push({ amount: a.value, due: due.text, start: start.text });
        }
      });
      out.push({ milestones });
    });
    if (errors.length > 0) {
      return Object.freeze({ ok: false, errors: Object.freeze(errors) });
    }
    return Object.freeze({ ok: true, tasks: out });
  };

  const root = h("div", { class: "fstp-plan" }, [list, h("p", {}, [addTask])]);
  return Object.freeze({ root, read });
}
