// What the creator pages share: the step navigation, the paths of the
// creator pages, and the draft and report reads.
//
// The step navigation is the Planning Studio's (`studio/view.ts`): the
// 11 steps grouped under the five studios of `SPEC/12-journey-ui.md`
// section 8.2, each with the state the creator's report gives it.

import { h, safeUrl } from "../../core/dom.js";
import type { Label } from "../../core/i18n.js";
import { fieldLabel } from "../editor.js";
import { labelOr, t } from "../i18n.js";
import { readDraft, readReport, type CreatorStep, type Draft, type Report } from "../model.js";
import { call, report } from "../ops.js";
import { stepStates, type StepId } from "../../studio/model.js";
import { studioNav } from "../../studio/view.js";

/** The page paths of the creator (e2e contract `APP`, interim). */
export const PATHS = {
  creatorNew: "/app/creator/new",
  approvals: "/app/admin/approvals",
  start: (p: string): string => `/app/programmes/${p}/creator/start`,
  step: (p: string, step: string): string => `/app/programmes/${p}/creator/${step}`,
  imports: (p: string): string => `/app/programmes/${p}/creator/imports`,
  people: (p: string): string => `/app/programmes/${p}/people`,
} as const;

/** The title of creator step `s`, with its number. */
export function stepTitle(s: CreatorStep): Label {
  return t.label("creator.step.title", {
    n: String(s.number),
    name: labelOr(`creator.step.${s.id}`, () => t.label("creator.step.unnamed")),
  });
}

/** A same-origin link with visible text. */
export function link(path: string, text: Label, attrs: Readonly<Record<string, string>> = {}): HTMLElement {
  const href = safeUrl(path);
  return href === null ? h("span", attrs, [text]) : h("a", { ...attrs, href }, [text]);
}

/**
 * The step navigation `#creator-steps` for `report`: one
 * `li[data-step]` per step, the current one marked for assistive
 * technology. A step opens only once every step before it validated.
 */
export function stepNav(p: string, current: StepId, r: Report | null): HTMLElement {
  return studioNav(p, stepStates(r), current);
}

/** Reads the draft of `p`, or shows why not in `alert`. */
export async function loadDraft(p: string, alert: HTMLElement): Promise<Draft | null> {
  const o = await call("creator.get_draft", [p], undefined, (v) => readDraft(v) !== null);
  if (report(alert, o) || o.kind !== "done") return null;
  return readDraft(o.body);
}

/** Reads the validation report of `p`, or shows why not in `alert`. */
export async function loadReport(p: string, alert: HTMLElement): Promise<Report | null> {
  const o = await call("creator.get_report", [p], undefined, (v) => readReport(v) !== null);
  if (report(alert, o) || o.kind !== "done") return null;
  return readReport(o.body);
}

/**
 * The text of a check, with the field it is about and the values it
 * names, such as both amounts of `CapAboveCeiling`.
 */
export function checkText(check: string, values: readonly string[], field: string | null = null): Label {
  const name = labelOr(`creator.check.${check}`, () => t.label("creator.check.unnamed", { check }));
  const about = field === null ? name : t.label("creator.check.field", { check: name, field: fieldLabel(field) });
  return values.length === 0 ? about : t.label("creator.check.values", { check: about, values: values.join(", ") });
}

/**
 * A queue of the page's writes. Each write starts once the one before
 * it settled, so every write names the newest revision.
 */
export function queue(): (run: () => Promise<void>) => Promise<void> {
  let tail: Promise<void> = Promise.resolve();
  return (run) => {
    const next = tail.then(run, run);
    tail = next.catch(() => undefined);
    return next;
  };
}
