// The parts of the Planning Studio pages, "Programme set-up" and
// "Approval and publication" (`SPEC/12-journey-ui.md` section 8.2;
// `docs/design/05-programme-staff-studio.md`; the `planning-studio` and
// `seal-ceremony` prototypes).
//
// Each builder takes what a server read gave and makes no request, so
// the Node tests can build it. The pages in `pages.ts` read and call.
//
// - The step navigation `#creator-steps` groups the 11 creator steps
//   under the five plain headings, each with its studio name as the
//   secondary `.voyage-label` line. One `li[data-step][data-condition]`
//   per step. A locked step holds no link and is not focusable. It
//   carries `data-locked="true"` and says what it waits for.
// - `#creator-step-next` is a link only when the current step validated.

import { VISUALLY_HIDDEN_CLASS } from "../core/a11y.js";
import { h, safeUrl } from "../core/dom.js";
import type { Label } from "../core/i18n.js";
import { fieldLabel } from "../creator/editor.js";
import { labelOr, t } from "../creator/i18n.js";
import { CREATOR_STEPS, activationGate, type ProposalRow, type Report } from "../creator/model.js";
import type { MyRoles } from "../home/model.js";
import {
  STUDIOS,
  awaitingConfirmation,
  mayApproveCalls,
  returnsCallToDraft,
  studioOf,
  type CallRow,
  type StepId,
  type StepState,
} from "./model.js";

/** The page paths of the studio. */
export const STUDIO_PATHS = {
  overview: (p: string): string => `/app/programmes/${p}/studio`,
  approval: (p: string): string => `/app/programmes/${p}/studio/approval`,
  guide: (p: string): string => `/app/programmes/${p}/studio/guide`,
} as const;

/** The creator step page of `step` (`creator/pages/common.ts` `PATHS.step`). */
function stepPath(p: string, step: string): string {
  return `/app/programmes/${p}/creator/${step}`;
}

/** The import review of `p` (`creator/pages/common.ts` `PATHS.imports`). */
function importsPath(p: string): string {
  return `/app/programmes/${p}/creator/imports`;
}

/** A same-origin link with visible text. */
function link(path: string, text: Label, attrs: Readonly<Record<string, string>> = {}): HTMLElement {
  const href = safeUrl(path);
  return href === null ? h("span", attrs, [text]) : h("a", { ...attrs, href }, [text]);
}

/** The name of creator step `id`. */
function stepName(id: string): Label {
  return labelOr(`creator.step.${id}`, () => t.label("creator.step.unnamed"));
}

/** The number of creator step `id`, as text. */
function numberOf(id: string): string {
  return String(CREATOR_STEPS.find((s) => s.id === id)?.number ?? 0);
}

const GLYPH: Readonly<Record<StepState["condition"], string>> = {
  valid: "✓",
  warnings: "!",
  failures: "✗",
  unknown: "○",
};

/** One step of the navigation. */
function stepItem(p: string, s: StepState, current: StepId | null, states: readonly StepState[]): HTMLElement {
  const status = s.open ? t.label(`studio.status.${s.condition}`) : t.label("studio.status.locked");
  const text = t.label("studio.step.item", { n: String(s.number), name: stepName(s.id), status });
  const mark = h("span", { class: "mark", "aria-hidden": "true" }, [s.open ? GLYPH[s.condition] : GLYPH.unknown]);
  const attrs: Record<string, string> = { "data-step": s.id, "data-condition": s.condition };
  const here = s.id === current;
  const words: (HTMLElement | string)[] = [mark, " ", text];
  if (here) words.push(h("span", { class: VISUALLY_HIDDEN_CLASS }, [t.label("studio.step.current")]));
  if (s.open || here) {
    const linkAttrs: Record<string, string> = here ? { "aria-current": "step" } : {};
    const href = safeUrl(stepPath(p, s.id));
    const target = href === null ? h("span", linkAttrs, words) : h("a", { ...linkAttrs, href }, words);
    if (!s.open) attrs["data-locked"] = "true";
    return h("li", attrs, [target]);
  }
  attrs["data-locked"] = "true";
  // A step waits for an earlier step's failures, or for a report at all.
  const blocker = states.find((x) => x.id === s.waitsFor);
  const reason =
    blocker === undefined || blocker.condition === "unknown"
      ? t.label("studio.step.waits_report")
      : t.label("studio.step.waits", { n: String(blocker.number) });
  return h("li", attrs, [h("span", { "aria-disabled": "true" }, words), " ", h("span", { class: "fstp-hint" }, [reason])]);
}

/**
 * The step navigation, `nav#creator-steps` "Set-up steps": the five
 * studios as an ordered list, each with its plain heading, its studio
 * name and its steps. `current` is the step of the page, or null.
 */
export function studioNav(p: string, states: readonly StepState[], current: StepId | null): HTMLElement {
  const groups = STUDIOS.map((g) =>
    h("li", { "data-studio": g.id }, [
      h("h2", {}, [t.label(`studio.group.${g.id}`)]),
      h("p", { class: "voyage-label" }, [t.label(`studio.voyage.${g.id}`)]),
      h(
        "ol",
        {},
        states.filter((s) => g.steps.includes(s.id)).map((s) => stepItem(p, s, current, states)),
      ),
    ]),
  );
  return h("nav", { id: "creator-steps", class: "studio-nav", "aria-label": t.label("creator.steps.nav") }, [
    h("ol", {}, groups),
  ]);
}

/** "Evaluation, money and contract, step 6 of 11". */
export function kicker(step: StepId): Label {
  const g = studioOf(step);
  return t.label("studio.kicker", {
    group: g === null ? "" : t.label(`studio.group.${g.id}`),
    n: numberOf(step),
    total: String(CREATOR_STEPS.length),
  });
}

/**
 * The way to the step after `step`: the link `#creator-step-next` once
 * the report says `step` validated, else a line that says it is locked.
 */
export function nextControl(p: string, step: StepId, states: readonly StepState[]): HTMLElement {
  const i = states.findIndex((s) => s.id === step);
  const next = i < 0 ? undefined : states[i + 1];
  if (next === undefined) return h("span", {});
  if (next.open) return link(stepPath(p, next.id), t.label("creator.step.next"), { id: "creator-step-next" });
  return h("span", { class: "fstp-hint", "data-locked": "true" }, [t.label("studio.next_locked")]);
}

/** The line a step page shows when it was opened before an earlier step validated. */
export function notOpenNote(): HTMLElement {
  return h("p", { class: "fstp-note", role: "status", "data-note": "not-open" }, [t.label("studio.not_open")]);
}

/**
 * The note an editor of `key` carries before the save (R-PC-03 NOTE):
 * once the programme is active, an edit of the call text, P-01 or P-09
 * returns each approved call to DRAFT. Null for any other field, and on
 * a programme not yet active, which has no call.
 */
export function afterApprovalNote(key: string, status: "draft" | "active"): HTMLElement | null {
  if (status !== "active" || !returnsCallToDraft(key)) return null;
  return h("p", { class: "fstp-note", "data-note": "returns-to-draft" }, [t.label("studio.after_approval")]);
}

/** The I-12 note of a step page of an active programme. */
export function frozenNote(): HTMLElement {
  return h("p", { class: "fstp-note", "data-note": "frozen" }, [t.label("studio.frozen")]);
}

/** The programme status of the draft read, as a word. */
export function programmeStatus(status: "draft" | "requested" | "active"): Label {
  return t.label(`studio.programme.${status}`);
}

/** What the final report allows (I-66): `unknown` when no report was read. */
export type Gate = "failures" | "warnings" | "clean" | "unknown";

/** The gate of `report`: failures block, then unacknowledged warnings. */
export function gateOf(report: Report | null): Gate {
  if (report === null) return "unknown";
  const g = activationGate(report.results);
  return g.failures > 0 ? "failures" : g.unacknowledged > 0 ? "warnings" : "clean";
}

/** The line that says what the final report allows, with its counts. */
export function gateLine(report: Report | null): HTMLElement {
  if (report === null) return h("p", {}, [t.label("studio.activation.unknown")]);
  const g = activationGate(report.results);
  return h("p", { "data-gate": gateOf(report) }, [
    g.failures > 0
      ? t.label("studio.activation.failures", { n: String(g.failures) })
      : g.unacknowledged > 0
        ? t.label("studio.activation.warnings", { n: String(g.unacknowledged) })
        : t.label("studio.activation.clean"),
  ]);
}

/**
 * Step 1 of "Approval and publication", `section#seal-activation`
 * (I-66, I-67, R-PG-03). `data-gate` says what the report allows:
 * `failures` and `warnings` leave no request, `clean` links the request
 * on the review step, `unknown` means no report was read.
 */
export function activationPanel(p: string, report: Report | null, status: "draft" | "requested" | "active"): HTMLElement {
  const parts: HTMLElement[] = [h("h2", { id: "seal-activation-title" }, [t.label("studio.activation.title")])];
  let gate: Gate | "active" = "unknown";
  if (status === "active") {
    gate = "active";
    parts.push(h("p", { role: "status" }, [t.label("studio.activation.active")]));
  } else if (report === null) {
    parts.push(gateLine(null));
  } else {
    gate = gateOf(report);
    parts.push(gateLine(report));
    if (status === "requested") {
      parts.push(h("p", { role: "status" }, [t.label("studio.activation.requested")]));
    } else if (gate === "clean") {
      parts.push(
        h("p", {}, [
          link(stepPath(p, "review"), t.label("studio.activation.request_link"), { "data-action": "request-activation" }),
        ]),
      );
    } else {
      parts.push(h("p", {}, [link(stepPath(p, "review"), t.label("studio.activation.review_link"))]));
    }
  }
  if (status !== "active") parts.push(h("p", {}, [t.label("studio.activation.approver")]));
  return h("section", { id: "seal-activation", "aria-labelledby": "seal-activation-title", "data-gate": gate, "data-status": status }, parts);
}

/** The name of a call: its published title, else "Call" and its number. */
function callName(c: CallRow, name: (call: string) => string): string {
  return c.title ?? name(c.call);
}

/**
 * Step 2 of "Approval and publication", `section#seal-calls` (R-PC-02,
 * R-PC-03). Each listed call shows its state and whether the cell says
 * it is open. Only a programme manager of the programme gets the
 * approve and publish controls. `form` is the `callControls` root the
 * page wired, or null for unwired controls.
 */
export function callsPanel(
  roles: MyRoles,
  p: string,
  calls: readonly CallRow[],
  name: (call: string) => string = (c) => c,
  form: HTMLElement | null = null,
): HTMLElement {
  const items = calls.map((c) =>
    h("li", { "data-call": c.call, "data-state": c.state }, [
      t.label("studio.calls.item", {
        call: callName(c, name),
        state: c.state,
        open: c.open ? t.label("studio.calls.open") : t.label("studio.calls.closed"),
      }),
    ]),
  );
  if (items.length === 0) items.push(h("li", {}, [t.label("studio.calls.none")]));
  const parts: HTMLElement[] = [
    h("h2", { id: "seal-calls-title" }, [t.label("studio.calls.title")]),
    h("p", {}, [t.label("studio.calls.intro")]),
    h("ul", { id: "seal-call-list" }, items),
  ];
  if (mayApproveCalls(roles, p)) {
    parts.push(h("p", {}, [t.label("studio.calls.rule")]), h("p", {}, [t.label("studio.calls.unlisted")]), form ?? callControls().root);
  } else {
    parts.push(h("p", { "data-note": "drafter" }, [t.label("studio.calls.drafter")]));
  }
  return h("section", { id: "seal-calls", "aria-labelledby": "seal-calls-title" }, parts);
}

/** The controls of a call approval: the call number, approve and publish. */
export interface CallForm {
  readonly root: HTMLElement;
  readonly number: HTMLElement;
  readonly approve: HTMLElement;
  readonly publish: HTMLElement;
  readonly status: HTMLElement;
}

/** Builds the call approval controls. */
export function callControls(): CallForm {
  const number = h("input", { id: "seal-call-number", type: "text", inputmode: "numeric", autocomplete: "off" });
  const approve = h("button", { type: "button", "data-action": "approve-call", class: "fstp-primary" }, [t.label("studio.calls.approve")]);
  const publish = h("button", { type: "button", "data-action": "publish-call" }, [t.label("studio.calls.publish")]);
  const status = h("p", { id: "seal-call-status", role: "status", class: "fstp-status" });
  const root = h("div", { id: "seal-call-form" }, [
    h("label", { for: "seal-call-number" }, [t.label("studio.calls.number")]),
    number,
    h("div", { class: "fstp-actions" }, [approve, publish]),
    status,
  ]);
  return { root, number, approve, publish, status };
}

/** The "Change after approval" section (R-PC-03 NOTE), shown before any edit. */
export function changePanel(): HTMLElement {
  const note = afterApprovalNote("call.text", "active");
  return h("section", { id: "seal-change", "aria-labelledby": "seal-change-title" }, [
    h("h2", { id: "seal-change-title" }, [t.label("studio.change.title")]),
    ...(note === null ? [] : [note]),
  ]);
}

/**
 * The imported values, `section#studio-imports` (I-65, R-PG-02): one
 * `li[data-awaiting="<field>"]` per proposal no programme manager has
 * resolved, and the link to the import review.
 */
export function importsPanel(p: string, rows: readonly ProposalRow[] | null): HTMLElement {
  const parts: HTMLElement[] = [h("h2", { id: "studio-imports-title" }, [t.label("studio.imports.title")])];
  if (rows === null) {
    parts.push(h("p", {}, [t.label("studio.imports.unavailable")]));
  } else {
    const waiting = awaitingConfirmation(rows);
    if (waiting.length === 0) {
      parts.push(h("p", {}, [t.label("studio.imports.none")]));
    } else {
      parts.push(
        h("p", {}, [t.label("studio.imports.waiting")]),
        h(
          "ul",
          {},
          waiting.map((r) => h("li", { "data-awaiting": r.field }, [t.label("studio.imports.awaiting", { field: fieldLabel(r.field) })])),
        ),
      );
    }
    if (rows.length > 0) parts.push(h("p", {}, [link(importsPath(p), t.label("studio.imports.link"))]));
  }
  return h("section", { id: "studio-imports", "aria-labelledby": "studio-imports-title" }, parts);
}

/**
 * The calls a change affects after activation, `section#studio-impact`
 * (R-PG-04), with the I-12 rule. `calls` is the impact read, null when
 * the cell could not answer it, which is never shown as an empty list,
 * or undefined before the read.
 */
export function impactPanel(calls: readonly string[] | null | undefined, name: (call: string) => string): HTMLElement {
  const parts: HTMLElement[] = [h("h2", { id: "studio-impact-title" }, [t.label("studio.impact.title")])];
  if (calls === undefined) {
    parts.push(h("p", {}, [t.label("studio.impact.ask")]));
  } else if (calls === null) {
    parts.push(h("p", {}, [t.label("studio.impact.unavailable")]));
  } else if (calls.length === 0) {
    parts.push(h("p", {}, [t.label("studio.impact.none")]));
  } else {
    parts.push(
      h("p", {}, [t.label("studio.impact.intro")]),
      h("ul", {}, calls.map((c) => h("li", { "data-affected": c }, [name(c)]))),
    );
  }
  parts.push(h("p", {}, [t.label("studio.impact.next_call")]));
  return h(
    "section",
    {
      id: "studio-impact",
      "aria-labelledby": "studio-impact-title",
      "data-impact": calls === undefined ? "not_read" : calls === null ? "unavailable" : "listed",
    },
    parts,
  );
}
