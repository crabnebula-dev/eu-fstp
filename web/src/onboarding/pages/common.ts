// What the onboarding pages share: their paths, the step statuses and
// the step navigation `#onboarding-steps`.

import { h, safeUrl } from "../../core/dom.js";
import type { Label } from "../../core/i18n.js";
import { call, report } from "../../creator/ops.js";
import { labelOr, t } from "../i18n.js";
import { ONBOARDING_STEPS, openableSteps, readStep, type OnboardingStep, type StepStatus, type StepView } from "../model.js";

/** The page paths of onboarding (e2e contract `APP`, interim beyond the step pages). */
export const PATHS = {
  step: (s: string): string => `/app/admin/onboarding/${s}`,
  summary: "/app/admin/onboarding/summary",
  identity: "/app/me/identity",
  setting: (p: string): string => `/app/admin/settings/${p}`,
} as const;

/** The name of onboarding step `s`. */
export function stepName(s: string): Label {
  return labelOr(`onboarding.step.${s}`, () => t.label("onboarding.step.unnamed"));
}

/** The text of status `s`. */
export function statusText(s: StepStatus | undefined): Label {
  switch (s) {
    case "locked":
      return t.label("onboarding.status.locked");
    case "open":
      return t.label("onboarding.status.open");
    case "saved":
      return t.label("onboarding.status.saved");
    case "validated":
      return t.label("onboarding.status.validated");
    case "skipped":
      return t.label("onboarding.status.skipped");
    case "unavailable":
      return t.label("onboarding.status.unavailable");
    case undefined:
      return t.label("onboarding.status.unknown");
  }
}

/** A same-origin link with visible text. */
export function link(path: string, text: Label, attrs: Readonly<Record<string, string>> = {}): HTMLElement {
  const href = safeUrl(path);
  return href === null ? h("span", attrs, [text]) : h("a", { ...attrs, href }, [text]);
}

/** Every step as the server answers it, or null when a read failed, shown in `alert`. */
export async function loadSteps(alert: HTMLElement): Promise<Map<OnboardingStep, StepView> | null> {
  const outcomes = await Promise.all(
    ONBOARDING_STEPS.map((s) => call("tenant.get_step", [s], undefined, (v) => readStep(v)?.step === s)),
  );
  const out = new Map<OnboardingStep, StepView>();
  for (const o of outcomes) {
    if (report(alert, o) || o.kind !== "done") return null;
    const v = readStep(o.body);
    if (v === null) return null;
    out.set(v.step, v);
  }
  return out;
}

/** The status of each step, by name. */
export function statusesOf(steps: ReadonlyMap<OnboardingStep, StepView>): Record<string, StepStatus> {
  const out: Record<string, StepStatus> = {};
  for (const [s, v] of steps) out[s] = v.status;
  return out;
}

/**
 * The step navigation: one `li[data-step][data-status]` per step, in the
 * order of the spec table. A step that cannot be opened yet holds no link.
 */
export function stepNav(current: string, statuses: Readonly<Record<string, StepStatus>> | null): HTMLElement {
  const open = new Set<string>(statuses === null ? [] : openableSteps(statuses));
  const items = ONBOARDING_STEPS.map((s) => {
    const status = statuses === null ? undefined : statuses[s];
    const attrs: Record<string, string> = { "data-step": s };
    if (status !== undefined) attrs["data-status"] = status;
    const text = t.label("onboarding.nav.item", { name: stepName(s), status: statusText(status) });
    const linkAttrs: Record<string, string> = {};
    if (s === current) linkAttrs["aria-current"] = "page";
    return h("li", attrs, [open.has(s) ? link(PATHS.step(s), text, linkAttrs) : h("span", {}, [text])]);
  });
  const summaryAttrs: Record<string, string> = {};
  if (current === "summary") summaryAttrs["aria-current"] = "page";
  items.push(h("li", {}, [link(PATHS.summary, t.label("onboarding.summary.title"), summaryAttrs)]));
  return h("nav", { id: "onboarding-steps", "aria-label": t.label("onboarding.nav") }, [h("ol", {}, items)]);
}
