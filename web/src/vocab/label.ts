// The secondary Voyage line beside a plain label (`SPEC/12-journey-ui.md`
// section 4, `docs/design/07-vocabulary-pack.md`; O-55, I-72, I-96).
//
// The plain label always leads. When the tenant switches Voyage on, its
// label follows as a secondary line with the class `voyage-label`. A
// proposal state also shows its formal name. Approved wording never goes
// through here: `I18n.approved` has no secondary line.
//
// Seam, interim pending Daniel: no read carries the tenant switch yet, so
// pages build their catalogue with `vocabOptions("plain")` until one does.

import { h } from "../core/dom.js";
import type { I18n, I18nOptions } from "../core/i18n.js";
import { VOYAGE_LABELS } from "./voyage.js";

/** The vocabulary a tenant shows: plain only, or plain with Voyage. */
export type VocabPack = "plain" | "voyage";

/** The `createI18n` option that switches the Voyage line on or off. */
export function vocabOptions(pack: VocabPack): Pick<I18nOptions, "secondary"> {
  return pack === "voyage" ? { secondary: VOYAGE_LABELS } : {};
}

function build(t: I18n, id: string, args: Readonly<Record<string, string>> | undefined, formal: string | null): HTMLElement {
  const parts: (Node | string)[] = [h("span", { class: "plain-label" }, [t.label(id, args)])];
  if (formal !== null) {
    parts.push(" ", h("span", { class: "state-name" }, [formal]));
  }
  const secondary = t.secondary(id, args);
  if (secondary !== null) {
    parts.push(h("br"), h("span", { class: "voyage-label" }, [secondary]));
  }
  return h("span", { class: "vocab-label" }, parts);
}

/**
 * A label for a heading, button or navigation entry: the plain label,
 * then the Voyage label as a secondary line when switched on.
 */
export function labelWithVoyage(t: I18n, id: string, args?: Readonly<Record<string, string>>): HTMLElement {
  return build(t, id, args, null);
}

/**
 * A status label of a proposal state: the plain label, the formal state
 * name such as `STAGE2` (I-96), then the Voyage line when switched on.
 */
export function stateWithVoyage(t: I18n, id: string, formal: string): HTMLElement {
  return build(t, id, undefined, formal);
}
