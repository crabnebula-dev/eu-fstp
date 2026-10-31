// The catalogue of the creator pages and of the shared page frame
// (R-NF-04, I-72), built with core i18n.

import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { CATALOGUE } from "./messages.en.js";

/** The creator catalogue in the one M4 locale. */
export const t: I18n = createI18n({ catalogues: [CATALOGUE], locale: CATALOGUE.locale });

/**
 * The label `id`, or `fallback` when the catalogue has no such label. For
 * ids a page computes from data, such as a field key or a check id, so a
 * value the catalogue does not know yet never stops a page.
 */
export function labelOr(id: string, fallback: () => Label, args?: Readonly<Record<string, string>>): Label {
  try {
    return t.label(id, args);
  } catch {
    return fallback();
  }
}
