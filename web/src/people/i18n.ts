// The catalogue of the people pages (R-NF-04, I-72), built with core i18n.

import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { CATALOGUE } from "./messages.en.js";

/** The people catalogue in the one M4 locale. */
export const t: I18n = createI18n({ catalogues: [CATALOGUE], locale: CATALOGUE.locale });

/** The label of a role key, from the catalogue. */
export function roleLabel(role: string): Label {
  try {
    return t.label(`people.role.${role}`);
  } catch {
    return t.label("people.role.unnamed", { role });
  }
}
