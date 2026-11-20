// The catalogue of the consent page (R-NF-04), built with core i18n.

import { createI18n, type I18n } from "../core/i18n.js";
import { CATALOGUE } from "./messages.en.js";

/** The consent page catalogue in the one M4 locale. */
export const t: I18n = createI18n({ catalogues: [CATALOGUE], locale: CATALOGUE.locale });
