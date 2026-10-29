// Type conformance of web/src/core against the W1c test contract
// (web/test/support/contract.ts; M4 design section 3.9, ADR-014).
//
// Check with: web/node_modules/.bin/tsc -p web/test/conformance
//
// The tests load each module by a computed URL, so they compile while a
// module is missing. This file imports each module statically, so tsc
// fails here until every module exists with the contract's exports and
// shapes. Red until the lane W1c implementer lands web/src/core.

import * as a11y from "../../src/core/a11y.js";
import * as api from "../../src/core/api.js";
import * as dom from "../../src/core/dom.js";
import * as forms from "../../src/core/forms.js";
import * as i18n from "../../src/core/i18n.js";
import * as money from "../../src/core/money.js";
import * as router from "../../src/core/router.js";
import * as stepup from "../../src/core/stepup.js";
import * as store from "../../src/core/store.js";
import type { CoreModules } from "../support/contract.js";

/** Each module, typed as the contract states it. */
export const CONFORMANCE: CoreModules = { money, dom, router, store, i18n, a11y, forms, api, stepup };
