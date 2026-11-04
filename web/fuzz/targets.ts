// Every TypeScript fuzz target of M4 design section 9 (Q33 interim, TH-26,
// H-05). run.ts runs them, and web/test checks the list.

import type { FuzzTarget } from "./harness.js";
import { target as messageFormat } from "./message_format.fuzz.js";
import { target as moneyParse } from "./money_parse.fuzz.js";
import { target as routerMatch } from "./router_match.fuzz.js";
import { target as returnPath } from "./return_path.fuzz.js";
import { target as safeUrl } from "./safe_url.fuzz.js";
import { target as validators } from "./validators.fuzz.js";

/** Every target, one per TypeScript parser. */
export const TARGETS: readonly FuzzTarget[] = [moneyParse, safeUrl, routerMatch, validators, messageFormat, returnPath];
