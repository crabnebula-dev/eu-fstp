// Every TypeScript fuzz target of M4 design section 9 (Q33 interim, TH-26,
// H-05), and the five of ADR-016 for the vendored LibPDF. run.ts runs
// them, and web/test checks the list.

import type { FuzzTarget } from "./harness.js";
import { target as applicantWire } from "./applicant_wire.fuzz.js";
import { target as messageFormat } from "./message_format.fuzz.js";
import { target as moneyParse } from "./money_parse.fuzz.js";
import { target as pdfDocument } from "./pdf_document.fuzz.js";
import { target as pdfPrepare } from "./pdf_prepare.fuzz.js";
import { target as pdfPrepareDifferential } from "./pdf_prepare_differential.fuzz.js";
import { target as pdfToken } from "./pdf_token.fuzz.js";
import { target as pdfXref } from "./pdf_xref.fuzz.js";
import { target as routerMatch } from "./router_match.fuzz.js";
import { target as returnPath } from "./return_path.fuzz.js";
import { target as routeTree } from "./route_tree.fuzz.js";
import { target as safeUrl } from "./safe_url.fuzz.js";
import { target as validators } from "./validators.fuzz.js";

/** Every target, one per TypeScript parser. */
export const TARGETS: readonly FuzzTarget[] = [
  moneyParse,
  safeUrl,
  routerMatch,
  validators,
  messageFormat,
  returnPath,
  pdfToken,
  pdfXref,
  pdfDocument,
  pdfPrepare,
  pdfPrepareDifferential,
  routeTree,
  applicantWire,
];
