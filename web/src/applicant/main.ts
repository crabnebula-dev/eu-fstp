// A stand-alone entry module for the applicant and call pages (ADR-014
// "Shell, assets and headers").
//
// Interim, pending the lead and lane W4e: the shell names one entry
// module, and no shared entry exists yet. Until one does, this module can
// be that entry for `/app/calls`, `/app/proposals` and `/app/notices`.

import { installTrustedTypesPolicy } from "../core/dom.js";
import { mountApplicantPage, mountNotFound } from "./app.js";

installTrustedTypesPolicy();
if (!mountApplicantPage(location.pathname)) {
  mountNotFound();
}
