# Footer texts

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Requirements: P-68, R-WL-04, I-69, M4 design section 3.9 "Footer". Request item W8.

Every page shows the privacy notice, the accessibility statement and the platform attribution. Pages with findings show the AI disclosure. Tenant admin pages show the Data Act information. Programme pages show the funder visibility elements of the pinned profile.

Today each element is a plain text span. None is a link, and no page exists behind it. Wiring the drafts means adding the target pages and turning each element into a link. `crates/fstp-cell/src/http/site.rs` serves the "Page not found" page with no footer for the same reason. It can take the footer once these texts are approved.

The same element appears in four catalogues, which must stay in step:

- `crates/fstp-public/src/html.rs` (`public.footer.*`)
- `web/src/auth/messages.en.ts` (`footer.*`)
- `web/src/applicant/messages.en.ts` (`FOOTER_APPROVED`)
- `web/src/creator/messages.en.ts` (`footer.*`)

---

| Element | Catalogue ids | Draft text | Target page |
| --- | --- | --- | --- |
| Privacy notice | `public.footer.privacy`, `footer.privacy`, `footer.privacy_notice` | "Privacy notice" | `01-privacy-notice.md`, or the tenant's own notice |
| Accessibility statement | `public.footer.accessibility`, `footer.accessibility`, `footer.accessibility_statement` | "Accessibility statement" | `07-accessibility-statement.md` |
| Platform attribution | `public.footer.attribution`, `footer.attribution`, `footer.platform_attribution` | "Runs on the FSTP platform by CrabNebula Ltd" | CrabNebula Ltd's site, a plain link with no tracking parameters. TODO(legal): the address |
| Imprint | none yet | "Imprint" | `06-imprint.md` |
| Terms of use | none yet | "Terms of use" | `04-terms-of-use.md` |
| AI disclosure | `public.footer.ai`, `footer.ai_disclosure` | "AI findings on this page come from an AI system. A person takes every decision." | `03-ai-disclosure.md`, section A |
| Data Act information | `public.footer.data_act`, `footer.data_act_information` | "Data Act information for organisations" | `16-data-act-information.md` |
| Funder visibility | `public.footer.funder`, `footer.funder_visibility` | See `funder-profiles/horizon-europe/visibility-elements.md` | none |
| Funder visibility element | `public.footer.funder_element`, `footer.funder_element` | The approved wording of each element of the pinned profile | none |

Note: P-68 fixes no attribution wording. The draft names CrabNebula Ltd so that users can see who operates the platform. TODO(legal): whether a white-labelled portal must name the operator in the footer.
