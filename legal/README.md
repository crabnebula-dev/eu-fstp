# Legal texts: drafts

Status: drafts for Daniel's review, 2026-11-21 (lane L14). Nothing here is approved, and nothing is wired into the product.

- Legal party: **CrabNebula Ltd**.
- Data Protection Officer (DPO) of CrabNebula Ltd: **Daniel Thompson-Yvetot**, formally designated (Daniel, 2026-11-21).

Daniel's instruction of 2026-11-21: "I want you to draft all the legal texts, but create a folder for them under /legal and write them in markdown. CrabNebula Ltd. Is the legal party and I am the responsible data officer."

## How to read these drafts

- Every fact the repository does not hold is a `TODO(legal): ...` marker. This covers addresses, company numbers, legal bases, article numbers, authorities, periods and contacts. No citation and no legal text was written from memory.
- A line marked `[NOT BUILT: ...]` describes a rule of the specification that the code does not carry out yet. Such a line must not reach users until the build exists or the line is removed.
- `{{...}}` names a value from the Guide placeholders or the policy parameters. `{{tenant.*}}` names a tenant value for which no placeholder exists yet (question Q4).
- Each draft names the code site it would replace. The code keeps its own `TODO(legal)` marker until Daniel approves the wording.
- `docs/legal/requests/` holds the five earlier requests for a legal reviewer. The item IDs used there (D1 to D10, P1 to P8, W1 to W11) appear in the drafts, so an answer can be traced to a draft.

## Index

| File | Text | Request item |
| --- | --- | --- |
| [01-privacy-notice.md](01-privacy-notice.md) | Platform privacy notice, the default when a tenant sets none | D9 |
| [02-data-protection-summary-and-notices.md](02-data-protection-summary-and-notices.md) | Guide data protection summary, privacy statement address, notices at submission and negotiation, display name line | D9, W6, R-NG-06 |
| [03-ai-disclosure.md](03-ai-disclosure.md) | AI disclosure on the call page, in the Guide, at the pre-check, in the findings panel and the footer | W1, R-LA-08 |
| [04-terms-of-use.md](04-terms-of-use.md) | Terms of use for platform users | W2, Q27 |
| [05-cookies-and-storage.md](05-cookies-and-storage.md) | Cookie and browser storage notice | none |
| [06-imprint.md](06-imprint.md) | Imprint (provider identification) | none |
| [07-accessibility-statement.md](07-accessibility-statement.md) | Accessibility statement template for a tenant portal | W7 |
| [08-role-invitation-and-confidentiality-terms.md](08-role-invitation-and-confidentiality-terms.md) | Role invitation email, confidentiality terms for Drafting and Judging roles | W2, W3, J2 |
| [09-emails.md](09-emails.md) | Outcome, contractual notice, submission copy and passkey emails | W10 |
| [10-identity-vault-statements.md](10-identity-vault-statements.md) | Date of birth field, age confirmation, guardian consent, bank and hardship texts | W4, D2, D10 |
| [11-calibration-consent.md](11-calibration-consent.md) | Calibration consent request, confirmation and withdrawal | W11, D5, I-37 |
| [12-publication-opt-in.md](12-publication-opt-in.md) | Public visibility notes and opt-in statement | D4, L-07 |
| [13-retention-and-erasure.md](13-retention-and-erasure.md) | Retention and erasure notice, erasure confirmation | D6 |
| [14-complaints-grant-and-contract-texts.md](14-complaints-grant-and-contract-texts.md) | Complaint screens, negotiation summary, grant acceptance, signature and decline, payment texts, support note | W5, W6, W9 |
| [15-footer-texts.md](15-footer-texts.md) | The mandatory footer elements | W8, P-68, I-69 |
| [16-data-act-information.md](16-data-act-information.md) | Data Act information for tenant organisations | P4, L-04 |
| [tenant-agreements/saas-terms.md](tenant-agreements/saas-terms.md) | SaaS terms between CrabNebula Ltd and a tenant | P1 |
| [tenant-agreements/dpa.md](tenant-agreements/dpa.md) | Data processing agreement | P2 |
| [tenant-agreements/sub-processors.md](tenant-agreements/sub-processors.md) | Sub-processor list | P2, P3, L-15 |
| [funder-profiles/horizon-europe/guide.v1.md](funder-profiles/horizon-europe/guide.v1.md) | Guide for Applicants template with sections 9 and 11 drafted | L-08, L-12 |
| [funder-profiles/horizon-europe/visibility-elements.md](funder-profiles/horizon-europe/visibility-elements.md) | Wording of the `acknowledgement` and `emblem` elements | L-08, L-09 |

## Questions for Daniel

**Q1. Who is controller, and who is processor? Answered by Daniel, 2026-11-21.**

- On a funder tenant, the funder is the controller of its programme data, and CrabNebula Ltd is its processor, as in `SPEC/05-compliance/gdpr.md`.
- CrabNebula Ltd also coordinates two grant programmes of its own. For those it is the controller, as tenant and coordinator. Names: TODO(legal): the names of both programmes.
- CrabNebula Ltd is controller of control plane data (tenant sign-up, billing) and licence registration data.
- The earlier alternative, CrabNebula Ltd as controller of platform accounts, is dropped.
- The controller identity is a per-tenant value, `{{controller.legal_name}}`, `{{controller.address}}`, `{{controller.privacy_contact}}` and `{{controller.dpo_contact}}`. A funder tenant names itself. The tenant of the two CrabNebula programmes names CrabNebula Ltd. No setting holds this value yet (see Q4).
- Where the value cannot be a placeholder, the drafts give one text per case. The Guide summary has a platform default for funders (02, A1) and a tenant override for CrabNebula's programmes (02, A2), through the existing `GuideNoticeOverride`.
- Updated drafts: `01-privacy-notice.md` sections 1, 2 and 13; `02-...` sections A, C and D; `04-terms-of-use.md` section 1; `tenant-agreements/dpa.md`; `tenant-agreements/saas-terms.md` section 4.

**Q2. Daniel's title. Answered by Daniel, 2026-11-21.** Daniel Thompson-Yvetot is the formally designated Data Protection Officer (DPO) of CrabNebula Ltd. The drafts name him as DPO with a dedicated DPO contact. The address stays TODO(legal).

**Q3. The Guide's privacy statement address. Answered by Daniel, 2026-11-21.** `PLATFORM_PRIVACY_STATEMENT_URL` stays the address of the platform privacy notice. The Guide sentence is reworded to name the platform notice. The Funding & Tenders Portal Privacy Statement gets a separate sentence where Horizon Europe requires it: section 12 of the Horizon Europe Guide and the two R-NG-06 notices. Its address stays TODO(legal) (L-09).

**Q4. Tenant values.** The privacy notice and the accessibility statement need tenant values: the controller identity of Q1, the tenant's legal name and address, and the accessibility contact. No setting holds them today. A tenant setting, or a profile field, is needed before wiring.

**Q5. Outcome emails.** One template serves every outcome today. W10 asks for a wording per outcome. Keep one neutral template (draft A0), or add a template id per outcome (A1 to A4)?

**Q6. Footer links.** Each footer element is a plain text span with no page behind it. Approving the texts also needs pages and links for the privacy notice, accessibility statement, imprint, terms of use and Data Act information.

**Q7. Funder profile wording store.** The report profile stores a wording ref and the status `TODO(legal)` only. Approved wording needs a store behind each ref, a second status value and a new profile version.

**Q8. The drafted Guide still holds markers.** `funder-profiles/horizon-europe/guide.v1.md` keeps one `TODO(legal)` line in each of sections 9 and 11. Each asks Daniel to verify the drafted text against the signed grant agreement. Section 12 holds a third marker, for the Portal Privacy Statement address (Q3). With these markers, `LegalWordingPending` still fails, as it should. Once Daniel clears all three, the file passes I-66.

## Inventory of `TODO(legal)` markers

The repository holds about 450 occurrences of `TODO(legal)` in about 210 files (2026-11-21). They fall into three groups.

### Group 1: markers that need user-facing text (drafted here)

| Code site | Marker or refusal | Draft | How it would be wired |
| --- | --- | --- | --- |
| `crates/fstp-tenant/src/state.rs` `PLATFORM_DATA_PROTECTION_SUMMARY` | Placeholder text; `crates/fstp-cell/src/shell/facts.rs` `PlatformNotice::platform_default` sets `approved: false`, so publication is refused under I-52 | 02, section A | Replace the constant; set `approved` true once Daniel approves; update `crates/fstp-tenant/tests/guide_notice.rs` and `crates/fstp-celltest/tests/g13_production_shell_facts.rs`, which pin the marker |
| `crates/fstp-tenant/src/state.rs` `PLATFORM_PRIVACY_STATEMENT_URL` | `https://privacy-statement.invalid/todo-legal` | 02, section B | Replace the constant with the address of the published platform privacy notice (Q3, answered) |
| `crates/fstp-guide/profiles/horizon-europe/guide.v1.md` lines 113 and 152 (and the byte-equal copy `SPEC/profiles/horizon-europe/guide-for-applicants.md`) | `LegalWordingPending` (Q6, I-66); refusal tested by `crates/fstp-api-testkit/tests/i66_pending_legal_wording_is_a_failure.rs` | `funder-profiles/horizon-europe/guide.v1.md` | Copy over both files once the three remaining markers are cleared (Q8). It follows the structure of `crates/fstp-api-testkit/profiles/synthetic-wording/horizon-europe/guide.v1.md`: same headings, the marker lines replaced. A new Guide wording may need a new template version |
| `crates/fstp-report/profiles/horizon-europe/profile.v1.json` `visibility_elements` | Status `TODO(legal)` | `funder-profiles/horizon-europe/visibility-elements.md` | New store, status and profile version (Q7) |
| `crates/fstp-public/src/html.rs` `public.footer.*`, `public.footer.funder_element` | Placeholder footer texts | 15 | Replace catalogue entries; add pages and links (Q6) |
| `crates/fstp-public/src/html.rs` `public.ai.disclosure` | Placeholder AI disclosure | 03, section A | Replace catalogue entry |
| `crates/fstp-guide/src/render.rs` line 57 | AI interaction disclosure placeholder | 03, section B | Replace constant |
| `web/src/findings/messages.en.ts` `ai.disclosure` | Placeholder | 03, sections C and D | Replace entry, or split into an applicant and a staff entry |
| `web/src/auth/messages.en.ts` `footer.*`; `web/src/applicant/messages.en.ts` `FOOTER_APPROVED`; `web/src/creator/messages.en.ts` `footer.*`; `web/src/creator/frame.ts`; `web/src/shell/brand.ts` | Placeholder footer texts | 15 | Replace entries in all four catalogues together |
| `web/src/applicant/messages.en.ts` `notice.submission`, `notice.negotiation` | Placeholder notices (R-NG-06) | 02, sections C and D | Replace entries; raise `NOTICE_VERSIONS`; the cell accepts the version |
| `web/src/applicant/messages.en.ts` `submit.dob.*`; `web/src/applicant/submit.ts`; `web/src/vault/write.ts` | L-02 | 10, section A | Replace entries |
| `web/src/vault/messages.en.ts` | Interim consent and attestation statements | 10, sections B to F | Replace and add entries |
| `web/src/auth/messages.en.ts` `account.name.*`; `web/src/auth/pages/account.ts` | Privacy notice line for display names (SA-11) | 02, section E; 01 | Add one entry and a link |
| `web/src/people/messages.en.ts` `people.terms.body`; `web/src/people/pages/invitation.ts`; `crates/fstp-api-core/src/people.rs` `TERMS_VERSION`; `crates/fstp-domain/src/roles/commands.rs` | Placeholder confidentiality terms (J2) | 08, sections B and C | Split into a Drafting and a Judging entry; raise `TERMS_VERSION` |
| `crates/fstp-mail/src/template.rs` `RoleInvitation` | Draft invitation wording | 08, section A | New template version 2; pin its digest (I-25) |
| `crates/fstp-mail/src/template.rs` `ProposalOutcome`, `ContractNotice`, `SubmissionCopy`, `PasskeyDisabled` | W10 and ADR-008 draft wording | 09 | New template versions; see Q5 |
| `crates/fstp-timeline/tests/issue6_l10_passkey_disabled.rs`; `web/src/mailbox/messages.en.ts` | Passkey disabled draft wording | 09, section D | Mailbox text can stay; test follows the template version |
| `crates/fstp-domain/src/calibration.rs`, `command.rs`, `record.rs`; `crates/fstp-domain-testkit/tests/i37_support/mod.rs` | Consent wording (I-37) | 11 | Store the approved text as a `TextRef`; add UI entries |
| `web/src/grant/visibility/messages.en.ts` | Two notes to review | 12 | Replace two entries; add the opt-in statement |
| `crates/fstp-api-core/src/erasure.rs` | Retention scope | 13 | Help page and, later, an erasure confirmation template |
| `web/src/grant/messages.en.ts` | Acceptance and approval texts | 14, section C | Replace entries |
| `web/src/contract/messages.en.ts` | Signature routes and decline text | 14, section D | Replace entries |
| `web/src/payments/messages.en.ts` | Review, approval and release texts | 14, section E | Replace entries |
| `web/src/operations/messages.en.ts` `ops.reports.failure.support_note` | Support channel | 14, section F | Replace entry |
| `crates/fstp-signup/src/render.rs` `agreements.text.*`; `crates/fstp-signup/src/lib.rs`, `types.rs`; tests `r_tn_01_agreement_records.rs`, `th26_rendered_forms.rs` (which count three markers) | Placeholder agreements | `tenant-agreements/` | Link or rendered text per agreement; new versions; update the tests that count markers |
| `crates/fstp-cell/src/http/site.rs` | "Page not found" has no footer while the footer wording is pending | 15 | Add the footer once approved |
| `docs/design/03-applicant-screens.md` (sign-up terms, access terms, complaint path, on-hold wording) | Prototype comments | 04, 09 section E, 14 | Needs new catalogue entries and, for terms, a page |
| `docs/design/10-post-grant-screens.md` (complaint windows, agreement descriptions, support) | Prototype comments | 14, `tenant-agreements/` | Complaint screens are not built |
| `SPEC/05-compliance/data-act.md`; `web/src/help/messages.en.ts` P-46 | Switching periods | 16 | Footer page; help text after L-04 |
| `SPEC/05-compliance/dsa.md` G-12 to G-16 | Duties to add | 04 section 8, 06 | Not built |
| R-NF-03, design section 3.9 | Accessibility statement | 07 | Page behind the footer element |

### Group 2: markers that ask Daniel for a legal reading or a citation (not drafted)

These need a decision or a verified source. A draft text would not answer them.

| Code site | What Daniel must answer |
| --- | --- |
| `crates/fstp-contract/src/render.rs`; `crates/fstp-api-core/src/dispatch/grant.rs`; `crates/fstp-api-core/src/dispatch/creator_ops.rs`; `web/src/help/messages.en.ts` `flow_down` | The contract clause texts come from the signed grant agreement. Daniel supplies them (L-12) |
| `crates/fstp-sigval/src/lib.rs` (three markers), `crates/fstp-sigval/tests/sigval.rs` | Which signature and seal levels the SuperSAFE MoU needs; whether the signer's extended key usage must be checked; whether the qualified level may rest on the anchor flag |
| `crates/fstp-domain/src/payment.rs` | L-11: hardship contributions and Annex 1 reporting |
| `crates/fstp-report/src/output.rs`, `crates/fstp-report/src/lib.rs`, `SPEC/03-architecture/funder-reporting.md` | L-09: the field lists and formats of each reporting template |
| `crates/fstp-api-core/src/port.rs`, `SPEC/01-requirements/functional.md` NOTEs, ADR-008, ADR-009 | L-02: the basis for date of birth, country and guardian data before negotiation |
| `crates/fstp-vault-core/src/fact.rs`, `ticket.rs`, ADR-009 | The basis for storing reviewers' relatives, and the minimum attribute set (Q31; no L- number yet) |
| ADR-009, ADR-024 | The basis for in-memory rate limiting on client addresses (Q19; no L- number yet) |
| ADR-007, `crates/fstp-api-core/src/erasure.rs`, `SPEC/12-journey-ui.md` | Which records the retention obligation covers; whether deferring erasure is lawful; whether the skeleton is anonymous |
| ADR-023 | The transparency duty when a coordinator reveals a person; the basis and retention of the purpose text |
| ADR-005, ADR-012 | L-15: the OVHcloud contracting entity, terms, data centres, backup retention, second provider |
| ADR-018, ADR-019 | The tenant's mail relay and AI provider as processors; the DPIA; the transfer basis for a non-EU provider |
| `crates/fstp-checks/src/detect.rs` | Whether an untagged licence text may count as a licence |
| `tools/deps-check/src/sbom.rs` | Whether CycloneDX 1.6 JSON meets the CRA SBOM duty |
| `SPEC/03-architecture/eudi-wallet.md` | L-05: the eIDAS intermediary obligations |
| `SPEC/12-journey-ui.md` | Rounding of calculated amounts |
| `SPEC/11-backlog.md`, `SPEC/05-compliance/data-act.md` | L-04: the Data Act periods; whether a pilot may run before export exists |
| `web/src/help/messages.en.ts` (nine help texts, pinned by `web/test/sa13_field_help.test.ts`) | Explanations of P-41, P-46, minors, P-19, P-77, P-30, P-44, P-47 and the flow-down obligations. Each needs the legal reading first |
| `crates/fstp-guide/profiles/...` section 9 and 11 | L-08 and L-12 (see Q8) |

### Group 3: markers in design prototypes and handoff notes

`design/prototypes/*.html` (about 120 markers in 79 files), `docs/handoff/` (about 80), `docs/design/` (about 35) and the ADRs (about 37) repeat the markers above as comments or as records. They need no text of their own. They close when the code site they describe closes.

### Tests that pin markers

These tests check that a marker is present or counted. Wiring an approved text means updating them in the same change, never weakening the rule they guard:

- `crates/fstp-tenant/tests/guide_notice.rs`
- `crates/fstp-celltest/tests/g13_production_shell_facts.rs`
- `crates/fstp-signup/tests/th26_rendered_forms.rs` (counts three markers)
- `crates/fstp-signup/tests/r_tn_01_agreement_records.rs`
- `crates/fstp-report/tests/r_rp_01_p53_pins_profile.rs`
- `web/test/m9_app_footer.test.ts`
- `web/test/sa13_field_help.test.ts`
- `crates/fstp-guide/tests/review_legal_marker.rs`, `review_invariants_legal_marker.rs`, `review_parser.rs` (marker detection itself; these stay)
- `crates/fstp-api-testkit/tests/i66_pending_legal_wording_is_a_failure.rs` (the I-66 rule; it stays)

## Rules of the specification not carried out by the code

The drafts do not claim these. Each is marked `[NOT BUILT]` where it appears.

- Deletion of unsubmitted drafts and pre-check runs when the call closes (`pre-check.md`).
- Deletion of assessment traces when P-22 ends (R-LA-07).
- Identity document upload and its deletion after verification (P-19, R-ID-03).
- Registration of vault identities with attribute tuples (ADR-004, lane L11).
- A guardian's withdrawal control on the vault page.
- A self-service erasure request, and the erasure confirmation message (ADR-007).
- Export and switching tools (R-TD-01 to R-TD-04, deferred as B-07).
- Complaint screens.
- DSA notice and action, statements of reasons and points of contact (G-12 to G-16).

## Everything Daniel must supply or verify

Facts about CrabNebula Ltd:

1. Registered address.
2. Company number and register.
3. VAT number, if one applies.
4. General contact email.
5. Dedicated DPO email and postal address (Daniel Thompson-Yvetot, DPO).
6. Support email or URL.
7. Accessibility contact email.
8. Switching contact.
9. Address of the platform attribution link.
10. DSA points of contact for authorities and users (G-14).
11. Vulnerability reporting contact (CRA, L-03).
12. Size category under the SME definition, with linked enterprises (L-16).

Decisions:

13. Q4 to Q8 above, and the names of the two programmes CrabNebula Ltd coordinates (Q1).
14. Versions and dates of each approved text.
15. Fees, service levels, liability, term and termination of the SaaS terms.
16. Sub-processor change notice and objection periods; breach notification time; audit terms in the DPA.
17. Whether a platform outage near a deadline needs a stated remedy.

Legal readings and citations:

18. Legal basis for each purpose in section 5 of the privacy notice.
19. The list of data subject rights to state, per basis, and the response time.
20. The lead supervisory authority and its contact details.
21. The information duty on automated decisions, and whether section 7 of the privacy notice meets it.
22. L-01: the DPIA for AI assessment.
23. L-02: date of birth, country and guardian data before negotiation; children's consent.
24. L-04: Data Act transitional and retrieval periods; pre-contract information; pilot before export.
25. L-06: the funder retention period and the records it covers; deferred erasure; the skeleton as anonymous data.
26. L-07: opt-in as the basis for publication, including for natural persons and group teams.
27. L-08: the EU funding acknowledgement wording and emblem rules.
28. L-09: the Portal Privacy Statement address; the address of the published platform privacy notice; the data passed to the granting authority; reporting fields.
29. L-11: hardship contributions as eligible costs.
30. L-12: the flow-down obligations and contract clauses against the signed grant agreement.
31. L-14: governing law and external redress for applicants and recipients; complaint windows P-61 to P-64.
32. L-15: OVHcloud entity, terms, locations, backup retention and second provider.
33. L-16 and L-17: DSA status of CrabNebula Ltd and of tenant portals.
34. Calibration consent (D5): basis, content, and results kept after withdrawal.
35. Health data in hardship evidence: basis and consent.
36. Reviewers' relatives (Q31): basis and minimum attributes.
37. In-memory rate limiting on client addresses (Q19): basis.
38. Coordinator reveal (ADR-023): transparency duty and purpose text retention.
39. Transfer basis for a non-EU AI provider (ADR-019).
40. Mail relay and AI provider as the tenant's processors (ADR-018, ADR-019).
41. AI Act provisions the disclosure serves; application dates; reviewer AI literacy.
42. Cookie consent for the session cookie and session storage.
43. Which accessibility law applies to tenant portals, the conformance status and the enforcement route.
44. Which provider information the imprint must carry.
45. Signature and seal levels, and their legal effect (P-30, P-47, sigval).
46. The legal nature of payments per instrument (P-44).
47. When a contractual notice counts as received (O-20).
48. Whether an invitation email must name the sender organisation (I-27 forbids it today).
49. Whether a contract decline can be undone.
50. The scope of the content licence in the terms of use, against the open licence duty.
51. The liability clause and consumer limits in the terms of use; governing law and courts.
