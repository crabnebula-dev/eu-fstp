# Data protection summary and notices

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

This file holds five short texts. Each has its own code site, listed in `README.md`.

---

## A. Data protection summary of the Guide

Replaces: `PLATFORM_DATA_PROTECTION_SUMMARY` in `crates/fstp-tenant/src/state.rs`. The Guide prints it at `{{gdpr.notice_summary}}`, in section 12 "Data protection and confidentiality". A tenant replaces it with its own summary through its settings (`GuideNoticeOverride`).

Format: one plain paragraph. No Markdown, no link, no placeholder. The Guide renders the value as text.

The controller differs per tenant (README.md, Q1, answered). The summary takes no placeholder, so the controller is set as follows:

- A1 is the platform default. It serves every funder tenant, where the funder is the controller and CrabNebula Ltd its processor.
- A2 serves the two programmes CrabNebula Ltd coordinates itself. Their tenant sets it as its own summary through `GuideNoticeOverride`, so no code change is needed.

### A1. Platform default (funder tenants)

> The organisation that runs this programme is the controller of your personal data for it. CrabNebula Ltd operates the platform and processes your data on that organisation's behalf, as its processor. Your data is used to receive and evaluate your proposal, to check eligibility, to agree and manage a contract, to pay the grant and to report to the granting authority. An AI system produces findings on your proposal, after names and contact details are replaced with placeholders. A named person takes every decision, and the findings never decide. Identity data, your date of birth, your country and bank details go only to a separate identity vault. Identity is checked only at contract negotiation. Records are kept for the funder retention period stated below, then erased. You can ask for access to your data, its correction or its erasure. The privacy notice gives the full details, the controller's contacts and the contact of the Data Protection Officer of CrabNebula Ltd. TODO(legal): add the right to complain once Daniel supplies the supervisory authority.

### A2. Programmes coordinated by CrabNebula Ltd

For: SuperSAFE (grant agreement 101342989) and ELFA (grant agreement 101298715).

> CrabNebula Ltd runs this programme and is the controller of your personal data for it. CrabNebula Ltd also operates the platform. Your data is used to receive and evaluate your proposal, to check eligibility, to agree and manage a contract, to pay the grant and to report to the granting authority. An AI system produces findings on your proposal, after names and contact details are replaced with placeholders. A named person takes every decision, and the findings never decide. Identity data, your date of birth, your country and bank details go only to a separate identity vault. Identity is checked only at contract negotiation. Records are kept for the funder retention period stated below, then erased. You can ask for access to your data, its correction or its erasure. Our Data Protection Officer, Daniel Thompson-Yvetot, can be reached at privacy@crabnebula.dev. The privacy notice gives the full details. TODO(legal): add the right to complain once Daniel supplies the supervisory authority.

## B. Privacy statement address of the Guide

Replaces: `PLATFORM_PRIVACY_STATEMENT_URL` in `crates/fstp-tenant/src/state.rs`, now `https://privacy-statement.invalid/todo-legal`. It fills `{{funder.privacy_statement_url}}` when the tenant sets no notice of its own.

Daniel's answer (Q3, 2026-11-21): this address is the platform privacy notice (`01-privacy-notice.md`). The Guide sentence around it is reworded to name the platform notice. The Funding & Tenders Portal Privacy Statement is linked separately, only where Horizon Europe requires it.

Draft value: TODO(legal): the `https:` address at which the platform privacy notice will be published.

Reworded Guide sentence, section 12 of the Horizon Europe template (`funder-profiles/horizon-europe/guide.v1.md`):

> The privacy notice explains how your personal data is used, who the controller is and how to exercise your rights: {{funder.privacy_statement_url}}.

Separate Portal sentence, in the same section, Horizon Europe profile only:

> Personal data transferred to the granting authority is processed under the Funding & Tenders Portal Privacy Statement: TODO(legal): the Portal Privacy Statement address (L-09).

Wiring note: the placeholder keeps its code name `funder.privacy_statement_url`. Renaming it, for example to `platform.privacy_notice_url`, is optional and touches `crates/fstp-guide/src/resolve.rs`. The Portal address is fixed text of the Horizon Europe profile, not a tenant value.

## C. Data protection notice at submission (R-NG-06)

Replaces: `APPLICANT_APPROVED["notice.submission"]` in `web/src/applicant/messages.en.ts`. A new wording needs a new version in `NOTICE_VERSIONS`, since the receipt records the version shown.

R-NG-06 requires this notice to refer to the Portal Privacy Statement, so the Portal link stays here.

Draft:

> Before you submit, please read how your data is used.
>
> {controller} is the controller of your data in this programme. It receives your proposal and uses it to evaluate your application. Reviewers see your proposal under a handle, not your name. An AI system produces findings on your proposal for the reviewers. A named person takes every decision.
>
> If your proposal is selected, data about you and your grant is passed to the granting authority of the EU programme. The authority processes it under the Funding & Tenders Portal Privacy Statement: TODO(legal): the Portal Privacy Statement address (L-09).
>
> Your country and your date of birth go only to the identity vault. The programme learns only whether you meet the country condition and whether you are under 18 at the deadline.
>
> The privacy notice gives the full details, your rights and the contacts, including the Data Protection Officer of CrabNebula Ltd.
>
> TODO(legal): confirm the categories of recipient data passed to the granting authority (L-09).

Wiring note: the catalogue text takes no placeholder today. `{controller}` needs a slot filled from the per-tenant controller value (README.md, Q1). The Portal address goes in as fixed text of the Horizon Europe profile.

## D. Data protection notice at negotiation (R-NG-06)

Replaces: `APPLICANT_APPROVED["notice.negotiation"]` in `web/src/applicant/messages.en.ts`. The grantee acknowledges it before negotiation continues.

Draft:

> Your proposal is in negotiation. This step needs more data about you. {controller} remains the controller of your data in this programme.
>
> You will verify your identity in the identity vault. If the lead applicant is under 18, a parent or legal guardian gives consent there too. Later you enter bank details for payments, also in the identity vault. The programme sees yes or no answers, not the data itself.
>
> The coordinator of the programme can see who you are, for a recorded purpose. Every such view is logged.
>
> Data about you and your grant is passed to the granting authority of the EU programme, for reporting and audits. This includes your name or your organisation's name, the amounts and the results of the project. The authority processes it under the Funding & Tenders Portal Privacy Statement: TODO(legal): the Portal Privacy Statement address (L-09).
>
> Records of your grant are kept until the funder retention period ends. It starts when your last payment is confirmed.
>
> The privacy notice gives the full details, your rights and the contacts, including the Data Protection Officer of CrabNebula Ltd.
>
> TODO(legal): confirm the list of data passed to the granting authority (L-09), the retention period (L-06), and the transparency wording for the coordinator's view (ADR-023).

## E. Privacy notice line for display names (SA-11)

Replaces: the `TODO(legal)` beside `account.name.*` in `web/src/auth/messages.en.ts` and `web/src/auth/pages/account.ts`. The line belongs in the privacy notice (`01-privacy-notice.md`, sections 4, 5 and 11, where it already stands). The account page can then link to it.

Draft line for the account page, under the display name heading:

> Your display name is optional. Tenant admins and programme managers see it on the team and member pages. Removing it erases it at once. See the privacy notice.
