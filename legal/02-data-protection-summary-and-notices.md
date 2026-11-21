# Data protection summary and notices

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

This file holds four short texts. Each has its own code site, listed in `README.md`.

---

## A. Platform default data protection summary of the Guide

Replaces: `PLATFORM_DATA_PROTECTION_SUMMARY` in `crates/fstp-tenant/src/state.rs`. The Guide prints it at `{{gdpr.notice_summary}}`, in section 12 "Data protection and confidentiality". A tenant replaces it with its own summary through its settings (`GuideNoticeOverride`).

Format: one plain paragraph. No Markdown, no link, no placeholder. The Guide renders the value as text.

Draft:

> The organisation that runs this programme decides how your personal data is used for it. CrabNebula Ltd operates the platform for that organisation. We use your data to receive and evaluate your proposal, to check eligibility, to agree and manage a contract, to pay the grant and to report to the granting authority. An AI system produces findings on your proposal, after names and contact details are replaced with placeholders. A named person takes every decision, and the findings never decide. Identity data, your date of birth, your country and bank details go only to a separate identity vault. Identity is checked only at contract negotiation. Records are kept for the funder retention period stated below, then erased. You can ask for access to your data, its correction or its erasure. The platform privacy notice gives the full details and contacts. TODO(legal): confirm the controller sentence (README.md, Q1), and add the contact address and the right to complain once Daniel supplies them.

Note for Daniel: the first sentence follows Reading A of the privacy notice. Under Reading B, replace it with: "CrabNebula Ltd is responsible for your platform account. The organisation that runs this programme is responsible for your data in this programme."

## B. Privacy statement address of the Guide

Replaces: `PLATFORM_PRIVACY_STATEMENT_URL` in `crates/fstp-tenant/src/state.rs`, now `https://privacy-statement.invalid/todo-legal`.

The Guide sentence around it reads: "Personal data transferred to the granting authority is processed under the Funding & Tenders Portal Privacy Statement: {{funder.privacy_statement_url}}." So this address must be the Portal Privacy Statement, not the platform privacy notice.

Draft value: TODO(legal): the current `https:` address of the Funding & Tenders Portal Privacy Statement, verified by Daniel (L-09). Do not use the platform privacy notice address here.

## C. Data protection notice at submission (R-NG-06)

Replaces: `APPLICANT_APPROVED["notice.submission"]` in `web/src/applicant/messages.en.ts`. A new wording needs a new version in `NOTICE_VERSIONS`, since the receipt records the version shown.

Draft:

> Before you submit, please read how your data is used.
>
> The organisation that runs this programme receives your proposal and uses it to evaluate your application. Reviewers see your proposal under a handle, not your name. An AI system produces findings on your proposal for the reviewers. A named person takes every decision.
>
> If your proposal is selected, data about you and your grant is passed to the granting authority of the EU programme. The authority processes it under the Funding & Tenders Portal Privacy Statement: {{funder.privacy_statement_url}}.
>
> Your country and your date of birth go only to the identity vault. The programme learns only whether you meet the country condition and whether you are under 18 at the deadline.
>
> The privacy notice of this platform gives the full details, your rights and the contacts.
>
> TODO(legal): confirm the controller sentence (README.md, Q1) and the categories of recipient data passed to the granting authority (L-09).

Wiring note: the catalogue text takes no placeholder today. Either the address goes in as a fixed text per profile, or the catalogue gains a `{url}` slot. Daniel decides.

## D. Data protection notice at negotiation (R-NG-06)

Replaces: `APPLICANT_APPROVED["notice.negotiation"]` in `web/src/applicant/messages.en.ts`. The grantee acknowledges it before negotiation continues.

Draft:

> Your proposal is in negotiation. This step needs more data about you.
>
> You will verify your identity in the identity vault. If the lead applicant is under 18, a parent or legal guardian gives consent there too. Later you enter bank details for payments, also in the identity vault. The programme sees yes or no answers, not the data itself.
>
> The coordinator of the programme can see who you are, for a recorded purpose. Every such view is logged.
>
> Data about you and your grant is passed to the granting authority of the EU programme, for reporting and audits. This includes your name or your organisation's name, the amounts and the results of the project. The authority processes it under the Funding & Tenders Portal Privacy Statement: {{funder.privacy_statement_url}}.
>
> Records of your grant are kept until the funder retention period ends. It starts when your last payment is confirmed.
>
> The privacy notice of this platform gives the full details, your rights and the contacts.
>
> TODO(legal): confirm the list of data passed to the granting authority (L-09), the retention period (L-06), and the transparency wording for the coordinator's view (ADR-023).

## E. Privacy notice line for display names (SA-11)

Replaces: the `TODO(legal)` beside `account.name.*` in `web/src/auth/messages.en.ts` and `web/src/auth/pages/account.ts`. The line belongs in the privacy notice (`01-privacy-notice.md`, sections 4, 5 and 11, where it already stands). The account page can then link to it.

Draft line for the account page, under the display name heading:

> Your display name is optional. Tenant admins and programme managers see it on the team and member pages. Removing it erases it at once. See the privacy notice.
