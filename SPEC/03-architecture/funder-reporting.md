# Funder reporting and document generation

## Funder profiles

Each programme references a funder profile (P-53). A profile defines the documents to generate, their templates, field mappings and reporting periods. Profiles are versioned and tenant-owned. The first profile is Horizon Europe.

## Generation rules

- Every document is generated from a data snapshot and records the snapshot hash and template version.
- Regenerating from the same snapshot and template yields an identical document.
- **I-44** Every figure in a funder document reconciles with recorded contracts, payment requests and payments at the snapshot. Generation fails on any mismatch and lists it.
- Documents are drafts until a named Operations role approves them. Approval is logged.
- The platform does not submit anything to funder portals. Humans upload approved documents.
- Generated documents are part of the tenant export.

## Horizon Europe profile (all outputs confirmed under O-31)

| Output | Content | Source data |
| --- | --- | --- |
| Call publication record | Fields for announcing the open call on the Funding & Tenders Portal listing of third-party calls | Frozen call policy, budget, dates |
| Open call package | Guide for Applicants (`02-domain/guide-for-applicants.md`), proposal form, contract template, data protection notice | Frozen call policy and programme narrative |
| Periodic reporting data | Recipients per period with legal form, country, call, amounts committed and paid, totals for the financial support cost category | Contracts, payments, vault attributes released at NEGOTIATION |
| Audit file per call | Knock-out decisions, scores, stage 2 records, ranking and cut-off rationale, IRC validations, conflict declarations, contracts, notices, payment evidence, with hashes | Audit chain and domain records |
| Deliverable drafts | Reports the DoA defines for the FSTP work package, such as per-call selection reports | Evaluation and grant records |

NOTE: Field lists and formats depend on current portal forms and the SuperSAFE grant agreement. Each template carries a `TODO(legal)` marker until checked (L-09).

## Horizon Europe rules applied by the profile

- Periodic reporting data reports FSTP as amounts actually paid within each reporting period, kept separate from the indirect cost base. Committed amounts are shown as context, never as costs.
- Reporting period ends and report deadlines from the Data Sheet become timeline events with reminders.
- The open call package fails generation unless it contains the five elements in I-48.
- The data protection notice in the package and at negotiation tells applicants that recipient data reaches the granting authority, and references the Portal Privacy Statement.
- Retention under P-41 starts when an Operations role records the date of the action's final payment. Until then, everything is retained.
- Hardship contributions are reported as FSTP only as far as Annex 1 describes them (L-11), and stay traceable as their own type.
- Balances returned under P-67 are shown as released commitments in periodic reporting data, never as costs.
