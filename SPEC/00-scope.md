# Scope

## Purpose

The platform lets an operator run one or more FSTP programmes. Each programme issues periodic open calls, evaluates proposals in staged review, awards grants under a memorandum of understanding (MoU), and pays on milestone delivery.

## In scope

- Multi-tenant SaaS and a self-hosted single-tenant deployment from the same codebase, in Rust on PostgreSQL.
- Programme and call configuration within bounded policy parameters.
- Submission, staged evaluation, independent review, negotiation, MoU, milestones and payments.
- Separation of duties and conflict-of-interest enforcement per programme.
- Identity verification at negotiation, including guardian consent for minors.
- LLM assessment of every submission, and an applicant pre-submission check.
- Tenant data export and import for switching.
- Contracts, payment requests, timeline-driven email notifications.
- Group messaging over Matrix. Notifications over WhatsApp are deferred by Daniel on 2026-11-04 (B-03).
- A white-labelled desktop client built with Tauri is deferred by Daniel on 2026-11-04 (B-04).
- Public pages for open, funded and finished subgrants.
- Funder documents, starting with a Horizon Europe profile.
- Guided tenant onboarding, a programme creator and full white-labelling.
- An MCP server so users and public agents can work with the platform, and an MCP client for external tools.

## Out of scope

- General ledger accounting. The platform records payment approvals and, where configured, emits payment instructions.
- Holding or controlling funds.
- Fundraising and funder relationship management.
- Signal integration.
- Realtime audio and video sessions (backlog B-01).
- Stylometric de-anonymisation defences beyond reasonable metadata hygiene.

## Actors

| Actor | Description |
| --- | --- |
| Platform operator | Runs the SaaS control plane. CrabNebula for the hosted service. |
| Tenant operator | Organisation running programmes in a tenant (for example a Horizon Europe consortium coordinator). |
| Programme roles | See `02-domain/roles-and-sod.md`. |
| Funder | Receives management information (for example the European Commission). |
| Inference provider | LLM endpoint chosen by the tenant. |

## Assumptions

- "Drafter" means the author of call text and criteria, not the author of a proposal.
- A person is identified by a tenant account. No identity links exist across tenants.
- Proposals are written in the programme language, English by default.

## Glossary

| Term | Meaning |
| --- | --- |
| Cell | Isolated runtime for one tenant: own database, object store, keys, identity vault and assessor. |
| Committee | Programme evaluation committee (Annexe FSTP section 5.a). |
| IRC | Independent review committee (Annexe FSTP section 5.d). |
| Finding | Structured LLM observation about a submission, with evidence pointers. |
| Profile bundle | User-held export of selected profile fields, importable into another tenant. |
