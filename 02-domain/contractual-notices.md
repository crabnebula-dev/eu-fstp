# Contractual notices

## Scope

Contractual notices include contract offers, signature completions, amendments, milestone acceptance or rejection, payment request decisions, termination and hardship decisions. Reminders are not contractual notices.

## Form (O-20)

Each notice exists as two artefacts:

1. A PDF notice rendered in-house, sealed with the tenant's electronic seal and stored in the platform. The grantee can download it at any time.
2. An email carrying the notice text, a reference to the PDF and a link to it.

## Rules

- **I-40** A contractual notice email is sent only after its sealed PDF exists and its hash is recorded in the audit chain.
- The PDF is immutable. A correction is a new notice referencing the earlier one.
- Seal level follows P-47. Seal creation uses ADR-001 crates and the tenant's key held in the cell.
- Each notice also carries a composite Ed25519 plus ML-DSA-65 companion signature over its hash. The eIDAS seal is the legally relevant one. The companion signature is evidence that stays verifiable if classical signatures weaken. It is stored with the notice and included in exports.
- Whether the email also attaches the PDF follows P-48.
- Notices remain downloadable after a grant ends, for the funder audit period (P-41), and are part of the tenant export.
