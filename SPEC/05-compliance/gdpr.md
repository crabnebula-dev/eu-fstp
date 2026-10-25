# GDPR

## Roles

| Context | Controller | Processor |
| --- | --- | --- |
| Tenant programme data (applicants, reviewers) | Tenant operator | CrabNebula (SaaS) |
| Control plane account and billing data | CrabNebula |  |
| Self-hosted cell | Tenant operator | None from CrabNebula |
| Inference | Tenant operator | Inference provider as sub-processor |

Per-tenant accounts and user-held profile bundles avoid CrabNebula becoming controller for cross-tenant identity data (I-20).

## Design outcomes

- Data minimisation: identity collected only in negotiation (R-NG-01).
- No solely automated decisions with legal or similarly significant effect. A named human records every decision (R-LA-03, Article 22).
- Data protection by design: pseudonymous review, vault separation, PII stripping before inference.
- Minors: age stored as a derived flag; guardian consent gates negotiation.
- Portability and access requests answered from the tenant cell.
- Per-tenant DPA with sub-processor list, including the chosen inference provider.

## To confirm

- DPIA for LLM assessment of all submissions. Systematic evaluation with new technology suggests one is needed.
- Legal basis for processing a minor's data before guardian consent, and whether Article 8 applies to this service.
- P-41 value per funder, which sets trace retention.

## Licence registration

Licence token issuance for self-hosted installs, including noncommercial ones, makes CrabNebula controller for registration data. Collect only the licence holder name, contact address and declared licence type. The licence refresh carries no tenant data (I-38).

## Hosting

The SaaS hosting provider is EU-owned (ADR-005) and is listed as a sub-processor in every tenant DPA.
