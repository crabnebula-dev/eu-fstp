# ADR-005: Hosting and database layout

Status: Accepted in structure by Daniel on 2026-10-10. The provider is named before M3 closes.

## Hosting

The SaaS runs on an EU-owned provider with no non-EU parent company, in EU data centres.

- This limits the third-country governmental access risk in TH-13 and supports the Data Act safeguards (Article 32).
- The provider becomes a sub-processor in each tenant's data processing agreement.
- Candidates to evaluate include OVHcloud, Scaleway, Hetzner and IONOS. Criteria: ownership structure, KMS or HSM offering for ADR-004, certifications, PostgreSQL operations, and data centre locations.
- Backups stay with an EU-owned provider, and preferably a second one for resilience.

## Database layout

| Mode | Description | Default |
| --- | --- | --- |
| Shared | Many cells on one PostgreSQL cluster. Each cell has its own database, roles and keys | Yes |
| Dedicated | A cluster for one cell only | On request (P-73) |

## Rules

- **I-82** No database role can read across databases of different cells, in either mode.
- **I-83** Identity vault databases never share a cluster with application databases.
- Moving a cell between shared and dedicated mode uses the tenant export and import path, so it exercises I-22.
- Connection pooling is per cell. No pool serves two cells.
