# Data Act (Regulation (EU) 2023/2854)

## Position

The SaaS offering is a data processing service. The switching obligations in Chapter VI apply to CrabNebula Ltd as provider towards tenant customers.

## Design outcomes

- A tenant can export all exportable data and digital assets at any time, in a documented, machine-readable format (R-TD-01).
- The export format is the import format, so a tenant can move to another instance, another provider or on-premises (R-TD-02).
- Export and import tooling and the schema are licensed under EUPL-1.2 as a separate executable (R-TD-03).
- No switching charges (R-TD-04). Article 29 removes switching charges entirely from 12 January 2027.
- Safeguards against unlawful third-country governmental access to non-personal tenant data are part of the threat model (TH-13). See Article 32.

## Switching terms (O-13)

| Term | Platform position |
| --- | --- |
| Notice period to initiate switching | None. Switching starts on request. |
| Transitional period | Within the statutory maximum. TODO(legal): confirm the exact maximum in Article 25. |
| Data retrieval period | 30 days (P-46). TODO(legal): confirm the statutory minimum in Article 25. |
| Erasure | Full erasure of the tenant cell after the retrieval period, with an erasure confirmation to the tenant. |

The switching process is a state machine of its own: REQUESTED, EXPORTED, RETRIEVAL_OPEN, ERASED. Each step is logged in the control plane without tenant content.

## Licence interaction

A commercial tenant switching to on-premises would otherwise need a licence from CrabNebula. R-TD-03 removes that dependency, since any provider can ingest a tenant export.

## To confirm

- Information obligations towards tenants under Article 26.
- Whether Article 30 technical requirements impose anything beyond the open export schema for a SaaS of this type.

## Dossier

Assessed in dossier FSTP-DOS-DA-DSA v1.0.0 (10 October 2026). Gaps G-01 to G-11 cover the transitional period, customer choices, the contractual export inventory, the online register, the SaaS contract, the Article 28 and 29 disclosures, the open interface under Article 30(2), third-country order handling, good faith cooperation and the Article 13 review of terms.
