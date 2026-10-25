# Services called by self-hosted cells

Self-hosted cells call two CrabNebula-hosted services: an update service and a licence service (O-14).

## Update service

- Release metadata and artefacts carry composite Ed25519 plus ML-DSA-65 signatures by CrabNebula release signing keys, which the release root certifies (ADR-001, ADR-004, I-91).
- Cells verify signatures, reject rollbacks to older versions and support key rotation.
- The update check sends only the product version and channel.
- Air-gapped cells import signed update bundles manually.
- Updates never run automatically during a migration-sensitive window, such as an open evaluation stage. The tenant admin schedules them.

## Licence service

- Every install, commercial or noncommercial, holds a signed licence token verified locally. The cell refreshes it periodically and does not need the service for each start.
- The refresh sends only the licence identifier and product version.
- A failed refresh starts a grace period (P-43). Expiry never interrupts a published call, payment processing or export.
- Noncommercial installs use the same check with a free licence token (O-27). Token issuance is automatic on self-declared noncommercial status, so registration adds minimal friction.

NOTE: PolyForm Noncommercial permits noncommercial users to modify the software, which includes removing the check. For them the check serves registration and the update channel, not enforcement.

## Invariants

- **I-38** Calls to the update and licence services carry no tenant data, only product version, channel and licence identifier.
- **I-39** Unavailability of either service never blocks evaluation, payments, notifications or export.

## CRA position

The licence service is remote data processing for the self-hosted product if its absence can stop the product from working. The update service delivers security updates for the product. Both fall within the product's conformity assessment and vulnerability handling. I-39 limits how far an outage can reach.
