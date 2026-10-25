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
- Every database connection from a cell component is mutually authenticated (R-NF-09). The client verifies the server's certificate and host name (verify-full). PostgreSQL checks a client certificate with `clientcert=verify-full` on every `hostssl` line, so this holds for every role.
- The client certificate's CN equals the database role. SCRAM-SHA-256-PLUS authentication still runs in addition to the certificate check. Production components get one client certificate per role.
- Daniel decided the two rules above on 2026-10-25 (M1 decision D2).

## Post-quantum database link

Deferred, recorded 2026-10-25 (M1 decision D3). Whether the database link must use X25519MLKEM768 is decided with the provider, since the provider's PostgreSQL build sets which groups the server can negotiate.

- A hybrid-only link needs a PostgreSQL release whose TLS group setting accepts hybrid groups, built against OpenSSL 3.5 or later.
- PostgreSQL 16 on Ubuntu 24.04 is built against OpenSSL 3.0.13 and cannot negotiate X25519MLKEM768. Its `ssl_ecdh_curve` accepts only named elliptic curves, and OpenSSL 3.0.13 has no ML-KEM. The link to that server uses a classical group.
- Both facts were verified on 2026-10-25 with `openssl list -kem-algorithms` and the server's own error strings.
- The client keeps offering X25519MLKEM768 first, as ADR-001 sets out.
