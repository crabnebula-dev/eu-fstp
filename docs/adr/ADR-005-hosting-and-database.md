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

## Amendment of 2026-10-28: provider, clusters, roles and backups

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

This section records Daniel's answers of 2026-10-28 to Q3, Q4, Q25 and Q36 of `docs/handoff/m3-design.md`. It also records the interim readings that still wait for an answer, each marked "interim, pending Daniel". Labels such as Q3, G22 and R16 exist only in that design. They are not spec identifiers. Daniel accepted this section on 2026-10-28, so it governs where it differs from the sections above. ADR-008 to ADR-012 were drafted and accepted on the same date.

### Provider

- Daniel named OVHcloud as the SaaS hosting provider on 2026-10-28. That meets the "provider is named" condition of this ADR's status line and of the M3 exit criteria.
- OVHcloud becomes a sub-processor in each tenant's data processing agreement. The contracting entity is not confirmed yet (verify item V1).
- TODO(legal): L-15. Daniel to confirm the contracting entity, the sub-processor terms and the entry for every tenant DPA.
- R-HS-01 is not claimed until L-15 closes. The ownership facts available so far come from search summaries, not from filings (verify item V2).
- No service named in this ADR runs from a region outside the EU. Which OVHcloud regions qualify, per service, is verify item V3.

### PostgreSQL by cluster kind (Q3 C, decided 2026-10-28)

| Cluster kind | Databases | Operated as | Database authentication |
| --- | --- | --- | --- |
| `application` | `c_<cell>` | Self-operated PostgreSQL 16 on OVHcloud Public Cloud instances or Bare Metal, in a private vRack network | D2 in full: `clientcert=verify-full` on every `hostssl` line, CN equal to the role, SCRAM-SHA-256-PLUS |
| `vault` | `v_<cell>` | Self-operated, as above | D2 in full |
| `witness` | `witness` | Self-operated, as above | D2 in full |
| `control` | `cp`, `licence` | OVHcloud Public Cloud Databases for PostgreSQL, the managed service | SCRAM over server-authenticated TLS. The client verifies the server certificate and host name (`verify-full`). No client certificate |

- Self-operation is needed for every cluster that holds a cell or vault database. D2 and I-82 need control of `pg_hba.conf`, the client CA and the superuser. The managed service documents none of these on the pages read (G3).
- The witness database stays self-operated, which is the stricter reading of Daniel's answer. I-24 detection then never rests on a role the provider holds.
- The exact PostgreSQL 16 minor version, package source and OpenSSL version of the self-operated build: Record at first use.
- The major version of the managed control cluster is 16, to match. Interim, pending Daniel. Whether 16 is offered in the EU regions used is verify item V5.

#### The managed control cluster

- `fstp-pgwire` connects with SCRAM only. It accepts SCRAM-SHA-256-PLUS or SCRAM-SHA-256 (`RequireAuth::SCRAM`), and moves to `RequireAuth::SCRAM_PLUS_ONLY` if the service supports channel binding (V6).
- Cleartext passwords and unauthenticated connections are never added to the accepted set. If the service cannot complete SCRAM, the control-plane databases move to a self-operated `control` cluster under D2.
- The server is verified against the CA that OVHcloud shares across the Public Cloud Databases services of the project, as documented. That CA is shared, so the host name check is what binds the connection to our service.
- D2 binds every database connection from a cell component. No cell or vault component connects to the control cluster. Cells reach the control plane only through `CellToCp` over mutual TLS.
- R-NF-09 is not claimed for this link until Q34 is answered. SCRAM authenticates both sides at the protocol level, but no client certificate is presented at the TLS layer.
- `CONNECT` is revoked from PUBLIC on `cp` and `licence`, and granted per database to `cp_service`, `cp_migrator`, `licence_service` and `licence_migrator`. Whether the admin user can do this is verify item V7. ADR-011 covers the set-up.

#### The provider's operator role on control-plane data

The pages read on 2026-10-28 say that the admin user `avnadmin` is `NOSUPERUSER` with `CREATEDB`, `CREATEROLE` and `REPLICATION`. They also say that "the SUPERUSER attribute is reserved for OVHcloud's operation of the service". OVHcloud's operator can therefore read and change every row of `cp` and `licence`. This ADR accepts that, for these reasons.

- `cp` holds the cluster and cell registries, placements, routes, custody entry handles, metering counts, staff ids and staff credential public keys, operator ticket records with opaque case references, and job records.
- `cp` holds no tenant content, no tenant account identifier and no identity attribute (design rule B6, I-20). It holds no private key, no password and no SCRAM verifier. `i19_control_plane_columns_are_declared` pins its exact column set.
- Daniel decided Q36 A on 2026-10-28. Tenant data is content, accounts, identity attributes and anything derived from them, except entries in a closed metadata register. The register is drafted in ADR-009 and built as `fstp_cp_proto::METADATA_REGISTER`.
- Only register entries reach the control plane. `i19_only_registered_metadata_crosses` checks every capture against the register. Under I-19, the provider's role on `cp` therefore reaches registered metadata and CrabNebula's own records, never tenant data.
- Design section 21.0 records the effect of Daniel's Q3 answer as "`cp` holds only registered metadata". As drafted, `cp` also holds staff records, job records and operator-ticket records. These are not tenant data, but they are not register entries either. ADR-009 proposes an `Infrastructure` register class for such fields, which Daniel has not settled. Until he does, this ADR does not claim that `cp` holds only registered metadata.
- `licence` holds only the licence holder name, contact address and licence type (`SPEC/05-compliance/gdpr.md`, Licence registration). CrabNebula is controller for these. They are not tenant data of any cell, and no cell sends them (I-38).
- TODO(legal): L-15. Daniel to confirm that the provider's operator access to licence registration data is covered by the sub-processor terms.
- No cell or vault database is ever placed on a `control` cluster. `Placement::new` refuses any cluster whose kind is not `application` or `vault`. I-82 and I-83 therefore never depend on the provider's role.

The provider's role can also write `cp` rows. **Rule: no isolation invariant rests on a `cp` row alone.** Each check that reads one is repeated against a source the provider does not hold.

- I-83: `fstp-cell` and `fstp-vault` check the `fstp_meta.placement` kind in their own database and the kind in the server certificate OU at start. Both sit on self-operated clusters.
- Routes: a changed `cp.route` row can misdirect a connection. The edge never terminates tenant TLS, and each cell host's key lives only in its cell. A misdirected browser therefore fails the TLS handshake and learns nothing.
- Operator tickets and staff assertions: cells accept only those signed by a control-plane custody key they pinned at provisioning. A row cannot forge one.
- Cluster CA keys are custody sign keys in OKMS (ADR-004), not rows.
- Staff credentials: a row the provider inserts could add a staff passkey. Interim, pending Daniel: each `cp.staff_credential` row carries a signature by a control-plane custody key, made at enrolment under two-person approval. `fstp-control` refuses a row whose signature fails. `m3-design.md` does not contain this rule; it follows from Q3 C.
- Destructive provisioning jobs are re-verified by `fstp-pgagent` itself (ADR-011).

### Cluster layout

- Four cluster kinds exist: `application`, `vault`, `control` and `witness`. A cluster's kind is set at registration and never changes (`i83_cluster_kind_is_immutable`).
- On self-operated clusters the kind appears three times: in `cp.cluster`, in the subject OU of the server certificate, and in `fstp_meta.placement` of every cell database, whose CHECK admits one kind only.
- Shared and dedicated modes stay as above (P-73, R-HS-02). In shared mode an `application` cluster holds the `c_<cell>` databases of many cells, and a `vault` cluster the `v_<cell>` databases. In dedicated mode each holds one cell.
- A cell's two databases are never on one cluster (I-83). `cp.cell` has `CHECK (app_cluster <> vault_cluster)`, and `Placement::new` refuses equal clusters or wrong kinds.
- Each SaaS environment has one `witness` cluster and one managed `control` service.
- Every self-operated host sits in a private vRack network with no public address. Only the edge has public addresses.
- `<cell>` is the 32 lowercase hex digits of the random `CellId`, so database and role names reveal nothing (`i82_names_reveal_nothing`).
- Self-hosted: one node runs two PostgreSQL 16 instances, `application` and `vault`, with separate data directories, ports, OS users and cluster CAs. The local witness uses an append-only file store, so no witness cluster runs. There is no control cluster. ADR-011 describes the install.

### Superuser and replication (Q4 A with R1, decided 2026-10-28)

- Reading of I-82, decided by Daniel: it covers every role that can log in from another host. The cluster superuser and the replication role are cluster machinery. They log in only over loopback, from processes on the database host.
- `fstp_super` has exactly one `pg_hba` line: `hostssl all fstp_super 127.0.0.1/32 scram-sha-256 clientcert=verify-full`. Its certificate, key and password are readable only by the `fstp-pgagent` OS user. It runs only typed, logged jobs (ADR-011).
- `fstp_repl` is the only role with REPLICATION. Its one line is `hostssl replication fstp_repl 127.0.0.1/32 scram-sha-256 clientcert=verify-full`. It has no CONNECT on any cell database. Its key and password are readable only by the `fstp-backup` OS user, which runs `pg_basebackup` on the host.
- On the self-operated clusters (`application`, `vault`, `witness`), no role with a remote line has SUPERUSER, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS. PostgreSQL 16 gives a CREATEROLE role ADMIN OPTION on the roles it creates, so CREATEROLE stays off the network there.
- This rule does not hold on the managed `control` cluster, where `avnadmin` logs in remotely with CREATEDB, CREATEROLE and REPLICATION. Daniel's answers Q3 C and Q4 A meet at that point. Daniel settled it on 2026-10-28: the rule applies to the self-operated clusters, and the managed control-plane cluster holds no cell data (Open points for Daniel below).
- `pg_hba.conf` has one line per role and database, no remote `all` line, and a final reject line.
- There is no streaming replica (R1). A standby restores continuously from the sealed WAL archive (ADR-012).
- Under Q5 A, ledger bodies, checkpoints and audit events are sealed under cell keys. The superuser, the replication stream and the archive then see only ciphertext for content. Random ids, sequence numbers, times, enums and digests stay in clear (R-NF-08, R-CR-01).
- Root on a database host can read the `fstp_super` credential. Daniel answered Q35 on 2026-10-28: the residual risk is accepted with separate host staff, no standing root, two-person access and host access events shown to the tenant (design risk R16).
- The design's risk R2 named a synchronous replica with manual promotion. That text predates the Q4 answer and is superseded here.
- Tests: `i82_generated_hba_has_no_remote_superuser_and_no_all_line`, `i82_replication_role_has_loopback_line_only_and_no_connect`, `i82_no_remote_role_has_createrole_or_createdb`, `i82_privilege_graph_has_no_cross_cell_path` and `t_db_iso_i82_every_role_refused_on_foreign_cell_database`. `i82_no_remote_role_has_createrole_or_createdb` runs over the self-operated clusters only, and its doc comment says so.
- These tests claim I-82 under the reading above. `SPEC/09-milestones.md` NOTE 2 records that reading as a scoped M3 claim (Daniel, 2026-10-28). The invariant text is unchanged.

### Role certificates

| Item | Rule |
| --- | --- |
| Cluster CA | One per self-operated cluster. In SaaS, `fstp-control` creates it at cluster registration, as an EC secp256r1 sign key in control-plane custody (OKMS, ADR-004). Self-hosted, it lives in `fstp-keyd` local custody (ADR-011) |
| Server certificate | Issued by the cluster CA, with the cluster kind in the subject OU |
| Client certificate | CN equal to the role. Lifetime 7 days, renewed daily. Written by `fstp-pki` |
| Key pair | Generated by the component that uses the role. It proves possession by signing a fresh challenge. No certificate signing request is parsed |
| Password | Generated by the component. Only the SCRAM-SHA-256 verifier reaches `fstp-pgagent`. The control plane relays the verifier and the public key, and never learns the password or the private key |
| Migrator certificate | Issued only for a deploy window |
| `fstp_super`, `fstp_repl` | Issued by the same cluster CA at cluster set-up. Same lifetime and daily renewal, run by `fstp-pgagent` on the host. Interim, pending Daniel |
| CA rollover | Yearly, with an overlap during which the server trusts the old and the new CA |
| Ending a role at once | A `fstp-pgagent` job sets NOLOGIN. No revocation list is used; the 7-day lifetime bounds a lost key. Interim, pending Daniel |

- D2's two factors stay split. The control plane can have a certificate issued but never knows the password. The cell knows the password but cannot issue a certificate.
- Each role's key and password sit in files readable only by the component's OS user.

### Backups, retention and recovery objectives

- Primary copy: OVHcloud Object Storage, S3-compatible, in an EU region, with object lock. ADR-012 sets the format, the client and the restore rule.
- Second EU-owned provider: decided later with L-15 (Q25, Daniel, 2026-10-28). The options are Scaleway, Hetzner or IONOS, or an OVHcloud primary region pair inside the EU. The design prefers a provider with object lock. The ADR-005 exit row stays blocked until then.
- The witness's object-lock copies at a second provider wait on the same decision.
- Retention: decided later with L-15, together with Q25. This covers base backup frequency, WAL archive retention, and the object lock mode and period.
- Erasure never depends on retention. I-81, R-ID-03 and R-SW-02 hold through key destruction, whatever the retention (ADR-004, ADR-012).
- Old backups are deleted only by bucket lifecycle rules, never by client DELETE calls.
- TODO(legal): L-15. Daniel to confirm whether tenant DPAs must state the backup retention period and the backup provider.
- Recovery point objective for self-operated clusters: about one minute. It follows from `archive_timeout` of 60 seconds and continuous archiving, plus upload time. Restore drills measure it.
- Recovery time objective: Record at first use, from the first restore drill.
- Control cluster: backed up by the provider's managed service, not by `fstp-backup`. Its properties are verify item V10.

**Open: R-CR-01 and the control cluster.** R-CR-01 asks that data at rest leaving the running system, such as backups, be protected by hybrid post-quantum key encapsulation. The provider's backups of `cp` and `licence` are not sealed by us.

- Interim, pending Daniel: licence holder name and contact address are sealed under a `ControlPlane` chain key before they are written. Provider backups then hold them only as ciphertext.
- Registered metadata in `cp` stays in clear, as the managed service sees it anyway.
- Daniel to decide whether R-CR-01 covers provider-made backups of control-plane metadata. If it does, Q3 C needs revisiting for `cp`.

### Post-quantum database link (D3 status, 2026-10-28)

- D3 stays deferred. No date is set.
- Self-operation lets us choose the PostgreSQL build for the `application`, `vault` and `witness` clusters. A build is adopted only once it is verified to negotiate X25519MLKEM768. That needs a release whose TLS group setting accepts hybrid groups, built against OpenSSL 3.5 or later, as above.
- Until then those links use a classical group, and the client keeps offering X25519MLKEM768 first.
- On the managed control cluster the provider's build decides (verify item V11).

### OVHcloud verify list

Documented on pages read directly on 2026-10-28, listed in `m3-design.md` section 1.6:

- Public Cloud Databases for PostgreSQL enforces TLS. Clients verify the server against a CA shared by the project's Public Cloud Databases services. `avnadmin` is `NOSUPERUSER` with `CREATEDB`, `CREATEROLE` and `REPLICATION`. SUPERUSER is reserved for OVHcloud. CONNECT is granted to PUBLIC by default.
- OVHcloud KMS (OKMS) offers `oct` keys of 128, 192 and 256 bits with encrypt, decrypt, wrapKey and unwrapKey, RSA keys, and EC keys on secp256r1, secp384r1 and secp521r1 with sign and verify.
- OKMS `protectionLevel` is `SOFTWARE` by default, or `HSM`. A key must be disabled before deletion. State changes take effect immediately, and deletion is permanent. Keys stay in their region, and billing is per key stored.
- OKMS REST takes a personal access token, a service account or an access certificate. KMIP requires an access certificate.
- Object Storage supports object lock configuration in Regions and Local Zones. Legal hold and retention are supported in Regions, not in Local Zones. Versioning and multipart upload are supported.

Everything below is unverified. Each item is a question for OVHcloud or for the L-15 due diligence. None is recorded here as fact. Daniel asks OVHcloud the OKMS items (Q11, 2026-10-28).

| ID | Question | Why it matters |
| --- | --- | --- |
| V1 | Which OVHcloud entity contracts with CrabNebula for EU services? Is it free of any non-EU parent? | R-HS-01, L-15 |
| V2 | Do the filings confirm the ownership that a search summary of the investor relations page reported on 2026-10-28? | R-HS-01, TH-13, L-15 |
| V3 | Which regions are inside the EU for each service used? Does any service we use run from Erith or another non-EU region? | R-HS-01 |
| V4 | Which certificates cover each service and region we use, with what dates? Is KMS in scope? | ADR-005 criteria, L-15 |
| V5 | Is PostgreSQL 16 offered by Public Cloud Databases in the EU regions we use, and until when? | Control cluster |
| V6 | Does the managed service authenticate every role with SCRAM-SHA-256? Does it offer channel binding (SCRAM-SHA-256-PLUS)? | Control cluster link |
| V7 | Can `avnadmin` revoke CONNECT from PUBLIC and limit each role to its database? | Control cluster set-up |
| V8 | Who holds the operator superuser? Is operator access to customer data logged, and can the customer see that log? | Operator role on `cp` and `licence`, L-15 |
| V9 | Does a third party operate the managed database service, and so become a sub-processor? The M4 design notes the admin user name and press releases about a partnership as leads only | L-15 |
| V10 | Where are managed database backups kept, for how long and under which encryption? Can they be deleted on request? Is point-in-time restore offered? | Control cluster backups, R-CR-01 |
| V11 | Which OpenSSL version and TLS groups does the managed server build use? | D3 |
| V12 | Can the managed service attach to the vRack only, with IP allowlists? | Network layout |
| V13 | What are the disk encryption defaults and anti-affinity options for Public Cloud instances and Bare Metal, and the operating cost? | Self-operated clusters (design risk R2) |
| V14 | Which EU regions offer object lock, retention and legal hold? Must object lock be set at bucket creation, and does it need versioning? | ADR-012 |
| V15 | Can credentials be scoped per bucket or per prefix, one set per cell? | ADR-012, B7 |
| V16 | Does Object Storage verify a signed payload hash (`x-amz-content-sha256`)? What are the multipart part size and count limits? Are quotes in ETag values escaped as XML entities? | ADR-012 client |
| V17 | Does a Load Balancer TCP listener forward the ClientHello byte for byte? Can it pass the client address? | Edge (ADR-009) |
| V18 | Does OVHcloud offer confidential computing for cell and vault hosts? | Q35 root on hosts: evaluated in L-15 (Daniel, 2026-10-28) |

The OKMS items K1 to K15 are kept in one list, in ADR-004 completion part 2 (Verify list). This ADR keeps no copy of them. They include K7, whether OKMS key material can be exported, on which the I-80 claim for OKMS-held epochs waits.

The ADR-005 exit row of the M3 design closes once this section is accepted (Daniel, 2026-10-28), Q25 is decided, and this verify list and the ADR-004 OKMS items are resolved through L-15 (`m3-design.md` section 20).

### Open points for Daniel

- **Where the I-82 reading is recorded.** Settled by Daniel on 2026-10-28. The Q4 A reading is recorded as a scoped claim in `SPEC/09-milestones.md` NOTE 2: I-82 covers every role that can log in from another host, applied to the self-operated clusters. The managed control-plane cluster holds no cell data. The I-82 text in `SPEC/02-domain/invariants.md` stays unchanged. The loopback superuser and the replication role can read across the cell databases of their cluster, and the M3 exit report states that scope.
- **`avnadmin` on the managed control cluster.** Settled by the same answer. The Q4 A rule covers the self-operated clusters only, since no cell or vault database is ever placed on a `control` cluster. `avnadmin` and the provider's superuser reach only `cp` and `licence`, which hold no cell data.
- **`cp` and the metadata register.** Whether staff, job and operator-ticket records in `cp` count as registered metadata waits on the `Infrastructure` class proposed in ADR-009.
