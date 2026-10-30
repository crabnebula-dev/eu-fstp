# M3 design: cell runtime, isolation and key custody (final)

Milestone M3 in `SPEC/09-milestones.md`: "Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services". Exit criteria: "I-16 to I-20, I-24, I-38, I-39 and I-77 to I-83 green; isolation tests green; hosting provider named in ADR-005".

Status: final design for Daniel's review, revised after a completeness review with 30 findings. Section 17.4 records each finding that was narrowed or answered differently, and why. No repository file was changed while writing it. Every repository change named here is staged by the implementing agent with a proposed commit message. Daniel creates, signs and pushes each commit.

Labels such as `Q4`, `G3`, `B5`, `W2`, `L-KEYS` and `M-SHRED` exist only in this document. They are not spec identifiers. Every `I-`, `R-`, `P-`, `SoD-`, `TH-`, `T-`, `H-`, `O-`, `L-` and `ADR-` identifier is quoted from the repository. ADR-008 to ADR-012 were proposed numbers, and Daniel accepted those ADRs on 2026-10-28. Crate, type, table, route, model and test names are design proposals.

Sources re-read for this final version:

- `.claude/CLAUDE.md`, `SPEC/README.md`, `SPEC/00-scope.md`, `SPEC/09-milestones.md`, `SPEC/10-open-questions.md`.
- `SPEC/02-domain/invariants.md`, `roles-and-sod.md`, `policy-parameters.md` (P-17 to P-22, P-35, P-36, P-41 to P-49, P-70 to P-78).
- `SPEC/01-requirements/functional.md` (R-LG, R-KY, R-HS, R-CR, R-ID, R-NG, R-SW, R-AU-01, R-CF-03, R-SB-02) and `non-functional.md`.
- `SPEC/03-architecture/overview.md` (vault queries and NOTE 1 to 6), `authentication.md`, `self-hosted-services.md`, `eudi-wallet.md`, `notifications.md`.
- `SPEC/05-compliance/gdpr.md` and `cra.md`, `SPEC/06-threat-model/threat-model.md`, `SPEC/07-test-plan/test-plan.md`, `SPEC/08-hardening/hardening-plan.md`.
- `docs/adr/ADR-001` to `ADR-007`, `docs/handoff/HANDOFF.md`, `docs/handoff/m2-design.md` (sections 0, 4, 5, 9 to 12), `docs/handoff/m2-exit-audit.md`.
- Workspace `Cargo.toml`, `deps/fuzz-required.txt`, `deps/allowlist.txt`, `tools/deps-check/src/layering.rs`.
- Public APIs of the M1 crates: `fstp-crypto` (SHA-256, HMAC, PBKDF2 and randomness only today), `fstp-rt` (runtime trait, `duplex`, `Shutdown`), `fstp-tls` (`provider.rs` offers X25519MLKEM768 from the aws-lc-rs provider), `fstp-pgwire`, `fstp-pgtest`, `fstp-migrate`.
- Public APIs of the M2 crates: `fstp-ledger` (`RecordStore` and its refusal order) and `fstp-domain` (`oracle::Query` with ten kinds including `MeetsTieBreakCountry`, `command::Ctx`, `CommandKind::high_risk`, `visibility`).
- `fstp-engine`: `Engine`, `IdentityOracle`, `RESERVED_COMMAND_PREFIX = b"fstp:vc:"`, and the `core` and `finding` envelope members.
- The registry source of `aws-lc-rs 1.18.2`: a stable `kem` module with `ML_KEM_768`, `digest::SHA3_256`, `agreement::PrivateKey::from_private_key`, `aead::RandomizedNonceKey` and `AES_256_GCM_SIV`. ML-DSA is stable too: `signature::ML_DSA_65` and `ML_DSA_65_SIGNING` (`src/signature.rs:1172`, `:1185`) and `PqdsaKeyPair::from_seed` (`src/pqdsa/key_pair.rs:175`) need no feature. The `unstable` module only re-exports them as deprecated aliases. moduletto is not in the local registry.
- The registry source of `rustls-pki-types 1.15.1`: `src/pem.rs` decodes PEM (`PemObject`) and writes none. `zeroize 1.9.1` features: `alloc` (default), `std`, `simd`, `aarch64`, and `derive`, which pulls in `zeroize_derive`.
- `deps/adr-roots.txt`: "Using any other crate directly needs an ADR first". `tools/deps-check/src` has no Tier B release gate today.
- The M2 close-out lane, branch `m2/w7-fix` at `b0343e6` when this revision was written. It changes `fstp-domain` (assignment, decision, roles and rules) and adds scheduled role ends.
- OVHcloud public documentation, fetched or searched on 2026-10-28 (section 1.6 lists the pages and what each says).

---

## 0. Approach

### 0.1 Base and grafts

The base is the isolation-and-custody-first proposal. It had the highest combined scores (40 and 41). It treats a cell as a trust domain, seals everything a cell stores, puts one checked guard in front of every invariant, and has the most complete gap table.

Kept from the base, as the judges highlighted:

- R-NF-08 is applied to the ledger. Ledger bodies, checkpoints and audit events are sealed under cell keys, and the chain hashes the stored ciphertext. A database superuser and a cluster backup see only ciphertext.
- The cluster superuser has no remote login. Only `fstp-pgagent` on the database host uses it, in logged provisioning jobs. Cross-database statistics views are revoked from PUBLIC.
- `Gate::admit` returns an `Admitted` witness, and the async engine executes only `Admitted`. `Route::new` has no default risk class, backed by a compile-fail twin.
- An erasure planner with a stored phase. Completion is recorded only after a custody `DestroyReceipt`. An identity document's key dies at verification (P-19, R-ID-03).
- I-38 egress is two fixed structs with byte-exact capture tests.
- Synchronous anchoring before high-risk acknowledgements, and two independent witnesses.
- A trust domain per cell: its own internal CA, databases, roots and processes. The edge passes SNI through and reaches the cell over a mutually authenticated tunnel (R-NF-09).
- `Custody` has no export operation. `RootMaterial` is not `Clone`, not `Debug` and not serialisable. The test custody backend runs in its own process, so a memory scan of the cell means something (I-80).

Grafted from the vertical-slice proposal:

- A runnable stack early. `cargo run -p fstp-celltest --bin fstp-devstack` starts a local cell with the real passkey login, no bypass and no default credentials (R-NF-05).
- The hybrid combiner that hashes the ML-KEM ciphertext into the KDF input. ADR-001 and ADR-004 both require binding "the ML-KEM ciphertext".
- Composite-signed anchors as ADR-001 and R-CR-03 require. Their ML-DSA-65 half waits on the moduletto pull request (section 21.0, Q1). The per-commit receipt is made stricter in this revision: the witness receipts the prospective link before the commit (section 7.2), so no committed entry is ever unwitnessed.
- `CREATE DATABASE` cannot run inside a transaction or a DO block. Provisioning DDL therefore uses a typed identifier grammar in one place, with its own ADR.
- The seam test that runs the M2 generators through both drivers and compares records after decryption, plus `adr007_pg_store_matches_mem_store`.
- A schema catalogue with a closed `TableClass`, and a closed egress `Destination` enum for I-16.
- A cluster CA key held in OVHcloud KMS, which documents EC secp256r1 sign keys.
- `StepUpConsumed` lands in the same batch. In this revision the database guard is an insert into `auth.stepup_consumed` with a primary key, not a row update, so the ledger-writing role stays INSERT and SELECT only (ADR-007).
- A sourced OVHcloud table with honest "unsure" items.
- New vault queries are raised as questions, never added silently to the decided set (`overview.md`, "The query set was decided on 2026-10-25").

Grafted from the verification-first proposal:

- The I-81 construction: per-group level 2 keys and a root-epoch rotation per erasure batch. Only siblings in the affected group are re-sealed. The old root epoch is destroyed at once, so erasure is immediate across every backup.
- Text salts stay inside the sealed envelope, never in a clear column.
- A database insert trigger recomputes each chain link with PostgreSQL's `sha256()`. That is an independent second implementation of the link function.
- The direct-to-vault origin with signed single-use tickets. Identity attributes never enter the application, so the I-17 storage check is a check for absence (Q7).
- A cluster CA signs role certificates, while each cell sets its own SCRAM verifier. The control plane never knows a cell role's password, so D2's two factors stay split.
- Layering rule: no crate on the command path reaches the licence state or the CrabNebula client (I-39). The control plane cannot decode tenant records (I-19).
- A declared column map pins the control-plane schema.
- `may_apply` refuses updates while a call sits in STAGE1 to IRC_REVIEW or a payment release is in flight.
- The verification apparatus: every model drives a production pure core, environment faults are model actions, M-SHRED uses a symbolic attacker, canaries are scanned in every encoding, and every scanner and auditor has a seeded-leak teeth twin.
- The cross-tenant join test for I-20, `RelyingParty::new` refusing a parent domain, and UV required for management logins and every step-up.
- The reading that a magic-link session cannot perform any high-risk action, even after a step-up.
- `fstp-ledger` gains a runtime-free `AsyncRecordStore`. `fstp-engine` and `fstp-domain` stay unchanged.

### 0.2 Fixes applied to the proposals

Each flaw the judges found is fixed. Section 17.3 lists them again with sources.

1. **Combiner.** It now takes the ML-KEM ciphertext as an input and hashes it into the KDF info (section 3.2). The base proposal's signature had no such parameter.
2. **No daily ratchet.** The base re-sealed every live data key every 24 hours and completed erasure up to a day late. ADR-007 says an erasure request "is honoured at once". The final design rotates one root epoch per erasure batch and re-seals only the affected group's siblings. No new tenant parameter is needed.
3. **Attribute release.** The base returned attributes to the cell process, against "answers the application only through the queries" in `overview.md`. Attributes now go from the vault to the browser on a vault origin, with tickets (section 6.5). The conflict is raised as Q7.
4. **No refactor of `fstp-engine`.** The sans-IO `DriverCore` lives in the new `fstp-cell-core`. The unchanged M2 `Engine` becomes its reference oracle (section 5.2).
5. **Anchors are composite-signed in M3.** ADR-001 lists audit chain anchors as composite, and R-CR-03 requires it. The signature is not left empty until M9 (Q8). Its ML-DSA-65 half waits on the moduletto pull request, and composite signing refuses with a typed error until it lands (section 21.0, Q1).
6. **Projections.** ADR-007's `numeric` projection tables would store amounts in clear, against R-NF-08. M3 keeps projections in memory with sealed checkpoints, and raises the conflict as Q5.
7. **`zeroize`.** It needs no `unsafe`. It is already in the ADR-001 runtime tree. `deps/adr-roots.txt` still requires an ADR before any direct use, so ADR-001 gains it as a root with features `alloc` and `default` only. `derive` stays off, since it would pull in `zeroize_derive`, `syn`, `quote` and `proc-macro2` (Q23).
8. **Scope.** 22 new crates instead of 23 to 30. Half are pure and small. OPAQUE, EUDI Wallet login, ACME, update installation and billing are out of M3 (section 2.1).
9. **No network call per text open.** Level 2 group secrets are held in the cell and vault processes. Opening a text is a local hybrid decapsulation and an AES-GCM decryption (section 3.4).
10. **No CREATEROLE network role.** PostgreSQL 16 gives a CREATEROLE role ADMIN OPTION on the roles it creates. No role with CREATEROLE or CREATEDB has a remote login (section 4.1).
11. **No backup-generation shredding.** Deleting rows and rotating backup keys leaves dead tuples, WAL and replicas holding wrapped keys. The final design kills the wrapping key itself.
12. **Licence gate.** It gates nothing in M3. The vertical-slice proposal's `LICENCE_GATED` list is not built (Q18).
13. **No classical fallback envelope.** No "dev-classical" envelope exists, even in development. Until moduletto is pinned, tests use the aws-lc-rs ML-KEM only through a test-only crate that deps-check keeps out of shipped binaries (Q1).
14. **No domain code in the vault.** `fstp-vault-proto` and `fstp-vault-core` have their own id newtypes and no path to `fstp-domain`.
15. **Separate key clusters dropped.** The keystore is a schema in each cell database. Root-epoch destruction reaches backups, so no fourth PostgreSQL instance is needed on a self-hosted node (R-NF-01).
16. **S3 client.** It supports multipart upload for large base backups. Its responses go through a fuzzed XML subset parser for exactly three response shapes (section 3.8).
17. **Cell CA per cell.** No regional CA signs leaves for every cell (I-19, TH-06).
18. **Edge to cell is mutually authenticated** (R-NF-09). The verification-first proposal spliced plain TCP.
19. **`pg_hba_file_rules` needs superuser in PostgreSQL 16.** The isolation auditor reads it only through `fstp-pgagent` on the host.
20. **Billing.** The control plane keeps metering counters and an opaque organisation reference. Legal names and contacts stay in CrabNebula's own accounting system (Q20).
21. **Break-glass approval, gate path and logging are built** (SoD-08, TH-18), because "Approving break-glass access" is on the high-risk list.
22. **Graceful SIGTERM.** `fstp-rt` already has `Shutdown`. Signal delivery needs tokio's `signal` feature, recorded in ADR-002 (Q23).
23. **`IsMinorAtDeadline` is a question**, not an addition to the decided query set (Q13).

Fixes from the completeness review of this design:

24. **No AEAD nonce is ever derived from a row position.** The first version sealed ledger bodies with nonce `seq`, so an aborted append followed by a new one reused a nonce under one key. Every seal now draws a random nonce inside `fstp-crypto` and stores it with the row (section 3.2).
25. **I-24 has no unwitnessed window.** The witness receipts each prospective link before commit, with an abort record (section 7.2, Q8).
26. **Insert-only side effects.** Step-up consumption and session ends are insert-only rows (sections 4.1, 5.3).
27. **Keyed digests die with erasure.** The email lookup key and the identity match key rotate in every erasure batch that touches them (section 3.5).
28. **The minor flag never comes from the request** (section 6.6, Q13). Verification recording, programme-side facts and a test-only seeding path are defined (sections 6.7 to 6.9).
29. **Self-hosted provisioning, the vault's anchoring, the replication role and file custody remnants** are designed (sections 9.5, 7.2, 4.1, 3.3).

### 0.3 Gaps and conflicts found in the sources

Each gap gets the strictest reading the sources allow. Section 17 explains each against the source-of-truth order.

| Label | Finding | Strict reading built until Daniel answers | Question |
| --- | --- | --- | --- |
| G1 | ADR-004 wraps level 3 keys under long-lived level 2 keys. Backups then hold wrapped data keys whose wrapping keys stay alive, so destroying one data key does not reach backups | Per-group level 2 keys and a root-epoch rotation per erasure batch (section 3.5) | Q6 |
| G2 | R-NF-08 asks for all data at rest encrypted with cell-specific keys. ADR-007 stores bodies as plaintext canonical text and projections in `numeric` columns, on shared clusters | Seal bodies, checkpoints and audit events. Chain over stored bytes. Projections in memory | Q5 |
| G3 | ADR-005 D2 needs `clientcert=verify-full` on every `hostssl` line. OVHcloud's managed PostgreSQL documents no client certificate login, and reserves SUPERUSER for OVHcloud's operation | Self-operated PostgreSQL 16 on OVHcloud instances or Bare Metal | Q3 |
| G4 | I-82 says no database role reads across cell databases. Every cluster has a superuser that can | The superuser logs in only from the database host, through `fstp-pgagent` | Q4 |
| G5 | ADR-001 names moduletto as the post-quantum half. moduletto is not yet pinned, and `fstp-tls` uses the aws-lc-rs group | moduletto ML-KEM-768 in key wrapping, aws-lc-rs ML-KEM as test oracle only. moduletto gains ML-DSA-65 on a pull request (section 21.0). TLS changes in M9 | Q1 (answered), Q24 |
| G6 | ADR-001 and R-CR-03 sign anchors with the composite signature. ML-DSA is otherwise M9 | Composite anchors and witness receipts in M3, with the ACVP sigGen and sigVer subsets | Q8 |
| G7 | I-24 says "any" modification or deletion is detectable. Entries after the last anchor could be truncated by a database owner | Prepare, receipt, commit: the witness receipts the prospective link inside the open transaction, and an abort record follows a failed commit. No committed entry is unwitnessed | Q8 |
| G8 | I-18 and R-NG-02 need verified guardian consent before NEGOTIATION. R-NG-01 collects identity attributes only in NEGOTIATION | Guardian identity collected at the IRC_REVIEW to NEGOTIATION gate, in the vault only | Q12 |
| G9 | R-ID-02 records a "verifier", and P-18 includes "document upload with manual check". No role in `roles-and-sod.md` performs that check. Without a verification, SoD-09 refuses every Drafting and Judging grant | The tenant admin records checks, and the platform operator verifies the first tenant admin (section 6.7). Tests write verification facts only through the test-only seeding path of section 6.9, which no shipped binary contains | Q14 (answered), Q33 |
| G10 | I-78 lists "adding a passkey". `authentication.md` also asks weak accounts to add one, and asks applicants to add one after email recovery. A magic-link session cannot step up | A first passkey is accepted only inside three ceremonies: invitation, self-registration and recovery completion | Q15 |
| G11 | OPAQUE needs prime-order group arithmetic that aws-lc-rs does not expose. webauthn-rs depends on the openssl crate, as far as I know | In-house WebAuthn with fuzzed CBOR and COSE parsers. OPAQUE and EUDI Wallet login deferred | Q10 |
| G12 | Magic links and recovery emails need SMTP, which is M6 | Outbox rows in the same transaction, a recording sink in tests, no magic links in production until M6 | none |
| G13 | `overview.md` says the vault answers the application "only through the queries". The vault also needs writes, releases and acknowledgements | Those operations exist as named non-query operations. Attributes never reach the application | Q7 |
| G14 | `pg_stat_database` and similar views show every database's activity to every role | Revoked from PUBLIC on every cluster, tested as part of I-82 | none |
| G15 | R-NF-02 does not say whether IP addresses are identity attributes (open since M1) | In memory only, for rate limits, at the edge and the cell | Q19 |
| G16 | I-39 lists what licence expiry must never block, not what it may block | Expiry blocks nothing in M3 | Q18 |
| G17 | A self-hosted cell has no control plane, and I-38 forbids anchoring at CrabNebula | A local witness process is mandatory at first start. An external object-lock witness is optional | Q9 |
| G18 | The `test-plan.md` row for I-39 asks that "a full call cycle, payment and export still complete". Payments are M5 and export is M9 | M3 runs the cycle as far as it is built. M5 and M9 rerun the same test. The exit report claims I-39 only as scoped by Daniel | Q33 |
| G19 | OVHcloud KMS documents no usage log of key operations. ADR-004 reconciles backend logs with the audit chain | Reconciliation is built against the trait. OKMS reconciliation waits on the verify list | Q11 |
| G20 | R-ID-04 asks for a derived minor flag. M2 takes `CreateDraft { minor }` from the actor. Age is known only after verification, which R-NG-01 places inside NEGOTIATION | The cell sets `minor = true` on every draft and never reads the flag from the request. Every proposal then needs a verified guardian consent before NEGOTIATION | Q13 (blocking) |
| G21 | P-38 lists, P-13 class facts about partners and IRC members, and I-54 relationships live in the vault. No write path for them exists in the spec | Named vault write operations with fixed writers (section 6.8) | Q31 |
| G22 | Streaming replication and `pg_basebackup` need a REPLICATION role whose stream carries every cell's pages | Replication logs in only over loopback. Replicas restore from sealed WAL archives | Q4 |
| G23 | File custody destroys an epoch by rewriting a file. Host backups, snapshots and copy-on-write blocks keep old copies that the same passphrase opens | Per-epoch random keys on a dedicated volume, and an I-81 claim scoped to that condition | Q32 (blocking) |
| G24 | Keyed digests (email lookup, identity match key) stay in backups while their long-lived keys live | The Lookup and Match keys rotate in every erasure batch that touches them | Q6 |
| G25 | Operator interception of the first admin invitation, and root on cell hosts reading unwrapped group keys, are content access without break-glass (SoD-08, TH-18) | Split delivery of the first invitation. Risk R16 recorded and accepted | Q35 (answered 2026-10-28) |
| G26 | I-19 does not say whether counters, health states, anchor digests, edge logs and metrics are tenant data | Only fields in a declared metadata register cross. Each has a closed type | Q36 (blocking) |
| G27 | R-NF-09 asks for mutual authentication between all components. Object storage, the licence and update services and the witness bucket offer server-authenticated TLS only | Request-level credentials on those links, and R-NF-09 claimed only for internal links | Q34 |
| G28 | `authentication.md` lists "changing ... login methods" and "Granting or changing a role in the ... Judging ... groups" as high-risk. M2's `high_risk()` omits `Assign`, `Unassign` and any login-policy change | `HighRiskAction` adds them as strict additions, checked against an explicit list | Q38 |
| G29 | A self-hosted cell has no control plane, yet cluster CAs, role certificates and the first admin come from it in SaaS | A local install tool and a local agent (section 9.5) | Q15 |
| G30 | The erasure log covers the tenant, while the Auditor role binds to one programme | Auditors read only entries of their programme. Tenant admins read every entry | Q42 |

### 0.4 Where each exit invariant is held

| Invariant | Structure | Single checked guard or witness | Main tests (section 14) |
| --- | --- | --- | --- |
| I-16 | No crate builds a payment instruction or names a platform account. The schema catalogue has no fund-holding class. The cell egress enum has no payment destination | deps-check `funds` rule; `TableClass`; `Destination` | Static gate, schema scan, egress enum test, teeth |
| I-17 | Attributes live only in the vault database and reach people only on the vault origin. The application holds a ticket, never an attribute | `release::issue_ticket` in `fstp-cell-core`, plus the vault's `release_allowed` | Canary machine over HTTP, app-database absence scan, vault property, Playwright origin test, teeth |
| I-18 | The route layer sets the minor flag on every draft, so NEGOTIATION entry always asks `HasGuardianConsent` (Q13). The vault counts only an effective consent with an effective guardian verification | `fstp_vault_core::eval::guardian_consent`, `routes::commands::create_draft` | M2 lifecycle over the real vault, the literal test-plan property, M-VCP, teeth |
| I-19 | One trust domain per cell. Closed `CellToCp`. The control plane cannot decode tenant records. The edge never terminates tenant TLS | `CellToCp` type and the cell CA trust store | Multi-cell canary harness (T-ISO), declared columns, teeth |
| I-20 | Random per-cell ids. RP ID equals the exact cell host. Per-cell keyed lookups and identity match keys. No account type in control-plane crates | `RelyingParty::new`, `CellKeyedIndex::new`, layering rule 4 | Cross-tenant join test, layering, Playwright passkey test, teeth |
| I-24 | Chain rows in the ledger's transaction. A database trigger recomputes each link. Composite anchors, whose ML-DSA-65 half waits on the moduletto pull request (Q1). The witness receipts every prospective link before commit, for both chains | `ChainWriter::append`, `fstp_audit::verify` and the prepare step of the anchorer core | Mutation property, crash injection, trigger test, witness tests, M-AUDIT, teeth |
| I-38 | Only `fstp-release::egress` builds requests to CrabNebula hosts, from two closed structs | `egress::encode` | Byte-exact capture, canary scan, teeth |
| I-39 | Licence and update checks run in a background task. No command-path crate reaches `fstp-release` | `LicenceGate::permits`, layering rule 6 | Services-down cycle, M-LICENCE, teeth |
| I-77 | Strength fixed at login. Holdings checked on every request. A grant ends weak sessions in the same batch | `fstp_auth::admit_method`, `fstp_auth::admit_session` inside `Gate::admit` | M-AUTH, HTTP machine, Playwright, teeth |
| I-78 | Routes need a risk class. Step-ups are single-use, bound to the command digest and consumed in the batch | Step-up branch of `Gate::admit` | Route sweep, M-STEPUP, spec table check, compile-fail twins, Playwright, teeth |
| I-79 | Recovery completes only through `recovery::complete`, which recomputes the path at completion | `fstp_auth::recovery::complete` | M-RECOVER, HTTP machine, teeth |
| I-80 | `Custody` has no export. Root material exists only in the custody backend process | `Custody` trait surface; `RootMaterial` confined to `fstp-keyd` and the test simulator | Compile-fail twins, process memory scans, store scans, teeth |
| I-81 | Root-epoch rotation per erasure batch. Completion recorded only after the old epoch's destroy receipt | `fstp_keys::plan_erasure` and `apply` | M-SHRED, backup restore test, crash injection, teeth |
| I-82 | Per-cell roles, one owner function for grants, per-database `pg_hba` lines, no remote superuser, no remote CREATEROLE | `fstp_control::pg::cell_role_plan`, applied only by `fstp-pgagent` | Connection matrix, privilege graph, teeth |
| I-83 | Immutable cluster kind, `Placement` type, database CHECK, kind in the server certificate, runtime kind checks | `Placement::new` | Placement property, M-PLACE, start-up refusals, teeth |

### 0.5 Prerequisites from M2

- M2 closes when its exit tests are green in CI on `m2-domain-core`. The exit audit left Q-W6-3 open: the I-12 twin test. That test now exists on the branch (`i12_frozen_edits_leave_call_outcomes_unchanged`), so CI must confirm it. Q-W6-2 and Q-W6-4 stay open, and neither blocks M3.
- W0 can start before M2 closes. It touches no M2 crate.
- **M3 pins its M2 base.** The M2 close-out lane (branch `m2/w7-fix`) is changing `fstp-domain` while this design is reviewed, including scheduled role ends. M3 starts from the commit that merges that lane into `m2-domain-core` and closes M2. W0 records that commit hash in `docs/handoff/m3-exit-audit.md` before any lane starts. W0 then re-derives three things from that commit and reports any difference to Daniel: the `HighRiskAction` table against `CommandKind::high_risk()`, the holdings rule of section 8.2, and the binding-end instants that section 8.2 uses to end sessions.
- M3 changes no M2 crate except `fstp-ledger`, which gains an additive `AsyncRecordStore` trait. `fstp-domain` gains read-only accessors only if `State` lacks one that the release rule or the session-end rule needs. Lane W2c owns that change, in a new file `crates/fstp-domain/src/view.rs`, and Daniel reviews it as an M2 crate change. Every M2 test must stay green unchanged.
- M1 crates that change: `fstp-crypto` (new primitives), `fstp-rt` (signal delivery), `fstp-pgtest` (several named servers, runtime role certificates), `fstp-migrate` (catalogue types and the shared grant function, section 4.5), `tools/deps-check` (M3 rules and the Tier B release gate).

---

## 1. Trust domains and the cell boundary

### 1.1 Trust domains

| Domain | Processes | Storage | Keys | Who can talk to it |
| --- | --- | --- | --- | --- |
| Cell application | `fstp-cell` | Database `c_<cell>` on an application cluster. Cell prefix in object storage | App chain root epochs in custody. App, ledger and text group keys in memory | Users through the edge. Its own vault. Its custody backend. The control plane through `CellToCp` |
| Cell vault | `fstp-vault` | Database `v_<cell>` on a vault cluster | Vault chain root epochs in a separate custody entry with its own credential. Its own `Anchor` key | Its own cell application over mTLS. Browsers on the vault origin, through the edge, with tickets only. It calls out only to its database, its custody backend and the witness (`VaultDestination`) |
| Control plane | `fstp-control`, `fstp-pgagent` on each database host | Database `cp` on the control cluster | Control-plane custody: cluster CAs, the control-plane CA, operator ticket keys, backup chain per cluster | Operators with passkeys. Cells through `CellToCp` |
| Witness | `fstp-witness` | Its own database on its own cluster, plus an object-lock bucket at a second provider | Witness receipt key (composite) | Cells and vaults for prepares, aborts and receipts, each with a chain-bound certificate. Auditors for reads |
| Edge | `fstp-edge` | None | Edge tunnel certificate from the control-plane CA | The public internet on port 443 |
| CrabNebula release services | `fstp-licence-svc`, `fstp-update-svc` | Licence registry database on the control cluster. Release metadata in object storage | Licence signing key (Ed25519). Release keys are M9 | Self-hosted cells, through `egress` only |
| Custody backend | OVHcloud KMS, `fstp-keyd` for file custody, or the test simulator | Provider-held, or the keyd file | Root epochs and CA signing keys | Only the process of the owning domain, each with its own credential |

### 1.2 Boundary rules

- **B1.** Each cell has its own internal CA, created at provisioning. `fstp-cell` and `fstp-vault` trust only that CA for peers. A database cluster trusts its cluster CA, which signs only role certificates of that cluster.
- **B2.** Cell data lives only in the cell's two databases, its object storage prefix and its processes. Each is named by the random `CellId`, never by a tenant name.
- **B3.** Every byte of tenant data a cell writes to storage is sealed under a cell key first. Random ids, sequence numbers, times and fixed-width enums may stay in clear for indexing.
- **B4.** A cell opens connections only to its own databases, its own vault, its custody backend, the control plane, the witness and the edge tunnel. The host firewall and the closed `Destination` enum both enforce this list.
- **B4a.** A vault opens connections only to its own database, its own custody entry and the witness. The closed `VaultDestination` enum and the host firewall enforce this list. It answers its own cell and the vault origin, and calls neither.
- **B5.** The edge never terminates tenant TLS. It reads the SNI from the ClientHello and carries the bytes to the cell inside an mTLS tunnel.
- **B6.** The control plane holds no tenant account identifier, no tenant content and no identity attribute. Its crates cannot depend on a crate that defines those types.
- **B7.** Database roles, pools and certificates are per cell. No role, pool or certificate serves two cells (ADR-005).
- **B8.** A vault database is never placed on a cluster that holds or may hold an application database (I-83).
- **B9.** Root epochs are per cell and per chain. The vault chain uses a custody entry and credential separate from the application chain (ADR-004).
- **B10.** Logs and metrics are typed events from `fstp-obs`. No event field can hold free text, content, identity attributes or key bytes (R-NF-02).
- **B11.** Session tokens carry the cell id and are refused by every other cell. Passkeys use the exact tenant host as relying party id.
- **B12.** A self-hosted cell is the same cell with no control plane. It reaches CrabNebula only through `fstp-release::egress`.

### 1.3 PKI and transports

| CA | Created by | Signing key held in | Issues |
| --- | --- | --- | --- |
| Cluster CA, one per PostgreSQL cluster | `fstp-control` at cluster registration | Control-plane custody, as an EC secp256r1 sign key | The server certificate, with the cluster kind in the subject OU. Client certificates with CN equal to a role, 7-day lifetime |
| Cell CA, one per cell | The cell at first start, in the custody entry that provisioning created | The cell's application custody entry, as an EC secp256r1 sign key | `cell-app`, `cell-vault`, `cell-backup`, `cell-witness` and `vault-witness` client certificates for internal links only, 7-day lifetime, renewed daily |
| Control-plane CA, one per environment | Once, at environment set-up | Control-plane custody | `CellToCp` client certificates, edge tunnel certificates, witness server certificates |

- The witness pins each cell CA's public key, registered at provisioning (SaaS) or at install (self-hosted). It accepts `cell-witness` only for the App chain and `vault-witness` only for the Vault chain of that cell.
- `fstp-pki` writes X.509 v3 certificates in-house: a DER writer and an ECDSA secp256r1 signature, either from aws-lc-rs or from the custody `sign` operation. PostgreSQL reads certificates as PEM, so `fstp-pki::pem` writes PEM with an encoder-only base64. `rustls-pki-types` only decodes PEM, so it is not used here. `fstp-pki` parses nothing. A test in `fstp-celltest` decodes every PEM output with `fstp_pgwire::base64::decode`, so `fstp-pki` keeps no I/O dependency. Tests validate every output with rustls-webpki and with a real PostgreSQL server.
- Components generate their own key pairs. They send the public key with a proof of possession, a signature over a fresh challenge. No certificate signing request is parsed.
- Each cell role's password is generated by the cell. The cell sends only the SCRAM-SHA-256 verifier to `fstp-pgagent`. The control plane relays the verifier and the public key, and never learns the password or the private key.
- All component traffic uses `fstp-tls` with mutual authentication, TLS 1.3 only, X25519MLKEM768 preferred (R-NF-09).
- Edge to cell: the edge opens an mTLS tunnel with its tunnel certificate. The first frame is a fixed-length header: version, address family, client address and port. The client's own TLS stream follows unchanged.
- Public certificates for `<cell host>` and `id.<cell host>` need a browser-trusted CA, so the cell CA cannot issue them. Each cell generates its own key pair, so no key is shared across cells. M3 tests use a test root. Production issuance through an in-house ACME client belongs to tenant onboarding (Q30). Custom domains are M9 (I-71).

### 1.4 Deployment layout

SaaS, recommended default (Q26 covers alternatives):

```text
                Internet :443
                     |
               fstp-edge (SNI only, no tenant keys)          control plane hosts
                     | mTLS tunnel per connection            fstp-control, fstp-witness,
      +--------------+---------------+                       fstp-licence-svc, fstp-update-svc
      |                              |                       control cluster, witness cluster
  cell A app host               cell A vault host
  fstp-cell (user fstp-cell)    fstp-vault (user fstp-vault)  <- serves id.<cell host> too
      |                              |
  application cluster(s)        vault cluster(s)       <- never the same cluster (I-83)
  c_<A>, c_<B> ...              v_<A>, v_<B> ...
      \________ OVHcloud KMS (per-cell, per-chain keys) ________/
                 OVHcloud Object Storage + second EU provider
```

- Every host sits in a private vRack network. Only the edge has public addresses.
- Each process runs as its own OS user under systemd sandboxing: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `MemoryDenyWriteExecute`, `LimitCORE=0`, a system call filter, and swap disabled on hosts that hold unwrapped group keys.
- Self-hosted: one node, the same processes and OS users, plus `fstp-keyd`, a local `fstp-witness`, a local `fstp-edge` that routes `<host>` and `id.<host>` by SNI, and `fstp-pgagent` in local mode. Two PostgreSQL 16 instances with separate data directories, ports, OS users and cluster CAs. That satisfies I-83 on one node and R-NF-01. Section 9.5 describes the install.
- Operators with root on a cell or vault host can read unwrapped group keys in process memory. Sandboxing does not stop root. Risk R16 covers this, and Daniel accepted the residual risk under Q35 on 2026-10-28.

### 1.5 Edge and vault origin hosts

- `<cell host>` routes to the cell application. `id.<cell host>` routes to the vault process of the same cell.
- The edge route table holds only verified hosts. A host maps to exactly one cell and one kind (application or vault origin).
- The vault origin serves three routes only (section 6.5). It has no session cookie and accepts no request without a ticket.

### 1.6 OVHcloud for ADR-005 and ADR-004

Daniel named OVHcloud on 2026-10-28. The ADR-005 amendment records that decision. The table separates what the documentation says from what I could not confirm. Every "unsure" item goes into the L-15 due diligence before ADR-005 records it as fact.

| Need | OVHcloud service | Documented (fetched 2026-10-28) | Unsure, to verify |
| --- | --- | --- | --- |
| EU-owned provider, EU data centres (R-HS-01) | OVH Groupe SA | The investor relations page (`corporate.ovhcloud.com/en/investor-relations/shareholders-and-governance/`), as summarised by a search on 2026-10-28, gives the Klaba family about 79% of capital and 79.6% of voting rights at 5 December 2025. The company is listed on Euronext Paris. TowerBrook and KKR vehicles held about 6.31% each in the 2024 offer document. Region pages list Erith (UK) among KMS regions | I read search summaries, not the filings. To verify in L-15: the filings themselves, the contracting entity (not the US subsidiary), which regions are inside the EU, and that no service we use runs from Erith or another non-EU region. R-HS-01 is not claimed until L-15 closes |
| Certifications (an ADR-005 criterion) | OVHcloud compliance pages | Search on 2026-10-28: ISO/IEC 27001:2022, 27017, 27018 and 27701 for most services, including Public Cloud Instances and Object Storage. SecNumCloud 3.2 for Private Cloud (VMware) only. C5 Type II listed for Dedicated Servers and VMware. HDS extended to Public Cloud | Which certificate covers each service and region we use, the certificate dates, and whether KMS is in scope |
| PostgreSQL 16 availability | Public Cloud Databases for PostgreSQL | The capabilities page lists PostgreSQL 15, 16, 17 and 18, in all 1-AZ and 3-AZ Public Cloud regions, with vRack networking | Moot if Q3 A is chosen, since we then operate PostgreSQL ourselves |
| PostgreSQL 16 with `clientcert=verify-full` on every role (D2) | Public Cloud Databases for PostgreSQL (managed) | TLS is enforced. Clients verify the server with `verify-full` against a CA "shared by all the Public Cloud Databases services of your project". The admin user `avnadmin` is `NOSUPERUSER` with `CREATEDB`, `CREATEROLE` and `REPLICATION`. "The SUPERUSER attribute is reserved for OVHcloud's operation of the service." CONNECT is granted to PUBLIC by default | Whether client certificate login with a customer CA exists at all, and whether `pg_hba` can be controlled. Neither is documented on the pages read. The provider-held superuser conflicts with the strict I-82 reading |
| Same need | Self-operated PostgreSQL 16 on Public Cloud instances or Bare Metal in a vRack | Not a managed product fact | Instance disk encryption defaults, anti-affinity options, operating cost (risk R2) |
| Root epochs (ADR-004, I-80, I-81) | OVHcloud KMS (OKMS) | Key types `oct` (128, 192, 256 bits) with encrypt, decrypt, wrapKey and unwrapKey; RSA; EC (curves secp256r1, secp384r1 and secp521r1) with sign and verify. Direct encryption is for "less than 4 kB". `protectionLevel` is `SOFTWARE` by default or `HSM` ("shared specialised hardware"). A key must be disabled before deletion, state changes "take effect immediately", and "deleting an encryption key is permanent". Keys stay in their region. Billing is per key stored. REST takes a personal access token, a service account or an access certificate; KMIP requires an access certificate. PCI-DSS covers "only key creation through regionalized APIs" | Whether REST accepts an access certificate as mutual TLS (R-NF-09). Whether deleted key material survives in provider backups (I-81). Rate limits and key quotas. Any usage log of key operations for ADR-004 reconciliation. Certification of the HSM protection level |
| KMS regions and the HSM level | OKMS | Search on 2026-10-28: the product page says software KMS is "available in all regions". KMS on HSM is in "progressive deployment"; an older Labs page named Paris and Milan first. The product page says KMS on HSM is backed by Thales Luna HSMs validated to FIPS 140-3 Level 3 | Which EU regions offer `HSM` today. Whether the FIPS claim covers the regions we use. Q11 needs both |
| CrabNebula-operated HSM (a second R-KY-01 backend) | OVHcloud HSM offerings | Search on 2026-10-28: "Cloud HSM" with a PKCS#11 driver is a Labs alpha in Paris and Milan, alpha ending 30 November 2026. "Dedicated HSM" is listed as coming soon | General availability, contract terms and certification. A PKCS#11 client still needs an ADR-001 Tier A review. R-KY-01 is claimed in M3 for the KMS option only (Q33) |
| Backups and anchors | Object Storage, S3-compatible | Object lock configuration is supported in Regions and Local Zones. Legal hold and retention are supported in Regions, not in Local Zones. Versioning and multipart upload are supported | Which EU regions offer each feature. Per-bucket credentials per cell |
| Second EU backup provider | Not OVHcloud | ADR-005 asks for one | Daniel chooses (Q25) |
| Edge | Anti-DDoS on public addresses, Public Cloud Load Balancer | Search on 2026-10-28: the concepts page lists a TCP listener with an HTTPS pool and a TLS-HELLO health monitor. The product page calls its HTTPS listener passthrough, as opposed to TERMINATED_HTTPS | Whether a TCP listener forwards the ClientHello byte for byte, and whether it can pass the client address. The edge does not need the load balancer if the edge hosts take public addresses directly |

Pages read: `docs.ovhcloud.com/en/guides/manage-and-operate/kms/quick-start`, `.../kms/kms-usage`, `.../public-cloud/databases/postgresql-secure-connection-tls`, `.../public-cloud/databases/postgresql-users-roles-grants`, `.../storage-and-backup/object-storage/s3-s3-compliancy`. Searched on 2026-10-28, summaries only: `.../public-cloud/databases/postgresql-capabilities`, `www.ovhcloud.com/en/identity-security-operations/key-management-service/`, `labs.ovhcloud.com/en/managed-hsm/`, `.../public-cloud/network-services/load-balancer-concepts`, `www.ovhcloud.com/en/compliance/`, `corporate.ovhcloud.com/en/investor-relations/shareholders-and-governance/`. A search summary is a lead for L-15, not a fact for an ADR.

What the OVHcloud decision implies, if Daniel answers Q3 and Q11 as recommended:

- **ADR-005.** Provider OVHcloud, decided by Daniel on 2026-10-28. With Q3 A, PostgreSQL 16 is self-operated on OVHcloud hosts in EU regions, because D2 and I-82 need control of `pg_hba`, client CAs and the superuser. Clusters carry an immutable kind. Backups go to OVHcloud Object Storage with object lock and to a second EU-owned provider. D3 stays deferred. Self-operation lets us choose the PostgreSQL build, so a release whose TLS group setting accepts hybrid groups can be adopted once one is verified.
- **ADR-004.** With Q11 A or B, OKMS is the "EU-operated KMS" backend. Each root epoch is one `oct` 256-bit key with `protectionLevel` `HSM` (Q11), used through wrapKey and unwrapKey. Each CA key is one EC secp256r1 key. Destruction is "disable, then delete". Each erasure batch creates and deletes one key per affected chain, so quotas and per-key billing matter (Q6, Q11). The CrabNebula-operated HSM backend is not built in M3, because a PKCS#11 client crate needs an ADR-001 Tier A review.

---

## 2. Crate and binary layout

### 2.1 New crates

| Crate | Responsibility | In-house dependencies | Third-party | I/O | Fuzz project |
| --- | --- | --- | --- | --- | --- |
| `fstp-pki` | X.509 v3 DER writer, lifetimes, proof of possession. Pure: it returns the bytes to sign and assembles the certificate from a signature, so the caller signs through aws-lc-rs or custody | `fstp-crypto` | none. PEM is written in-house | no | yes |
| `fstp-keys` | Key hierarchy model, envelope formats, group and epoch state, the erasure planner. Pure | `fstp-crypto`, `fstp-json` | none | no | yes |
| `fstp-custody` | `Custody` trait, `OkmsCustody` client, `KeydCustody` client | `fstp-keys`, `fstp-crypto`, `fstp-json`, `fstp-http`, `fstp-tls`, `fstp-rt` | `zeroize` (features `alloc`, `default`; Q23) | yes | yes |
| `fstp-keyd` | File custody server for self-hosted cells. The only shipped crate that names `RootMaterial` | `fstp-custody`, `fstp-crypto`, `fstp-rt` | `zeroize` (features `alloc`, `default`; Q23) | yes | yes |
| `fstp-audit` | Chain row format, link function, verifier, anchor and receipt formats, composite signing calls. Pure | `fstp-crypto`, `fstp-json`, `fstp-ledger` | none | no | yes |
| `fstp-obs` | Closed log and metric event enums | `fstp-json` | none | writes only | no (no parser) |
| `fstp-pgstore` | `PgRecordStore`, chain writer, keystore tables, text store, schema catalogue, per-role pools, app migrations | `fstp-pgwire`, `fstp-migrate`, `fstp-ledger`, `fstp-audit`, `fstp-keys`, `fstp-rt`. Generic over the record type through `fstp_ledger::Canonical` for encoding and a decode function the composer passes in, so it never names `CellRecord` | none | yes | yes |
| `fstp-vault-proto` | Vault wire types, tickets and codecs. Own id newtypes | `fstp-json`, `fstp-money` | none | no | yes |
| `fstp-vault-core` | Vault facts, epochs, the commit protocol, query evaluation, release and write rules. Pure | `fstp-vault-proto`, `fstp-money` | none | no | yes |
| `fstp-vault` | Vault service: internal API, vault origin, persistence, vault migrations, its own anchorer. No seeding path | `fstp-vault-core`, `fstp-keys`, `fstp-custody`, `fstp-audit`, `fstp-pgwire`, `fstp-migrate`, `fstp-http`, `fstp-tls`, `fstp-obs`, `fstp-rt` | none | yes | yes |
| `fstp-webauthn` | Strict CBOR subset, COSE keys, authenticator and client data, registration and assertion verification. Pure | `fstp-crypto`, `fstp-json` | none | no | yes |
| `fstp-auth` | Login policy, sessions, step-up, recovery, magic links, enrolment ceremonies. Pure | `fstp-webauthn`, `fstp-domain` (ids and roster view), `fstp-json` | none | no | yes |
| `fstp-cell-core` | `CellCommand`, `CellRecord`, `CellState`, the gate, `DriverCore`, the release rule, tenant records. Pure | `fstp-engine`, `fstp-domain`, `fstp-auth`, `fstp-keys` (records only), `fstp-ledger`, `fstp-crypto`, `fstp-json` | none | no | yes |
| `fstp-cell` | Cell runtime: async engine, routes, background tasks (anchorer, erasure runner, licence and update checks). Binary `fstp-cell` | `fstp-cell-core`, `fstp-pgstore`, `fstp-custody`, `fstp-vault-proto`, `fstp-cp-proto`, `fstp-release`, `fstp-edge` (the tunnel header codec only), `fstp-http`, `fstp-tls`, `fstp-obs`, `fstp-rt` | tokio through `fstp-rt` | yes | yes (request bodies) |
| `fstp-cp-proto` | Closed `CellToCp` and `CpToCell` types and codec | `fstp-json` | none | no | yes |
| `fstp-control` | Registry, placement, provisioning, routing, operator tickets, metering, isolation auditor, the cell role plan. Binaries `fstp-control`, `fstp-pgagent` and the self-hosted `fstp-install` (section 9.5) | `fstp-cp-proto`, `fstp-pki`, `fstp-custody`, `fstp-webauthn` (staff passkeys), `fstp-pgwire`, `fstp-migrate`, `fstp-http`, `fstp-tls`, `fstp-obs` | none | yes | yes |
| `fstp-witness` | Anchor intake, per-cell anchor chains, receipts. PostgreSQL store for SaaS and an append-only file store for self-hosted. Binary `fstp-witness` | `fstp-audit`, `fstp-cp-proto`, `fstp-pgwire`, `fstp-http`, `fstp-tls` | none | yes | yes |
| `fstp-edge` | ClientHello SNI parser, route table, tunnel header, splice. Binary `fstp-edge` | `fstp-tls` (tunnel client only), `fstp-rt`, `fstp-json` | none | yes | yes |
| `fstp-release` | Licence token and release metadata formats, licence state, `may_apply`, and the I-38 `egress` client | `fstp-crypto`, `fstp-json`, `fstp-http`, `fstp-tls` | none | yes, client only | yes |
| `fstp-release-svc` | CrabNebula licence and update services. Binaries `fstp-licence-svc`, `fstp-update-svc` | `fstp-release`, `fstp-pgwire`, `fstp-migrate`, `fstp-http`, `fstp-tls` | none | yes | yes |
| `fstp-backup` | Backup container, multipart S3 client with SigV4 and an XML subset parser. Binary `fstp-backup` | `fstp-keys`, `fstp-custody`, `fstp-crypto`, `fstp-http`, `fstp-tls` | none | yes | yes |
| `fstp-celltest` | Test only, `publish = false`. Multi-cell worlds, custody simulator, software authenticator, canaries, scanners, egress recorder, references, models, the vault fact seeder (section 6.9). Binaries `fstp-custody-sim`, `fstp-devstack` and `fstp-vault-seeded` | everything above, including `fstp-vault-core` under the rule 2 test exception, `fstp-pgtest`, `fstp-prop`, `fstp-mc`, `fstp-domain-testkit` | aws-lc-rs ML-KEM and ML-DSA (stable APIs, no extra feature) as test oracles | yes | yes (`proc_maps` reader) |

Out of M3: OPAQUE, EUDI Wallet login and verification, ACME and custom domains, update installation, billing and invoicing, a PKCS#11 backend.

### 2.2 Changes to existing crates

| Crate | Change |
| --- | --- |
| `fstp-crypto` | New modules: `aead` (AES-256-GCM through `aws_lc_rs::aead::RandomizedNonceKey`; no function takes a caller nonce), `kdf` (HKDF-SHA-256), `sha3` (SHA3-256) and `x25519` (static and ephemeral keys). Also `sig` (Ed25519 sign and verify, ECDSA secp256r1 sign and verify, RSA PKCS#1 SHA-256 verify for WebAuthn RS256), `mlkem` (moduletto ML-KEM-768), `mldsa` (moduletto ML-DSA-65), `hybrid_kem` (section 3.2), `composite` (section 7.4). Until the moduletto ML-DSA-65 pull request lands, every `mldsa` call refuses with a typed error. Secret types implement no `Debug` or `Clone` and zeroize on drop. moduletto is reachable only through this crate |
| `fstp-ledger` | `AsyncRecordStore<R>`: the same contract and refusal order as `RecordStore`, using only `core::future`. Additive. No decode trait is added: `PgRecordStore` takes the decoder as a function value (section 5.3) |
| `fstp-migrate` | `catalogue` module: `TableSpec`, `TableClass` and `ColumnSpec` types, and the shared SQL of `fstp_meta.apply_grant` (section 4.1). Additive. Each migration set's owner lists its own tables beside its migrations |
| `fstp-rt` | `signal` module behind the runtime trait, so SIGTERM triggers the existing `Shutdown` (tokio `signal` feature, Q23) |
| `fstp-pgtest` | Several named servers per test binary (`PgServer::shared_named`), any role name, client certificates minted at runtime by `fstp-pki` from a test cluster CA, generated per-database `pg_hba` lines |
| `tools/deps-check` | M3 layering rules (section 2.4), a `funds` rule (I-16), a one-runtime-per-binary rule (ADR-002), an npm lockfile check for `web/` and `e2e/` (ADR-003), and the Tier B release gate (section 2.6) |
| `fstp-engine`, `fstp-domain` | Unchanged. `fstp-domain` gains a read-only accessor in `src/view.rs` only if the release rule or the session-end rule needs one, with no record change (section 0.5) |

### 2.3 Binaries and runtime

Every binary uses tokio 1.54.1 through `fstp_rt::tokio::TokioRuntime`, exactly once. smol is not used in M3. Its fit for the self-hosted cell stays open, as ADR-002 notes.

| Binary | Crate | Runs | Listens on |
| --- | --- | --- | --- |
| `fstp-cell` | `fstp-cell` | One cell's application | Tunnel port from the edge; internal mTLS port for the vault; loopback health |
| `fstp-vault` | `fstp-vault` | One cell's vault and its origin | Internal mTLS port for its cell; tunnel port for the vault origin |
| `fstp-keyd` | `fstp-keyd` | Self-hosted file custody | Unix socket, readable only by the cell and vault OS users |
| `fstp-control` | `fstp-control` | SaaS control plane | Control-private port |
| `fstp-pgagent` | `fstp-control` | Provisioning agent on each database host | Control-private port, mTLS from the control-plane CA |
| `fstp-witness` | `fstp-witness` | Anchor witness, SaaS or self-hosted | Control-private port, or loopback when self-hosted |
| `fstp-edge` | `fstp-edge` | SNI router | Public :443 |
| `fstp-licence-svc`, `fstp-update-svc` | `fstp-release-svc` | CrabNebula-hosted services | Public :443 |
| `fstp-backup` | `fstp-backup` | Backup agent next to each cluster, called by `archive_command` and a timer | none |
| `fstp-install` | `fstp-control` | Self-hosted install and certificate renewal (section 9.5) | none |
| `fstp-custody-sim`, `fstp-devstack`, `fstp-vault-seeded` | `fstp-celltest` | Tests and local development only | Loopback |

### 2.4 Layering rules

`tools/deps-check/src/layering_m3.rs` reuses the reach logic of `layering.rs`. Each rule has a passing designed graph and a failing fixture graph, as the M2 rules do.

1. **Pure cores do no I/O.** `fstp-keys`, `fstp-audit`, `fstp-vault-proto`, `fstp-vault-core`, `fstp-webauthn`, `fstp-auth`, `fstp-cell-core`, `fstp-cp-proto` and `fstp-pki` reach none of `fstp-rt`, `fstp-http`, `fstp-tls`, `fstp-pgwire`, `fstp-pgtest`, `fstp-migrate` or tokio.
2. **Vault narrowness.** `fstp-vault`, `fstp-vault-core` and `fstp-vault-proto` reach none of `fstp-domain`, `fstp-engine`, `fstp-findings` or `fstp-cell-core`. No crate outside `fstp-vault` reaches `fstp-vault-core`, except the test-only `fstp-celltest`, which seeds facts through it (section 6.9).
3. **One composer.** Only `fstp-cell` depends on both `fstp-cell-core` and `fstp-pgstore` at runtime.
4. **The control plane cannot decode tenant data (I-19, I-20).** `fstp-control`, `fstp-cp-proto`, `fstp-witness`, `fstp-edge`, `fstp-release` and `fstp-release-svc` reach none of `fstp-domain`, `fstp-engine`, `fstp-findings`, `fstp-auth`, `fstp-cell-core`, `fstp-pgstore` or `fstp-vault*`.
5. **The edge holds no tenant TLS server.** `fstp-edge` reaches `fstp-tls`, but a source scan refuses any server configuration constructor in it. A behaviour test checks that bytes after the ClientHello pass unchanged.
6. **I-39.** Only `fstp-cell` and `fstp-release-svc` reach `fstp-release`. None of `fstp-cell-core`, `fstp-engine`, `fstp-domain`, `fstp-pgstore`, `fstp-vault` or `fstp-backup` reaches it.
7. **I-80.** A source scan allows the identifier `RootMaterial` only in `fstp-keyd` and `fstp-celltest`. Only `fstp-cell`, `fstp-vault`, `fstp-control`, `fstp-backup`, `fstp-keyd` and `fstp-celltest` reach `fstp-custody`.
8. **Tier B confinement.** moduletto is reachable only through `fstp-crypto`.
9. **Test and dev crates never ship.** `fstp-celltest` joins `TEST_ONLY`. The aws-lc-rs ML-KEM and ML-DSA oracles are reachable only from it. A source scan refuses the identifiers `SeedSource` and `seed_fact` outside `fstp-celltest`, so no shipped binary can write a vault fact around the vault's own write rules.
10. **One runtime per binary (ADR-002).** Each `[[bin]]` target's resolved graph holds at most one of tokio and smol.
11. **Funds (I-16).** Section 14.4.
12. **The M2 rules stand,** including I-10.

### 2.5 Third-party additions

| Item | Why | ADR action |
| --- | --- | --- |
| moduletto: ML-KEM-768 now, ML-DSA-65 once its pull request lands | Post-quantum half of key wrapping and of composite anchors | ADR-001 A2 record: repository `https://github.com/crabnebula-dev/moduletto`, full commit, version, features and resolved tree (`subtle`, `libm`, `zeroize`). ML-DSA-65 is added on a moduletto pull request that Claude writes and Daniel reviews and merges. Tier B release gate I-74 applies (section 2.6) |
| `zeroize 1.9.1` as a direct dependency, features `alloc` and `default` only | Wiping secrets without `unsafe` | ADR-001 amendment before first use, because `deps/adr-roots.txt` says "Using any other crate directly needs an ADR first". A new root line `zeroize ADR-001 alloc,default`. `derive` is refused, since it adds `zeroize_derive`, `syn`, `quote` and `proc-macro2` (Q23) |
| tokio `signal` feature, adding `signal-hook-registry` | SIGTERM for graceful shutdown (ADR-002 Needs) | ADR-002 review note before first use ("Enabling an additional feature needs a review note"), then the record with the resolved version and tree. The tokio root line in `deps/adr-roots.txt` gains `signal` (Q23) |
| Node.js and npm, as the host for tsc and Playwright | tsc and Playwright run on Node.js. ADR-003 allowlists tsc, libFuzzer and Playwright only | ADR-003 amendment by Daniel before W3c starts (Q39). A record line alone does not cover a new tool |
| tsc, Playwright and its pinned browsers | Login, step-up, sessions and vault origin pages; Playwright tests for I-17, I-20, I-77, I-78 | ADR-003 first-use records with versions and trees |

No other crate or npm package is needed. webauthn-rs and opaque-ke are not used (Q10).

- **No aws-lc-rs feature change.** The aws-lc-rs ML-DSA oracle needs no `unstable` feature. `signature::ML_DSA_65`, `ML_DSA_65_SIGNING` and `PqdsaKeyPair::from_seed` are stable in 1.18.2. `from_seed` also lets the oracle run ACVP keyGen vectors.
- **No `rustls-pki-types` edge from `fstp-pki`.** Version 1.15.1 only decodes PEM. The PEM writer is in-house (section 1.3).
- **One owner for dependency files.** The lead owns the workspace `Cargo.toml`, every third-party line in a crate manifest, `deps/allowlist.txt`, `deps/adr-roots.txt`, `deps/fuzz-required.txt` and `deps/funds-allowed.txt`. Lanes request a change, and the lead lands it as its own staged commit with the ADR record (section 19).

### 2.6 Tier B release gate (I-74, R-CR-02, H-18)

M3 brings moduletto into production code, so the gate ADR-001 asks for is built now. "CI blocks a release build whose Tier B versions lack a matching confirmation."

- `tools/deps-check/src/tier_b.rs` reads the resolved tree for each shipped `[[bin]]`. Every package marked Tier B in `deps/allowlist.txt` must have a confirmation row. ADR-001 records each confirmation "with crate, version, source hash, review date and findings reference". deps-check reads the mirror `deps/tier-b-confirmations.txt`, and a test checks that the mirror equals the ADR-001 rows. The source hash must equal the `.crate` SHA-256 that `deps/allowlist.txt` pins.
- `deps-check --release` fails without a matching confirmation. Development and test builds report the missing confirmation and pass, as ADR-001 allows Tier B use in development.
- The release workflow job runs `deps-check --release`. M3 ships no release, so the job runs on a tag pattern only, and its fixture test runs on every push.
- Tests: `i74_release_gate_refuses_unconfirmed_tier_b_version`, `i74_release_gate_refuses_a_confirmation_for_another_hash`, `i74_dev_build_reports_but_passes`, and `i74_teeth_gate_skipping_tier_b_is_caught`.

---

## 3. Key custody

### 3.1 Hierarchy as built

| ADR-004 level | Object | Held in | Lifetime |
| --- | --- | --- | --- |
| 1 | Root epoch `R(cell, chain, e)` | Custody backend. Created there, never exported | Until the next erasure batch on that chain, then destroyed |
| 1, wrap step | Epoch seal key `S(cell, chain, e)`, 32 bytes | Wrapped by `R(e)` through custody wrapKey. Unwrapped into process memory only | Same as `R(e)` |
| 2 | Group key `G(cell, chain, purpose, group, gen)`: X25519 plus ML-KEM-768 | Public half in `keystore.group_key`. Secret half sealed with AES-256-GCM under `S(e)` | Until its group takes part in an erasure batch, then replaced by generation `gen + 1` |
| 3 | Data key per object, AES-256-GCM | `keystore.data_key`: sealed to its group key through the hybrid KEM | Until destroyed |

- `S(e)` is not a root key. It is how the root wraps level 2 keys while keeping custody calls to one per epoch. The root itself never leaves custody (I-80).
- Rotation re-wraps level 2 secrets under a new epoch. Data is never re-encrypted, as ADR-004 requires.

Chains and purposes:

| Chain | Process | Purposes and groups | Rotated by |
| --- | --- | --- | --- |
| App | `fstp-cell` | `Text` (groups of at most 256 data keys), `Ledger` (one group, keys replaced every 2^20 seals); `Lookup` and `CredLookup` (HMAC keys for the email and credential id indexes, each its own group, replaced in every batch that erases an email or a credential); `Ticket` (Ed25519 ticket key); `Anchor` (composite anchor key) | Each erasure batch of App data keys |
| Vault | `fstp-vault` | `Attribute`, `Document` (one group per document), `Fact`, `Match` (identity match key, its own group, replaced in every batch that erases an identity), `Anchor` (the vault chain's composite anchor key) | Each erasure batch of Vault data keys, including every verification (P-19) |
| CellBackup | `fstp-cell` | Keystore snapshot containers | Yearly re-wrap. Never rotated by erasure |
| ClusterBackup | `fstp-control` | Cluster backup containers | Yearly re-wrap. Never rotated by erasure |
| ControlPlane | `fstp-control`, `fstp-witness` (separate entries and credentials) | Licence, staff assertion and operator ticket keys; the witness receipt key (section 3.9) | Yearly re-wrap |

The Vault chain uses its own custody entry and credential (ADR-004, R-NF-08).

### 3.2 Hybrid KEM and sealed formats (Q2)

The recommended combiner. ADR-004 fixes its exact bytes and test vectors before implementation, and H-19 reviews it.

```text
(ct_M, ss_M) = ML-KEM-768.Encaps(pk_M)                         -- moduletto
(e, E)       = X25519 ephemeral key pair;  ss_X = X25519(e, pk_X)  -- aws-lc-rs
prk = HKDF-SHA-256-Extract(salt = "fstp-hkem-v1", ikm = ss_M || ss_X)
ss  = HKDF-SHA-256-Expand(prk, info = SHA-256(ct_M) || E || pk_X || SHA-256(pk_M), L = 32)
```

It binds both shared secrets, the ML-KEM ciphertext and the X25519 public values, as ADR-001 and ADR-004 ask. Exact X-Wing, as the review of the proposals found, omits the ML-KEM ciphertext from its KDF input. ADR-004 must confirm that against the pinned draft text, not from memory.

```rust
// fstp-crypto::hybrid_kem
pub struct HybridPublicKey { x: X25519Public, m: MlKem768EncapsKey }          // 32 + 1184 bytes
pub struct HybridSecretKey { x: X25519Secret, m: MlKem768DecapsKey, public: HybridPublicKey } // zeroized on drop
pub struct HybridCiphertext { e: [u8; 32], m: [u8; 1088] }
pub fn generate() -> Result<HybridSecretKey, CryptoError>;
pub fn encapsulate(pk: &HybridPublicKey) -> Result<(HybridCiphertext, SharedSecret), CryptoError>;
pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> Result<SharedSecret, CryptoError>;
/// The combiner. Every input that ADR-004 names is a parameter.
fn combine(ss_m: &[u8; 32], ss_x: &[u8; 32], ct_m: &[u8; 1088], e: &[u8; 32],
           pk_x: &[u8; 32], pk_m: &[u8; 1184]) -> SharedSecret;

// fstp-keys::envelope
pub struct SealContext { pub cell: CellId, pub chain: Chain, pub purpose: Purpose,
                         pub group: GroupId, pub generation: u32, pub object: ObjectId }
pub struct SealedKey { header: KeyHeader, ct: HybridCiphertext, nonce: [u8; 12], wrapped: [u8; 48] }
pub struct SealedBlob { header: BlobHeader, nonce: [u8; 12], body: Vec<u8> }  // ciphertext || tag
pub fn seal_key(pk: &HybridPublicKey, dek: &DataKey, ctx: &SealContext) -> Result<SealedKey, SealError>;
pub fn open_key(sk: &HybridSecretKey, s: &SealedKey, ctx: &SealContext) -> Result<DataKey, SealError>;
pub fn seal_blob(dek: &DataKey, ctx: &SealContext, pt: &[u8]) -> Result<SealedBlob, SealError>;
pub fn open_blob(dek: &DataKey, ctx: &SealContext, b: &SealedBlob) -> Result<Zeroizing<Vec<u8>>, SealError>;
pub fn decode_sealed_key(bytes: &[u8]) -> Result<SealedKey, DecodeError>;   // fuzzed
pub fn decode_sealed_blob(bytes: &[u8]) -> Result<SealedBlob, DecodeError>; // fuzzed
```

- **Wire form of a sealed key.** `"FSK1" | version u8 | kem u16 | aead u16 | chain u8 | group 16 | generation u32 | e 32 | ct_m 1088 | nonce 12 | wrapped 48`. Every length is fixed, and the decoder accepts exactly one spelling.
- **Key derivation.** The AES key is HKDF-SHA-256 over `ss`, with info `"fstp-seal-v1"` and the header bytes. The AAD is the header plus the canonical `SealContext`. A sealed key moved to another object, group, generation, chain or cell fails to open.
- **Nonces.** Every AES-256-GCM seal in the platform goes through `fstp_crypto::aead::seal`, which wraps `aws_lc_rs::aead::RandomizedNonceKey`. It draws a fresh 96-bit nonce from the system generator and returns it, and the nonce is stored in the sealed bytes. No function in the workspace takes a nonce from its caller, and none derives one from a sequence number, row id or counter. That covers ledger bodies, chain event bodies, checkpoints, outbox rows, texts, keystore secrets and backup chunks.
- **Why.** The first version used nonce `seq` for ledger bodies. A transaction that aborted after sealing left that ciphertext in the WAL and in archived WAL. The next command then sealed a different body at the same `seq`, under the same key and nonce. Under GCM that reveals the XOR of the two plaintexts and allows tag forgery. An attacker could trigger it by replaying a consumed step-up. With random nonces an aborted attempt and its retry never share a nonce.
- **Usage limit.** Random 96-bit nonces stay safe for well under 2^32 seals per key. Every key here seals far fewer: a ledger key is replaced after 2^20 seals, bodies and chain events together, and every other data key seals one object or one backup. `fstp-keys` counts seals per key and refuses at 2^24, which a test checks. AES-256-GCM-SIV (stable in aws-lc-rs) is the fallback if H-19 asks for misuse resistance on top.
- **Vectors.** Combiner vectors run on fixed inputs, computed by an independent implementation in `fstp-celltest`. ML-KEM ACVP vectors need deterministic encapsulation. aws-lc-rs does not expose it. moduletto does, through `keygen_derand` and `encaps_derand` (Q1, later answer in section 21.0).
- **Differential test.** moduletto ML-KEM-768 and aws-lc-rs ML-KEM-768 decapsulate each other's ciphertexts on random keys (ADR-001 Verification, T-CR-HYBRID).

### 3.3 Custody trait and backends

```rust
// fstp-custody
pub enum Chain { App, Vault, CellBackup, ClusterBackup, ControlPlane }
pub struct RootRef { backend: BackendId, cell: Option<CellId>, chain: Chain, epoch: Epoch, handle: CustodyHandle }
pub struct SealKey(Zeroizing<[u8; 32]>);          // no Clone, no Debug output, no ToJson
pub struct WrappedSealKey(Vec<u8>);               // backend-specific, opaque
pub struct SignKeyRef { backend: BackendId, handle: CustodyHandle }   // EC secp256r1, CA use only

pub trait Custody: Send + Sync + 'static {
    fn create_root(&self, label: RootLabel) -> impl Future<Output = Result<RootRef, CustodyError>> + Send;
    fn wrap(&self, root: &RootRef, key: &SealKey, aad: &Aad) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send;
    fn unwrap(&self, root: &RootRef, w: &WrappedSealKey, aad: &Aad) -> impl Future<Output = Result<SealKey, CustodyError>> + Send;
    fn destroy(&self, root: &RootRef) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send;
    fn sign(&self, key: &SignKeyRef, digest: &[u8; 32]) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send;
    fn usage_since(&self, root: &RootRef, cursor: UsageCursor) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send;
}
```

- There is no export method, so no code path can ask for a root (I-80).
- `DestroyReceipt` records the backend's own confirmation that the key material is gone, not merely scheduled. For OKMS that is "disable, then delete", with the state read back.

| Backend | Use | Notes |
| --- | --- | --- |
| `OkmsCustody` | SaaS default | REST over `fstp-http`. One `oct` 256-bit HSM-level key per root epoch, one EC secp256r1 key per CA. The response decoder is fuzzed. Authentication follows Q11 |
| `KeydCustody` | Self-hosted small installs (ADR-004 "passphrase-protected file key") | Framed protocol over a Unix socket to `fstp-keyd`. The custody boundary is the `fstp-keyd` process. Interim layout below; Q32 asks Daniel to choose |
| PKCS#11 | CrabNebula HSM | Not in M3. Needs a crate under an ADR-001 Tier A review, since FFI needs `unsafe`. OVHcloud's PKCS#11 "Cloud HSM" is a Labs alpha (section 1.6) |
| `SimCustody` | Tests | Lives in `fstp-celltest` and runs as `fstp-custody-sim`, its own process, so memory scans can show root bytes never enter the cell or vault |

**File custody, interim layout (G23, Q32).** The first version kept every epoch in one file sealed under a passphrase-derived key, and destroyed an epoch by rewriting the file. Old copies of that file in host backups, filesystem snapshots, copy-on-write extents or remapped SSD blocks would still open with the same passphrase. I-81 says "including from backups", so that layout fails it.

- Each root epoch is 32 random bytes in its own file `epoch-<chain>-<e>.key`, sealed with AES-256-GCM under a per-epoch random key `K(e)`.
- The `K(e)` values live in a separate small key table, sealed under the passphrase-derived key (PBKDF2-HMAC-SHA-256 from `fstp-crypto`, at least 600 000 iterations).
- Both live in a key directory that the install puts on a dedicated volume. `fstp-keyd` refuses to start if `statfs` reports btrfs, ZFS, overlayfs or a network filesystem there. The install excludes that volume from host backup tooling it knows, and the operator guide says so.
- Destroy overwrites `K(e)` in the key table in place, fsyncs, unlinks the epoch file, fsyncs the directory, and reads back. The receipt records these steps.
- This narrows the remnant to the key table on one non-copy-on-write volume. It does not remove SSD remapping or a host backup the install does not know about. The I-81 claim for file custody is therefore scoped to "the key volume is excluded from host backups and snapshots", and the exit report says so. Q32 offers stronger options.
- **Unattended boot (I-80, R-NF-05).** There is no default passphrase. The interim reads it from a systemd credential (`LoadCredentialEncrypted=`), which systemd can bind to the host's TPM 2.0. On a host without a TPM, `fstp-keyd` waits for the operator to enter it through `systemd-ask-password`, and the cell does not start until then. systemd does the TPM work, so no crate is added. That systemd feature set is from my own knowledge, so ADR-004 records the minimum systemd version only after W2f checks it.

Reconciliation (ADR-004): every custody call first writes a `KeyOp` audit event with a request id. A daily task reads `usage_since` and compares. A backend entry without a matching event raises `CustodyAnomaly`. OKMS documents no usage log on the pages read, so OKMS reconciliation waits on Q11.

### 3.4 Keys at runtime

- `fstp-cell` and `fstp-vault` each hold their own chain. At start, each unwraps its current `S(e)` through custody, then opens its group secrets into `Zeroizing` memory.
- Opening a text costs one hybrid decapsulation and one AES-GCM decryption, both local. No network call is made per open (fix 9). The latency budget is measured in W2 (risk R4).
- A data key under destruction cannot be opened from the moment its request is recorded. The in-memory index refuses it before the planner runs.
- Rate limits per caller and purpose bound the decryption oracle a compromised handler could run.

### 3.5 Erasure construction (I-81, R-KY-02, ADR-007)

Why it is needed: a backup, a WAL segment, a replica or a dead tuple can hold a copy of a sealed data key. That copy is recoverable as long as some live key can open its group key. So the wrapping chain itself must die, and live keys must move first.

```rust
// fstp-keys::erasure (pure)
pub struct ChainState {
    epoch: Epoch,                                  // current root epoch
    groups: BTreeMap<GroupId, GroupState>,         // generation, members, state
    destroying: BTreeMap<DekId, ErasureRequest>,   // refused for open from the request on
    roots: BTreeMap<Epoch, RootState>,             // Active | Retiring | Destroyed(receipt)
    phase: Phase,                                  // Idle | Planned | Resealed | Committed | SnapshotVerified | Destroyed
}
pub enum Step {
    NewGroups { groups: Vec<GroupId> },
    Reseal { group: GroupId, keep: Vec<DekId> },   // batches of at most 256
    NewEpoch(Epoch), RewrapGroups(Epoch), Commit(Epoch),
    Snapshot(Epoch), VerifySnapshot(Epoch),
    DestroyRoot(Epoch), Complete { epoch: Epoch, erased: Vec<DekId> },
}
pub fn plan_erasure(s: &ChainState, batch: &BTreeSet<DekId>) -> ErasurePlan;
pub fn next(s: &ChainState) -> Option<Step>;
pub fn apply(s: &mut ChainState, done: &Step) -> Result<(), KeyFoldError>;
```

One erasure batch on chain C, from epoch `e` to `e + 1`:

1. Record the requests (`TextErasureRequested` or `DocumentErasureRequested`) and an intent row. The keys cannot be opened from here on.
2. For each affected group G, create generation `gen + 1`. Open every surviving sibling under G and seal it to the new generation.
3. Create `R(e+1)` in custody and a fresh `S(e+1)`. Wrap `S(e+1)` under `R(e+1)`. Re-seal every live group secret of C under `S(e+1)`, locally.
4. Commit the new rows in one transaction. Phase `Committed`.
5. Take a keystore snapshot, sealed under the CellBackup chain, and verify it by opening a sample of live keys from a scratch restore under `R(e+1)`.
6. Destroy `R(e)` in custody and keep the receipt. Zeroize `S(e)` and the old group secrets.
7. Append `KeyEpochDestroyed { chain, epoch, receipt_digest }` and one `TextErased` or `DocumentErased` per key, in one batch.

Properties:

- After step 6, every copy of an erased key anywhere is sealed to an old group generation. That generation's secret was only ever sealed under epochs up to `e`, and every one of them is destroyed. No backup and no live key can open it (I-81).
- Until step 6, `R(e)` and `R(e+1)` are both alive. A crash at any step loses nothing. The planner resumes from the stored phase.
- Requests that arrive while a batch runs join the next batch. No batch waits for a timer. Erasure is complete in seconds, which honours ADR-007's "at once" (fix 2).
- An erasure is reported complete only at step 7. The erasure-log entry gains `completed_at` and keeps the request time.
- Cost per batch: one custody create, one wrap, one destroy; at most 255 hybrid re-seals; one AES re-seal per live group of the chain.
- **Keyed digests (G24).** A keyed digest outlives its plaintext in every backup while its key lives. A guessed email or attribute tuple could then be confirmed against an erased account by recomputing the HMAC. ADR-007 refused that for `TextRef`, and the same rule applies here. When a batch erases a login email, step 2 also creates a new `Lookup` key, recomputes the index of every live account from its live sealed email, and adds the old `Lookup` key to the batch. The vault does the same with the `Match` key and the live identities' attribute tuples. After step 6 no live key can recompute an erased account's digest. The cost is one HMAC per live account or identity per such batch.
- Restore rule: data tables may come from any backup point. Key tables always come from the newest keystore snapshot or the live store, because key rows are keyed by stable id. An old keystore copy cannot open keys whose group later rotated.

### 3.6 Identity documents (P-19, R-ID-03, TH-30)

- An upload goes from the browser to the vault origin with a write ticket. It is sealed under its own data key in its own `Document` group. The cell never sees it.
- When the verification outcome is recorded, the vault puts the document key into an immediate erasure batch.
- The verification fact becomes provisional only after the batch completes. So no backup can recover the document once the verification is recorded, as P-19 "deleted on verification" requires.
- Each verification creates and destroys one custody key. Q6 asks about OKMS quotas.

### 3.7 Cell erasure (R-SW-02, TH-48)

`fstp-control erase-cell` runs after the P-46 retrieval period:

1. Destroy every live root epoch of the cell's App, Vault and CellBackup chains in custody.
2. Drop both databases and their roles through `fstp-pgagent`. Delete the cell's object storage prefix and witness credentials.
3. Remove every route of the cell, including `id.<cell host>`.
4. Issue an erasure confirmation, composite-signed by the control plane, listing the custody receipts.

Shared-cluster backups still hold the cell's rows until their retention ends. Every tenant byte in them is sealed under a destroyed chain. Only random ids, sequence numbers, times and enums stay readable, and they link to no person once the vault and text keys are gone. `r_sw_02_cell_erasure_kills_every_backup` checks the AC "no backup or replica can restore the cell".

### 3.8 Backups

- **Physical cluster backups.** `pg_basebackup` streams and WAL archives, written by PostgreSQL's own tools. `fstp-backup` seals them in 1 MiB chunks with AES-256-GCM, a random nonce per chunk (section 3.2), and the chunk index and a final-chunk flag in the AAD. Each backup attempt draws its own data key, sealed to the cluster's ClusterBackup group key, so the writer cannot decrypt and a retried upload never reuses a key.
- **Keystore snapshots.** Per cell, after every erasure batch and daily, sealed to the cell's CellBackup group key.
- **Upload.** An in-house SigV4 client with PUT, GET, HEAD and multipart upload (create, upload part, complete, abort). Responses go through a fuzzed XML subset parser for the multipart create and complete responses and the error document. No DTD, entity or processing instruction is accepted.
- **Deletion** of old backups uses bucket lifecycle rules, not client DELETE calls.
- **Copies.** OVHcloud Object Storage with object lock, plus the second EU provider (Q25).
- **Restore drills.** A monthly job restores the latest backup into a scratch cluster and verifies every cell's chains against the witness.
- **Replicas (G22, Q4).** A streaming replica would need a REPLICATION role that logs in from another host, and its stream carries every cell's pages. Under the Q4 reading that is a remote role that reads across cells. The interim therefore has no streaming replica. `pg_basebackup` runs on the database host over loopback, as the role `fstp_repl`, whose certificate only the `fstp-backup` OS user can read. A standby restores continuously from the sealed WAL archive, with `archive_timeout` of 60 seconds. The recovery point objective is then about one minute, which ADR-005 records. Q4 asks whether a confined streaming replica is acceptable instead.

### 3.9 Signing keys in M3 (ADR-004 Signing keys)

| Key | Algorithm | Custody placement | Rotation |
| --- | --- | --- | --- |
| App chain anchor key, per cell | Composite Ed25519 plus ML-DSA-65 | App chain level 2 key, purpose `Anchor` (ADR-004 table) | Re-wrapped under each new root epoch. Replaced yearly; old public keys stay in the anchor key history the witness holds |
| Vault chain anchor key, per cell | Composite | Vault chain level 2 key, purpose `Anchor` | As above |
| Vault ticket key, per cell | Ed25519 | App chain level 2 key, purpose `Ticket` | Yearly, and on suspicion. The vault pins the current and the next public key |
| Witness receipt key | Composite | The witness's own custody entry, chain `ControlPlane`, separate credential | Yearly. Cells pin a set of witness keys; a new key is announced signed by the old one |
| Licence token key | Ed25519 (ADR-004: "Level 2 keys of the issuing cell or the control plane") | Control-plane custody, level 2 under chain `ControlPlane` | Yearly. Cells pin a key set shipped with the release; a key-transition statement signed by the current key adds the next one (section 10.2) |
| Staff assertion key, operator ticket key | Composite | Control-plane custody, level 2 under chain `ControlPlane` | Yearly. Each cell pins the current and the next public key at provisioning |
| Cluster CA, cell CA, control-plane CA | EC secp256r1 | Custody `sign` keys (section 1.3) | Yearly CA rollover with overlap |
| Release root and release signing keys | Composite | Not built in M3 (I-91 is M9) | ADR-004 |

---

## 4. Data and storage

### 4.1 Clusters, databases and roles

| Cluster kind | Databases | Login roles per cell (CN equals role) | Rights |
| --- | --- | --- | --- |
| `application` | `c_<cell>` | `c_<cell>_migrator` | Owns every schema. Certificate issued only for a deploy window |
| | | `c_<cell>_writer` | `ledger.*`, `audit.chain`, `audit.anchor`, `auth_log.*`, `ops.outbox`: INSERT and SELECT only. No UPDATE or DELETE anywhere (ADR-007: "holds INSERT and SELECT only") |
| | | `c_<cell>_app` | SELECT on `ledger`, `audit` and `auth_log`. Full rights on `auth` and on `ops` except `ops.outbox` (SELECT only); INSERT and SELECT on `blob` |
| | | `c_<cell>_keys` | Full rights on `keystore` only. DELETE on `blob` rows of completed erasures |
| | | `c_<cell>_auditor` | SELECT on `audit.*` and the stored ledger rows only |
| `vault` | `v_<cell>` | `v_<cell>_migrator`, `v_<cell>_vault`, `v_<cell>_keys` | Same pattern. `vault_audit.*` is INSERT and SELECT only |
| `control` | `cp`, `licence` | `cp_service`, `cp_migrator`, `licence_service`, `licence_migrator` | Per database |
| `witness` | `witness` | `witness_service`, `witness_migrator` | `witness.anchor` is INSERT and SELECT only |

- `<cell>` is the 32 lowercase hex digits of the random `CellId`. Role names stay under 63 bytes.
- `REVOKE CONNECT ON DATABASE ... FROM PUBLIC` on every database. CONNECT goes only to the cell's own roles.
- No cell role is SUPERUSER, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS. None is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_read_all_stats`, `pg_monitor`, `pg_signal_backend`, `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`.
- `dblink`, `postgres_fdw` and every other extension are absent. `CREATE EXTENSION` is refused for every cell role.
- `pg_stat_database`, `pg_stat_activity`, `pg_stat_statements` (absent anyway) and similar cross-database views are revoked from PUBLIC (G14). EXECUTE on the `pg_stat_get_*` functions behind each revoked view is revoked from PUBLIC too, since they return the same rows (Daniel, 2026-10-29). A test checks that `fstp-pgwire` sessions still work.
- `pg_hba.conf` holds one `hostssl <db> <role> <cell subnet> scram-sha-256 clientcert=verify-full` line per role and database. It has no `all` line and a final reject line.
- **Superuser and provisioning (G4, Q4).** The superuser has one line only: `hostssl all fstp_super 127.0.0.1/32 scram-sha-256 clientcert=verify-full`. Its certificate and password are readable only by the `fstp-pgagent` OS user.
- **Replication role (G22, Q4).** `fstp_repl` is the only role with REPLICATION. Its one line is `hostssl replication fstp_repl 127.0.0.1/32 scram-sha-256 clientcert=verify-full`, and only the `fstp-backup` OS user can read its key and password. It has no CONNECT on any cell database. Like the superuser, it is cluster machinery under the Q4 reading, and the I-82 privilege-graph and `pg_hba` tests cover it. No role with CREATEROLE or CREATEDB has any remote line. `fstp-pgagent` runs only typed jobs from `fstp-control`, each logged and approved by two operators for destructive jobs.
- **DDL grammar (ADR-011).** `CREATE DATABASE` cannot run inside a transaction or a DO block. `fstp-pgagent` renders that one statement and `DROP DATABASE` from a closed identifier grammar, `^[cv]_[0-9a-f]{32}$`, quoted as an identifier. Every grant runs through the owner function `fstp_meta.apply_grant`, which checks each argument against a closed grammar and quotes identifiers with `format('%I')`, following the M1 `set_config` pattern. The grant rows come only from `fstp_control::pg::cell_role_plan`, so the plan has one owner (W2h). The migration sets only define the function, from one shared text in `fstp-migrate`.

```sql
-- migrations/app/0000_meta.sql (excerpt)
CREATE SCHEMA fstp_meta;
CREATE TABLE fstp_meta.placement (
  cell_id    bytea    NOT NULL CHECK (octet_length(cell_id) = 16),
  cluster_id bytea    NOT NULL CHECK (octet_length(cluster_id) = 16),
  kind       smallint NOT NULL CHECK (kind = 1)          -- 1 application; the vault set uses CHECK (kind = 2)
);
CREATE FUNCTION fstp_meta.refuse_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'append-only' USING ERRCODE = '42501'; END $$;
-- Shared text from fstp_migrate::catalogue::APPLY_GRANT_SQL, identical in the app and vault sets.
CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cell text := current_setting('fstp.cell');
BEGIN
  IF cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF object !~ '^[a-z_]{1,30}\.[a-z_]{1,30}$' THEN RAISE EXCEPTION 'bad object'; END IF;
  IF suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, split_part(object, '.', 1), split_part(object, '.', 2),
                 left(current_database(), 1) || '_' || cell || '_' || suffix);
END $$;
-- fstp-pgagent calls apply_grant once per row of fstp_control::pg::cell_role_plan, after migrations.
```

### 4.2 Application database (`c_<cell>`)

```sql
CREATE SCHEMA ledger;
CREATE TABLE ledger.command (command bytea PRIMARY KEY CHECK (octet_length(command) = 16),
  first_seq bigint NOT NULL, last_seq bigint NOT NULL, at bigint NOT NULL);
CREATE TABLE ledger.entry (
  seq     bigint   PRIMARY KEY CHECK (seq >= 1),
  at      bigint   NOT NULL,
  command bytea    NOT NULL REFERENCES ledger.command,
  schema  smallint NOT NULL CHECK (schema >= 1),
  key_ix  integer  NOT NULL,                                  -- ledger data key generation, replaced after 2^20 seals
  body    bytea    NOT NULL                                   -- random nonce 12 || AES-256-GCM ciphertext || tag of the RFC 8785 text
);
CREATE TRIGGER entry_no_update BEFORE UPDATE OR DELETE ON ledger.entry
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER entry_no_truncate BEFORE TRUNCATE ON ledger.entry
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE SCHEMA audit;
CREATE TABLE audit.chain (
  n          bigint   PRIMARY KEY CHECK (n >= 1),
  at         bigint   NOT NULL,
  kind       smallint NOT NULL,                   -- 1 ledger entry, 2 event
  ledger_seq bigint   UNIQUE REFERENCES ledger.entry(seq),
  stored_hash bytea   NOT NULL CHECK (octet_length(stored_hash) = 32),  -- SHA-256 of the stored row bytes
  body       bytea,                               -- sealed event body, kind 2 only
  link       bytea    NOT NULL CHECK (octet_length(link) = 32),
  CHECK ((kind = 1 AND ledger_seq IS NOT NULL AND body IS NULL) OR (kind = 2 AND ledger_seq IS NULL AND body IS NOT NULL))
);
CREATE TRIGGER chain_link_check BEFORE INSERT ON audit.chain
  FOR EACH ROW EXECUTE FUNCTION audit.check_link();   -- recomputes link with sha256(); refuses a mismatch
CREATE TABLE audit.anchor (n bigint PRIMARY KEY REFERENCES audit.chain(n), link bytea NOT NULL,
  at bigint NOT NULL, signature bytea NOT NULL, witness_seq bigint NOT NULL, receipt bytea NOT NULL);  -- receipted before commit (section 7.2)

CREATE SCHEMA blob;
CREATE TABLE blob.text (id uuid PRIMARY KEY, dek uuid NOT NULL UNIQUE, envelope bytea NOT NULL); -- seal(salt || text)

CREATE SCHEMA keystore;
CREATE TABLE keystore.root (chain smallint, epoch bigint, backend smallint NOT NULL, handle bytea NOT NULL,
  wrapped_seal_key bytea NOT NULL, state smallint NOT NULL, created_at bigint NOT NULL,
  destroyed_at bigint, receipt bytea, PRIMARY KEY (chain, epoch));
CREATE TABLE keystore.group_key (chain smallint, purpose smallint, group_id uuid, generation integer,
  public_key bytea NOT NULL, sealed_secret bytea NOT NULL, epoch bigint NOT NULL, state smallint NOT NULL,
  PRIMARY KEY (group_id, generation));
CREATE TABLE keystore.data_key (id uuid PRIMARY KEY, group_id uuid NOT NULL, generation integer NOT NULL,
  sealed bytea NOT NULL, state smallint NOT NULL);
CREATE TABLE keystore.erasure_intent (id uuid PRIMARY KEY, chain smallint NOT NULL, plan bytea NOT NULL,
  phase smallint NOT NULL);

CREATE SCHEMA auth;
CREATE TABLE auth.session (token_hash bytea PRIMARY KEY, session_id uuid UNIQUE NOT NULL, account_id uuid NOT NULL,
  method smallint NOT NULL, created_at bigint NOT NULL, last_seen_at bigint NOT NULL,
  idle_expiry bigint NOT NULL, absolute_expiry bigint NOT NULL);   -- ended only by a row in auth_log.session_end
CREATE TABLE auth.challenge (id uuid PRIMARY KEY, session_id uuid, purpose smallint NOT NULL,
  action_digest bytea, challenge bytea NOT NULL, issued_at bigint NOT NULL);   -- consumed only by a row in auth_log.stepup_consumed
CREATE TABLE auth.sign_count (credential_key bytea PRIMARY KEY,   -- HMAC of the credential id under the CredLookup key
  sign_count bigint NOT NULL, last_used_at bigint);
CREATE TABLE auth.token (token_hash bytea PRIMARY KEY, kind smallint NOT NULL, account_id uuid,
  expires_at bigint NOT NULL, consumed_at bigint);    -- invitations, magic links, enrolment, recovery

CREATE SCHEMA auth_log;   -- insert-only side effects of an append; c_<cell>_writer holds INSERT and SELECT only
CREATE TABLE auth_log.stepup_consumed (challenge_id uuid PRIMARY KEY, ledger_seq bigint NOT NULL REFERENCES ledger.entry(seq));
CREATE TABLE auth_log.session_end (session_id uuid PRIMARY KEY, at bigint NOT NULL, cause smallint NOT NULL,
  ledger_seq bigint NOT NULL REFERENCES ledger.entry(seq));   -- idle and absolute expiry need no row
-- refuse_mutation triggers on both tables, as on ledger.entry

CREATE SCHEMA ops;
CREATE TABLE ops.outbox (id uuid PRIMARY KEY, kind smallint NOT NULL, idem bytea UNIQUE NOT NULL,
  dek uuid NOT NULL, body bytea NOT NULL, created_at bigint NOT NULL);   -- M6 dispatches
CREATE TABLE ops.checkpoint (seq bigint PRIMARY KEY, key_ix integer NOT NULL, body bytea NOT NULL);   -- random nonce, as ledger.entry
CREATE TABLE ops.licence_state (id smallint PRIMARY KEY CHECK (id = 1), sealed_token bytea,
  last_refresh_ok bigint, last_refresh_attempt bigint);
```

- Accounts, credential public keys, tenant admin grants, login policy, recovery approvals, break-glass approvals and ticket issuance are ledger records (section 5.1), so they are append-only (I-23). Sessions, challenges, sign counts and tokens are operational rows.
- The login email is a `TextRef` with a `CellKeyedIndex` lookup (HMAC-SHA-256 under the `Lookup` key over the normalised address). The address sits only in `blob.text` (Q22).
- Session tokens are 32 random bytes, stored only as SHA-256 hashes.
- A session or a step-up challenge ends only by an insert into `auth_log`, made by the writer in the append that records `SessionEnded` or `StepUpConsumed`. A second consumption violates the primary key and aborts the transaction, so the database refuses a replay even if the fold were wrong (I-78). Section 3.2 keeps that abort safe for sealing.
- Clear columns are limited to random ids, sequence numbers, times, enums, digests of random secrets and keyed digests (Q5). Credential ids are stored as keyed digests, and the licence token is sealed.
- No plaintext projection table exists (Q5). The engine folds state in memory and writes sealed checkpoints every 10 000 entries.

### 4.3 Vault database (`v_<cell>`)

```sql
CREATE SCHEMA vault;
CREATE TABLE vault.epoch (epoch bigint PRIMARY KEY, state smallint NOT NULL,      -- 1 provisional, 2 effective
  created_at bigint NOT NULL, affected bytea NOT NULL, ack_seq bigint, ack_link bytea, acked_at bigint);
CREATE TABLE vault.fact (fact_id uuid PRIMARY KEY, epoch bigint NOT NULL REFERENCES vault.epoch,
  kind smallint NOT NULL, subject uuid NOT NULL, dek uuid NOT NULL, body bytea NOT NULL, ended_epoch bigint);
CREATE TABLE vault.identity (identity_id uuid PRIMARY KEY, match_key bytea UNIQUE NOT NULL);  -- HMAC under Match key, rotated by erasure (section 3.5)
CREATE TABLE vault.account (account_id uuid PRIMARY KEY, identity_id uuid, verified_epoch bigint);
CREATE TABLE vault.document (doc_id uuid PRIMARY KEY, account_id uuid NOT NULL, dek uuid NOT NULL,
  sealed_object_ref bytea NOT NULL, uploaded_at bigint NOT NULL, erased_epoch bigint);
CREATE TABLE vault.negotiation (proposal_id uuid PRIMARY KEY, sealed_accounts bytea NOT NULL, opened_seq bigint NOT NULL,
  closed_seq bigint);
CREATE TABLE vault.ticket_used (ticket_id bytea PRIMARY KEY, used_at bigint NOT NULL);
CREATE TABLE vault.query_log (n bigint PRIMARY KEY, at bigint NOT NULL, query_digest bytea NOT NULL,
  holds boolean NOT NULL, epoch bigint NOT NULL);
-- plus keystore.* and vault_audit.chain, vault_audit.anchor with the shapes and triggers of section 4.2
```

- Fact bodies hold verification records (outcome, method, document type, checks, time, verifier: R-ID-02, no document numbers or images), affiliations, relationships (I-54), guardian consents, the P-17 country (NOTE 6), and the programme-side and reviewer-side facts of section 6.8.
- Bank details (M5), messaging handles (M8) and hardship evidence (M5) get their fact kinds in those milestones.

### 4.4 Control plane and witness databases

```sql
CREATE SCHEMA cp;
CREATE TABLE cp.cluster (cluster_id bytea PRIMARY KEY, kind smallint NOT NULL, region smallint NOT NULL,
  endpoint text NOT NULL CHECK (endpoint ~ '^[a-z0-9.-]{1,253}:[0-9]{1,5}$'), server_spki bytea NOT NULL,
  created_at bigint NOT NULL);
CREATE TRIGGER cluster_kind_immutable BEFORE UPDATE OF kind ON cp.cluster
  FOR EACH ROW EXECUTE FUNCTION cp.refuse_mutation();
CREATE TABLE cp.cell (cell_id bytea PRIMARY KEY, status smallint NOT NULL, mode smallint NOT NULL,
  app_cluster bytea NOT NULL REFERENCES cp.cluster, vault_cluster bytea NOT NULL REFERENCES cp.cluster,
  app_backend smallint NOT NULL, vault_backend smallint NOT NULL, org_ref bytea NOT NULL,
  created_at bigint NOT NULL, erased_at bigint, CHECK (app_cluster <> vault_cluster));
CREATE TABLE cp.route (host text PRIMARY KEY, cell_id bytea NOT NULL REFERENCES cp.cell, kind smallint NOT NULL,
  verified_at bigint NOT NULL);
CREATE TABLE cp.custody_entry (cell_id bytea, chain smallint, backend smallint, key_ref bytea, PRIMARY KEY (cell_id, chain));
CREATE TABLE cp.metering (cell_id bytea, period bigint, counter smallint, value bigint, PRIMARY KEY (cell_id, period, counter));
CREATE TABLE cp.staff (staff_id uuid PRIMARY KEY, created_at bigint NOT NULL);
CREATE TABLE cp.staff_credential (cred_id bytea PRIMARY KEY, staff_id uuid NOT NULL, cose_key bytea NOT NULL);
CREATE TABLE cp.operator_ticket (id uuid PRIMARY KEY, cell_id bytea NOT NULL, kind smallint NOT NULL,
  case_ref bytea NOT NULL, approved_by bytea NOT NULL, issued_at bigint NOT NULL);
CREATE TABLE cp.job (id uuid PRIMARY KEY, cluster_id bytea NOT NULL, kind smallint NOT NULL, state smallint NOT NULL,
  approved_by bytea, at bigint NOT NULL);

CREATE SCHEMA witness;
CREATE TABLE witness.anchor (cell_id bytea, chain smallint, n bigint, link bytea NOT NULL, at bigint NOT NULL,
  signature bytea NOT NULL, received_at bigint NOT NULL, witness_seq bigint UNIQUE NOT NULL,
  witness_link bytea NOT NULL, PRIMARY KEY (cell_id, chain, n));
```

- `org_ref` is an opaque reference into CrabNebula's accounting system. No legal name or contact is stored here (Q20).
- `operator_ticket.case_ref` is the cell's opaque recovery or break-glass case reference, never an account id (I-20).
- A database CHECK and the `Placement` type both forbid one cluster for both roles (I-83).
- `i19_control_plane_columns_are_declared` pins this exact column set to declared field classes.

### 4.5 Schema catalogue

The types live in `fstp_migrate::catalogue`: `TableSpec { schema, name, class: TableClass, columns: &[ColumnSpec] }`. Each migration set's owner exports its own list next to its migrations: `fstp_pgstore::CATALOGUE` (app), `fstp_vault::CATALOGUE`, `fstp_control::CATALOGUE` (cp), `fstp_witness::CATALOGUE` and `fstp_release_svc::CATALOGUE` (licence). A test in `fstp-celltest` takes their union, so no lane edits another lane's list. `TableClass` is closed: `LedgerRecord`, `AuditEvent`, `SealedContent`, `KeyMaterial`, `Operational`, `Migration`, `Placement`. It has no class for a balance or a held amount (I-16). `ColumnSpec` marks each column as `Sealed`, `RandomId`, `Sequence`, `Time`, `Enum`, `SecretDigest` (a hash of a random secret), `KeyedDigest` (an HMAC under a key that erasure rotates) or `Count`. A test fails on any table or column missing from it, and on any clear column outside those classes (R-NF-08).

### 4.6 Migrations

- Sets: `crates/fstp-pgstore/migrations/app/`, `crates/fstp-vault/migrations/vault/`, `crates/fstp-control/migrations/cp/`, `crates/fstp-witness/migrations/witness/`, `crates/fstp-release-svc/migrations/licence/`.
- `fstp-migrate` runs each set with its migrator role. Grants run afterwards through `fstp_meta.grant_cell_roles`.
- Trigger functions are created by the migrator. `SECURITY DEFINER` is not used.
- The ledger schema version stays as ADR-007 sets it. Decoders accept every published version.

### 4.7 Pools and connections

- `fstp_pgstore::Pool<R: Runtime>` keeps at most N clients per role. A process belongs to one cell, so no pool serves two cells (ADR-005).
- Every client uses `fstp_pgwire::Config` with a per-role `ClientTls`. Client keys and passwords live in files readable only by the component's OS user. Certificates are renewed daily.

### 4.8 What lives where

| Data | Cell app DB | Vault DB | Control plane | Edge | Object storage |
| --- | --- | --- | --- | --- | --- |
| Domain and tenant records | sealed | no | no | no | inside sealed backups |
| Free text | sealed, per-text key, salt inside | no | no | no | inside sealed backups |
| Login email | sealed `TextRef`, keyed lookup | no | no | no | inside sealed backups |
| Identity attributes, consents, affiliations, country, documents | no | sealed | no | no | sealed document objects |
| Vault answers | `VaultOutcome` digest and bit | query log | no | no | inside sealed backups |
| Data keys | sealed to groups | sealed to groups | no | no | keystore snapshots |
| Root epochs | no | no | no | no | no (custody only) |
| Anchors and receipts | own copy | own copy | no (the witness holds them) | no | object-lock copies at the witness's second provider |
| Routes and placements | no | no | yes | route cache | no |
| Client IP addresses | memory only | no | no | memory only | no |

---

## 5. Domain seams: cell core, driver, store and gate

### 5.1 Cell core (`fstp-cell-core`)

```rust
pub enum CellCommand {
    Engine(fstp_engine::Command),
    Auth(fstp_auth::AuthCommand),      // RegisterCredential, RevokeCredential, GrantStepUp, recovery steps
    Tenant(TenantCommand),             // GrantTenantAdmin, EndTenantAdmin, ApproveSelfGrant, SetLoginPolicy (P-70 to P-72)
    Text(TextCommand),                 // PutText, EraseTexts { ids, cause }
    Key(KeyCommand),                   // RecordKeyOp, RecordEpochDestroyed (from the erasure runner)
    Release(ReleaseCommand),           // IssueReleaseTicket, IssueWriteTicket (every kind of sections 6.5 and 6.8), RecordRelationship (system)
    Ops(OpsCommand),                   // ApproveBreakGlass, EndBreakGlass, ApplyOperatorTicket, EndSessionsAtBindingEnd (system)
}
pub enum CellRecord { Engine(fstp_engine::Record), Auth(AuthRecord), Tenant(TenantRecord),
                      Text(TextRecord), Key(KeyRecord), Release(ReleaseRecord), Ops(OpsRecord) }
pub struct CellState { engine: EngineState, auth: AuthState, tenant: TenantState,
                       texts: TextIndex, keys: KeyIndex, releases: ReleaseState, ops: OpsState }

pub fn queries(s: &CellState, c: &CellCommand, x: &CellCtx) -> Result<Vec<Query>, CellRefusal>;
pub fn decide(s: &CellState, c: &CellCommand, x: &CellCtx, a: &Answers) -> Result<Vec<CellRecord>, CellRefusal>;
pub fn apply(s: &mut CellState, e: &Entry<CellRecord>) -> Result<(), FoldError>;
pub fn replay(entries: &[Entry<CellRecord>]) -> Result<CellState, FoldError>;
/// Ctx attestations for M2 commands, read only from the tenant fold.
pub fn attest(s: &CellState, actor: AccountId, cmd: &fstp_engine::Command) -> Attestation;
```

- **Envelope.** The stored member names extend the M2 envelope. `core` and `finding` decode through `fstp_engine::Record` unchanged, so every M2 record keeps its exact bytes. New members are `auth`, `tenant`, `text`, `key`, `release` and `ops`.
- **Attestation.** `Ctx::tenant_admin`, `second_tenant_admin` and `binds_tenant_admin` come from `TenantState` in the ledger, never from request fields. This closes the M2 shell attestation seam.
- **SoD-07 approval.** A tenant admin who grants a role to their own account needs a second tenant admin's approval. The second admin issues `ApproveSelfGrant { grant_digest }` with a step-up (`ManagementRoleChange`). `grant_digest` is SHA-256 over the canonical `GrantRole` without its `second_admin` field, plus its command id. `decide` records `SelfGrantApproved { approval, approver, grant_digest, expires_at }`. `attest` sets `Ctx::second_tenant_admin` only when an unconsumed approval by a different current tenant admin matches the grant's digest and has not expired. The grant batch records `SelfGrantApprovalUsed`, so one approval admits one grant (TH-05). The interim expiry is P-71 from the approval's step-up (Q40).
- **Reactions.** `decide` appends `SessionEnded` reactions in the same batch. A grant of a Drafting, Judging, Operations or tenant admin role ends that account's weak sessions. An ended, suspended or voided binding of those groups ends every session of the account (Q16).
- **Scheduled ends.** A binding end may be scheduled for a later instant (`roles-and-sod.md`). No command runs at that instant, so section 8.2 makes the gate refuse, from that instant on, every session the end would have ended. A background task then issues the system command `EndSessionsAtBindingEnd`, which records `SessionEnded` and the `auth_log` rows. The gate check carries the guarantee, and the record makes it visible.
- **Step-up consumption.** For a high-risk command, the batch carries `StepUpConsumed { id }`. The fold refuses a second consumption, so replay checks single use by structure.

### 5.2 `DriverCore` and the async engine

`DriverCore` is a sans-IO state machine in `fstp-cell-core`. It follows `fstp_engine::Engine::execute` step for step and adds the acknowledgement of NOTE 4. The M2 `Engine` stays unchanged and becomes its reference oracle.

```rust
pub enum Need {
    ReadFrom(Seq),
    Epoch,
    Ask { queries: Vec<Query>, reaction_for: Option<VaultEpoch> },
    Append { expected: Seq, at: i64, command: [u8; 16], batch: Vec<CellRecord>, side: SideEffects },
    Ack { epoch: VaultEpoch, seq: Seq, link: Link },
}
pub enum Event { Read(Vec<Entry<CellRecord>>), Epoch(Result<VaultEpoch, VaultFault>),
                 Answers(Result<Answers, VaultFault>), Appended(Result<(Seq, Link), AppendError>),
                 Acked(Result<(), VaultFault>) }
pub enum Step { Need(Need), Done(Result<Done, ExecError>) }
pub struct Done { pub head: Seq, pub receipt: ReceiptRef }  // every committed append holds its witness receipt (section 7.2)
pub struct DriverCore { /* phase, attempts, pending command, progress */ }
impl DriverCore {
    pub fn start(admitted: Admitted) -> DriverCore;
    pub fn step(&mut self, state: &mut CellState, ev: Option<Event>) -> Step;
}
```

- **Steps.** Catch up from the store. Refuse a caller command id with the reserved prefix `fstp:vc:`. If the vault epoch is ahead, run `VaultChanged` with `reaction_for = Some(epoch)`, append it, then ask for `Ack`. Run `queries`, ask once, fail closed on any `VaultFault` (NOTE 2). On an epoch mismatch, process the change first (NOTE 3). Decide, append with the expected head, retry on `StaleHead` up to `MAX_ATTEMPTS`, and report `DuplicateCommand` as the stored result.
- **Restart.** At start the driver finds a committed reaction whose epoch the vault still reports as provisional, by its reserved command id. It sends `Ack` again. Acks are idempotent.
- **Single writer.** One engine task per cell owns `CellState` and runs one `DriverCore` at a time. Handlers send `Admitted` commands over a bounded channel. A second process for availability contends through the expected head, as ADR-007 allows.
- **Query digests (NOTE 5).** HMAC-SHA-256 under a cell key over the canonical query encoding. A reader of the ledger cannot confirm a guessed query without the key.
- **Equivalence.** `seam_driver_core_matches_reference_engine` runs the M2 generators through `DriverCore` over `MemStore` and `SyntheticVault`, and through `fstp_engine::Engine`. Ledgers must be byte-identical and refusals equal (section 14.6). Q29 asks whether `Engine` should later collapse onto `DriverCore`.

### 5.3 `PgRecordStore` append protocol

```rust
pub type Decode<T> = fn(canonical: &[u8], schema: u16) -> Result<T, DecodeError>;
pub struct PgRecordStore<R: Runtime, T, W> { pool: Pool<R>, keys: LedgerKeys, chain: ChainWriter,
                                             witness: W, decode: Decode<T> }
// W: fstp_audit::PrepareWitness, an async trait that fstp-cell implements over its witness client
impl<R: Runtime, T: Canonical, W: PrepareWitness> AsyncRecordStore<T> for PgRecordStore<R, T, W> { /* head, append, read */ }
// fstp-cell uses T = CellRecord and decode = fstp_cell_core::record_from_canonical_at
```

One append is one transaction as `c_<cell>_writer`, which holds INSERT and SELECT only (section 4.1):

1. `SELECT pg_advisory_xact_lock(1)`: one writer per cell database.
2. If the command id exists in `ledger.command`, return `DuplicateCommand`. The command check comes before the head check (ADR-007).
3. If the head is not `expected`, return `StaleHead`.
4. Seal each entry's canonical text under the current ledger key with a random nonce (section 3.2), AAD `"fstp-ledger-v1" || cell || seq || at || command || schema`. Insert row by row, since `fstp-pgwire` has no array types.
5. Insert one `audit.chain` row per entry. `ChainWriter` computes each link from the stored row bytes. The insert trigger recomputes it.
6. Apply `SideEffects` as inserts only: one `auth_log.stepup_consumed` row for a consumed step-up, one `auth_log.session_end` row per ended session, and sealed `ops.outbox` rows. A replayed step-up violates the primary key, and the transaction aborts.
7. **Prepare.** Send the prospective head `(cell, App, n, link)` with its composite-signed anchor to the witness, and wait for the receipt (section 7.2). Insert the anchor and receipt into `audit.anchor`.
8. Commit. If the commit fails or its outcome is unknown, the anchorer core follows the abort rule of section 7.2 before the next append.

Every step before the commit can abort. An aborted attempt leaves sealed rows in the WAL, which is safe because no nonce is ever reused (section 3.2).

### 5.4 Gate and `Admitted`

```rust
// fstp-cell-core::gate (pure)
pub enum Action { Command(CellCommand), Read(ReadAction) }  // ReadContent, ReadAudit, ReadErasureLog, ...
pub struct Admitted { action: Action, principal: Principal, stepup: Option<StepUpUse>, at: Timestamp } // private
pub enum Principal { Account(AccountId), BreakGlass(GrantId) }
pub enum Deny { NoSession, SessionEnded, WeakSessionForRole, StepUpRequired(HighRiskAction), StepUpStale,
                StepUpMismatch, StepUpFromWeakMethod, MagicLinkSessionHighRisk, EnrolPasskeyFirst, NotPermitted }
pub fn admit(s: &CellState, session: &SessionView, action: Action, stepup: Option<&StepUpView>,
             now: Timestamp, policy: &LoginPolicy) -> Result<Admitted, Deny>;
```

`admit` runs these checks in order:

1. The session exists, is not ended, and is inside the P-72 idle and absolute lifetimes.
2. `admit_session` (I-77). Holdings come from the engine roster and the tenant fold at `now`. A session is also refused as `SessionEnded` when any binding of the account ended, by any cause and including a scheduled end, at an instant after the session started and at or before `now` (section 8.2). That holds even if the `EndSessionsAtBindingEnd` record is not yet written.
3. `HighRiskAction::of(&action)`. For a high-risk action: the session's method is not a magic link; the step-up exists, belongs to this session, matches the action digest, used a phishing-resistant method with UV, is no older than P-71, and is unused (I-78).
4. A break-glass principal is admitted only for the read actions inside its recorded scope and time (SoD-08).
5. P-77 and `Via::Mcp` stay with `decide`, as in M2. MCP itself is M4.

`fstp-cell::routes::Route::new(method, path, risk: RiskClass, handler)` has no default for `risk`. A route without a class does not compile. `CellEngine::execute(admitted: Admitted)` is the only way a command reaches `DriverCore`.

### 5.5 Projections and checkpoints

- The engine replays the ledger at start and writes a sealed checkpoint every 10 000 entries. A test compares every checkpoint with a full replay (ADR-007).
- M4 read models are folds in memory. If Daniel keeps ADR-007's `numeric` projection tables (Q5 option B), they go to `projection.*` with amounts through `fstp_pgwire::Numeric`.

### 5.6 Text store and erasure log (ADR-007)

- `TextStore::put(text, purpose, retention) -> TextRef` creates the id, a random salt, a data key and `seal(salt || text)`. The digest is HMAC-SHA-256 keyed by the salt. The salt never sits in a clear column.
- `TextStore::get(&TextRef)` returns `Text` or `Erased(ErasureEntry)`. A `TextRef` whose key is under destruction resolves to its erasure-log entry, never to the text.
- Causes: retention expiry (P-41), erasure request, cell erasure, and verification completed for documents (R-ID-03). The erasure log is the set of `TextErasureRequested` and `TextErased` ledger records, so it is chained by construction (I-24).
- Each erasure-log entry holds the text id, the request time, `completed_at`, the cause, and the person who authorised it, as ADR-007 requires. The authoriser is the requesting account for an erasure request, the tenant admin or operator ticket for a cell erasure, and the system with the P-41 rule reference for a retention expiry.
- Tenant admins read every entry. An Auditor reads only entries for texts of the programme its binding names. Entries for tenant-wide texts, such as login emails, and for cell erasure are tenant admin only (G30, Q42). The person concerned receives a confirmation once M6 sends email.

---

## 6. Identity vault

### 6.1 Process and listeners

`fstp-vault` has two listeners:

| Listener | Peers | Routes |
| --- | --- | --- |
| Internal mTLS | Only its cell's `cell-app` certificate from the cell CA | `POST /v1/epoch`, `/v1/ask`, `/v1/ack`, `/v1/negotiation` |
| Vault origin `id.<cell host>`, through the edge tunnel | Browsers, with a ticket | `POST /w` (write), `POST /r` (release), static pages and scripts for those two |

Outbound, the vault opens only its `VaultDestination` connections (B4a): its database, its custody entry, and the witness for its own chain's anchors (section 7.2).

### 6.2 Wire types

```rust
// fstp-vault-proto (own id newtypes; no fstp-domain dependency)
pub enum VaultRequest {
    Epoch,
    Ask { at: u64, reaction_for: Option<u64>, queries: Vec<WireQuery> },
    Ack { epoch: u64, ledger_seq: u64, link: [u8; 32] },
    NegotiationOpened { proposal: WireProposal, accounts: Vec<WireAccount>, ledger_seq: u64 },
    NegotiationClosed { proposal: WireProposal, ledger_seq: u64 },
    RecordRelationship { a: WireAccount, b: WireAccount, kind: RelationshipKind, programme: WireProgramme, ledger_seq: u64 },
}
pub enum VaultResponse { Epoch(u64), Answers(Vec<WireAnswer>), Acked, Refused(VaultRefusal) }
pub enum VaultRefusal { Pending { epoch: u64 }, StaleEpoch { current: u64 }, NotThisCell, Malformed, Unavailable }
pub struct WireAnswer { pub holds: bool, pub accounts: Option<Vec<WireAccount>>, pub epoch: u64 }
```

- `WireQuery` mirrors the ten `fstp_domain::oracle::Query` kinds exactly. `fstp-cell` converts between them, so neither pure core depends on the other. A round-trip property keeps the two in step.
- Every answer is one bit, except `ChangedSince`, which lists account ids and nothing else (`overview.md`).
- Amounts cross as canonical ADR-006 strings and are compared exactly through `fstp-money`.

### 6.3 Facts, epochs and the commit protocol (NOTE 4)

```rust
// fstp-vault-core
pub struct VaultState { effective: Epoch, outstanding: Option<Provisional>, queue: VecDeque<FactWrite>,
                        facts: Facts, negotiation: BTreeMap<Proposal, BTreeSet<Account>> }
pub struct Provisional { epoch: Epoch, affected: BTreeSet<Account>, facts: Vec<Fact> }
pub fn write(s: &mut VaultState, w: FactWrite, now: Timestamp) -> Result<Vec<VaultEvent>, VaultRefusal>;
pub fn ask(s: &VaultState, req: &Ask) -> Result<Vec<WireAnswer>, VaultRefusal>;
pub fn ack(s: &mut VaultState, a: &AckMsg) -> Result<Vec<VaultEvent>, VaultRefusal>;
pub fn release_allowed(s: &VaultState, t: &ReleaseClaims, now: Timestamp) -> Result<(), VaultRefusal>;
```

1. A new fact is stored as provisional at a new epoch. Only one provisional epoch exists at a time. Later writes queue behind it.
2. `affected` lists the accounts the fact touches, plus every account that facts revealed by a verification touch (confirmed 2026-10-25).
3. `ask` refuses with `Pending` any query that names an affected account, unless `reaction_for` equals the provisional epoch. Reaction queries see the provisional fact.
4. The cell runs `VaultChanged`, appends the reaction, then sends `Ack { epoch, seq, link }`.
5. `ack` makes the facts effective, records the cell's sequence and link, and dequeues the next write. A repeated `ack` is accepted.

Every fact kind written in M3 uses this protocol, including consents and countries. Every query counts only effective facts, apart from reaction queries, so I-04 and I-06 hold at every instant.

### 6.4 Query evaluation

| Query | Evaluation over effective facts |
| --- | --- |
| `IsVerified` | The account has an effective verification |
| `SameIdentityAsAny` | The subject's identity equals the identity of any account in the set |
| `HasConflict` | A relationship or affiliation links the reviewer's identity with any team identity (I-03, I-54) |
| `InExcludedClass` | An effective affiliation of the account's identity carries a class in the set |
| `WithinRecipientCap` | Group committed amounts by identity, add the amount to the subject's group, compare with the cap |
| `AllRecipientsWithinCap` | Every identity group stays within the cap |
| `HasGuardianConsent` | An effective consent exists whose guardian verification is effective (I-18) |
| `DeclaresAffiliationOnList` | A team identity's declared affiliation is on the list |
| `MeetsTieBreakCountry` | The stated country meets the P-17 condition. The country never leaves the vault |
| `ChangedSince` | Accounts touched by facts after the epoch |

`seam_pg_vault_matches_synthetic_vault` checks these against the M2 `GroundTruth` predicates.

Identity match key (Q17): `match_key = HMAC-SHA-256(Match key of this cell, canonical attribute tuple of the verification method)`. The Match key differs per cell, so keys never correlate across tenants (I-20). It is replaced in every erasure batch that erases an identity, so an erased identity's match key cannot be recomputed from a backup (section 3.5).

### 6.5 The vault origin (I-17, NOTE 6, Q7)

- **Write tickets.** The cell issues a ticket for one write: the P-17 country at submission, a declared affiliation, a guardian consent, a document upload, or one of the section 6.8 kinds. The browser opens `https://id.<cell host>/w#<ticket>`. The fragment never reaches a server log. The vault's own page posts the data same-origin. The cell receives only the resulting epoch change.
- **Release tickets.** `release::issue_ticket` issues one only to an Operations role holder of the programme, for a proposal in NEGOTIATION or later (I-17, `overview.md`). Issuing it appends `IdentityReleaseIssued`, so the read is logged (R-AU-01). The vault renders released fields server-side, with `Content-Security-Policy: default-src 'none'` and `Cache-Control: no-store`. A download is the high-risk action `IdentityDownload`.
- **Second guard.** The vault refuses a release unless its own `negotiation` fact, pushed by the cell when NEGOTIATION opens, lists the subject.
- **Ticket format.** Canonical JSON `{kind, cell, account, proposal, scope, issued_at, expires_at, nonce}` with an Ed25519 signature by the cell's `Ticket` key. The vault pins the cell's ticket public key at provisioning. A ticket lives at most 5 minutes, an interim constant with no P- id (Q37), and is single-use (`vault.ticket_used`).
- **Surface.** No cookies, no sessions, a body limit per kind, the signature checked before any field is used, and each decoder fuzzed.
- **Handles.** Phone numbers and messaging handles have no release scope until M8. They go only to channel adapters.

### 6.6 Guardian consent and the minor flag (I-18, G8, G20)

**The flag.** M2 takes `CreateDraft { minor: bool }` from the actor (`crates/fstp-domain/src/command.rs:243`). R-ID-04 asks for "a derived flag", and an applicant who clears it would skip the I-18 guard. Age is known only from a verification, and R-NG-01 places verification inside NEGOTIATION, after the I-18 gate. No reading of the current sources gives a trusted flag before the gate.

Interim strict reading, built until Daniel answers Q13 (blocking):

1. The route layer never reads `minor` from a request. `routes::commands::create_draft` builds every `CreateDraft` with `minor = true`. A request body that carries the field is refused as malformed, so a client cannot believe it set the flag.
2. Every proposal is therefore minor-flagged, and M2's NEGOTIATION entry guard asks `HasGuardianConsent` for every proposal.
3. When the last IRC validation is recorded, the cell issues a write ticket to the guardian, a Receiving account added by `AddGuardian`. The guardian verifies and consents on the vault origin.
4. The consent fact becomes effective only after the guardian's verification is effective and the cell has reacted to its epoch.
5. Consequence: in M3 no proposal without a verified guardian consent reaches NEGOTIATION, including an adult's. Production M3 records manual verifications only within the release window of ADR-008, and only once composite operator tickets exist (Q14, section 21.0). HTTP-level cycle tests seed verified guardian consents through section 6.9 and say so in their doc comments.

The seam tests that drive `CellEngine` directly keep the M2 generators' flags, because they test driver equivalence, not the flag's source. Q13 offers the options that would let adults through without a guardian.

Judging roles never see the guardian's attributes, so I-17 holds. `TODO(legal)`: L-02 covers the legal basis for collecting a guardian's data, or an over-18 attestation, before NEGOTIATION.

### 6.7 Manual identity checks (G9)

Daniel answered Q14 (B now, A later), and later on 2026-10-28 how a tenant's first recorder starts (section 21.0). A current tenant admin records a manual verification outcome as a vault write. The platform operator verifies the first tenant admin of each tenant. Two operator staff take part, the verification is logged, and it is shown to the tenant. That admin then records the checks of others. They never record their own check, or the check of an account that shares their identity. This replaces the strict interim that refused every unverified recorder.

- ADR-008 moves the outcome from a cell route to a write ticket on the vault origin. It keeps the release window as a strict interim, so a tenant recorder reviews only subjects whose proposal is in NEGOTIATION or later.
- The operator path uses a composite-signed operator ticket. It waits on the moduletto ML-DSA-65 pull request (Q1), so no operator verification is recorded in production before that lands.
- Until the release-window open point and that pull request are settled, SoD-09 refuses Drafting and Judging grants in production to every account the operator did not verify.

M3 builds and tests everything behind that path:

- The vault write kind `VerificationRecorded { account, method, document_type, checks, at, verifier }`, with no document number or image (R-ID-02).
- The P-19 erasure of the document key in the same batch (section 3.6).
- The NOTE 4 commit protocol for the identities the verification reveals.

When the Operations role "identity verifier" replaces the tenant admin (Q14 A later), the ticket's permission rule changes, and nothing else.

### 6.8 Programme-side and reviewer-side facts (G21, Q31)

Several queries need facts that no applicant writes. `HasConflict` needs reviewers' employers and relatives and the I-54 relationships. `InExcludedClass` needs to know who is partner staff or an IRC member's employer, co-worker or relative (roles-and-sod NOTE 2). `DeclaresAffiliationOnList` needs the P-38 proximity lists, which `crates/fstp-domain/src/policy/mod.rs:206` says are "held by the vault". The first version wrote none of these, so I-03, I-04 and I-35 had no real data.

| Write kind | Fact | Written by (interim) | Path | Affected accounts for NOTE 4 |
| --- | --- | --- | --- | --- |
| `ProximityListDeclared { programme, organisation, entries }` | P-38 list of one partner organisation, "declared by each partner at programme start" | The programme manager, with a step-up, on the partner's behalf | Write ticket on the vault origin | Every account of a proposal in that programme whose declared affiliation is on the old or new list |
| `ReviewerDeclaration { programme, employer, relatives }` | A Judging-role holder's own employer and relatives | The holder, as part of the SoD-09 verification at binding time | Write ticket on the vault origin | Every Receiving holder of the programme who matches the employer or a relative |
| `PartnerStaffDeclared { programme, organisation }` | The declaring person is staff of a consortium partner (Annexe 8.a, 8.e) | The person, at binding or at verification | Write ticket on the vault origin | That person's accounts |
| `AffiliationDeclared` | An applicant's or team member's declared affiliation (already in section 6.5) | The person | Write ticket | That person's accounts |
| `RecordRelationship { a, b, kind, programme }` | An I-54 mentoring relationship, ids only | The cell, as a system command when a mentoring assignment is accepted | Internal mTLS API (section 6.2) | `a` and `b` |
| `VerificationRecorded` | Section 6.7 | The tenant admin. For the first tenant admin, the platform operator with two staff (Q14, section 21.0) | Write ticket on the vault origin (ADR-008) | Every account the verification reveals |

- Every kind uses the NOTE 4 protocol, so a fact that flips an answer is acted on in one step, as NOTE 4 and P-13 NOTE 7 require for affiliations.
- Issuing each write ticket is a ledger record, so the write is logged (R-AU-01).
- Relatives are personal data of third parties. The interim stores only what matching needs, and `TODO(legal)` asks for the basis and the minimum attribute set.
- Answers stay one bit (NOTE 5). No Judging role reads any of these facts.

### 6.9 Test-only fact seeding

Tests need verified identities, consents and affiliations that M3 production cannot create (sections 6.6 to 6.8). They are written only through `fstp-celltest`:

- `fstp_celltest::vault_seed::SeedSource` turns a synthetic `GroundTruth` into `FactWrite`s. It feeds them through `fstp_vault_core::write` and the NOTE 4 protocol, so seeded facts become effective exactly as real ones do, after the cell's reaction.
- The binary `fstp-vault-seeded` links the `fstp-vault` library with a `SeedSource`. It exists only in `fstp-celltest`, which is `TEST_ONLY` (layering rule 9).
- The shipped `fstp-vault` binary has no seed route, no seed flag and no seed file reader. `fstp_vault_has_no_seed_path` checks its route table, its configuration decoder, and a source scan for `SeedSource` and `seed_fact` outside `fstp-celltest`.
- Claims built on seeding say so. I-18 is claimed over the vault core, and over the real vault with seeded facts. The end-to-end claim through a production verification waits on the ADR-008 open point "Reviews outside NEGOTIATION" and on the moduletto ML-DSA-65 pull request (Q1).

---

## 7. Audit log (I-24)

### 7.1 Chain format

```rust
// fstp-audit
pub enum ChainId { App, Vault }
pub struct ChainRow { pub n: u64, pub at: i64, pub kind: RowKind, pub stored_hash: [u8; 32] }
pub enum RowKind { Ledger { seq: u64 }, Event { body: SealedBlob } }
pub fn genesis(cell: CellId, chain: ChainId) -> Link;
pub fn link(prev: &Link, cell: CellId, chain: ChainId, row: &ChainRow) -> Link;
pub struct ChainWriter { head: (u64, Link) }        // the only code that computes links
pub fn verify(rows: &[ChainRow], ledger: &[StoredEntry], anchors: &[Anchor], receipts: &[Receipt],
              keys: &AnchorKeys) -> Result<Verified, Tamper>;
pub enum Tamper { Changed { n: u64 }, Gap { n: u64 }, Reordered { n: u64 }, Truncated { witnessed: u64, have: u64 },
                  AnchorMismatch { n: u64 }, BadSignature { n: u64 }, LedgerWithoutRow { seq: u64 },
                  RowWithoutLedger { n: u64 }, StoredHashMismatch { seq: u64 },
                  Deleted { n: u64 }, AbortedButPresent { n: u64 } }
```

- **Link.** `link_n = SHA-256("fstp-audit-v1" || cell || chain || be64(n) || link_{n-1} || stored_hash_n)`. `stored_hash_n` is SHA-256 of the stored row's fixed byte layout, ciphertext included. The genesis link binds the cell and chain.
- **Second implementation.** The `audit.check_link` trigger recomputes the same bytes with `sha256()` and `int8send()` and refuses a mismatch. A differential test compares both implementations byte for byte.
- **Events.** Logins, refused logins, step-ups with their action digest, sessions ended, credentials added or removed, recovery steps, break-glass grants and uses, custody calls, erasure phases, licence state changes and vault intake. Bodies hold ids, enums and digests only, sealed under the `Ledger` purpose.
- **No content key needed.** The witness and an auditor verify links over ciphertext.
- **Database rights.** `c_<cell>_writer` holds INSERT and SELECT only. Triggers refuse UPDATE, DELETE and TRUNCATE even for the owner.

### 7.2 Witness receipts and anchors (G7, Q8)

The first version receipted each head after its commit and refused writes once an entry stayed unwitnessed for 60 seconds. A database owner could delete an entry inside that window without detection. I-24 says "any modification or deletion of a past entry is detectable", and `.claude/CLAUDE.md` forbids resolving a conflict by weakening an invariant. The interim is therefore prepare, receipt, commit.

- **Prepare.** Inside the open append transaction (section 5.3 step 7), the anchorer core sends `Prepare { cell, chain, n, link, anchor }` for the prospective head. `anchor` is `Anchor { cell, chain, n, link, at, signature }`, composite-signed with the chain's `Anchor` key (ADR-001, R-CR-03). The witness appends it to its own per-cell chain and returns a composite-signed receipt. The cell stores anchor and receipt in `audit.anchor` in the same transaction, then commits.
- **One outstanding prepare per chain.** The witness refuses a new prepare for a chain until the previous one is extended (the new prepare's history contains its link), aborted or resolved.
- **Abort.** If the transaction fails before COMMIT is sent, or COMMIT returns an error, nothing was committed. The cell sends `Abort { n, link }`, which the witness records. Only then may the cell prepare `n` again with another link.
- **In doubt.** If the outcome of COMMIT is unknown, for example after a lost connection or a crash, the cell reads its chain at reconnect or restart. If row `n` with that link exists, it was committed, and the next prepare extends it. If the row is missing, the cell cannot tell an abort from a deletion. It sends `InDoubtAbsent { n, link }`. The witness records it, and the cell raises `PossibleDeletion` to tenant admins and the auditor view. That alert is the detection, so no deletion goes unreported.
- **Verification.** `fstp_audit::verify` requires every prepared link at the witness to match a chain row, or to carry an `Abort` or an `InDoubtAbsent`. A prepared link with neither is `Tamper::Deleted`. An `Abort` for a link that exists in the chain is `Tamper::AbortedButPresent`.
- **Acknowledgement.** Every committed entry already holds its receipt, so responses wait for nothing more. `202 witness_pending` and the 60-second bound are gone.
- **Cost.** One witness round trip per append transaction, while the cell's advisory lock is held. A batch of entries shares one prepare. Audit events without a ledger entry, such as refused logins, are grouped into one chain transaction at most every 200 ms, so a login flood cannot flood the witness. Risk R8 covers the availability cost: without a reachable witness the cell refuses writes and keeps serving reads.
- **Both chains.** The vault runs the same anchorer core for `ChainId::Vault`, with its own `Anchor` key and its `vault-witness` certificate, over its `VaultDestination::Witness` connection (B4a). The cell never anchors the vault's chain, and the vault never anchors the cell's.
- **Copies.** The witness writes each prepare, abort and receipt to its database and to an object-lock bucket at a second provider.
- **Self-hosted (Q9).** A local `fstp-witness` with its own OS user, its own append-only file store and its own receipt key is mandatory at first start. An external object-lock bucket is optional. No anchor ever goes to a CrabNebula host (I-38).
- **Start-up.** The cell and the vault each verify their chain against the witness before they serve requests, and resolve any in-doubt prepare first.
- **Anchors leave the control plane out.** Anchors go from the cell and the vault straight to the witness. `CellToCp` carries no anchor (section 9.1).

### 7.3 Erasure log in the chain

`TextErasureRequested`, `TextErased`, `DocumentErased` and `KeyEpochDestroyed` are ledger records, so each sits in the chain (ADR-007).

### 7.4 Composite signatures in M3

- Format: draft-ietf-lamps-pq-composite-sigs version 19, as ADR-001 pins. ADR-010 transcribes the exact encoding from that draft before code, not from memory.
- Ed25519 from aws-lc-rs, ML-DSA-65 from moduletto (I-75). moduletto has no ML-DSA-65 yet. It is added on a moduletto pull request that Claude writes and Daniel reviews and merges (Q1, section 21.0).
- Until it lands, the ML-DSA half sits behind the `fstp-crypto` seam and composite signing refuses with a typed error. The anchorer core cannot prepare, so production writes are refused. aws-lc-rs ML-DSA stays a test oracle only, never a production fallback.
- I-90 already holds for anchors: the verifier accepts only when both halves verify. `i90_anchor_verifier_rejects_either_half_alone` runs in M3, although I-90 is an M9 exit.
- ACVP keyGen, sigGen and sigVer vectors for ML-DSA-65 run in CI. aws-lc-rs runs them through its stable `PqdsaKeyPair::from_seed` and `ML_DSA_65` APIs, and moduletto runs them once its ML-DSA-65 pull request lands. That pull request is proposed to include deterministic entry points (ADR-001 A2). Differential checks compare moduletto with aws-lc-rs. These are the T-CR-MLDSA tests for TH-68, and the composite verifier tests are T-CR-COMPOSITE for TH-67. M9 completes the remaining ML-DSA work.

---

## 8. Authentication (I-77, I-78, I-79)

### 8.1 Methods in M3

| Method | Strength | M3 status |
| --- | --- | --- |
| Passkey | Phishing-resistant | Built: in-house WebAuthn subset, attestation `none` only, ES256, EdDSA and RS256 of at least 2048 bits |
| Magic link | Weak | Built for Receiving-only accounts. Delivery through the outbox, so production use waits for M6 |
| EUDI Wallet | Phishing-resistant | Deferred (Q10). The `Method` enum reserves it, and P-70 refuses it until then |
| OPAQUE | Weak | Deferred (Q10). Needs an ADR-001 addition |

```rust
// fstp-webauthn
pub fn parse_attestation_object(b: &[u8]) -> Result<AttestationObject, WebAuthnError>; // CBOR, fuzzed
pub fn parse_authenticator_data(b: &[u8]) -> Result<AuthenticatorData, WebAuthnError>; // fuzzed
pub fn parse_cose_key(b: &[u8]) -> Result<CoseKey, WebAuthnError>;                     // fuzzed
pub fn parse_client_data(b: &[u8]) -> Result<ClientData, WebAuthnError>;               // fstp-json, fuzzed
pub struct RelyingParty { id: HostName, origin: Origin }   // new() refuses a registrable parent domain
pub fn verify_registration(r: &RegistrationResponse, x: &RegistrationExpect) -> Result<NewCredential, WebAuthnError>;
pub fn verify_assertion(a: &AssertionResponse, c: &StoredCredential, x: &AssertionExpect) -> Result<AssertionOk, WebAuthnError>;
```

- The CBOR decoder accepts only what WebAuthn uses: definite lengths, shortest form, no tags, no floats, no duplicate keys, depth at most 4, at most 64 KiB.
- `expect` fixes the RP id (the exact tenant host), the origin, the challenge, user presence, user verification and the sign count rule. UV is required for management accounts and for every step-up. Applicant passkeys request UV and record whether it was given.
- A sign count that goes down, with non-zero counters, refuses the login and records `CredentialSuspect`.

### 8.2 Sessions

```rust
// fstp-auth
pub enum Method { Passkey, EudiWallet, Opaque, MagicLink }
pub fn holds_management(roster: &RosterView, tenant: &TenantState, a: AccountId, now: Timestamp) -> bool;
pub fn admit_method(holdings: bool, m: Method, enabled: &EnabledMethods) -> Result<(), LoginDeny>;   // I-77 at login
pub fn admit_session(holdings: bool, s: &SessionView, now: Timestamp, p72: &SessionLifetimes) -> Result<(), SessionDeny>;
```

- "Holding" counts active, scheduled and suspended bindings of the Drafting, Judging and Operations groups, plus tenant admin. Voided bindings do not count. This is the strictest reading for I-77 and I-79. A binding whose end is scheduled counts until the end instant.
- **Sessions and binding ends (Q16 A).** `authentication.md` says "Ending a role binding ends the sessions that relied on it". No session records which binding it relied on, so every session of the account that started before the end instant ends at that instant. For an end recorded by a command, the batch carries the `SessionEnded` records. For a scheduled end, `admit` refuses the session from the instant on (section 5.4), and the system command `EndSessionsAtBindingEnd` records it afterwards (section 5.1). The end instants come from the roster that the M2 close-out lane defines (section 0.5).
- The cookie is `__Host-fstp`, Secure, HttpOnly, SameSite=Strict, Path=/. Its value is `cell id || token`. Another cell refuses it before any lookup (B11).
- State-changing routes also check the `Origin` header and accept only JSON bodies.
- R-LG-04: `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `GET /auth/devices`, `DELETE /auth/devices/{id}`. Removing a device is the high-risk action `ChangeLoginMethods`.

### 8.3 First passkey ceremonies (G10, Q15)

A first passkey is accepted only inside one of three logged ceremonies:

1. **Invitation.** A tenant admin issues an invitation with a step-up, or provisioning issues the first admin's. The token is single-use, valid 72 hours (an interim constant, Q37), and stored as a digest.
   - **First admin, SaaS (G25, Q35).** An operator who intercepts a single invitation would become tenant admin without any tenant approval. Daniel accepted the split on 2026-10-28, with a token sealed to a tenant-generated key once M4 onboarding exists. The cell, not the control plane, draws the token as two random halves, and the enrolment needs both. The control plane sends one half to the tenant contact recorded at contract. A second staff member gives the other half to the tenant's contract signatory over a different channel. Each half is shown to one staff member only. Enrolment records `FirstAdminEnrolled`, which every later tenant admin sees in the admin list and the audit view.
   - **First admin, self-hosted.** `fstp-cell` writes the token once to a root-only file on first start, and `fstp-cell first-admin` prints it on the host console. No default credential exists (R-NF-05).
2. **Self-registration** of a new Receiving account: email proof, then passkey enrolment in the same ceremony, at account creation.
3. **Recovery completion** (section 8.5).

An ordinary session, weak or strong, can add a second passkey only as the high-risk action `AddPasskey`. A magic-link session never can.

### 8.4 Step-up

- `POST /auth/stepup/options {command}` returns a challenge. `action_digest = SHA-256(canonical(command) || command_id)`. The challenge is `SHA-256("fstp-stepup-v1" || cell || session || action_digest || nonce)`.
- `POST /auth/stepup` verifies a passkey assertion with UV over that challenge and records `StepUpGranted { id, action_digest }`. So every step-up is logged with the action it authorised.
- The action request names the step-up id. `Gate::admit` checks it, and the batch consumes it.
- Freshness: `now - asserted_at <= P-71`, checked at admission and again at commit. A tenant value above the default is refused, because P-71 "may only shorten". P-71 (5 minutes) and P-72 (30 minutes idle, 12 hours absolute) are marked "(proposed)" in `policy-parameters.md`. M3 builds them as interim defaults, and Q37 asks Daniel to confirm them.
- One step-up authorises one command (Q15).

`HighRiskAction` is the single table:

| Variant | Source row in `authentication.md`, or domain kind |
| --- | --- |
| `ManagementRoleChange` (`GrantRole`, `EndRole`, `ReinstateBinding`, `GrantTenantAdmin`, `EndTenantAdmin`, `ApproveSelfGrant`) | Granting or changing a Drafting, Judging, Operations or tenant admin role |
| `ManagementRoleChange` (`Assign`, `Unassign`) | Strict addition (G28, Q38): "Assigned reviewer" is a Judging role in `roles-and-sod.md`, so assigning one grants it. M2's `high_risk()` omits both |
| `TenantExport`, `VaultExport`, `IdentityDownload` | Exporting data (export routes in M9) |
| `AddPasskey`, `LinkDevice`, `DesktopSignIn` | Linking a new device |
| `ChangeEmail`, `ChangeLoginMethods` (including `SetLoginPolicy` for P-70 to P-72) | Account takeover path. "Changing ... login methods" read strictly covers the tenant's login policy too (G28, Q38) |
| `ChangeBankDetails` | Payment diversion (M5) |
| `ApprovePayment`, `ReleasePayment` | Money movement |
| `ActivateProgramme` (`CreateProgramme`), `PublishCall` | Binding public commitments; creating counts as activating (confirmed 2026-10-25) |
| `PublishTemplate` | Data leaving the cell (M4) |
| `ApproveBreakGlass` | Operator access to content |
| `ApproveRecovery` | Strict addition: approving a recovery changes another account's login methods (Q15) |

`i78_high_risk_table_matches_spec_and_domain` checks this table against a transcription of the spec table and against `CommandKind::high_risk()`. Every domain high-risk kind must be in the table. Every table entry must be either a domain high-risk kind or on the explicit list `STRICT_ADDITIONS` (`Assign`, `Unassign`, `ApproveSelfGrant`, `SetLoginPolicy`, `ApproveRecovery`), each with its source row. So the M2 set is not locked in, and no addition is silent. W0 re-derives the table from the M2 close commit (section 0.5).

### 8.5 Recovery (I-79)

```rust
pub enum RecoveryPath { EmailThenPasskey, SecondAdmin, OperatorProcess, HostConsole }
pub fn recovery_path(holdings: Holdings, other_admins: usize, mode: Deployment) -> RecoveryPath;
pub mod recovery { pub fn complete(..) -> Result<Vec<AuthRecord>, CellRefusal>; }
```

| Account | Path | Steps |
| --- | --- | --- |
| Receiving roles only | `EmailThenPasskey` | Email proof, then a new passkey in the same ceremony |
| Holds a role outside Receiving, and another tenant admin exists | `SecondAdmin` | Email proof, then `ApproveRecovery` by a different current tenant admin with a step-up, then a new passkey from a one-time enrolment token |
| Sole tenant admin, SaaS | `OperatorProcess` | Email proof, then an operator ticket for the case reference with two staff approvals, then a new passkey. Logged and shown to the tenant |
| Sole tenant admin, self-hosted | `HostConsole` | Interim reading of "the platform operator's verified process" for a self-hosted cell, whose operator is the hosting organisation (Q15): a host console command run as root that needs custody access, then a new passkey. Logged, and shown to every tenant admin |

- `recovery::complete` recomputes the path from holdings at completion. A role granted during an open email recovery makes that recovery fail.
- Completion revokes every credential and ends every session of the account.
- When both approver and holder are verified, `SameIdentityAsAny` must be false. A vault outage refuses the approval (fail closed).

### 8.6 Break-glass (SoD-08, TH-18)

- Operator staff hold no binding in any cell. A request names a staff member, a scope of read actions and an end time of at most 4 hours. The 4 hours are an interim constant with no P- id (Q37).
- A tenant admin approves it with a step-up, recording `BreakGlassApproved { grant, staff, scope, until }`.
- Staff reach the cell with a control-plane-signed staff assertion, which the cell verifies against a pinned key. The gate treats them as a separate principal kind.
- Every use is a `BreakGlassRead` record and shows in the tenant's audit view. Content views for operators arrive with the M4 interfaces.

### 8.7 Cell routes in M3

| Route | Risk class |
| --- | --- |
| `POST /auth/invitations/{token}/register/options`, `.../register` | Ceremony |
| `POST /auth/signup/options`, `POST /auth/signup` | Ceremony, Receiving accounts only |
| `POST /auth/passkey/login/options`, `POST /auth/passkey/login` | Public |
| `POST /auth/magic/request`, `GET /auth/magic` (confirm page), `POST /auth/magic/consume` | Public, Receiving-only accounts. Same response whether or not the account exists |
| `POST /auth/stepup/options`, `POST /auth/stepup` | Session |
| `POST /auth/passkeys/options`, `POST /auth/passkeys` | High risk `AddPasskey` |
| `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `GET /auth/devices` | Session |
| `DELETE /auth/devices/{id}` | High risk `ChangeLoginMethods` |
| `POST /auth/recovery`, `.../{case}/email`, `.../{case}/approve`, `.../{case}/complete` | Public, public, high risk `ApproveRecovery`, ceremony |
| `POST /api/v1/commands` | Per command through `HighRiskAction::of` |
| `POST /api/v1/vault-tickets` | Session; `IdentityDownload` for download scope |
| `POST /api/v1/verifications` | Issues a `VerificationRecorded` write ticket for the vault origin to a tenant admin with a verified identity, within the ADR-008 release window. The outcome itself goes browser to vault (ADR-008, section 6.7) |
| `GET /api/v1/audit/anchors`, `GET /api/v1/erasures` | Session, Auditor or tenant admin |
| `GET /healthz` | Loopback only, fixed body |

---

## 9. Control plane, provisioning and edge

### 9.1 Control plane protocol

```rust
// fstp-cp-proto. Every field has a closed type. No variant has a free-text or byte-blob field.
pub enum CellToCp {
    Heartbeat { cell: CellId, version: ProductVersion, health: Health },
    RoleCredential { role: RoleName, spki: SpkiDigest, pop: PopSig, scram_verifier: ScramVerifier },
    CertRenewal { component: Component, spki: SpkiDigest, pop: PopSig },
    Metering { cell: CellId, period: i64, counters: Vec<(CounterKind, u64)> },
}
pub enum CpToCell {
    Ack, Certificate(CertDer),
    OperatorTicket { case: CaseRef, kind: TicketKind, issued_at: i64, sig: CompositeSig },
    BreakGlassRequest { staff: StaffRef, scope: BreakGlassScope, until: i64 },
    EraseScheduled { at: i64 },
}
pub enum Health { Ok, Degraded(DegradedReason), Maintenance }
```

- Template publication (I-73) and the open-call directory (P-76) are the only planned tenant-data paths. Their variants arrive in M4 and M9, each behind its own guard. In M3 the enum cannot carry tenant data.
- `CertDer` and `ScramVerifier` are closed grammars, checked on decode.
- Anchors do not pass through the control plane. They go straight to the witness (section 7.2).
- **Metadata register (G26, Q36).** Fields that cross to shared infrastructure without being tenant content are listed in `fstp_cp_proto::METADATA_REGISTER`, each with its type, its destination and its coarsest useful form. In M3 the register holds six entries. They are the heartbeat version and `Health` (a closed enum with no free text), and metering counters as counts per day. At the edge they are the cell id and host, and byte counts and timings bucketed to powers of two. The others are metric names and values labelled by cell id, and anchor links at the witness. Anchor links are SHA-256 values over sealed rows, so they reveal only that the chain grew. `i19_only_registered_metadata_crosses` checks every capture against the register. T-ISO canaries cannot see metadata, so this test carries that part of I-19.

### 9.2 Provisioning

`fstp-control provision-cell --org <ref> --mode shared|dedicated`, by an operator with a passkey and a step-up. Each step is idempotent and recorded in `cp.job`:

1. Draw a `CellId` (128 random bits).
2. `Placement::new(app_cluster, vault_cluster)`, which refuses equal clusters or wrong kinds (I-83).
3. Create custody entries for the App, Vault and CellBackup chains. The Vault chain uses a separate credential.
4. `fstp-pgagent` creates both databases, the roles as NOLOGIN, the `pg_hba` lines and the revocations, from `fstp_control::pg::cell_role_plan(cell)`.
5. Issue the public host certificates for `<cell host>` and `id.<cell host>` to keys the cell generates (Q30). The cell creates its CA key in its custody entry at first start.
6. Start the cell and vault. Each generates role key pairs and passwords, and sends `RoleCredential` messages. `fstp-pgagent` sets the SCRAM verifiers and LOGIN. The cluster CA issues the role certificates.
7. Run migrations and grants. Write `fstp_meta.placement` in both databases.
8. Create epoch 1 for each chain. Write the genesis chain rows and first anchors.
9. Publish the routes for `<cell host>` and `id.<cell host>` to the edge.
10. The cell creates the first tenant admin invitation as two halves (section 8.3). The control plane relays one half to the tenant contact and keeps no copy. A second staff member hands over the other half. The control plane never learns the account id or the full token.

```rust
pub struct Placement { app: ClusterId, vault: ClusterId }   // private fields
impl Placement { pub fn new(app: &Cluster, vault: &Cluster) -> Result<Placement, PlacementError>; }
```

At start, `fstp-vault` refuses a database whose `fstp_meta.placement.kind` is not vault, or whose server certificate OU is not `vault`, or whose server SPKI is registered for an application cluster. `fstp-cell` makes the mirror checks.

### 9.3 Isolation auditor

`fstp_control::isolation_audit::privilege_graph` reads `pg_roles`, `pg_auth_members`, `pg_database.datacl`, `pg_extension`, view grants and `pg_hba_file_rules`. Array columns are expanded on the server, through `aclexplode(datacl)` and `unnest()` over the `text[]` columns of `pg_hba_file_rules`. The auditor therefore receives scalar text, integer and boolean values only, which existing `fstp-pgwire` decoders handle, and no new array parser exists. A source scan refuses an array type in the auditor's queries. If one is ever needed, it gets a fuzz target in its first commit. The last needs superuser in PostgreSQL 16, so the audit runs as a `fstp-pgagent` job on the host. It runs hourly in production and is the test oracle in CI.

### 9.4 Edge

```rust
// fstp-edge
pub enum SniOutcome { NeedMore, Host(HostName), NoSni, NotTls }
pub fn parse_client_hello_sni(buf: &[u8]) -> Result<SniOutcome, SniError>;   // at most 16 KiB, fuzzed
pub struct RouteTable { by_host: BTreeMap<HostName, (CellEndpoint, RouteKind)> } // verified hosts only
pub fn encode_tunnel_header(h: &TunnelHeader) -> [u8; TUNNEL_HEADER_LEN];
pub fn decode_tunnel_header(b: &[u8]) -> Result<TunnelHeader, HeaderError>;      // fuzzed, used by the cell
```

- No SNI, an unknown host or a malformed hello closes the connection. A hello with the ECH extension is routed on its outer SNI (Daniel, 2026-10-29; ADR-009).
- The edge logs host, cell id, byte counts and timings only. It holds no tenant TLS key.
- Client addresses go into the tunnel header for the cell's in-memory rate limits only (Q19).

### 9.5 Self-hosted install and renewal (G29, R-NF-01, R-NF-05)

A self-hosted cell has no control plane (B12), so the steps that `fstp-control` performs in SaaS run locally. `fstp-install` is a one-shot binary in `fstp-control`, run as root on the node. It reuses `Placement`, `cell_role_plan` and the DDL grammar, so the two modes share one implementation.

1. Check the node: two PostgreSQL 16 data directories with separate OS users and ports, the `fstp-keyd` key volume (section 3.3), and swap disabled.
2. Start `fstp-keyd`. It creates the App, Vault and CellBackup chain entries, and one EC secp256r1 sign key per cluster CA. The cluster CA keys therefore live in local custody, not in control-plane custody.
3. Create both cluster CAs and server certificates, with the kind in the OU. Write `pg_hba.conf` from the same generator as SaaS, plus the loopback superuser and replication lines (section 4.1).
4. Run `fstp-pgagent` in local mode over loopback for databases, NOLOGIN roles and revocations. Each role key pair and password is generated by the component that uses it. `fstp-pgagent` sets the SCRAM verifiers and LOGIN, and signs role certificates with the local cluster CA through `fstp-keyd`.
5. Run migrations and grants. Write `fstp_meta.placement` in both databases.
6. Start `fstp-witness` locally. Register the cell CA's public key with it.
7. Configure the local `fstp-edge` route table for `<host>` and `id.<host>`, so the vault origin is routed by SNI as in SaaS (section 1.4).
8. Start the cell and the vault. The cell writes the first-admin token to a root-only file (section 8.3).

Renewal: a `fstp-pgagent` timer in local mode renews role certificates daily, and the cell CA renews internal certificates as in SaaS. No step needs a CrabNebula host (I-38). `i83_self_hosted_layout_runs_two_instances` runs `fstp-install` in a fresh world. `r_nf_05_self_hosted_install_has_no_default_credentials` checks that every credential is generated at install and that no file holds a fixed value.

---

## 10. Update and licence services (I-38, I-39)

### 10.1 What a self-hosted cell sends

```rust
// fstp-release::egress. The only code that builds requests to CrabNebula hosts.
pub struct UpdateCheck { pub version: ProductVersion, pub channel: Channel }
pub struct LicenceRefresh { pub licence: LicenceId, pub version: ProductVersion }
pub enum CnCall { Update(UpdateCheck), Licence(LicenceRefresh) }
pub fn encode(call: &CnCall) -> Vec<u8>;
// Update:  GET /v1/updates/{channel}/{version}   Host only; no body, cookies or User-Agent
// Licence: POST /v1/licences/{licence}/refresh   Host, Content-Type, Content-Length; body {"version":"x.y.z"}
```

- `ProductVersion`, `Channel` and `LicenceId` have closed grammars. None can hold arbitrary text.
- TLS uses the service host as SNI and presents no client certificate, so this link is not mutually authenticated at the TLS layer. The licence refresh is authenticated by the licence id and the signed token it refreshes; the update check is deliberately anonymous. R-NF-09 is not claimed for this link until Q34 is answered.
- The client's address still reaches the service (Q19).

### 10.2 Licence

```rust
pub struct LicenceToken { licence: LicenceId, kind: LicenceKind, issued_at: i64, refresh_after: i64,
                          not_after: i64, sig: Ed25519Sig }
pub fn verify_token(bytes: &[u8], key: &Ed25519Public) -> Result<VerifiedToken, TokenError>; // fuzzed
pub enum LicenceState { Valid { until: i64 }, Grace { since: i64, ends: i64 }, Expired { since: i64 }, Missing }
pub fn licence_state(token: Option<&VerifiedToken>, last_ok: Option<i64>, now: i64, p43: Days) -> LicenceState;
pub fn permits(state: LicenceState, kind: GateKind) -> bool;   // true for every kind in M3 (Q18)
```

- A refresh runs in a background task of `fstp-cell`, at most daily, with a 10-second timeout and backoff. Neither cell start nor any request waits for it. Handlers' context holds no handle to it.
- The `permits` table already marks evaluation, payments, notifications and export as protected. A later change cannot touch protected rows without failing `i39_*`.
- `fstp-licence-svc` issues noncommercial tokens automatically on self-declared status (O-27). It stores only holder name, contact address and licence type (`gdpr.md`, ADR-005).
- **First token (Q41).** The cell never sends registration data. The holder registers on a CrabNebula web page, outside the cell, and receives a signed token file. `fstp-cell licence import <file>` verifies it locally and stores it sealed. So `CnCall` keeps its two variants, and no holder name or contact ever leaves a cell (I-38).
- **Key rotation** (`self-hosted-services.md`: "support key rotation"). The cell pins a licence key set shipped with its release. A `KeyTransition { next_key, not_before, sig }` statement signed by a current key adds the next key, and the refresh response may carry one. A token signed by a key outside the set is refused. Tests: `i39_licence_key_transition_accepted_only_when_signed_by_a_pinned_key`, `i39_rotation_never_blocks_protected_commands`.

### 10.3 Update

- `fstp-update-svc` serves release metadata per channel. The cell stores the highest metadata version it has seen and refuses older or expired metadata.
- The cell does not report "update available" in M3. Metadata cannot be verified until the release root certification of I-91 lands in M9, and an unverified notice would let a forged response steer tenant admins. The admin view shows only the last check time and outcome.
- Installation is not built in M3. `ReleaseVerifier::verify` returns `NotYetVerifiable` until the release root certification of I-91 lands in M9.
- `may_apply(state, now)` is false while any call has a proposal in STAGE1, STAGE2, RANKED or IRC_REVIEW, or a payment release is in flight (`self-hosted-services.md`). The tenant admin schedules updates.
- Air-gapped cells import bundles from a file, through the same verifier.
- A self-hosted build refuses P-45 intermediary mode at configuration decode (`eudi-wallet.md`).

---

## 11. Observability and the web pages

### 11.1 `fstp-obs` (R-NF-02)

- `LogEvent` and `Metric` are closed enums. Fields are ids, rule references, enums, counts, durations and `&'static str`. No variant takes a `String`, so free text cannot reach a log by construction.
- Paths are logged as route templates. Logs stay per cell. Operator aggregation receives metrics only, labelled with the cell id.
- A clippy `disallowed-methods` entry bans `println!` and `eprintln!` in shipped crates.

### 11.2 TypeScript pages (ADR-003)

- `web/auth/` (login, signup, step-up, sessions, recovery) on the cell origin, and `web/vault/` (write and release pages) on the vault origin. In-house TypeScript in strict mode, compiled by the pinned tsc, no framework, no third-party asset.
- CSP on the cell origin: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. The vault origin is stricter and allows no script on release pages.
- WebAuthn JSON conversion uses the browser's `parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON`, so the pages hold no in-house parser.
- Accessibility follows R-NF-03 (WCAG 2.2 level AA): labelled controls, keyboard paths, AA contrast, visible focus, and error text tied to its field. No third-party checker is allowed, so `e2e/r-nf-03-auth-and-vault-pages.spec.ts` checks in-house what a browser can check. Every control has an accessible name, and every flow completes by keyboard alone. Focus order follows the page, and colour pairs from the stylesheet tokens meet the AA ratio. A manual WCAG 2.2 AA review of each new page is recorded in the exit audit.
- Localisation follows R-NF-04. Every user-visible string comes from a message catalogue keyed by id, with English as the M3 catalogue. `r_nf_04_pages_have_no_literal_user_strings` scans the TypeScript sources and the vault's server-rendered pages for literals outside the catalogue.
- `cargo test` never needs Node. Playwright runs in its own CI job.

---

## 12. Security design against the threat model

| Threat | M3 mitigation |
| --- | --- |
| TH-03 | SoD-09 queries answered by the real vault under the commit protocol, model-checked in M-VCP |
| TH-04 | `HasConflict` over reviewer declarations and I-54 relationships in the real vault (section 6.8). Test `th_04_t_sod_conflict_over_real_vault` (T-SOD-CONFLICT) |
| TH-05 | `Gate::admit` on every route, SoD-07 in the tenant fold, admin grants high-risk, identity reads logged |
| TH-06 | Trust domain per cell (B1 to B12), sealed storage, typed logs, closed egress, layering rule 4 |
| TH-07 | Attributes never enter the application. Releases need an Operations role, NEGOTIATION and the vault's own negotiation fact. `i17_canary_attributes_never_reach_judging_responses` is the T-PRIV-CANARY test for M3. Metadata and file-property stripping of submissions stays with the submission pipeline |
| TH-13 | EU regions of an EU-owned provider (ADR-005) |
| TH-14 | Insert-only role and triggers, a database-side link check, per-commit witness receipts, composite anchors at two witnesses |
| TH-15 | No new crate except moduletto, already Tier B. Every tree recorded. Funds, layering and runtime rules in deps-check |
| TH-18 | Operators hold no roles. Break-glass is tenant-approved, scoped, time-boxed and logged. Content is sealed even from a database superuser. The first admin invitation is split across two staff and two channels. Root on a cell host remains a path to unwrapped group keys, accepted as residual risk by Daniel (R16, Q35) |
| TH-27 | `DeclaresAffiliationOnList` over P-38 lists written by the programme manager (section 6.8). Test `th_27_t_sod_assign_proximity_list_over_real_vault` (T-SOD-ASSIGN) |
| TH-26 | A fuzz target for every new parser from its first commit (section 15) |
| TH-30 | Per-document groups destroyed on verification by root-epoch rotation |
| TH-32 | M3 installs nothing and announces no update. Metadata rollback and expired metadata refused; licence key rotation only through a pinned key. Tests `th_32_t_update_rollback_and_expired_metadata_refused`, `th_32_t_update_no_notice_from_unverifiable_metadata` (T-UPDATE) |
| TH-33 | Licence checks off the request path; nothing gated in M3 |
| TH-34 | Self-hosted refuses intermediary mode. The intermediary is out of M3 |
| TH-48 | Cell erasure removes both routes |
| TH-50 | moduletto ML-KEM only with X25519, ML-DSA only with Ed25519 (I-75). Differential tests against aws-lc-rs |
| TH-51 | Every stored body, keystore snapshot and backup sealed through the hybrid KEM (R-CR-01) |
| TH-55 | Passkeys with UV for every management holding (I-77) |
| TH-56 | Single-use step-ups bound to the command digest (I-78) |
| TH-57 | Second-admin recovery with a step-up and an identity check, path recomputed at completion (I-79) |
| TH-58 | Per-cell roles, per-database `pg_hba` lines, no remote superuser or CREATEROLE, revoked shared views, no extensions, vault clusters apart |
| TH-59 | Roots created in custody and never exported. Per-cell, per-chain credentials. Reconciliation where the backend logs use |
| TH-67 | Composite anchors and receipts, verifier requires both halves (I-90). Tests `r_cr_03_*` and `i90_*` are labelled T-CR-COMPOSITE |
| TH-68 | moduletto ML-DSA only inside the composite (I-75, I-90). ACVP and differential tests labelled T-CR-MLDSA. The Tier B release gate (section 2.6, I-74) |

Hardening activities M3 feeds: H-01 (the gate and route table), H-02, H-05, H-07, H-09, H-10 (deps-check rules and the Tier B gate), H-11 (the self-hosted install of section 9.5), H-16, H-18 (moduletto's first production use), H-19, H-21, H-22.

---

## 13. Seams to earlier and later milestones

### 13.1 From M1

- `fstp-pgwire` `Config` with `ClientTls` for every role, as ADR-005 D2 requires. The M1 default "production client certificates per role: not designed yet" is closed by the cluster CA (section 1.3).
- `fstp-migrate` runs every migration set. The ledger schema rule refusing a schema owned by another role stays.
- `fstp-tls` resumption policy P2 applies to every M3 link.

### 13.2 From M2 (`m2-design.md` sections 4 and 5)

| M2 seam | M3 delivery |
| --- | --- |
| Async driver over `queries`, `decide`, `append`, `apply` | `DriverCore` plus `CellEngine`, checked against `fstp_engine::Engine` |
| `PgRecordStore` over an insert-only table, INSERT and SELECT only, expected head, idempotency | Section 5.3, with sealed bodies (Q5) |
| Audit chain `link_n = H(link_{n-1} || canonical(entry_n))` in the same transaction | Section 7, over the stored row bytes |
| Vault with the decided query set, epochs, fail-closed, NOTE 1 to 6 | Section 6. NOTE 1 candidate sets stay in the domain. NOTE 2 in `DriverCore`. NOTE 3 epoch match. NOTE 4 commit protocol. NOTE 5 digests and one-bit answers. NOTE 6 country only to the vault, through the vault origin |
| Erasure log (ADR-007) | Section 5.6 and section 3.5 |
| `TextRef` | Unchanged; salts sealed with the text |
| Outbox records in the same batch | `ops.outbox`, sealed. M6 dispatches |
| Projection checkpoints | Sealed `ops.checkpoint` rows, compared with replay |
| `Ctx` tenant admin attestations | From the tenant fold (section 5.1) |
| `CommandKind::high_risk()` enforced by the shell | `Gate::admit` (section 5.4) |

### 13.3 To later milestones

- **M4.** The route table with risk classes feeds the authorisation matrix. `ACTOR_RULES` and `Gate::admit` are the single path for MCP (I-84, I-85). Tenant onboarding uses provisioning. Break-glass content views. EUDI Wallet if Q10 places it there. Template publication gets its `CellToCp` variant.
- **M5.** Bank details as vault facts on the vault origin. Payment adapters take credentials from the tenant's vault. The funds allowlist gains the one adapter crate.
- **M6.** The dispatcher reads `ops.outbox`. Magic links, recovery emails and erasure confirmations start being sent.
- **M8.** Messaging handles as vault facts, released only to adapters.
- **M9.** Full ML-DSA ACVP, the moduletto TLS group, release root certification and update installation (I-91), export manifests, ACME and custom domains (I-71), the self-hosted package. smol for the self-hosted cell if ADR-002 chooses it.

---

## 14. Test plan

### 14.1 Conventions

M3 keeps every convention of `m2-design.md` section 6.1. Test names carry identifiers, and each test function holds one check. Model runs are exhaustive, with `reachable` witnesses, `max_states` tripwires at twice the measured count, and two-way postconditions. References are independent and written by a different agent. Start states come from genesis, the clock is reduced, symmetry needs a self-test, and teeth use public structural entry points.

M3 adds:

- **Sans-IO models.** Every model drives a production pure core: `fstp-cell-core` (gate, `DriverCore`), `fstp-auth`, `fstp-vault-core`, `fstp-keys`, `fstp-audit` or `fstp_control::placement`. The async shells are tested separately against real PostgreSQL.
- **Environment faults as model actions.** Crash and restart of either side, message loss, duplication and reordering, custody failure mid-plan, witness unavailability.
- **Reduced clock** around P-71, P-72 and P-43: each step-up instant plus P-71, one microsecond before and after, and the same for session ends and the licence grace end.
- **Canaries.** Every synthetic personal value is a canary `CNRY-<cell>-<kind>-<32 hex>`. Kinds: name, email, phone, country, document byte pattern, IP address, proposal text, root key, text salt, account id.
- **Scanners** search raw bytes, both hex cases, base64, base64url, percent-encoding, JSON string escaping and UTF-16LE.
- **Teeth for scanners and auditors.** Each scanner test has a twin that seeds one canary and asserts that it is found. Each catalogue auditor has a twin that seeds one forbidden grant.
- **Real topology.** `fstp-pgtest` worlds with application, vault, control and witness servers, each with its own cluster CA. Role certificates are minted at test time by `fstp-pki`.
- **Process mode.** I-80 and isolation tests spawn real binaries through `CARGO_BIN_EXE_*`.
- **Fixtures** are synthetic only, shaped like the corpus variants "Sybil", "Excluded affiliation", "Minor applicant" and "Repeat applicant".

### 14.2 Models

| Model | Production code driven | Universe | Properties | Teeth |
| --- | --- | --- | --- | --- |
| M-AUTH | `fstp-cell-core` gate with `fstp-auth` and the M2 roster | Accounts a, b, admin1, admin2. Passkey and magic link. Grants and ends of committee member and finance approver, one tenant admin grant. One scheduled end, with ticks one microsecond before and after its instant. Two logins each. One credential revocation | `always("I-77")`; `transition("I-77")` for weak `StartSession` of a holder. Witnesses: applicant by magic link; committee member by passkey; a grant ends a weak session in the same batch | `admit_method` ignores scheduled bindings; the grant batch omits `SessionEnded` |
| M-STEPUP | `gate::admit` step-up branch | One admin, one session, actions `ManagementRoleChange`, `ReleasePayment`, `AddPasskey`. Step-ups by passkey, by passkey without UV, from a magic-link session. Ticks at P-71 minus 1 µs, P-71, P-71 plus 1 µs. One replay. P-71 in {5 min, 1 min} | `transition("I-78")`: every committed high-risk command has a strong, fresh, unconsumed step-up for its digest. `always("I-78-single-use")`. Witness: an action at exactly P-71 commits | `>=` for staleness; consumption dropped; digest compared by kind only |
| M-RECOVER | `fstp_auth::recovery` with the roster | Accounts a (committee member), b (applicant), admin1, admin2. Email recovery, approval, a grant racing an open recovery, an operator ticket in a single-admin variant | `transition("I-79")`. Witnesses: b by email; a with admin2's approval | Path checked at request time only |
| M-VCP | `fstp-vault-core`, `DriverCore`, `fstp-cell-core` | Accounts A and B (one identity), C. One provisional verification revealing the pair, one provisional affiliation into an excluded class, one consent. One applicant command per account. One loss, one duplicate, one crash of each side | `always("I-04")`, `always("I-06")` over effective facts. `transition("NOTE-4")`. `always("I-18")` over effective consents. Witnesses: the fact becomes effective after the ack; the reaction voids the Receiving binding | Vault answers a non-reaction query while provisional; driver acks before its reaction commits; fact effective without an ack |
| M-DRIVER | `DriverCore` with `MemStore` and `SyntheticVault` | Two commands, one `VaultChanged`. Crash after append before the reply. One lost ack. One stale head | `always("I-23")`; a retried command is a duplicate, never applied twice | Retry with a fresh command id |
| M-SHRED | `fstp-keys` planner and a symbolic attacker in `fstp-celltest` | Two groups, four data keys, three erasure requests, snapshots and backups at any step, custody failure after any operation, crash and resume | `always("I-81")`: for every erased key and every snapshot, the attacker's closure over all snapshots, the live store and every live custody key lacks the key. `always("no-data-loss")`: every live key opens from the live store and from the newest verified snapshot. Witnesses: an erasure completes; a crash resumes | Group not rotated; old epoch destroyed before the commit; completion before the receipt |
| M-AUDIT | `fstp_audit::verify`, the anchorer core | Up to six entries, two anchors. Prepare, abort, commit failure, unknown commit outcome, crash of the cell or the witness at any step. Attacker actions: modify, delete, insert, reorder, truncate, recompute links after a change | `always("I-24")`: every change to any committed entry is reported, as a tamper or as `PossibleDeletion`. `always("no-unwitnessed-commit")`. Witnesses: an abort then a retry at the same `n`; an in-doubt prepare resolved as committed | Verifier skips the receipt comparison; abort accepted for a present row; commit before receipt |
| M-PLACE | `fstp_control::placement` and `cell_role_plan` | Three clusters, two cells, kinds application, vault and control. Provisioning in shared and dedicated mode, cluster registration, decommission. Moves between modes are M9 work through export and import (ADR-005), so the model has no move action | `always("I-83")`; `always("I-82-plan")`: no planned grant reaches two cells' databases | Placement takes the first free cluster |
| M-LICENCE | `fstp-release` licence state with a command classifier | Valid, grace, expired, missing. Refresh success, failure, garbage. Ticks at grace end ±1 µs | `always("I-39")`. Witness: an expired state with an evaluation command committing | `permits` refuses `ReleasePayment` |

### 14.3 Isolation harness (`fstp-celltest`)

```rust
pub struct WorldSpec { pub cells: u8, pub mode: DbMode, pub vault_layout: VaultLayout, pub self_hosted: bool, pub process_mode: bool }
pub struct World { /* clusters, cells, control plane, edge, witness, custody simulator, recorders */ }
impl World {
    pub fn start(spec: WorldSpec) -> Result<World, WorldError>;
    pub fn cell(&self, i: u8) -> &CellHandle;                  // HTTP client with SoftAuthenticator
    pub fn run_cycle(&self, cell: u8, script: &CycleScript) -> CycleReport;
    pub fn stores(&self) -> StoreSet;                          // every database, object dir, log and metrics sink
    pub fn egress(&self) -> &EgressLog;                        // plaintext captures above TLS on every outbound client
}
pub fn scan(stores: &StoreSet, canaries: &[Canary]) -> ScanReport;
pub fn shared_identifiers(a: &CellDump, b: &CellDump, allow: &PublicConstants) -> BTreeSet<Vec<u8>>;
```

- The egress recorder is a test transport on `fstp_rt::duplex`, above TLS. It records cell to vault, cell to control plane, cell to witness, cell to custody, cell to CrabNebula hosts.
- `SoftAuthenticator` produces real WebAuthn registrations and assertions with ES256 and Ed25519 keys. It also produces faults: a wrong origin, a wrong RP id hash, UV off, a replayed challenge, a counter regression.
- `fstp-custody-sim` holds known root bytes so scanners can look for them.

### 14.4 Per exit invariant

**I-16 The platform never holds or controls funds**

- Structure: no crate builds a payment instruction or names a platform account. Payment adapters arrive in M5 and must take credentials from the tenant's vault.
- Guard: `tools/deps-check/src/funds.rs` with `deps/funds-allowed.txt` empty in M3, `TableClass`, `Destination`.
- Tests:
  - `i16_no_crate_builds_payment_instructions`: a source scan for SEPA credit transfer element names and payment credential types, listed in the rule's fixture.
  - `i16_schemas_have_no_fund_class`: every migration applied, then `pg_tables` and columns compared with `catalogue::TABLES`.
  - `i16_config_types_hold_no_debtor_account`: `CellConfig` and `ControlConfig` have no field of a payment account type.
  - `i16_cell_egress_has_no_payment_destination`: enumerates `Destination`.
  - `i16_teeth_seeded_instruction_crate_is_caught`.

**I-17 Judging roles cannot read identity attributes before negotiation**

- Structure: attributes exist only in the vault database and are rendered only on the vault origin.
- Guards: `release::issue_ticket`, `release_allowed`.
- Tests:
  - `i17_canary_attributes_never_reach_judging_responses` (machine over cell HTTP): random M2 commands plus vault-origin writes of country, affiliation, consent and documents. Every response body and header for a Judging or Drafting session is scanned. Login email canaries of applicants are included.
  - `i17_app_database_holds_no_identity_attribute`: after the machine run, zero canaries of kind name, phone, country or document in any application table.
  - `i17_release_ticket_only_for_operations_in_negotiation`: property against an independent reference over roles and states.
  - `i17_vault_refuses_release_without_negotiation_fact`.
  - `i17_vault_refuses_forged_stale_replayed_or_foreign_tickets`.
  - `i17_logs_and_metrics_hold_no_attribute`.
  - Playwright `i17-vault-origin-release.spec.ts`: the release page lives on the vault origin and the application origin cannot read it.
  - `i17_teeth_ticket_issued_in_ranked_is_caught`, `i17_teeth_attribute_logged_is_caught`.

**I-18 Minor proposals need verified guardian consent before negotiation**

- Structure: M2's guard asks `HasGuardianConsent`. The vault counts only effective consents with an effective guardian verification.
- Guard: `fstp_vault_core::eval::guardian_consent`.
- Tests:
  - `i18_minor_flag_blocks_negotiation_without_verified_consent` (machine over `CellEngine`, the real vault and PostgreSQL), with the "Minor applicant" variant. Consents recorded, withdrawn, or recorded by an unverified guardian. Facts come from the section 6.9 seeder.
  - `i18_no_minor_flagged_proposal_reaches_granted_without_consent`: the literal `test-plan.md` property, over random full cycles through HTTP.
  - `i18_route_never_takes_minor_flag_from_the_request`: every `CreateDraft` the route builds has `minor = true`, and a body with the field is refused (Q13 interim).
  - `fstp_vault_has_no_seed_path` (section 6.9).
  - `i18_consent_counts_only_after_guardian_verification_is_effective` (vault-core property).
  - `i18_m_vcp` properties.
  - `i18_teeth_provisional_consent_counted_is_caught`.

**I-19 No tenant data crosses a cell boundary (T-ISO)**

- Structure: B1 to B12, closed `CellToCp`, cell CA trust stores.
- Tests:
  - `t_iso_i19_no_canary_crosses_a_cell_boundary`: three cells in shared mode, plus a dedicated variant. A full cycle per cell with that cell's canaries. Every store and egress capture outside the cell is scanned: other cells, control plane, edge, witness and every shared log sink.
  - `i19_control_plane_columns_are_declared`.
  - `i19_cp_proto_fields_are_declared`: every `CellToCp` and `CpToCell` field type is in the allowlist of closed types.
  - `i19_edge_forwards_bytes_after_client_hello_unchanged`.
  - `i19_foreign_cell_certificates_are_refused`: cell B's certificates against cell A's vault and databases.
  - `i19_session_of_one_cell_is_refused_by_another`.
  - `i19_cell_process_serves_one_cell`.
  - `i19_only_registered_metadata_crosses` (section 9.1, Q36).
  - `i19_teeth_canary_in_heartbeat_is_caught` (test-only mutant client), `i19_teeth_seeded_leak_in_control_plane_is_caught`.

**I-20 No link between tenant accounts in different tenants (T-ISO)**

- Structure: accounts, credentials, sessions and lookups live in the cell; match keys and lookup keys are per cell.
- Guards: layering rule 4, `RelyingParty::new`, `CellKeyedIndex::new`.
- Tests:
  - `t_iso_i20_no_shared_identifier_across_tenants`: one synthetic person joins cells A and B with the same email, authenticator, client address and attributes. `shared_identifiers` over every store reachable from either cell and from shared infrastructure returns only public constants.
  - `i20_rp_id_is_the_exact_cell_host`.
  - `i20_control_plane_crates_cannot_name_account_types` (layering, with a failing fixture).
  - `i20_control_plane_and_witness_hold_no_account_id`.
  - `i20_vault_match_keys_differ_across_cells`.
  - Playwright `i20-passkey-not-offered-across-tenants.spec.ts`: Chromium virtual authenticator, two tenant hosts.
  - `i20_teeth_shared_lookup_key_is_caught`.

**I-24 The audit log is tamper-evident (T-AUDIT)**

- Structure: section 7.
- Guards: `ChainWriter::append`, `fstp_audit::verify`, the `audit.check_link` trigger.
- Anchor signatures: until the moduletto ML-DSA-65 pull request lands (Q1, section 21.0), these tests sign with the aws-lc-rs ML-DSA test oracle through `fstp-celltest`. Production composite signing refuses with a typed error meanwhile. The exit report states which implementation the tests ran against (`SPEC/09-milestones.md` NOTE 2).
- Tests:
  - `i24_verifier_flags_every_mutation`: property over random chains with one change, deletion, insertion, reordering, truncation or consistent recomputation at any row, ledger entry, anchor or receipt. Both chains.
  - `i24_m_audit`.
  - `i24_pg_chain_equals_reference_chain` (differential, byte for byte).
  - `i24_database_refuses_bad_link_and_mutation`: wrong link refused by the trigger; SQLSTATE 42501 on UPDATE, DELETE and TRUNCATE for the writer; the trigger exception for the owner; superuser edits then detected by `verify`.
  - `i24_ledger_and_chain_commit_together`: crash injection after every statement of the append.
  - `i24_no_commit_without_a_receipt_for_its_link`: crash and fault injection at every step of section 5.3.
  - `i24_abort_recorded_before_the_same_n_is_prepared_again`.
  - `i24_in_doubt_missing_row_raises_possible_deletion`.
  - `i24_tail_deletion_after_commit_is_detected`, for both chains.
  - `i24_vault_chain_anchored_by_the_vault_only`.
  - `i24_erasure_entries_are_chained`.
  - `i24_custody_ops_reconcile_with_key_records` (simulator log).
  - `i24_teeth_verifier_without_receipt_check_is_caught`, `i24_teeth_link_omitting_a_field_is_caught`.

**I-38 Calls to CrabNebula services carry no tenant data**

- Structure: section 10.1.
- Guard: `egress::encode`.
- Tests:
  - `i38_update_check_bytes_match_the_template`, `i38_licence_refresh_bytes_match_the_template`: byte-exact captures. Only version, channel and licence id vary.
  - `i38_self_hosted_cell_sends_no_canary_to_crabnebula_hosts`: random full cycles, restarts, refresh outcomes and update checks.
  - `i38_only_egress_reaches_crabnebula_hosts`: the cell's outbound connector refuses those hosts for any other caller.
  - `i38_self_hosted_refuses_intermediary_mode`, `i38_self_hosted_witness_never_targets_crabnebula`.
  - `i38_teeth_extra_header_is_caught`.

**I-39 Service outages never block evaluation, payments, notifications or export (T-LICENCE-OUTAGE)**

- Structure: background checks with timeouts, no start-up dependency, layering rule 6, `permits`.
- Tests:
  - `i39_cycle_completes_with_services_down`: refused, timed out, failed TLS, garbage, slow body, expired token, bad signature, clock skew. Each case runs the M2 catalogue to GRANTED and through the payment commands, enqueues outbox events and calls the export entry point stub. M5, M6 and M9 rerun it with real legs (G18).
  - `i39_licence_states_never_block_protected_commands`: property over every command kind and licence state.
  - `i39_no_command_path_reaches_release_crate` (layering).
  - `i39_m_licence`.
  - `i39_teeth_gate_on_release_payment_is_caught`.

**I-77 Strong-required accounts log in with phishing-resistant methods only (T-AU-ROLES)**

- Tests: `i77_m_auth`; `i77_management_login_requires_phishing_resistant_method_over_http` (machine with grants, ends, scheduled ends, suspensions, logins and magic links); `i77_scheduled_end_ends_sessions_at_its_instant` (no command at the instant); `i77_role_grant_ends_weak_sessions_in_the_same_batch` (PostgreSQL); Playwright `i77-management-login.spec.ts`; `i77_teeth_weak_session_admitted_is_caught`.

**I-78 No high-risk action without a fresh phishing-resistant step-up (T-AU-STEPUP)**

- Tests:
  - `i78_high_risk_table_matches_spec_and_domain`.
  - `i78_every_high_risk_route_and_command_needs_a_fresh_step_up`: generated from the route table and `HIGH_RISK_TABLE`. For each action: none, P-71 plus 1 µs old, another command's digest, consumed, another session's, a passkey without UV, from a magic-link session. Each fails. A fresh valid one passes the gate.
  - `i78_route_without_risk_class_does_not_compile`, `i78_stepup_proof_cannot_be_built_outside_the_gate`: compile-fail twin pairs.
  - `i78_stepup_logged_with_action_digest`, `i78_p71_may_only_shorten`, `i78_m_stepup`.
  - `i78_database_refuses_a_second_step_up_consumption` (the `auth_log` primary key), and `i78_writer_role_holds_insert_and_select_only`.
  - `sod_07_self_grant_needs_second_admin_approval_of_the_same_digest` (section 5.1).
  - Playwright `r_lg_03_committee_grant_and_add_passkey_need_stepup.spec.ts` (the R-LG-03 AC).
  - `i78_teeth_stale_step_up_accepted_is_caught`.

**I-79 Non-Receiving accounts are never recovered by email alone (T-AU-RECOVERY)**

- Tests: `i79_m_recover`; `i79_non_receiving_never_recovered_by_email_alone` (HTTP machine, including the grant race); `i79_approver_differs_steps_up_and_is_not_the_same_identity`; `i79_sole_admin_needs_operator_ticket_shown_to_tenant`; `i79_teeth_path_checked_at_request_only_is_caught`.

**I-80 No root key in plaintext outside its custody backend**

- Tests:
  - `i80_custody_has_no_export_and_root_material_cannot_escape`: compile-fail twins for clone, debug output, serialisation and access from outside `fstp-keyd`.
  - `i80_root_canary_absent_from_cell_and_vault_memory` (Linux, process mode): `/proc/<pid>/maps` and `/proc/<pid>/mem` of `fstp-cell` and `fstp-vault` after a cycle, an erasure and a rotation.
  - `i80_root_canary_absent_from_logs_dumps_and_backups`.
  - `i80_file_custody_root_confined_to_keyd`.
  - `i80_root_material_named_only_in_keyd` (source scan, layering rule 7).
  - `i80_teeth_leaking_custody_is_caught`.

**I-81 Destroying a key makes data unrecoverable, including from backups (T-ID-SHRED)**

- Tests:
  - `i81_m_shred`.
  - `i81_erased_text_unrecoverable_from_every_backup`: `pg_basebackup` copies and WAL archives through `fstp-backup` before and between erasures. Each is restored into a fresh server. Every wrapped key in every copy and the live store is tried against every live custody key. The erased text never opens; every live text still does.
  - `r_id_03_document_unrecoverable_after_verification`.
  - `r_sw_02_cell_erasure_kills_every_backup`.
  - `i81_completion_recorded_only_after_destroy_receipt`.
  - `i81_erasure_resumes_after_crash_at_every_step`.
  - `i81_text_salt_never_stored_in_clear` (salt canaries).
  - `i81_erased_email_digest_cannot_be_recomputed_from_backups`, `i81_erased_identity_match_key_cannot_be_recomputed_from_backups` (section 3.5).
  - `i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume`, and `i81_keyd_refuses_copy_on_write_key_volume` (section 3.3, Q32).
  - `i81_teeth_group_not_rotated_is_caught`, `i81_teeth_destroy_before_commit_loses_data_is_caught`.

**I-82 No database role reads across cell databases (T-DB-ISO)**

- Tests:
  - `t_db_iso_i82_every_role_refused_on_foreign_cell_database`: every login role of cells A, B and C on shared and dedicated servers, against every other database. Paths: connect; `dblink` and `postgres_fdw` absent and `CREATE EXTENSION` refused; `pg_read_file`; `COPY ... PROGRAM`; `lo_import`; other sessions' query text in `pg_stat_activity`.
  - `i82_privilege_graph_has_no_cross_cell_path` (through `fstp-pgagent`).
  - `i82_generated_hba_has_no_remote_superuser_and_no_all_line`.
  - `i82_replication_role_has_loopback_line_only_and_no_connect` (section 4.1). The privilege graph includes `fstp_repl` and `fstp_super`.
  - `i82_no_remote_role_has_createrole_or_createdb`.
  - `i82_names_reveal_nothing`, `i82_pool_serves_one_cell`.
  - `i82_teeth_seeded_connect_grant_is_caught`.

**I-83 Vault databases never share a cluster with application databases (T-DB-ISO)**

- Tests: `i83_placement_never_mixes_kinds` (property); `i83_m_place`; `i83_vault_refuses_an_application_cluster`, `i83_cell_refuses_a_vault_cluster` (kind marker, certificate OU and SPKI); `i83_cluster_kind_is_immutable`; `i83_self_hosted_layout_runs_two_instances`; `i83_teeth_first_free_cluster_is_caught`.

**Isolation exit item.** "Isolation tests green" means every `t_iso_*` (I-19, I-20, TH-06) and `t_db_iso_*` (I-82, I-83, TH-58) test, plus `i80_root_canary_*`, passes in the `isolation (multi-cell)` CI job.

**Hosting exit item.** ADR-005 names OVHcloud, decided by Daniel on 2026-10-28, and records the answers to Q3, Q4, Q11 and Q25.

### 14.5 Requirement and hardening tests that M3 also runs

- `r_cr_01_backups_and_snapshots_use_the_hybrid_kem` (T-CR-ATREST), `i75_mlkem_never_used_without_x25519` and `i75_mldsa_never_used_without_ed25519` (T-CR-HYBRID).
- `r_cr_03_anchors_carry_composite_signatures`, `i90_anchor_verifier_rejects_either_half_alone`.
- `r_nf_02_log_events_take_no_free_text` (type surface), `r_nf_05_first_start_has_no_default_credentials`, `r_nf_05_self_hosted_install_has_no_default_credentials`, `r_nf_08_catalogue_has_no_clear_content_column`, `r_nf_09_every_internal_link_is_mutually_authenticated` (captured handshakes; the external links of Q34 are listed as exceptions in the test, not passed silently).
- `r_nf_08_aborted_append_never_reuses_a_nonce`: every seal in a run with forced aborts, retries and replayed step-ups is captured, and no (key, nonce) pair repeats. `r_nf_08_no_api_takes_a_caller_nonce` (source scan). `r_nf_08_seal_count_limit_refuses_at_two_to_the_24`. Teeth: `r_nf_08_teeth_counter_nonce_is_caught`.
- `r_nf_03_*` and `r_nf_04_*` (section 11.2). `i74_*` (section 2.6). `th_32_t_update_*` (section 12).
- `r_lg_04_sessions_and_devices_listed_and_ended` (also Playwright).
- `sod_08_break_glass_needs_tenant_approval_and_logs_every_read` (T-BREAKGLASS).

### 14.6 M2 seams (acceptance, not exit criteria)

- `seam_driver_core_matches_reference_engine`.
- `adr007_pg_store_matches_mem_store`: same inputs, same results, same refusal order.
- `seam_async_engine_matches_reference_over_pg_and_real_vault`: M2 generators through `fstp_engine::Engine<MemStore, SyntheticVault>` and through `CellEngine` with `PgRecordStore` and `fstp-vault` seeded from the same ground truth. Ledgers equal record for record after decryption.
- `seam_pg_vault_matches_synthetic_vault`.
- `seam_m2_suites_over_pg`: reduced-case runs of the I-03, I-04, I-06, I-13 and I-14, I-15 and I-23 machines over the real stack. The I-03, I-04 and I-35 runs get their reviewer, partner and proximity facts through the section 6.8 write kinds, seeded by section 6.9.
- `seam_note2_every_vault_fault_fails_closed_and_appends_nothing`, `seam_note3_stale_epoch_processes_the_change_first`, `seam_note6_country_reaches_only_the_vault`.
- `adr007_erased_textref_resolves_to_its_log_entry`, `adr007_erasure_log_visible_to_auditor_and_tenant_admin_only`.

### 14.7 Playwright (ADR-003)

Only where the browser carries part of the guarantee: `i17-vault-origin-release`, `i20-passkey-not-offered-across-tenants`, `i77-management-login`, `r_lg_03_committee_grant_and_add_passkey_need_stepup`, `r-lg-04-sessions`, `r-nf-03-auth-and-vault-pages`. Each uses Chromium's virtual authenticator through CDP. The browser binary is pinned and fetched in a controlled CI step.

### 14.8 CI changes

- The test job starts several PostgreSQL 16 servers per isolation binary. Each database costs about 15 MB.
- A new job `isolation (multi-cell)` runs `t_iso_*`, `t_db_iso_*` and process-mode tests on Linux.
- A new job `e2e (Playwright)` with pinned Node, tsc and browser versions.
- Fuzz smoke grows by the 60 targets of section 15, at 60 seconds each, so it splits into parallel shards.
- `i80_root_canary_absent_from_cell_and_vault_memory` is Linux-only. A companion test on every platform asserts that `ci.yml` runs it (Q27).

---

## 15. Fuzz targets

Each parser-bearing crate joins `deps/fuzz-required.txt` and owns `crates/<crate>/fuzz/` from its first commit.

| Crate | Target | Checks |
| --- | --- | --- |
| `fstp-crypto` | `hybrid_ciphertext_decode`, `public_key_decode`, `composite_signature_decode` | No panic; exact lengths; one layout |
| `fstp-keys` | `sealed_key_decode`, `sealed_blob_decode`, `erasure_plan_sequence` | No panic; accepted input re-encodes byte for byte; a mutated byte never opens; random step sequences keep the M-SHRED predicates |
| `fstp-pki` | `cert_build_roundtrip` | Arbitrary names, serials and lifetimes build certificates that rustls-webpki parses with equal fields |
| `fstp-custody` | `okms_response_decode`, `keyd_frame_decode` | No panic; bounded allocation; unknown members refused; key bytes never in error displays |
| `fstp-keyd` | `keyd_request_decode`, `custody_file_decode` | No panic; limits enforced |
| `fstp-audit` | `chain_row_decode`, `anchor_decode`, `receipt_decode`, `verify_mutations` | No panic; the verifier never accepts a mutated chain |
| `fstp-pgstore` | `stored_entry_decode` | Decrypt and decode never panic on arbitrary rows |
| `fstp-vault-proto` | `vault_request_decode`, `vault_response_decode`, `ticket_decode` | No panic; round trip; exact amount strings; one-bit answers carry no account set |
| `fstp-vault` | `origin_write_decode`, `fact_body_decode` | No panic; signature checked before any field is used |
| `fstp-webauthn` | `cbor_decode`, `cose_key_decode`, `authenticator_data_decode`, `client_data_decode`, `attestation_object_decode`, `assertion_verify`, `registration_verify` | No panic; depth and size limits; non-shortest forms and duplicate keys refused; a mutation of a signed byte never verifies |
| `fstp-auth` | `auth_record_decode`, `auth_command_decode`, `session_cookie_decode`, `token_decode` | No panic; round trip; constant-length tokens only |
| `fstp-cell-core` | `cell_record_decode`, `cell_command_decode`, `cell_decide_sequence`, `driver_core_sequence` | Every schema version round-trips; `decide`, `apply` and `replay` never panic; replay equals incremental state; random needs and events never panic |
| `fstp-cell` | `command_request_decode` | No panic; size limits; a `minor` field is refused |
| `fstp-cp-proto` | `cell_to_cp_decode`, `cp_to_cell_decode` | No panic; round trip; only declared field classes decode |
| `fstp-control` | `cp_api_decode`, `pgagent_job_decode`, `ddl_identifier_render`, `install_config_decode` | No panic; identifiers outside the grammar refused; rendered DDL never contains input outside it |
| `fstp-witness` | `witness_message_decode` (prepare, abort, in-doubt), `file_store_decode` | No panic; round trip; truncated files detected; an abort for an unknown prepare refused |
| `fstp-edge` | `client_hello_sni`, `tunnel_header_decode` | No panic; on valid hellos the SNI equals what an `fstp-tls` server reports; the tunnel header round-trips and has one spelling. The decoder lives here and `fstp-cell` calls it |
| `fstp-release` | `licence_token_decode`, `licence_file_import_decode`, `key_transition_decode`, `release_metadata_decode`, `egress_response_decode` | No panic; signature checked before use |
| `fstp-release-svc` | `refresh_request_decode`, `update_query_decode` | Only the permitted grammar |
| `fstp-backup` | `backup_container_decode`, `s3_xml_decode`, `wal_name_parse` | No panic; chunk order and final flag enforced; DTDs, entities and processing instructions refused |
| `fstp-celltest` | `proc_maps_decode` | No panic. Test-only parser |
| `tools/deps-check` | `npm_lock_decode`, `tier_b_confirmations_decode` | No panic. The parsers of the npm lockfile gate and the Tier B release gate |

---

## 16. Risks

1. **R1 Unverified provider facts.** OKMS rate limits, quotas, usage logs, mutual TLS on REST, and whether deleted key material survives in provider backups. Mitigation: the verify list of section 1.6 is W0 work. `SimCustody` lets every lane proceed. M-SHRED models destruction as an event, so the I-81 claim moves with the provider fact.
2. **R2 Operating PostgreSQL ourselves.** Patroni is Python, which the project excludes. Mitigation: a synchronous replica with manual promotion in M3, monthly restore drills, and recovery objectives recorded in ADR-005.
3. **R3 Scope.** 22 new crates and up to seven changed. Mitigation: verification lanes start first, pure cores before shells, disjoint lane files, and OPAQUE, EUDI, ACME, installation and billing out of scope.
4. **R4 Erasure and open costs.** Per-batch custody calls and local re-seals; one hybrid decapsulation per text open. Mitigation: measure in W2, record budgets in the exit audit, and coalesce requests that arrive during a running batch.
5. **R5 moduletto availability.** It is a git dependency from `https://github.com/crabnebula-dev/moduletto` (Q1). It has ML-KEM-768 but no ML-DSA-65, which a moduletto pull request adds. Production key wrapping waits on the pin, and production anchors wait on that pull request. Mitigation: every crate above `fstp-crypto` builds against the `hybrid_kem` and `composite` interfaces, with test-only oracles from aws-lc-rs. No classical fallback ships.
6. **R6 In-house WebAuthn.** CBOR and COSE near authentication. Mitigation: a strict subset, fuzz targets from the first commit, attestation `none`, H-21.
7. **R7 Memory scans.** Linux-only, and they can miss copies the allocator moved. They catch presence, never prove absence. Structural guards carry I-80.
8. **R8 Witness coupling.** Prepare, receipt, commit ties every write to witness availability and adds one round trip per append under the cell's lock. Mitigation: a replicated witness in the same region, retries, batching of audit events, a refusal that names the witness, and a latency budget measured in W2 and recorded in the exit audit.
9. **R9 In-doubt commits.** After a lost COMMIT outcome, a missing row is reported as `PossibleDeletion`, never resolved silently. Frequent reports would train people to ignore them. Mitigation: alerts count in-doubt events per cell, and each one needs a tenant admin acknowledgement in the audit view (Q8).
10. **R10 CI time.** Multi-cluster worlds, process mode and 60 new fuzz targets. Mitigation: a separate isolation job, fuzz shards, one world per binary, timings in the exit audit.
11. **R11 State-space growth.** M-VCP couples three cores with crashes and a lossy network. Mitigation: one provisional epoch, tiny universes, tripwires, and splitting by fault class before any bound is relaxed.
12. **R12 Passkeys and custom domains.** Passkeys bind to the RP id, so moving a tenant to a custom domain in M9 strands them. Mitigation: ADR-008 records the RP id choice and a re-enrolment path.
13. **R13 Vault origin surface.** The vault becomes reachable from browsers through the edge. Mitigation: three routes, no sessions, signed single-use tickets checked first, fuzzed decoders, H-07.
14. **R14 Clock steps.** The ledger is time-monotone. Mitigation: NTP on every host and an alert on `TimeBackwards` refusals.
15. **R15 Encrypted storage and operations.** Ad hoc SQL can no longer read content. Mitigation: typed metrics and the audit view. Operators have no content access through the application, the databases or backups.
16. **R16 Root on cell hosts (SoD-08, TH-18).** A person with root on a cell or vault host can read unwrapped group keys from process memory, and so read content without break-glass. Sandboxing and swap-off do not stop root. Mitigation in M3: separate host-administration staff with no control-plane rights, no standing root (short-lived SSH certificates issued per case with two-person approval), session recording, and host access events shown to the tenant. Daniel accepted the residual risk on 2026-10-28 (Q35). Confidential computing, whose OVHcloud availability is not checked, is evaluated in L-15.
17. **R17 First admin interception.** A single invitation path would let one operator become tenant admin. Mitigation: split delivery (section 8.3). Residual: two colluding staff, until the M4 token sealed to a tenant-generated key (Q35).
18. **R18 File custody remnants.** Section 3.3 narrows but does not remove copies of the key table on SSD or in backups the install does not know about (Q32).

---

## 17. Readings

### 17.1 Resolved by the source-of-truth order

Order from `.claude/CLAUDE.md`: `SPEC/02-domain/invariants.md`, then `SPEC/01-requirements/`, then `SPEC/02-domain/`, then `SPEC/03-architecture/`. ADRs are architecture decisions and rank with `SPEC/03-architecture/` here.

1. **R-NF-08 over ADR-007's plaintext bodies and `numeric` projections.** The requirement asks for all data at rest encrypted with cell-specific keys. Shared clusters make disk encryption not cell-specific. Bodies are sealed, and the chain hashes the stored ciphertext, which keeps ADR-007's "stored bytes are the bytes that are hashed" (Q5).
2. **R-ID-03 and R-SW-02 ACs over ADR-004's static hierarchy.** "No backup or replica can reproduce the document" needs the wrapping chain to die. Hence root-epoch rotation (Q6).
3. **ADR-007 "an erasure request is honoured at once".** No periodic ratchet. Batches run as requests arrive.
4. **R-CR-03 over the M9 schedule.** The requirement and ADR-001 both make anchors composite-signed. Anchors are signed in M3 (Q8). Production signing waits on the moduletto ML-DSA-65 pull request (Q1, section 21.0).
5. **ADR-001 and ADR-004 "binding the ML-KEM ciphertext".** The combiner takes it as an input (Q2).
6. **I-82 "no database role" over ADR-005's shared default.** No role that can read across cells has a remote login (Q4).
7. **`overview.md` "answers the application only through the queries" and NOTE 6 "only the vault receives it".** Attributes and the country go browser to vault directly (Q7).
8. **R-NF-09 "all network traffic between components ... mutually authenticated".** Edge to cell is an mTLS tunnel. The KMS link follows Q11.
9. **`authentication.md` "Magic-link sessions ... cannot perform any high-risk action".** No high-risk action from such a session, even after a step-up. A first passkey comes only from a ceremony (Q15).
10. **I-18 and R-NG-02 with R-NG-01.** Guardian identity is collected at the gate, in the vault only. `TODO(legal)`: L-02 (Q12).
11. **I-38 over a convenient platform witness.** Self-hosted anchors never go to CrabNebula (Q9).
12. **R-AU-01 "read of ... identity attributes is logged".** Ticket issuance is a ledger record, and the vault logs the release in its own chain.
13. **I-39 test-plan row over M3 scope.** The cycle runs as far as M3 builds it. M5 and M9 rerun it (G18).
14. **The decided query set.** No query is added. `IsMinorAtDeadline` is Q13.
15. **I-24 "any ... deletion" over the cost of a round trip.** No bounded window is accepted without Daniel. Prepare, receipt, commit is built (Q8).
16. **R-ID-04 "derived flag" over M2's actor-supplied flag.** I-18 binds flagged proposals, and a flag the applicant can clear makes the guard empty. The route sets the flag on every draft (Q13).
17. **ADR-007 "holds INSERT and SELECT only" over the first version's UPDATE grants.** Side effects are insert-only rows.
18. **I-81 "including from backups" over long-lived HMAC keys and a rewritten key file.** Keyed digests rotate, and file custody uses per-epoch keys (Q32).
19. **I-82 over the replication role.** REPLICATION logs in over loopback only (Q4).
20. **SoD-08 over operator delivery of the first invitation.** Split delivery (Q35, answered 2026-10-28).
21. **ADR-005 "Moving a cell between shared and dedicated mode uses the tenant export and import path".** M-PLACE models no move.

### 17.2 Interim strict readings

| Topic | Interim reading built | Question |
| --- | --- | --- |
| moduletto | Production code waits on the pin. Composite signing refuses with a typed error until the ML-DSA-65 pull request lands. Tests use aws-lc-rs oracles through `fstp-celltest` only | Q1 (answered; pull request pending) |
| Combiner | HKDF-SHA-256 combiner of section 3.2 | Q2 |
| PostgreSQL | Self-operated PostgreSQL 16 on OVHcloud hosts | Q3 |
| Superuser and replication | Loopback `hostssl` with a client certificate, used only by `fstp-pgagent` and `fstp-backup`. No streaming replica; standby from sealed WAL archives | Q4 |
| Ledger at rest | Sealed bodies, chain over ciphertext, no plaintext projection tables | Q5 |
| Erasure | Root-epoch rotation per batch, completion after the destroy receipt | Q6 |
| Attributes | Vault origin with tickets | Q7 |
| Anchors | Composite-signed; prepare, receipt, commit with abort and in-doubt records; no unwitnessed commit; the ML-DSA half waits on the moduletto pull request | Q8 (confirmed) |
| Self-hosted witness | Mandatory local witness at first start | Q9 |
| Login methods | Passkeys and magic links only | Q10 |
| OKMS authentication | Access certificate over mutual TLS if REST accepts it; otherwise the lane waits | Q11 |
| Guardian | Collected at the IRC_REVIEW to NEGOTIATION gate, vault only | Q12 |
| Minor flag | Set on every draft by the route layer; never read from the request | Q13 |
| Manual identity check | The tenant admin records. The platform operator verifies the first tenant admin with two staff. Release window as ADR-008 sets it. Tests seed facts through `fstp-celltest` only | Q14 (answered) |
| First passkey, step-up, recovery | Three ceremonies; one step-up per command; recovery revokes everything; approval is high-risk; UV for management | Q15 |
| Sessions on binding end | Every session of the account ends | Q16 |
| Identity match | Keyed hash over the method's attribute tuple, per cell | Q17 |
| Licence expiry | Blocks nothing | Q18 |
| IP addresses | Memory only, rate limits only | Q19 |
| Billing | Metering and an opaque org reference | Q20 |
| Break-glass | Approval, gate path and logging built; content views in M4 | Q21 |
| Login email | Sealed in the cell, keyed lookup, treated as identity-revealing for I-17 canaries | Q22 |
| Holdings | Active, scheduled and suspended bindings plus tenant admin count; voided do not | none |
| File custody | Per-epoch keys on a non-copy-on-write key volume; passphrase from a systemd credential or the console; I-81 claim scoped | Q32 |
| Exit scope | Partial claims stated per invariant and requirement, as in section 20 | Q33 |
| R-NF-09 external links | Claimed for internal links only; request-level credentials on external ones | Q34 |
| Insider paths | Split first-admin delivery now, tenant-sealed token in M4; no standing root; R16 accepted | Q35 (answered) |
| I-19 metadata | Only the metadata register crosses | Q36 |
| New constants and proposed parameters | Ticket 5 minutes, invitation 72 hours, break-glass at most 4 hours as ADR constants; P-71 and P-72 as proposed | Q37 |
| High-risk additions | `Assign`, `Unassign`, `SetLoginPolicy`, `ApproveSelfGrant`, `ApproveRecovery` | Q38 |
| Node.js and npm | Not used until ADR-003 is amended | Q39 |
| SoD-07 approval | Digest-bound, single-use, expires after P-71 | Q40 |
| First licence token | Imported from a file; the cell sends no registration data | Q41 |
| Programme-side facts | Section 6.8 writers | Q31 |
| Erasure log for Auditors | Programme-scoped | Q42 |
| Keyed digests | Lookup, CredLookup and Match keys rotate with erasure | Q6 |
| Clear columns | Sealed where not needed for lookup; keyed digests for lookups | Q5 |
| Relatives in reviewer-side facts | A kind 8 relationship fact names relatives by vault identity id (lane W2d). No reviewer knows those ids, so the relatives part of I-03 cannot fire from the origin yet. Once the attribute set is settled, the body takes attribute tuples resolved through the match key, never ids from the request | Q31, `TODO(legal)` of section 6.8 |

### 17.3 Corrections to the proposals

| Proposal text | Correct reading | Source |
| --- | --- | --- |
| Base: `combine(ss_m, ss_x, ct_x, pk_x)` claims to bind the ML-KEM ciphertext | The combiner takes `ct_m` as a parameter | ADR-001 Uses, ADR-004 Hybrid combiner |
| Base: daily ratchet re-seals every live key; erasure up to 24 hours late | Root-epoch rotation per batch, immediate | ADR-007 Retention and erasure |
| Base and vertical slice: the vault returns attributes to the cell | Attributes go to the browser on the vault origin; raised as Q7 | `overview.md` Identity vault, NOTE 6 |
| Base: refactor `fstp-engine/src/driver.rs` | `DriverCore` in `fstp-cell-core`; `Engine` unchanged as reference | M2 exit audit |
| Base and verification-first: unsigned anchors until M9 | Composite anchors in M3 | ADR-001 Post-quantum signatures, R-CR-03 |
| Base: G13 says `zeroize` needs `unsafe` | It does not. It still needs an ADR-001 root line before direct use | ADR-001 Record, `deps/adr-roots.txt` |
| Base: every text open is a call to `fstp-keyd` | Group secrets in process; local open | Feasibility finding |
| Vertical slice: `fstp_provisioner` with CREATEDB and CREATEROLE and a network login | No remote role with either attribute | I-82; PostgreSQL 16 CREATEROLE semantics |
| Vertical slice: erasure by row deletion and backup-generation rotation | Kill the wrapping chain | I-81, R-KY-02 |
| Vertical slice: `LICENCE_GATED` while claiming the strictest option | Nothing gated in M3 | I-39, `self-hosted-services.md` |
| Vertical slice: "dev-classical" envelope | No classical fallback | I-75 |
| Vertical slice: `fstp-vault-core` depends on `fstp-domain` | Own newtypes; layering rule 2 | Vault narrowness |
| Vertical slice: one intermediate CA per region | One CA per cell | I-19, TH-06 |
| Vertical slice: first passkey from a magic-link session is setup | Only in ceremonies | `authentication.md` Strong methods |
| Vertical slice: break-glass and billing deferred | Break-glass built; metering kept | `authentication.md` high-risk table, `overview.md` Control plane |
| Verification-first: plaintext `ledger.entries.body` and `projection.money_committed` | Sealed bodies, no plaintext projections | R-NF-08 |
| Verification-first: plain TCP splice from edge to cell | mTLS tunnel | R-NF-09 |
| Verification-first: hourly `pg_hba_file_rules` read without superuser | Read through `fstp-pgagent` | PostgreSQL 16 |
| Verification-first: email moved into the vault | Email stays sealed in the cell; Q22 | `notifications.md` Email |
| Verification-first: `SoftCustody` as a feature of the shipped crate | In `fstp-celltest` only | Layering rule 9 |
| Verification-first: exact X-Wing satisfies ADR-001 | It omits the ML-KEM ciphertext, as reviewed; confirm against the pinned draft | ADR-001, ADR-004 |
| Verification-first: no tokio feature change | `signal` needed for SIGTERM | ADR-002 Needs |
| This design, first version: ML-DSA "only in the `unstable` module" of aws-lc-rs 1.18.2 | `signature::ML_DSA_65`, `ML_DSA_65_SIGNING` and `PqdsaKeyPair::from_seed` are stable; no feature change | aws-lc-rs source `src/signature.rs:1172`, `:1185`, `src/pqdsa/key_pair.rs:175` |
| This design, first version: `rustls-pki-types` for PEM writing | It only decodes PEM; the writer is in-house | `rustls-pki-types` 1.15.1 `src/pem.rs` |
| This design, first version: `fstp_ledger::FromStored` | No such trait; only `Canonical` exists. `PgRecordStore` takes a decode function | `crates/fstp-ledger/src/verify.rs` |
| This design, first version: ledger nonce `seq` | Random nonces through `RandomizedNonceKey` | Section 3.2 |
| This design, first version: writer UPDATE on `auth.session` and `auth.challenge` | Insert-only `auth_log` rows | ADR-007 Storage |

### 17.4 Review findings narrowed or answered differently

Every one of the 30 review findings was accepted in substance. These were closed in a different way from the one the review proposed, or narrowed:

- **Finding 1 (nonce reuse).** The review offered random nonces, AES-256-GCM-SIV or a key per transaction. Random nonces through aws-lc-rs `RandomizedNonceKey` were chosen, since they change no format beyond a stored nonce and keep one AEAD everywhere. GCM-SIV stays the fallback if H-19 asks for it.
- **Finding 5 (I-24 window).** The review asked Daniel to decide whether any window is acceptable. That question is asked (Q8), but the strict option is built as the interim rather than the bounded window.
- **Finding 6 (vault anchoring).** Closed by giving the vault its own anchorer and witness connection. The first version's `CellToCp::Anchor` route was also removed, because anchors through the control plane were never needed.
- **Finding 13 (c) (`FromStored`).** No new trait is added to `fstp-ledger`. A decode function value avoids an M2 crate change.
- **Finding 13 (b) (PEM).** No shared base64 crate is extracted from `fstp-pgwire`. An encoder-only base64 in `fstp-pki` keeps it a pure crate that parses nothing, and a test in `fstp-celltest` checks it against the `fstp-pgwire` decoder.
- **Finding 26 (array parser).** No array parser is written. The auditor expands arrays on the server with `aclexplode()` and `unnest()`, so no new parser exists to fuzz. A source scan keeps it that way.
- **Finding 22 (scheduled ends).** The gate refuses affected sessions from the end instant. The record follows from a background task. The guarantee therefore does not depend on that task running on time.
- **Finding 29 (OVHcloud facts).** Checked by web search on 2026-10-28. The results are summaries, not documents, so they appear as leads in section 1.6, and R-HS-01 is not claimed until L-15 confirms them.
- **Finding 16 (R-NF-09).** No link was changed to mutual TLS, because the providers offer none as far as the pages read show. The claim is narrowed and raised (Q34).

---

## 18. ADRs needed before implementation

`.claude/CLAUDE.md`: "Decisions marked ADR-required get an ADR in `docs/adr/` before implementation." The first version kept the ADRs as drafts while lanes implemented the interim readings. This revision orders them:

- W0 drafts every ADR below, with the interim reading of section 17.2 written in as the proposed decision.
- **No production lane starts before Daniel accepts its ADR**, interim readings included. Verification lanes may write tests and references against a draft, since tests come first and constrain nothing until code exists.
- When a later answer changes an accepted interim reading, the ADR is amended first, then the code.
- Daniel accepted every ADR below on 2026-10-28. Readings marked interim inside them stay interim unless section 21.0 settles them.

| ADR | Content | Accepted before |
| --- | --- | --- |
| ADR-001 amendment | `zeroize` as a root with features `alloc` and `default` (Q23). moduletto repository, exact commit, version, features and tree, and the ML-DSA-65 pull request (Q1). Close the "Open points" line on authentication crates: in-house WebAuthn, with the CBOR and COSE fuzz targets that `authentication.md` asks for (Q10). The Tier B confirmation mirror (section 2.6). No aws-lc-rs feature change | W1h production agent starts; moduletto edges before W1h merges |
| ADR-002 review note | tokio `signal` feature and `signal-hook-registry` with its resolved version and tree | W2l starts |
| ADR-003 amendment | Node.js and npm as the host of tsc and Playwright (Q39). Then first-use records with versions and trees | W3c starts |
| ADR-004 completion, part 1 | Combiner bytes and test vectors, "fixed here before implementation" (ADR-004). Nonce rule and seal-count limit | W1h production agent starts |
| ADR-004 completion, part 2 | Chains, epochs, epoch seal keys, groups. The erasure construction, keyed-digest rotation and restore rule. Custody backends (OKMS, file custody per Q32, simulator). CA keys in custody. Signing key placement (section 3.9). Reconciliation | W2f starts. ADR-004's status line also says the combiner and custody providers "are fixed before M3 closes", which is an exit row in section 20 |
| ADR-005 amendment | OVHcloud named (2026-10-28). Self-operated PostgreSQL 16 (Q3). Cluster kinds and layout. Superuser and replication handling (Q4). Role certificate issuance and rotation. Backup providers and retention (Q25). Recovery point objective. D3 status | W2h starts |
| ADR-007 amendment | Sealed bodies with random nonces, chain over stored bytes, the database link trigger, insert-only side-effect rows, projections in memory with sealed checkpoints, the cell envelope members, `completed_at` and the authoriser on erasure entries | W2e starts |
| ADR-008 (new) | Authentication implementation: in-house WebAuthn subset, methods in M3, ceremonies, split first-admin delivery, step-up binding, SoD-07 approval, recovery paths, break-glass, RP id choice, interim constants (Q37) | W2b starts |
| ADR-009 (new) | Cell boundary: trust domains, CAs, edge tunnel, `Destination` and `VaultDestination`, the vault origin, tickets and write kinds, the metadata register (Q36), R-NF-09 reading (Q34) | W2d and W2i start |
| ADR-010 (new) | Audit chain format, prepare, receipt and commit, abort and in-doubt records, composite anchors encoding transcribed from draft version 19, witnesses | W2g starts |
| ADR-011 (new) | Provisioning: `fstp-pgagent`, the DDL identifier grammar, `apply_grant`, two-operator approval, the self-hosted install | W2h starts |
| ADR-012 (new) | Backups: container format, multipart S3 subset, keystore snapshots, restore rule, WAL-archive standby, second provider | W2k starts |

---

## 19. Work plan

Tests come first in every step. They compile against stubs that refuse with `NotImplemented`, so each step starts red without `todo!` or panics. Verification lanes (W1, prefix R-) write references, predicates, models and tests. Production lanes write the code those tests constrain. A different agent writes each side. No two agents own the same file at the same time. W0 creates every crate skeleton and module stub, then hands each crate to its lane.

| Step | Lane (agents) | Owns | Tests first | Depends on |
| --- | --- | --- | --- | --- |
| W0 | lead (1), then the standing dependency owner | `Cargo.toml`, every third-party line of every crate manifest, `deps/*` (including `adr-roots.txt` and `tier-b-confirmations.txt`); `docs/adr/*` drafts (section 18), `crates/<new>/Cargo.toml` and stub `src/lib.rs`, `crates/<new>/fuzz/**` skeletons; every stub file under `crates/fstp-celltest/src/` (including `reference/hybrid.rs`), `tools/deps-check/src/{layering_m3,funds,runtime,npm,tier_b}.rs` and their registration; `crates/fstp-celltest/src/mc/tripwires.rs`, spec wording proposals (Q28), the OVHcloud verify list, the M2 base commit record (section 0.5) | Layering, funds, runtime and Tier B rules with failing fixtures; every fuzz target builds; `HIGH_RISK_TABLE`, `STRICT_ADDITIONS`, the column map, the metadata register and the field-class allowlist reviewed row by row against the spec at the M2 base commit | M2 close commit. Each production lane waits for Daniel to accept its ADR (section 18). Lanes request dependency changes from the lead, who lands them with the ADR record |
| W1a | H, harness (1) | `crates/fstp-celltest/src/{lib,world,canary,scan,egress,soft_authn,custody_sim,procmem,vault_seed}.rs`, `src/bin/{fstp-custody-sim,fstp-vault-seeded}.rs`, `crates/fstp-pgtest/src/{lib,server,named,certs}.rs`. Not the `reference/*` or `mc/*` stubs, which W0 creates and each W1 lane then owns | Scanner finds seeded canaries in every encoding; worlds start; role certificates accepted by PostgreSQL; `proc_maps` fuzz target | W0, W1i API stub |
| W1b | R-AUTH (1) | `fstp-celltest` `src/reference/auth.rs`, `src/mc/{auth,stepup,recover}_model.rs`, `tests/i77_*`, `tests/i78_*`, `tests/i79_*`, `tests/r_lg_04_*` | Section 14.4 for I-77 to I-79 against stubs | W1a |
| W1c | R-VAULT (1) | `src/reference/vault.rs`, `src/mc/{vcp,driver}_model.rs`, `tests/seam_*`, `tests/adr007_*`, `tests/i17_*`, `tests/i18_*`, `tests/th_04_*`, `tests/th_27_*`, `tests/fstp_vault_*` | Sections 14.4 (I-17, I-18) and 14.6 | W1a |
| W1d | R-KEYS (1) | `src/reference/keys.rs`, `src/mc/shred_model.rs`, `tests/i80_*`, `tests/i81_*`, `tests/r_id_03_*`, `tests/r_sw_02_*`, `tests/r_cr_01_*`, `tests/i75_*` | Section 14.4 for I-80, I-81; section 14.5 | W1a |
| W1e | R-AUDIT (1) | `src/reference/audit.rs`, `src/mc/audit_model.rs`, `tests/i24_*`, `tests/r_cr_03_*`, `tests/i90_*` | Section 14.4 for I-24 | W1a |
| W1f | R-ISO (1) | `src/mc/place_model.rs`, `tests/t_iso_*`, `tests/t_db_iso_*`, `tests/i19_*`, `tests/i20_*`, `tests/i82_*`, `tests/i83_*`, `tests/i16_*`, `tests/r_nf_*`, `tests/sod_08_*`, `tests/sod_07_*` | Section 14.4 for I-16, I-19, I-20, I-82, I-83 | W1a |
| W1g | R-REL (1) | `src/reference/licence.rs`, `src/mc/licence_model.rs`, `tests/i38_*`, `tests/i39_*`, `tests/th_32_*` | Section 14.4 for I-38, I-39 | W1a |
| W1h | L-CRYPTO (2) | Production agent: `crates/fstp-crypto/src/**`. Test agent: `crates/fstp-crypto/tests/**`, `crates/fstp-crypto/fuzz/**`, `fstp-celltest/src/reference/hybrid.rs` | KATs, ML-KEM and ML-DSA ACVP subsets, differential tests against aws-lc-rs, combiner vectors from an independent implementation, no-`Debug` and zeroize checks. ML-DSA-65 runs against moduletto only once its pull request lands | W0; ADR-001 amendment and ADR-004 part 1 accepted; Q1 (answered) and Q2 for the moduletto half; the moduletto ML-DSA-65 pull request for the `mldsa` and `composite` production code |
| W1i | L-PKI (2) | Production agent: `crates/fstp-pki/src/**`. Test agent: `crates/fstp-pki/tests/**`, `crates/fstp-pki/fuzz/**` | rustls-webpki round trips; PostgreSQL accepts issued certificates; proof of possession refused when forged | W0 |
| W2a | L-WEBAUTHN (1) | `crates/fstp-webauthn/**` | Fuzz targets in the first commit; `SoftAuthenticator` fault cases | W1a |
| W2b | L-AUTH (1) | `crates/fstp-auth/**` | W1b pure parts | W2a API stub |
| W2c | L-CORE (1) | `crates/fstp-cell-core/**`, `crates/fstp-ledger/src/{async_store,lib}.rs`, and `crates/fstp-domain/src/view.rs` if one is needed (section 0.5) | W1b gate parts, W1c driver parts, `seam_driver_core_matches_reference_engine` | W2b API stub |
| W2d | L-VAULT (1) | `crates/fstp-vault-proto/**`, `crates/fstp-vault-core/**`, `crates/fstp-vault/**` | W1c vault parts, M-VCP | W1h, W2f API stub |
| W2e | L-STORE (1) | `crates/fstp-pgstore/**`, `crates/fstp-migrate/src/catalogue.rs` | `adr007_pg_store_matches_mem_store`, I-24 database tests, catalogue tests | W2c (`AsyncRecordStore`), W2f, W2g |
| W2f | L-KEYS (1) | `crates/fstp-keys/**`, `crates/fstp-custody/**`, `crates/fstp-keyd/**` | W1d, M-SHRED | W1h |
| W2g | L-AUDIT (1) | `crates/fstp-audit/**`, `crates/fstp-witness/**` | W1e, M-AUDIT | W1h |
| W2h | L-CP (1) | `crates/fstp-cp-proto/**`, `crates/fstp-control/**`. The cell role plan and its grant rows have this one owner (section 4.1) | W1f placement, provisioning and auditor parts | W1i, W2f |
| W2i | L-EDGE (1) | `crates/fstp-edge/**` | `client_hello_sni` differential; tunnel header round trip | W1i |
| W2j | L-REL (1) | `crates/fstp-release/**`, `crates/fstp-release-svc/**` | W1g | W1h |
| W2k | L-BACKUP (1) | `crates/fstp-backup/**` | Container properties; the backup legs of `i81_*` | W2f |
| W2l | L-OBS (1) | `crates/fstp-obs/**`, `crates/fstp-rt/src/{signal,lib}.rs` | R-NF-02 type surface; SIGTERM drains through `Shutdown` | W0; ADR-002 review note accepted |
| W3a | L-CELL (2) | Agent one: `crates/fstp-cell/src/{routes,http}/**`. Agent two: `crates/fstp-cell/src/{engine,tasks,witness}/**`, `src/main.rs`. Shared `src/lib.rs` is created by W0 and changed only by agent two | HTTP machines of W1b, W1c and W1g; route-table sweep | W2c, W2d, W2e, W2g, W2j, W2l |
| W3b | L-SLICE (1) | `fstp-celltest` `src/bin/fstp-devstack.rs`, `tests/slice_*` | `slice_s1_passkey_login_create_programme_lands_in_ledger_and_chain` first, then the full call cycle through HTTP | W3a route stubs |
| W3c | L-WEB (2) | Agent one: `web/**` and its lockfile. Agent two: `e2e/**` and its lockfile | Playwright specs of section 14.7 | W3a route stubs; ADR-003 amendment accepted (Q39) |
| W4 | lead plus R-ISO | `.github/workflows/ci.yml`, `deploy/systemd/**`, `fstp-celltest` `tests/teeth_m3_registry.rs` (checks that every teeth test named in section 20 exists and fails its property), `src/mc/tripwires.rs` constants. Each teeth test itself lives in its W1 lane's file | Full isolation worlds in process mode; every teeth test fails its property; measured state counts recorded | W3 |
| W5 | independent reviewers, then fix lanes | Findings and reproducers only; fixes in the owning lane's files | Every finding of medium or higher severity has an executable reproducer, then a regression test that failed before the fix, then an adversarial pass (HANDOFF) | W4 |
| W6 | lead | `docs/handoff/m3-exit-audit.md`, final ADR records with exact versions and trees, milestone report, staged commits with proposed messages | All exit tests green in CI | W5 |

Where Daniel has not answered a question, the lane builds the interim reading of section 17.2, once the ADR that records it is accepted (section 18).

---

## 20. M3 exit checklist

Every test below is green in CI and each model run is exhaustive. Each teeth test fails its property as expected. "Blocked on" names only questions from section 21.1. "Shaped by" names section 21.2 questions whose answers change the test but not whether M3 can close. Every claim is made only as far as Daniel's scope decision (Q33) allows, and the exit report states that scope beside each row.

| Invariant | Property and integration tests | Models | Isolation and Playwright | Teeth | Blocked on | Shaped by |
| --- | --- | --- | --- | --- | --- | --- |
| I-16 | `i16_no_crate_builds_payment_instructions`, `i16_schemas_have_no_fund_class`, `i16_config_types_hold_no_debtor_account`, `i16_cell_egress_has_no_payment_destination` | none | none | `i16_teeth_seeded_instruction_crate_is_caught` | Q33 (structural claim; adapters are M5) | Q20 |
| I-17 | `i17_canary_attributes_never_reach_judging_responses`, `i17_app_database_holds_no_identity_attribute`, `i17_release_ticket_only_for_operations_in_negotiation`, `i17_vault_refuses_release_without_negotiation_fact`, `i17_vault_refuses_forged_stale_replayed_or_foreign_tickets`, `i17_logs_and_metrics_hold_no_attribute` | none | Playwright `i17-vault-origin-release` | `i17_teeth_ticket_issued_in_ranked_is_caught`, `i17_teeth_attribute_logged_is_caught` | Q7 | Q22 |
| I-18 | `i18_minor_flag_blocks_negotiation_without_verified_consent`, `i18_no_minor_flagged_proposal_reaches_granted_without_consent`, `i18_route_never_takes_minor_flag_from_the_request`, `i18_consent_counts_only_after_guardian_verification_is_effective`, `fstp_vault_has_no_seed_path` | `i18_m_vcp` | none | `i18_teeth_provisional_consent_counted_is_caught` | Q12, Q13, Q14, Q33 (claimed over seeded facts until a verification method exists) | none |
| I-19 | `i19_control_plane_columns_are_declared`, `i19_cp_proto_fields_are_declared`, `i19_only_registered_metadata_crosses`, `i19_edge_forwards_bytes_after_client_hello_unchanged`, `i19_foreign_cell_certificates_are_refused`, `i19_session_of_one_cell_is_refused_by_another`, `i19_cell_process_serves_one_cell` | none | `t_iso_i19_no_canary_crosses_a_cell_boundary` | `i19_teeth_canary_in_heartbeat_is_caught`, `i19_teeth_seeded_leak_in_control_plane_is_caught` | Q36 | Q26 |
| I-20 | `i20_rp_id_is_the_exact_cell_host`, `i20_control_plane_crates_cannot_name_account_types`, `i20_control_plane_and_witness_hold_no_account_id`, `i20_vault_match_keys_differ_across_cells` | none | `t_iso_i20_no_shared_identifier_across_tenants`, Playwright `i20-passkey-not-offered-across-tenants` | `i20_teeth_shared_lookup_key_is_caught` | none | Q17, Q19 |
| I-24 | `i24_verifier_flags_every_mutation`, `i24_pg_chain_equals_reference_chain`, `i24_database_refuses_bad_link_and_mutation`, `i24_ledger_and_chain_commit_together`, `i24_no_commit_without_a_receipt_for_its_link`, `i24_abort_recorded_before_the_same_n_is_prepared_again`, `i24_in_doubt_missing_row_raises_possible_deletion`, `i24_tail_deletion_after_commit_is_detected`, `i24_vault_chain_anchored_by_the_vault_only`, `i24_erasure_entries_are_chained`, `i24_custody_ops_reconcile_with_key_records`, `r_nf_08_aborted_append_never_reuses_a_nonce` | `i24_m_audit` | none | `i24_teeth_verifier_without_receipt_check_is_caught`, `i24_teeth_link_omitting_a_field_is_caught`, `r_nf_08_teeth_counter_nonce_is_caught` | Q1 (the moduletto ML-DSA-65 pull request), Q5, Q8, Q9 | none |
| I-38 | `i38_update_check_bytes_match_the_template`, `i38_licence_refresh_bytes_match_the_template`, `i38_only_egress_reaches_crabnebula_hosts`, `i38_self_hosted_refuses_intermediary_mode`, `i38_self_hosted_witness_never_targets_crabnebula` | none | `i38_self_hosted_cell_sends_no_canary_to_crabnebula_hosts` | `i38_teeth_extra_header_is_caught` | none | Q19, Q41 |
| I-39 | `i39_licence_states_never_block_protected_commands`, `i39_no_command_path_reaches_release_crate`, `i39_licence_key_transition_accepted_only_when_signed_by_a_pinned_key`, `i39_rotation_never_blocks_protected_commands` | `i39_m_licence` | `i39_cycle_completes_with_services_down` | `i39_teeth_gate_on_release_payment_is_caught` | Q33 (cycle as far as built; payment M5, export M9) | Q18 |
| I-77 | `i77_management_login_requires_phishing_resistant_method_over_http`, `i77_role_grant_ends_weak_sessions_in_the_same_batch`, `i77_scheduled_end_ends_sessions_at_its_instant` | `i77_m_auth` | Playwright `i77-management-login` | `i77_teeth_weak_session_admitted_is_caught` | Q10, Q15 | Q16 |
| I-78 | `i78_high_risk_table_matches_spec_and_domain`, `i78_every_high_risk_route_and_command_needs_a_fresh_step_up`, `i78_route_without_risk_class_does_not_compile`, `i78_stepup_proof_cannot_be_built_outside_the_gate`, `i78_stepup_logged_with_action_digest`, `i78_p71_may_only_shorten`, `i78_database_refuses_a_second_step_up_consumption`, `i78_writer_role_holds_insert_and_select_only` | `i78_m_stepup` | Playwright `r_lg_03_committee_grant_and_add_passkey_need_stepup` | `i78_teeth_stale_step_up_accepted_is_caught` | Q15 | Q37, Q38, Q40 |
| I-79 | `i79_non_receiving_never_recovered_by_email_alone`, `i79_approver_differs_steps_up_and_is_not_the_same_identity`, `i79_sole_admin_needs_operator_ticket_shown_to_tenant` | `i79_m_recover` | none | `i79_teeth_path_checked_at_request_only_is_caught` | Q15 | none |
| I-80 | `i80_custody_has_no_export_and_root_material_cannot_escape`, `i80_root_material_named_only_in_keyd` | none | `i80_root_canary_absent_from_cell_and_vault_memory`, `i80_root_canary_absent_from_logs_dumps_and_backups`, `i80_file_custody_root_confined_to_keyd` | `i80_teeth_leaking_custody_is_caught` | Q11, Q32 | Q27 |
| I-81 | `i81_erased_text_unrecoverable_from_every_backup`, `r_id_03_document_unrecoverable_after_verification`, `r_sw_02_cell_erasure_kills_every_backup`, `i81_completion_recorded_only_after_destroy_receipt`, `i81_erasure_resumes_after_crash_at_every_step`, `i81_text_salt_never_stored_in_clear`, `i81_erased_email_digest_cannot_be_recomputed_from_backups`, `i81_erased_identity_match_key_cannot_be_recomputed_from_backups`, `i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume`, `i81_keyd_refuses_copy_on_write_key_volume` | `i81_m_shred` | none | `i81_teeth_group_not_rotated_is_caught`, `i81_teeth_destroy_before_commit_loses_data_is_caught` | Q1, Q6, Q11, Q32 | none |
| I-82 | `i82_privilege_graph_has_no_cross_cell_path`, `i82_generated_hba_has_no_remote_superuser_and_no_all_line`, `i82_replication_role_has_loopback_line_only_and_no_connect`, `i82_no_remote_role_has_createrole_or_createdb`, `i82_names_reveal_nothing`, `i82_pool_serves_one_cell` | `i83_m_place` (I-82 plan property) | `t_db_iso_i82_every_role_refused_on_foreign_cell_database` | `i82_teeth_seeded_connect_grant_is_caught` | Q3, Q4 | none |
| I-83 | `i83_placement_never_mixes_kinds`, `i83_vault_refuses_an_application_cluster`, `i83_cell_refuses_a_vault_cluster`, `i83_cluster_kind_is_immutable`, `i83_self_hosted_layout_runs_two_instances` | `i83_m_place` | part of `t_db_iso_*` | `i83_teeth_first_free_cluster_is_caught` | Q3 | none |
| Isolation | every `t_iso_*`, `t_db_iso_*` and `i80_root_canary_*` | none | `isolation (multi-cell)` job | as above | as above | as above |
| ADR-005 | Provider named (OVHcloud, 2026-10-28); amendment accepted with the section 1.6 verify list resolved through L-15 | none | none | none | Q3, Q4, Q11, Q25 | none |
| ADR-004 | Combiner details and custody providers fixed, as its status line requires "before M3 closes" | none | none | none | Q1, Q2, Q11, Q32 | none |
| ADRs before code | Every ADR of section 18 accepted before its lane's first production commit. Daniel accepted all of them on 2026-10-28, and the exit audit lists that date | none | none | none | Q23, Q39 | none |
| Tier B gate | `i74_release_gate_refuses_unconfirmed_tier_b_version`, `i74_release_gate_refuses_a_confirmation_for_another_hash`, `i74_dev_build_reports_but_passes` | none | none | `i74_teeth_gate_skipping_tier_b_is_caught` | Q1 | none |
| M2 seams | `seam_driver_core_matches_reference_engine`, `adr007_pg_store_matches_mem_store`, `seam_async_engine_matches_reference_over_pg_and_real_vault`, `seam_pg_vault_matches_synthetic_vault`, `seam_m2_suites_over_pg`, `seam_note2_*`, `seam_note3_*`, `seam_note6_*`, `adr007_erased_textref_*` | `m_vcp`, `m_driver` | none | M-VCP and M-DRIVER teeth | Q5, Q7 | Q31 |

Requirements covered in M3, as far as Q33 scopes them:

- Authentication: R-LG-01 (passkeys and magic links), R-LG-02, R-LG-03, R-LG-04.
- Keys, hosting and cryptography: R-KY-01 (the EU-operated KMS option only; the CrabNebula HSM is not built), R-KY-02, R-HS-02, R-CR-01, R-CR-02 (the gate is built; no release is cut), R-CR-03 (anchors only). The ML-DSA-65 half of those anchors waits on the moduletto pull request, and until then the tests use the aws-lc-rs oracle. R-HS-01 is claimed only once L-15 confirms ownership, contracting entity and regions (section 1.6).
- Identity and negotiation: R-ID-02 and R-ID-03 (over seeded verifications until the ADR-008 release-window open point and the moduletto ML-DSA-65 pull request are settled), R-ID-04 (interim: every draft flagged, Q13), R-NG-01 (vault side), R-NG-02, R-CF-03 (vault answers).
- Audit and switching: R-AU-01 (security events and identity reads), R-SW-02.
- Non-functional: R-NF-01 (self-hosted layout and install), R-NF-02, R-NF-03 and R-NF-04 (for the M3 pages), R-NF-05, R-NF-08, R-NF-09 (internal links only, Q34).

---

## 21. Questions for Daniel

Each question gives options and a recommendation. Until you answer, M3 builds the interim reading in section 17.2, once its ADR is accepted (section 18). This revision moves Q12 to Q15, Q23 and Q25 into the blocking set, because section 20 depends on them, and adds Q31 to Q42.

### 21.0 Daniel's answers (2026-10-28)

Daniel answered the blocking set in the order it was presented. Later on 2026-10-28, after the ADR drafts were committed, he gave further answers, marked "later answer" below. These answers override the recommendations and the interim readings below wherever they differ.

| Question | Answer | Effect on this design |
| --- | --- | --- |
| Q1 moduletto source | C: a git dependency. Repository `https://github.com/crabnebula-dev/moduletto`, public, so CI fetches it without credentials (later answer) | Pinned to a full commit hash in `Cargo.lock`. W1h records the exact commit at first use. The main branch head on 2026-10-28 is `46754f2fccb0a501be278fb2fab63b670101a33d`, version 0.1.0. deps-check gains a git-source rule: the allowlist records the repository URL and commit, and any other git source fails. moduletto provides ML-KEM-512 and ML-KEM-768 (FIPS 203) with `keygen_derand` and `encaps_derand`, which answers the deterministic-keygen sub-question for ML-KEM. It has no ML-DSA-65. Daniel decided that ML-DSA-65 (FIPS 204) is added to moduletto, on a pull request that Claude writes and Daniel reviews and merges. Until it lands, the ML-DSA half sits behind the `fstp-crypto` seam and composite signing refuses with a typed error. aws-lc-rs ML-DSA stays a test oracle only and is never a production fallback. Tree: `subtle 2.6` always, `libm 0.2` through the `std` feature, and the allowlisted `zeroize`, with exact versions and checksums recorded at first use (ADR-001 A2) |
| Q2 combiner | A | As section 3.2 |
| Q3 PostgreSQL | C: managed for the control-plane databases only; self-operated for cell and vault clusters | Control-plane databases use OVHcloud Public Cloud Databases with SCRAM over server-authenticated TLS (`fstp-pgwire` supports SCRAM). The witness database stays self-operated, the stricter reading, since I-24 detection must not rest on the provider's superuser. ADR-005 records the provider's operator role on control-plane data, which holds only registered metadata (Q36) |
| Q4 superuser and replication | A with R1 | As recommended |
| Q5 ledger at rest | A | As recommended, with the listed clear classes accepted |
| Q6 erasure | A | Per-request root-epoch rotation, with keyed-digest key replacement |
| Q7 identity attributes | A | Vault origin with tickets |
| Q8 anchors and tail | Signatures A, tail D. Confirmed again (later answer) | Composite anchors in M3; prepare, witness receipt, commit. No bounded window. The ML-DSA half of every anchor waits on the moduletto pull request (Q1), so production anchoring and production writes wait on it too (ADR-010) |
| Q9 self-hosted witness | A | Mandatory local witness |
| Q10 authentication scope | A | In-house WebAuthn and magic links; OPAQUE later; EUDI login and verification in M4 |
| Q11 OKMS | A, otherwise B | Daniel asks OVHcloud the verify items |
| Q12 guardian consent | A | At the IRC_REVIEW to NEGOTIATION gate, vault only, R-NG-01 exception, `TODO(legal)` L-02 |
| Q13 minor flag | A | Over-18 attestation in the vault before NEGOTIATION, new one-bit query, M2 guard change. This also settles M4 Q23 |
| Q14 manual identity check | B now, A later. First tenant admin verified by the platform operator (later answer) | The tenant admin records manual checks in M3. A new Operations role "identity verifier" replaces it later. Guard: no recorder verifies their own account or an account that shares their identity. The platform operator verifies the first tenant admin of each tenant. Two operator staff take part, the verification is logged, and it is shown to the tenant. That admin then records the checks of others. This replaces the strict interim that refused every unverified recorder (ADR-008, `roles-and-sod.md`) |
| Q15 authentication details | Yes to all seven | As recommended |
| Q23 dependencies | Accept | As recommended |
| Q25 backup provider | Later | Decided with L-15 due diligence; the ADR-005 exit row stays blocked until then |
| Q32 file custody | A | As recommended |
| Q33 exit scope | A | A NOTE for M3 in `SPEC/09-milestones.md` |
| Q35 insider paths | Both recommendations (later answer) | First-admin invitation split across two staff and two channels now, then a token sealed to a tenant-generated key once M4 onboarding exists. Root on cell hosts: the residual risk is accepted under separate host staff, no standing root, two-person access and tenant-visible access events. Confidential computing is evaluated in L-15 |
| Q36 tenant data | A | Closed metadata register |
| Q39 Node.js and npm | A | ADR-003 amendment. This also settles M4 Q7 |
| ADR acceptance | All drafted M3 ADR sections accepted (later answer) | ADR-001, ADR-002, ADR-003, ADR-004, ADR-005 and ADR-007 amendments and ADR-008 to ADR-012 read "Accepted 2026-10-28 (Daniel Thompson-Yvetot)". Readings marked "interim, pending Daniel" inside them stay interim unless a row here settles them |
| I-80 epoch seal keys | Not root keys (later answer) | `S(e)` lives in process memory, is zeroised on drop and is covered by the memory scan. Only root epochs stay in custody (ADR-004 part 2) |
| I-82 reading | Q4 A as a scoped milestone NOTE (later answer) | I-82 covers every role that can log in from another host, applied to the self-operated clusters. The managed control-plane cluster holds no cell data. Recorded in `SPEC/09-milestones.md` NOTE 2. The invariant text is unchanged |

Daniel gave further answers on 2026-10-29:

| Question | Answer | Effect on this design |
| --- | --- | --- |
| ADR-010 composite encoding | Accepted as transcribed from draft 19, with its three platform rows | W2g may sign and verify anchors and receipts |
| Degenerate ML-DSA-65 keys | The check stays in `fstp-crypto`. The remaining gap is accepted | ADR-010 open point 1 closes |
| KeyOp record | Both: a sealed `KeyOp` chain event and a `RecordKeyOp` ledger record, with one request id | ADR-004 Reconciliation. W2f, W2g and W2c record both; the vault has the chain event only |
| GRANTED guard | Derives the minor flag again | `state-machine.md` NOTE 14. An M2 domain change |
| Which deadline | The call in which the proposal passes IRC review, so a re-entered proposal uses the later call | NOTE 14 and ADR-008. Replaces the interim submission-call reading |
| Under-18 verification after an attestation | Neither wins: a manual identity check (G9) resolves the conflict | The vault answers neither yes nor no until then, so the gate fails closed |
| Refused release presentation | Leaves the ticket unused | The W1c reading stands |
| WebAuthn attestation | Format `none` only for M3 | ADR-008 as written |
| ECH at the edge | Route on the outer SNI; GREASE and real ECH alike | ADR-009 and section 9.4. The edge test `b5_th26_sni_encrypted_client_hello_closes` is replaced by a routing test |
| Tunnel header host | Kept. Version 1, 274 bytes | ADR-009 records the layout. The receiver checks the host against its own SNI |
| Consent after the GRANTED re-check | Collection reopens in NEGOTIATION | `AddGuardian` and the guardian ticket are allowed in NEGOTIATION when the GRANTED check finds the lead not adult. NOTE 14 |
| Decline during an age conflict | Allowed when another decline ground holds | The decline treats the adult query as optional: an unanswered query removes only the ground that needs it. An engine change for that command |
| G14 functions | Revoke the `pg_stat_get_*` functions too | Section 4.1. W2h revokes them and W1f checks it |
| Rules version at GRANTED | A new rules version | Decisions under the new guard set carry it |
| Witness column classes (2026-10-30) | Add three public classes | Section 4.5 gains three closed classes: a public digest (link hashes), a signature (composite signatures) and public key material (pinned certificates and public keys). None holds personal data or content, and each is checked by type and length. The witness catalogue classes its columns with them, so the i19 and R-NF-08 catalogue tests can pass |
| Witness anchor key (2026-10-30) | Accept lane int5's key | Section 4.4 is amended: `witness.anchor` and `witness.withdrawal` are keyed on (cell_id, chain, witness_seq), with (cell_id, chain, n, link) unique. A cell may prepare n again with another link after its abort is recorded, and a withdrawn head is never receipted again. The three extra tables of ADR-010 open point 4 are accepted |
| vault.p17_condition grant (2026-10-30) | Rename the table | The table gets a letters-only name in the vault migrations and code, recorded in section 4.3. The `apply_grant` grammar of ADR-011 stays as accepted, and the vault role's SELECT and INSERT move into `cell_role_plan`. `P17_CONDITION_GRANT_SEAM` is then deleted |

### 21.1 These block the milestone

**Q1. moduletto for M3 (ADR-001 Tier B, I-74, I-75).** Key wrapping needs ML-KEM-768 now, and composite anchors need ML-DSA-65. moduletto is not in the local registry.

- A: A crates.io release, pinned with its checksum, so deps-check's existing allowlist flow applies.
- B: A vendored path in the repository.
- C: A git dependency.
- D: aws-lc-rs ML-KEM and ML-DSA as the post-quantum half until M9. This departs from ADR-001, which names moduletto.
- Also: does moduletto expose deterministic key generation and encapsulation for the ACVP and combiner vectors?
- Recommendation: A. Every lane above `fstp-crypto` proceeds against the interfaces meanwhile. No classical fallback ships.

**Q2. Hybrid combiner (ADR-001, ADR-004, H-19).**

- A: The HKDF-SHA-256 combiner of section 3.2, which hashes `ct_M` into the KDF info.
- B: X-Wing as pinned in one draft version, extended with `SHA3-256(ct_M)` in its hash input.
- C: Exact X-Wing. As reviewed, it omits the ML-KEM ciphertext, which ADR-001 and ADR-004 name.
- Recommendation: A. It meets the ADR wording literally and uses only HKDF and SHA-256 from aws-lc-rs. ADR-004 records the bytes and vectors before code.

**Q3. PostgreSQL on OVHcloud (ADR-005 D2 and D3, I-82, I-83).** The managed service documents no client certificate login, and reserves SUPERUSER for OVHcloud's operation.

- A: Self-operated PostgreSQL 16 on Public Cloud instances or Bare Metal in a vRack, with our `pg_hba.conf`, cluster CAs and superuser.
- B: Managed Public Cloud Databases, if OVHcloud confirms customer-CA client certificates and that its operator superuser cannot read customer databases. D2 and I-82 would still need a reading for the provider's role.
- C: Managed for the control-plane databases only, self-operated for cell and vault clusters.
- Recommendation: A. Self-operation also lets us adopt a PostgreSQL build that negotiates the hybrid group once one is verified (D3).

**Q4. The cluster superuser, the replication role and provisioning (I-82, G22).**

- A: The superuser logs in only from the database host, over loopback `hostssl` with a client certificate held by the `fstp-pgagent` OS user. No remote role has CREATEROLE or CREATEDB. Destructive jobs need two operators. I-82 is read as covering every role that can log in from another host.
- B: As A, with Unix-socket peer authentication instead of loopback TLS. `fstp-pgwire` would need a socket transport.
- C: The literal reading: no role at all can read across cells. PostgreSQL cannot meet it, so this means one cluster per cell and no shared mode.
- Replication, with A or B. R1: as built, REPLICATION only over loopback for `pg_basebackup`, and a standby fed from the sealed WAL archive, with a recovery point of about one minute. R2: a streaming replica whose REPLICATION role logs in only from the replica host, treated like the superuser as cluster machinery. Its stream carries every cell's pages, with bodies sealed but ids, times and enums in clear.
- Recommendation: A with R1, recorded in ADR-005 and ADR-011. With Q5 A, the superuser and the archive see only ciphertext for content. Choose R2 only if a one-minute recovery point is too long.

**Q5. Ledger at rest and clear columns (R-NF-08 against ADR-007).**

- A: Seal ledger bodies, checkpoints and audit events under cell keys. The chain hashes stored ciphertext. No plaintext projection tables; projections in memory with sealed checkpoints. ADR-007 is amended.
- B: As A, but keep ADR-007's `numeric` projection tables for amounts. Amounts are then at rest in clear on shared clusters.
- C: Keep plaintext bodies and restate R-NF-08 for shared mode.
- Also, clear columns. Even with A, ids, times, enums, digests of random tokens and keyed lookup digests stay in clear on shared clusters, because indexes need them. This revision seals what no index needs: `ops.licence_state` token, `vault.document` object reference and `vault.negotiation` accounts. Credential ids become keyed digests. Is a clear column of those classes acceptable under "all data at rest encrypted with cell-specific keys"?
- Recommendation: A, and accept the listed classes, recorded in ADR-007 with the catalogue as the enforced list. Backups and a database superuser then see only ciphertext for content (R-CR-01, TH-58).

**Q6. Erasure construction and its cost (I-81, R-ID-03, ADR-004, ADR-007).**

- A: Root-epoch rotation per erasure batch, run as requests arrive, including each document verification (section 3.5).
- B: The same construction, batched at most once a minute.
- C: One custody key per identity document, destroyed on verification, with A or B for texts.
- Also: each batch creates and deletes one OKMS key per affected chain. OKMS documents billing per key stored but no quotas.
- Also: keyed digests (G24). The email lookup, credential lookup and identity match keys are replaced in every batch that erases one of their subjects, at one HMAC per live account. The alternative is to accept that an erased email or attribute tuple can be confirmed by a guess against a backup.
- Recommendation: A, if OKMS quotas allow it, otherwise B, with key replacement for digests in both. A matches ADR-007's "honoured at once" and P-19's "deleted on verification" most closely.

**Q7. Identity attributes bypass the application (I-17, `overview.md`, NOTE 6).**

- A: The vault origin with signed single-use tickets (section 6.5). Attributes, the P-17 country and documents go browser to vault. `overview.md` gains a paragraph naming the vault's non-query operations: writes, releases, acknowledgements and negotiation facts.
- B: The application proxies releases and writes. `overview.md` then needs an exception to "only through the queries".
- Recommendation: A. It matches both sentences of the spec and makes the I-17 storage check a check for absence. The vault origin has three routes and no sessions (risk R13).

**Q8. Anchors and the unwitnessed tail (I-24, ADR-001, R-CR-03, G7).**

- Signatures. A: composite anchors and receipts in M3, with ML-DSA-65 ACVP keyGen, sigGen and sigVer subsets. B: unsigned anchors until M9, with two witnesses carrying detection. C: Ed25519-only anchors, which departs from the ADR-001 table.
- Tail. D (built as the interim): prepare, receipt, commit, with abort and in-doubt records, so no committed entry is unwitnessed (section 7.2). A: a receipt after each commit, with writes refused once an entry stays unwitnessed for 60 seconds. B: as A, but each command waits for its receipt before it is reported. C: periodic anchors only.
- A, B and C each leave a window in which a committed entry can be deleted undetectably. I-24 says "any modification or deletion of a past entry is detectable". Can any bounded window satisfy I-24?
- Recommendation: signatures A, tail D. D costs one witness round trip per append and stops writes while the witness is down (R8). Choose A only if you decide that a bounded window meets I-24, and then please name the bound.

**Q9. Self-hosted witness (I-24, I-38).**

- A: A local `fstp-witness` with its own OS user, storage and key is mandatory at first start. An external object-lock bucket is optional.
- B: The witness is optional, with a standing warning to tenant admins.
- Recommendation: A. A self-hosted cell cannot anchor at CrabNebula under I-38, and R-NF-05 asks for secure defaults.

**Q10. Authentication scope (I-77, R-LG-01, ADR-001 open points).**

- A: In-house WebAuthn and magic links in M3. OPAQUE deferred until an ADR-001 addition covers its group arithmetic. EUDI Wallet login deferred to the milestone that builds EUDI verification.
- B: Add opaque-ke and its group crates under an ADR now.
- C: Use webauthn-rs. As far as I know it depends on the openssl crate, which no ADR allows.
- Also: which milestone owns EUDI Wallet login and verification (P-18, P-45)? M4 fits, with negotiation.
- Recommendation: A, recorded in ADR-008, and EUDI in M4. ADR-001's "Open points" line on authentication crates is then closed in the same amendment, since `authentication.md` says the crates "are chosen in ADR-001".

**Q11. OKMS as the SaaS custody backend (ADR-004, R-KY-01, R-NF-09).**

- Authentication. A: an access certificate over mutual TLS on REST, if OKMS accepts it there. B: KMIP, which requires certificates, with an in-house fuzzed TTLV codec. C: a personal access token or service account over server-authenticated TLS. That is not mutual authentication.
- Protection level: `HSM` for every root epoch and CA key.
- Verify before W2 L-KEYS merges: whether deleted key material survives in provider backups, rate limits and quotas, and any usage log for reconciliation. Also verify which EU regions offer the `HSM` level today, and whether the FIPS 140-3 claim on the product page covers them.
- Recommendation: A if available, otherwise B. Please ask OVHcloud about the verify items.


**Q12. Guardian consent timing (I-18, R-NG-01, R-NG-02).** A: collect and verify the guardian at the IRC_REVIEW to NEGOTIATION gate, in the vault only, with an R-NG-01 exception like O-48's. B: collect at submission, which R-SB-02 does not require. C: a new pre-negotiation state. Recommendation: A. `TODO(legal)`: L-02. Blocking, because the I-18 exit row depends on where the consent comes from.

**Q13. Source of the minor flag (R-ID-04, I-18, G20).** M2 takes the flag from the actor, so an applicant can clear it. The interim sets it on every draft, which means no proposal enters NEGOTIATION without a verified guardian consent, including adults' proposals.

- A: Collect an over-18 attestation into the vault before NEGOTIATION, as `eudi-wallet.md` describes ("Age is requested as an over-18 attestation"), with an R-NG-01 exception like the P-17 country. The NEGOTIATION gate then admits a proposal whose lead has an effective verified adult attestation, or a verified guardian consent. This needs a one-bit query such as `IsVerifiedAdultAtDeadline`, which extends the decided query set, and a domain change to the M2 guard.
- B: Treat every proposal as minor-flagged unless such an attestation exists, using the same attestation as A, but keep the domain guard unchanged. The cell clears the flag through a new command once the vault reports the attestation.
- C: The vault derives the flag at verification inside NEGOTIATION, and a minor without consent leaves NEGOTIATION. That breaks I-18's "cannot enter".
- D: Keep the flag the actor supplies, as M2 builds it. Not the strict reading.
- Recommendation: A, decided together with Q14 and the EUDI milestone of Q10. The interim stays until then. `TODO(legal)`: L-02, and whether Article 8 GDPR applies to the attestation.

**Q14. Who records a manual identity check (P-18, R-ID-02, SoD-09)?** Without an answer, no verification can be recorded in production. SoD-09 then refuses every Drafting and Judging grant, and I-18 can be claimed only over seeded facts (section 6.9). A: a new Operations role such as "identity verifier", outside Judging. B: the tenant admin. C: the programme manager. Recommendation: A. Until then the route refuses every caller.

**Q15. First passkey, step-up, recovery and self-hosted details (I-77, I-78, I-79, G29).**

- First passkey only in invitation, self-registration and recovery ceremonies, written into `authentication.md`: yes or no. This removes the flow "An account without a phishing-resistant method is asked to add one before its first high-risk action" for magic-link sessions.
- One step-up per command, bound to its digest, rather than a P-71 window: yes or no.
- Approving a recovery is high-risk: yes or no.
- Recovery revokes every old credential and session: yes or no.
- UV required for management logins and every step-up: yes or no.
- Self-hosted sole tenant admin: is a host console command, run as root with custody access, logged and shown to every tenant admin, an acceptable reading of "the platform operator's verified process"? The alternative is to require two tenant admins on every self-hosted install.
- Self-hosted install: the local `fstp-install` and local `fstp-pgagent` of section 9.5, with cluster CA keys in local custody: yes or no.
- Recommendation: yes to all seven.

**Q23. Crate features and direct dependencies (ADR-001, ADR-002, `deps/adr-roots.txt`).** Add `zeroize 1.9.1` as an ADR-001 root with features `alloc` and `default` only, never `derive`. Enable tokio `signal`, which adds `signal-hook-registry`, with an ADR-002 review note. No aws-lc-rs feature change is needed, since its ML-DSA API is stable. Recommendation: accept both, recorded before first use. Blocking, because deps-check fails without the records.

**Q25. Second backup provider and regions (ADR-005).** Options: Scaleway, Hetzner or IONOS, plus an OVHcloud primary region pair inside the EU. Recommendation: decide with the L-15 due diligence, preferring one with object lock. Blocking, because the ADR-005 exit row depends on it.

**Q32. File custody and its remnants (I-80, I-81, ADR-004, G23).** The interim narrows the remnant to a key table on a dedicated non-copy-on-write volume (section 3.3).

- A: The interim, with the I-81 claim for file custody scoped to "the key volume is excluded from host backups and snapshots".
- B: Per-epoch secrets sealed by the host TPM 2.0, so destroying the TPM object destroys the epoch everywhere. A TPM client crate needs FFI and an ADR-001 review; systemd tools alone cover the passphrase, not per-epoch objects, as far as I know.
- C: File custody claims I-80 only. Self-hosted installs that need I-81 use OKMS or an HSM.
- Unattended boot, with any option: the passphrase comes from a systemd credential bound to the TPM where one exists, otherwise from the console at boot. No default passphrase.
- Recommendation: A in M3, with C's wording in the operator guide, and B evaluated with the M9 self-hosted package.

**Q33. M3 exit scope, like `SPEC/09-milestones.md` NOTE 1 for M2.** Several exit items can be claimed only in part in M3.

- I-39: the test-plan row needs "a full call cycle, payment and export". M3 runs the cycle as far as it is built; payment is M5 and export is M9.
- I-16: claimed statically and structurally; payment adapters are M5.
- I-18: claimed over the vault core and over seeded facts, until a verification method exists (Q13, Q14).
- R-KY-01: claimed for the EU-operated KMS option only; the CrabNebula HSM is not built.
- R-HS-01: claimed only after L-15.
- Options. A: record a NOTE for M3 listing these scopes, as M2's NOTE 1 does, and claim them so. B: move the partial items to the milestones that complete them. C: extend M3 until each is complete.
- Recommendation: A, with M5 and M9 rerunning the same tests.

**Q35. Insider paths around SoD-08 (TH-18, G25).**

- First admin invitation. A: split delivery by two staff over two channels (section 8.3, built). B: the cell seals the token to a public key the tenant generates at onboarding, so no staff member ever sees it. C: one channel with logging only.
- Root on cell hosts. A: accept the residual risk, with separate host staff, no standing root, two-person access and tenant-visible access events (R16). B: require confidential computing for cell and vault hosts. I have not checked OVHcloud's offer for it. C: per-tenant dedicated hosts administered only under break-glass.
- Recommendation: B for the invitation once tenant onboarding exists in M4, and A until then. A for root access in M3, with B evaluated in L-15.

**Q36. What counts as tenant data for I-19 (G26).** Counters, health states, anchor links at the witness, edge logs and per-cell metrics cross to shared infrastructure.

- A: Tenant data is content, accounts, identity attributes and anything derived from them, except entries in a closed metadata register. Each register entry has a closed type and its coarsest useful form (section 9.1).
- B: Everything derived from tenant activity is tenant data. Nothing crosses except anchors, and metering moves into the cell's own export.
- Recommendation: A, with the register in ADR-009 and `i19_only_registered_metadata_crosses` as its test.

**Q39. Node.js and npm under ADR-003.** tsc and Playwright run on Node.js, and Playwright installs through npm. ADR-003 allowlists tsc, libFuzzer and Playwright only. A: amend ADR-003 to allow Node.js and npm as build and test hosts that never ship, with a pinned version and a lockfile check. B: run tsc and Playwright from pinned prebuilt archives without npm. Recommendation: A. Blocking, because W3c cannot start without it.

### 21.2 These shape M3 and can follow

**Q16. Sessions ended by a binding end (`authentication.md` Sessions).** This includes a scheduled end, which the gate enforces from its instant (section 5.4). A: end every session of the account. B: end only sessions that used the binding. No session records which binding it relied on. Recommendation: A.

**Q17. Identity matching rule (I-06, I-15, SoD-09).** A: a keyed hash over the method's canonical attribute tuple, per cell. B: an EUDI persistent identifier where present, falling back to A. C: a manual link by the verifier. Recommendation: A in M3, B with EUDI. `TODO(legal)`: confirm minimisation for the attributes used.

**Q18. What licence expiry may block (I-39).** A: nothing, only a notice. B: creating programmes and publishing calls after the P-43 grace period. Recommendation: A for noncommercial installs. For commercial installs you decide; B never touches an I-39 class.

**Q19. IP addresses (R-NF-02, I-38, open since M1).** A: memory only, for rate limits, at the edge and the cell, and recorded in R-NF-02 as identity attributes. B: keyed hashes of the prefix in cell logs. C: full addresses in audit events. Recommendation: A. `TODO(legal)`: the basis for short-lived in-memory rate limiting.

**Q20. Billing and I-16.** Confirm that CrabNebula's subscription revenue is outside I-16. Confirm that the control plane keeps metering counters and an opaque org reference, while legal names and contacts stay in CrabNebula's accounting system. Recommendation: confirm both.

**Q21. Break-glass in M3 (SoD-08, TH-18).** A: approval, scope, expiry, the gate path and logging now; content views with the M4 interfaces. B: all of it in M4. Recommendation: A, since approving break-glass is already a high-risk action.

**Q22. Login email (I-17, I-20, `notifications.md`).** A: sealed in the cell with a per-cell keyed lookup, treated as identity-revealing for I-17 canaries. B: in the vault, with the vault starting magic links. That extends the vault's operations and couples M6 to the vault. Recommendation: A.

**Q24. The moduletto TLS group (ADR-001 Uses).** `fstp-tls` negotiates X25519MLKEM768 through the aws-lc-rs provider today. A: M9, with the ACVP work, and record the gap in ADR-001. B: M3, beside key wrapping. Recommendation: A.


**Q26. Deployment unit (I-19).** A: an application host and a vault host per cell in SaaS, one node when self-hosted. B: one host per cell with OS-user separation. C: shared hosts with containers per cell. Recommendation: A, with systemd units and one OS user per process.

**Q27. Linux-only memory scan (I-80).** A: CI on Linux carries it, with a companion test on every platform asserting that CI runs it. B: also find a macOS method. Recommendation: A.

**Q28. Spec wording proposals, not edits.** Test-plan rows for I-16 to I-20 and I-77 to I-83 as section 14.4 phrases them. The R-NG-01 over-18 attestation exception (Q13), the R-NF-09 wording (Q34), and the metadata register for I-19 (Q36). An `overview.md` paragraph naming the vault's non-query operations (Q7). `authentication.md` notes on first-passkey ceremonies and on recovery approval being high-risk (Q15). The R-NG-01 guardian exception (Q12). Recommendation: accept, so tests cite spec text rather than this design.

**Q29. One driver after M3.** `DriverCore` and the M2 `Engine` both exist, checked against each other. A: keep both, with `Engine` as the reference oracle. B: collapse `Engine` onto `DriverCore` after M3 exits. Recommendation: A. A frozen reference catches drift that one shared implementation would hide.

**Q30. Public certificates for tenant hosts (I-19, I-71).** Each cell needs browser-trusted certificates for `<cell host>` and `id.<cell host>`, with keys generated in the cell. A: an in-house ACME client, fuzzed, built with tenant onboarding in M4. B: operator-run issuance per cell until M9. C: one wildcard certificate for the platform domain, which shares a private key across cells and is refused here. Recommendation: A.

**Q31. Writers of programme-side and reviewer-side facts (I-03, I-04, I-35, I-54, G21).** Section 6.8 has the programme manager write each partner's P-38 list, reviewers declare their own employer and relatives at binding, and partner staff declare themselves. A: as built. B: each partner writes its own list through a partner representative role. C: the tenant admin writes every list. Recommendation: A, with B if partners want direct control. `TODO(legal)`: the basis for storing relatives and the minimum attributes matching needs.

**Q34. R-NF-09 for links to external services (G27).** Object storage (SigV4), the witness's second-provider bucket, the licence and update services, and OKMS without an access certificate offer server-authenticated TLS only. A: read R-NF-09 as covering links between platform components, and record these links as authenticated by request credentials. B: put a platform-operated proxy with mutual TLS in front of each. C: drop providers that lack client certificates. Recommendation: A, with a wording proposal for R-NF-09. Until then M3 claims R-NF-09 for internal links only.

**Q37. New constants and proposed parameters.** The vault ticket lifetime (5 minutes), the invitation lifetime (72 hours) and the break-glass maximum (4 hours) have no P- id. P-71 (5 minutes) and P-72 (30 minutes idle, 12 hours absolute) are marked "(proposed)". A: keep the three as fixed ADR-008 and ADR-009 constants, and confirm P-71 and P-72. B: number the three as new policy parameters, which you would assign. Recommendation: A, and confirm P-71 and P-72 as proposed.

**Q38. High-risk additions (I-78, G28).** `HighRiskAction` adds `Assign` and `Unassign` (assigning a Judging role), `SetLoginPolicy` (changing login methods), `ApproveSelfGrant` and `ApproveRecovery`. M2's `CommandKind::high_risk()` lacks the first two. A: keep the additions in M3 and update the domain's `high_risk()` in a reviewed M2 crate change. B: keep the additions in the cell only. C: drop `Assign` and `Unassign`, since a call can need many assignments. Recommendation: A for the strict reading, with a batched step-up per assignment list if C's workload concern appears.

**Q40. SoD-07 approval lifetime.** The interim makes a self-grant approval single-use and valid for P-71 from its step-up. A: as built. B: a longer fixed window, such as 24 hours. Recommendation: A.

**Q41. First licence token (I-38, ADR-005 Licence registration).** A: the holder registers on a CrabNebula web page and imports the token file into the cell, so the cell never sends registration data (built). B: a third `CnCall` variant carrying holder name, contact and licence type. Recommendation: A.

**Q42. Erasure log scope for Auditors (ADR-007, G30).** A: an Auditor reads only entries for its programme's texts; tenant admins read all (built). B: an Auditor binding grants the whole tenant's log. Recommendation: A.
