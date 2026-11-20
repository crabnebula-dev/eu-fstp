# Production MCP: setting up programmes with Claude on a production cell

Status: design for Daniel, 2026-11-20. Lane `feat/prod-design`, on main `8c0ba49c`. No code changes. Every choice marked "interim" waits for Daniel.

Goal (Daniel, 2026-11-20): "make it work for real users". Programme staff add a production cell's `/mcp` to Claude Code or claude.ai, sign in, and set up programmes. Prepared actions are confirmed in the platform with a passkey step-up.

The demo flow works on `fstp-e2e-cell` (`docs/guide/claude-connector-demo.md`, ADR-013 "Record of lane mcp-demo"). This document says what the production cell `fstp-cell` lacks, what must be decided, and how to build it in lanes.

## 1. Where things stand

### 1.1 What the production cell serves today

`fstp_cell::process::start` starts a real cell over PostgreSQL, the witness and the vault. The world of `fstp-celltest` and `tools/devstack` use it in process. Its front serves one route table (`crates/fstp-cell/src/routes/mod.rs`).

| Surface | Production cell | Evidence |
| --- | --- | --- |
| `/auth/*` ceremonies (passkey login, step-up, recovery, sessions, devices) | Served, over `routes::pg::PgBackend` | `routes/mod.rs` `TABLE` |
| `/api/v1/commands`, `vault-tickets`, `verifications`, `audit/anchors`, `erasures` | Served: the M3 surface, raw `CellCommand` bodies through the gate | `routes/mod.rs:404-445`, `routes/api.rs` |
| `/p/**` public pages and `/app/assets/{file}` stylesheets | Served by `crate::public` | `routes/mod.rs` `PUBLIC_TABLE` |
| `/auth/login` and the other auth pages | Not served by a shipped build. Only the `dev-pages` feature serves them | `routes/mod.rs:591-601`, `process.rs:743-748` |
| `/app/**` journey UI | Not served. `/app/` answers the styled 404 | `http/front.rs:18-21`, `462-471` |
| `/api/v1/**` over `ApiCore` | Not served. `fstp-cell` does not depend on `fstp-api-core` or `fstp-web` | `crates/fstp-cell/Cargo.toml` |
| `/mcp`, `/.well-known/oauth-*` | Not served | as above |
| `/oauth/**` | Not served. A browser navigation gets 303 to `/app/`, any other client 404 | `http/front.rs:462-471` |

`fstp-web` holds every `ApiCore` surface (`/api/v1`, `/app`, `/p`, `/mcp`, the metadata). Only the e2e cell mounts it. It answers `/oauth/**` with the typed ADR-013 refusal (`crates/fstp-web/src/lib.rs:31-35`, `src/mcp.rs:6-14`).

**Can real users use the journey UI on a production cell?** No. Each of these blocks it on its own:

1. The `fstp-cell` binary does not start (G1).
2. No shipped build serves a login page (G9).
3. `/app` and the `ApiCore` API are not mounted (G2).
4. No proof mail is sent, so no recovery, magic link or self-registration completes (G10).
5. The first admin invitation leaves the cell only through an in-process call (G11).
6. A process restart loses every key, so stored texts and sealed rows become unreadable (G7).

### 1.2 Gaps

Each gap names its evidence and what it needs. The lane column refers to section 3.

| Id | Gap | Evidence | What it needs | Lane |
| --- | --- | --- | --- | --- |
| G1 | `fstp_cell::run` refuses after decoding the configuration. The grammar has five members: `cell`, `mode`, `eudi_relying_party`, `licence`, `version` | `crates/fstp-cell/src/lib.rs:40-44`, `145-159`; `config.rs:88` | A configuration grammar that names every part of `CellProcessParts` (`process.rs:128-160`) by file reference, and a `run` that builds them | L4 |
| G2 | No `ApiCore` over PostgreSQL ("W6 composition"). No `CellPorts` implementation outside the test kit. No `AsyncEngine` or `AuditSink` over the cell's store | `docs/handoff/m4-exit-audit.md:44-45`; `crates/fstp-api-core/src/port.rs:1559-1646` (21 ports) | A `CellPorts` implementation in `fstp-cell` over `CellEngine` and `PgBackend`, then `fstp-web` mounted in the cell front | L1 |
| G2a | `CellEngine` has no dry run. `AsyncEngine::dry_run` and `dry_run_answers` need one | `crates/fstp-cell/src/engine/mod.rs:490-595` | A dry run of `DriverCore` over a copy of `CellState`, answering vault queries and appending nothing | L1 |
| G2b | The gate has no agent principal. `Principal` is `Account`, `BreakGlass`, `System` or `Ceremony`, and every account admission takes a `SessionView`. An MCP call has a token, not a session | `crates/fstp-cell-core/src/gate.rs:441-455`, `636-666` | An admission for a command that `ApiCore` authorised under `Via::Mcp`, with the token's account and no step-up | L1 |
| G2c | Step-up digests differ. `ApiCore` binds a step-up to its request digest. The cell gate checks `SHA-256(canonical(command) \|\| command_id)` | `gate.rs:646-662`; `routes/auth.rs:1094-1115`; `web/src/core/stepup.ts:14-17` | An admission that accepts a `StepUpGranted` whose digest is the `ApiCore` request digest, with the same strength, session, P-71 and single-use checks | L1 |
| G2d | `AuditSink::record` is synchronous and takes the W0 placeholder `Tx` | `port.rs:520-523`, `1002-1005`; `dispatch.rs:574-608` | A sink over the App chain's kind 2 events (`0003_app.sql:46-58`), flushed before the reply | L1 |
| G3 | `api.pending_actions`, `workspace.drafts` and the `mcp` schema are not in the app migrations. The set ends at `0008_column_classes.sql` | `crates/fstp-pgstore/migrations/app/`; designed in `m4-design.md:978-1018` | Migrations 0009 and 0010, role grants (`crates/fstp-control/src/pg.rs:236-275`), column classes (`fstp-pgstore/src/catalogue.rs`) | L1, L2 |
| G4 | `ApiCore` keeps state in process memory: pending actions, rate counters, workspace cache, journal, read marks, begun verifications, creator memory, grant memory, agent activity | `crates/fstp-api-core/src/dispatch.rs:217-239`; `pending.rs:20-24`; `content.rs:38-44`; `creator.rs:1340-1356` | Pending actions move to `api.pending_actions` through a new port. The journal folds `AsyncEngine::ledger_after`. Workspaces go through the existing `Workspaces` and `Sealer` ports. The rest is listed as lost on restart in section 2.2 D10 | L1 |
| G5 | `fstp-oauth` holds clients, consents, codes, families and tokens in `BTreeMap`s. A restart ends every grant | `crates/fstp-oauth/src/server.rs:585-598`; ADR-013 line 134 | Persistence of clients, families and refresh records in the `mcp` schema, and the endpoints mounted in production | L2 |
| G5a | The OAuth endpoints and the consent page exist only in the test binary. The consent step-up is the demo button | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/oauth.rs:1-37`; ADR-013 lines 294-298 | Production endpoints, and a consent page that runs the passkey step-up of `web/src/core/stepup.ts` | L2 |
| G6 | H-21, issue 6 item M5: recovery does not revoke agent tokens in production. `complete_revoking` exists, but the cell decides with `recovery::complete` | `crates/fstp-auth/src/recovery.rs:643-668`; `crates/fstp-cell-core/src/decide.rs:1270-1272`; `crates/fstp-oauth/src/server.rs:1505-1520` | A token check against the account's last completed recovery, and `revoke_all_agents` after the commit | L2 |
| G7 | The keystore is held in process memory. The `keystore.*` tables exist, but no code reads or writes them. The test world passes the keystore from the old process to the new one | `crates/fstp-cell/src/tasks/erasure.rs:46-52`, `222-224`; `process.rs:671-683`; `crates/fstp-celltest/src/world.rs:5164-5168` | Keystore persistence in the `keystore.*` tables, loaded at start. The image format of `tasks/erasure/snapshot.rs` already names the rows | L3 |
| G8 | The `Anchor` key, the ledger data keys, the CredLookup key and the ticket key are handed in by the caller | `process.rs:41-46`, `94-108` | A sealed cell key file opened through custody, as the witness receipt key file does (`crates/fstp-witness/src/config.rs:25-38`) | L4 |
| G9 | The auth pages are served only with the `dev-pages` feature, since M3 design section 8.7 lists no page rows | `routes/mod.rs:591-601` | Daniel adds the page rows. The feature gate is lifted | L1 |
| G10 | `NoProofMail` refuses every send | `crates/fstp-cell/src/mail.rs:9-13`; `process.rs:544` | A proof mail port over a configured submission relay (`fstp-smtp`, ADR-018) | L4 |
| G11 | `RunningCell::issue_first_admin_invitation` returns the token to an in-process caller | `process.rs:35-40`, `919` | An operator command that prints the token once | L4 |
| G12 | `fstp_vault::run` and `fstp_edge::run` refuse to start | `crates/fstp-vault/src/lib.rs:133-137`; `crates/fstp-edge/src/lib.rs:66-70` | Their own configuration grammars and runs. Not needed for the definition of done, which uses the devstack's vault and edge | Wave 3 |
| G13 | `ProductionShell` supplies no probe, no Q35 vault answer and no Guide inputs. The shipped profile's legal wording is pending. So no programme activates and no call publishes | `crates/fstp-cell/src/shell.rs:8-26`; `crates/fstp-guide/profiles/horizon-europe/guide.v1.md` (`TODO(legal)`) | A prober, the two Q35 vault queries in `fstp-vault`, the Guide inputs, and Daniel's legal wording. Drafts work without them | Wave 3 |
| G14 | claude.ai unknowns: a token endpoint auth method other than `none`; an `Origin` header from claude.ai servers, which gets 403; which MCP era it speaks | ADR-013 lines 305-307 | One recorded trace from a real claude.ai connector, then an ADR-013 amendment | D9 |
| G15 | `PgBackend` keeps two things in process memory: the login credential of each passkey session, and the address of a pending registration between ceremony steps | `crates/fstp-cell/src/routes/pg.rs:17-35` | A restart then ends no session on a device removal, and breaks a ceremony in flight. Accepted for the pilot, or a column in `auth.session` | L1 (column), or accepted |
| G16 | A release build fails `deps-check --release` until a Mythos confirmation of moduletto is recorded (I-74, H-18) | `docs/handoff/m3-exit-audit.md` section 6; memory "Mythos run timing" | The M10 Mythos run. Outside this design | Daniel |

## 2. Decisions

### 2.1 ADR-required decisions, with draft rows

These are interim choices for Daniel. No ADR file is written yet. Each lane writes its rows into the ADR before code, as CLAUDE.md asks.

**ADR-026 (new): production cell configuration and composition.**

| Topic | Interim choice | Basis |
| --- | --- | --- |
| Configuration | One JSON object, closed member set, decoded by `fstp_json`, at most 8 KiB. Members: `cell`, `mode`, `version`, `host`, `licence`, `eudi_relying_party`, `credentials_dir`, `assets_dir`, `database` (`host`, `port`, `dbname`), `registered_servers` (SPKI SHA-256 and kind), `keyd_socket`, `witness` (address, server name), `vault` (address, server name), `listen` (`tunnel`, `internal`, `health`), `mail` (submission address, sender), `mcp` (see ADR-013 below) | G1; the witness grammar `crates/fstp-witness/src/config.rs:7-23` |
| Secrets | No secret in the configuration. The credentials directory holds, by fixed name: `db-ca.pem`, `writer.pem`, `writer.key`, `app.pem`, `app.key`, `origin.pem`, `origin.key`, `tunnel-ca.pem`, `internal.pem`, `internal.key`, `cell-ca.pem`, `witness-ca.pem`, `witness-receipt-keys`, `vault-ca.pem`, `cell-keys.sealed`, `mail.password` | R-NF-02; witness precedent |
| Decoder | Fuzzed: the existing target `cell_config_decode` covers the new grammar | CLAUDE.md fuzz rule |
| Composition | `fstp-cell` builds one `ApiCore` over its engine and route backend (`fstp_api_core::port::api_core`). The tunnel front matches the cell table first, then hands every other path to `fstp_web::router`. A build-time test proves the two tables share no method and path | M4 design section 1.3, W6 row; I-84 |
| M3 raw command route | `POST /api/v1/commands` stays on the cell table during the pilot. It runs the gate and every domain guard. Its retirement is a later decision | G2; D8 |
| Agent admission | `gate::admit_agent_command`: principal `Account`, `Via::Mcp`, no `SessionView`, no step-up. It refuses every `HighRiskAction`, every system-only and route-only command, and an account whose recovery completed after the token family started | G2b; I-85; I-79 |
| API step-up admission | `gate::admit_api_command`: a web session, with a `StepUpGranted` bound to the `ApiCore` request digest. Same checks as `admit_command`: strong method with UV, same session, within P-71, unused. The store checks freshness and use again at commit | G2c; I-78; ADR-008 |
| Dry run | `CellEngine::dry_run` runs `DriverCore` on a copy of the state after the last commit. It answers vault queries and stops at the append. It records every vault answer through `VaultAudit` | G2a; `overview.md` NOTE 5 |
| Deployment of the pilot | SaaS mode, one host, `fstp-keyd` custody, no control plane link, no licence. R-KY-01 is not claimed until OKMS custody runs (ADR-004 Q11) | D1 |

**ADR-013 amendment: production authorisation server.**

| Topic | Interim choice | Basis |
| --- | --- | --- |
| Records | Persisted in the `mcp` schema: clients, grant families, current and retired refresh token hashes. Kept in memory only: pending consents (10 minutes), codes (60 seconds), access tokens (10 minutes) and registration counters. A restart burns those. The client then refreshes or logs in again, which fails closed | G5; ADR-013 "Records" row |
| Write path | `fstp-oauth` stays sans-IO. It gains an export of its records and a journal of changes per call. `fstp-cell` writes the changes of one endpoint call in one transaction before it sends the reply | G5 |
| Tables | `mcp.client`, `mcp.family`, `mcp.refresh`, all with hashes or opaque references only. The M4 design tables `mcp.codes`, `mcp.tokens` and `mcp.sessions` are not built, since the modern era has no session | `m4-design.md:995-1007` |
| Endpoints | `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` served by `fstp-cell` over the same server as the `Tokens` port. `fstp-web` serves the two metadata documents from the same `fstp_oauth::Config` | G5a |
| Consent page | `/oauth/authorize` answers 303 to `/app/connect/{handle}`. That page reads `agents.consent_request`, a new web-only read naming the client name as unverified text, the redirect host and the scopes. Approval calls `agents.consent` with `withStepUp`, then follows the redirect. No demo button exists in production | G5a; I-78; I-77; I-86 |
| Recovery | A grant whose family started at or before the account's last completed recovery is refused on every call. The recovery route also calls `revoke_all_agents` after the commit | G6; H-21; I-79 |
| Agent origins | `/mcp` accepts a request without `Origin`, or with the tenant origin, as now. A configured list `mcp.agent_origins`, empty by default, adds origins for `/mcp` only, with the bearer token still required. Built only after a claude.ai trace shows the need | G14; D9 |
| Token auth method | `none` only, until a claude.ai trace shows another method | G14; D9 |
| Consent texts | The e2e cell's texts (`oauth.rs:63-90`) become the production texts, pending Daniel. They move to the platform message catalogue | ADR-013 "Scopes" |

**ADR-010 amendment: API call audit events.**

| Topic | Interim choice | Basis |
| --- | --- | --- |
| Event | Each `ApiCore` call writes one kind 2 event on the App chain: actor, channel, agent client, operation, outcome, request digest, step-up reference. The body is sealed like every kind 2 body | I-24; R-AU-01; M4 design 3.7 |
| Executed command | The event joins the command's append transaction through `SideEffects`, so the ledger batch, its audit event and the pending status commit together | M4 design 6.1 requirement 1 |
| Other calls | `AuditSink::record` buffers the event for the call. A new `AuditSink::flush` is awaited before `ApiCore::dispatch` returns. A failed flush turns the reply into a 503 refusal | G2d |

**ADR-004 amendment: keystore tables and the cell key file.**

| Topic | Interim choice | Basis |
| --- | --- | --- |
| Keystore | The rows of the keystore image (`tasks/erasure/snapshot.rs:21-31`) move to `keystore.root`, `keystore.group_key`, `keystore.data_key` and `blob.text`. Signer rows, the chain state and the login email index get their own tables in migration 0011. Written through `c_<cell>_keys` only | G7; M3 design 3.5 and 4.7 |
| Load | `process::start` loads the keystore from the tables when the ledger is not empty, and runs genesis only on an empty ledger | G7 |
| Cell key file | `cell-keys.sealed` holds the `Anchor` key, the ledger data key generations, the CredLookup key and the ticket key. It is sealed under a seal key wrapped by `fstp-keyd`, with the layout of the witness receipt key file. Fuzzed decoder `cell_key_file_decode` | G8 |

**M3 design section 8.7 amendment: page rows.** The rows of `page_table` join the served table, so a shipped build serves `/auth/login` and the other auth pages (G9).

### 2.2 Decisions that need Daniel

| Id | Question | Recommendation |
| --- | --- | --- |
| D1 | Which deployment comes first? | A single-host SaaS pilot with `fstp-keyd` custody and the devstack topology. OKMS, the control plane listener and remote edges come later. R-KY-01 is not claimed for the pilot |
| D2 | Ship the auth pages (section 8.7 page rows)? | Yes. Without them no person can sign in to a shipped build |
| D3 | Where does proof mail go before a tenant sets its relay? | A platform submission relay named in the cell configuration. The tenant's relay (ADR-018) replaces it once set |
| D4 | How does the operator receive the first admin invitation? | A subcommand `fstp-cell first-admin` that prints the token once, two halves on a SaaS cell, and records the `Provisioning` invitation |
| D5 | Keystore persistence now, and the sealed cell key file? | Yes to both, as in the ADR-004 rows above. A restart cannot work otherwise |
| D6 | The two new gate admissions (agent and API step-up)? | Yes, as in the ADR-026 rows. They keep the gate as the one path into `DriverCore` |
| D7 | Audit events as kind 2 rows, with a flush before the reply? | Yes, as in the ADR-010 rows |
| D8 | Keep the raw `POST /api/v1/commands` on the production front? | Keep it for the pilot. Decide its retirement once `/app` runs on `ApiCore` |
| D9 | How to close the three claude.ai unknowns? | Run one claude.ai connector against the demo cell through an HTTPS tunnel, with `--log-requests`, before L2 merges. Build the agent origin list or another auth method only if the trace needs it |
| D10 | Which in-memory `ApiCore` state may be lost on a restart in the pilot? | Accept the loss of: rate counters, begun verifications, the tenant template catalogue and upload texts of `CreatorMemory`, contract memory, agent activity, read marks (ADR-020 is still proposed) and the R-NG-06 acknowledgement. Pending actions and workspaces must survive |
| D11 | Where does `t_authz_matrix_pg_sample` live? | In `crates/fstp-celltest/tests/`. Rule A9 forbids `fstp-cell` to reach `fstp-api-testkit`, and only `fstp-celltest` depends on both |
| D12 | Real users on a build that is not a release? | Needs Daniel. A release waits for the M10 Mythos confirmation (G16) |

### 2.3 Deployment and infrastructure, out of code scope

The definition of done in section 4 runs on one machine. Real users need the following, which no lane builds. An operator must supply:

- **Host.** A Linux host in the EU, ext4 or XFS for the `fstp-keyd` volume (I-81 assurance). Hosting choice under ADR-005 (OVHcloud).
- **DNS.** A tenant domain, for example `grants.example.eu`, pointing at the edge.
- **Public TLS.** An origin certificate for that domain from a public CA. Browsers and claude.ai need it. WebAuthn needs `https` with no port.
- **PostgreSQL.** Application, vault and witness clusters, each with a server certificate whose OU names its kind, and client certificates per login role (I-82, I-83). The SPKI digests of the application cluster go into `registered_servers`.
- **ADR-005 V6.** The OVHcloud answer on SCRAM-SHA-256 and channel binding for the managed control cluster link. It blocks the SaaS control plane, not the single-host pilot.
- **Custody.** `fstp-keyd` with its passphrase as a systemd credential. OKMS later (ADR-004 Q11).
- **Witness.** `fstp-witness` from its configuration, already runnable (`crates/fstp-witness/src/lib.rs:288-300`).
- **Mail.** A submission relay account for proof mail and notices.
- **Backups.** Object storage under ADR-012. The S3 client of `fstp-backup` is still a stub.
- **Release gate.** The Mythos confirmation of moduletto (I-74) and the legal wording marked `TODO(legal)`.
- **claude.ai.** A claude.ai plan that allows custom connectors, for D9.

## 3. Lane plan

### 3.1 Waves

| Wave | Lanes | Runs |
| --- | --- | --- |
| 1 | L1 `prod/api-pg`, L2 `prod/oauth-pg`, L3 `prod/keystore-pg` | In parallel |
| 2 | L4 `prod/cell-run` and the definition of done | After L1, L2 and L3 merge |
| 3 | Vault run, edge run, production shell facts | Not needed for section 4. Listed in 3.6 |

All four lanes touch security code, so each runs on Opus. Each lane uses 4 threads and one test binary at a time, as `.lanes/.cargo/config.toml` sets.

### 3.2 Shared files and merge order

- Migration numbers are fixed now: `0009_api.sql` (L1), `0010_mcp.sql` (L2), `0011_keystore.sql` (L3).
- `crates/fstp-pgstore/src/migrations.rs`, `src/catalogue.rs` and `crates/fstp-control/src/pg.rs` take one appended block per lane. Merge order is L1, L3, L2. Each later lane rebases and keeps the earlier blocks.
- `crates/fstp-api-core/src/port.rs`: L1 owns it, except the `Tokens` trait, which L2 owns. Neither edits the other's region.
- `crates/fstp-pgstore/src/store.rs` side effects: L1 adds the pending and audit rows, L3 adds none.
- `crates/fstp-cell/src/process.rs`: L1 owns the composition hooks, L3 the keystore load. L4 owns it in wave 2.
- After each merge, every target of the merge result is checked, as the 2026-11-19 lesson asks.

### 3.3 L1 `prod/api-pg`: ApiCore over PostgreSQL in the cell

**Scope.** The W6 composition (G2, G2a to G2d, G3 for `api` and `workspace`, G4, G9, G15 optional). `ApiCore` over the cell's engine and route backend, `fstp-web` mounted behind the cell table, pending actions in PostgreSQL, audit events on the App chain, and the auth pages served.

**Owns.**

- `crates/fstp-cell/src/api/` (new): one module per port group: `engine.rs` (`AsyncEngine` over `CellEngine`, `ledger_after` from the store), `session.rs` (`Sessions`, `StepUp`, `SessionsAdmin`), `audit.rs` (`AuditSink`, `VaultAudit`), `content.rs` (`Workspaces`, `Sealer`, `TextStore` over `ErasureHandle`, `BlobStore` over `doc.blob`), `tenant.rs` (`TenantConfig`, `Outbox`, `Clock`, `Ids`), `closed.rs` (fail-closed `Vault` extras, `Prober`, `BreakGlass`, `Recovery`, `Precheck` absent), `mod.rs` (`compose`).
- `crates/fstp-cell/src/engine/mod.rs` (dry run), `crates/fstp-cell/src/http/front.rs` (mount), `crates/fstp-cell/src/routes/mod.rs` (page rows), `crates/fstp-cell/Cargo.toml` (adds `fstp-api-core`, `fstp-web`).
- `crates/fstp-cell-core/src/gate.rs` and `driver.rs` (two admissions, `SideEffects` members).
- `crates/fstp-api-core/src/port.rs` (new `PendingActions` port, `AuditSink::flush`), `pending.rs`, `dispatch.rs` (pending store behind the port).
- `crates/fstp-api-testkit/src/fake/` (memory `PendingActions`, `flush`).
- `crates/fstp-pgstore/migrations/app/0009_api.sql` (`api.pending_actions` with a sealed request column, `workspace.drafts`), `store.rs` side effects.
- `crates/fstp-celltest/tests/t_authz_matrix_pg_sample.rs`, `i85_concurrent_confirmations_execute_once.rs`, and the tests below.

**Tests first.**

- `t_authz_matrix_pg_sample`: 2,000 stratified cells of the authorisation matrix on a PostgreSQL cell, every outcome equal to the reference (I-84, M4 design section 8.3).
- `i85_concurrent_confirmations_execute_once`: two transactions confirm one pending action, exactly one appends (I-85).
- `i85_agent_admission_refuses_every_high_risk_action`: `admit_agent_command` over every row of `HIGH_RISK_TABLE` (I-85, I-78).
- `i78_api_step_up_is_digest_bound_and_single_use_on_pg`, and `i78_stale_api_step_up_refused_at_commit` (I-78, TH-56).
- `i77_magic_link_session_refused_for_management_ops_on_pg` (I-77, TH-55).
- `i24_every_api_call_leaves_one_chain_event`, accepted and refused, web and MCP, with the agent named (I-24, R-AU-01).
- `i84_audit_parity_on_pg`: the existing property of `i84_audit_parity.rs`, run on the PostgreSQL cell (I-84).
- `i21_workspace_rows_hold_sealed_bytes_only` and `r_nf_08_api_and_workspace_columns_are_classed` (I-21, R-NF-08).
- `t_db_m4_migrations_forward_only` and `t_db_app_role_has_no_ledger_update` (M4 design section 9).
- `i82_role_plan_grants_api_and_workspace_to_app_only` (I-82, TH-58).
- `t_cell_and_web_routes_do_not_overlap` (I-84).
- `i23_restart_replays_pending_and_workspace` over an in-process restart of the world (I-23). The cross-process restart waits for L3.

**Depends on.** Nothing in wave 1. L2 plugs its `Tokens` into `compose` after L1 merges. L1 ships a fail-closed `Tokens` until then.

**Size.** Large. About 4,000 to 6,000 lines with tests. The biggest parts are the engine adapter with its dry run, and the matrix sample harness.

### 3.4 L2 `prod/oauth-pg`: the production authorisation server

**Scope.** G5, G5a, G6, and G3 for `mcp`. The OAuth records in PostgreSQL, the four endpoints in production, the consent page with a passkey step-up, and the H-21 fix.

**Owns.**

- `crates/fstp-oauth/src/` (records export and change journal; `server.rs` stays sans-IO).
- `crates/fstp-cell/src/oauth/` (new): `store.rs` (`mcp.*` rows), `tokens.rs` (`Tokens` port, with the recovery check against `CellState`), `routes.rs` (the four endpoints, rate keys from the tunnel peer).
- `crates/fstp-cell/src/routes/auth.rs`: `recovery_complete` only, calling `revoke_all_agents` after the commit.
- `crates/fstp-pgstore/migrations/app/0010_mcp.sql`.
- `crates/fstp-api-core/src/port.rs` (`Tokens` trait only: `consent_request`), `dispatch/agents.rs`.
- `crates/fstp-access/src/registry.rs` (the `agents.consent_request` row, web only).
- `web/src/connect/` (new page), `web/src/gen/api.ts` (regenerated by `tools/gen-ts`).
- `crates/fstp-web/src/mcp.rs` (metadata from the shared config).
- `crates/fstp-oauth/fuzz/` (a target for any new record decoder).

**Tests first.**

- `h21_recovery_completion_revokes_agent_tokens_pg` (issue 6 M5, H-21, I-79, TH-57).
- `i79_token_family_older_than_recovery_is_refused` (I-79). It holds after a restart too.
- `r_mc_01_oauth_records_survive_restart`: a refresh after a restart succeeds, and a code minted before it is burned (R-MC-01).
- `th61_refresh_reuse_after_restart_revokes_family` (TH-61).
- `r_mc_03_revocation_takes_effect_at_once_on_pg`, through `/oauth/revoke` and through `agents.revoke` (R-MC-03).
- `i78_consent_needs_passkey_step_up` and `i77_magic_link_session_cannot_consent` on the production page (I-78, I-77).
- `i86_consent_request_names_no_identity` (I-86).
- `th61_mcp_tables_hold_hashes_only`: a scan of `mcp.*` for every token and code issued in the test (TH-61, R-NF-02).
- `r_nf_08_mcp_columns_are_classed` (R-NF-08).
- The fuzz targets of every new decoder, from the first commit.

**Depends on.** L1 for mounting into the production front and for `compose`. Until L1 merges, L2 tests its store and endpoints over `fstp-pgtest` and the `memory` route backend. Merges after L1 and L3.

**Size.** Medium to large. About 2,500 to 3,500 lines with tests and the page.

### 3.5 L3 `prod/keystore-pg`: keystore persistence

**Scope.** G7. The keystore in its tables, loaded at start, with the login email index and the signer rows. A real process restart keeps every key.

**Owns.**

- `crates/fstp-cell/src/tasks/erasure.rs` and `erasure/snapshot.rs` (write-through to the tables, load).
- `crates/fstp-pgstore/src/` (new `keystore.rs`), `migrations/app/0011_keystore.sql`.
- `crates/fstp-cell/src/process.rs`: the `keystore` branch at `671-683` only.
- `crates/fstp-celltest/src/world.rs`: `restart` stops passing the keystore in process.

**Tests first.**

- `i80_keystore_rows_hold_no_root_material` (I-80, TH-59).
- `i81_destroyed_epoch_stays_unreadable_after_restart` (I-81).
- `r_cr_01_keystore_rows_sealed_at_rest` (R-CR-01).
- `adr004_keystore_round_trips_through_tables` (ADR-004).
- `i23_process_restart_reads_every_text` (I-23).
- `i79_login_email_lookup_survives_restart`, since recovery needs it (I-79).
- `i82_keystore_written_by_keys_role_only` (I-82).

**Depends on.** Nothing. Merges second.

**Size.** Medium to large. About 2,000 to 3,000 lines. The erasure task is 2,088 lines and its crash rules (`ChainState::restart`) must hold over the tables.

### 3.6 L4 `prod/cell-run` (wave 2) and wave 3

**Scope of L4.** G1, G8, G10, G11. The configuration grammar of ADR-026, `fstp_cell::run`, the sealed cell key file, proof mail over the configured relay, `fstp-cell first-admin`, a devstack mode that runs the cell as its own process, and the definition of done.

**Owns.** `crates/fstp-cell/src/config.rs`, `lib.rs`, `main.rs`, `mail.rs`, `process.rs`, a new `keyfile.rs`; `crates/fstp-cell/fuzz/` (`cell_config_decode` grows, `cell_key_file_decode` new); `crates/fstp-celltest/src/bin/fstp-devstack/` and `tools/devstack/run.sh` (mode `external-cell`); `crates/fstp-celltest/tests/prod_mcp_e2e.rs`; `docs/guide/claude-connector-production.md`.

**Tests first.**

- `i19_config_names_one_cell` and `i16_config_types_hold_no_debtor_account` over the new grammar (I-19, I-16).
- `i83_config_start_refuses_a_vault_cluster` (I-83).
- `i80_cell_key_file_holds_no_open_key` (I-80).
- `r_nf_02_config_and_key_errors_never_quote_bytes` (R-NF-02).
- The end-to-end checks of section 4.

**Depends on.** L1, L2 and L3.

**Size.** Medium. About 1,500 to 2,500 lines, plus the end-to-end test.

**Wave 3, outside the definition of done.** Each is needed before an operator runs the services as separate hosts or activates a programme.

- `fstp_vault::run` from a configuration (G12). Medium.
- `fstp_edge::run` from a configuration (G12). Medium.
- `ProductionShell` facts: a prober, the two Q35 vault queries in `fstp-vault`, the Guide inputs (G13). Large. Legal wording stays with Daniel.
- The `journey` schema projector, so `AsyncEngine::ledger` is not read from genesis on every journey read (`port.rs:893-903`). Medium.

## 4. Definition of done

A production `fstp-cell` binary, started from a configuration file on local PostgreSQL, passes every check below. The other services come from `tools/devstack` in its new `external-cell` mode: PostgreSQL clusters through `fstp-pgtest`, the witness, the vault, the edge and `fstp-custody-sim --serve` on a keyd socket. The devstack writes `cell.json` and the credentials directory, then starts `target/debug/fstp-cell` with `FSTP_CELL_CONFIG`.

### 4.1 Automated: `crates/fstp-celltest/tests/prod_mcp_e2e.rs`

The test drives the browser side with the software authenticator (`crates/fstp-celltest/src/soft_authn.rs`) and an MCP client in Rust that speaks the 2026-07-28 era, as Claude Code 2.1.328 does (ADR-013 lines 257-270).

1. **Start.** The binary starts from the file and reaches `ready`. `fstp-cell first-admin` prints the token halves. The first admin enrols a passkey through `/auth/login`'s pages. Onboarding and activation run through `/app` with a second admin (ADR-021).
2. **Connect (R-MC-01).** `POST /mcp` without a token gets 401 naming the resource metadata. Both metadata documents read. Open registration answers a `client_id`. `/oauth/authorize` with PKCE `S256` and `resource` answers 303 to `/app/connect/{handle}`.
3. **Consent with a passkey (I-78, I-77).** A magic-link session is refused. The passkey session approves with a step-up from the software authenticator. The redirect carries `code`, `state` and `iss`. The token endpoint answers an access and a refresh token.
4. **Prepare a draft (I-85, I-84).** `server/discover`, then `tools/list` lists `fstp_prepare_programme_draft`. `tools/call` answers a pending action and its `/app/pending/{id}` path. No programme exists in the state yet.
5. **Confirm (I-85, I-78).** The same account confirms at `POST /api/v1/pending-actions/{id}/confirmation` with a fresh step-up bound to the stored digest. The programme draft exists. A second confirmation is refused. The App chain holds one audit event per call, the agent named on the MCP ones (I-24).
6. **Restart (I-23).** SIGTERM drains the process. The same binary starts again from the same file. The refresh token rotates. `fstp_creator_list_programmes` lists the draft. The pending action shows as confirmed. A text stored before the restart opens.
7. **Recovery revokes the agent (I-79, H-21).** The account recovers through the second-admin path, with the email proof caught by the devstack relay sink. The old access token gets 401. The old refresh token gets `invalid_grant`. A new consent works with the new passkey.

Each step names its IDs in the test's doc comments.

### 4.2 Manual: real Claude Code

The same stack, with `NODE_EXTRA_CA_CERTS` set to the devstack origin CA, so Claude Code trusts `https://a.fstp.localhost`. If the installed Claude Code does not honour it, the lane records that in ADR-013 and the check moves to a tunnel with a public certificate.

1. `claude mcp add --transport http fstp https://a.fstp.localhost/mcp`, then `/mcp` and sign in.
2. Approve on `/app/connect/...` with a passkey (Chromium with a platform or virtual authenticator).
3. Ask Claude to set up a programme from the Horizon Europe profile. Confirm the prepared draft in `/app/pending`.
4. Restart the cell. Claude's next call works without `claude mcp logout`.
5. Record the observed requests in ADR-013, as the lane mcp-demo record does.

### 4.3 What the definition of done does not claim

- claude.ai. It needs a public origin and Daniel's account (D9).
- Activation or publication of the programme (G13).
- R-KY-01 custody, separate vault and edge hosts, backups (section 2.3).
- A release (G16).

## 5. Open questions raised

- D1 to D12 above.
- The 2026-07-28 revision deprecates dynamic registration in favour of client ID metadata documents (ADR-013 line 109). If claude.ai uses metadata documents, the cell needs a guarded fetch. That is a new egress destination under ADR-018 rules.
- Q35 was answered "A" on 2026-11-06 (`m4-design.md:1931`), but `fstp-vault` implements neither query. Wave 3 builds them.
- ADR-020 (read marks) is still proposed. D10 treats the marks as memory only.
