# ADR-026: Production cell composition

Status: Accepted in part. The rows of "Composition" below were decided by Daniel on 2026-11-20 (D2, D6, D8 and D10 of `docs/handoff/production-mcp-design.md` section 2.2). The "Configuration" rows were written by lane L4 before its code. Rows there marked "interim, pending Daniel" wait for him.

## Context

- The production cell `fstp-cell` serves the M3 surface only. `ApiCore` runs over fakes in `fstp-api-testkit` and in the test-only e2e cell (`docs/handoff/production-mcp-design.md` section 1.1, gaps G2 to G4 and G9).
- M4 design section 1.3 names the W6 composition: one `ApiCore` over the cell's engine and route backend, with `fstp-web` behind the cell table.
- The gate is the one path into `DriverCore` (M3 design section 5.4). Its account admissions take a `SessionView`. An MCP call carries a bearer token, not a session (G2b).
- `ApiCore` binds a step-up to its own request digest. The gate checks `SHA-256(canonical(command) || command_id)` (G2c).
- I-85: an agent prepares, and only the user confirms, once. I-78: a high-risk action needs a fresh, phishing-resistant step-up bound to its digest. I-79: a completed recovery ends every earlier session and grant of the account.

## Composition

Decided by Daniel on 2026-11-20.

| Topic | Decision | Basis |
| --- | --- | --- |
| Composition | `fstp-cell` builds one `ApiCore` over its engine and route backend (`fstp_api_core::port::api_core`), in `crates/fstp-cell/src/api/`. The tunnel front matches the cell table first, then hands every other path to `fstp_web::router`. A test proves the two tables share no method and path | M4 design section 1.3, W6 row; I-84 |
| M3 raw command route | `POST /api/v1/commands` stays on the cell table during the pilot. It runs the gate and every domain guard. Its retirement is a later decision | D8 |
| Agent admission | `gate::admit_agent_command`: principal `Account`, channel `Via::Mcp`, no `SessionView`, no step-up. It refuses every `HighRiskAction`, every system-only and route-only command and every read. It refuses an account whose recovery completed at or after the token family started, and an account with a binding that ended after the family started | G2b; I-85; I-79 |
| API step-up admission | `gate::admit_api_command`: a web session, with a `StepUpGranted` bound to the `ApiCore` request digest. The checks are those of `admit_command`: a phishing-resistant session, a strong method with UV, the same session, within P-71, unused. The store checks freshness and use again at commit. The step-up challenges the API core begins are held in process memory, so a restart asks for the step-up again. Decided by Daniel on 2026-11-20, for the pilot | G2c; I-78; ADR-008 |
| Channel in the decision | Each admission records its channel in the route inputs. The cell decides an engine command with that channel in `Ctx.via`, so every guard of the domain that reads `Via::Mcp` runs in the cell as in the M2 engine. The channel can only add refusals | I-85; I-84 |
| Dry run | `CellEngine::dry_run` runs `DriverCore` on a copy of the state after the last commit. It answers vault questions through the cell's vault client and stops at the command's append. A reaction the vault asks for is folded on the copy only, with no append and no acknowledgement. It returns every vault answer it obtained, so the API core records each through `VaultAudit`. A dry run is admitted by `gate::admit_dry_run`, with no session or step-up check, and the engine never executes such an admission. Decided by Daniel on 2026-11-20 | G2a; `overview.md` NOTE 5 |
| Pending actions | Stored in `api.pending_actions` through the new `PendingActions` port, written by the app role. The request text is sealed under the current ledger key generation, with the AAD `"fstp-api-pending-v1" \|\| cell \|\| id`. A confirmation inserts one `api.pending_confirmed` row inside the append transaction of its command, as the writer role. A second confirmation of the same action violates its primary key, and the whole append aborts. Decided by Daniel on 2026-11-20: the exactly-once confirmation is this insert-only row, and the writer keeps INSERT and SELECT only | G3; G4; I-85; M4 design section 4.3 "Exactly once" |
| Workspaces | `workspace.drafts` holds one sealed value per proposal and slot, through the existing `Workspaces` port. The `Sealer` seals under the current ledger key generation with the AAD `"fstp-workspace-v1" \|\| cell \|\| proposal`. The app role reads, writes and deletes the rows. Decided by Daniel on 2026-11-20, as a pilot reading: pending requests, workspace values and kind 2 event bodies are sealed under the ledger key generation. Erasing a workspace deletes its rows and destroys no key. Per-workspace erasure keys come before any release | G3; G4; I-21 |
| State lost on a restart | Rate counters, begun verifications, the tenant template catalogue and upload texts of `CreatorMemory`, contract memory, agent activity, read marks and the R-NG-06 acknowledgement stay in process memory. Pending actions and workspaces survive | D10 |
| Auth pages | The rows of `routes::page_table` join the served table, so a shipped build serves `/auth/login` and the other auth pages from the compiled assets. The `dev-pages` feature no longer gates them. M3 design section 8.7 is amended to list them | D2; G9 |
| Tokens until lane L2 | The `Tokens` port of the production cell refuses every token, so `/mcp` answers 401 and no agent call is admitted. Lane L2 replaces it with the token store over the `mcp` schema | G5 |
| Fail-closed ports | The production cell has no pre-check provider, no prober, no recovery or break-glass approval through the API core, and no vault Q35 queries. Each port answers unavailable | G13; Q38 |

## Configuration

Written by lane L4 `prod/cell-run` before its code, from `docs/handoff/production-mcp-design.md` section 2.1, rows "Configuration", "Secrets", "Decoder" and "Deployment of the pilot". Rows marked "interim, pending Daniel" are the lane's own readings.

| Topic | Decision | Basis |
| --- | --- | --- |
| Deployment of the pilot | A single-host pilot in SaaS mode, with `fstp-keyd` custody and no control plane link. No licence. R-KY-01 is not claimed until OKMS custody runs (ADR-004 Q11). Decided by Daniel on 2026-11-20 (D1) | D1 |
| Real users | moduletto is confirmed for release, so a clearly labelled pilot may have real users. A pilot is not a release. `der`, `spki`, `x509-cert` and `cms` stay unconfirmed (I-74). Decided by Daniel on 2026-11-20 (D12, changed) | D12; I-74 |
| File | One JSON object in the file that `FSTP_CELL_CONFIG` names, at most 8 KiB, decoded by `fstp_json` with depth, member and string limits. The member set is closed. An unknown member, a member given twice or a missing required member is refused, so a typo never falls back to a default | G1; witness precedent |
| Members | `cell`, `mode`, `version`, `licence` and `eudi_relying_party` keep their M3 grammar. New: `host`, `credentials_dir`, `assets_dir` (optional), `database` (`host`, `port`, and `dbname`, which must be `c_<cell>`, so a vault database is refused under I-83), `registered_servers` (a list of `spki_sha256` and `kind`), `keyd_socket`, `key_file_keyd_socket`, `witness` (`address`, `server_name`, `ca_spki_sha256`), `vault` (`address`, which the vault certificate names), `listen` (`tunnel`, `internal`, `health`), `mail` (optional: `relay`, `sender`, `username`, `address`) and `organisation_active` (optional). The `mcp` member of the design is not added, since the agent origin list waits for D9 | G1; ADR-013 amendment |
| Logins | The three logins are `<dbname>_writer`, `<dbname>_app` and `<dbname>_keys` on `database`, as `fstp_control::pg::role_name` names them. The configuration names no role | M3 design section 4.7; I-82 |
| Secrets | No secret is in the configuration. The credentials directory holds, by fixed name: `db-ca.pem`; `writer.pem`, `writer.key`, `writer.password`; `app.pem`, `app.key`, `app.password`; `keys.pem`, `keys.key`, `keys.password`; `tunnel.pem`, `tunnel.key`, `tunnel-ca.pem`; `origin.pem`, `origin.key`; `internal.pem`, `internal.key`, `cell-ca.pem`; `witness.pem`, `witness.key`, `witness-ca.pem`, `witness-receipt-keys`; `vault.pem`, `vault.key`, `vault-ca.pem`; `cell-keys.sealed`; and with `mail`, `mail.password` and optionally `mail-ca.pem` | R-NF-02; witness precedent |
| Receipt key list | `witness-receipt-keys` holds one encoded witness receipt public key per line, in lowercase hex. At most 8 keys | ADR-010 "Keys" |
| Decoder | `fstp_cell::config::decode_file` reads the file, and `decode_receipt_keys` the key list. The fuzz target `cell_config_decode` covers both. A refusal names its rule and never quotes the input | CLAUDE.md fuzz rule; R-NF-02 |
| Assets | With `assets_dir`, the cell serves the compiled auth pages of `assets_dir/auth` (with `shell.html` and the stylesheets beside them) and mounts the journey UI of `assets_dir/app` (`fstp_web::load_dir`, manifest checked). Without it, the cell mounts the web adapter over a one-module stub shell, so `/api/v1`, `/mcp` and the OAuth endpoints are served and `/app` shows an empty page. Interim, pending Daniel | D2; G2 |
| Proof mail | Proof mail goes through a platform submission relay named in `mail`, until a tenant sets its own relay (ADR-018). Decided by Daniel on 2026-11-20 (D3) | D3 |
| Relay address | Interim, pending Daniel. `mail.address` may pin the relay's socket address in place of a DNS lookup. The relay is then reached at that address on its port, and the public address and port 465 rules of ADR-018 do not apply. TLS still verifies the certificate for `mail.relay` against the public roots and `mail-ca.pem`. Only the operator's configuration can name it. A tenant relay never can. The devstack names a loopback sink this way | D3; ADR-018 |
| First admin | `fstp-cell first-admin <file>` starts the cell from the same configuration with every listener on a loopback port the system picks. It records the `Provisioning` invitation, writes the token once to a new file with mode 0600, and stops. A SaaS cell writes two halves on two lines. The file must not exist. Run it while the cell is stopped. Decided by Daniel on 2026-11-20 (D4). Interim, pending Daniel: "prints" is read as "writes once to a new file", since R-NF-02 bans a write to standard output outside `fstp-obs` | D4; R-NF-02 |
| Organisation port | Interim, pending Daniel. A production cell records no `TenantProvisioned`, since no control plane runs (D1). Its ledger then holds no tenant part, and the ADR-021 gate reads the organisation port, whose default is "not active". `organisation_active: true` sets that port to "active" for such a ledger, as the test world does. A ledger with a tenant part ignores it. Without it, no programme draft can be prepared on a pilot cell | ADR-021 "Where the answer comes from" |
| Start | `fstp_cell::run` decodes the file, reads the credentials, opens the cell key file through `key_file_keyd_socket`, draws a new ledger key generation and rewrites the key file before any seal, then runs `process::start_with` over `keyd_socket` on one tokio runtime until SIGTERM or SIGINT drains it | G1; G8; ADR-002 |

## Configuration tests

- `i19_config_names_one_cell` and `i16_config_types_hold_no_debtor_account` over the new grammar (I-19, I-16).
- `i83_config_start_refuses_a_vault_cluster` (I-83).
- `i80_cell_key_file_holds_no_open_key` (I-80).
- `r_nf_02_config_and_key_errors_never_quote_bytes` (R-NF-02).
- `crates/fstp-celltest/tests/prod_mcp_e2e.rs`: section 4.1 of the design over the `fstp-cell` binary.

## Consequences

- An MCP call can execute only what the API core's channel policy lets it execute directly, and only through the gate, as the account that consented. Every high-risk command of an agent becomes a pending action.
- A web call with a step-up commits only while the step-up is fresh at the store's commit instant (I-78), as a cell route does.
- A pending action survives a restart. A confirmation in flight during a crash either committed with its `api.pending_confirmed` row or did not commit at all.
- The ledger key generation now also seals pending requests and workspace values. Its nonce budget counts these seals. Erasing a workspace deletes its rows. It destroys no key.
- Read calls cost one witness round trip each, through their audit event (ADR-010 amendment of 2026-11-20).

## Tests

- `i85_agent_admission_refuses_every_high_risk_action`, `i85_concurrent_confirmations_execute_once`.
- `i78_api_step_up_is_digest_bound_and_single_use_on_pg`, `i78_stale_api_step_up_refused_at_commit`.
- `i77_magic_link_session_refused_for_management_ops_on_pg`.
- `t_authz_matrix_pg_sample`, `i84_audit_parity_on_pg`, `t_cell_and_web_routes_do_not_overlap`.
- `i21_workspace_rows_hold_sealed_bytes_only`, `r_nf_08_api_and_workspace_columns_are_classed`.
- `t_db_m4_migrations_forward_only`, `t_db_app_role_has_no_ledger_update`, `i82_role_plan_grants_api_and_workspace_to_app_only`.
- `i23_restart_replays_pending_and_workspace`.
