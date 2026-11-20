# ADR-026: Production cell composition

Status: Accepted in part. The rows of "Composition" below were decided by Daniel on 2026-11-20 (D2, D6, D8 and D10 of `docs/handoff/production-mcp-design.md` section 2.2). The configuration rows are written by lane L4 before its code.

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

## Record of lane L5 `prod/api-ports`

Written by lane L5 before its code. Each row is interim, pending Daniel, unless it says otherwise. The ports below replace the fail-closed ports of the row "Fail-closed ports" one by one.

| Topic | Reading | Basis |
| --- | --- | --- |
| Invitation port | `Accounts::invite` takes the programme role invitation that `creator.invite` appended. An address with a login email account needs no enrolment: its holder signs in and accepts. An address without one gets a new random account and an M3 enrolment invitation for the same link token, so the landing page enrols the first passkey at `/auth/invitations/{token}/register`. The address is noted for that enrolment, which binds it as the login email, as the command route notes it | J2; ADR-008 "Ceremonies and the first passkey"; design section 4.2 |
| Enrolment invitation | A new cell command `TenantCommand::IssueRoleInvitation`, issued only by the system task `Provisioning` for the accounts port. `decide` admits it only for a live creator invitation by address on that programme, not withdrawn and not accepted. The M3 invitation id is the creator invitation id, so one creator invitation has at most one. The rule is `fstp_auth::ceremony::issue_invitation` with the new issuer `RoleInvitation`. It grants nothing: roles come only from the acceptance and the grant under the SoD guards | J2; SoD-09; I-78 |
| Invitation mail (I-25) | A timeline event of the new kind `ROLE_INVITATION`, sourced by the programme and the creator invitation. The accounts port schedules it through `TimelineCommand::Plan` and fires it at once through `TimelineCommand::Fire`, both under the system task `Timeline`. The fire entry records the template version first and lists the one message, whose body is the composed mail sealed in its `ops.outbox` row in the same append. The timeline's own plan never cancels an event of this kind, and its own firing skips it, since only the port holds the link token | I-25; M6 design sections 3.1 and 4 |
| Invitation template | `role-invitation` version 1, with one slot: the link `/app/invitation#<token>`. The token travels in the URL fragment, so no server request line carries it. The wording is a draft marked `TODO(legal)` | I-27; J2 |
| Delivery (I-26) | Right after the fire entry commits, the port runs one `fstp_dispatch::Worker` over `ops.delivery` for that outbox row, through a `Relay` the cell is started with. The attempt protocol of M6 design section 5.1 holds as for the dispatcher: the COMMITTING row before the final dot, and an unknown outcome left IN_DOUBT, never sent again. The body digest key is derived from the App chain `Lookup` key, as `tasks::dispatch::digest_key` does. Lane L4's configured relay plugs in behind `Relay` at merge. A cell started with no relay refuses the invitation before it records anything, so no invitation waits for a mail that cannot leave | I-26; ADR-018; m4-design section 15.0 "Delivery body digest key" |

## Configuration

Written by lane L4 before its code (`docs/handoff/production-mcp-design.md` section 2.1, rows "Configuration", "Secrets", "Decoder" and "Deployment of the pilot").

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
