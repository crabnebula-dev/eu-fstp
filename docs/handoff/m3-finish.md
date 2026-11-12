# M3 finish: small lanes for the weekend

Written on 2026-11-06 against `main` at `8f3f405`. Read it with `docs/handoff/m3-design.md` (sections 0.4, 14, 19, 20 and 21.0) and `docs/handoff/m3-base.md`. It does not change the design. It cuts what is left of M3 into lanes that one agent can build in a few hours.

## 1. Rules for these lanes

- Daniel asked for M3 to M12 built this weekend, "built even if buggy". A lane may merge with tests still red. Each red test must then be on `ci/known-red.txt` with the next seam it waits on and the lane that closes it.
- Never weaken, skip or mark expected-failure an invariant test. A lane may wire a test-side seam helper (a `*_SEAM` constant or a stub accessor that says "edit once it lands"). It never changes an assertion.
- Fixture changes are allowed where a later decision changed the path a setup must take, as `52cdc5c` did for strict D2e. The commit message names the decision.
- One agent per lane. It writes only the files in its row. A lane removes only its own lines from `ci/known-red.txt`, in the commit that turns them green.
- No new third-party crate or npm package. No Python. Load cap: 4 threads and one test binary at a time (`.lanes/.cargo/config.toml`, `.lanes/testlock.sh`).
- Snapshot with `snapshot.sh --tree <key>` after the tests stage and after the build stage.

Before wave 1, the lead makes one commit to `ci/known-red.txt`. It relabels each "M3 slice-cycle lane" and "M3 or M4 lane to confirm" entry with the lane key from section 4. It also lists the six red slice tests that are not yet listed (`slice_http::slice_cycle_*` five times, `slice_devstack::slice_devstack_serves_healthz_and_stops_on_sigterm`), under F-CYCLE1 and F-CYCLE2.

## 2. What is done

- Cell runtime: routes, engine, `PgRecordStore`, signing, the first-admin split invitation, start-up checks (I-83 server kind, chain verification).
- Control plane protocol, `Placement`, the cell role plan and `pg_hba` renderer, the provisioning jobs (I-82, I-83 green at unit level).
- Authentication: passkeys, magic links, step-up, recovery and break-glass in `fstp-auth` and the gate in `fstp-cell-core`.
- Identity vault core, the vault service loop (`service::serve`), the witness service loop (`fstp_witness::serve`), anchor and receipt signing under ADR-010.
- Key custody: `fstp-keys`, `fstp-custody`, `fstp-keyd` with the ext4 and XFS volume rule.
- ML-DSA-65: moduletto PR #13 merged on 2026-10-29. `fstp-crypto` pins `6c1ae92`, which is moduletto `HEAD` today, and calls `moduletto::dsa::ml_dsa_65`. `mldsa_acvp.rs` and the aws-lc-rs differential tests run. The README line "ML-DSA-65 in moduletto" is out of date.
- The test world starts real SaaS cells: witness, edge, vault and cell per cell, from the production role plan (`fstp-celltest/src/world.rs`).
- ADR-005 names OVHcloud (2026-10-28). That meets the "hosting provider named" exit item. The verify items V1 and V3 stay with L-15 and gate only the R-HS-01 claim.

## 3. What is open per exit item

Causes come from the local runs of 2026-11-06 (`.lanes/logs/m5dom/t-celltest.log`, `.lanes/logs/studio/merge-test.log`).

| Exit item | Main blockers | Lanes |
| --- | --- | --- |
| I-16 | Catalogue: `schema_migrations` catalogued with no migration; `fstp-release-svc/migrations/licence` missing | F-CAT |
| I-17 | Strict D2e refuses the test setup (`I66 GuardFailed`); `run_cycle` has no steps | F-D2E, F-CYCLE2, F-ISO |
| I-18 | `run_cycle` steps; the attestation test is refused with `WrongActor` | F-D2E, F-VAULTP, F-CYCLE2 |
| I-19 | Unclassed `cp` columns; no HTTP client on `CellHandle`; `run_cycle` steps | F-CAT, F-HTTP, F-ISO |
| I-20 | `run_cycle` steps | F-ISO |
| I-24 | `fstp-pgstore` exposes no migrations, roles or pool to the tests; no KeyOp events from the cell keystore; start-up raises before it records; vault chain coverage undecided | F-STORE, F-KEYOP, F-VCHAIN |
| I-38 | The self-hosted world refuses: the local witness file store has no run loop | F-SELF |
| I-39 | Same as I-38 for `i39_cycle_completes_with_services_down` | F-SELF |
| I-77 | Strict D2e setup; the cell roster does not count a suspended binding (m3-base re-derivation 2); no HTTP client | F-D2E, F-AUTHP, F-HTTP |
| I-78 | `HIGH_RISK_TABLE` lacks `ActivateProgramme`; strict D2e setup; step-up table tests need the store | F-D2E, F-STORE |
| I-79 | No HTTP client on `CellHandle` | F-HTTP |
| I-80 | `FSTP_KEY_VOLUME_DIR` unset; no CI memory-scan step; `run_cycle` steps | F-KEYD, F-ERASE |
| I-81 | Same as I-80, plus backups over a real cycle | F-KEYD, F-CRYPTO, F-ERASE |
| I-82, I-83 | `i82_pool_serves_one_cell` waits on `run_cycle`; `i83_self_hosted_layout_runs_two_instances` waits on F-SELF | F-ISO, F-SELF |
| Isolation | `t_iso_*` wait on `run_cycle`; no multi-cell CI job yet | F-ISO, F-EXIT |
| ADR-005 provider | Met (OVHcloud) | F-EXIT records it |

## 4. Lane table

Each row lists the known-red entries the lane turns green. Where a test is red for two reasons, the second lane is named. A lane that turns a test to a later seam relabels its entry instead.

| Key | Builds | Owns | Known-red it turns green | Depends on |
| --- | --- | --- | --- | --- |
| F-D2E | Programme set-up in the M3 tests goes through the creator path (draft, clean report, second-admin activation), as `52cdc5c` did. `ActivateProgramme` joins `HIGH_RISK_TABLE` (basis: m4-design Q10, `authentication.md`). The W0 record test states the M4 addition | `fstp-cell-core/src/gate.rs` (table only); set-up helpers in `fstp-celltest/src/mc/*.rs` and `src/reference/*.rs`; set-up blocks of the listed test files | `w0_high_risk_table::*` (2), `i78_gate_high_risk::*`, `review_m4w1b_activate_programme_gate::*`, `i78_stepup::*` except the two database tests (12), `sod_07_self_grant::*` (2), `sod_08_break_glass::*`, `i24_audit_chain::i24_erasure_entries_are_chained`, `review_seams1_fidelity::*` (2), `system_tasks::*` (2), `i17_identity_release::i17_release_ticket_only_for_operations_in_negotiation`, `adr007_store_and_erasure::adr007_erased_textref_*`, `adr007_erasure_log_*`, `seam_driver_core::*` (3). `i77_login` set-up failures (3) move to their next seam | none |
| F-CAT | Classes for every unclassed column (Q-A), the missing `schema_migrations` migration rows, and the `licence` migration set with its catalogue | every `catalogue.rs` (`fstp-migrate`, `fstp-pgstore`, `fstp-vault`, `fstp-control`); `crates/fstp-release-svc/migrations/**`, `fstp-release-svc/src/catalogue.rs` (new) | `i16_funds::i16_schemas_have_no_fund_class`, `i19_boundary::i19_control_plane_columns_are_declared`, `r_nf_m3::r_nf_08_catalogue_has_no_clear_content_column`, `schema::r_nf_08_app_catalogue_classes_every_column` | Q-A (builds the recommendation as interim) |
| F-STORE | `fstp-pgstore` exposes its cell migrations, writer and owner roles, a pool constructor and a per-case store with crash points between statements. Wire the test-side seams that wait on them | `fstp-pgstore/src/**` except `catalogue.rs`; `fstp-pgstore/migrations/**`; `fstp-ledger/src/async_store.rs`; `fstp-pgstore/tests/common/mod.rs` seams; `tools/deps-check/tests/m3_records.rs` stub list | `i24_audit_chain::{i24_database_refuses_bad_link_and_mutation, i24_ledger_and_chain_commit_together, i24_pg_chain_equals_reference_chain}`, `i78_stepup::{i78_database_refuses_a_second_step_up_consumption, i78_writer_role_holds_insert_and_select_only}`, `adr007_store_and_erasure::adr007_pg_store_matches_mem_store`, `m3_records::w0_new_crate_stubs_refuse_without_panicking_macros` | none |
| F-KEYD | Resume `wip/m3keyd` (section 5). `fstp-keyd` starts on any host and reports `Assurance` instead of refusing. CI gets an ext4 key volume and the memory-scan step | `fstp-obs/src/{assurance,lib}.rs`; `fstp-keyd/**`; `fstp-custody/**`; the `KEY_VOLUME_SEAM` helpers in `fstp-keyd/tests/common` and `fstp-celltest/tests/{i80_custody,i81_backups}.rs`; `.github/workflows/ci.yml` test job only | `serve::*` (10), `review_w1d_fidelity::*`, `review_w1d_keyd_inplace::*`, `review_w1d_strength::*`, `i80_custody::{i80_file_custody_root_confined_to_keyd, i80_memory_scan_runs_in_linux_ci}`, `i81_backups::{i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume, i81_teeth_restored_epoch_file_opens_without_destroy}` | none |
| F-CRYPTO | `CompositeSigningKey` gives its public key. `fstp_backup::decode_container`. The ADR-004 purpose code table, drafted as Proposed (Q-E) | `fstp-crypto/src/composite.rs`; `fstp-backup/**`; `docs/adr/ADR-004-key-custody.md` (that table only); `composite_public_key` in `tests/i75_hybrids.rs` | `i75_hybrids::*`, `r_cr_01_at_rest::*` except `r_cr_01_backups_and_snapshots_use_the_hybrid_kem` (5) | Q-E for the two seal round trips |
| F-KEYOP | The cell keystore makes custody calls with request ids and writes a sealed `KeyOp` event plus a `RecordKeyOp` record (Daniel, 2026-10-29). Start-up records `InDoubtAbsent` before it raises possible deletion (design 7.2) | `fstp-keys/**`; `fstp-cell/src/tasks/erasure.rs`; `fstp-cell/src/engine/startup.rs`; `prod_cell_custody_round` in `fstp-celltest/src/mc/audit_model.rs` | `erasure_runner::*`, `main_startup::*`, `i24_audit_chain::i24_custody_ops_reconcile_with_key_records` | F-STORE |
| F-AUTHP | The cell roster counts a suspended binding as holding for login (m3-base re-derivation 2). The self-grant digest defect from seams1: the grantor's own approval no longer blocks the second admin | `fstp-auth/**`; `fstp-cell-core/src/{state,ops}.rs` | `i77_login::{i77_suspended_holder_magic_link_login_is_refused, i77_m_auth}`, plus the `i77_login` set-up three after F-D2E | F-D2E |
| F-VAULTP | The I-18 attestation path is admitted for the right actor, and the cell never shows `VaultOutcome` records to the IRC actor. Retire the `engine_mem` duplicate by pointing it at the celltest equivalent, if its doc comment says so | `fstp-cell-core/src/{driver,release,decide}.rs`; `fstp-vault-core/**` | `i18_guardian_consent::{i18_cell_asks_adult_attestation_before_guardian_ticket, i18_r_ng_01_irc_actor_is_never_shown_the_vault_outcomes}`, `seam_m_driver::*`, `engine_mem::*` | F-D2E |
| F-HTTP | `CellHandle` gets an HTTP client over the soft authenticator. Auth, recovery and session routes are reachable from the world | `fstp-celltest/src/{world,soft_authn}.rs` (client part); `fstp-cell/src/routes/auth.rs`; `fstp-cell/src/http/**` | `i19_boundary::i19_session_of_one_cell_is_refused_by_another`, `i79_recovery::*` (3), `i77_login::i77_management_login_requires_phishing_resistant_method_over_http`, `r_lg_04_sessions_and_devices::*` | F-D2E |
| F-CYCLE1 | `World::run_cycle` steps `login`, `create-programme` (creator draft, report, second-admin activation, each with step-up) and `publish-call`. The devstack finds the compiled auth pages | `fstp-celltest/src/world.rs` (`run_cycle`, `CycleScript`); `fstp-celltest/src/bin/fstp-devstack.rs`; `tools/devstack/**` | slice: `slice_cycle_r_pc_03_*`, `slice_devstack_*` | F-HTTP |
| F-CYCLE2 | Steps `signup`, `verify-identity` (test-only seeding, design 6.9), `submit-proposal`, `score`, `rank`, `negotiate`, `grant` | as F-CYCLE1; `fstp-celltest/src/vault_seed.rs` | slice: the other four `slice_cycle_*`; `seam_world::*` (10); `i18_guardian_consent::i18_no_minor_flagged_proposal_reaches_granted_without_consent` | F-CYCLE1 |
| F-ISO | Fix what the cycle shows in the multi-cell scans. Check the `i82_no_remote_role_has_createrole_or_createdb` "database does not exist" race in the shared clusters | `fstp-cell/src/{egress,process,config}.rs`; `fstp-edge/**`; `fstp-control/src/isolation_audit.rs` | `t_iso_i19::*` (2), `t_iso_i20::*`, `i19_boundary::{i19_cell_process_serves_one_cell, i19_only_registered_metadata_crosses}`, `i20_tenants::*` (2), `i82_role_plan::i82_pool_serves_one_cell`, `r_nf_m3::r_nf_09_*`, `i17_identity_release::*` cycle three | F-CYCLE2, F-CAT |
| F-ERASE | Erasure and backups over a real cycle | `fstp-cell/src/tasks/erasure.rs` and `fstp-backup/**` after F-KEYOP and F-CRYPTO merge | `i81_backups::*` cycle six, `i80_custody::i80_root_canary_absent_from_logs_dumps_and_backups`, `r_cr_01_at_rest::r_cr_01_backups_and_snapshots_use_the_hybrid_kem`, `r_id_03_documents::*`, `r_sw_02_cell_erasure::*`, `r_nf_m3::r_nf_08_aborted_append_never_reuses_a_nonce` | F-CYCLE2, F-KEYD, F-KEYOP, F-CRYPTO |
| F-SELF | A run loop for the local witness over `file_store.rs`, then a self-hosted cell in the test world. No packaging or installer (B-06 stays deferred) | `fstp-witness/src/{file_store,service}.rs`; the self-hosted branch of `start_cell` in `world.rs` | `i38_egress::i38_self_hosted_*` (3), `i39_licence::i39_cycle_completes_with_services_down`, `i83_placement::i83_self_hosted_layout_runs_two_instances`, `r_nf_m3::r_nf_05_self_hosted_install_has_no_default_credentials` | Q-B; F-CYCLE1 for the `world.rs` edit |
| F-VCHAIN | The vault chain writer for `vault_audit.chain` under Q-C. The vault stops answering 503 once its journal holds a write | `fstp-vault/src/**` except `catalogue.rs` | none listed. Keeps `i24_vault_chain_anchored_by_the_vault_only` and `i24_m_audit` green against the real vault | Q-C, F-STORE |
| F-CP | Process configuration and run loops for `fstp-control`, `fstp-pgagent` and `fstp-witness` (SaaS). `fstp-install` stays a refusal under B-06. Destructive jobs keep refusing until the two-operator check exists | `fstp-control/src/{placement,pgagent,api}.rs`, `src/bin/{fstp-control,fstp-pgagent}.rs`; `fstp-witness/src/lib.rs` and a new `config.rs` | none listed | Q-D for the witness receipt key |
| F-EXIT | Multi-cell isolation CI job, `tests/teeth_m3_registry.rs` (design 19, W4), `docs/handoff/m3-exit-audit.md` with each scoped claim of NOTE 2, the README M3 status | `.github/workflows/ci.yml` (isolation job); `fstp-celltest/tests/teeth_m3_registry.rs`; `fstp-celltest/src/mc/tripwires.rs`; `docs/handoff/m3-exit-audit.md`; `README.md` M3 lines | whatever is left, or relabel it | every lane above |

Waves: (1) F-D2E, F-CAT, F-STORE, F-KEYD, F-CRYPTO. (2) F-HTTP, F-AUTHP, F-VAULTP, F-KEYOP, F-SELF witness part. (3) F-CYCLE1, then F-CYCLE2, with F-VCHAIN beside them. (4) F-ISO, F-ERASE, F-CP. (5) F-EXIT. Run only as many at once as the lead's slot cap allows.

## 5. Resuming the keyd lane from `wip/m3keyd`

`origin/wip/m3keyd` is `780067c`, one snapshot commit on `4847537`, which is already on `main`. It adds one file, `crates/fstp-obs/src/assurance.rs` (443 lines). That file holds `DeploymentMode`, `FSTP_DEPLOYMENT_MODE`, `resolve_mode`, `ReducedReason` (22 reasons), `Assurance` with a two-byte encoding, and `HostCheck`. Nothing registers it yet, and `fstp-keyd` still refuses any volume that is not ext4 or XFS on Linux.

```sh
cd /Users/denjell/git/eu-fstp && git fetch origin
git worktree add -b m3/keyd-assurance .lanes/m3keyd origin/main
git -C .lanes/m3keyd checkout origin/wip/m3keyd -- crates/fstp-obs/src/assurance.rs
```

Then, in order:

1. Add `pub mod assurance;` to `fstp-obs/src/lib.rs`. Write unit tests for the mode rules first: a release build refuses an unset or misspelt mode; a debug build defaults to development and logs `DeploymentModeUnset`.
2. Change `fstp-keyd/src/volume.rs` so `check_key_volume` returns an `Assurance`, not an error, for a volume outside ext4 and XFS. `key_volume_accepted` stays the one decision for `Full`. No host reports `Full` except Linux ext4 or XFS without `data=journal`.
3. `fstp-keyd` logs the assurance in its start event. In development mode no host check stops a start (I-81 NOTE, design 21.0 row of 2026-11-01).
4. Test harness reading (Q-F): with `FSTP_KEY_VOLUME_DIR` unset, the keyd tests use a temporary directory, and every assertion still runs. Each test that needs `Full` asserts `Full` only when the volume reports it. Elsewhere it asserts `Reduced` with a reason. A guard test fails on Linux CI when `FSTP_KEY_VOLUME_DIR` is unset, so the full path is never skipped there.
5. CI: in the Linux test job, create a loop-mounted ext4 image, export `FSTP_KEY_VOLUME_DIR`, and run the two process-memory tests that `i80_memory_scan_runs_in_linux_ci` names.
6. Rewrite the stale comments that say keyd starts only on Linux. Snapshot with `snapshot.sh --tree m3keyd`.

## 6. ML-DSA-65: what the platform side needs

- For the M3 exit: nothing more in moduletto. F-CRYPTO adds the public key accessor that `i75_hybrids` waits on. The exit audit states that the I-24 tests ran against moduletto `6c1ae92`, not the aws-lc-rs oracle.
- For a release (not M3): a Mythos confirmation of `6c1ae92` in `deps/tier-b-confirmations.txt` (I-74). PR #13 also left one box open: no independent security review of the ML-DSA code yet.
- If Daniel merges a later moduletto PR, the pin move follows the ADR-001 A2 pin move record, `deps/allowlist.txt` and `deps-check`. A pin move resets the Tier B confirmation.

## 7. Questions that block a lane

Each lane builds the recommendation, marked "Interim, pending Daniel", until he answers.

- **Q-A (F-CAT). Classes for unclassed columns.** Recommendation: `server_spki`, `cose_key` and `group_key.public_key` take the public key material class. `stored_hash`, `link`, `ack_link` and `action_digest` take the public digest class. Both `receipt` columns take the signature class. `endpoint` and `host` take the interim Infrastructure class of ADR-009. `org_ref`, `key_ref`, `case_ref`, `keystore.root.handle` and `ops.outbox.idem` take a new closed "opaque reference" class, checked by length and alphabet. `schema_migrations` columns take the Migration class. `ledger.command` gets its sealed column named.
- **Q-B (F-SELF). Do the self-hosted tests stay in M3 now that B-06 is deferred?** B-06 defers "the full suite on a self-hosted cell". I-38 and I-39 are still in the M3 exit. Recommendation: keep them in M3 and build the test-world self-hosted cell only, with no packaging. Decided by Daniel on 2026-11-13: accepted.
- **Q-C (F-VCHAIN). Vault chain coverage, ADR-010 open point 5.** Recommendation: each committed fact batch and each identity release or read (R-AU-01) is a kind 1 row. A KeyOp stays an event only, as Daniel decided on 2026-10-29 for the vault. Decided by Daniel on 2026-11-13: accepted.
- **Q-D (F-CP). Receipt key custody of the witness, ADR-010 open point 6.** Recommendation: the proposed separate `fstp-keyd` entry with its own credential, recorded in ADR-004 part 2. Decided by Daniel on 2026-11-13: accepted.
- **Q-E (F-CRYPTO). The ADR-004 purpose code table.** It is ADR-required and not recorded, so `Ledger` has no code. Recommendation: F-CRYPTO drafts one code per existing `fstp-keys` purpose, in declaration order, as Proposed. Daniel accepts it before the lane merges.
- **Q-F (F-KEYD). Key-volume tests on hosts without ext4.** Recommendation: section 5 step 4. It follows Daniel's decision of 2026-11-01 and keeps the full claim on Linux CI.

No legal text is needed for these lanes. If a lane meets a legal point (L-02 guardian consent wording, the OVHcloud contracting entity under L-15), it leaves `TODO(legal)` for Daniel.
