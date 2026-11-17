# M4 exit audit

Written on 2026-11-17 by the lead, on `main` at `0a54b50d`. It maps each row of the M4 exit checklist (`docs/handoff/m4-design.md` section 14) to the tests that exist under those or other names. It closes M4, with the open items listed below.

## The closing run

Full-tier CI run 44115329811 on `0a54b50d` (started 2026-11-17 15:31 UTC, finished 17:44 UTC) passed all 43 jobs:

- deps-check, fmt and clippy, the SBOM job, and the web job (tsc, web tests, fuzz harness, generated types);
- fuzz smoke, four shards, 60 seconds per target;
- the test parts: workspace, api-testkit, domain-testkit, devstack, m-activate, isolation-multi-cell, celltest, celltest-login, celltest-recovery and celltest-sessions;
- all 12 direct, 4 HTTP and 8 MCP matrix shards;
- the demo browser suite (Playwright).

The two full runs before it (44047751974 on `11f336af` and 44073887881 on `afe942a2`) each passed 42 of 43 jobs. Only Playwright failed, each time on a race or an oracle in the test, not in the product. Lanes e2e/flake-a to flake-c then reviewed every spec for the same kinds of fault.

## Method

- Each test name in section 14 was searched for in `crates/`, `tools/`, `web/test/` and `e2e/`.
- Where the name is absent, the table names the test that covers the row instead, or lists the row as open.
- "Renamed" means a test with a different name checks the same property.

## Checklist rows

| Criterion | Tests that exist | Models and teeth | Open |
| --- | --- | --- | --- |
| SuperSAFE built in the creator | `r_pg_01_supersafe_fixture_matches_policy_defaults`, `r_pg_01_every_programme_parameter_has_one_field` (`fstp-programme`); renamed: `r_pg_01_i50_supersafe_fixture_compiles_with_every_field_set` for `..._compiles_and_validates`; `d3_preview_grant_equals_grant_on_activated_copy` (domain-testkit); `e2e/creator/supersafe.spec.ts` with `r_pg_02_supersafe_built_through_creator_api` | none in the design | `r_pc_03_builder_authorship_survives_activation` is not built. The `r_pc_03_*` tests in `r_pc_03_publication_needs_independent_approval.rs` cover the drafter and P-01 author rules, but not across activation |
| Call cycle to NEGOTIATION | `slice_cycle_full_call_cycle_reaches_granted` (`fstp-celltest/tests/slice_http.rs`, through NEGOTIATION to GRANTED over HTTP); `lifecycle_states_reachable_up_to_negotiation`; `d13_sweep_expires_stage2_at_p07`; renamed: `i52_publication_recomputes_a_clean_report_missing_section` and `..._unresolved_placeholder` for `i52_publication_recomputes_clean_report`; the demo specs under `e2e/journey/` and `e2e/review/` | none in the design | `r_ev_03_exactly_75_percent_does_not_pass_through_the_interface` is not built. R-EV-03 is checked in the domain only, by `i08_r_ev_03_three_quarters_does_not_exceed_75_00` and `i08_reference_edge_case_is_exactly_75_percent`. The `..._via_agent.spec.ts` cycle spec is not built |
| Authorisation matrix | `t_authz_matrix_direct`, `t_authz_matrix_http`, `i84_t_authz_matrix_mcp_equals_channel_policy_of_web`, `t_authz_matrix_covers_every_rule`, `t_authz_denial_has_no_effect`, `d11_every_read_has_a_rule_in_every_state` | `t_authz_teeth_extra_cell_is_caught`, `..._missing_cell_is_caught`, `..._reference_flip_is_caught` | `t_authz_matrix_pg_sample` (2,000 cells on `PgRecordStore`) is not built |
| I-65 | All six named tests | `i65_m_import`, `i65_teeth_auto_applied_proposal_is_caught` | none |
| I-66 | All nine named tests (`i66_witnesses_cannot_be_forged` as compile-fail twins in `fstp-creator/src/twins.rs`) | `i66_m_activate`, `i66_teeth_stale_report_accepted_is_caught` | none |
| I-67 | All five named tests | `i67_m_activate`, `i67_teeth_builder_approval_is_caught` | none |
| I-84 | `i84_t_authz_matrix_mcp_equals_channel_policy_of_web`, `i84_every_tool_has_a_web_route`, `i84_principal_has_no_public_fields`, `i84_one_tool_table`, `i84_roles_reevaluated_per_call`; renamed: the deps-check fixtures `i84_layering_m4_a1_*`, `..._a2_*` and `..._a2b_*` for `i84_adapters_cannot_name_engine_types`; `i84_d6_p75_off_refuses_content_through_mcp_only` and the matrix unit test `i84_mcp_team_reads_own_content_while_p75_bars_others` for `i84_applicant_reads_own_proposal_through_mcp_with_p75_off` | `i84_m_parity` (662 states), `i84_teeth_mcp_only_shortcut_is_caught` | The two audit properties are examples only. `i84_mcp_audit_entry_names_agent_client` checks one accepted and one refused MCP call. No property runs random sequences on both channels |
| I-85 | Seven of eight named tests | `i85_m_prep`, `i85_teeth_confirm_without_digest_check_is_caught` | `i85_concurrent_confirmations_execute_once` on PostgreSQL is not built. `i85_pending_store_is_per_account_and_closes_once` covers the in-memory store only |
| I-86 | `i86_canary_crawl_over_every_tool_role_and_state`, `i86_no_canary_in_logs_or_metrics`, `i86_declared_country_never_reaches_app_tables` (`fstp-celltest`, PostgreSQL); renamed: `i86_layering_m4_a5_vault_boundary` (deps-check) for `i86_mcp_cannot_reach_vault_types` | `i86_teeth_identity_field_leak_is_caught` | `i86_identity_types_are_not_mcp_safe`, the compile-fail twins for `VaultBound<T>`, `IdentityAttribute`, `BankDetails`, `VaultOutcomeRow` and `AccountContact`, is not built |
| I-87 | `i87_feed_equals_pages`, `i87_page_render_trace_equals_view_leaves`, `i87_every_view_leaf_reaches_its_page`, `i87_equal_views_give_equal_page_bytes`, `i87_authenticated_public_tools_equal_public_endpoint`, `i87_two_cells_never_cross` (isolation-multi-cell); renamed: `i87_public_tools_on_mcp_public_equal_public_view` | `i87_m_public`, `i87_teeth_tool_reads_state_directly_is_caught`, `i87_teeth_filter_skipped_for_feed_is_caught` | `t_iso_public_rate_limit_keys_are_per_cell` is not built. The cell's public routes keep no rate limit |

Every fuzz target ran in the four fuzz smoke shards of the closing run.

## Open after M4

Daniel decided on 2026-11-16 to build the key gaps and then close M4. The items below stay open. None weakens an invariant test that exists.

1. `t_authz_matrix_pg_sample`: the matrix sample on PostgreSQL.
2. `i85_concurrent_confirmations_execute_once` on PostgreSQL.
3. `i86_identity_types_are_not_mcp_safe`: the compile-fail twins.
4. The I-84 audit properties over random sequences on both channels.
5. `r_ev_03_exactly_75_percent_does_not_pass_through_the_interface`.
6. `r_pc_03_builder_authorship_survives_activation`.
7. `t_iso_public_rate_limit_keys_are_per_cell`, and a rate limit on the cell's public routes.
8. The public text class. Daniel chose "copy at publication" on 2026-11-17. Until it is built, the production cell (`NoPublicTexts`) shows programme pages with no open call.
9. The cell's public routes differ from the web adapter: no platform stylesheet, the router's empty 404, and gating by activation only.
10. The country code: the vault grammar holds a 1 to 999 code, while `fstp-api-core` takes an alpha-2 code. The registry route still names a body the production cell does not take. This needs Daniel.
11. Suspected browser spec flakes left unchanged by the flake review: the async response handlers of the devstack specs i17, i20 and i77; `waitForTimeout(2500)` in `e2e/mail/mail.spec.ts`; the day boundary of the assess daily limit; and `#page-status:not(:empty)` in `e2e/speedrun/speedrun.ui.spec.ts`.
