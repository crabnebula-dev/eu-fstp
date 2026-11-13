# M9 exit audit (lane M9 finish)

Written on 2026-11-13 on branch `m9/finish`, based on `main` at `e5815413`. It maps each M9 exit invariant and each R-ID of `docs/handoff/m9-design.md` section 4.1 to the tests that verify it and the CI job that runs them. It does not close M9. `SPEC/09-milestones.md` closes a milestone only when its exit criteria pass in CI, and the lead checks that run.

## Method

- Test names were found by searching `crates/`, `tools/`, `web/test/` and `e2e/` for the ID in the function name or the doc comment.
- The CI job of each test comes from `.github/workflows/ci.yml`. The `test` job runs in parts: `workspace` (every crate but `fstp-api-testkit` and `fstp-domain-testkit`), `api-testkit` (without the two matrix tests), `matrix-http-0` to `-3` and `matrix-direct-0` to `-11`. The `web` job runs `tsc` and `web/test`. The `fuzz-smoke` job runs every fuzz target for 60 seconds. The `sbom` job writes the SBOM twice and compares the bytes.
- No CI job runs the Playwright specs under `e2e/`. They run against the demo cell (`tools/demo/run.sh e2e`).
- Each part of the `test` job is judged against `ci/known-red.txt`. No M9 test is listed there. `fstp_api_testkit::matrix::tests::t_authz_matrix_direct` is listed as a whole.
- "Local" names what this lane ran on 2026-11-13 on an Apple machine, within the lane limits of `.lanes/.cargo/config.toml`. Every test named there passed. The `sbom` unit tests of `tools/deps-check` passed too (9 tests). Fuzz targets were not run locally.

## Exit invariants

| ID | Tests | CI job | Local run in this lane |
| --- | --- | --- | --- |
| I-41 | `i41_never_granted_never_public`, `i41_choice_commands_on_a_draft_are_refused_in_every_stage` (`fstp-api-testkit/tests/i41_i42_i43_m9_public_choices.rs`); `i41_proposal_before_granted_never_appears`, `i41_i42_i43_p54_public_view_filters_hold_in_every_state` (`i41_i42_i43_p54_public_view_filters.rs`); `i41_choice_ops_refused_before_their_states` (`fstp-api-testkit/src/harness_m9_publicity.rs`); `i41_publicity_view_is_the_leads_from_granted_on` (`fstp-access/tests/m9p1_publicity_registry.rs`) | `test` api-testkit; `test` workspace for `fstp-access` | Passed: `i41_i42_i43_m9_public_choices.rs`, `i41_i42_i43_p54_public_view_filters.rs`, the `harness_m9_publicity` tests, `fstp-access` |
| I-42 | `i42_minor_never_named` (`i41_i42_i43_m9_public_choices.rs`); `i42_minor_grant_never_appears` (`i41_i42_i43_p54_public_view_filters.rs`); `i42_unknown_proposal_reads_as_minor_flagged` (`fstp-domain/src/view.rs`); `i42_visibility_screen_disables_levels_for_a_minor` (`web/test/m9p2_visibility.test.ts`) | `test` api-testkit; `test` workspace; `web` | Passed: the two api-testkit files above, `web/test` |
| I-43 | `i43_lower_of_max_and_choice`, `i43_withdrawal_and_narrowing_immediate` (`i41_i42_i43_m9_public_choices.rs`); `i43_grant_shows_at_the_lower_of_maximum_and_choice`, `i43_q11_grant_without_choice_is_hidden_in_every_stage` (`i41_i42_i43_p54_public_view_filters.rs`); `r_pb_02_i43_choice_shows_and_withdrawal_hides_at_once` (`harness_m9_publicity.rs`) | `test` api-testkit | Passed: the two api-testkit files above, the `harness_m9_publicity` tests |
| I-44 | `i44_profile_fields_are_ledger_folds`, `i44_seeded_mismatch_fails_generation` (`fstp-report/tests/i44_profiles.rs`, under HE v1 and the synthetic profile); `i44_periodic_figures_equal_an_independent_fold`, `i44_seeded_mismatch_fails_generation_and_is_listed` (`fstp-report/tests/i44_reconciliation.rs`). Fuzz target `funder_profile_parse` | `test` workspace; `fuzz-smoke` | Passed: `i44_profiles.rs`, `i44_reconciliation.rs`. Fuzz not run |
| I-68 | `i68_fuzzed_branding_is_data`, `i68_parser_refuses_malformed_tokens`, `i68_parse_canonical_round_trip` (`fstp-brand/tests/brand.rs`); `i68_css_holds_only_token_values`, `i68_css_has_no_url_import_or_comment` (`fstp-brand/tests/css.rs`); `i68_csp_unchanged` (`fstp-web/tests/i68_csp.rs`); `i68_brand_css_is_served_by_digest_only`, `i68_brand_path_grammar_is_closed` (`fstp-web/src/brand.rs`); `i68_shell_links_brand_sheet_for_a_valid_digest_only` (`fstp-web/src/shell.rs`); `i68_current_brand_is_the_css_of_the_set_tokens` (`fstp-api-testkit/tests/m9b2_brand_read.rs`); `i68_branding_fuzz_seeds_decode_to_their_operations` (`fstp-api-core/tests/m9b1_branding_seeds.rs`); `i68_web_branding_body_is_typed_tokens` (`web/test/m9p2_admin_branding.test.ts`). Fuzz target `branding_parse` | `test` workspace; `test` api-testkit; `web`; `fuzz-smoke` | Passed: `fstp-brand`, `i68_csp.rs`, `m9b2_brand_read.rs`, `web/test`. Fuzz not run |
| I-69 | `i69_footer_survives_any_branding`, `i69_footer_carries_the_pinned_funder_profile_elements` (`fstp-public/tests/i69_footer.rs`); `i69_cell_public_page_footer_carries_the_pinned_profile_elements` (`fstp-api-testkit/tests/r_pb_04_public_routes_on_a_cell.rs`); `i69_he_visibility_wording_is_pending_legal` (`fstp-report/tests/r_rp_01_p53_pins_profile.rs`) | `test` workspace; `test` api-testkit | Passed: `fstp-public` (all), `r_pb_04_public_routes_on_a_cell.rs`, `r_rp_01_p53_pins_profile.rs` |
| I-70 | `i70_accepted_iff_all_pairs_pass`, `i70_refusal_lists_failing_pairs`, `i70_pair_table_covers_light_and_dark`, `i70_pair_set_bits_round_trip` (`fstp-brand/tests/brand.rs`); `i70_branding_set_accepted_iff_all_pairs_pass`, `i70_failing_branding_record_does_not_fold` (`fstp-tenant/tests/branding.rs`); `i70_branding_check_lists_pairs_and_saves_nothing` (`fstp-access/tests/m9b1_branding.rs`); `i70_branding_check_lists_failing_pairs_and_saves_nothing`, `i70_branding_set_with_a_failing_pair_is_refused` (`fstp-api-testkit/tests/m9b1_branding_dispatch.rs`); the M4 bound tests `i70_contrast_bounds_enclose_f64_values` (`fstp-api-testkit/src/reference/creator.rs`) and `i70_contrast_edge_is_exact_at_four_point_five` (`fstp-creator/src/tests.rs`); `i70_branding_screen_lists_failing_pairs_and_saves_only_when_all_pass`, `i70_web_check_reply_accepted_iff_no_pair_fails`, `i70_web_platform_palette_and_pairs_repeat_fstp_brand` (`web/test/m9p2_admin_branding.test.ts`) | `test` workspace; `test` api-testkit; `web` | Passed: `fstp-brand`, `fstp-tenant`, `fstp-access` (all), `m9b1_branding_dispatch.rs`, `web/test` |
| I-90 | `i90_every_verifier_rejects_one_half`, `i90_every_composite_verify_call_site_is_in_the_table` and their teeth (`fstp-celltest/tests/i90_every_verifier.rs`, notice companion row included); `i90_claim_moduletto_signs_aws_lc_rs_verifies_1000`, `i90_claim_aws_lc_rs_signs_moduletto_verifies_1000` (`fstp-celltest/tests/i90_claim_mldsa_differential.rs`, at least 1000 inputs each way); `i90_composite_verify_rejects_either_half_alone` and its teeth (`fstp-celltest/tests/i90_composite_verify.rs`); `i90_composite_verify_rejects_either_half_alone_of_production_signatures` (`fstp-crypto/tests/composite_api.rs`); `i90_verify_rejects_an_anchor_with_either_half_alone`, `i90_verify_rejects_a_receipt_with_either_half_alone` (`fstp-audit/tests/signatures.rs`) | `test` workspace | Passed: `i90_every_verifier.rs`, `i90_claim_mldsa_differential.rs`, `i90_composite_verify.rs`, `composite_api.rs`. `fstp-audit` not rerun |

Supporting rows of section 4.1:

| ID | Tests | CI job | Local run in this lane |
| --- | --- | --- | --- |
| I-72 | `i72_tenant_pack_labels_only`, `i72_tenant_pack_naming_approved_wording_is_refused` (`fstp-journey/tests/i72_tenant_pack.rs`); `i72_terminology_set_folds_and_replaces` (`fstp-tenant/tests/terminology.rs`); `i72_terminology_set_refuses_approved_keys_and_fixed_wording` (`fstp-api-testkit/tests/m9t1_terminology_dispatch.rs`); `i72_terminology_screen_sends_labels_of_the_closed_list`, `i72_web_terminology_body_names_editable_keys_only` (`web/test/m9p2_admin_branding.test.ts`). Fuzz target `vocab_parse` | `test` workspace; `test` api-testkit; `web`; `fuzz-smoke` | Passed: `fstp-journey`, `fstp-tenant`, `m9t1_terminology_dispatch.rs`, `web/test`. Fuzz not run |
| I-75 | `i75_pq_only_through_hybrids` and its teeth (`fstp-crypto/tests/i75_pq_only_through_hybrids.rs`); the scans of `fstp-crypto/tests/source_scans.rs`; `i75_repository_crates_pass_the_scan` (`tools/deps-check/src/pq_hybrid.rs`) | `test` workspace; `deps-check` | Passed: `i75_pq_only_through_hybrids.rs`, `fstp-celltest/tests/i75_hybrids.rs`, `mldsa_acvp.rs` |
| I-87, I-94 | covered by the I-41 to I-43 rows and by `i72_tenant_pack_labels_only` | as above | as above |

## Requirements of section 4.1

| ID | Tests | CI job |
| --- | --- | --- |
| R-PB-01 | `r_pb_01_funded_and_finished_pages_list_their_own_grants`, `r_pb_01_programme_page_links_every_open_call` (`fstp-public/tests/r_pb_04_pages.rs`); `r_pb_01_finished_list_shows_included_deliverables` (`fstp-public/tests/m9p2_finished_deliverables.rs`) | `test` workspace |
| R-PB-02 | `r_pb_02_choice_ops_carry_the_core_commands_web_only` (`fstp-access`); `r_pb_02_former_lead_sets_the_finished_choice`, `r_pb_02_i43_choice_shows_and_withdrawal_hides_at_once` (`harness_m9_publicity.rs`); `r_pb_02_narrowed_or_withdrawn_choice_leaves_the_next_view`; `r_pb_02_visibility_screen_shows_and_saves_a_choice` (`web/test/m9p2_visibility.test.ts`) | `test` workspace; `test` api-testkit; `web` |
| R-PB-03 | `r_pb_03_client_text_reference_and_other_actors_refused` (`harness_m9_publicity.rs`); `r_pb_03_proposal_text_never_reaches_a_public_output`; `r_pb_03_cell_router_public_answers_hold_no_script_and_no_proposal_text`; `r_pb_03_set_body_carries_texts_as_text` (web) | `test` api-testkit; `web` |
| R-PB-04 | `r_pb_04_every_page_is_wellformed_and_scriptless`, `r_pb_04_view_text_is_escaped_never_markup` and the other tests of `fstp-public/tests/r_pb_04_pages.rs`; `r_pb_04_public_pages_carry_the_scriptless_csp` and the TH-37 tests of `fstp-api-testkit/tests/r_pb_04_public_pages_scriptless.rs`; `r_pb_04_cell_router_public_answers_carry_the_csp_and_set_no_cookie` | `test` workspace; `test` api-testkit |
| R-PB-05 | `r_pb_05_p54_aggregates_withheld_over_real_records` (`i41_i42_i43_m9_public_choices.rs`); `r_pb_05_aggregate_appears_only_at_p54`, `r_pb_05_i43_aggregate_never_reveals_a_hidden_amount` | `test` api-testkit |
| R-WL-03 | The I-68, I-69 and I-70 rows above. The doc comments of `web/test/m9p2_admin_branding.test.ts` and `e2e/admin/branding.spec.ts` cite it | as those rows; the e2e spec runs outside CI |
| R-WL-04 | The `platform_attribution` element of `i69_footer_survives_any_branding` and of the web footers (`web/src/creator/frame.ts`, `web/src/shell/brand.ts`); the Playwright footer checks of `e2e/creator/support.ts` | `test` workspace; the e2e specs run outside CI |
| R-WL-05 | The I-72 row; `r_wl_05_web_plain_pack_repeats_the_shipped_pack_and_fixed_keys` (`web/test/m9p2_admin_branding.test.ts`); `r_wl_05_web_catalogue_labels_are_the_plain_pack` (`web/test/vocab.test.ts`) | `test` workspace; `web` |
| R-RP-01 | `r_rp_01_p53_pins_the_shipped_profile_version`, `r_rp_01_unshipped_p53_resolves_to_nothing` (`fstp-report/tests/r_rp_01_p53_pins_profile.rs`); `r_rp_01_each_output_is_deterministic_for_equal_ledgers` (`r_rp_01_deterministic.rs`); `r_rp_01_funder_profile_view_is_the_report_readers_read` (`fstp-access/tests/m9_funder_profile_registry.rs`); `r_rp_01_funder_profile_view_shows_the_pinned_profile_to_report_readers` (`fstp-api-testkit/src/harness_m9_funder_profile.rs`); `r_rp_01_reports_page_shows_the_pinned_funder_profile` (`web/test/m9_funder_profile.test.ts`) | `test` workspace; `test` api-testkit; `web` |
| R-RP-02 | The I-44 row. `fstp-report/tests/i44_profiles.rs` and `i44_reconciliation.rs` cite it in their doc comments | `test` workspace |
| R-NF-07 | `r_nf_07_sbom_matches_tree`, `r_nf_07_sbom_marks_build_time_tools`, `r_nf_07_sbom_tier_b_carries_confirmation_status`, `r_nf_07_sbom_two_runs_give_identical_bytes` (`tools/deps-check/src/sbom.rs`); `r_nf_07_sbom_cli_writes_identical_bytes` (`tools/deps-check/tests/sbom.rs`) | `test` workspace; `sbom` |

## Added by this lane

- Admin screens for branding and terminology, reached from Home (`web/src/admin/branding/`). Web tests above, and `e2e/admin/branding.spec.ts`, which passed against the demo cell `reset` scene.
- The pinned profile's visibility elements in the public footer (I-69).
- The notice companion key in the App chain keystore, created, resealed each epoch and rotated: `r_cr_04_keystore_holds_and_rotates_the_notice_companion_key` (`fstp-cell/tests/erasure_runner.rs`). The stored form of `NoticeCompanionSigned`: `r_cr_04_stored_form_round_trips_and_is_canonical`, `r_cr_04_stored_form_refuses_other_shapes` (`fstp-contract-core/src/notice.rs`), `r_cr_04_notice_carries_its_stored_companion_signature` (`fstp-contract/tests/r_cr_04_notice_companion.rs`), and the fuzz target `notice_companion_decode`.
- The read `programme.funder_profile.view`. The narrowed matrices passed locally with `FSTP_MATRIX_OPS=programme.funder_profile.view`: the direct matrix (1 test) and the HTTP matrix (5 tests).

## Not claimed

- I-71: custom domains and full white-label packages are deferred (B-09, Daniel 2026-11-04).
- I-73: cross-tenant templates (M4 Q17).
- I-74: `deps/tier-b-confirmations.txt` lists the Tier B crates and records no confirmation. `deps-check --release` stays red until the Mythos confirmation of `moduletto` at its pinned commit (M10).
- I-39 with export: `SPEC/09-milestones.md` says M9 reruns I-39 with export. Export and import are deferred (B-07), so no export rerun exists.

## Interim decisions still pending Daniel

- D1 to D6 of `m9-design.md` section 1.3.
- PD1 to PD12 of "P lanes: decisions taken".
- FD1 to FD10 and CD1 to CD5 of "F1 and C2: decisions taken". MD5 and MD6 replace the last sentence of FD9. MD7 to MD9 complete CD3 and CD4.
- MD1 to MD10 of "M9 finish: decisions taken".
- The ADR-004 record lines of lane C2 and of M9 finish.
- The funder visibility wording stays a `TODO(legal)` placeholder until Daniel supplies the approved text (section 6, accepted 2026-11-13).

## Open questions

- The open questions of the P lanes, F1 and C2, and M9 finish sections of `m9-design.md`.
- `erasure_runner::i24_cell_erasure_runner_records_a_key_op_for_each_custody_change` is in `ci/known-red.txt` with a conflict raised to Daniel. Creating the notice companion key makes no custody call, so it adds no key record either way.
- The Playwright specs, including the new branding spec, run outside CI. Should a CI job run them?
