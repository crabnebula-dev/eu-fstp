//! The M3 teeth registry (design sections 19 and 20, lane W4).
//!
//! A check that cannot fail proves nothing. For each M3 exit invariant
//! the registry lists the teeth tests that prove its check can fail: each
//! seeds one fault and asserts that the invariant's test, model or scan
//! catches it. The teeth tests themselves live in their W1 lanes' files.
//!
//! These tests check the registry, not the teeth. Every teeth test runs
//! in its own binary and fails CI when its seeded fault goes unseen.
//! This file fails when:
//!
//! - an exit invariant has no registered teeth and no named gap;
//! - a registered teeth test is missing, is not a `#[test]`, or is
//!   ignored;
//! - a teeth test named in design section 20 is not registered;
//! - a teeth test for an exit invariant exists but is not registered;
//! - every registered teeth test of an invariant is on the known-red list;
//! - a model of design section 14.2 has no measured count, is not bounded
//!   by its tripwire, or has a teeth mutant that is not registered;
//! - the multi-cell isolation CI part and the workspace part do not run
//!   each isolation test exactly once between them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fstp_celltest::mc::tripwires::{M3_MODELS, NOT_MEASURED};

/// A registered teeth test: the file that defines it, relative to the
/// repository root, and its function name.
#[derive(Clone, Copy, Debug)]
struct Teeth {
    file: &'static str,
    name: &'static str,
}

const fn t(file: &'static str, name: &'static str) -> Teeth {
    Teeth { file, name }
}

/// One exit row: the row label of design section 20 and its teeth.
struct Row {
    invariant: &'static str,
    teeth: &'static [Teeth],
}

/// An exit invariant with no working teeth yet, and why.
struct Gap {
    invariant: &'static str,
    reason: &'static str,
}

/// The M3 exit rows of the task scope (`docs/handoff/m3-finish.md` lane
/// F-EXIT). Design section 20 adds the rows it gives teeth to.
const EXIT: &[&str] = &[
    "I-16",
    "I-17",
    "I-18",
    "I-19",
    "I-20",
    "I-24",
    "I-38",
    "I-39",
    "I-77",
    "I-78",
    "I-79",
    "I-80",
    "I-81",
    "I-82",
    "I-83",
    "Isolation",
];

/// The name prefixes of teeth tests that belong to an exit row. Every
/// `#[test]` with `teeth` in its name and one of these prefixes must be
/// registered.
const EXIT_PREFIXES: &[&str] = &[
    "i16_",
    "i17_",
    "i18_",
    "i19_",
    "i20_",
    "i24_",
    "i38_",
    "i39_",
    "i74_",
    "i77_",
    "i78_",
    "i79_",
    "i80_",
    "i81_",
    "i82_",
    "i83_",
    "t_iso_",
    "t_db_iso_",
    "seam_m_driver_",
];

const CT: &str = "crates/fstp-celltest/tests/";
const DEPS_M3: &str = "tools/deps-check/tests/m3_rules.rs";
const PG_SCHEMA: &str = "crates/fstp-pgstore/tests/schema.rs";
const PG_GRANT: &str = "crates/fstp-pgstore/tests/apply_grant.rs";
const CP_G14: &str = "crates/fstp-control/tests/i82_g14_revocation.rs";
const EDGE_R5: &str = "crates/fstp-edge/tests/i19_rule5_source_scan.rs";
const SHRED_MODEL: &str = "crates/fstp-celltest/src/mc/shred_model.rs";
const PLACE_MODEL: &str = "crates/fstp-celltest/src/mc/place_model.rs";

const I16: &str = "crates/fstp-celltest/tests/i16_funds.rs";
const I17: &str = "crates/fstp-celltest/tests/i17_identity_release.rs";
const I18: &str = "crates/fstp-celltest/tests/i18_guardian_consent.rs";
const I18_VCP: &str = "crates/fstp-celltest/tests/i18_m_vcp.rs";
const ORIGIN: &str = "crates/fstp-celltest/tests/fstp_vault_origin_binding.rs";
const I19: &str = "crates/fstp-celltest/tests/i19_boundary.rs";
const I20: &str = "crates/fstp-celltest/tests/i20_tenants.rs";
const SCAN_VIEWS: &str = "crates/fstp-celltest/tests/harness_scan_views.rs";
const DUMP_VIEWS: &str = "crates/fstp-celltest/tests/harness_dump_views.rs";
const SCAN: &str = "crates/fstp-celltest/tests/harness_scan.rs";
const I24: &str = "crates/fstp-celltest/tests/i24_audit_chain.rs";
const RNF: &str = "crates/fstp-celltest/tests/r_nf_m3.rs";
const I38: &str = "crates/fstp-celltest/tests/i38_egress.rs";
const I39: &str = "crates/fstp-celltest/tests/i39_licence.rs";
const I39_M: &str = "crates/fstp-celltest/tests/i39_m_licence.rs";
const I77: &str = "crates/fstp-celltest/tests/i77_login.rs";
const I78: &str = "crates/fstp-celltest/tests/i78_stepup.rs";
const I79: &str = "crates/fstp-celltest/tests/i79_recovery.rs";
const I80: &str = "crates/fstp-celltest/tests/i80_custody.rs";
const I81: &str = "crates/fstp-celltest/tests/i81_shred.rs";
const I81_BACKUPS: &str = "crates/fstp-celltest/tests/i81_backups.rs";
const RSW02: &str = "crates/fstp-celltest/tests/r_sw_02_cell_erasure.rs";
const I82: &str = "crates/fstp-celltest/tests/i82_role_plan.rs";
const I83: &str = "crates/fstp-celltest/tests/i83_placement.rs";
const TISO19: &str = "crates/fstp-celltest/tests/t_iso_i19.rs";
const TISO20: &str = "crates/fstp-celltest/tests/t_iso_i20.rs";
const TDBISO: &str = "crates/fstp-celltest/tests/t_db_iso_i82.rs";
const SEAM_DRIVER: &str = "crates/fstp-celltest/tests/seam_m_driver.rs";
const ADR007: &str = "crates/fstp-celltest/tests/adr007_store_and_erasure.rs";

/// The registry. Rows carry the labels of design section 20.
const REGISTRY: &[Row] = &[
    Row {
        invariant: "I-16",
        teeth: &[
            t(DEPS_M3, "i16_teeth_seeded_instruction_crate_is_caught"),
            t(I16, "i16_teeth_seeded_instruction_source_is_caught"),
            t(I16, "i16_teeth_seeded_balance_table_is_caught"),
            t(I16, "i16_teeth_config_scan_catches_a_debtor_account_field"),
        ],
    },
    Row {
        invariant: "I-17",
        teeth: &[
            t(I17, "i17_teeth_ticket_issued_in_ranked_is_caught"),
            t(I17, "i17_teeth_attribute_logged_is_caught"),
        ],
    },
    Row {
        invariant: "I-18",
        teeth: &[
            t(I18_VCP, "i18_teeth_provisional_consent_counted_is_caught"),
            t(I18, "i18_teeth_consent_by_unverified_guardian_is_caught"),
            t(I18, "i18_teeth_guardian_ticket_to_a_non_guardian_is_caught"),
            t(
                I18,
                "i18_teeth_guardian_ticket_without_adult_query_is_caught",
            ),
            t(I18, "i18_teeth_vault_outcome_shown_to_judging_is_caught"),
            t(
                ORIGIN,
                "i18_teeth_origin_ignoring_the_ticket_proposal_is_caught",
            ),
            t(
                ORIGIN,
                "i18_teeth_origin_refusing_every_consent_withdrawal_is_caught",
            ),
        ],
    },
    Row {
        invariant: "I-19",
        teeth: &[
            t(I19, "i19_teeth_canary_in_heartbeat_is_caught"),
            t(I19, "i19_teeth_seeded_leak_in_control_plane_is_caught"),
            t(EDGE_R5, "i19_rule5_teeth_seeded_server_api_is_caught"),
        ],
    },
    Row {
        invariant: "I-20",
        teeth: &[
            t(I20, "i20_teeth_shared_lookup_key_is_caught"),
            t(
                I20,
                "i20_teeth_control_plane_reaching_account_types_is_caught",
            ),
            t(
                SCAN_VIEWS,
                "harness_scan_i20_teeth_shared_lookup_key_is_caught",
            ),
            t(
                DUMP_VIEWS,
                "harness_dump_i20_teeth_shared_key_across_dumps_is_caught",
            ),
        ],
    },
    Row {
        invariant: "I-24",
        teeth: &[
            t(I24, "i24_teeth_verifier_without_receipt_check_is_caught"),
            t(I24, "i24_teeth_link_omitting_a_field_is_caught"),
            t(RNF, "r_nf_08_teeth_counter_nonce_is_caught"),
            t(RNF, "r_nf_08_teeth_nonce_reused_after_an_abort_is_caught"),
            t(
                I24,
                "i24_teeth_m_audit_verifier_skips_receipt_comparison_is_caught",
            ),
            t(
                I24,
                "i24_teeth_m_audit_verifier_skips_receipt_comparison_is_caught_on_the_reference",
            ),
            t(
                I24,
                "i24_teeth_m_audit_abort_accepted_for_present_row_is_caught",
            ),
            t(
                I24,
                "i24_teeth_m_audit_abort_accepted_for_present_row_is_caught_on_the_reference",
            ),
            t(I24, "i24_teeth_m_audit_commit_before_receipt_is_caught"),
            t(
                I24,
                "i24_teeth_m_audit_commit_before_receipt_is_caught_on_the_reference",
            ),
            t(
                I24,
                "i24_teeth_m_audit_failed_commit_treated_as_in_doubt_is_caught",
            ),
            t(
                I24,
                "i24_teeth_m_audit_failed_commit_treated_as_in_doubt_is_caught_on_the_reference",
            ),
            t(
                I24,
                "i24_teeth_m_audit_reads_refused_while_witness_down_is_caught",
            ),
            t(
                I24,
                "i24_teeth_m_audit_reads_refused_while_witness_down_is_caught_on_the_reference",
            ),
            t(I24, "i24_teeth_witness_ignores_the_sender_cell_is_caught"),
            t(I24, "i24_teeth_witness_prepare_over_a_stale_head_is_caught"),
            t(
                I24,
                "i24_teeth_witness_receipts_a_link_its_rows_do_not_recompute_is_caught",
            ),
            t(I24, "i24_teeth_witness_receipts_an_empty_prepare_is_caught"),
            t(
                I24,
                "i24_teeth_witness_takes_withdrawal_from_any_sender_is_caught",
            ),
            t(PG_SCHEMA, "i24_teeth_dropped_mutation_trigger_is_caught"),
            t(
                PG_SCHEMA,
                "i24_teeth_trigger_trusting_the_stored_hash_is_caught",
            ),
        ],
    },
    Row {
        invariant: "I-38",
        teeth: &[
            t(I38, "i38_teeth_extra_header_is_caught"),
            t(I38, "i38_teeth_extra_body_member_is_caught"),
            t(I38, "i38_teeth_canary_in_crabnebula_capture_is_caught"),
        ],
    },
    Row {
        invariant: "I-39",
        teeth: &[
            t(I39_M, "i39_teeth_gate_on_release_payment_is_caught"),
            t(I39_M, "i39_teeth_grace_end_off_by_one_is_caught"),
            t(
                I39_M,
                "i39_teeth_refresh_adopts_replayed_or_foreign_token_is_caught",
            ),
            t(I39, "i39_teeth_unpinned_key_transition_is_caught"),
        ],
    },
    Row {
        invariant: "I-77",
        teeth: &[
            t(I77, "i77_teeth_weak_session_admitted_is_caught"),
            t(
                I77,
                "i77_teeth_weak_session_admitted_is_caught_on_the_reference",
            ),
            t(
                I77,
                "i77_teeth_admit_method_ignores_scheduled_bindings_is_caught",
            ),
            t(
                I77,
                "i77_teeth_admit_method_ignores_scheduled_bindings_is_caught_on_the_reference",
            ),
            t(I77, "i77_teeth_grant_batch_omits_session_ended_is_caught"),
            t(
                I77,
                "i77_teeth_grant_batch_omits_session_ended_is_caught_on_the_reference",
            ),
            t(I77, "i77_teeth_end_batch_omits_session_ended_is_caught"),
            t(
                I77,
                "i77_teeth_end_batch_omits_session_ended_is_caught_on_the_reference",
            ),
        ],
    },
    Row {
        invariant: "I-78",
        teeth: &[
            t(I78, "i78_teeth_stale_step_up_accepted_is_caught"),
            t(
                I78,
                "i78_teeth_stale_step_up_accepted_is_caught_on_the_reference",
            ),
            t(I78, "i78_teeth_step_up_exactly_p71_old_refused_is_caught"),
            t(
                I78,
                "i78_teeth_step_up_exactly_p71_old_refused_is_caught_on_the_reference",
            ),
            t(I78, "i78_teeth_consumption_dropped_is_caught"),
            t(
                I78,
                "i78_teeth_consumption_dropped_is_caught_on_the_reference",
            ),
            t(I78, "i78_teeth_digest_compared_by_kind_is_caught"),
            t(
                I78,
                "i78_teeth_digest_compared_by_kind_is_caught_on_the_reference",
            ),
            t(I78, "i78_teeth_magic_link_session_adds_passkey_is_caught"),
            t(
                I78,
                "i78_teeth_magic_link_session_adds_passkey_is_caught_on_the_reference",
            ),
            t(PG_SCHEMA, "i78_teeth_stepup_without_primary_key_is_caught"),
        ],
    },
    Row {
        invariant: "I-79",
        teeth: &[
            t(I79, "i79_teeth_path_checked_at_request_only_is_caught"),
            t(
                I79,
                "i79_teeth_path_checked_at_request_only_is_caught_on_the_reference",
            ),
            t(I79, "i79_teeth_approval_without_step_up_is_caught"),
            t(
                I79,
                "i79_teeth_approval_without_step_up_is_caught_on_the_reference",
            ),
            t(I79, "i79_teeth_completion_revokes_nothing_is_caught"),
            t(
                I79,
                "i79_teeth_completion_revokes_nothing_is_caught_on_the_reference",
            ),
            t(I79, "i79_teeth_one_staff_ticket_is_caught"),
            t(I79, "i79_teeth_one_staff_ticket_is_caught_on_the_reference"),
        ],
    },
    Row {
        invariant: "I-80",
        teeth: &[
            t(I80, "i80_teeth_leaking_custody_is_caught"),
            t(I80, "i80_teeth_custody_manifest_scan_sees_every_form"),
            t(I80, "i80_teeth_custody_surface_scan_sees_an_export"),
            t(I80, "i80_teeth_root_material_scan_sees_a_seeded_name"),
            t(I80, "i80_teeth_trait_probe_sees_escape_traits"),
        ],
    },
    Row {
        invariant: "I-81",
        teeth: &[
            t(I81, "i81_teeth_group_not_rotated_is_caught"),
            t(I81, "i81_teeth_destroy_before_commit_loses_data_is_caught"),
            t(I81, "i81_teeth_completion_before_receipt_is_caught"),
            t(I81, "i81_teeth_completion_before_receipt_breaks_i81"),
            t(I81, "i81_teeth_digest_key_not_rotated_is_caught"),
            t(I81, "i81_teeth_dropped_mid_run_request_is_caught"),
            t(I81, "i81_teeth_queue_lost_on_restart_is_caught"),
            t(
                I81,
                "i81_teeth_reseal_keeps_a_second_erased_sibling_is_caught",
            ),
            t(
                I81,
                "i81_teeth_scripted_crash_run_sees_destroy_before_commit",
            ),
            t(SHRED_MODEL, "i81_teeth_unrunnable_step_is_caught"),
            t(
                I81_BACKUPS,
                "i81_teeth_restored_epoch_file_opens_without_destroy",
            ),
            t(I81_BACKUPS, "i81_teeth_live_email_digest_is_recomputed"),
            t(
                I81_BACKUPS,
                "i81_teeth_live_identity_match_digest_is_recomputed",
            ),
            t(
                RSW02,
                "r_sw_02_teeth_committed_epoch_only_keeps_keys_openable",
            ),
            t(RSW02, "r_sw_02_teeth_skipped_chain_keeps_keys_openable"),
        ],
    },
    Row {
        invariant: "I-82",
        teeth: &[
            t(I82, "i82_teeth_seeded_connect_grant_is_caught"),
            t(I82, "i82_teeth_public_connect_is_caught"),
            t(
                I82,
                "i82_teeth_hba_line_form_refuses_group_file_and_keyword_lines",
            ),
            t(I82, "i82_teeth_indirect_predefined_membership_is_a_path"),
            t(
                I82,
                "i82_teeth_indirect_predefined_membership_is_a_path_in_the_production_graph",
            ),
            t(
                I82,
                "i82_teeth_role_attributes_and_indirect_membership_are_caught",
            ),
            t(I82, "i82_teeth_set_role_to_a_superuser_role_is_caught"),
            t(I83, "i82_teeth_m_place_plan_for_another_cell_is_caught"),
            t(
                I83,
                "i82_teeth_m_place_plan_for_another_cell_is_caught_on_the_reference",
            ),
            t(PG_SCHEMA, "i82_teeth_role_with_a_grant_option_is_caught"),
            t(PG_SCHEMA, "i82_teeth_security_definer_function_is_caught"),
            t(PG_SCHEMA, "i82_teeth_seeded_public_grant_is_caught"),
            t(PG_SCHEMA, "i82_teeth_seeded_schema_create_is_caught"),
            t(PG_SCHEMA, "i82_teeth_seeded_update_grant_is_caught"),
            t(
                PG_GRANT,
                "i82_teeth_apply_grant_without_object_check_is_caught",
            ),
            t(CP_G14, "i82_g14_teeth_unrevoked_server_is_caught"),
            t(CP_G14, "i82_g14_teeth_backend_and_lock_paths_are_caught"),
        ],
    },
    Row {
        invariant: "I-83",
        teeth: &[
            t(I83, "i83_teeth_first_free_cluster_is_caught"),
            t(
                I83,
                "i83_teeth_first_free_cluster_is_caught_on_the_reference",
            ),
            t(I83, "i83_teeth_refusing_every_placement_loses_the_witness"),
            t(I83, "i83_teeth_start_check_comparison_catches_a_lax_check"),
            t(
                PLACE_MODEL,
                "i83_m_place_self_test_teeth_hold_at_the_tripwire",
            ),
            t(
                PG_SCHEMA,
                "i83_teeth_placement_without_kind_check_is_caught",
            ),
        ],
    },
    Row {
        invariant: "Isolation",
        teeth: &[
            t(
                TISO19,
                "t_iso_i19_teeth_lone_leak_into_another_cell_database_is_caught",
            ),
            t(
                TISO19,
                "t_iso_i19_teeth_crossing_rule_flags_every_foreign_store",
            ),
            t(
                TISO19,
                "t_iso_i19_teeth_positive_control_needs_one_home_per_cell",
            ),
            t(
                TISO19,
                "t_iso_i19_teeth_background_write_during_another_cycle_keeps_the_homes",
            ),
            t(
                TISO20,
                "t_iso_i20_teeth_link_kept_by_shared_infrastructure_is_caught",
            ),
            t(
                TISO20,
                "t_iso_i20_teeth_cycle_cells_tolerate_a_background_write",
            ),
            t(
                TDBISO,
                "t_db_iso_i82_teeth_seeded_cross_cell_login_is_caught",
            ),
            t(
                TDBISO,
                "t_db_iso_i82_teeth_seeded_server_file_read_is_caught",
            ),
            t(TDBISO, "t_db_iso_i82_teeth_every_escape_probe_fires"),
            t(
                TDBISO,
                "t_db_iso_i82_teeth_g14_views_without_the_revocation_are_caught",
            ),
            t(SCAN, "harness_scan_teeth_skipping_raw_is_caught"),
            t(SCAN, "harness_scan_teeth_skipping_hex_lower_is_caught"),
            t(SCAN, "harness_scan_teeth_skipping_hex_upper_is_caught"),
            t(
                SCAN,
                "harness_scan_teeth_skipping_base64_and_base64url_is_caught",
            ),
            t(
                SCAN,
                "harness_scan_teeth_base64_at_one_alignment_only_is_caught",
            ),
            t(SCAN, "harness_scan_teeth_skipping_percent_is_caught"),
            t(SCAN, "harness_scan_teeth_skipping_json_escape_is_caught"),
            t(SCAN, "harness_scan_teeth_skipping_utf16le_is_caught"),
            t(SCAN, "harness_scan_teeth_prefix_matching_scanner_is_caught"),
        ],
    },
    Row {
        invariant: "Tier B gate",
        teeth: &[t(DEPS_M3, "i74_teeth_gate_skipping_tier_b_is_caught")],
    },
    Row {
        invariant: "M2 seams",
        teeth: &[
            t(
                SEAM_DRIVER,
                "seam_m_driver_i23_teeth_retry_with_fresh_command_id_is_caught",
            ),
            t(
                I18_VCP,
                "i18_m_vcp_note4_teeth_vault_answers_while_provisional_is_caught",
            ),
            t(
                I18_VCP,
                "i18_m_vcp_note4_teeth_driver_acks_before_reaction_commits_is_caught",
            ),
            t(
                I18_VCP,
                "i18_m_vcp_note4_teeth_fact_effective_without_ack_is_caught",
            ),
            t(
                I18_VCP,
                "i18_m_vcp_i04_teeth_driver_acks_before_reaction_commits_is_caught",
            ),
            t(
                I18_VCP,
                "i18_m_vcp_i06_teeth_fact_effective_without_ack_is_caught",
            ),
            t(ADR007, "adr007_teeth_head_checked_before_command_is_caught"),
        ],
    },
];

/// Exit rows whose teeth do not work yet, each with its reason. Empty on
/// 2026-11-13: every exit row has at least one registered teeth test off
/// the known-red list.
const ALLOWED_GAPS: &[Gap] = &[];

// ---------------------------------------------------------------------------
// Source reading.

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The function name a line defines, if it opens a `fn` item.
fn fn_name(line: &str) -> Option<&str> {
    let s = line.trim_start();
    let s = s.strip_prefix("pub ").unwrap_or(s);
    let s = s.strip_prefix("async ").unwrap_or(s);
    let rest = s.strip_prefix("fn ")?;
    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    rest[end..].starts_with(['(', '<']).then(|| &rest[..end])
}

/// The attribute and doc lines directly above line `at`.
fn attributes(lines: &[&str], at: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines[..at].iter().rev() {
        let s = line.trim();
        let attribute = s.starts_with("#[") || s.starts_with("//");
        if !attribute && (s.is_empty() || s.ends_with(['{', '}', ';'])) {
            break;
        }
        out.push(s.to_owned());
    }
    out
}

/// How a function is defined in a source file.
#[derive(Debug, PartialEq, Eq)]
enum Def {
    Missing,
    Twice,
    NotATest,
    Ignored,
    Test,
}

fn definition(text: &str, name: &str) -> Def {
    let lines: Vec<&str> = text.lines().collect();
    let at: Vec<usize> = (0..lines.len())
        .filter(|&i| fn_name(lines[i]) == Some(name))
        .collect();
    match at.as_slice() {
        [] => Def::Missing,
        [i] => {
            let attrs = attributes(&lines, *i);
            if attrs.iter().any(|a| a.starts_with("#[ignore")) {
                Def::Ignored
            } else if attrs.iter().any(|a| a == "#[test]") {
                Def::Test
            } else {
                Def::NotATest
            }
        }
        _ => Def::Twice,
    }
}

/// Every `#[test]` function of a source file.
fn tests_in(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    (0..lines.len())
        .filter_map(|i| {
            let name = fn_name(lines[i])?;
            attributes(&lines, i)
                .iter()
                .any(|a| a == "#[test]")
                .then(|| name.to_owned())
        })
        .collect()
}

/// Every `.rs` file under `dir`, relative to the repository root, outside
/// build output and the separate fuzz projects.
fn rust_files(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(name.as_str(), "target" | "fuzz" | "node_modules")
                && !name.starts_with('.')
            {
                rust_files(&path, out);
            }
        } else if name.ends_with(".rs") {
            let rel = path.strip_prefix(repo_root()).unwrap();
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Every `#[test]` of the workspace with the file that defines it.
fn workspace_tests() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_files(&repo_root().join("crates"), &mut files);
    rust_files(&repo_root().join("tools"), &mut files);
    files.sort();
    let mut out = Vec::new();
    for f in files {
        for name in tests_in(&read(&f)) {
            out.push((f.clone(), name));
        }
    }
    out
}

/// The test keys of `ci/known-red.txt`.
fn known_red() -> Vec<String> {
    read("ci/known-red.txt")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split(" | ").next())
        .map(|k| k.trim().to_owned())
        .collect()
}

fn is_known_red(red: &[String], name: &str) -> bool {
    let suffix = format!("::{name}");
    red.iter().any(|k| k.ends_with(&suffix))
}

fn registered() -> BTreeMap<&'static str, &'static str> {
    REGISTRY
        .iter()
        .flat_map(|r| r.teeth.iter().map(|t| (t.name, r.invariant)))
        .collect()
}

/// The rows of design section 20 that name teeth, with the backticked
/// teeth tests of each. A row whose teeth cell is `none` is a decision,
/// not a check, and has no teeth to register.
fn design_section_20() -> Vec<(String, Vec<String>)> {
    let text = read("docs/handoff/m3-design.md");
    let start = text.find("## 20. M3 exit checklist").unwrap();
    let section = &text[start..];
    let end = section[3..].find("\n## ").map_or(section.len(), |e| e + 3);
    let mut rows = Vec::new();
    for line in section[..end].lines() {
        let cells: Vec<&str> = line.trim().trim_matches('|').split(" | ").collect();
        if cells.len() < 7 || cells[0].trim() == "Invariant" || cells[0].trim().starts_with("---") {
            continue;
        }
        let teeth_cell = cells[4].trim();
        if teeth_cell == "none" {
            continue;
        }
        let named: Vec<String> = teeth_cell
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|s| s.contains("teeth"))
            .map(str::to_owned)
            .collect();
        rows.push((cells[0].trim().to_owned(), named));
    }
    rows
}

// ---------------------------------------------------------------------------
// The registry checks.

/// I-16 to I-20, I-24, I-38, I-39, I-77 to I-83 and the isolation tests
/// (design section 20, W4): every exit row has registered teeth, or a
/// named gap.
#[test]
fn w4_every_m3_exit_invariant_has_registered_teeth() {
    let mut rows: BTreeSet<String> = EXIT.iter().map(|s| (*s).to_owned()).collect();
    rows.extend(design_section_20().into_iter().map(|(r, _)| r));
    let missing: Vec<&String> = rows
        .iter()
        .filter(|r| {
            let has = REGISTRY
                .iter()
                .any(|row| row.invariant == r.as_str() && !row.teeth.is_empty());
            !has && !ALLOWED_GAPS.iter().any(|g| g.invariant == r.as_str())
        })
        .collect();
    assert!(missing.is_empty(), "exit rows without teeth: {missing:?}");
}

/// I-16 to I-20, I-24, I-38, I-39, I-77 to I-83 and the isolation tests
/// (design section 19, W4): every registered teeth test exists once in
/// its file as a `#[test]` and is not ignored.
#[test]
fn w4_every_registered_teeth_test_exists_and_runs() {
    let mut seen = BTreeSet::new();
    let mut bad = Vec::new();
    for row in REGISTRY {
        for teeth in row.teeth {
            if !seen.insert((teeth.file, teeth.name)) {
                bad.push(format!(
                    "{}: {} registered twice",
                    row.invariant, teeth.name
                ));
                continue;
            }
            let def = definition(&read(teeth.file), teeth.name);
            if def != Def::Test {
                bad.push(format!(
                    "{}: {}::{} is {def:?}",
                    row.invariant, teeth.file, teeth.name
                ));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

/// Design section 20, W4: every teeth test that the exit checklist names
/// is registered under its row.
#[test]
fn w4_every_teeth_test_named_in_design_section_20_is_registered() {
    let rows = design_section_20();
    let count: usize = rows.iter().map(|(_, n)| n.len()).sum();
    assert!(
        rows.len() >= EXIT.len() && count >= 20,
        "section 20 parsed to {} rows and {count} teeth",
        rows.len()
    );
    let mut missing = Vec::new();
    for (row, named) in rows {
        for name in named {
            let found = REGISTRY
                .iter()
                .filter(|r| r.invariant == row)
                .any(|r| r.teeth.iter().any(|t| t.name == name));
            if !found {
                missing.push(format!("{row}: {name}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "design section 20 teeth not registered: {missing:#?}"
    );
}

/// I-16 to I-20, I-24, I-38, I-39, I-74, I-77 to I-83, T-ISO and T-DB-ISO
/// (W4): a teeth test written for an exit invariant cannot drift out of
/// the registry.
#[test]
fn w4_every_exit_teeth_test_in_the_workspace_is_registered() {
    let reg = registered();
    let missing: Vec<String> = workspace_tests()
        .into_iter()
        .filter(|(_, name)| {
            name.contains("teeth") && EXIT_PREFIXES.iter().any(|p| name.starts_with(p))
        })
        .filter(|(_, name)| !reg.contains_key(name.as_str()))
        .map(|(file, name)| format!("{file}: {name}"))
        .collect();
    assert!(missing.is_empty(), "unregistered exit teeth: {missing:#?}");
}

/// I-16 to I-20, I-24, I-38, I-39, I-77 to I-83 and the isolation tests
/// (W4): each exit row keeps at least one registered teeth test off
/// `ci/known-red.txt`, so some teeth of every row run green in CI.
#[test]
fn w4_every_exit_invariant_has_teeth_outside_known_red() {
    let red = known_red();
    let without: Vec<&str> = REGISTRY
        .iter()
        .filter(|r| r.teeth.iter().all(|t| is_known_red(&red, t.name)))
        .filter(|r| !ALLOWED_GAPS.iter().any(|g| g.invariant == r.invariant))
        .map(|r| r.invariant)
        .collect();
    assert!(
        without.is_empty(),
        "rows whose teeth are all known red: {without:?}"
    );
}

/// W4: an allowed gap names a reason, and stops being allowed once its
/// row has teeth that run green.
#[test]
fn w4_allowed_gaps_name_a_reason_and_are_still_gaps() {
    let red = known_red();
    let mut bad = Vec::new();
    for gap in ALLOWED_GAPS {
        if gap.reason.trim().is_empty() {
            bad.push(format!("{}: no reason", gap.invariant));
        }
        let covered = REGISTRY
            .iter()
            .filter(|r| r.invariant == gap.invariant)
            .any(|r| r.teeth.iter().any(|t| !is_known_red(&red, t.name)));
        if covered {
            bad.push(format!(
                "{}: has working teeth, remove the gap",
                gap.invariant
            ));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

/// I-04, I-06, I-18, I-23, I-24, I-39, I-77 to I-79 and I-81 to I-83
/// (design sections 14.1 and 14.2, W4): every M3 model has a measured
/// count, its runner bounds it by the tripwire of that count, and each
/// teeth mutant of section 14.2 is registered.
#[test]
fn w4_every_m3_model_is_measured_bounded_and_has_registered_teeth() {
    let reg = registered();
    let mut bad = Vec::new();
    for m in M3_MODELS {
        if m.measured == NOT_MEASURED {
            bad.push(format!("{}: not measured", m.model));
        }
        let call = format!("tripwire({})", m.constant);
        if !read(m.runner).contains(&call) {
            bad.push(format!("{}: {} does not call {call}", m.model, m.runner));
        }
        if m.teeth.is_empty() {
            bad.push(format!("{}: no teeth", m.model));
        }
        for name in m.teeth {
            if !reg.contains_key(name) {
                bad.push(format!("{}: {name} not registered", m.model));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---------------------------------------------------------------------------
// The multi-cell isolation CI part (design sections 14.4 and 14.8).

/// The libtest words of one matrix entry of the CI test job.
#[derive(Debug, Default)]
struct Part {
    packages: Vec<String>,
    filters: Vec<String>,
    skips: Vec<String>,
}

/// The matrix entry `part` of `.github/workflows/ci.yml`, in either the
/// block or the inline form the file uses.
fn ci_part(part: &str) -> Part {
    let ci = read(".github/workflows/ci.yml");
    let words = |v: &str| v.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
    let mut out = Part::default();
    let mut lines = ci.lines().peekable();
    while let Some(line) = lines.next() {
        let s = line.trim();
        if let Some(inline) = s.strip_prefix("- {").and_then(|r| r.strip_suffix('}')) {
            let fields: BTreeMap<&str, &str> = inline
                .split(", ")
                .filter_map(|f| f.trim().split_once(": "))
                .collect();
            if fields.get("part") == Some(&part) {
                out.packages = words(fields.get("packages").unwrap_or(&""));
                out.filters = words(fields.get("filter").unwrap_or(&""));
                out.skips = words(fields.get("skip").unwrap_or(&""));
                return out;
            }
        } else if s == format!("- part: {part}") {
            while let Some(next) = lines.peek() {
                let n = next.trim();
                if n.starts_with("- ") || n.starts_with('#') || n.is_empty() {
                    break;
                }
                if let Some((k, v)) = n.split_once(": ") {
                    match k {
                        "packages" => out.packages = words(v),
                        "filter" => out.filters = words(v),
                        "skip" => out.skips = words(v),
                        _ => {}
                    }
                }
                lines.next();
            }
            return out;
        }
    }
    panic!("ci.yml has no test part {part}");
}

fn selects(filters: &[String], skips: &[String], name: &str) -> bool {
    (filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str())))
        && !skips.iter().any(|s| name.contains(s.as_str()))
}

/// I-19, I-20, I-80, I-82, I-83 (design sections 14.4 and 14.8, W4): the
/// `isolation-multi-cell` CI part runs every `t_iso_*` and `t_db_iso_*`
/// test, the `i80_root_canary_*` scans and the process-mode isolation
/// tests. The workspace part skips exactly those, so each runs once and
/// no skip drops a test that the isolation part does not run.
#[test]
fn w4_isolation_part_and_workspace_part_run_each_isolation_test_once() {
    let iso = ci_part("isolation-multi-cell");
    let ws = ci_part("workspace");
    // The devstack part (M3 exit audit section 7, item 7) runs
    // slice_devstack after compiling the auth pages, and the workspace
    // part skips it. It counts like the other parts: each test runs once.
    let dev = ci_part("devstack");
    let test_bins = |packages: &[String]| {
        let mut bins = BTreeSet::new();
        let mut it = packages.iter();
        while let Some(w) = it.next() {
            if w == "--test" {
                bins.insert(format!("{CT}{}.rs", it.next().unwrap()));
            }
        }
        bins
    };
    let bins = test_bins(&iso.packages);
    let dev_bins = test_bins(&dev.packages);
    assert!(
        iso.packages
            .starts_with(&["-p".to_owned(), "fstp-celltest".to_owned()])
    );
    let mut bad = Vec::new();
    let mut isolated = Vec::new();
    for (file, name) in workspace_tests() {
        // The testkits run in parts of their own, which these skips do
        // not touch.
        if file.starts_with("crates/fstp-api-testkit/")
            || file.starts_with("crates/fstp-domain-testkit/")
        {
            continue;
        }
        let in_iso = bins.contains(&file) && selects(&iso.filters, &iso.skips, &name);
        let in_ws = selects(&ws.filters, &ws.skips, &name);
        let in_dev = dev_bins.contains(&file) && selects(&dev.filters, &dev.skips, &name);
        let isolation = name.starts_with("t_iso_")
            || name.starts_with("t_db_iso_")
            || name.starts_with("i80_root_canary_");
        let parts = usize::from(in_iso) + usize::from(in_ws) + usize::from(in_dev);
        if parts > 1 {
            bad.push(format!("{file}: {name} runs in more than one part"));
        }
        if parts == 0 {
            bad.push(format!("{file}: {name} runs in no part"));
        }
        if isolation && !in_iso {
            bad.push(format!(
                "{file}: {name} is an isolation test outside the isolation part"
            ));
        }
        if in_iso {
            isolated.push(name);
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(
        isolated.len() >= 10,
        "the isolation part selects too few tests: {isolated:?}"
    );
}
