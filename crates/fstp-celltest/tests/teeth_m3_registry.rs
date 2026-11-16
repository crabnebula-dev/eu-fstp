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
//! - an isolation test runs in a CI part other than the multi-cell
//!   isolation part;
//! - a test runs in no CI test part or in more than one, a
//!   `crates/fstp-celltest/tests/*.rs` file runs in no part, or a
//!   library's doc tests do not run in exactly one part;
//! - the light CI tier skips a test outside its declared heavy classes
//!   (the teeth tests and the matrix layout self-checks), or stops a part
//!   other than the authorisation matrices and M-ACTIVATE;
//! - the full CI tier adds a skip or a case cap to any part.

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
const I17_UNMASK: &str = "crates/fstp-api-testkit/src/harness_unmask.rs";
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
            t(I17_UNMASK, "i17_teeth_committee_member_unmask_is_caught"),
            t(I17_UNMASK, "i17_teeth_forged_unmask_record_is_caught"),
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
// The CI test parts: the multi-cell isolation part (design sections 14.4
// and 14.8) and the parts of fstp-celltest (Daniel, 2026-11-16).

/// One matrix entry of the CI test job.
#[derive(Debug, Default)]
struct Part {
    name: String,
    /// The cargo selections of `packages`, separated by `;`, which the
    /// part runs one after another.
    selections: Vec<Selection>,
    filters: Vec<String>,
    skips: Vec<String>,
}

/// One cargo test target selection.
#[derive(Debug, Default)]
struct Selection {
    workspace: bool,
    packages: Vec<String>,
    excludes: Vec<String>,
    /// The `--test` names. A `*` matches any run of characters, as in
    /// cargo's target patterns.
    tests: Vec<String>,
    lib: bool,
    bins: bool,
    doc: bool,
}

/// What a source file belongs to within its package.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// `src/` outside the binaries: the library and its unit tests.
    Lib,
    /// `src/main.rs` and `src/bin/`.
    Bin,
    /// `tests/<name>.rs`: the integration test binary `<name>`.
    Test(String),
    /// A module under `tests/<dir>/`, part of whichever test binary
    /// includes it.
    TestModule,
    /// The doc tests of the library.
    Doc,
    /// Anything else, such as a build script.
    Other,
}

impl Selection {
    /// Reads the cargo words of one selection. A word the check does not
    /// know fails it, so a new kind of selection cannot slip past.
    fn parse(words: &[&str]) -> Selection {
        let mut s = Selection::default();
        let mut it = words.iter();
        while let Some(&w) = it.next() {
            let mut value = || {
                (*it.next()
                    .unwrap_or_else(|| panic!("ci.yml: {w} without a value")))
                .to_owned()
            };
            match w {
                "--workspace" => s.workspace = true,
                "-p" | "--package" => s.packages.push(value()),
                "--exclude" => s.excludes.push(value()),
                "--test" => s.tests.push(value()),
                "--lib" => s.lib = true,
                "--bins" => s.bins = true,
                "--doc" => s.doc = true,
                other => panic!("ci.yml: this check does not know the cargo word {other}"),
            }
        }
        s
    }

    /// Whether the selection names its targets. Without, cargo runs the
    /// library, binaries, test binaries and doc tests of each package.
    fn names_targets(&self) -> bool {
        !self.tests.is_empty() || self.lib || self.bins || self.doc
    }

    fn has_package(&self, package: &str) -> bool {
        if self.workspace {
            !self.excludes.iter().any(|e| e == package)
        } else {
            self.packages.iter().any(|p| p == package)
        }
    }

    /// Whether the selection runs `target` of `package`.
    fn runs(&self, package: &str, target: &Target) -> bool {
        if !self.has_package(package) {
            return false;
        }
        if !self.names_targets() {
            return *target != Target::Other;
        }
        match target {
            Target::Lib => self.lib,
            Target::Bin => self.bins,
            Target::Doc => self.doc,
            Target::Test(name) => self.tests.iter().any(|p| glob(p, name)),
            Target::TestModule | Target::Other => false,
        }
    }
}

/// Whether `name` matches the cargo target pattern `pattern`, in which
/// `*` matches any run of characters. The parts use no other wildcard.
fn glob(pattern: &str, name: &str) -> bool {
    assert!(
        !pattern.contains(['?', '[', ']', '{', '}']),
        "ci.yml: the pattern {pattern} uses a wildcard this check does not read"
    );
    let mut pieces = pattern.split('*');
    let first = pieces.next().unwrap();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let pieces: Vec<&str> = pieces.collect();
    let Some((last, middle)) = pieces.split_last() else {
        return rest.is_empty();
    };
    for piece in middle {
        match rest.find(piece) {
            Some(i) => rest = &rest[i + piece.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// The leading spaces of a line.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Every matrix entry of the CI test job in `.github/workflows/ci.yml`,
/// in the inline or the block form, with folded (`>-`) values.
fn ci_parts() -> Vec<Part> {
    let ci = read(".github/workflows/ci.yml");
    let lines: Vec<&str> = ci.lines().collect();
    let mut out: Vec<Part> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let s = lines[i].trim();
        i += 1;
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        if let Some(inline) = s.strip_prefix("- {").and_then(|r| r.strip_suffix('}')) {
            for f in inline.split(", ") {
                if let Some((k, v)) = f.trim().split_once(": ") {
                    fields.insert(k.to_owned(), v.trim().to_owned());
                }
            }
        } else if let Some(name) = s.strip_prefix("- part: ") {
            fields.insert("part".to_owned(), name.trim().to_owned());
            while i < lines.len() {
                let n = lines[i].trim();
                if n.starts_with("- ") || n.starts_with('#') || n.is_empty() {
                    break;
                }
                let key_indent = indent(lines[i]);
                i += 1;
                let Some((k, v)) = n.split_once(':') else {
                    continue;
                };
                let mut v = v.trim().to_owned();
                if v == ">-" || v == ">" {
                    let mut folded = Vec::new();
                    while i < lines.len()
                        && !lines[i].trim().is_empty()
                        && indent(lines[i]) > key_indent
                    {
                        folded.push(lines[i].trim());
                        i += 1;
                    }
                    v = folded.join(" ");
                }
                fields.insert(k.to_owned(), v);
            }
        }
        let Some(name) = fields.get("part") else {
            continue;
        };
        let words = |k: &str| -> Vec<String> {
            fields
                .get(k)
                .map(|v| v.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default()
        };
        let selections: Vec<Selection> = fields
            .get("packages")
            .map(String::as_str)
            .unwrap_or("")
            .split(';')
            .map(|s| s.split_whitespace().collect::<Vec<_>>())
            .filter(|w| !w.is_empty())
            .map(|w| Selection::parse(&w))
            .collect();
        assert!(
            !selections.is_empty(),
            "ci.yml: part {name} selects nothing"
        );
        assert!(
            out.iter().all(|p| &p.name != name),
            "ci.yml: two parts are named {name}"
        );
        out.push(Part {
            name: name.clone(),
            selections,
            filters: words("filter"),
            skips: words("skip"),
        });
    }
    for want in ["workspace", "celltest", "isolation-multi-cell", "devstack"] {
        assert!(
            out.iter().any(|p| p.name == want),
            "ci.yml has no test part {want}"
        );
    }
    out
}

fn selects(filters: &[String], skips: &[String], name: &str) -> bool {
    (filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str())))
        && !skips.iter().any(|s| name.contains(s.as_str()))
}

/// The package that `<top>/<dir>/Cargo.toml` names.
fn package_name(root: &str) -> String {
    read(&format!("{root}/Cargo.toml"))
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("name = \"")
                .and_then(|r| r.strip_suffix('"'))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("{root}/Cargo.toml names no package"))
}

/// The package root and target of a source file, from its path
/// relative to the repository root (`crates/<dir>/...` or
/// `tools/<dir>/...`).
fn target_of(file: &str) -> (String, Target) {
    let mut parts = file.splitn(3, '/');
    let (top, dir, rest) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap_or(""),
    );
    let target = if rest == "src/main.rs" || rest.starts_with("src/bin/") {
        Target::Bin
    } else if rest.starts_with("src/") {
        Target::Lib
    } else if let Some(t) = rest.strip_prefix("tests/") {
        match t.strip_suffix(".rs") {
            Some(name) if !name.contains('/') => Target::Test(name.to_owned()),
            _ => Target::TestModule,
        }
    } else {
        Target::Other
    };
    (format!("{top}/{dir}"), target)
}

/// The testkits run in parts of their own. Their matrix shards run one
/// test name each, under a different `FSTP_MATRIX_SHARD`, so the
/// exactly-once rule does not apply to them.
fn in_testkit(file: &str) -> bool {
    file.starts_with("crates/fstp-api-testkit/") || file.starts_with("crates/fstp-domain-testkit/")
}

/// The parts that run test `name` of `package`'s `target`.
fn parts_running(parts: &[Part], package: &str, target: &Target, name: &str) -> Vec<String> {
    parts
        .iter()
        .filter(|p| p.selections.iter().any(|s| s.runs(package, target)))
        .filter(|p| selects(&p.filters, &p.skips, name))
        .map(|p| p.name.clone())
        .collect()
}

/// Every test of the workspace outside the testkits, with the file that
/// defines it and the parts that run it.
fn placements(parts: &[Part]) -> Vec<(String, String, Vec<String>)> {
    let mut packages: BTreeMap<String, String> = BTreeMap::new();
    workspace_tests()
        .into_iter()
        .filter(|(file, _)| !in_testkit(file))
        .map(|(file, name)| {
            let (root, target) = target_of(&file);
            let package = packages
                .entry(root.clone())
                .or_insert_with(|| package_name(&root))
                .clone();
            let runs = parts_running(parts, &package, &target, &name);
            (file, name, runs)
        })
        .collect()
}

/// I-19, I-20, I-80, I-82, I-83 (design sections 14.4 and 14.8, W4): the
/// `isolation-multi-cell` CI part runs every `t_iso_*` and `t_db_iso_*`
/// test, the `i80_root_canary_*` scans and the process-mode isolation
/// tests, and no other part runs any of them.
#[test]
fn w4_isolation_part_runs_each_isolation_test_and_no_other_part_does() {
    let parts = ci_parts();
    let iso = parts
        .iter()
        .find(|p| p.name == "isolation-multi-cell")
        .unwrap();
    assert!(
        iso.selections
            .iter()
            .all(|s| !s.workspace && s.packages == ["fstp-celltest"]),
        "the isolation part runs fstp-celltest binaries only: {iso:?}"
    );
    let mut bad = Vec::new();
    let mut isolated = Vec::new();
    for (file, name, runs) in placements(&parts) {
        let isolation = name.starts_with("t_iso_")
            || name.starts_with("t_db_iso_")
            || name.starts_with("i80_root_canary_");
        if isolation && runs != ["isolation-multi-cell"] {
            bad.push(format!(
                "{file}: {name} is an isolation test and runs in {runs:?}"
            ));
        }
        if runs.iter().any(|r| r == "isolation-multi-cell") {
            isolated.push(name);
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(
        isolated.len() >= 10,
        "the isolation part selects too few tests: {isolated:?}"
    );
}

/// Every invariant and requirement test outside the testkits runs in
/// exactly one CI test part (Daniel, 2026-11-16). This is the full tier,
/// which adds nothing to the parts' filters and skips
/// (`ci_full_tier_adds_no_skip_and_no_case_cap`). The parts split the
/// workspace by package, by test binary and by libtest filter, and a
/// libtest skip matches its substring in every binary of its part. So
/// no part runs a test twice, and no skip or missing `--test` name
/// drops one.
#[test]
fn ci_test_parts_run_each_test_exactly_once() {
    let parts = ci_parts();
    let mut bad = Vec::new();
    let mut counted = 0usize;
    for (file, name, runs) in placements(&parts) {
        counted += 1;
        match runs.len() {
            1 => {}
            0 => bad.push(format!("{file}: {name} runs in no part")),
            _ => bad.push(format!("{file}: {name} runs in the parts {runs:?}")),
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(counted > 1000, "the check read too few tests: {counted}");
}

/// The fstp-celltest parts name their binaries one by one, so a new test
/// file must be named too (Daniel, 2026-11-16). Every
/// `crates/fstp-celltest/tests/*.rs` runs in at least one part, whether
/// or not this check reads a test in it. Every `--test` pattern of a
/// part matches a file, and every library's doc tests run in exactly one
/// part without a libtest filter.
#[test]
fn ci_every_celltest_file_and_doc_test_set_runs_in_a_part() {
    let parts = ci_parts();
    let mut bad = Vec::new();
    let mut files: Vec<String> = fs::read_dir(repo_root().join(CT))
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".rs")?;
            e.path().is_file().then(|| stem.to_owned())
        })
        .collect();
    files.sort();
    assert!(files.len() >= 50, "too few celltest files: {files:?}");
    for f in &files {
        let target = Target::Test(f.clone());
        let runs: Vec<&str> = parts
            .iter()
            .filter(|p| {
                p.selections
                    .iter()
                    .any(|s| s.runs("fstp-celltest", &target))
            })
            .map(|p| p.name.as_str())
            .collect();
        if runs.is_empty() {
            bad.push(format!("{CT}{f}.rs runs in no part"));
        }
    }
    for p in &parts {
        for s in &p.selections {
            if s.packages != ["fstp-celltest"] {
                continue;
            }
            for pattern in &s.tests {
                if !files.iter().any(|f| glob(pattern, f)) {
                    bad.push(format!("{}: --test {pattern} matches no file", p.name));
                }
            }
        }
    }
    let mut libraries = Vec::new();
    for top in ["crates", "tools"] {
        for e in fs::read_dir(repo_root().join(top)).unwrap().flatten() {
            let root = format!("{top}/{}", e.file_name().to_string_lossy());
            if e.path().join("src/lib.rs").is_file() && !in_testkit(&format!("{root}/")) {
                libraries.push(package_name(&root));
            }
        }
    }
    assert!(libraries.iter().any(|l| l == "fstp-celltest"));
    for lib in &libraries {
        let runs: Vec<&Part> = parts
            .iter()
            .filter(|p| p.selections.iter().any(|s| s.runs(lib, &Target::Doc)))
            .collect();
        match runs.as_slice() {
            [p] if p.filters.is_empty() => {}
            [p] => bad.push(format!(
                "{lib}: doc tests run under the filters of {}",
                p.name
            )),
            _ => bad.push(format!(
                "{lib}: doc tests run in {:?}",
                runs.iter().map(|p| &p.name).collect::<Vec<_>>()
            )),
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The pattern reader the parts rely on.
#[test]
fn ci_part_glob_reads_cargo_target_patterns() {
    assert!(glob("i79_recovery", "i79_recovery"));
    assert!(!glob("i79_recovery", "i79_recovery_x"));
    assert!(glob("review_*", "review_w1b_strength"));
    assert!(glob("review_*", "review_"));
    assert!(!glob("review_*", "i79_review_x"));
    assert!(glob("t_*", "t_iso_i19"));
    assert!(!glob("t_*", "teeth_m3_registry"));
    assert!(glob("*_world", "seam_world"));
    assert!(glob("a*b*c", "a_x_b_y_c"));
    assert!(!glob("a*b*c", "a_x_c"));
    assert!(!glob("ab*ba", "aba"));
}

// ---------------------------------------------------------------------------
// The CI tiers (Daniel, 2026-11-16, ADR-003). The light tier runs on every
// push and pull request, the full tier on a manual run with `full` ticked.

/// The heavy classes that the light tier may leave out, as libtest
/// substrings of a test path. The full tier runs them all.
///
/// - `_teeth_`: the teeth tests. Each plants a known bug and proves a
///   check catches it. The class matches test function names only.
/// - `matrix::tests::q34_`: the matrix layout self-checks of the
///   fstp-api-testkit library, exactly [`Q34_SELF_CHECKS`] (Daniel,
///   2026-11-16). A bare `q34_` would also drop
///   `q34_http_matrix_runs_the_covering_array`.
const LIGHT_HEAVY_CLASSES: &[&str] = &["_teeth_", "matrix::tests::q34_"];

/// The libtest paths of the class `matrix::tests::q34_`, all in
/// `crates/fstp-api-testkit/src/matrix.rs`. They ran 240 s to 421 s each
/// in CI run 43853477946.
const Q34_SELF_CHECKS: &[&str] = &[
    "matrix::tests::q34_covering_matrix_keeps_every_op_principal_state_and_session",
    "matrix::tests::q34_direct_matrix_runs_the_full_policy_product",
    "matrix::tests::q34_full_product_groups_partition_the_cells",
];

/// The parts that the light tier stops at their first step: every
/// `matrix-*` part and the part `m-activate` (Daniel, 2026-11-16).
const LIGHT_STOPPED_PARTS: &str =
    r#"if [[ ( "$PART" == matrix-* || "$PART" == m-activate ) && "$tier" != full ]]; then"#;

/// The property case cap of the light tier (Daniel, 2026-11-16).
const LIGHT_PROP_MAX_CASES: &str = "32";

const CI_YML: &str = ".github/workflows/ci.yml";
const DECIDE_STEP: &str = "Decide the tier and whether this part runs";
const TEST_STEP: &str = "cargo test, then the known-red gate";

/// The value that `ci.yml` gives `key` at the indent of the test job's
/// environment. It must be set exactly once.
fn ci_job_env(key: &str) -> String {
    let prefix = format!("      {key}: ");
    let hits: Vec<String> = read(CI_YML)
        .lines()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .collect();
    assert_eq!(hits.len(), 1, "ci.yml sets {key} {} times", hits.len());
    hits[0].clone()
}

/// The step of the test job named `name`: its `env` entries and the
/// trimmed lines of its `run: |` script.
fn ci_step(name: &str) -> (BTreeMap<String, String>, Vec<String>) {
    let ci = read(CI_YML);
    let lines: Vec<&str> = ci.lines().collect();
    let want = format!("- name: {name}");
    let at: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim() == want)
        .collect();
    assert_eq!(at.len(), 1, "ci.yml has {} steps named {name}", at.len());
    let step = indent(lines[at[0]]);
    let mut env = BTreeMap::new();
    let mut script = Vec::new();
    let mut i = at[0] + 1;
    while i < lines.len() {
        let l = lines[i];
        if !l.trim().is_empty() && indent(l) <= step {
            break;
        }
        i += 1;
        if l.trim() == "run: |" {
            let body = indent(l);
            while i < lines.len() && (lines[i].trim().is_empty() || indent(lines[i]) > body) {
                script.push(lines[i].trim().to_owned());
                i += 1;
            }
            break;
        }
        if l.trim() == "env:" {
            let body = indent(l);
            while i < lines.len() && !lines[i].trim().is_empty() && indent(lines[i]) > body {
                let (k, v) = lines[i].trim().split_once(": ").unwrap();
                env.insert(k.to_owned(), v.trim().to_owned());
                i += 1;
            }
        }
    }
    assert!(!script.is_empty(), "ci.yml: step {name} has no run script");
    (env, script)
}

/// The script lines of the arm `arm)` of the `case "$TIER"` in the test
/// step, up to and including its `;;`.
fn tier_arm<'a>(script: &'a [String], arm: &str) -> &'a [String] {
    let open = format!("{arm})");
    let at: Vec<usize> = (0..script.len())
        .filter(|&i| script[i].starts_with(open.as_str()))
        .collect();
    assert_eq!(at.len(), 1, "the test step has {} arms {open}", at.len());
    let end = (at[0]..script.len())
        .find(|&i| script[i].ends_with(";;"))
        .unwrap_or_else(|| panic!("the arm {open} has no ;;"));
    &script[at[0]..=end]
}

/// The module path that libtest puts before a test function of `file`
/// whose `fn` line is `at`: the modules of the file's place in its crate,
/// then the inline `mod` blocks around the line, found by indentation. A
/// test binary's own file name is not part of its paths. It does not
/// follow `#[path]` attributes. On 2026-11-16 it gave 6,747 paths exactly
/// as libtest printed them in CI run 43853477946. The rest differ only in
/// module prefixes that `#[path]` sets, and no heavy class can hide there:
/// the light check also refuses any `mod` name that holds a class.
fn module_path(file: &str, lines: &[&str], at: usize) -> Vec<String> {
    let rest = file.splitn(3, '/').nth(2).unwrap_or("");
    let mut path: Vec<String> = Vec::new();
    let within = match target_of(file).1 {
        Target::Lib => rest.strip_prefix("src/"),
        // `src/bin/<name>/<module>.rs`: the binary's own modules.
        Target::Bin => rest
            .strip_prefix("src/bin/")
            .and_then(|r| r.split_once('/'))
            .map(|(_, r)| r),
        Target::TestModule => rest
            .strip_prefix("tests/")
            .and_then(|r| r.split_once('/'))
            .map(|(_, r)| r),
        _ => None,
    };
    if let Some(within) = within {
        let stem = within.strip_suffix(".rs").unwrap_or(within);
        for seg in stem.split('/') {
            if !matches!(seg, "lib" | "main" | "mod") {
                path.push(seg.to_owned());
            }
        }
    }
    let mut inline = Vec::new();
    let mut level = indent(lines[at]);
    for line in lines[..at].iter().rev() {
        if level == 0 {
            break;
        }
        // Only a `mod` opener changes the level, so a string literal that
        // continues at column 0 does not end the search.
        let s = line.trim();
        let s = s.strip_prefix("pub ").unwrap_or(s);
        let s = s.strip_prefix("pub(crate) ").unwrap_or(s);
        if let Some(m) = s.strip_prefix("mod ").and_then(|m| m.strip_suffix(" {"))
            && indent(line) < level
        {
            inline.push(m.to_owned());
            level = indent(line);
        }
    }
    inline.reverse();
    path.extend(inline);
    path
}

/// Every `#[test]` of the workspace and the testkits: the file, the
/// function name and the libtest path.
fn workspace_test_paths() -> Vec<(String, String, String)> {
    let mut files = Vec::new();
    rust_files(&repo_root().join("crates"), &mut files);
    rust_files(&repo_root().join("tools"), &mut files);
    files.sort();
    let mut out = Vec::new();
    for f in files {
        let text = read(&f);
        let lines: Vec<&str> = text.lines().collect();
        for i in 0..lines.len() {
            let Some(name) = fn_name(lines[i]) else {
                continue;
            };
            if !attributes(&lines, i).iter().any(|a| a == "#[test]") {
                continue;
            }
            let mut path = module_path(&f, &lines, i);
            path.push(name.to_owned());
            out.push((f.clone(), name.to_owned(), path.join("::")));
        }
    }
    out
}

/// CI tiers (Daniel, 2026-11-16): the light tier leaves out only the
/// declared heavy classes. Every light skip lies inside a class, so it
/// drops no test whose libtest path lacks one. `_teeth_` matches test
/// function names only and drops at least 250 tests across the workspace
/// and the testkits. `matrix::tests::q34_` drops exactly the three
/// matrix layout self-checks. The parts the light tier stops are exactly
/// the `matrix-*` parts, each of which runs only authorisation matrix
/// tests, and `m-activate`, which runs only the I-66 and I-67 M-ACTIVATE
/// binaries.
#[test]
fn ci_light_tier_skips_only_the_declared_heavy_classes() {
    let skips: Vec<String> = ci_job_env("LIGHT_SKIP")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert!(!skips.is_empty(), "LIGHT_SKIP is empty");
    let in_class = |path: &str| LIGHT_HEAVY_CLASSES.iter().any(|c| path.contains(c));
    let mut bad = Vec::new();
    for s in &skips {
        if !in_class(s) {
            bad.push(format!("the light skip {s} is in no heavy class"));
        }
    }
    // No module name, whether a file or inline or under `#[path]`, holds
    // the last segment of a class (`_teeth_`, `q34_`), so a class reaches a
    // test only through its function name or the paths checked below.
    let last: Vec<&str> = LIGHT_HEAVY_CLASSES
        .iter()
        .map(|c| c.rsplit("::").next().unwrap_or(c))
        .collect();
    let mut files = Vec::new();
    rust_files(&repo_root().join("crates"), &mut files);
    rust_files(&repo_root().join("tools"), &mut files);
    for f in &files {
        if !matches!(target_of(f).1, Target::Test(_)) && last.iter().any(|c| f.contains(c)) {
            bad.push(format!("{f}: a module path holds a heavy class"));
        }
        for line in read(f).lines() {
            let s = line.trim_start();
            let s = s.strip_prefix("pub ").unwrap_or(s);
            let s = s.strip_prefix("pub(crate) ").unwrap_or(s);
            if let Some(m) = s.strip_prefix("mod ")
                && last.iter().any(|c| m.contains(c))
            {
                bad.push(format!("{f}: the module {m} holds a heavy class"));
            }
        }
    }
    let tests = workspace_test_paths();
    assert!(tests.len() > 1000, "the check read too few tests");
    let mut teeth = 0usize;
    let mut q34 = Vec::new();
    for (file, name, path) in &tests {
        if path.contains("_teeth_") {
            teeth += 1;
            if !name.contains("_teeth_") {
                bad.push(format!("{file}: {path} is teeth by its module path only"));
            }
        }
        if path.contains("matrix::tests::q34_") {
            q34.push(format!("{file}: {path}"));
        }
        if skips.iter().any(|s| path.contains(s.as_str())) && !in_class(path) {
            bad.push(format!("{file}: {path} is dropped and in no heavy class"));
        }
    }
    let want_q34: Vec<String> = Q34_SELF_CHECKS
        .iter()
        .map(|p| format!("crates/fstp-api-testkit/src/matrix.rs: {p}"))
        .collect();
    q34.sort();
    if q34 != want_q34 {
        bad.push(format!(
            "matrix::tests::q34_ matches {q34:#?}, not {want_q34:#?}"
        ));
    }
    let (_, decide) = ci_step(DECIDE_STEP);
    let stops: Vec<&String> = decide.iter().filter(|l| l.contains("run=false")).collect();
    assert_eq!(
        stops.len(),
        1,
        "the decide step stops parts twice: {decide:#?}"
    );
    assert!(
        decide.iter().any(|l| l == LIGHT_STOPPED_PARTS),
        "the light tier stops other parts than matrix-* and m-activate: {decide:#?}"
    );
    let parts = ci_parts();
    let stopped: Vec<&Part> = parts
        .iter()
        .filter(|p| p.name.starts_with("matrix-") || p.name == "m-activate")
        .collect();
    assert!(stopped.len() >= 4, "too few stopped parts");
    for p in stopped {
        for s in &p.selections {
            let only = if p.name == "m-activate" {
                !s.workspace
                    && s.packages == ["fstp-api-testkit"]
                    && !s.lib
                    && !s.bins
                    && !s.doc
                    && s.tests == ["i66_m_activate", "i67_m_activate"]
                    && p.filters.is_empty()
            } else {
                !s.workspace
                    && s.packages == ["fstp-api-testkit"]
                    && !s.bins
                    && !s.doc
                    && s.tests.iter().all(|t| t.contains("matrix"))
                    && (!s.lib
                        || (!p.filters.is_empty()
                            && p.filters.iter().all(|f| f.contains("matrix"))))
                    && s.names_targets()
            };
            if !only {
                bad.push(format!("{}: runs more than its heavy tests: {s:?}", p.name));
            }
        }
    }
    assert!(
        parts.iter().any(|p| p.name == "m-activate"),
        "ci.yml has no part m-activate"
    );
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(teeth >= 250, "the teeth class holds only {teeth} tests");
}

/// CI tiers (Daniel, 2026-11-16): the full tier is a manual run with the
/// one input `full` ticked, and it runs every part with its own filters
/// and skips and every property at its own case count. The light skips
/// and the case cap sit only in the light arm of the test step, the full
/// arm adds nothing, and an unknown tier fails the step. So the
/// exactly-once checks above hold for the full tier.
#[test]
fn ci_full_tier_adds_no_skip_and_no_case_cap() {
    let ci = read(CI_YML);
    let lines: Vec<&str> = ci.lines().collect();
    let inputs = lines
        .iter()
        .position(|l| l.trim() == "inputs:")
        .expect("ci.yml has no workflow_dispatch inputs");
    let names: Vec<&str> = lines[inputs + 1..]
        .iter()
        .take_while(|l| l.trim().is_empty() || indent(l) > indent(lines[inputs]))
        .filter(|l| indent(l) == indent(lines[inputs]) + 2)
        .map(|l| l.trim().trim_end_matches(':'))
        .collect();
    assert_eq!(names, ["full"], "the manual run takes the one input full");
    let (decide_env, decide) = ci_step(DECIDE_STEP);
    assert_eq!(
        decide_env.get("WANT_FULL").map(String::as_str),
        Some("${{ github.event_name == 'workflow_dispatch' && inputs.full }}")
    );
    assert!(
        decide
            .iter()
            .any(|l| l == r#"if [[ "$WANT_FULL" == true ]]; then tier=full; else tier=light; fi"#),
        "{decide:#?}"
    );
    let (test_env, script) = ci_step(TEST_STEP);
    assert_eq!(
        test_env.get("TIER").map(String::as_str),
        Some("${{ steps.part.outputs.tier }}")
    );
    let full = tier_arm(&script, "full");
    assert_eq!(full.len(), 1, "the full arm is one line: {full:#?}");
    assert!(
        full[0].starts_with("full) echo ")
            && !full[0].contains("+=")
            && !full[0].contains("export"),
        "the full arm adds nothing: {full:#?}"
    );
    let light = tier_arm(&script, "light");
    assert!(
        light.iter().any(|l| l
            == r#"for s in $LIGHT_SKIP; do libtest+=(--skip "$s"); gate+=(--skip "$s"); done"#),
        "{light:#?}"
    );
    assert!(
        light
            .iter()
            .any(|l| l == r#"export FSTP_PROP_MAX_CASES="$LIGHT_PROP_MAX_CASES""#),
        "{light:#?}"
    );
    assert!(
        script
            .iter()
            .any(|l| l == r#"*) echo "unknown tier '$TIER'"; exit 1 ;;"#),
        "an unknown tier must fail the step: {script:#?}"
    );
    // Every selection change outside the light arm is a part's own.
    let own = [
        r#"for f in $TEST_FILTER; do libtest+=("$f"); gate+=(--filter "$f"); done"#,
        r#"for s in $TEST_SKIP; do libtest+=(--skip "$s"); gate+=(--skip "$s"); done"#,
    ];
    let mut bad = Vec::new();
    for l in &script {
        if light.contains(l) || own.contains(&l.as_str()) {
            continue;
        }
        if l.contains("libtest+=") || l.contains("gate+=") || l.contains("--skip") {
            bad.push(format!(
                "the test step changes the selection outside the light arm: {l}"
            ));
        }
        if l.contains("LIGHT_") {
            bad.push(format!(
                "the test step reads a light setting outside the light arm: {l}"
            ));
        }
    }
    // No other line of ci.yml sets an fstp-prop variable.
    for l in &lines {
        let s = l.trim();
        if s.starts_with('#') || !s.contains("FSTP_PROP_") {
            continue;
        }
        if !light.iter().any(|x| x == s) {
            bad.push(format!(
                "ci.yml sets FSTP_PROP_* outside the light arm: {s}"
            ));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(ci_job_env("LIGHT_PROP_MAX_CASES"), LIGHT_PROP_MAX_CASES);
}
