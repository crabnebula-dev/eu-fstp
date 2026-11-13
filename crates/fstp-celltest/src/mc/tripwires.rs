//! Measured state counts of the M3 models (design sections 14.1 and 19).
//!
//! Each model runs exhaustively under a `max_states` tripwire at twice its
//! measured count, as in M2. Lane W4 records each measured count here.
//!
//! Status: M-AUTH, M-STEPUP and M-RECOVER were measured by the lead on
//! 2026-10-29 after lane W1b merged. M-VCP and M-DRIVER followed lane W1c,
//! M-SHRED lane W1d, M-AUDIT lane W1e, M-LICENCE lane W1g and M-PLACE lane
//! W1f. Every model count is now measured; [`NOT_MEASURED`] stays for a
//! model added later, and a tripwire of zero states stops every run.

/// The placeholder for a count that is not measured yet.
pub const NOT_MEASURED: usize = 0;

/// M-AUTH (I-77).
pub const M_AUTH: usize = 1905;
/// M-STEPUP (I-78).
pub const M_STEPUP: usize = 13184;
/// M-RECOVER (I-79).
pub const M_RECOVER: usize = 5006;
/// M-VCP (I-04, I-06, I-18, NOTE 4).
pub const M_VCP: usize = 33796;
/// M-DRIVER (I-23).
pub const M_DRIVER: usize = 2262;
/// M-SHRED (I-81).
pub const M_SHRED: usize = 99514;
/// M-AUDIT (I-24).
pub const M_AUDIT: usize = 90834;
/// M-PLACE (I-82, I-83).
pub const M_PLACE: usize = 107;
/// M-LICENCE (I-39).
pub const M_LICENCE: usize = 1425;

/// The tripwire for a measured count: twice the count.
pub const fn tripwire(measured: usize) -> usize {
    measured.saturating_mul(2)
}

/// M-DISPATCH (I-25, I-26), M6 design section 7 (T2). Measured by lane
/// L6-DISP on 2026-11-07.
pub const M_DISPATCH: usize = 51358;

/// One M3 model of design section 14.2, as lane W4 records it (design
/// section 19). `tests/teeth_m3_registry.rs` checks every row: the count
/// is measured, the runner bounds the model by [`tripwire`] of the named
/// constant, and each teeth test is in the M3 teeth registry.
#[derive(Clone, Copy, Debug)]
pub struct ModelRecord {
    /// The model's name in design section 14.2.
    pub model: &'static str,
    /// The invariants the model checks.
    pub invariants: &'static [&'static str],
    /// The name of the constant above that holds its measured count.
    pub constant: &'static str,
    /// The measured count.
    pub measured: usize,
    /// The test file that runs the model exhaustively, relative to the
    /// repository root.
    pub runner: &'static str,
    /// The teeth tests for the mutants that design section 14.2 names in
    /// the model's teeth column.
    pub teeth: &'static [&'static str],
}

/// The M3 exit models (design sections 14.2 and 20). M-DISPATCH is M6
/// work and is not an M3 exit model.
pub const M3_MODELS: &[ModelRecord] = &[
    ModelRecord {
        model: "M-AUTH",
        invariants: &["I-77"],
        constant: "M_AUTH",
        measured: M_AUTH,
        runner: "crates/fstp-celltest/tests/i77_login.rs",
        teeth: &[
            "i77_teeth_admit_method_ignores_scheduled_bindings_is_caught",
            "i77_teeth_grant_batch_omits_session_ended_is_caught",
        ],
    },
    ModelRecord {
        model: "M-STEPUP",
        invariants: &["I-78"],
        constant: "M_STEPUP",
        measured: M_STEPUP,
        runner: "crates/fstp-celltest/tests/i78_stepup.rs",
        teeth: &[
            "i78_teeth_step_up_exactly_p71_old_refused_is_caught",
            "i78_teeth_consumption_dropped_is_caught",
            "i78_teeth_digest_compared_by_kind_is_caught",
        ],
    },
    ModelRecord {
        model: "M-RECOVER",
        invariants: &["I-79"],
        constant: "M_RECOVER",
        measured: M_RECOVER,
        runner: "crates/fstp-celltest/tests/i79_recovery.rs",
        teeth: &["i79_teeth_path_checked_at_request_only_is_caught"],
    },
    ModelRecord {
        model: "M-VCP",
        invariants: &["I-04", "I-06", "I-18", "NOTE-4"],
        constant: "M_VCP",
        measured: M_VCP,
        runner: "crates/fstp-celltest/tests/i18_m_vcp.rs",
        teeth: &[
            "i18_m_vcp_note4_teeth_vault_answers_while_provisional_is_caught",
            "i18_m_vcp_note4_teeth_driver_acks_before_reaction_commits_is_caught",
            "i18_m_vcp_note4_teeth_fact_effective_without_ack_is_caught",
        ],
    },
    ModelRecord {
        model: "M-DRIVER",
        invariants: &["I-23"],
        constant: "M_DRIVER",
        measured: M_DRIVER,
        runner: "crates/fstp-celltest/tests/seam_m_driver.rs",
        teeth: &["seam_m_driver_i23_teeth_retry_with_fresh_command_id_is_caught"],
    },
    ModelRecord {
        model: "M-SHRED",
        invariants: &["I-81"],
        constant: "M_SHRED",
        measured: M_SHRED,
        runner: "crates/fstp-celltest/tests/i81_shred.rs",
        teeth: &[
            "i81_teeth_group_not_rotated_is_caught",
            "i81_teeth_destroy_before_commit_loses_data_is_caught",
            "i81_teeth_completion_before_receipt_is_caught",
        ],
    },
    ModelRecord {
        model: "M-AUDIT",
        invariants: &["I-24"],
        constant: "M_AUDIT",
        measured: M_AUDIT,
        runner: "crates/fstp-celltest/tests/i24_audit_chain.rs",
        teeth: &[
            "i24_teeth_m_audit_verifier_skips_receipt_comparison_is_caught",
            "i24_teeth_m_audit_abort_accepted_for_present_row_is_caught",
            "i24_teeth_m_audit_commit_before_receipt_is_caught",
        ],
    },
    ModelRecord {
        model: "M-PLACE",
        invariants: &["I-82", "I-83"],
        constant: "M_PLACE",
        measured: M_PLACE,
        runner: "crates/fstp-celltest/tests/i83_placement.rs",
        teeth: &["i83_teeth_first_free_cluster_is_caught"],
    },
    ModelRecord {
        model: "M-LICENCE",
        invariants: &["I-39"],
        constant: "M_LICENCE",
        measured: M_LICENCE,
        runner: "crates/fstp-celltest/tests/i39_m_licence.rs",
        teeth: &["i39_teeth_gate_on_release_payment_is_caught"],
    },
];
