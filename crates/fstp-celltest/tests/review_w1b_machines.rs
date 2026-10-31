//! Review reproducers for lane W1b, round 2 (adversarial verifier).
//!
//! Each test fails against the current models or tests, and passes once
//! the defect it names is fixed. Model runs use their own exhaustive
//! bound, so they do not wait for the tripwire counts of lane W4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::auth_model::{self as am, AuthAction, AuthModel};
use fstp_celltest::mc::recover_model::{self as rm, RecoverAction, RecoverModel, Variant};
use fstp_celltest::reference::auth as r;
use fstp_mc::{Config, Model, explore};

/// A bound far above every measured count, so each run is exhaustive.
fn wide() -> Config {
    Config::default().with_max_states(1_000_000)
}

/// I-77, design section 14.4: the HTTP machine
/// `i77_management_login_requires_phishing_resistant_method_over_http`
/// expects the cell to refuse a login exactly when M-AUTH has no step for
/// it (`got.is_some() == next.is_some()`). M-AUTH also has no step for a
/// login that its own bound prunes (two logins of the focused account).
/// A correct cell admits that third login, so the machine fails on it.
/// Every login M-AUTH offers in a machine state and then refuses must be
/// one the reference login rule refuses.
#[test]
fn review_i77_http_machine_reads_no_model_bound_as_a_login_refusal() {
    let model = AuthModel::new(am::Reference);
    let space = explore(&model, &wide());
    assert!(space.exhaustive, "M-AUTH over the reference did not finish");
    for s in space.states() {
        // The machine takes no revocation, so no revoked state is reached.
        if s.revoked {
            continue;
        }
        let mut actions = Vec::new();
        model.actions(s, &mut actions);
        for a in actions {
            let AuthAction::Login(i, m) = a else { continue };
            if model.step(s, &a).is_some() {
                continue;
            }
            let holds = s.roster().holds_management(am::account(i), s.now());
            assert!(
                r::admit_login(holds, m, true, am::ENABLED).is_err(),
                "M-AUTH offers {a:?} in {s:?} and has no step for it, but the login rule \
                 admits it, so the HTTP machine expects a correct cell to refuse it"
            );
        }
    }
}

/// I-79, design section 14.4: the HTTP machine
/// `i79_non_receiving_never_recovered_by_email_alone` expects
/// `POST /auth/recovery` to fail whenever M-RECOVER has no step for it.
/// M-RECOVER has none once `MAX_CASES` cases exist, a bound of the model
/// and no rule of design section 8.5. A correct cell opens the third case,
/// so the machine fails on it. No request M-RECOVER offers for an account
/// without an open case may lack a step.
#[test]
fn review_i79_http_machine_reads_no_model_bound_as_a_request_refusal() {
    let model = RecoverModel::new(rm::Reference);
    let space = explore(&model, &wide());
    assert!(
        space.exhaustive,
        "M-RECOVER over the reference did not finish"
    );
    for s in space.states() {
        if s.variant == Variant::SoleAdminSelfHosted {
            continue;
        }
        let mut actions = Vec::new();
        model.actions(s, &mut actions);
        for a in actions {
            let RecoverAction::Request(h) = a else {
                continue;
            };
            let open = s.cases.iter().any(|c| c.holder == h && !c.completed);
            assert!(
                open || model.step(s, &a).is_some(),
                "M-RECOVER offers {a:?} in {s:?} and has no step for it, though no rule \
                 refuses it, so the HTTP machine expects a correct cell to refuse it"
            );
        }
    }
}

/// I-78, design section 14.4: the I-78 test list names
/// `sod_07_self_grant_needs_second_admin_approval_of_the_same_digest`
/// (design section 5.1). Lane W1b writes the I-78 tests, and no test of
/// that name exists in this crate.
#[test]
fn review_i78_sod_07_self_grant_test_exists() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let wanted = "fn sod_07_self_grant_needs_second_admin_approval_of_the_same_digest(";
    let found = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("review_"))
        })
        .any(|p| {
            std::fs::read_to_string(&p)
                .map(|t| t.contains(wanted))
                .unwrap_or(false)
        });
    assert!(
        found,
        "no test named sod_07_self_grant_needs_second_admin_approval_of_the_same_digest \
         in {}",
        dir.display()
    );
}
