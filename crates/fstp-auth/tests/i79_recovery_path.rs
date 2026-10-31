//! `fstp_auth::recovery::recovery_path`: the recovery path table of I-79
//! (`authentication.md` "Account recovery", ADR-008 "Recovery", design
//! section 8.5, Q15).
//!
//! | Holdings | Other tenant admins | Deployment | Path |
//! | --- | --- | --- | --- |
//! | Receiving only, or none | any | any | `EmailThenPasskey` |
//! | Management or tenant admin | at least one | any | `SecondAdmin` |
//! | Management or tenant admin | none | SaaS | `OperatorProcess` |
//! | Management or tenant admin | none | self-hosted | `HostConsole` |
//!
//! Reading, shared with the W1b reference: an account outside Receiving
//! with no tenant admin to approve takes the operator path, as a sole
//! tenant admin does. I-79 forbids email alone, and no second admin
//! exists.
//!
//! The completion itself (path recomputed at completion, every credential
//! revoked, every session ended, the operator and host console paths shown
//! to the tenant) is checked in `i79_recovery_completion.rs` and by the
//! M-RECOVER model in `fstp-celltest`.
//!
//! Lane W2b test author.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::real;
use fstp_auth::recovery::{Deployment, Holdings, RecoveryPath, recovery_path};
use fstp_prop::{Gen, check, prop_assert_ne};

/// The other-admin counts each table test runs over.
const COUNTS: [usize; 4] = [0, 1, 2, usize::MAX];

/// Both deployments.
const MODES: [Deployment; 2] = [Deployment::Saas, Deployment::SelfHosted];

/// The path, or a panic that names the stub.
#[track_caller]
fn path(h: Holdings, others: usize, mode: Deployment) -> RecoveryPath {
    match recovery_path(h, others, mode) {
        Ok(p) => p,
        Err(e) => panic!("recovery_path({h:?}, {others}, {mode:?}) refused: {e:?}"),
    }
}

/// I-79, `authentication.md`: applicants and grantees recover through a
/// verified email, then a new passkey, whatever the admin count.
#[test]
fn i79_receiving_only_recovers_by_email_then_passkey() {
    for others in COUNTS {
        for mode in MODES {
            assert_eq!(
                path(Holdings::ReceivingOnly, others, mode),
                RecoveryPath::EmailThenPasskey,
                "{others} other admins, {mode:?}"
            );
        }
    }
}

/// I-79: a non-Receiving account with another tenant admin needs that
/// admin's approval (`SecondAdmin`).
#[test]
fn i79_management_holder_with_an_admin_needs_second_admin() {
    for others in [1, 2, usize::MAX] {
        for mode in MODES {
            assert_eq!(
                path(Holdings::Management, others, mode),
                RecoveryPath::SecondAdmin,
                "{others} other admins, {mode:?}"
            );
        }
    }
}

/// I-79, `authentication.md`: a tenant admin is recovered by another
/// tenant admin when one exists.
#[test]
fn i79_tenant_admin_with_another_admin_needs_second_admin() {
    for others in [1, 2, usize::MAX] {
        for mode in MODES {
            assert_eq!(
                path(Holdings::TenantAdmin, others, mode),
                RecoveryPath::SecondAdmin,
                "{others} other admins, {mode:?}"
            );
        }
    }
}

/// I-79, `authentication.md`: the sole tenant admin of a SaaS cell needs
/// the platform operator's verified process (`OperatorProcess`).
#[test]
fn i79_sole_admin_saas_needs_operator_process() {
    assert_eq!(
        path(Holdings::TenantAdmin, 0, Deployment::Saas),
        RecoveryPath::OperatorProcess
    );
}

/// I-79, `authentication.md` (decided 2026-10-28): on a self-hosted cell
/// the operator's verified process for a sole tenant admin is a host
/// console command (`HostConsole`).
#[test]
fn i79_sole_admin_self_hosted_needs_host_console() {
    assert_eq!(
        path(Holdings::TenantAdmin, 0, Deployment::SelfHosted),
        RecoveryPath::HostConsole
    );
}

/// I-79, reading: a management holder with no tenant admin to approve
/// takes the operator path of the deployment, never email alone.
#[test]
fn i79_management_holder_without_admin_takes_the_operator_path() {
    assert_eq!(
        path(Holdings::Management, 0, Deployment::Saas),
        RecoveryPath::OperatorProcess
    );
    assert_eq!(
        path(Holdings::Management, 0, Deployment::SelfHosted),
        RecoveryPath::HostConsole
    );
}

/// I-79: an account outside the Receiving group is never given the email
/// path, for any admin count and deployment.
#[test]
fn i79_non_receiving_never_gets_the_email_path() {
    check(
        "i79_non_receiving_never_gets_the_email_path",
        |g: &mut Gen| {
            let h = *g.pick(&[Holdings::Management, Holdings::TenantAdmin]);
            let others = g.usize();
            let mode = *g.pick(&MODES);
            let got = recovery_path(h, others, mode);
            real("recovery_path", &got)?;
            prop_assert_ne!(
                got,
                Ok(RecoveryPath::EmailThenPasskey),
                "{h:?}, {others} other admins, {mode:?}"
            );
            Ok(())
        },
    );
}
