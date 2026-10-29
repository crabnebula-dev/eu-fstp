//! I-66, M4 design section 3.2 "Bound to a revision": the end of a
//! programme manager binding on the draft is a record on the programme.
//! Under reading R1 it is an edit, so it voids the acknowledgement and
//! the request made before it (interim, pending Daniel).
//!
//! These tests run on the reference. The production creator folds the
//! same records through `CreatorState::observe_core`, which the unit
//! tests of `fstp-creator` check.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{ActivateConfig, check_i66, check_i67, model_plan};
use fstp_api_testkit::reference::creator::{
    Base, M1, M2, RefCheck, RefCommand, RefRefusal, RefSystem, StepVerdict, TA, TB,
};

/// The M-ACTIVATE plan without the seeded failure: only the roster
/// warning is left.
fn system() -> RefSystem {
    let mut plan = model_plan(ActivateConfig { sybil: false });
    plan.seeds.remove(&RefCheck::FieldUnset);
    RefSystem::open(&plan).unwrap()
}

/// I-66, R-PG-03: A1 ends M1's binding after M1 acknowledged and
/// requested. A2's approval at the new head finds no live request, and a
/// new request still needs a new acknowledgement.
#[test]
fn i66_binding_end_voids_acknowledgement_and_request() {
    let mut s = system();
    assert!(s.apply(&RefCommand::Grant { by: TA, to: M2 }).accepted());
    for cmd in [
        RefCommand::Acknowledge {
            by: M1,
            warning: RefCheck::RosterShort,
            base: Base::Head,
        },
        RefCommand::Request {
            by: M1,
            base: Base::Head,
        },
        RefCommand::EndBinding { by: TA, of: M1 },
    ] {
        assert_eq!(s.apply(&cmd), StepVerdict::Accepted, "{cmd:?}");
    }
    let approve = RefCommand::Approve {
        by: TB,
        base: Base::Head,
    };
    assert_eq!(
        s.apply(&approve),
        StepVerdict::Refused(RefRefusal::NoLiveRequest)
    );
    assert_eq!(
        s.apply(&RefCommand::Request {
            by: M2,
            base: Base::Head,
        }),
        StepVerdict::Accepted
    );
    assert_eq!(
        s.apply(&approve),
        StepVerdict::Refused(RefRefusal::Unacknowledged(RefCheck::RosterShort))
    );
    check_i66(&s.stat, &s.events).unwrap();
    check_i67(&s.stat, &s.events).unwrap();
}

/// I-66: a binding end names a live binding, and only a tenant admin
/// ends it. The former manager can no longer edit.
#[test]
fn i66_binding_end_needs_an_admin_and_a_binding() {
    let mut s = system();
    assert_eq!(
        s.apply(&RefCommand::EndBinding { by: M1, of: M1 }),
        StepVerdict::Refused(RefRefusal::NotTenantAdmin)
    );
    assert_eq!(
        s.apply(&RefCommand::EndBinding { by: TA, of: M2 }),
        StepVerdict::Refused(RefRefusal::NoSuchBinding)
    );
    assert_eq!(
        s.apply(&RefCommand::EndBinding { by: TA, of: M1 }),
        StepVerdict::Accepted
    );
    assert_eq!(
        s.apply(&RefCommand::Request {
            by: M1,
            base: Base::Head,
        }),
        StepVerdict::Refused(RefRefusal::NotProgrammeManager)
    );
}
