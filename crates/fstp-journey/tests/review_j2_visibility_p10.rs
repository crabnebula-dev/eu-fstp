//! Review reproducers J2-R3 and J2-R4 (I-93, R-JV-03, P-10 NOTE 1, O-43):
//! under P-10 "operator staff only" no committee member reads another
//! reviewer's score, and the reference reads P-10 as
//! `fstp_domain::visibility` does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::StateTag;
use fstp_domain::id::ProgrammeId;
use fstp_domain::policy::ReadAccess;
use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Facts, Kind};
use fstp_journey::visibility::{EntryFacts, EntryKind, Relation, Viewer, visible};

const P: ProgrammeId = ProgrammeId::from_raw(1);

fn path() -> Vec<StateTag> {
    vec![StateTag::Draft, StateTag::Submitted, StateTag::Stage1]
}

/// J2-R3, I-93, O-43: an assigned committee member who declared no
/// conflict does not see another reviewer's score under "operator staff
/// only".
#[test]
fn review_i93_p10_operator_staff_only_hides_other_scores_from_reviewers() {
    let viewer = Viewer {
        role: Role::CommitteeMember,
        programme: P,
        relation: Relation {
            assigned: true,
            declared_no_conflict: true,
            own: false,
            ..Relation::default()
        },
    };
    let entry = EntryFacts {
        kind: EntryKind::ReviewerScore,
        programme: P,
        path: path(),
        transition: None,
    };
    assert!(
        !visible(&viewer, ReadAccess::OperatorStaffOnly, &entry),
        "I-93, O-43: a committee member reads another score under operator staff only"
    );
}

/// J2-R4, R-JV-03: the reference reads "operator staff only" as the
/// domain does: no committee member reads.
#[test]
fn review_r_jv_03_reference_reads_p10_operator_staff_only_as_the_domain() {
    let f = Facts {
        role: Role::CommitteeMember,
        viewer_programme: P,
        entry_programme: P,
        p10: ReadAccess::OperatorStaffOnly,
        kind: Kind::ReviewerScore,
        path: path(),
        transition: None,
        team: false,
        guardian_of: false,
        assigned: true,
        declared_no_conflict: true,
        conflicted: false,
        own: false,
        complaint_reviewer: false,
        sod13_barred: false,
    };
    assert!(
        !diary::visible(&f),
        "R-JV-03: the reference lets a committee member read under operator staff only"
    );
}
