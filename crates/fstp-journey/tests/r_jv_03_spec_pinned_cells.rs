//! R-JV-03, I-93, O-54, O-57, O-58, O-60, P-10 NOTE 1: spec-pinned
//! example cases of the section 7.2 matrix.
//!
//! Each case states its expected verdict as a literal, read from the
//! spec cell it names. Both the production function and the reference
//! must give that verdict. Neither function decides what is expected, so
//! a shared misreading of a cell cannot pass here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod j2;

use fstp_domain::StateTag as S;
use fstp_domain::policy::ReadAccess;
use fstp_domain::roles::Role;
use fstp_domain_testkit::reference::diary::{self, Facts, Kind};
use j2::production_visible;

/// A case: the facts, the verdict the spec gives, and the cell.
struct Case {
    facts: Facts,
    want: bool,
    cell: &'static str,
}

/// Facts with every relation off, for `role` reading `kind` on `path`.
fn base(role: Role, kind: Kind, p10: ReadAccess, path: &[S]) -> Facts {
    Facts {
        role,
        viewer_programme: diary::PROGRAMMES[0],
        entry_programme: diary::PROGRAMMES[0],
        p10,
        kind,
        path: path.to_vec(),
        transition: None,
        team: false,
        guardian_of: false,
        assigned: false,
        declared_no_conflict: false,
        conflicted: false,
        own: false,
        complaint_reviewer: false,
        sod13_barred: false,
    }
}

const STAGE1: &[S] = &[S::Draft, S::Submitted, S::Stage1];
const WITHDRAWN: &[S] = &[S::Draft, S::Submitted, S::Stage1, S::Withdrawn];
const INELIGIBLE: &[S] = &[S::Draft, S::Submitted, S::Ineligible];
const NOT_SELECTED: &[S] = &[S::Draft, S::Submitted, S::Stage1, S::NotSelected];
const STAGE2: &[S] = &[S::Draft, S::Submitted, S::Stage1, S::Stage2];
const GRANTED: &[S] = &[
    S::Draft,
    S::Submitted,
    S::Stage1,
    S::Stage2,
    S::Ranked,
    S::IrcReview,
    S::Negotiation,
    S::Granted,
    S::InExecution,
];

use ReadAccess::OperatorStaffOnly as STAFF;
use ReadAccess::{AllCommitteeMembers as ALL, AssignedReviewersOnly as ASSIGNED};

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut add = |facts: Facts, want: bool, cell: &'static str| {
        out.push(Case { facts, want, cell });
    };

    // Reviewer score, reviewer column: "Own, and as P-10 allows".
    let mut f = base(Role::CommitteeMember, Kind::ReviewerScore, STAFF, STAGE1);
    f.assigned = true;
    f.declared_no_conflict = true;
    add(
        f.clone(),
        false,
        "score, reviewer, operator staff only, not own (J2-R3)",
    );
    f.own = true;
    add(f, true, "score, reviewer, own score");
    let mut f = base(Role::CommitteeMember, Kind::ReviewerScore, ASSIGNED, STAGE1);
    f.assigned = true;
    add(
        f,
        true,
        "score, reviewer, assigned reviewers only, assigned",
    );
    let mut f = base(Role::CommitteeMember, Kind::ReviewerScore, ASSIGNED, STAGE1);
    f.declared_no_conflict = true;
    add(
        f,
        false,
        "score, reviewer, assigned reviewers only, declared only",
    );
    let mut f = base(Role::CommitteeMember, Kind::ReviewerScore, ALL, STAGE1);
    f.declared_no_conflict = true;
    add(
        f,
        true,
        "score, committee member, all committee members, declared",
    );

    // State transition, reviewer column: "Assigned proposals, within P-10".
    let mut f = base(Role::CommitteeMember, Kind::StateTransition, STAFF, STAGE1);
    f.assigned = true;
    f.transition = Some((S::Submitted, S::Stage1));
    add(f, false, "transition, reviewer, operator staff only");
    let mut f = base(
        Role::CommitteeChair,
        Kind::StateTransition,
        ASSIGNED,
        STAGE1,
    );
    f.assigned = true;
    f.transition = Some((S::Submitted, S::Stage1));
    add(f, true, "transition, chair, assigned");

    // Reviewer score, voyager column: after a final decision only (O-54).
    for (path, want, cell) in [
        (WITHDRAWN, false, "score, voyager, WITHDRAWN (O-54)"),
        (INELIGIBLE, false, "score, voyager, INELIGIBLE (O-54)"),
        (STAGE2, false, "score, voyager, STAGE2 (O-54)"),
        (NOT_SELECTED, true, "score, voyager, NOT_SELECTED (O-54)"),
        (GRANTED, true, "score, voyager, after GRANTED (O-54)"),
    ] {
        let mut f = base(Role::Applicant, Kind::ReviewerScore, ASSIGNED, path);
        f.team = true;
        add(f, want, cell);
    }

    // Reviewer score, programme column: "Per P-10" (O-43).
    let mut f = base(Role::FstpCoordinator, Kind::ReviewerScore, STAFF, STAGE1);
    f.declared_no_conflict = true;
    add(f.clone(), true, "score, coordinator, operator staff only");
    f.p10 = ASSIGNED;
    add(f, false, "score, coordinator, assigned reviewers only");
    let mut f = base(Role::ProgrammeManager, Kind::ReviewerScore, STAFF, STAGE1);
    f.declared_no_conflict = true;
    add(f, false, "score, programme manager");

    // O-57: no entry before the coordinator declares.
    let mut f = base(
        Role::FstpCoordinator,
        Kind::StateTransition,
        ASSIGNED,
        STAGE1,
    );
    f.transition = Some((S::Submitted, S::Stage1));
    add(f, false, "transition, coordinator before declaring (O-57)");

    // State transition, operations column: "Grants only".
    for (leg, want, cell) in [
        (
            (S::Stage1, S::Stage2),
            false,
            "transition, finance, evaluation leg",
        ),
        (
            (S::Negotiation, S::Granted),
            true,
            "transition, finance, leg into GRANTED",
        ),
        (
            (S::Granted, S::InExecution),
            true,
            "transition, finance, grant leg",
        ),
    ] {
        let mut f = base(
            Role::FinanceApprover,
            Kind::StateTransition,
            ASSIGNED,
            GRANTED,
        );
        f.transition = Some(leg);
        add(f, want, cell);
    }

    // Vault outcome: operations yes, programme from NEGOTIATION.
    add(
        base(Role::PaymentReleaser, Kind::VaultOutcome, ASSIGNED, STAGE2),
        true,
        "vault, operations",
    );
    let mut f = base(Role::ProgrammeManager, Kind::VaultOutcome, ASSIGNED, STAGE2);
    add(
        f.clone(),
        false,
        "vault, programme manager before NEGOTIATION",
    );
    f.path = GRANTED.to_vec();
    add(f, true, "vault, programme manager from NEGOTIATION");

    // IRC (O-58), guardian (O-60), auditor, call drafter.
    let mut f = base(Role::IrcMember, Kind::StateTransition, ASSIGNED, GRANTED);
    f.assigned = true;
    f.transition = Some((S::IrcReview, S::Negotiation));
    add(f, true, "transition, IRC member, assigned (O-58)");
    let mut f = base(Role::IrcMember, Kind::ReviewerScore, ASSIGNED, GRANTED);
    f.assigned = true;
    add(f, false, "score, IRC member (O-58)");
    let mut f = base(Role::Guardian, Kind::GuardianStep, ASSIGNED, STAGE1);
    f.guardian_of = true;
    add(f, true, "guardian step, the named guardian (O-60)");
    let mut f = base(Role::Applicant, Kind::GuardianStep, ASSIGNED, STAGE1);
    f.team = true;
    f.own = true;
    add(f, false, "guardian step, the team (O-60)");
    add(
        base(Role::Auditor, Kind::GuardianStep, ASSIGNED, STAGE1),
        false,
        "guardian step, auditor (O-60)",
    );
    add(
        base(Role::Auditor, Kind::Conflict, ASSIGNED, STAGE1),
        true,
        "conflict, auditor",
    );
    let mut f = base(Role::Applicant, Kind::Conflict, ASSIGNED, STAGE1);
    f.team = true;
    add(f, false, "conflict, voyager");
    let mut f = base(Role::CallDrafter, Kind::StateTransition, ASSIGNED, STAGE1);
    f.own = true;
    f.transition = Some((S::Submitted, S::Stage1));
    add(f, false, "transition, call drafter");

    // Financial and legal signatories: interim, fail closed (design
    // section 15.0, lane j2). Section 7.2 and the section 1 actor table
    // name neither, and both bind tenant-wide (roles-and-sod.md NOTE 5).
    // They see no kind, even with every relation on and a grant leg.
    for role in [Role::FinancialSignatory, Role::LegalSignatory] {
        for kind in Kind::ALL {
            let mut f = base(role, kind, ASSIGNED, GRANTED);
            f.transition = (kind == Kind::StateTransition).then_some((S::Granted, S::InExecution));
            f.team = true;
            f.guardian_of = true;
            f.assigned = true;
            f.declared_no_conflict = true;
            f.own = true;
            f.complaint_reviewer = true;
            add(f, false, "signatory, any kind, fail closed (NOTE 5)");
        }
    }
    out
}

/// R-JV-03, I-93: every spec-pinned case gives the spec's verdict, in
/// production and in the reference.
#[test]
fn r_jv_03_spec_pinned_cells_give_the_spec_verdict() {
    let mut wrong = Vec::new();
    for c in cases() {
        let prod = production_visible(&c.facts);
        let reference = diary::visible(&c.facts);
        if prod != c.want || reference != c.want {
            wrong.push(format!(
                "{}: spec {}, production {prod}, reference {reference}",
                c.cell, c.want
            ));
        }
    }
    assert!(wrong.is_empty(), "R-JV-03: {wrong:#?}");
}
