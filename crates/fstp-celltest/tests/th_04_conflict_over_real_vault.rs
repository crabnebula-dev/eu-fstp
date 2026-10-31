//! TH-04 (T-SOD-CONFLICT): `HasConflict` over reviewer declarations and
//! I-54 relationships in the real vault (design sections 6.8 and 12, I-03,
//! I-54, Q31).
//!
//! Lane W1c wrote these tests before the production code. The production
//! test drives `fstp_vault_core` and is red until lane W2d lands it.
//!
//! Gap: "the real vault" with PostgreSQL waits for `fstp_vault`, which has
//! no API beyond its decoders yet. This test drives the pure vault core
//! that the service wraps.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::mc::vcp_model::{
    AskReply, Production, Reference, VOp, VcpVault, reference_vault,
};
use fstp_celltest::reference::vault::{Org, Person, RefWrite};
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Query;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert_eq};

const REVIEWER: AccountId = AccountId::from_raw(211);
const REVIEWER_TWIN: AccountId = AccountId::from_raw(212);
const LEAD: AccountId = AccountId::from_raw(301);
const MEMBER: AccountId = AccountId::from_raw(311);
const MENTOR: AccountId = AccountId::from_raw(321);
const ACCOUNTS: [AccountId; 5] = [REVIEWER, REVIEWER_TWIN, LEAD, MEMBER, MENTOR];
const PERSONS: [Person; 4] = [Person(1), Person(2), Person(3), Person(4)];
const ORGS: [Org; 3] = [Org(1), Org(2), Org(3)];

/// One fact of the conflict machine: a verification, a reviewer
/// declaration, an I-54 relationship or an affiliation.
fn conflict_write(g: &mut Gen) -> RefWrite {
    match g.u8_in(0..=4) {
        0 => RefWrite::VerificationRecorded {
            account: *g.pick(&ACCOUNTS),
            person: *g.pick(&PERSONS),
        },
        1 => {
            let mut relatives = BTreeSet::new();
            for p in PERSONS {
                if g.bool() {
                    relatives.insert(p);
                }
            }
            RefWrite::ReviewerDeclaration {
                reviewer: *g.pick(&[REVIEWER, REVIEWER_TWIN]),
                employer: g.option(|g| *g.pick(&ORGS)),
                relatives,
            }
        }
        2 => RefWrite::Relationship {
            a: *g.pick(&ACCOUNTS),
            b: *g.pick(&ACCOUNTS),
        },
        3 => RefWrite::AffiliationDeclared {
            account: *g.pick(&[LEAD, MEMBER, MENTOR]),
            org: *g.pick(&ORGS),
            class: None,
        },
        _ => RefWrite::AffiliationEnded {
            account: *g.pick(&[LEAD, MEMBER, MENTOR]),
            org: *g.pick(&ORGS),
        },
    }
}

/// A history of writes, each acknowledged at once, so each is effective.
/// With `open_last`, the last write stays provisional.
fn history(g: &mut Gen) -> Vec<VOp> {
    let mut h = Vec::new();
    let n = g.usize_in(0..=10);
    for i in 0..n {
        h.push(VOp::Write(conflict_write(g)));
        let last = i + 1 == n;
        if !(last && g.bool()) {
            let epoch = reference_vault(&h).current();
            h.push(VOp::Ack {
                epoch,
                seq: u64::try_from(i).unwrap() + 1,
            });
        }
    }
    h
}

fn conflict_query(g: &mut Gen) -> Query {
    let mut team = BTreeSet::from([LEAD]);
    if g.bool() {
        team.insert(MEMBER);
    }
    Query::HasConflict {
        reviewer: REVIEWER,
        team,
    }
}

type Candidate<'a> = &'a dyn Fn(&[VOp], &Query) -> Result<AskReply, String>;

fn th04_property(g: &mut Gen, candidate: Candidate<'_>) -> Result<(), String> {
    let h = history(g);
    let q = conflict_query(g);
    let want = Reference.ask(&h, None, std::slice::from_ref(&q)).unwrap();
    let got = candidate(&h, &q)?;
    prop_assert_eq!(got, want, "TH-04: {q:?} after {h:?}");
    Ok(())
}

/// TH-04 (T-SOD-CONFLICT): the vault core answers `HasConflict` over
/// reviewer declarations, I-54 relationships, affiliations and shared
/// identity as the reference does, and refuses it as pending while a
/// provisional fact touches it (NOTE 4).
#[test]
fn th_04_t_sod_conflict_over_real_vault() {
    fstp_prop::check("th_04_t_sod_conflict_over_real_vault", |g: &mut Gen| {
        th04_property(g, &|h, q| {
            Production
                .ask(h, None, std::slice::from_ref(q))
                .map_err(|e| format!("{} is NotImplemented", e.operation))
        })
    });
}

/// TH-04 teeth: a vault that ignores reviewer declarations misses the
/// relative and employer conflicts of Q31.
#[test]
fn th_04_teeth_declarations_ignored_is_caught() {
    let mutant = |h: &[VOp], q: &Query| -> Result<AskReply, String> {
        let mut stripped: Vec<VOp> = Vec::new();
        for op in h {
            match op {
                VOp::Write(RefWrite::ReviewerDeclaration { .. }) => {
                    stripped.push(VOp::Write(RefWrite::Relationship {
                        a: MENTOR,
                        b: MENTOR,
                    }));
                }
                other => stripped.push(other.clone()),
            }
        }
        Ok(Reference
            .ask(&stripped, None, std::slice::from_ref(q))
            .unwrap())
    };
    let outcome = fstp_prop::run(
        "th_04_teeth_declarations_ignored_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| th04_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "TH-04") {
        panic!("{e}");
    }
}

/// TH-04, I-54: a mentoring relationship recorded between the reviewer's
/// twin account and the lead is a conflict once both are effective.
#[test]
fn th_04_reference_relationship_through_shared_identity_is_a_conflict() {
    let mut h = Vec::new();
    for (i, w) in [
        RefWrite::VerificationRecorded {
            account: REVIEWER,
            person: Person(1),
        },
        RefWrite::VerificationRecorded {
            account: REVIEWER_TWIN,
            person: Person(1),
        },
        RefWrite::Relationship {
            a: REVIEWER_TWIN,
            b: LEAD,
        },
    ]
    .into_iter()
    .enumerate()
    {
        h.push(VOp::Write(w));
        h.push(VOp::Ack {
            epoch: u64::try_from(i).unwrap() + 1,
            seq: 1,
        });
    }
    let q = Query::HasConflict {
        reviewer: REVIEWER,
        team: BTreeSet::from([LEAD]),
    };
    match Reference.ask(&h, None, &[q]).unwrap() {
        AskReply::Answered(a) => assert!(a[0].holds, "TH-04: the I-54 conflict was missed"),
        other => panic!("TH-04: the reference did not answer: {other:?}"),
    }
}
