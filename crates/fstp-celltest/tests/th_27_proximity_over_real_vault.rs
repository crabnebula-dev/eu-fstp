//! TH-27 (T-SOD-ASSIGN): `DeclaresAffiliationOnList` over P-38 proximity
//! lists written by the programme manager, in the real vault (design
//! sections 6.8 and 12, I-35, Q31).
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
use fstp_domain::id::{AccountId, ProximityListId};
use fstp_domain::oracle::Query;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert_eq};

const LEAD: AccountId = AccountId::from_raw(301);
const MEMBER: AccountId = AccountId::from_raw(311);
const TWIN: AccountId = AccountId::from_raw(312);
const ACCOUNTS: [AccountId; 3] = [LEAD, MEMBER, TWIN];
const LISTS: [ProximityListId; 2] = [ProximityListId::from_raw(1), ProximityListId::from_raw(2)];
const ORGS: [Org; 4] = [Org(1), Org(2), Org(3), Org(4)];

fn orgs(g: &mut Gen) -> BTreeSet<Org> {
    ORGS.iter().copied().filter(|_| g.bool()).collect()
}

/// One fact of the proximity machine: a list declared or re-declared by
/// the programme manager, an affiliation declared or ended, or a
/// verification that joins the member's twin to the member's person.
fn proximity_write(g: &mut Gen) -> RefWrite {
    match g.u8_in(0..=3) {
        0 => RefWrite::ProximityListDeclared {
            list: *g.pick(&LISTS),
            orgs: orgs(g),
        },
        1 => RefWrite::AffiliationDeclared {
            account: *g.pick(&ACCOUNTS),
            org: *g.pick(&ORGS),
            class: None,
        },
        2 => RefWrite::AffiliationEnded {
            account: *g.pick(&ACCOUNTS),
            org: *g.pick(&ORGS),
        },
        _ => RefWrite::VerificationRecorded {
            account: *g.pick(&[MEMBER, TWIN]),
            person: Person(9),
        },
    }
}

fn history(g: &mut Gen) -> Vec<VOp> {
    let mut h = Vec::new();
    let n = g.usize_in(0..=10);
    for i in 0..n {
        h.push(VOp::Write(proximity_write(g)));
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

fn list_query(g: &mut Gen) -> Query {
    let mut team = BTreeSet::from([LEAD]);
    if g.bool() {
        team.insert(MEMBER);
    }
    Query::DeclaresAffiliationOnList {
        team,
        list: *g.pick(&LISTS),
    }
}

type Candidate<'a> = &'a dyn Fn(&[VOp], &Query) -> Result<AskReply, String>;

fn th27_property(g: &mut Gen, candidate: Candidate<'_>) -> Result<(), String> {
    let h = history(g);
    let q = list_query(g);
    let want = Reference.ask(&h, None, std::slice::from_ref(&q)).unwrap();
    let got = candidate(&h, &q)?;
    prop_assert_eq!(got, want, "TH-27: {q:?} after {h:?}");
    Ok(())
}

/// TH-27 (T-SOD-ASSIGN): the vault core answers
/// `DeclaresAffiliationOnList` as the reference does. It reads the newest
/// effective P-38 list and the effective affiliations of every account of
/// a team member's person. It refuses the query as pending while a
/// provisional list or affiliation touches it (NOTE 4).
#[test]
fn th_27_t_sod_assign_proximity_list_over_real_vault() {
    fstp_prop::check(
        "th_27_t_sod_assign_proximity_list_over_real_vault",
        |g: &mut Gen| {
            th27_property(g, &|h, q| {
                Production
                    .ask(h, None, std::slice::from_ref(q))
                    .map_err(|e| format!("{} is NotImplemented", e.operation))
            })
        },
    );
}

/// TH-27 teeth: a vault that keeps the first declaration of a list and
/// ignores the programme manager's later one is caught.
#[test]
fn th_27_teeth_stale_list_is_caught() {
    let mutant = |h: &[VOp], q: &Query| -> Result<AskReply, String> {
        let mut seen: BTreeSet<ProximityListId> = BTreeSet::new();
        let mut kept: Vec<VOp> = Vec::new();
        for op in h {
            match op {
                VOp::Write(RefWrite::ProximityListDeclared { list, .. }) if seen.contains(list) => {
                    kept.push(VOp::Write(RefWrite::AffiliationEnded {
                        account: LEAD,
                        org: Org(99),
                    }));
                }
                VOp::Write(RefWrite::ProximityListDeclared { list, .. }) => {
                    seen.insert(*list);
                    kept.push(op.clone());
                }
                other => kept.push(other.clone()),
            }
        }
        Ok(Reference.ask(&kept, None, std::slice::from_ref(q)).unwrap())
    };
    let outcome = fstp_prop::run(
        "th_27_teeth_stale_list_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| th27_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "TH-27") {
        panic!("{e}");
    }
}
