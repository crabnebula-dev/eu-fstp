//! Q35 A, `overview.md` NOTE 8, ADR-027: the two creator queries of the
//! vault core.
//!
//! - `ClassesDefined` (I-04): yes when every P-13 class of the set appears
//!   on an effective affiliation of the view. The vault holds no class
//!   register, so a class with no declared member is unknown.
//! - `ProximityListsDeclared` (I-35, P-38): yes when every list of the set
//!   has an effective `ProximityListDeclared` fact.
//! - Each answers one bit and names no account (NOTE 5). A provisional
//!   write does not count until it is effective (NOTE 4).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::BTreeSet;

use fstp_prop::{Gen, check, prop_assert_eq};
use fstp_vault_core::{Fact, Org, VaultEvent, VaultState, ack, ask, write_fact};
use fstp_vault_proto::{Query, WireAccount, WireClass, WireList, WireProgramme};

const PROGRAMME: WireProgramme = WireProgramme(7);

/// Writes `f` and returns its provisional epoch.
fn provisional(s: &mut VaultState, f: Fact) -> u64 {
    let events = write_fact(s, f, 0).unwrap();
    events
        .iter()
        .find_map(|e| match e {
            VaultEvent::Provisional { epoch } => Some(*epoch),
            VaultEvent::Effective { .. } => None,
        })
        .unwrap()
}

/// Writes `f` and acknowledges its epoch, so it is effective.
fn commit(s: &mut VaultState, f: Fact) {
    let epoch = provisional(s, f);
    ack(s, epoch, epoch).unwrap();
}

fn staff(account: u128, org: u128, class: Option<u128>) -> Fact {
    Fact::AffiliationDeclared {
        account: WireAccount(account),
        org: Org(org),
        class: class.map(WireClass),
        partner_staff: true,
    }
}

fn list(id: u128, orgs: &[u128]) -> Fact {
    Fact::ProximityListDeclared {
        list: WireList(id),
        orgs: orgs.iter().copied().map(Org).collect(),
    }
}

fn one_bit(s: &VaultState, q: Query) -> bool {
    let a = ask(s, &[q.to_wire().unwrap()]).unwrap();
    assert_eq!(a.len(), 1);
    assert!(a[0].accounts.is_none(), "NOTE 5: one bit, no account");
    a[0].holds
}

fn classes(s: &VaultState, ids: &[u128]) -> bool {
    one_bit(
        s,
        Query::ClassesDefined {
            programme: PROGRAMME,
            classes: ids.iter().copied().map(WireClass).collect(),
        },
    )
}

fn lists(s: &VaultState, ids: &[u128]) -> bool {
    one_bit(
        s,
        Query::ProximityListsDeclared {
            programme: PROGRAMME,
            lists: ids.iter().copied().map(WireList).collect(),
        },
    )
}

/// Q35, I-04: a class the vault knows answers yes, an unknown class no,
/// and a set answers yes only when it knows every class. The empty set
/// answers yes.
#[test]
fn q35_classes_defined_answers_known_and_unknown() {
    let mut s = VaultState::default();
    assert!(classes(&s, &[]), "the empty set is known");
    assert!(!classes(&s, &[1]), "an empty vault knows no class");
    commit(&mut s, staff(10, 100, Some(1)));
    assert!(classes(&s, &[1]), "class 1 is on an effective affiliation");
    assert!(!classes(&s, &[1, 2]), "class 2 is unknown");
    commit(&mut s, staff(11, 101, Some(2)));
    assert!(classes(&s, &[1, 2]));
    // An affiliation with no class defines none.
    commit(&mut s, staff(12, 102, None));
    assert!(!classes(&s, &[3]));
}

/// Q35, NOTE 4: a provisional affiliation does not define its class until
/// the cell acknowledges it.
#[test]
fn q35_classes_defined_counts_effective_facts_only() {
    let mut s = VaultState::default();
    let epoch = provisional(&mut s, staff(10, 100, Some(1)));
    assert!(!classes(&s, &[1]), "a provisional fact does not count");
    ack(&mut s, epoch, epoch).unwrap();
    assert!(classes(&s, &[1]));
}

/// Q35, I-35, P-38: a declared list answers yes, an undeclared one no.
/// The empty set answers yes.
#[test]
fn q35_proximity_lists_declared_answers_known_and_unknown() {
    let mut s = VaultState::default();
    assert!(lists(&s, &[]), "the empty set is declared");
    assert!(!lists(&s, &[5]), "an empty vault holds no list");
    commit(&mut s, list(5, &[100, 101]));
    assert!(lists(&s, &[5]));
    assert!(!lists(&s, &[5, 6]), "list 6 is not declared");
    commit(&mut s, list(6, &[102]));
    assert!(lists(&s, &[5, 6]));
}

/// Q35, NOTE 8: over random facts, each answer is the set inclusion it
/// states, and it never names an account.
#[test]
fn q35_answers_are_set_inclusion_over_random_facts() {
    check(
        "q35_answers_are_set_inclusion_over_random_facts",
        |g: &mut Gen| {
            let mut s = VaultState::default();
            let mut known_classes = BTreeSet::new();
            let mut known_lists = BTreeSet::new();
            for i in 0..g.u8_in(0..=6) {
                let account = 10 + u128::from(i);
                if g.bool() {
                    let class = u128::from(g.u8_in(1..=4));
                    commit(&mut s, staff(account, 100 + account, Some(class)));
                    known_classes.insert(class);
                } else {
                    let id = u128::from(g.u8_in(1..=4));
                    commit(&mut s, list(id, &[100 + account]));
                    known_lists.insert(id);
                }
            }
            let asked_classes: Vec<u128> = g.vec(0..=3, |g| u128::from(g.u8_in(1..=4)));
            let asked_lists: Vec<u128> = g.vec(0..=3, |g| u128::from(g.u8_in(1..=4)));
            prop_assert_eq!(
                classes(&s, &asked_classes),
                asked_classes.iter().all(|c| known_classes.contains(c))
            );
            prop_assert_eq!(
                lists(&s, &asked_lists),
                asked_lists.iter().all(|l| known_lists.contains(l))
            );
            Ok(())
        },
    );
}
