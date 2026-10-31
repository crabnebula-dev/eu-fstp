//! The NOTE 4 commit protocol of `fstp_vault_core` (design section 6.3,
//! I-04, I-06, NOTE 3).
//!
//! 1. A new fact is provisional at a new epoch. One provisional epoch at a
//!    time; later writes queue.
//! 2. `affected` lists the accounts the fact touches, and every account
//!    that facts revealed by a verification touch.
//! 3. `ask` refuses as pending any query that names an affected account,
//!    unless it is the reaction to the provisional epoch. A reaction sees
//!    the provisional fact.
//! 4. The cell reacts, appends the reaction, then acknowledges.
//! 5. `ack` makes the fact effective and dequeues the next write. A
//!    repeated `ack` is accepted.
//!
//! These tests drive the core through `common::Vault`. The M-VCP model in
//! `fstp-celltest` checks the same protocol against W1c's reference. Here
//! each step has its own test, and one property compares random step
//! sequences with a small model of the protocol.
//!
//! Gap (lane report): `VaultEvent` has no `Queued` event, so a queued
//! write shows as a write with no event.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::{BTreeSet, VecDeque};

use common::{Fail, RQuery, Vault, fact, provisional_of, refusal, set};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault_core::VaultEvent;
use fstp_vault_proto::VaultRefusal;

const A: u128 = 101;
const B: u128 = 102;
const C: u128 = 103;
const PERSON_AB: u128 = 1_001;
const PERSON_C: u128 = 1_003;
const PROGRAMME: u128 = 1;
const K1: u128 = 1;
const ORG: u128 = 31;

fn verified(a: u128) -> RQuery {
    RQuery::IsVerified { account: a }
}

/// I-06, NOTE 4 step 1: the first write is provisional at epoch 1, and
/// the effective epoch stays 0.
#[test]
fn i06_first_write_is_provisional_at_epoch_one() -> Result<(), Fail> {
    let mut v = Vault::new();
    let events = v.write(fact::verification(A, PERSON_AB))?;
    assert_eq!(events, vec![VaultEvent::Provisional { epoch: 1 }]);
    assert_eq!(v.effective(), 0);
    Ok(())
}

/// I-06, NOTE 4 step 1: while an epoch is provisional, a later write
/// queues. It opens no epoch and makes nothing effective.
#[test]
fn i06_later_writes_queue_behind_the_provisional_one() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.write(fact::verification(A, PERSON_AB))?;
    let events = v.write(fact::verification(C, PERSON_C))?;
    assert_eq!(provisional_of(&events), None, "{events:?}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, VaultEvent::Effective { .. })),
        "{events:?}"
    );
    assert_eq!(v.effective(), 0);
    Ok(())
}

/// I-06, NOTE 4 step 5: the acknowledgement makes the provisional fact
/// effective and opens the queued write at the next epoch.
#[test]
fn i06_ack_makes_the_fact_effective_and_opens_the_next() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.write(fact::verification(A, PERSON_AB))?;
    v.write(fact::verification(C, PERSON_C))?;
    let events = v.ack(1, 1)?;
    assert_eq!(
        events,
        vec![
            VaultEvent::Effective { epoch: 1 },
            VaultEvent::Provisional { epoch: 2 }
        ]
    );
    assert_eq!(v.effective(), 1);
    assert!(v.holds(verified(A))?, "A is verified at epoch 1");
    assert_eq!(
        refusal(v.ask(&[verified(C)]))?,
        VaultRefusal::Pending { epoch: 2 }
    );
    Ok(())
}

/// I-06, NOTE 4 step 3: a query about the account a provisional fact
/// touches is refused as pending, and the fact does not count.
#[test]
fn i06_queries_about_affected_accounts_are_pending() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.write(fact::verification(A, PERSON_AB))?;
    assert_eq!(
        refusal(v.ask(&[verified(A)]))?,
        VaultRefusal::Pending { epoch: 1 }
    );
    assert_eq!(
        refusal(v.ask(&[
            verified(C),
            RQuery::SameIdentityAsAny {
                subject: C,
                others: set([A]),
            }
        ]))?,
        VaultRefusal::Pending { epoch: 1 },
        "one affected query refuses the whole ask"
    );
    Ok(())
}

/// I-06, NOTE 4 step 2 (confirmed 2026-10-25): a verification that
/// reveals B as A's person makes queries about A pending too.
#[test]
fn i06_verification_makes_revealed_accounts_pending() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(A, PERSON_AB))?;
    v.write(fact::verification(B, PERSON_AB))?;
    assert_eq!(
        refusal(v.ask(&[verified(A)]))?,
        VaultRefusal::Pending { epoch: 2 }
    );
    assert!(!v.holds(verified(C))?, "C is untouched and answered");
    Ok(())
}

/// I-06, NOTE 3: a query no provisional fact touches is answered over
/// the effective facts, and the answer carries the effective epoch.
#[test]
fn i06_unaffected_queries_are_answered_at_the_effective_epoch() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(C, PERSON_C))?;
    v.write(fact::verification(A, PERSON_AB))?;
    let answers = v.ask(&[verified(C), verified(B)])?;
    assert_eq!(answers.len(), 2);
    assert!(answers[0].holds && !answers[1].holds, "{answers:?}");
    assert!(
        answers.iter().all(|a| a.epoch == 1 && a.accounts.is_none()),
        "{answers:?}"
    );
    Ok(())
}

/// I-06, NOTE 4 step 5: a repeated acknowledgement of an effective epoch
/// is accepted and changes nothing.
#[test]
fn i06_repeated_ack_is_accepted_and_changes_nothing() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(A, PERSON_AB))?;
    v.write(fact::verification(C, PERSON_C))?;
    let again = v.ack(1, 1)?;
    assert!(
        !again
            .iter()
            .any(|e| matches!(e, VaultEvent::Effective { .. })),
        "{again:?}"
    );
    assert_eq!(v.effective(), 1);
    assert_eq!(
        refusal(v.ask(&[verified(C)]))?,
        VaultRefusal::Pending { epoch: 2 },
        "the provisional epoch stays provisional"
    );
    Ok(())
}

/// I-06, NOTE 4: an acknowledgement of an epoch that is neither
/// provisional nor effective is refused as stale, with the current epoch.
#[test]
fn i06_ack_of_an_unknown_epoch_is_refused_as_stale() -> Result<(), Fail> {
    let mut v = Vault::new();
    assert_eq!(
        refusal(v.ack(1, 1))?,
        VaultRefusal::StaleEpoch { current: 0 }
    );
    v.commit(fact::verification(A, PERSON_AB))?;
    v.write(fact::verification(C, PERSON_C))?;
    for e in [0, 3, u64::MAX] {
        assert_eq!(
            refusal(v.ack(e, 9))?,
            VaultRefusal::StaleEpoch { current: 2 },
            "epoch {e}"
        );
    }
    assert_eq!(v.effective(), 1);
    Ok(())
}

/// I-06, NOTE 4: `ChangedSince` names no account, so it is never pending.
/// Outside a reaction it lists only effective changes.
#[test]
fn i06_changed_since_is_never_pending() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(C, PERSON_C))?;
    v.write(fact::verification(A, PERSON_AB))?;
    let a = v.ask(&[RQuery::ChangedSince { epoch: 0 }])?;
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].accounts, Some(vec![fstp_vault_proto::WireAccount(C)]));
    assert!(a[0].holds);
    Ok(())
}

/// I-06, NOTE 4 step 3: the reaction to the provisional epoch sees the
/// provisional fact, and its answers carry that epoch.
#[test]
fn i06_reaction_ask_sees_the_provisional_fact() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(A, PERSON_AB))?;
    v.write(fact::verification(B, PERSON_AB))?;
    let a = v.react(
        2,
        &[
            RQuery::SameIdentityAsAny {
                subject: B,
                others: set([A]),
            },
            RQuery::ChangedSince { epoch: 1 },
        ],
    )?;
    assert_eq!(a.len(), 2);
    assert!(a[0].holds && a[0].epoch == 2, "{a:?}");
    let changed: BTreeSet<u128> = a[1].accounts.iter().flatten().map(|x| x.0).collect();
    assert!(
        changed.is_superset(&set([A, B])),
        "the change lists the revealed account: {a:?}"
    );
    Ok(())
}

/// I-06, NOTE 4: a reaction that names another epoch is refused as stale.
#[test]
fn i06_reaction_ask_for_another_epoch_is_stale() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(A, PERSON_AB))?;
    v.write(fact::verification(B, PERSON_AB))?;
    for e in [1, 3] {
        assert_eq!(
            refusal(v.react(e, &[verified(B)]))?,
            VaultRefusal::StaleEpoch { current: 2 }
        );
    }
    Ok(())
}

/// I-04, NOTE 4 ("the vault marks a new verification or affiliation as
/// provisional"): a classed affiliation is pending until acknowledged,
/// then counts.
#[test]
fn i04_affiliation_is_pending_until_acknowledged() -> Result<(), Fail> {
    let mut v = Vault::new();
    let q = RQuery::InExcludedClass {
        account: C,
        programme: PROGRAMME,
        classes: set([K1]),
    };
    assert!(!v.holds(q.clone())?);
    let events = v.write(fact::affiliation(C, ORG, Some(K1)))?;
    let epoch = provisional_of(&events).unwrap();
    assert_eq!(
        refusal(v.ask(std::slice::from_ref(&q)))?,
        VaultRefusal::Pending { epoch }
    );
    v.ack(epoch, 7)?;
    assert!(v.holds(q)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// The protocol against a model.

/// One write of the model: a verification or a classed affiliation of
/// one account. Each account has its own person, so a write touches only
/// its account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MWrite {
    Verify(u128),
    Affiliate(u128),
}

impl MWrite {
    fn account(self) -> u128 {
        match self {
            MWrite::Verify(a) | MWrite::Affiliate(a) => a,
        }
    }

    fn fact(self) -> fstp_vault_core::FactWrite {
        match self {
            MWrite::Verify(a) => fact::verification(a, a + 1_000),
            MWrite::Affiliate(a) => fact::affiliation(a, ORG, Some(K1)),
        }
    }
}

#[derive(Debug, Default)]
struct Model {
    effective: Vec<MWrite>,
    provisional: Option<MWrite>,
    queue: VecDeque<MWrite>,
}

impl Model {
    fn epoch(&self) -> u64 {
        u64::try_from(self.effective.len()).unwrap()
    }

    fn current(&self) -> u64 {
        self.epoch() + u64::from(self.provisional.is_some())
    }

    fn holds(&self, q: MWrite) -> bool {
        self.effective.contains(&q)
    }
}

const ACCOUNTS: [u128; 3] = [A, B, C];

fn query_of(w: MWrite) -> RQuery {
    match w {
        MWrite::Verify(a) => verified(a),
        MWrite::Affiliate(a) => RQuery::InExcludedClass {
            account: a,
            programme: PROGRAMME,
            classes: set([K1]),
        },
    }
}

fn gen_write(g: &mut Gen) -> MWrite {
    let a = *g.pick(&ACCOUNTS);
    if g.bool() {
        MWrite::Verify(a)
    } else {
        MWrite::Affiliate(a)
    }
}

/// I-04, I-06, NOTE 4: random sequences of writes, acknowledgements (the
/// right epoch, a repeat, a stale one) and asks agree with the model at
/// every step. Events, the effective epoch, pending refusals, answer bits
/// and answer epochs are all compared.
#[test]
fn i06_note4_commit_protocol_matches_its_model() {
    fstp_prop::check(
        "i06_note4_commit_protocol_matches_its_model",
        |g: &mut Gen| {
            let mut v = Vault::new();
            let mut m = Model::default();
            let stub = |f: Fail| format!("{f:?}");
            for step in 0..g.usize_in(1..=24) {
                match g.u8_in(0..=2) {
                    0 => {
                        let w = gen_write(g);
                        let events = v.write(w.fact()).map_err(stub)?;
                        if m.provisional.is_none() {
                            m.provisional = Some(w);
                            prop_assert_eq!(
                                events,
                                vec![VaultEvent::Provisional { epoch: m.current() }],
                                "step {step}: write {w:?}"
                            );
                        } else {
                            m.queue.push_back(w);
                            prop_assert!(
                                provisional_of(&events).is_none()
                                    && !events
                                        .iter()
                                        .any(|e| matches!(e, VaultEvent::Effective { .. })),
                                "step {step}: queued write {w:?} gave {events:?}"
                            );
                        }
                    }
                    1 => {
                        let choice = g.u8_in(0..=2);
                        let epoch = match choice {
                            0 => m.current(),
                            1 => g.u64_in(1..=m.epoch().max(1)),
                            _ => m.current() + g.u64_in(1..=3),
                        };
                        let got = v.ack(epoch, epoch);
                        match m.provisional {
                            Some(p) if epoch == m.current() => {
                                m.effective.push(p);
                                m.provisional = m.queue.pop_front();
                                let mut want = vec![VaultEvent::Effective { epoch }];
                                if m.provisional.is_some() {
                                    want.push(VaultEvent::Provisional { epoch: m.current() });
                                }
                                prop_assert_eq!(
                                    got.map_err(stub)?,
                                    want,
                                    "step {step}: ack {epoch}"
                                );
                            }
                            _ if epoch >= 1 && epoch <= m.epoch() => {
                                let events = got.map_err(stub)?;
                                prop_assert!(
                                    !events
                                        .iter()
                                        .any(|e| matches!(e, VaultEvent::Effective { .. })),
                                    "step {step}: repeated ack {epoch} gave {events:?}"
                                );
                            }
                            _ => {
                                prop_assert_eq!(
                                    refusal(got).map_err(stub)?,
                                    VaultRefusal::StaleEpoch {
                                        current: m.current()
                                    },
                                    "step {step}: stale ack {epoch}"
                                );
                            }
                        }
                    }
                    _ => {
                        let w = gen_write(g);
                        let got = v.ask(&[query_of(w)]);
                        match m.provisional {
                            Some(p) if p.account() == w.account() => {
                                prop_assert_eq!(
                                    refusal(got).map_err(stub)?,
                                    VaultRefusal::Pending { epoch: m.current() },
                                    "step {step}: ask {w:?}"
                                );
                            }
                            _ => {
                                let a = got.map_err(stub)?;
                                prop_assert_eq!(a.len(), 1);
                                prop_assert_eq!(a[0].holds, m.holds(w), "step {step}: ask {w:?}");
                                prop_assert_eq!(a[0].epoch, m.epoch());
                                prop_assert_eq!(a[0].accounts.clone(), None);
                            }
                        }
                    }
                }
                prop_assert_eq!(v.effective(), m.epoch(), "step {step}: effective epoch");
            }
            Ok(())
        },
    );
}

/// NOTE 5, design section 6.2: a `ChangedSince` answer never lists more
/// ids than the response may hold. Past the bound it lists the whole
/// epochs that fit, and its epoch is the last of them, so the cell asks
/// again from there and reaches every epoch.
#[test]
fn note5_changed_since_is_cut_at_whole_epochs_within_the_bound() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([
        fact::relationship(1, 2),
        fact::relationship(3, 4),
        fact::relationship(5, 6),
    ])?;
    let changed = |since| RQuery::ChangedSince { epoch: since };
    let all = v.ask_bounded(&[changed(0)], 6)?;
    assert_eq!(all[0].epoch, 3, "everything fits: the effective epoch");
    assert_eq!(all[0].accounts.as_ref().map(Vec::len), Some(6));
    let cut = v.ask_bounded(&[changed(0)], 5)?;
    assert_eq!(cut[0].epoch, 2, "cut after the last whole epoch that fits");
    let ids: Vec<u128> = cut[0].accounts.iter().flatten().map(|a| a.0).collect();
    assert_eq!(ids, vec![1, 2, 3, 4]);
    let rest = v.ask_bounded(&[changed(cut[0].epoch)], 5)?;
    assert_eq!(rest[0].epoch, 3, "the next ask reaches the effective epoch");
    let ids: Vec<u128> = rest[0].accounts.iter().flatten().map(|a| a.0).collect();
    assert_eq!(ids, vec![5, 6]);
    // Two answers share one bound: the second gets what the first left.
    let two = v.ask_bounded(&[changed(0), changed(0)], 6)?;
    assert_eq!(two[0].epoch, 3);
    assert_eq!(
        two[1].epoch, 0,
        "nothing fits: the answer stays at its epoch"
    );
    assert_eq!(two[1].accounts, Some(Vec::new()));
    assert!(!two[1].holds);
    Ok(())
}
