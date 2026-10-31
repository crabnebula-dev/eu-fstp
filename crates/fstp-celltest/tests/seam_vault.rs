//! The vault seam of design section 14.6: the vault answers every query of
//! design section 6.4 as the M2 `GroundTruth` predicates do, over facts
//! that both can hold (`seam_pg_vault_matches_synthetic_vault`).
//!
//! Lane W1c wrote these tests before the production code. The production
//! test seeds `fstp_vault_core` through `vault_seed` and is red until lane
//! W2d lands it. The reference test checks this lane's reference against
//! the M2 synthetic vault, which another lane wrote, so the two references
//! are independent.
//!
//! The generator keeps to the facts both models share. Every account with
//! an identity is verified, since the M2 truth knows conflicts and
//! exclusions of unverified accounts and the vault cannot. Affiliations on
//! lists are declared for every account of a person, since the M2 truth
//! holds them per account and the vault per person. Each M2 consent is a
//! consent by a verified guardian.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_celltest::reference::vault::{self as rv, Org, Person, RefVault, RefWrite};
use fstp_celltest::vault_seed::{SeedLog, SeedSource, seed_fact};
use fstp_domain::id::{AccountId, ClassId, ProgrammeId, ProposalId, ProximityListId};
use fstp_domain::oracle::Query;
use fstp_domain::policy::ExclusionClasses;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::nonneg;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag, Relation};
use fstp_prop::{Gen, prop_assert_eq};

const ACCOUNTS: [AccountId; 5] = [
    AccountId::from_raw(101),
    AccountId::from_raw(102),
    AccountId::from_raw(103),
    AccountId::from_raw(104),
    AccountId::from_raw(105),
];
const GUARDIAN: AccountId = AccountId::from_raw(900);
const PROGRAMME: ProgrammeId = ProgrammeId::from_raw(1);
const CLASSES: [ClassId; 2] = [ClassId::from_raw(1), ClassId::from_raw(2)];
const LISTS: [ProximityListId; 2] = [ProximityListId::from_raw(1), ProximityListId::from_raw(2)];
const PROPOSALS: [ProposalId; 2] = [ProposalId::from_raw(1), ProposalId::from_raw(2)];
const DEADLINE: Timestamp = Timestamp::from_micros(4_000_000_000_000);
const NOW: i64 = 1_000_000;

fn list_org(l: ProximityListId) -> Org {
    Org(200 + u64::try_from(l.raw()).unwrap())
}

/// One world: the M2 truth, and the vault writes that hold the same facts.
struct Pair {
    truth: GroundTruth,
    writes: Vec<RefWrite>,
    p17: BTreeMap<ProgrammeId, BTreeSet<u16>>,
}

fn pair(g: &mut Gen) -> Pair {
    let mut truth = GroundTruth::new();
    let mut writes = Vec::new();
    let mut tags: BTreeMap<AccountId, u64> = BTreeMap::new();
    for a in ACCOUNTS {
        tags.insert(a, g.u64_in(1..=3));
    }
    for (a, t) in &tags {
        truth.set_identity(*a, IdentityTag::new(*t));
        truth.verify(*a);
        writes.push(RefWrite::VerificationRecorded {
            account: *a,
            person: Person(*t),
        });
    }
    writes.push(RefWrite::VerificationRecorded {
        account: GUARDIAN,
        person: Person(900),
    });
    for l in LISTS {
        writes.push(RefWrite::ProximityListDeclared {
            list: l,
            orgs: BTreeSet::from([list_org(l)]),
        });
    }
    let of_tag = |t: u64| -> Vec<AccountId> {
        tags.iter()
            .filter(|(_, x)| **x == t)
            .map(|(a, _)| *a)
            .collect()
    };
    for _ in 0..g.usize_in(0..=6) {
        match g.u8_in(0..=5) {
            0 => {
                let (ta, tb) = (g.u64_in(1..=3), g.u64_in(1..=3));
                let (Some(a), Some(b)) = (of_tag(ta).first().copied(), of_tag(tb).first().copied())
                else {
                    continue;
                };
                truth.relate(
                    IdentityTag::new(ta),
                    IdentityTag::new(tb),
                    Relation::Mentoring,
                );
                writes.push(RefWrite::Relationship { a, b });
            }
            1 => {
                let t = g.u64_in(1..=3);
                let Some(a) = of_tag(t).first().copied() else {
                    continue;
                };
                let class = *g.pick(&CLASSES);
                truth.exclude(IdentityTag::new(t), class);
                writes.push(RefWrite::AffiliationDeclared {
                    account: a,
                    org: Org(100 + u64::try_from(class.raw()).unwrap()),
                    class: Some(class),
                });
            }
            2 => {
                let p = *g.pick(&PROPOSALS);
                truth.consent(p);
                writes.push(RefWrite::GuardianConsent {
                    proposal: p,
                    guardian: GUARDIAN,
                });
            }
            3 => {
                let t = g.u64_in(1..=3);
                let l = *g.pick(&LISTS);
                for a in of_tag(t) {
                    truth.declare_affiliation(a, l);
                    writes.push(RefWrite::AffiliationDeclared {
                        account: a,
                        org: list_org(l),
                        class: None,
                    });
                }
            }
            4 => {
                let a = *g.pick(&ACCOUNTS);
                truth.meet_country(a, PROGRAMME);
                writes.push(RefWrite::CountryStated {
                    account: a,
                    programme: PROGRAMME,
                    country: 1,
                });
            }
            _ => {
                let a = *g.pick(&ACCOUNTS);
                let from = Timestamp::from_micros(DEADLINE.micros() + g.i64_in(-2..=2));
                truth.attest_adult(a, from);
                writes.push(RefWrite::AdultAttestation {
                    account: a,
                    adult_from: from,
                });
            }
        }
    }
    Pair {
        truth,
        writes,
        p17: BTreeMap::from([(PROGRAMME, BTreeSet::from([1]))]),
    }
}

fn accounts(g: &mut Gen) -> BTreeSet<AccountId> {
    ACCOUNTS.iter().copied().filter(|_| g.bool()).collect()
}

/// A map of committed amounts per account. A macro, since this crate has
/// no `fstp-money` dependency to name the amount type.
macro_rules! committed {
    ($g:expr) => {{
        let mut out = BTreeMap::new();
        for a in ACCOUNTS {
            if $g.bool() {
                out.insert(a, nonneg($g.i64_in(0..=5_000)).unwrap());
            }
        }
        out
    }};
}

/// A query of every kind of design section 6.4 but `ChangedSince`, whose
/// epochs the two models count differently. `with_country` adds the P-17
/// query.
fn query(g: &mut Gen, with_country: bool) -> Query {
    let a = *g.pick(&ACCOUNTS);
    let top = if with_country { 9 } else { 8 };
    match g.u8_in(0..=top) {
        0 => Query::IsVerified { account: a },
        1 => Query::SameIdentityAsAny {
            subject: a,
            others: accounts(g),
        },
        2 => Query::HasConflict {
            reviewer: a,
            team: accounts(g),
        },
        3 => Query::InExcludedClass {
            account: a,
            programme: PROGRAMME,
            classes: ExclusionClasses(CLASSES.iter().copied().filter(|_| g.bool()).collect()),
        },
        4 => Query::WithinRecipientCap {
            subject: a,
            amount: nonneg(g.i64_in(0..=5_000)).unwrap(),
            committed: committed!(g),
            cap: nonneg(g.i64_in(0..=12_000)).unwrap(),
        },
        5 => Query::AllRecipientsWithinCap {
            committed: committed!(g),
            cap: nonneg(g.i64_in(0..=12_000)).unwrap(),
        },
        6 => Query::HasGuardianConsent {
            proposal: *g.pick(&PROPOSALS),
        },
        7 => Query::IsVerifiedAdultAtDeadline {
            account: a,
            deadline: DEADLINE,
        },
        8 => Query::DeclaresAffiliationOnList {
            team: accounts(g),
            list: *g.pick(&LISTS),
        },
        _ => Query::MeetsTieBreakCountry {
            account: a,
            programme: PROGRAMME,
        },
    }
}

/// The reference vault holding `writes`, each made effective.
fn reference_vault(p: &Pair) -> RefVault {
    let mut v = RefVault::with_p17(p.p17.clone());
    for (i, w) in p.writes.iter().enumerate() {
        v.write(w.clone());
        let e = v.current();
        v.ack(e, u64::try_from(i).unwrap() + 1, [0; 32]).unwrap();
    }
    v
}

/// The design section 6.4 seam over the reference: every one-bit answer
/// equals the M2 `GroundTruth` predicate.
#[test]
fn seam_reference_vault_matches_synthetic_vault() {
    fstp_prop::check(
        "seam_reference_vault_matches_synthetic_vault",
        |g: &mut Gen| {
            let p = pair(g);
            let v = reference_vault(&p);
            for _ in 0..8 {
                let q = query(g, true);
                let got = v
                    .ask(None, std::slice::from_ref(&q))
                    .map_err(|e| format!("{e:?}"))?;
                prop_assert_eq!(got[0].holds, p.truth.holds(&q), "{q:?} over {:?}", p.writes);
                prop_assert_eq!(got[0].accounts.clone(), None);
            }
            Ok(())
        },
    );
}

/// The seam of the P-17 condition: `fstp_vault_core` has no way to hold a
/// programme's P-17 countries yet (lane W2d), so the production seam test
/// leaves out `MeetsTieBreakCountry`.
pub const P17_SEAM: &str = "fstp_vault_core holds no P-17 condition per programme (lane W2d)";

/// Design section 14.6, `seam_pg_vault_matches_synthetic_vault`: the vault
/// core, seeded through `vault_seed` with every fact made effective under
/// NOTE 4, answers as the M2 `GroundTruth` does.
///
/// Gap: the PostgreSQL-backed `fstp_vault` has no API yet (lane W2d), so
/// this drives the pure core it wraps. `MeetsTieBreakCountry` waits on
/// [`P17_SEAM`].
#[test]
fn seam_pg_vault_matches_synthetic_vault() {
    fstp_prop::check("seam_pg_vault_matches_synthetic_vault", |g: &mut Gen| {
        let p = pair(g);
        let mut state = fstp_vault_core::VaultState::default();
        let mut log = SeedLog::default();
        for (i, w) in p.writes.iter().enumerate() {
            let source = match w {
                RefWrite::VerificationRecorded { .. } => SeedSource::SyntheticVerification,
                RefWrite::GuardianConsent { .. } => SeedSource::SyntheticConsent,
                _ => SeedSource::SyntheticAffiliation,
            };
            seed_fact(&mut state, &mut log, source, rv::wire::fact_write(w), NOW)
                .map_err(|e| format!("seed: {e}"))?;
            let epoch = u64::try_from(i).unwrap() + 1;
            match fstp_vault_core::ack(&mut state, epoch, epoch) {
                Ok(_) => {}
                Err(fstp_vault_core::CoreError::NotImplemented(op)) => {
                    return Err(format!("{op} is NotImplemented"));
                }
                Err(e) => return Err(format!("ack of epoch {epoch} refused: {e:?}")),
            }
        }
        for _ in 0..8 {
            let q = query(g, false);
            let got = match fstp_vault_core::ask(&state, &[rv::wire::query(&q)]) {
                Ok(a) => a,
                Err(fstp_vault_core::CoreError::NotImplemented(op)) => {
                    return Err(format!("{op} is NotImplemented"));
                }
                Err(e) => return Err(format!("{q:?} refused: {e:?}")),
            };
            prop_assert_eq!(got.len(), 1);
            prop_assert_eq!(got[0].holds, p.truth.holds(&q), "{q:?} over {:?}", p.writes);
            prop_assert_eq!(
                got[0].accounts.clone(),
                None,
                "NOTE 5: one bit, no accounts"
            );
        }
        Ok(())
    });
}
