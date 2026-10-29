//! Self-tests of the vault doubles (`docs/handoff/m2-design.md` section 4.5,
//! `SPEC/03-architecture/overview.md` identity vault, NOTE 1 to NOTE 5).
//!
//! The synthetic vault must answer every query kind exactly as its ground
//! truth says. The reference here is written from the overview text and
//! keeps its own record of the facts, so it shares no code with the vault.
//! `HavocOracle` returns exactly its script, and `DownOracle` always fails.
//! The corpus-variant fixtures (`SPEC/07-test-plan/synthetic-corpus.md`)
//! build truths whose answers match their variant. Every id is a small
//! synthetic number.
//!
//! API this file is written against (design 4.5, completed by this lane):
//! - `IdentityTag::new(u64)`; `Relation::{CoWorker, Relative, Mentoring}`;
//!   `PendingFact::{Excluded { identity, class }, Related { a, b, relation }}`;
//! - `GroundTruth::new()`, `epoch()`, and the mutators `set_identity`,
//!   `verify`, `relate`, `exclude`, `add_pending`, `consent`,
//!   `declare_affiliation` and `meet_country`; the removals `unrelate`,
//!   `unexclude`, `end_affiliation` and `withdraw_consent`; and the NOTE 4
//!   mutators `verify_provisional`, `declare_affiliation_provisional` and
//!   `make_effective`;
//! - `SyntheticVault::new(truth)`, `truth()`, `truth_mut()`;
//! - `HavocOracle::new(epoch, script)`, `set`, `set_changed`,
//!   `advance_epoch`, `script` and `changed`, and `DownOracle`;
//! - `sybil_pair`, `excluded_applicant`, `repeat_applicant` and
//!   `minor_applicant`, each taking `(&mut Gen, &mut GroundTruth)`.
//!
//! Readings taken where the spec is silent, raised in the lane report:
//! - every mutator call advances the vault epoch by exactly one;
//! - a verified identity is a verified account's identity tag, so
//!   `SameIdentityAsAny` and identity grouping for the caps count verified
//!   accounts only, and the subject itself counts when it is in the set;
//! - conflicts and exclusions are facts about identities, known for every
//!   account with an identity tag, verified or not;
//! - two accounts with one identity are always in conflict;
//! - a pending fact counts only once the named account is verified
//!   (design 4.5), and adding it changes no account;
//! - under the NOTE 4 commit protocol a provisional verification or
//!   affiliation advances the epoch and appears in `ChangedSince` only;
//!   `make_effective` then makes it count, as a separate change;
//! - removing a fact advances the epoch and logs the accounts it touches;
//! - affiliations on proximity lists and the P-17 bit are per account;
//! - an account changes when a fact about it or its identity takes effect,
//!   and `ChangedSince` lists every account changed after the given epoch;
//! - an unverified account, or one without an identity tag, forms its own
//!   cap group;
//! - a query missing from a havoc script fails closed with `OracleDown`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, ClassId, ProgrammeId, ProposalId, ProximityListId, VaultEpoch};
use fstp_domain::oracle::{OracleDown, Query, QueryKind};
use fstp_domain::policy::ExclusionClasses;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::vault::{
    DownOracle, GroundTruth, HavocOracle, IdentityTag, PendingFact, PriorDeliverables, Relation,
    SyntheticVault, excluded_applicant, minor_applicant, repeat_applicant, sybil_pair,
};
use fstp_engine::IdentityOracle;
use fstp_money::{Amount, Currency, NonNegAmount};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// An independent record of the facts
// ---------------------------------------------------------------------------

/// One change to the vault, applied to both the vault and the reference.
#[derive(Clone, Debug)]
enum Op {
    SetIdentity(u128, u64),
    Verify(u128),
    Relate(u64, u64, Relation),
    Exclude(u64, u128),
    PendingExcluded(u128, u64, u128),
    PendingRelated(u128, u64, u64, Relation),
    Consent(u128),
    DeclareAffiliation(u128, u128),
    MeetCountry(u128, u128),
    Unrelate(u64, u64, Relation),
    Unexclude(u64, u128),
    EndAffiliation(u128, u128),
    WithdrawConsent(u128),
    VerifyProvisional(u128),
    AffiliateProvisional(u128, u128),
    MakeEffective(u128),
    /// An effective over-18 attestation: account and the instant from which it shows 18 or older.
    AttestAdult(u128, i64),
    /// A provisional over-18 attestation (NOTE 4).
    AttestAdultProvisional(u128, i64),
    /// The over-18 attestation of the account is withdrawn.
    WithdrawAttestation(u128),
}

/// A pending fact in the reference: an exclusion or a relation.
#[derive(Clone, Debug)]
enum Fact {
    Excluded(u64, u128),
    Related(u64, u64, Relation),
}

/// The reference's record of the facts, written from the overview text.
#[derive(Default, Debug)]
struct Facts {
    epoch: u64,
    identity: BTreeMap<u128, u64>,
    verified: BTreeSet<u128>,
    relations: BTreeSet<(u64, u64, Relation)>,
    excluded: BTreeSet<(u64, u128)>,
    pending: BTreeMap<u128, Vec<Fact>>,
    consents: BTreeSet<u128>,
    affiliations: BTreeSet<(u128, u128)>,
    country: BTreeSet<(u128, u128)>,
    /// Provisional verifications (NOTE 4). No query but `ChangedSince` sees them.
    provisional_verified: BTreeSet<u128>,
    /// Provisional affiliations (NOTE 4). No query but `ChangedSince` sees them.
    provisional_affiliations: BTreeSet<(u128, u128)>,
    /// Effective over-18 attestations, by account (overview NOTE 7).
    adults: BTreeMap<u128, i64>,
    /// Provisional over-18 attestations (NOTE 4). No query but `ChangedSince` sees them.
    provisional_adults: BTreeMap<u128, i64>,
    /// The accounts changed by the change that produced each epoch.
    changes: Vec<(u64, BTreeSet<u128>)>,
}

impl Facts {
    fn accounts_with(&self, tags: &[u64]) -> BTreeSet<u128> {
        self.identity
            .iter()
            .filter(|(_, t)| tags.contains(t))
            .map(|(a, _)| *a)
            .collect()
    }

    fn apply(&mut self, op: &Op) {
        let changed = match op {
            Op::SetIdentity(a, t) => {
                self.identity.insert(*a, *t);
                [*a].into_iter().collect()
            }
            Op::Verify(a) => self.verify(*a),
            Op::Relate(x, y, r) => {
                self.relations.insert((*x, *y, *r));
                self.accounts_with(&[*x, *y])
            }
            Op::Exclude(t, c) => {
                self.excluded.insert((*t, *c));
                self.accounts_with(&[*t])
            }
            Op::PendingExcluded(a, t, c) => {
                self.pending
                    .entry(*a)
                    .or_default()
                    .push(Fact::Excluded(*t, *c));
                BTreeSet::new()
            }
            Op::PendingRelated(a, x, y, r) => {
                self.pending
                    .entry(*a)
                    .or_default()
                    .push(Fact::Related(*x, *y, *r));
                BTreeSet::new()
            }
            Op::Consent(p) => {
                self.consents.insert(*p);
                BTreeSet::new()
            }
            Op::DeclareAffiliation(a, l) => {
                self.affiliations.insert((*a, *l));
                [*a].into_iter().collect()
            }
            Op::MeetCountry(a, p) => {
                self.country.insert((*a, *p));
                [*a].into_iter().collect()
            }
            Op::Unrelate(x, y, r) => {
                self.relations.remove(&(*x, *y, *r));
                self.relations.remove(&(*y, *x, *r));
                self.accounts_with(&[*x, *y])
            }
            Op::Unexclude(t, c) => {
                self.excluded.remove(&(*t, *c));
                self.accounts_with(&[*t])
            }
            Op::EndAffiliation(a, l) => {
                self.affiliations.remove(&(*a, *l));
                self.provisional_affiliations.remove(&(*a, *l));
                [*a].into_iter().collect()
            }
            Op::WithdrawConsent(p) => {
                self.consents.remove(p);
                BTreeSet::new()
            }
            Op::VerifyProvisional(a) => {
                self.provisional_verified.insert(*a);
                [*a].into_iter().collect()
            }
            Op::AffiliateProvisional(a, l) => {
                self.provisional_affiliations.insert((*a, *l));
                [*a].into_iter().collect()
            }
            Op::MakeEffective(a) => {
                let mut changed = BTreeSet::new();
                if self.provisional_verified.remove(a) {
                    changed.extend(self.verify(*a));
                }
                let lists: Vec<u128> = self
                    .provisional_affiliations
                    .iter()
                    .filter(|(b, _)| b == a)
                    .map(|(_, l)| *l)
                    .collect();
                for l in lists {
                    self.provisional_affiliations.remove(&(*a, l));
                    self.affiliations.insert((*a, l));
                    changed.insert(*a);
                }
                if let Some(from) = self.provisional_adults.remove(a) {
                    self.adults.insert(*a, from);
                    changed.insert(*a);
                }
                changed
            }
            Op::AttestAdult(a, from) => {
                self.adults.insert(*a, *from);
                [*a].into_iter().collect()
            }
            Op::AttestAdultProvisional(a, from) => {
                self.provisional_adults.insert(*a, *from);
                [*a].into_iter().collect()
            }
            Op::WithdrawAttestation(a) => {
                self.adults.remove(a);
                self.provisional_adults.remove(a);
                [*a].into_iter().collect()
            }
        };
        self.epoch += 1;
        self.changes.push((self.epoch, changed));
    }

    /// Verifies `a`, revealing its pending facts, and returns the accounts changed.
    fn verify(&mut self, a: u128) -> BTreeSet<u128> {
        self.verified.insert(a);
        let mut changed: BTreeSet<u128> = [a].into_iter().collect();
        for fact in self.pending.remove(&a).unwrap_or_default() {
            match fact {
                Fact::Excluded(t, c) => {
                    self.excluded.insert((t, c));
                    changed.extend(self.accounts_with(&[t]));
                }
                Fact::Related(x, y, r) => {
                    self.relations.insert((x, y, r));
                    changed.extend(self.accounts_with(&[x, y]));
                }
            }
        }
        changed
    }

    fn tag(&self, a: u128) -> Option<u64> {
        self.identity.get(&a).copied()
    }

    /// The verified identity of `a`: its tag, if it is verified.
    fn verified_tag(&self, a: u128) -> Option<u64> {
        if self.verified.contains(&a) {
            self.tag(a)
        } else {
            None
        }
    }

    fn related(&self, x: u64, y: u64) -> bool {
        x == y
            || self
                .relations
                .iter()
                .any(|(a, b, _)| (*a == x && *b == y) || (*a == y && *b == x))
    }

    /// The accounts of `pool` that count with `a` towards one cap.
    fn cap_group(&self, a: u128, pool: &BTreeSet<u128>) -> BTreeSet<u128> {
        match self.verified_tag(a) {
            Some(t) => pool
                .iter()
                .copied()
                .filter(|b| self.verified_tag(*b) == Some(t))
                .chain([a])
                .collect(),
            None => [a].into_iter().collect(),
        }
    }

    /// The expected answer bit and change list for `q`.
    fn answer(&self, q: &Query) -> (bool, Option<BTreeSet<u128>>) {
        let bit = match q {
            Query::IsVerified { account } => self.verified.contains(&account.raw()),
            Query::SameIdentityAsAny { subject, others } => {
                match self.verified_tag(subject.raw()) {
                    Some(t) => others.iter().any(|o| self.verified_tag(o.raw()) == Some(t)),
                    None => false,
                }
            }
            Query::HasConflict { reviewer, team } => match self.tag(reviewer.raw()) {
                Some(r) => team
                    .iter()
                    .filter_map(|m| self.tag(m.raw()))
                    .any(|m| self.related(r, m)),
                None => false,
            },
            Query::InExcludedClass {
                account, classes, ..
            } => match self.tag(account.raw()) {
                Some(t) => classes
                    .0
                    .iter()
                    .any(|c| self.excluded.contains(&(t, c.raw()))),
                None => false,
            },
            Query::WithinRecipientCap {
                subject,
                amount,
                committed,
                cap,
            } => {
                let pool: BTreeSet<u128> = committed.keys().map(|a| a.raw()).collect();
                let group = self.cap_group(subject.raw(), &pool);
                let sum: i64 = group
                    .iter()
                    .filter_map(|a| committed.get(&AccountId::from_raw(*a)))
                    .map(|v| v.amount().minor())
                    .sum();
                sum + amount.amount().minor() <= cap.amount().minor()
            }
            Query::AllRecipientsWithinCap { committed, cap } => {
                let pool: BTreeSet<u128> = committed.keys().map(|a| a.raw()).collect();
                pool.iter().all(|a| {
                    let sum: i64 = self
                        .cap_group(*a, &pool)
                        .iter()
                        .filter_map(|b| committed.get(&AccountId::from_raw(*b)))
                        .map(|v| v.amount().minor())
                        .sum();
                    sum <= cap.amount().minor()
                })
            }
            Query::HasGuardianConsent { proposal } => self.consents.contains(&proposal.raw()),
            // Overview NOTE 7: yes only for an effective attestation that shows
            // the lead 18 or older at the deadline.
            Query::IsVerifiedAdultAtDeadline { account, deadline } => self
                .adults
                .get(&account.raw())
                .is_some_and(|from| *from <= deadline.micros()),
            Query::DeclaresAffiliationOnList { team, list } => team
                .iter()
                .any(|m| self.affiliations.contains(&(m.raw(), list.raw()))),
            Query::MeetsTieBreakCountry { account, programme } => {
                self.country.contains(&(account.raw(), programme.raw()))
            }
            Query::ChangedSince { epoch } => {
                let changed: BTreeSet<u128> = self
                    .changes
                    .iter()
                    .filter(|(e, _)| *e > epoch.raw())
                    .flat_map(|(_, c)| c.iter().copied())
                    .collect();
                return (!changed.is_empty(), Some(changed));
            }
        };
        (bit, None)
    }
}

/// Applies `op` to the ground truth through its public mutators.
fn apply_to_truth(truth: &mut GroundTruth, op: &Op) {
    let acc = AccountId::from_raw;
    match op {
        Op::SetIdentity(a, t) => truth.set_identity(acc(*a), IdentityTag::new(*t)),
        Op::Verify(a) => truth.verify(acc(*a)),
        Op::Relate(x, y, r) => truth.relate(IdentityTag::new(*x), IdentityTag::new(*y), *r),
        Op::Exclude(t, c) => truth.exclude(IdentityTag::new(*t), ClassId::from_raw(*c)),
        Op::PendingExcluded(a, t, c) => truth.add_pending(
            acc(*a),
            PendingFact::Excluded {
                identity: IdentityTag::new(*t),
                class: ClassId::from_raw(*c),
            },
        ),
        Op::PendingRelated(a, x, y, r) => truth.add_pending(
            acc(*a),
            PendingFact::Related {
                a: IdentityTag::new(*x),
                b: IdentityTag::new(*y),
                relation: *r,
            },
        ),
        Op::Consent(p) => truth.consent(ProposalId::from_raw(*p)),
        Op::DeclareAffiliation(a, l) => {
            truth.declare_affiliation(acc(*a), ProximityListId::from_raw(*l));
        }
        Op::MeetCountry(a, p) => truth.meet_country(acc(*a), ProgrammeId::from_raw(*p)),
        Op::Unrelate(x, y, r) => truth.unrelate(IdentityTag::new(*x), IdentityTag::new(*y), *r),
        Op::Unexclude(t, c) => truth.unexclude(IdentityTag::new(*t), ClassId::from_raw(*c)),
        Op::EndAffiliation(a, l) => {
            truth.end_affiliation(acc(*a), ProximityListId::from_raw(*l));
        }
        Op::WithdrawConsent(p) => truth.withdraw_consent(ProposalId::from_raw(*p)),
        Op::VerifyProvisional(a) => truth.verify_provisional(acc(*a)),
        Op::AffiliateProvisional(a, l) => {
            truth.declare_affiliation_provisional(acc(*a), ProximityListId::from_raw(*l));
        }
        Op::MakeEffective(a) => truth.make_effective(acc(*a)),
        Op::AttestAdult(a, from) => truth.attest_adult(acc(*a), Timestamp::from_micros(*from)),
        Op::AttestAdultProvisional(a, from) => {
            truth.attest_adult_provisional(acc(*a), Timestamp::from_micros(*from));
        }
        Op::WithdrawAttestation(a) => truth.withdraw_attestation(acc(*a)),
    }
}

// ---------------------------------------------------------------------------
// Generators over a small synthetic universe
// ---------------------------------------------------------------------------

const ACCOUNTS: u128 = 5;
const TAGS: u64 = 2;
const CLASSES: u128 = 3;
const LISTS: u128 = 2;
const PROPOSALS: u128 = 2;
const PROGRAMMES: u128 = 2;
/// The instants of attestations and deadlines, in microseconds.
const INSTANTS: i64 = 3;

fn account(g: &mut Gen) -> u128 {
    u128::from(g.u8_in(1..=ACCOUNTS as u8))
}

fn tag(g: &mut Gen) -> u64 {
    g.u64_in(1..=TAGS)
}

fn small(g: &mut Gen, max: u128) -> u128 {
    u128::from(g.u8_in(1..=max as u8))
}

fn instant(g: &mut Gen) -> i64 {
    g.i64_in(1..=INSTANTS)
}

fn relation(g: &mut Gen) -> Relation {
    *g.pick(&[Relation::CoWorker, Relation::Relative, Relation::Mentoring])
}

fn gen_op(g: &mut Gen) -> Op {
    // Identities and verifications are drawn more often, so shared and
    // unverified identities meet in most cases.
    match g.weighted(&[4, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1]) {
        0 => Op::SetIdentity(account(g), tag(g)),
        1 => Op::Verify(account(g)),
        2 => Op::Relate(tag(g), tag(g), relation(g)),
        3 => Op::Exclude(tag(g), small(g, CLASSES)),
        4 => Op::PendingExcluded(account(g), tag(g), small(g, CLASSES)),
        5 => Op::PendingRelated(account(g), tag(g), tag(g), relation(g)),
        6 => Op::Consent(small(g, PROPOSALS)),
        7 => Op::DeclareAffiliation(account(g), small(g, LISTS)),
        8 => Op::MeetCountry(account(g), small(g, PROGRAMMES)),
        9 => Op::Unrelate(tag(g), tag(g), relation(g)),
        10 => Op::Unexclude(tag(g), small(g, CLASSES)),
        11 => Op::EndAffiliation(account(g), small(g, LISTS)),
        12 => Op::WithdrawConsent(small(g, PROPOSALS)),
        13 => Op::VerifyProvisional(account(g)),
        14 => Op::AffiliateProvisional(account(g), small(g, LISTS)),
        15 => Op::MakeEffective(account(g)),
        16 => Op::AttestAdult(account(g), instant(g)),
        17 => Op::AttestAdultProvisional(account(g), instant(g)),
        _ => Op::WithdrawAttestation(account(g)),
    }
}

fn accounts(g: &mut Gen) -> BTreeSet<AccountId> {
    g.vec(0..=4, |g| AccountId::from_raw(account(g)))
        .into_iter()
        .collect()
}

fn eur(g: &mut Gen, max_minor: i64) -> NonNegAmount {
    let minor = g.i64_in(0..=max_minor);
    NonNegAmount::new(Amount::from_minor(minor, Currency::Eur).expect("small amount"))
        .expect("non-negative")
}

fn committed(g: &mut Gen) -> BTreeMap<AccountId, NonNegAmount> {
    g.vec(0..=4, |g| (AccountId::from_raw(account(g)), eur(g, 500)))
        .into_iter()
        .collect()
}

fn gen_query(g: &mut Gen, kind: QueryKind, max_epoch: u64) -> Query {
    match kind {
        QueryKind::IsVerified => Query::IsVerified {
            account: AccountId::from_raw(account(g)),
        },
        QueryKind::SameIdentityAsAny => Query::SameIdentityAsAny {
            subject: AccountId::from_raw(account(g)),
            others: accounts(g),
        },
        QueryKind::HasConflict => Query::HasConflict {
            reviewer: AccountId::from_raw(account(g)),
            team: accounts(g),
        },
        QueryKind::InExcludedClass => Query::InExcludedClass {
            account: AccountId::from_raw(account(g)),
            programme: ProgrammeId::from_raw(small(g, PROGRAMMES)),
            classes: ExclusionClasses(
                g.vec(0..=3, |g| ClassId::from_raw(small(g, CLASSES)))
                    .into_iter()
                    .collect(),
            ),
        },
        QueryKind::WithinRecipientCap => Query::WithinRecipientCap {
            subject: AccountId::from_raw(account(g)),
            amount: eur(g, 500),
            committed: committed(g),
            cap: eur(g, 1500),
        },
        QueryKind::AllRecipientsWithinCap => Query::AllRecipientsWithinCap {
            committed: committed(g),
            cap: eur(g, 1500),
        },
        QueryKind::HasGuardianConsent => Query::HasGuardianConsent {
            proposal: ProposalId::from_raw(small(g, PROPOSALS)),
        },
        QueryKind::IsVerifiedAdultAtDeadline => Query::IsVerifiedAdultAtDeadline {
            account: AccountId::from_raw(account(g)),
            deadline: Timestamp::from_micros(instant(g)),
        },
        QueryKind::DeclaresAffiliationOnList => Query::DeclaresAffiliationOnList {
            team: accounts(g),
            list: ProximityListId::from_raw(small(g, LISTS)),
        },
        QueryKind::MeetsTieBreakCountry => Query::MeetsTieBreakCountry {
            account: AccountId::from_raw(account(g)),
            programme: ProgrammeId::from_raw(small(g, PROGRAMMES)),
        },
        QueryKind::ChangedSince => Query::ChangedSince {
            epoch: VaultEpoch::from_raw(g.u64_in(0..=max_epoch)),
        },
    }
}

fn set(ids: &[u128]) -> BTreeSet<AccountId> {
    ids.iter().copied().map(AccountId::from_raw).collect()
}

/// The answer bit of `vault` for `q`, failing the case on `OracleDown`.
fn holds(vault: &SyntheticVault, q: &Query) -> Result<bool, String> {
    vault
        .ask(q)
        .map(|a| a.holds)
        .map_err(|e| format!("{q:?}: {e}"))
}

// ---------------------------------------------------------------------------
// SyntheticVault against the reference
// ---------------------------------------------------------------------------

/// Overview query table, NOTE 1, NOTE 3 and NOTE 4 (I-03, I-04, I-06, I-14,
/// I-15, I-18, I-35, SoD-09, P-17): after any sequence of vault changes, the
/// synthetic vault answers every query kind as the facts say. Every answer
/// carries the vault's current epoch, and only `ChangedSince` lists accounts.
#[test]
fn harness_vault_answers_match_ground_truth_for_every_query_kind() {
    check(
        "harness_vault_answers_match_ground_truth_for_every_query_kind",
        |g| {
            let ops = g.vec(0..=24, gen_op);
            g.note("ops", &ops);
            let mut facts = Facts::default();
            let mut truth = GroundTruth::new();
            for op in &ops {
                facts.apply(op);
                apply_to_truth(&mut truth, op);
            }
            prop_assert_eq!(truth.epoch(), VaultEpoch::from_raw(facts.epoch));
            let vault = SyntheticVault::new(truth);
            prop_assert_eq!(vault.epoch(), Ok(VaultEpoch::from_raw(facts.epoch)));
            let queries = g.vec(8..=40, |g| {
                let kind = *g.pick(&QueryKind::ALL);
                gen_query(g, kind, facts.epoch + 1)
            });
            for q in &queries {
                let (bit, changed) = facts.answer(q);
                let got = vault.ask(q).map_err(|e| format!("{q:?}: {e}"))?;
                prop_assert_eq!(got.epoch, VaultEpoch::from_raw(facts.epoch));
                match changed {
                    Some(expected) => {
                        let expected: BTreeSet<AccountId> =
                            expected.into_iter().map(AccountId::from_raw).collect();
                        prop_assert_eq!(got.accounts, Some(expected));
                    }
                    None => {
                        prop_assert_eq!((q, got.holds), (q, bit));
                        prop_assert!(got.accounts.is_none(), "{q:?} listed accounts");
                    }
                }
            }
            Ok(())
        },
    );
}

/// The query table: one fixed truth, with each query kind asked once with
/// a positive and once with a negative answer. The kinds are checked to be
/// complete against `QueryKind::ALL`.
#[test]
fn harness_vault_fixed_truth_answers_each_query_kind() {
    let mut truth = GroundTruth::new();
    let a = AccountId::from_raw;
    // Accounts 1 and 2 are one verified person, and account 5 is that person
    // too but unverified. Account 3 is unverified and a co-worker of that
    // person. Account 4 is unverified and excluded in class 1. Account 6 has
    // no identity tag.
    truth.set_identity(a(1), IdentityTag::new(1));
    truth.set_identity(a(2), IdentityTag::new(1));
    truth.set_identity(a(3), IdentityTag::new(2));
    truth.set_identity(a(4), IdentityTag::new(3));
    truth.set_identity(a(5), IdentityTag::new(1));
    truth.verify(a(1));
    truth.verify(a(2));
    truth.relate(IdentityTag::new(1), IdentityTag::new(2), Relation::CoWorker);
    truth.exclude(IdentityTag::new(3), ClassId::from_raw(1));
    truth.consent(ProposalId::from_raw(1));
    truth.declare_affiliation(a(3), ProximityListId::from_raw(1));
    truth.meet_country(a(1), ProgrammeId::from_raw(1));
    // Account 1 is attested 18 or older from instant 10 on. Account 2 has a
    // provisional attestation only, which no query counts (NOTE 4).
    truth.attest_adult(a(1), Timestamp::from_micros(10));
    truth.attest_adult_provisional(a(2), Timestamp::from_micros(0));
    let epoch_before_last = truth.epoch();
    truth.verify(a(6));
    let vault = SyntheticVault::new(truth);

    let eur = |minor: i64| {
        NonNegAmount::new(Amount::from_minor(minor, Currency::Eur).expect("amount"))
            .expect("non-negative")
    };
    let classes =
        |ids: &[u128]| ExclusionClasses(ids.iter().map(|c| ClassId::from_raw(*c)).collect());
    let committed = |pairs: &[(u128, i64)]| -> BTreeMap<AccountId, NonNegAmount> {
        pairs.iter().map(|(x, m)| (a(*x), eur(*m))).collect()
    };

    let table: Vec<(Query, bool)> = vec![
        (Query::IsVerified { account: a(1) }, true),
        (Query::IsVerified { account: a(3) }, false),
        (
            Query::SameIdentityAsAny {
                subject: a(1),
                others: set(&[2, 3]),
            },
            true,
        ),
        (
            Query::SameIdentityAsAny {
                subject: a(1),
                others: set(&[3, 4]),
            },
            false,
        ),
        // Account 5 is the same person, but unverified.
        (
            Query::SameIdentityAsAny {
                subject: a(1),
                others: set(&[5]),
            },
            false,
        ),
        (
            Query::HasConflict {
                reviewer: a(1),
                team: set(&[3]),
            },
            true,
        ),
        (
            Query::HasConflict {
                reviewer: a(1),
                team: set(&[4]),
            },
            false,
        ),
        (
            Query::InExcludedClass {
                account: a(4),
                programme: ProgrammeId::from_raw(1),
                classes: classes(&[1, 2]),
            },
            true,
        ),
        (
            Query::InExcludedClass {
                account: a(4),
                programme: ProgrammeId::from_raw(1),
                classes: classes(&[2]),
            },
            false,
        ),
        // Accounts 1 and 2 are one verified person: 400 + 500 + 100 = 1000.
        // Account 5 is unverified, so it forms its own group.
        (
            Query::WithinRecipientCap {
                subject: a(1),
                amount: eur(100),
                committed: committed(&[(1, 400), (2, 500), (3, 900), (5, 900)]),
                cap: eur(1000),
            },
            true,
        ),
        (
            Query::WithinRecipientCap {
                subject: a(1),
                amount: eur(101),
                committed: committed(&[(1, 400), (2, 500), (3, 900), (5, 900)]),
                cap: eur(1000),
            },
            false,
        ),
        (
            Query::AllRecipientsWithinCap {
                committed: committed(&[(1, 400), (2, 500), (3, 900), (5, 900)]),
                cap: eur(900),
            },
            true,
        ),
        (
            Query::AllRecipientsWithinCap {
                committed: committed(&[(1, 400), (2, 501), (3, 900), (5, 900)]),
                cap: eur(900),
            },
            false,
        ),
        (
            Query::HasGuardianConsent {
                proposal: ProposalId::from_raw(1),
            },
            true,
        ),
        (
            Query::HasGuardianConsent {
                proposal: ProposalId::from_raw(2),
            },
            false,
        ),
        // Overview NOTE 7, R-ID-04: at the deadline 10 account 1 is shown
        // 18 or older, at 9 it is not, and a provisional attestation of
        // account 2 does not count.
        (
            Query::IsVerifiedAdultAtDeadline {
                account: a(1),
                deadline: Timestamp::from_micros(10),
            },
            true,
        ),
        (
            Query::IsVerifiedAdultAtDeadline {
                account: a(1),
                deadline: Timestamp::from_micros(9),
            },
            false,
        ),
        (
            Query::IsVerifiedAdultAtDeadline {
                account: a(2),
                deadline: Timestamp::from_micros(10),
            },
            false,
        ),
        (
            Query::DeclaresAffiliationOnList {
                team: set(&[2, 3]),
                list: ProximityListId::from_raw(1),
            },
            true,
        ),
        (
            Query::DeclaresAffiliationOnList {
                team: set(&[2, 3]),
                list: ProximityListId::from_raw(2),
            },
            false,
        ),
        (
            Query::MeetsTieBreakCountry {
                account: a(1),
                programme: ProgrammeId::from_raw(1),
            },
            true,
        ),
        (
            Query::MeetsTieBreakCountry {
                account: a(1),
                programme: ProgrammeId::from_raw(2),
            },
            false,
        ),
    ];
    let mut kinds = BTreeSet::new();
    for (q, expected) in &table {
        kinds.insert(q.kind());
        assert_eq!(holds(&vault, q), Ok(*expected), "{q:?}");
    }
    let changed = vault
        .ask(&Query::ChangedSince {
            epoch: epoch_before_last,
        })
        .expect("answer");
    assert_eq!(changed.accounts, Some(set(&[6])));
    let none = vault
        .ask(&Query::ChangedSince {
            epoch: vault.truth().epoch(),
        })
        .expect("answer");
    assert_eq!(none.accounts, Some(BTreeSet::new()));
    kinds.insert(QueryKind::ChangedSince);
    assert_eq!(kinds, QueryKind::ALL.into_iter().collect());
}

/// Design 4.5: a pending fact does not count until its account is
/// verified. Verification makes it count and advances the epoch, and the
/// change query then lists the accounts the fact is about.
#[test]
fn harness_vault_pending_fact_counts_only_after_verification() {
    let a = AccountId::from_raw;
    let mut truth = GroundTruth::new();
    truth.set_identity(a(1), IdentityTag::new(1));
    truth.add_pending(
        a(1),
        PendingFact::Excluded {
            identity: IdentityTag::new(1),
            class: ClassId::from_raw(1),
        },
    );
    let mut vault = SyntheticVault::new(truth);
    let q = Query::InExcludedClass {
        account: a(1),
        programme: ProgrammeId::from_raw(1),
        classes: ExclusionClasses([ClassId::from_raw(1)].into_iter().collect()),
    };
    assert_eq!(holds(&vault, &q), Ok(false));
    let before = vault.truth().epoch();
    vault.truth_mut().verify(a(1));
    assert_eq!(
        vault.truth().epoch(),
        VaultEpoch::from_raw(before.raw() + 1)
    );
    assert_eq!(holds(&vault, &q), Ok(true));
    let changed = vault
        .ask(&Query::ChangedSince { epoch: before })
        .expect("answer");
    assert_eq!(changed.accounts, Some(set(&[1])));
}

// ---------------------------------------------------------------------------
// Corpus-variant fixtures (synthetic-corpus.md)
// ---------------------------------------------------------------------------

/// Corpus variant "Sybil", SoD-09 and I-06: the fixture's applicant and
/// reviewer are two verified accounts of one identity. The vault reports
/// the shared identity both ways and a conflict between them.
#[test]
fn i06_sod09_sybil_fixture_shares_one_verified_identity() {
    check(
        "i06_sod09_sybil_fixture_shares_one_verified_identity",
        |g| {
            let mut truth = GroundTruth::new();
            let f = sybil_pair(g, &mut truth);
            g.note("fixture", &f);
            let vault = SyntheticVault::new(truth);
            prop_assert!(f.applicant != f.reviewer, "one account, not a pair");
            for account in [f.applicant, f.reviewer] {
                prop_assert_eq!(holds(&vault, &Query::IsVerified { account })?, true);
            }
            let one_way = Query::SameIdentityAsAny {
                subject: f.applicant,
                others: [f.reviewer].into_iter().collect(),
            };
            let other_way = Query::SameIdentityAsAny {
                subject: f.reviewer,
                others: [f.applicant].into_iter().collect(),
            };
            let conflict = Query::HasConflict {
                reviewer: f.reviewer,
                team: [f.applicant].into_iter().collect(),
            };
            prop_assert_eq!(holds(&vault, &one_way)?, true);
            prop_assert_eq!(holds(&vault, &other_way)?, true);
            prop_assert_eq!(holds(&vault, &conflict)?, true);
            Ok(())
        },
    );
}

/// Corpus variant "Excluded affiliation", I-04 and SoD-06: the fixture's
/// account is in its class. When the variant is revealed at verification,
/// the vault reports the class only after the account is verified, as at
/// negotiation. Otherwise it reports it at once, as at binding.
#[test]
fn i04_sod06_excluded_fixture_is_in_its_class() {
    check("i04_sod06_excluded_fixture_is_in_its_class", |g| {
        let mut truth = GroundTruth::new();
        let f = excluded_applicant(g, &mut truth);
        g.note("fixture", &f);
        let mut vault = SyntheticVault::new(truth);
        let programme = ProgrammeId::from_raw(small(g, PROGRAMMES));
        let q = Query::InExcludedClass {
            account: f.account,
            programme,
            classes: ExclusionClasses([f.class].into_iter().collect()),
        };
        let empty = Query::InExcludedClass {
            account: f.account,
            programme,
            classes: ExclusionClasses(BTreeSet::new()),
        };
        prop_assert_eq!(holds(&vault, &empty)?, false);
        if f.revealed_on_verification {
            prop_assert_eq!(holds(&vault, &q)?, false);
            vault.truth_mut().verify(f.account);
        }
        prop_assert_eq!(holds(&vault, &q)?, true);
        Ok(())
    });
}

/// Corpus variant "Repeat applicant" and I-15: the new lead is verified and
/// shares a verified identity with the lead of the prior grant.
#[test]
fn i15_repeat_fixture_links_the_new_lead_to_the_prior_lead() {
    check(
        "i15_repeat_fixture_links_the_new_lead_to_the_prior_lead",
        |g| {
            let mut truth = GroundTruth::new();
            let f = repeat_applicant(g, &mut truth);
            g.note("fixture", &f);
            let vault = SyntheticVault::new(truth);
            for account in [f.prior_lead, f.new_lead] {
                prop_assert_eq!(holds(&vault, &Query::IsVerified { account })?, true);
            }
            let q = Query::SameIdentityAsAny {
                subject: f.new_lead,
                others: [f.prior_lead].into_iter().collect(),
            };
            prop_assert_eq!(holds(&vault, &q)?, true);
            Ok(())
        },
    );
}

/// Corpus variant "Minor applicant" and I-18: the vault reports a guardian
/// consent record for the fixture's proposal exactly when the fixture says
/// consent was given. The guardian is another account than the lead.
#[test]
fn i18_minor_fixture_consent_matches_its_flag() {
    check("i18_minor_fixture_consent_matches_its_flag", |g| {
        let mut truth = GroundTruth::new();
        let f = minor_applicant(g, &mut truth);
        g.note("fixture", &f);
        let vault = SyntheticVault::new(truth);
        prop_assert!(f.lead != f.guardian, "the lead is their own guardian");
        let q = Query::HasGuardianConsent {
            proposal: f.proposal,
        };
        prop_assert_eq!(holds(&vault, &q)?, f.consent);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// HavocOracle and DownOracle
// ---------------------------------------------------------------------------

/// Design 4.5: the havoc oracle answers exactly its script, at its epoch,
/// with no account list. A query outside the script fails closed.
#[test]
fn harness_havoc_oracle_returns_exactly_its_script() {
    check("harness_havoc_oracle_returns_exactly_its_script", |g| {
        let epoch = VaultEpoch::from_raw(g.u64_in(0..=5));
        let kinds: Vec<QueryKind> = QueryKind::ALL
            .into_iter()
            .filter(|k| *k != QueryKind::ChangedSince)
            .collect();
        let mut script: Vec<(Query, bool)> = Vec::new();
        for (q, b) in g.vec(0..=12, |g| {
            let kind = *g.pick(&kinds);
            (gen_query(g, kind, 0), g.bool())
        }) {
            if script.iter().all(|(s, _)| *s != q) {
                script.push((q, b));
            }
        }
        g.note("script", &script);
        let havoc = HavocOracle::new(epoch, script.clone());
        prop_assert_eq!(havoc.epoch(), Ok(epoch));
        for (q, b) in &script {
            let got = havoc.ask(q).map_err(|e| format!("{q:?}: {e}"))?;
            prop_assert_eq!((q, got.holds, got.epoch), (q, *b, epoch));
            prop_assert!(got.accounts.is_none(), "{q:?} listed accounts");
        }
        let kind = *g.pick(&kinds);
        let probe = gen_query(g, kind, 0);
        if script.iter().all(|(s, _)| *s != probe) {
            prop_assert_eq!(havoc.ask(&probe).map(|a| a.holds), Err(OracleDown));
        }
        Ok(())
    });
}

/// Design 4.5 and overview NOTE 2: the down oracle fails every question and
/// every epoch request.
#[test]
fn harness_down_oracle_always_fails() {
    check("harness_down_oracle_always_fails", |g| {
        let kind = *g.pick(&QueryKind::ALL);
        let q = gen_query(g, kind, 5);
        prop_assert_eq!(DownOracle.ask(&q).map(|a| a.holds), Err(OracleDown));
        prop_assert_eq!(DownOracle.epoch(), Err(OracleDown));
        Ok(())
    });
}

/// Overview NOTE 4: a provisional verification advances the epoch and is
/// listed by `ChangedSince`, but no other query counts it. Once made
/// effective it counts, its pending facts are revealed, and the epoch
/// advances again. A provisional affiliation behaves the same way.
#[test]
fn harness_vault_note4_provisional_facts_count_only_once_effective() {
    let a = AccountId::from_raw;
    let list = ProximityListId::from_raw(1);
    let mut truth = GroundTruth::new();
    truth.set_identity(a(1), IdentityTag::new(1));
    truth.add_pending(
        a(1),
        PendingFact::Excluded {
            identity: IdentityTag::new(1),
            class: ClassId::from_raw(1),
        },
    );
    let start = truth.epoch();
    truth.verify_provisional(a(1));
    truth.declare_affiliation_provisional(a(1), list);
    assert_eq!(truth.epoch(), VaultEpoch::from_raw(start.raw() + 2));
    assert!(truth.is_provisionally_verified(a(1)));
    assert!(truth.has_provisional_affiliation(a(1), list));
    assert_eq!(truth.provisional_accounts(), set(&[1]));
    let mut vault = SyntheticVault::new(truth);
    let verified = Query::IsVerified { account: a(1) };
    let affiliated = Query::DeclaresAffiliationOnList {
        team: set(&[1]),
        list,
    };
    let excluded = Query::InExcludedClass {
        account: a(1),
        programme: ProgrammeId::from_raw(1),
        classes: ExclusionClasses([ClassId::from_raw(1)].into_iter().collect()),
    };
    for q in [&verified, &affiliated, &excluded] {
        assert_eq!(holds(&vault, q), Ok(false), "{q:?}");
    }
    let changed = vault
        .ask(&Query::ChangedSince { epoch: start })
        .expect("answer");
    assert_eq!(changed.accounts, Some(set(&[1])));

    let before = vault.truth().epoch();
    vault.truth_mut().make_effective(a(1));
    assert_eq!(
        vault.truth().epoch(),
        VaultEpoch::from_raw(before.raw() + 1)
    );
    for q in [&verified, &affiliated, &excluded] {
        assert_eq!(holds(&vault, q), Ok(true), "{q:?}");
    }
    assert!(vault.truth().provisional_accounts().is_empty());
    let changed = vault
        .ask(&Query::ChangedSince { epoch: before })
        .expect("answer");
    assert_eq!(changed.accounts, Some(set(&[1])));
}

/// Roles-and-sod enforcement point 3: a fact can go from true to false.
/// Each removal turns its answer back to false, advances the epoch past
/// the one before, and lists the accounts it touches.
#[test]
fn harness_vault_removals_turn_answers_false_and_advance_the_epoch() {
    let a = AccountId::from_raw;
    let (t1, t2) = (IdentityTag::new(1), IdentityTag::new(2));
    let class = ClassId::from_raw(1);
    let list = ProximityListId::from_raw(1);
    let proposal = ProposalId::from_raw(1);
    let mut truth = GroundTruth::new();
    truth.set_identity(a(1), t1);
    truth.set_identity(a(2), t2);
    truth.relate(t1, t2, Relation::CoWorker);
    truth.exclude(t1, class);
    truth.declare_affiliation(a(1), list);
    truth.consent(proposal);
    let conflict = Query::HasConflict {
        reviewer: a(1),
        team: set(&[2]),
    };
    let excluded = Query::InExcludedClass {
        account: a(1),
        programme: ProgrammeId::from_raw(1),
        classes: ExclusionClasses([class].into_iter().collect()),
    };
    let affiliated = Query::DeclaresAffiliationOnList {
        team: set(&[1]),
        list,
    };
    let consent = Query::HasGuardianConsent { proposal };
    let mut vault = SyntheticVault::new(truth);
    for q in [&conflict, &excluded, &affiliated, &consent] {
        assert_eq!(holds(&vault, q), Ok(true), "{q:?}");
    }
    type Removal = Box<dyn Fn(&mut GroundTruth)>;
    let steps: Vec<(Removal, &Query, BTreeSet<AccountId>)> = vec![
        (
            Box::new(move |t| t.unrelate(t2, t1, Relation::CoWorker)),
            &conflict,
            set(&[1, 2]),
        ),
        (
            Box::new(move |t| t.unexclude(t1, class)),
            &excluded,
            set(&[1]),
        ),
        (
            Box::new(move |t| t.end_affiliation(a(1), list)),
            &affiliated,
            set(&[1]),
        ),
        (
            Box::new(move |t| t.withdraw_consent(proposal)),
            &consent,
            BTreeSet::new(),
        ),
    ];
    for (remove, q, touched) in steps {
        let before = vault.truth().epoch();
        remove(vault.truth_mut());
        assert_eq!(
            vault.truth().epoch(),
            VaultEpoch::from_raw(before.raw() + 1)
        );
        assert_eq!(holds(&vault, q), Ok(false), "{q:?}");
        let changed = vault
            .ask(&Query::ChangedSince { epoch: before })
            .expect("answer");
        assert_eq!(changed.accounts, Some(touched), "{q:?}");
    }
}

/// Design 4.5: a havoc oracle can be changed in place, so a model state can
/// hold it. `set` replaces the bit that counts for a query or adds one,
/// `advance_epoch` moves every answer to the next epoch, and `set_changed`
/// changes the `ChangedSince` list. The oracle is hashable.
#[test]
fn harness_havoc_oracle_is_rescriptable_in_place() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let q = Query::IsVerified {
        account: AccountId::from_raw(1),
    };
    let other = Query::HasGuardianConsent {
        proposal: ProposalId::from_raw(1),
    };
    let mut havoc = HavocOracle::new(VaultEpoch::from_raw(2), vec![(q.clone(), true)]);
    let original = havoc.clone();
    havoc.set(q.clone(), false);
    havoc.set(other.clone(), true);
    assert_eq!(
        havoc.script(),
        &[(q.clone(), false), (other.clone(), true)][..]
    );
    assert_eq!(havoc.ask(&q).map(|a| a.holds), Ok(false));
    havoc.advance_epoch();
    assert_eq!(havoc.epoch(), Ok(VaultEpoch::from_raw(3)));
    assert_eq!(
        havoc.ask(&other).map(|a| a.epoch),
        Ok(VaultEpoch::from_raw(3))
    );
    let changed = set(&[4, 5]);
    havoc.set_changed(changed.clone());
    havoc.set(
        Query::ChangedSince {
            epoch: VaultEpoch::GENESIS,
        },
        true,
    );
    assert_eq!(havoc.changed(), &changed);
    assert_eq!(
        havoc
            .ask(&Query::ChangedSince {
                epoch: VaultEpoch::GENESIS
            })
            .map(|a| a.accounts),
        Ok(Some(changed))
    );
    let hash = |h: &HavocOracle| {
        let mut s = DefaultHasher::new();
        h.hash(&mut s);
        s.finish()
    };
    assert_eq!(hash(&original), hash(&original.clone()));
    assert_ne!(original, havoc);
}

/// Design 6.2 (I-15) and the answer to Q8: the repeat fixture draws the
/// prior deliverables from all five states of the test plan, and every
/// state is reached.
#[test]
fn i15_repeat_fixture_reaches_every_prior_deliverable_state() {
    let seen = std::sync::Mutex::new(BTreeSet::new());
    let outcome = fstp_prop::run(
        "i15_repeat_fixture_reaches_every_prior_deliverable_state",
        fstp_prop::Config::default().with_cases(200),
        |g| {
            let mut truth = GroundTruth::new();
            let f = repeat_applicant(g, &mut truth);
            prop_assert!(PriorDeliverables::ALL.contains(&f.prior_deliverables));
            seen.lock()
                .map_err(|e| e.to_string())?
                .insert(f.prior_deliverables);
            Ok(())
        },
    );
    assert!(outcome.failure().is_none(), "{outcome:?}");
    let seen = seen.into_inner().expect("lock");
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        PriorDeliverables::ALL.to_vec()
    );
}

// ---------------------------------------------------------------------------
// Fix round 2 regressions
// ---------------------------------------------------------------------------

/// Two havoc oracles scripted with the same bits in another order answer
/// alike, so they must be one model state: equal, with equal hashes. A
/// duplicate entry in `new` changes nothing, since the first one counts.
#[test]
fn harness_havoc_oracle_equality_ignores_script_order() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let hash = |h: &HavocOracle| {
        let mut s = DefaultHasher::new();
        h.hash(&mut s);
        s.finish()
    };
    let p = Query::IsVerified {
        account: AccountId::from_raw(1),
    };
    let q = Query::HasGuardianConsent {
        proposal: ProposalId::from_raw(2),
    };
    let mut one = HavocOracle::new(VaultEpoch::from_raw(3), Vec::new());
    one.set(p.clone(), true);
    one.set(q.clone(), false);
    let mut two = HavocOracle::new(VaultEpoch::from_raw(3), Vec::new());
    two.set(q.clone(), false);
    two.set(p.clone(), true);
    assert_eq!(one, two);
    assert_eq!(hash(&one), hash(&two));
    let dup = HavocOracle::new(
        VaultEpoch::from_raw(3),
        vec![(q.clone(), false), (p.clone(), true), (q.clone(), true)],
    );
    assert_eq!(dup.scripted(&q), Some(false));
    assert_eq!(dup, one);
    assert_eq!(hash(&dup), hash(&one));
    two.set(q, true);
    assert_ne!(one, two);
}

/// Runs `prop` once with every draw at its smallest value, so a fixture
/// draws 1 for every new id and must step past every id already taken.
fn with_smallest_draws(name: &str, prop: impl Fn(&mut Gen) -> Result<(), String>) {
    let outcome = fstp_prop::run(
        name,
        fstp_prop::Config::default().with_replay(Vec::new()),
        prop,
    );
    assert!(outcome.failure().is_none(), "{outcome:?}");
}

/// Design 4.5: a fixture's new identity must be new to the vault. An
/// identity named only by a relation, an exclusion or a pending fact is
/// taken, or the Sybil pair would be related or excluded by accident.
#[test]
fn harness_fixture_fresh_identity_skips_tags_named_only_by_facts() {
    with_smallest_draws(
        "harness_fixture_fresh_identity_skips_tags_named_only_by_facts",
        |g| {
            let t = IdentityTag::new;
            let class = ClassId::from_raw(1);
            let mut truth = GroundTruth::new();
            truth.relate(t(1), t(2), Relation::CoWorker);
            truth.exclude(t(3), class);
            truth.add_pending(
                AccountId::from_raw(500),
                PendingFact::Related {
                    a: t(4),
                    b: t(5),
                    relation: Relation::Relative,
                },
            );
            truth.add_pending(
                AccountId::from_raw(501),
                PendingFact::Excluded {
                    identity: t(6),
                    class,
                },
            );
            let f = sybil_pair(g, &mut truth);
            g.note("fixture", &f);
            prop_assert!(f.identity.raw() > 6, "drew a taken identity {f:?}");
            for n in 1..=6 {
                prop_assert!(!truth.related(f.identity, t(n)), "{f:?} related to {n}");
            }
            prop_assert!(!truth.is_excluded(f.identity, class), "{f:?} excluded");
            Ok(())
        },
    );
}

/// Design 4.5: a fixture's new account must be new to the vault. An
/// account named only by an affiliation, a country bit, a provisional
/// affiliation, a pending fact or the change log is taken.
#[test]
fn harness_fixture_fresh_account_skips_accounts_named_only_by_facts() {
    with_smallest_draws(
        "harness_fixture_fresh_account_skips_accounts_named_only_by_facts",
        |g| {
            let a = AccountId::from_raw;
            let list = ProximityListId::from_raw(1);
            let mut truth = GroundTruth::new();
            truth.declare_affiliation(a(1), list);
            truth.meet_country(a(2), ProgrammeId::from_raw(1));
            truth.declare_affiliation_provisional(a(3), list);
            truth.add_pending(
                a(4),
                PendingFact::Excluded {
                    identity: IdentityTag::new(100),
                    class: ClassId::from_raw(1),
                },
            );
            truth.declare_affiliation(a(5), list);
            truth.end_affiliation(a(5), list);
            let f = sybil_pair(g, &mut truth);
            g.note("fixture", &f);
            for acc in [f.applicant, f.reviewer] {
                prop_assert!(acc.raw() > 5, "drew a taken account {acc:?}");
                prop_assert!(!truth.declares_affiliation(acc, list), "{acc:?} affiliated");
                prop_assert!(!truth.has_provisional_affiliation(acc, list), "{acc:?}");
            }
            Ok(())
        },
    );
}

/// I-18 and R-NG-02: a minor fixture that says the vault holds no
/// guardian consent must name a proposal without one.
#[test]
fn i18_minor_fixture_consent_flag_matches_the_vault() {
    with_smallest_draws("i18_minor_fixture_consent_flag_matches_the_vault", |g| {
        let mut truth = GroundTruth::new();
        for n in 1..=3 {
            truth.consent(ProposalId::from_raw(n));
        }
        let f = minor_applicant(g, &mut truth);
        g.note("fixture", &f);
        prop_assert_eq!(truth.has_consent(f.proposal), f.consent);
        Ok(())
    });
}

/// I-15: the repeat fixture's two proposals are distinct and carry no
/// guardian consent already in the vault.
#[test]
fn i15_repeat_fixture_proposals_are_fresh() {
    with_smallest_draws("i15_repeat_fixture_proposals_are_fresh", |g| {
        let mut truth = GroundTruth::new();
        for n in 1..=3 {
            truth.consent(ProposalId::from_raw(n));
        }
        let f = repeat_applicant(g, &mut truth);
        g.note("fixture", &f);
        prop_assert!(f.prior_proposal != f.new_proposal, "{f:?}");
        prop_assert!(!truth.has_consent(f.prior_proposal), "{f:?}");
        prop_assert!(!truth.has_consent(f.new_proposal), "{f:?}");
        Ok(())
    });
}
