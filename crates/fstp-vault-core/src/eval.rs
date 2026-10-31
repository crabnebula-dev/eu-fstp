//! The facts of one view and the evaluation of every query over them
//! (design section 6.4, `overview.md` query table, NOTE 1, NOTE 5).
//!
//! A view is the effective facts, or the effective facts with the
//! provisional one for a reaction (NOTE 4). Every answer is one bit.
//! `ChangedSince` needs the epoch log, so [`crate::VaultState`] answers it.
//!
//! The readings follow lane W1c's `reference::vault::Facts`, which the
//! acceptance tests check this module against.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use fstp_money::Amount;
use fstp_vault_proto::{Query, WireAccount, WireClass, WireList, WireProgramme, WireProposal};

use crate::fact::{Fact, Org, Person};

/// The facts of one view.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Facts {
    person: BTreeMap<WireAccount, Person>,
    adult_from: BTreeMap<WireAccount, i64>,
    consent: BTreeMap<WireProposal, WireAccount>,
    affiliations: BTreeMap<(WireAccount, Org), Option<WireClass>>,
    lists: BTreeMap<WireList, BTreeSet<Org>>,
    declarations: BTreeMap<WireAccount, (Option<Org>, BTreeSet<Person>)>,
    relationships: BTreeSet<(WireAccount, WireAccount)>,
    country: BTreeMap<(WireAccount, WireProgramme), u16>,
}

/// The two accounts of a relationship, smaller first.
fn pair(a: WireAccount, b: WireAccount) -> (WireAccount, WireAccount) {
    if a <= b { (a, b) } else { (b, a) }
}

impl Facts {
    /// Applies one write.
    pub fn apply(&mut self, f: &Fact) {
        match f {
            Fact::VerificationRecorded {
                account, person, ..
            } => {
                self.person.insert(*account, *person);
            }
            Fact::AdultAttestation {
                account,
                adult_from,
            } => {
                self.adult_from.insert(*account, *adult_from);
            }
            Fact::AttestationWithdrawn { account } => {
                self.adult_from.remove(account);
            }
            Fact::GuardianConsent { proposal, guardian } => {
                self.consent.insert(*proposal, *guardian);
            }
            Fact::ConsentWithdrawn { proposal } => {
                self.consent.remove(proposal);
            }
            Fact::AffiliationDeclared {
                account,
                org,
                class,
                ..
            } => {
                self.affiliations.insert((*account, *org), *class);
            }
            Fact::AffiliationEnded { account, org } => {
                self.affiliations.remove(&(*account, *org));
            }
            Fact::ProximityListDeclared { list, orgs } => {
                self.lists.insert(*list, orgs.clone());
            }
            Fact::ReviewerDeclaration {
                reviewer,
                employer,
                relatives,
            } => {
                self.declarations
                    .insert(*reviewer, (*employer, relatives.clone()));
            }
            Fact::Relationship { a, b } => {
                self.relationships.insert(pair(*a, *b));
            }
            Fact::CountryStated {
                account,
                programme,
                country,
            } => {
                self.country.insert((*account, *programme), *country);
            }
        }
    }

    /// The facts after `f`.
    pub fn after(&self, f: &Fact) -> Facts {
        let mut out = self.clone();
        out.apply(f);
        out
    }

    /// The person of `account`, once a verification of it is in the view.
    pub fn person_of(&self, account: WireAccount) -> Option<Person> {
        self.person.get(&account).copied()
    }

    /// The guardian of `proposal`'s consent in this view, if any.
    pub fn consent_guardian(&self, proposal: WireProposal) -> Option<WireAccount> {
        self.consent.get(&proposal).copied()
    }

    /// The class of `account`'s affiliation with `org` in this view: `None`
    /// when there is none, `Some(None)` for an unclassed one.
    pub fn affiliation(&self, account: WireAccount, org: Org) -> Option<Option<WireClass>> {
        self.affiliations.get(&(account, org)).copied()
    }

    /// The country `account` stated for `programme`, if any. It is
    /// released only on the vault origin, under a release ticket that names
    /// the programme.
    pub fn country_of(&self, account: WireAccount, programme: WireProgramme) -> Option<u16> {
        self.country.get(&(account, programme)).copied()
    }

    /// Whether this view holds an I-54 relationship between `a` and `b`,
    /// in either order.
    pub fn has_relationship(&self, a: WireAccount, b: WireAccount) -> bool {
        self.relationships.contains(&pair(a, b))
    }

    /// Whether any account stated a country for `programme` in this view.
    pub fn has_country_for(&self, programme: WireProgramme) -> bool {
        self.country.keys().any(|(_, p)| *p == programme)
    }

    /// The instant from which `account`'s attestation shows it 18 or
    /// older, if it has one in this view.
    pub fn attestation_of(&self, account: WireAccount) -> Option<i64> {
        self.adult_from.get(&account).copied()
    }

    /// `account` and every account with the same verified person.
    pub fn accounts_of(&self, account: WireAccount) -> BTreeSet<WireAccount> {
        let mut out = BTreeSet::from([account]);
        if let Some(p) = self.person_of(account) {
            out.extend(self.accounts_of_person(p));
        }
        out
    }

    fn accounts_of_person(&self, p: Person) -> BTreeSet<WireAccount> {
        self.person
            .iter()
            .filter(|(_, q)| **q == p)
            .map(|(a, _)| *a)
            .collect()
    }

    fn closure(&self, accounts: &BTreeSet<WireAccount>) -> BTreeSet<WireAccount> {
        accounts.iter().flat_map(|a| self.accounts_of(*a)).collect()
    }

    fn partners(&self, accounts: &BTreeSet<WireAccount>) -> BTreeSet<WireAccount> {
        let mut out = BTreeSet::new();
        for (a, b) in &self.relationships {
            if accounts.contains(a) {
                out.insert(*b);
            }
            if accounts.contains(b) {
                out.insert(*a);
            }
        }
        out
    }

    fn affiliated_with(&self, org: Org) -> BTreeSet<WireAccount> {
        self.affiliations
            .keys()
            .filter(|(_, o)| *o == org)
            .map(|(a, _)| *a)
            .collect()
    }

    fn reviewers_naming(&self, p: Person) -> BTreeSet<WireAccount> {
        self.declarations
            .iter()
            .filter(|(_, (_, rel))| rel.contains(&p))
            .map(|(r, _)| *r)
            .collect()
    }

    /// The accounts a write touches (NOTE 4 step 2, design sections 6.3
    /// and 6.8), over this view before the write and the view after it.
    ///
    /// Every set is closed under shared identity in both views, since a
    /// query about one account of a person is a query about that person.
    /// A verification touches its account, every account of the person
    /// before and after, their relationship partners, the reviewers who
    /// name either person as a relative, and the relatives those reviewers
    /// name (confirmed 2026-10-25). A proximity list touches every account
    /// affiliated with an organisation on the old or new list. A reviewer
    /// declaration touches the reviewer, the old and new relatives, and
    /// every account affiliated with the old or new employer.
    pub fn touched(&self, f: &Fact) -> BTreeSet<WireAccount> {
        let after = self.after(f);
        let both = |set: &BTreeSet<WireAccount>| -> BTreeSet<WireAccount> {
            let mut out = self.closure(set);
            out.extend(after.closure(set));
            out
        };
        match f {
            Fact::VerificationRecorded {
                account, person, ..
            } => {
                let old = self.person_of(*account);
                let mut base = BTreeSet::from([*account]);
                base.extend(after.accounts_of_person(*person));
                if let Some(old) = old {
                    base.extend(self.accounts_of_person(old));
                }
                let mut out = both(&base);
                let before_partners = self.partners(&out);
                out.extend(before_partners);
                let after_partners = after.partners(&out);
                out.extend(after_partners);
                out.extend(after.reviewers_naming(*person));
                if let Some(old) = old {
                    out.extend(self.reviewers_naming(old));
                }
                let mut relatives = BTreeSet::new();
                for r in &out {
                    if let Some((_, rel)) = after.declarations.get(r) {
                        for p in rel {
                            relatives.extend(after.accounts_of_person(*p));
                        }
                    }
                }
                out.extend(relatives);
                both(&out)
            }
            Fact::AdultAttestation { account, .. }
            | Fact::AttestationWithdrawn { account }
            | Fact::AffiliationDeclared { account, .. }
            | Fact::AffiliationEnded { account, .. }
            | Fact::CountryStated { account, .. } => both(&BTreeSet::from([*account])),
            Fact::GuardianConsent { proposal, guardian } => {
                let mut base = BTreeSet::from([*guardian]);
                if let Some(old) = self.consent.get(proposal) {
                    base.insert(*old);
                }
                both(&base)
            }
            Fact::ConsentWithdrawn { proposal } => match self.consent.get(proposal) {
                Some(old) => both(&BTreeSet::from([*old])),
                None => BTreeSet::new(),
            },
            Fact::ProximityListDeclared { list, orgs } => {
                let mut all: BTreeSet<Org> = orgs.clone();
                if let Some(old) = self.lists.get(list) {
                    all.extend(old.iter().copied());
                }
                let mut base = BTreeSet::new();
                for o in all {
                    base.extend(self.affiliated_with(o));
                }
                both(&base)
            }
            Fact::ReviewerDeclaration {
                reviewer,
                employer,
                relatives,
            } => {
                let mut base = BTreeSet::from([*reviewer]);
                let mut people: BTreeSet<Person> = relatives.clone();
                let mut orgs: BTreeSet<Org> = employer.iter().copied().collect();
                if let Some((old_employer, old_rel)) = self.declarations.get(reviewer) {
                    people.extend(old_rel.iter().copied());
                    orgs.extend(old_employer.iter().copied());
                }
                for p in people {
                    base.extend(self.accounts_of_person(p));
                }
                for o in orgs {
                    base.extend(self.affiliated_with(o));
                }
                both(&base)
            }
            Fact::Relationship { a, b } => both(&BTreeSet::from([*a, *b])),
        }
    }

    /// Whether `reviewer` and `member` are in conflict (I-03, I-54, Q31).
    /// A conflict is a shared person, or an I-54 relationship between any
    /// accounts of the two persons. It is also a declared relative who is
    /// the member's person, or the reviewer's declared employer among the
    /// member's declared affiliations.
    ///
    /// Interim reading, pending Daniel: a relationship names no programme
    /// (W1c's kind 10 body), so it counts in every programme of the cell.
    /// I-54 asks for all later calls of its programme. This over-denies in
    /// another programme and never under-denies.
    pub fn conflict(&self, reviewer: WireAccount, member: WireAccount) -> bool {
        let pr = self.person_of(reviewer);
        let pm = self.person_of(member);
        if pr.is_some() && pr == pm {
            return true;
        }
        let rs = self.accounts_of(reviewer);
        let ms = self.accounts_of(member);
        if self
            .relationships
            .iter()
            .any(|(a, b)| (rs.contains(a) && ms.contains(b)) || (rs.contains(b) && ms.contains(a)))
        {
            return true;
        }
        rs.iter().any(|r| match self.declarations.get(r) {
            Some((employer, relatives)) => {
                pm.is_some_and(|p| relatives.contains(&p))
                    || employer.is_some_and(|e| {
                        ms.iter().any(|m| self.affiliations.contains_key(&(*m, e)))
                    })
            }
            None => false,
        })
    }

    /// Whether any account of `account`'s person declares an affiliation
    /// with a class in `classes` (I-04).
    ///
    /// Reading (W1c, open with Daniel): only class tags on declared
    /// affiliations count. A reviewer declaration feeds `HasConflict` only.
    ///
    /// Interim reading, pending Daniel: the query's programme is not used.
    /// A partner staff affiliation names no programme (W1c's kind 9 body),
    /// so a class counts in every programme of the cell. This over-denies
    /// in another programme and never under-denies (design section 6.8).
    pub fn excluded(&self, account: WireAccount, classes: &BTreeSet<WireClass>) -> bool {
        let accounts = self.accounts_of(account);
        self.affiliations
            .iter()
            .any(|((a, _), c)| accounts.contains(a) && c.is_some_and(|c| classes.contains(&c)))
    }

    /// The cap group of `subject` among `keys`: the subject, and every key
    /// with the subject's verified person. An unverified subject forms its
    /// own group (overview NOTE 1).
    fn cap_group<'a>(
        &self,
        subject: WireAccount,
        keys: impl IntoIterator<Item = &'a WireAccount>,
    ) -> BTreeSet<WireAccount> {
        let mut out = BTreeSet::from([subject]);
        if let Some(p) = self.person_of(subject) {
            out.extend(
                keys.into_iter()
                    .filter(|k| self.person_of(**k) == Some(p))
                    .copied(),
            );
        }
        out
    }

    /// Whether `start` plus the committed amounts of `group` stays within
    /// `cap`. Any overflow of the ADR-006 range answers no, never wraps.
    fn within(
        start: Amount,
        group: &BTreeSet<WireAccount>,
        committed: &BTreeMap<WireAccount, Amount>,
        cap: Amount,
    ) -> bool {
        let mut total = start;
        for a in group {
            if let Some(c) = committed.get(a) {
                match total.checked_add(*c) {
                    Ok(t) => total = t,
                    Err(_) => return false,
                }
            }
        }
        matches!(total.cmp_same(cap), Ok(Ordering::Less | Ordering::Equal))
    }

    /// Whether a consent for `proposal` counts: one is in the view, and
    /// its guardian's verification is in the same view (I-18, design
    /// section 14.4, `eval::guardian_consent`).
    pub fn guardian_consent(&self, proposal: WireProposal) -> bool {
        self.consent
            .get(&proposal)
            .is_some_and(|g| self.person_of(*g).is_some())
    }

    /// Whether `account` has an attestation that shows it 18 or older at
    /// `deadline`, and a verification in the same view (NOTE 7).
    ///
    /// Reading (W1c): the override by a later verification that shows the
    /// lead under 18 is not built, as Daniel has not decided it (ADR-008).
    pub fn adult_at(&self, account: WireAccount, deadline: i64) -> bool {
        self.person_of(account).is_some()
            && self
                .adult_from
                .get(&account)
                .is_some_and(|from| *from <= deadline)
    }

    /// The one-bit answer to `q` over this view. `ChangedSince` needs the
    /// epoch log, so it answers no here.
    pub fn holds(&self, q: &Query, p17: &BTreeMap<WireProgramme, BTreeSet<u16>>) -> bool {
        match q {
            Query::IsVerified { account } => self.person_of(*account).is_some(),
            Query::SameIdentityAsAny { subject, others } => match self.person_of(*subject) {
                Some(p) => others.iter().any(|o| self.person_of(*o) == Some(p)),
                None => false,
            },
            Query::HasConflict { reviewer, team } => {
                team.iter().any(|m| self.conflict(*reviewer, *m))
            }
            Query::InExcludedClass {
                account, classes, ..
            } => self.excluded(*account, classes),
            Query::WithinRecipientCap {
                subject,
                amount,
                committed,
                cap,
            } => {
                let group = self.cap_group(*subject, committed.keys());
                Facts::within(*amount, &group, committed, *cap)
            }
            Query::AllRecipientsWithinCap { committed, cap } => committed.keys().all(|k| {
                let group = self.cap_group(*k, committed.keys());
                Facts::within(Amount::zero(cap.currency()), &group, committed, *cap)
            }),
            Query::HasGuardianConsent { proposal } => self.guardian_consent(*proposal),
            Query::IsVerifiedAdultAtDeadline { account, deadline } => {
                self.adult_at(*account, *deadline)
            }
            Query::DeclaresAffiliationOnList { team, list } => match self.lists.get(list) {
                Some(orgs) => team.iter().any(|m| {
                    let accounts = self.accounts_of(*m);
                    self.affiliations
                        .keys()
                        .any(|(a, o)| accounts.contains(a) && orgs.contains(o))
                }),
                None => false,
            },
            Query::MeetsTieBreakCountry { account, programme } => {
                match (
                    self.country.get(&(*account, *programme)),
                    p17.get(programme),
                ) {
                    (Some(c), Some(allowed)) => allowed.contains(c),
                    _ => false,
                }
            }
            Query::ChangedSince { .. } => false,
        }
    }
}

/// The accounts and the proposal a query names, for the pending rule of
/// NOTE 4.
///
/// Reading (W1c): `HasGuardianConsent` names no account. It is pending
/// while a consent write for its proposal is provisional. `ChangedSince`
/// names nothing and is never pending.
pub fn named(q: &Query) -> (BTreeSet<WireAccount>, Option<WireProposal>) {
    match q {
        Query::IsVerified { account }
        | Query::InExcludedClass { account, .. }
        | Query::IsVerifiedAdultAtDeadline { account, .. }
        | Query::MeetsTieBreakCountry { account, .. } => (BTreeSet::from([*account]), None),
        Query::SameIdentityAsAny { subject, others } => {
            let mut out = others.clone();
            out.insert(*subject);
            (out, None)
        }
        Query::HasConflict { reviewer, team } => {
            let mut out = team.clone();
            out.insert(*reviewer);
            (out, None)
        }
        Query::WithinRecipientCap {
            subject, committed, ..
        } => {
            let mut out: BTreeSet<WireAccount> = committed.keys().copied().collect();
            out.insert(*subject);
            (out, None)
        }
        Query::AllRecipientsWithinCap { committed, .. } => {
            (committed.keys().copied().collect(), None)
        }
        Query::DeclaresAffiliationOnList { team, .. } => (team.clone(), None),
        Query::HasGuardianConsent { proposal } => (BTreeSet::new(), Some(*proposal)),
        Query::ChangedSince { .. } => (BTreeSet::new(), None),
    }
}

/// The proposal whose consent `f` writes, if any.
pub fn consent_proposal(f: &Fact) -> Option<WireProposal> {
    match f {
        Fact::GuardianConsent { proposal, .. } | Fact::ConsentWithdrawn { proposal } => {
            Some(*proposal)
        }
        _ => None,
    }
}
