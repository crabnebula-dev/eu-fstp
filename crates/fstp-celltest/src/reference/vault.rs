//! The reference identity vault (I-17, I-18, NOTE 4, design section 6).
//! Lane W1c owns this file.
//!
//! The reference is written from `SPEC/03-architecture/overview.md` (the
//! query table and NOTE 1 to NOTE 7), `SPEC/02-domain/state-machine.md`
//! NOTE 14, ADR-009 ("Vault origin", "Tickets", "Write kinds",
//! "Releases") and design section 6. It does not read `fstp-vault-core`,
//! `fstp-vault` or `fstp-cell-core`. It uses M2 types only as data.
//!
//! It holds:
//!
//! - [`Facts`]: the facts of one view and the evaluation of every query
//!   kind of `fstp_domain::oracle::Query` over them, as one bit, with
//!   `ChangedSince` listing account ids only.
//! - [`RefVault`]: epochs and the commit protocol of NOTE 4. One
//!   provisional write at a time, later writes queue, non-reaction queries
//!   about affected accounts are refused as pending, reaction queries see
//!   the provisional fact, and an acknowledgement makes it effective.
//! - Tickets of the vault origin ([`RefTicket`], [`check_ticket`]) and the
//!   release rules on both sides ([`release_ticket_allowed`],
//!   [`release_allowed`]).
//! - The guardian consent order of the cell ([`guardian_ticket_allowed`],
//!   [`guardian_ticket_order`]).
//! - [`wire`]: the encodings that carry reference facts and queries to the
//!   production vault core. They are a proposal of this lane, since the
//!   stubs fix no encoding (see that module).
//!
//! Every function is pure and total. No function panics. Arithmetic is
//! checked, so an overflow refuses or answers no.
//!
//! Readings the sources leave open are marked "Reading" in the item that
//! takes them. Lane W1c reports each one to Daniel.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fstp_domain::id::{AccountId, ClassId, ProgrammeId, ProposalId, ProximityListId};
use fstp_domain::oracle::Query;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;

// ---------------------------------------------------------------------------
// Constants.

/// The longest ticket lifetime: 5 minutes, an ADR-009 constant with no
/// P- id (Q37, interim).
pub const TICKET_LIFETIME_MAX_US: i64 = 5 * 60 * 1_000_000;

/// The first bytes of the command id of every reaction the cell appends
/// (design section 5.2). A caller command may not use them.
pub const REACTION_COMMAND_PREFIX: [u8; 8] = *b"fstp:vc:";

/// The command id of the reaction to vault epoch `epoch`: the reserved
/// prefix, then the epoch big-endian.
pub fn reaction_command_id(epoch: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (slot, b) in out.iter_mut().zip(REACTION_COMMAND_PREFIX.iter()) {
        *slot = *b;
    }
    for (slot, b) in out.iter_mut().skip(8).zip(epoch.to_be_bytes().iter()) {
        *slot = *b;
    }
    out
}

/// Whether `id` is a reserved reaction command id.
pub fn is_reaction_command_id(id: [u8; 16]) -> bool {
    id.starts_with(&REACTION_COMMAND_PREFIX)
}

// ---------------------------------------------------------------------------
// Facts.

/// A synthetic person, as the vault's identity match key stands for one
/// (design section 6.4, Q17). Only the vault knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Person(pub u64);

/// An organisation, as a declared affiliation or a proximity list names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Org(pub u64);

/// One write of a fact (ADR-009 "Write kinds", design sections 6.5 to 6.8).
///
/// Every kind becomes effective under the NOTE 4 protocol. A withdrawal is
/// a write too.
///
/// Reading: `PartnerStaffDeclared` is an [`RefWrite::AffiliationDeclared`]
/// whose class is the partner staff class of P-13. The design gives it no
/// other effect on any query.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RefWrite {
    /// A verification outcome, which gives the account its person
    /// (`VerificationRecorded`, design section 6.7).
    VerificationRecorded {
        /// The verified account.
        account: AccountId,
        /// The person the verification shows.
        person: Person,
    },
    /// An over-18 attestation of the account (`AdultAttestation`, NOTE 7).
    AdultAttestation {
        /// The attesting account.
        account: AccountId,
        /// The instant from which the attestation shows the account 18 or
        /// older. The vault never releases it.
        adult_from: Timestamp,
    },
    /// The withdrawal of an attestation.
    AttestationWithdrawn {
        /// The account.
        account: AccountId,
    },
    /// A guardian's consent for a proposal (`GuardianConsent`, I-18).
    GuardianConsent {
        /// The proposal.
        proposal: ProposalId,
        /// The guardian's account.
        guardian: AccountId,
    },
    /// The withdrawal of a proposal's guardian consent.
    ConsentWithdrawn {
        /// The proposal.
        proposal: ProposalId,
    },
    /// A declared affiliation, with the P-13 class it falls in, if any
    /// (`AffiliationDeclared`, `PartnerStaffDeclared`).
    AffiliationDeclared {
        /// The declaring account.
        account: AccountId,
        /// The organisation.
        org: Org,
        /// The excluded class of P-13 the affiliation falls in, if any.
        class: Option<ClassId>,
    },
    /// The end of a declared affiliation.
    AffiliationEnded {
        /// The account.
        account: AccountId,
        /// The organisation.
        org: Org,
    },
    /// A P-38 proximity list of one partner organisation. It replaces the
    /// earlier list with the same id (`ProximityListDeclared`, Q31).
    ProximityListDeclared {
        /// The list.
        list: ProximityListId,
        /// The organisations on it.
        orgs: BTreeSet<Org>,
    },
    /// A Judging-role holder's own employer and relatives. It replaces the
    /// holder's earlier declaration (`ReviewerDeclaration`, Q31).
    ReviewerDeclaration {
        /// The reviewer's account.
        reviewer: AccountId,
        /// The employer, if declared.
        employer: Option<Org>,
        /// The relatives, by the person each match key stands for.
        relatives: BTreeSet<Person>,
    },
    /// An I-54 mentoring relationship, account ids only
    /// (`RecordRelationship`, internal API).
    Relationship {
        /// One account.
        a: AccountId,
        /// The other account.
        b: AccountId,
    },
    /// The P-17 country stated at submission (`CountryStated`, NOTE 6).
    CountryStated {
        /// The applicant lead.
        account: AccountId,
        /// The programme.
        programme: ProgrammeId,
        /// The country, as a code the vault alone holds.
        country: u16,
    },
}

/// The facts of one view: the effective facts, or the effective facts with
/// the provisional one for a reaction (NOTE 4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Facts {
    person: BTreeMap<AccountId, Person>,
    adult_from: BTreeMap<AccountId, Timestamp>,
    consent: BTreeMap<ProposalId, AccountId>,
    affiliations: BTreeMap<(AccountId, Org), Option<ClassId>>,
    lists: BTreeMap<ProximityListId, BTreeSet<Org>>,
    declarations: BTreeMap<AccountId, (Option<Org>, BTreeSet<Person>)>,
    relationships: BTreeSet<(AccountId, AccountId)>,
    country: BTreeMap<(AccountId, ProgrammeId), u16>,
    p17: BTreeMap<ProgrammeId, BTreeSet<u16>>,
}

/// The two accounts of a relationship, smaller first.
fn pair(a: AccountId, b: AccountId) -> (AccountId, AccountId) {
    if a <= b { (a, b) } else { (b, a) }
}

impl Facts {
    /// No facts. `p17` gives the P-17 countries of each programme.
    ///
    /// Reading: the vault holds the P-17 condition of each programme as a
    /// set of countries. The sources say only that the country never
    /// leaves the vault (NOTE 6).
    pub fn with_p17(p17: BTreeMap<ProgrammeId, BTreeSet<u16>>) -> Facts {
        Facts {
            p17,
            ..Facts::default()
        }
    }

    /// Applies one write.
    pub fn apply(&mut self, w: &RefWrite) {
        match w {
            RefWrite::VerificationRecorded { account, person } => {
                self.person.insert(*account, *person);
            }
            RefWrite::AdultAttestation {
                account,
                adult_from,
            } => {
                self.adult_from.insert(*account, *adult_from);
            }
            RefWrite::AttestationWithdrawn { account } => {
                self.adult_from.remove(account);
            }
            RefWrite::GuardianConsent { proposal, guardian } => {
                self.consent.insert(*proposal, *guardian);
            }
            RefWrite::ConsentWithdrawn { proposal } => {
                self.consent.remove(proposal);
            }
            RefWrite::AffiliationDeclared {
                account,
                org,
                class,
            } => {
                self.affiliations.insert((*account, *org), *class);
            }
            RefWrite::AffiliationEnded { account, org } => {
                self.affiliations.remove(&(*account, *org));
            }
            RefWrite::ProximityListDeclared { list, orgs } => {
                self.lists.insert(*list, orgs.clone());
            }
            RefWrite::ReviewerDeclaration {
                reviewer,
                employer,
                relatives,
            } => {
                self.declarations
                    .insert(*reviewer, (*employer, relatives.clone()));
            }
            RefWrite::Relationship { a, b } => {
                self.relationships.insert(pair(*a, *b));
            }
            RefWrite::CountryStated {
                account,
                programme,
                country,
            } => {
                self.country.insert((*account, *programme), *country);
            }
        }
    }

    /// The facts after `w`.
    pub fn after(&self, w: &RefWrite) -> Facts {
        let mut out = self.clone();
        out.apply(w);
        out
    }

    /// The person of `account`, once a verification of it is in the view.
    pub fn person_of(&self, account: AccountId) -> Option<Person> {
        self.person.get(&account).copied()
    }

    /// `account` and every account with the same verified person.
    pub fn accounts_of(&self, account: AccountId) -> BTreeSet<AccountId> {
        let mut out = BTreeSet::from([account]);
        if let Some(p) = self.person_of(account) {
            out.extend(
                self.person
                    .iter()
                    .filter(|(_, q)| **q == p)
                    .map(|(a, _)| *a),
            );
        }
        out
    }

    /// Every account with the verified person `p`.
    fn accounts_of_person(&self, p: Person) -> BTreeSet<AccountId> {
        self.person
            .iter()
            .filter(|(_, q)| **q == p)
            .map(|(a, _)| *a)
            .collect()
    }

    /// The closure under shared identity of `accounts`.
    fn closure(&self, accounts: &BTreeSet<AccountId>) -> BTreeSet<AccountId> {
        accounts.iter().flat_map(|a| self.accounts_of(*a)).collect()
    }

    /// The relationship partners of any account in `accounts`.
    fn partners(&self, accounts: &BTreeSet<AccountId>) -> BTreeSet<AccountId> {
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

    /// The accounts affiliated with `org`.
    fn affiliated_with(&self, org: Org) -> BTreeSet<AccountId> {
        self.affiliations
            .keys()
            .filter(|(_, o)| *o == org)
            .map(|(a, _)| *a)
            .collect()
    }

    /// The reviewers whose declaration names `p` as a relative.
    fn reviewers_naming(&self, p: Person) -> BTreeSet<AccountId> {
        self.declarations
            .iter()
            .filter(|(_, (_, rel))| rel.contains(&p))
            .map(|(r, _)| *r)
            .collect()
    }

    /// The accounts a write touches (NOTE 4 step 2, design sections 6.3
    /// and 6.8), over the view before the write (`self`) and after it.
    ///
    /// Reading: every set is closed under shared identity in both views,
    /// since a query about one account of a person is a query about that
    /// person. A verification touches its account, every account of the
    /// person before and after, their relationship partners, the reviewers
    /// who name either person as a relative, and the relatives the account
    /// itself names. A proximity list touches every account affiliated
    /// with an organisation on the old or new list. A reviewer declaration
    /// touches the reviewer, the old and new relatives, and every account
    /// affiliated with the old or new employer.
    pub fn touched(&self, w: &RefWrite) -> BTreeSet<AccountId> {
        let after = self.after(w);
        let both = |set: &BTreeSet<AccountId>| -> BTreeSet<AccountId> {
            let mut out = self.closure(set);
            out.extend(after.closure(set));
            out
        };
        match w {
            RefWrite::VerificationRecorded { account, person } => {
                let mut base = BTreeSet::from([*account]);
                base.extend(after.accounts_of_person(*person));
                if let Some(old) = self.person_of(*account) {
                    base.extend(self.accounts_of_person(old));
                }
                let mut out = both(&base);
                out.extend(self.partners(&out.clone()));
                out.extend(after.partners(&out.clone()));
                out.extend(after.reviewers_naming(*person));
                if let Some(old) = self.person_of(*account) {
                    out.extend(self.reviewers_naming(old));
                }
                for r in out.clone() {
                    if let Some((_, rel)) = after.declarations.get(&r) {
                        for p in rel {
                            out.extend(after.accounts_of_person(*p));
                        }
                    }
                }
                both(&out)
            }
            RefWrite::AdultAttestation { account, .. }
            | RefWrite::AttestationWithdrawn { account }
            | RefWrite::AffiliationDeclared { account, .. }
            | RefWrite::AffiliationEnded { account, .. }
            | RefWrite::CountryStated { account, .. } => both(&BTreeSet::from([*account])),
            RefWrite::GuardianConsent { proposal, guardian } => {
                let mut base = BTreeSet::from([*guardian]);
                if let Some(old) = self.consent.get(proposal) {
                    base.insert(*old);
                }
                both(&base)
            }
            RefWrite::ConsentWithdrawn { proposal } => match self.consent.get(proposal) {
                Some(old) => both(&BTreeSet::from([*old])),
                None => BTreeSet::new(),
            },
            RefWrite::ProximityListDeclared { list, orgs } => {
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
            RefWrite::ReviewerDeclaration {
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
            RefWrite::Relationship { a, b } => both(&BTreeSet::from([*a, *b])),
        }
    }

    /// The proposal whose consent `w` writes, if any.
    pub fn consent_proposal(w: &RefWrite) -> Option<ProposalId> {
        match w {
            RefWrite::GuardianConsent { proposal, .. }
            | RefWrite::ConsentWithdrawn { proposal } => Some(*proposal),
            _ => None,
        }
    }

    /// Whether `reviewer` and `member` are in conflict (I-03, I-54, Q31).
    ///
    /// Reading: a conflict is a shared person, an I-54 relationship
    /// between any accounts of the two persons, a relative the reviewer
    /// declared who is the member's person, or the reviewer's declared
    /// employer among the member's declared affiliations.
    pub fn conflict(&self, reviewer: AccountId, member: AccountId) -> bool {
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
    /// Reading, open and reported to Daniel: roles-and-sod NOTE 2 places an
    /// IRC member's employer, co-workers and relatives in an excluded
    /// class, and design section 6.8 feeds `InExcludedClass` from
    /// `ReviewerDeclaration`. The sources name no P-13 class id for those
    /// declarations, and the vault does not know which reviewer sits on the
    /// IRC. So this reference counts only class tags on declared
    /// affiliations. A reviewer declaration feeds `HasConflict` only. Once
    /// Daniel fixes the class, the declaration carries its programme and
    /// class, and this function also counts a declared relative's accounts
    /// and the accounts affiliated with a declared employer.
    pub fn excluded(&self, account: AccountId, classes: &BTreeSet<ClassId>) -> bool {
        let accounts = self.accounts_of(account);
        self.affiliations
            .iter()
            .any(|((a, _), c)| accounts.contains(a) && c.is_some_and(|c| classes.contains(&c)))
    }

    /// The cap group of `subject` among `keys`: the subject, and every key
    /// with the subject's verified person. An unverified subject forms its
    /// own group (overview NOTE 1).
    pub fn cap_group(
        &self,
        subject: AccountId,
        keys: impl IntoIterator<Item = AccountId>,
    ) -> BTreeSet<AccountId> {
        let mut out = BTreeSet::from([subject]);
        if let Some(p) = self.person_of(subject) {
            out.extend(keys.into_iter().filter(|k| self.person_of(*k) == Some(p)));
        }
        out
    }

    /// The one-bit answer to `q` over this view. `ChangedSince` needs the
    /// vault's log, so it answers no here; [`RefVault`] answers it.
    pub fn holds(&self, q: &Query) -> bool {
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
            } => self.excluded(*account, &classes.0),
            Query::WithinRecipientCap {
                subject,
                amount,
                committed,
                cap,
            } => {
                let group = self.cap_group(*subject, committed.keys().copied());
                let mut total = amount.amount();
                for a in &group {
                    if let Some(c) = committed.get(a) {
                        match total.checked_add(c.amount()) {
                            Ok(t) => total = t,
                            Err(_) => return false,
                        }
                    }
                }
                matches!(
                    total.cmp_same(cap.amount()),
                    Ok(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                )
            }
            Query::AllRecipientsWithinCap { committed, cap } => committed.keys().all(|k| {
                let group = self.cap_group(*k, committed.keys().copied());
                let Ok(mut total) = cap.amount().checked_sub(cap.amount()) else {
                    return false;
                };
                for a in &group {
                    if let Some(c) = committed.get(a) {
                        match total.checked_add(c.amount()) {
                            Ok(t) => total = t,
                            Err(_) => return false,
                        }
                    }
                }
                matches!(
                    total.cmp_same(cap.amount()),
                    Ok(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                )
            }),
            Query::HasGuardianConsent { proposal } => self.consent_counts(*proposal),
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
                    self.p17.get(programme),
                ) {
                    (Some(c), Some(allowed)) => allowed.contains(c),
                    _ => false,
                }
            }
            Query::ChangedSince { .. } => false,
            // The bank and hardship queries of M5 (Q1 A) have no facts in
            // this twin yet, so they fail closed (I-33, R-PR-04).
            Query::BankReleasable { .. } | Query::HardshipEvidenceVerified { .. } => false,
        }
    }

    /// Whether a consent for `proposal` counts: one is in the view, and its
    /// guardian's verification is in the same view (I-18, design 6.4).
    pub fn consent_counts(&self, proposal: ProposalId) -> bool {
        self.consent
            .get(&proposal)
            .is_some_and(|g| self.person_of(*g).is_some())
    }

    /// Whether `account` has a verified attestation that shows it 18 or
    /// older at `deadline` (NOTE 7).
    ///
    /// Reading: "verified" means the attesting account has a verification
    /// in the same view. The override by a later verification that shows
    /// the lead under 18 is not modelled, as Daniel has not decided it
    /// (ADR-008, "Override").
    pub fn adult_at(&self, account: AccountId, deadline: Timestamp) -> bool {
        self.person_of(account).is_some()
            && self
                .adult_from
                .get(&account)
                .is_some_and(|from| *from <= deadline)
    }
}

/// The accounts and proposal a query names, for the pending rule of NOTE 4.
///
/// Reading: `HasGuardianConsent` names no account. It is refused as
/// pending while a consent write for its proposal is provisional, since
/// that write is about it. `ChangedSince` names nothing and is never
/// pending.
pub fn named(q: &Query) -> (BTreeSet<AccountId>, Option<ProposalId>) {
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
            let mut out: BTreeSet<AccountId> = committed.keys().copied().collect();
            out.insert(*subject);
            (out, None)
        }
        Query::AllRecipientsWithinCap { committed, .. } => {
            (committed.keys().copied().collect(), None)
        }
        Query::DeclaresAffiliationOnList { team, .. } => (team.clone(), None),
        Query::HasGuardianConsent { proposal } => (BTreeSet::new(), Some(*proposal)),
        Query::ChangedSince { .. } => (BTreeSet::new(), None),
        Query::BankReleasable { .. } | Query::HardshipEvidenceVerified { .. } => {
            (BTreeSet::new(), None)
        }
    }
}

// ---------------------------------------------------------------------------
// Epochs and the commit protocol (NOTE 4).

/// One answer of the reference vault.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefAnswer {
    /// The answer bit.
    pub holds: bool,
    /// The changed accounts, for `ChangedSince` only.
    pub accounts: Option<BTreeSet<AccountId>>,
    /// The epoch the answer is at.
    pub epoch: u64,
}

/// Why the reference vault refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefRefusal {
    /// A provisional epoch that touches the query waits for its
    /// acknowledgement.
    Pending {
        /// The provisional epoch.
        epoch: u64,
    },
    /// A reaction or an acknowledgement named an epoch that is not the
    /// provisional one.
    StaleEpoch {
        /// The vault's current epoch.
        current: u64,
    },
}

/// What a write or an acknowledgement did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefEvent {
    /// A write became provisional at this epoch.
    Provisional {
        /// The epoch.
        epoch: u64,
    },
    /// A write queued behind the provisional one.
    Queued,
    /// An epoch became effective.
    Effective {
        /// The epoch.
        epoch: u64,
    },
}

/// The provisional write.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Provisional {
    /// Its epoch.
    pub epoch: u64,
    /// The write.
    pub write: RefWrite,
    /// The accounts it touches.
    pub affected: BTreeSet<AccountId>,
    /// The proposal whose consent it writes, if any.
    pub proposal: Option<ProposalId>,
}

/// One effective write and what it touched.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Effective {
    /// Its epoch.
    pub epoch: u64,
    /// The write.
    pub write: RefWrite,
    /// The accounts it touched.
    pub affected: BTreeSet<AccountId>,
    /// The ledger sequence of the reaction that the acknowledgement named.
    pub reaction_seq: u64,
    /// The chain link of that reaction.
    pub reaction_link: [u8; 32],
}

/// The reference vault of one cell.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RefVault {
    facts: Facts,
    log: Vec<Effective>,
    provisional: Option<Provisional>,
    queue: VecDeque<RefWrite>,
    negotiation: BTreeMap<ProposalId, BTreeSet<AccountId>>,
    used_tickets: BTreeSet<[u8; 16]>,
}

impl RefVault {
    /// An empty vault whose programmes have the P-17 countries `p17`.
    pub fn with_p17(p17: BTreeMap<ProgrammeId, BTreeSet<u16>>) -> RefVault {
        RefVault {
            facts: Facts::with_p17(p17),
            ..RefVault::default()
        }
    }

    /// The effective epoch: the number of effective writes.
    pub fn effective(&self) -> u64 {
        self.log.last().map_or(0, |e| e.epoch)
    }

    /// The epoch the vault reports to the cell (`VaultRequest::Epoch`):
    /// the provisional epoch while one is outstanding, else the effective
    /// one.
    pub fn current(&self) -> u64 {
        self.provisional
            .as_ref()
            .map_or_else(|| self.effective(), |p| p.epoch)
    }

    /// The provisional write, if any.
    pub fn provisional(&self) -> Option<&Provisional> {
        self.provisional.as_ref()
    }

    /// The effective facts.
    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// The effective writes, in epoch order.
    pub fn log(&self) -> &[Effective] {
        &self.log
    }

    /// The writes queued behind the provisional one.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// The facts a reaction to the provisional epoch sees.
    pub fn reaction_facts(&self) -> Facts {
        match &self.provisional {
            Some(p) => self.facts.after(&p.write),
            None => self.facts.clone(),
        }
    }

    fn open(&mut self, w: RefWrite) -> Option<u64> {
        let epoch = self.effective().checked_add(1)?;
        let affected = self.facts.touched(&w);
        let proposal = Facts::consent_proposal(&w);
        self.provisional = Some(Provisional {
            epoch,
            write: w,
            affected,
            proposal,
        });
        Some(epoch)
    }

    /// Takes a write (NOTE 4 step 1). It becomes provisional at a new epoch
    /// when none is outstanding, and queues otherwise.
    pub fn write(&mut self, w: RefWrite) -> Vec<RefEvent> {
        if self.provisional.is_some() {
            self.queue.push_back(w);
            return vec![RefEvent::Queued];
        }
        match self.open(w) {
            Some(epoch) => vec![RefEvent::Provisional { epoch }],
            None => Vec::new(),
        }
    }

    /// Whether the provisional write makes `q` pending (NOTE 4 step 3).
    pub fn pending_for(&self, q: &Query) -> Option<u64> {
        let p = self.provisional.as_ref()?;
        let (accounts, proposal) = named(q);
        let hit = accounts.iter().any(|a| p.affected.contains(a))
            || (proposal.is_some() && proposal == p.proposal);
        hit.then_some(p.epoch)
    }

    /// The accounts touched by effective writes after `epoch`, and by the
    /// provisional write too when `with_provisional` is set.
    pub fn changed_since(&self, epoch: u64, with_provisional: bool) -> BTreeSet<AccountId> {
        let mut out: BTreeSet<AccountId> = self
            .log
            .iter()
            .filter(|e| e.epoch > epoch)
            .flat_map(|e| e.affected.iter().copied())
            .collect();
        if with_provisional && let Some(p) = &self.provisional {
            out.extend(p.affected.iter().copied());
        }
        out
    }

    fn answer_in(&self, facts: &Facts, q: &Query, epoch: u64, with_provisional: bool) -> RefAnswer {
        match q {
            Query::ChangedSince { epoch: since } => {
                let accounts = self.changed_since(since.raw(), with_provisional);
                RefAnswer {
                    holds: !accounts.is_empty(),
                    accounts: Some(accounts),
                    epoch,
                }
            }
            _ => RefAnswer {
                holds: facts.holds(q),
                accounts: None,
                epoch,
            },
        }
    }

    /// The answer to `q` over the effective facts, with no pending rule. A
    /// teeth test builds a defective vault from it.
    pub fn eval_effective(&self, q: &Query) -> RefAnswer {
        self.answer_in(&self.facts, q, self.effective(), false)
    }

    /// The answer to `q` over the effective and provisional facts, with no
    /// pending rule. A teeth test builds a defective vault from it.
    pub fn eval_with_provisional(&self, q: &Query) -> RefAnswer {
        self.answer_in(&self.reaction_facts(), q, self.current(), true)
    }

    /// Answers `queries` (NOTE 3, NOTE 4 step 3, design section 6.3).
    ///
    /// - A reaction ask (`reaction_for` set) must name the provisional
    ///   epoch. It sees the provisional fact, and its answers carry that
    ///   epoch.
    /// - Any other ask is refused as pending when one query names an
    ///   account the provisional write touches. Otherwise it is answered
    ///   over the effective facts at the effective epoch.
    ///
    /// # Errors
    ///
    /// [`RefRefusal::StaleEpoch`] for a reaction ask that names another
    /// epoch, and [`RefRefusal::Pending`] as above.
    pub fn ask(
        &self,
        reaction_for: Option<u64>,
        queries: &[Query],
    ) -> Result<Vec<RefAnswer>, RefRefusal> {
        match reaction_for {
            Some(e) => {
                let current = self.current();
                match &self.provisional {
                    Some(p) if p.epoch == e => {
                        let facts = self.reaction_facts();
                        Ok(queries
                            .iter()
                            .map(|q| self.answer_in(&facts, q, e, true))
                            .collect())
                    }
                    _ => Err(RefRefusal::StaleEpoch { current }),
                }
            }
            None => {
                if let Some(epoch) = queries.iter().find_map(|q| self.pending_for(q)) {
                    return Err(RefRefusal::Pending { epoch });
                }
                Ok(queries.iter().map(|q| self.eval_effective(q)).collect())
            }
        }
    }

    /// Records the cell's acknowledgement of its reaction (NOTE 4 step 5).
    /// The provisional fact becomes effective and the next queued write
    /// becomes provisional. A repeated acknowledgement of an effective
    /// epoch is accepted and changes nothing.
    ///
    /// Reading: a repeat keeps the first sequence and link.
    ///
    /// # Errors
    ///
    /// [`RefRefusal::StaleEpoch`] for an epoch that is neither provisional
    /// nor effective.
    pub fn ack(
        &mut self,
        epoch: u64,
        seq: u64,
        link: [u8; 32],
    ) -> Result<Vec<RefEvent>, RefRefusal> {
        let current = self.current();
        match self.provisional.take() {
            Some(p) if p.epoch == epoch => {
                self.facts.apply(&p.write);
                self.log.push(Effective {
                    epoch,
                    write: p.write,
                    affected: p.affected,
                    reaction_seq: seq,
                    reaction_link: link,
                });
                let mut out = vec![RefEvent::Effective { epoch }];
                if let Some(next) = self.queue.pop_front()
                    && let Some(e) = self.open(next)
                {
                    out.push(RefEvent::Provisional { epoch: e });
                }
                Ok(out)
            }
            other => {
                self.provisional = other;
                if epoch >= 1 && epoch <= self.effective() {
                    Ok(Vec::new())
                } else {
                    Err(RefRefusal::StaleEpoch { current })
                }
            }
        }
    }

    /// Records the negotiation fact the cell pushes when `proposal` enters
    /// NEGOTIATION (`NegotiationOpened`, ADR-009 "Releases").
    pub fn negotiation_opened(&mut self, proposal: ProposalId, accounts: BTreeSet<AccountId>) {
        self.negotiation.insert(proposal, accounts);
    }

    /// Removes the negotiation fact of `proposal` (`NegotiationClosed`).
    pub fn negotiation_closed(&mut self, proposal: ProposalId) {
        self.negotiation.remove(&proposal);
    }

    /// Whether the vault's own negotiation fact for `proposal` lists
    /// `subject` (the second guard of design section 6.5).
    pub fn negotiation_lists(&self, proposal: ProposalId, subject: AccountId) -> bool {
        self.negotiation
            .get(&proposal)
            .is_some_and(|s| s.contains(&subject))
    }

    /// The ticket ids used so far.
    pub fn used_tickets(&self) -> &BTreeSet<[u8; 16]> {
        &self.used_tickets
    }

    /// The facts once the provisional write and every queued write are
    /// effective: the newest facts the vault holds.
    pub fn latest_facts(&self) -> Facts {
        let mut out = self.reaction_facts();
        for w in &self.queue {
            out.apply(w);
        }
        out
    }

    /// Takes one write on the vault origin (ADR-009): the ticket is checked
    /// first, then bound to the write by [`origin_binding`], then marked
    /// used, and then the write enters the NOTE 4 protocol.
    ///
    /// Reading: the binding reads [`RefVault::latest_facts`], so a
    /// withdrawal or an ended affiliation may follow a write that is still
    /// provisional or queued.
    ///
    /// Reading: a refused write does not use up its ticket. Nothing was
    /// written, and the ticket stays bound to the one write it names.
    ///
    /// # Errors
    ///
    /// The ticket refusal, or [`TicketRefusal::WrongKind`] when the ticket
    /// does not bind the write (another kind, writer, proposal or scope).
    pub fn origin_write(
        &mut self,
        ticket: &[u8],
        write: RefWrite,
        check: &TicketCheck<'_>,
    ) -> Result<Vec<RefEvent>, TicketRefusal> {
        let t = check_ticket(ticket, check, &self.used_tickets)?;
        let binding =
            origin_binding(&self.latest_facts(), &write).ok_or(TicketRefusal::WrongKind)?;
        if !binding.admits(&t) {
            return Err(TicketRefusal::WrongKind);
        }
        self.used_tickets.insert(t.nonce);
        Ok(self.write(write))
    }

    /// Honours one release ticket (ADR-009 "Releases"): the ticket is
    /// checked and marked used, and the vault's own negotiation fact must
    /// list the subject.
    ///
    /// Reading: a release refused for any reason does not use up its
    /// ticket, as for [`RefVault::origin_write`]. Nothing is released, and
    /// the cell pushes the negotiation fact when NEGOTIATION opens, so a
    /// presentation that raced that push may be repeated before the ticket
    /// expires. ADR-009 says only that a second use is refused. Lane W1c
    /// reports this reading to Daniel.
    ///
    /// # Errors
    ///
    /// The ticket refusal, or [`TicketRefusal::NoNegotiationFact`].
    pub fn release(
        &mut self,
        ticket: &[u8],
        check: &TicketCheck<'_>,
    ) -> Result<RefTicket, TicketRefusal> {
        let t = check_ticket(ticket, check, &self.used_tickets)?;
        release_allowed(self, &t)?;
        self.used_tickets.insert(t.nonce);
        Ok(t)
    }
}

// ---------------------------------------------------------------------------
// Tickets (ADR-009 "Tickets").

/// A kind of vault origin write (ADR-009 "Write kinds").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WriteKind {
    /// The P-17 country.
    CountryStated,
    /// A declared affiliation.
    AffiliationDeclared,
    /// An over-18 attestation.
    AdultAttestation,
    /// A guardian consent.
    GuardianConsent,
    /// A document upload.
    DocumentUpload,
    /// A manual verification outcome.
    VerificationRecorded,
    /// A P-38 proximity list.
    ProximityListDeclared,
    /// A reviewer's employer and relatives.
    ReviewerDeclaration,
    /// A partner staff declaration.
    PartnerStaffDeclared,
}

impl WriteKind {
    /// Every kind.
    pub const ALL: [WriteKind; 9] = [
        WriteKind::CountryStated,
        WriteKind::AffiliationDeclared,
        WriteKind::AdultAttestation,
        WriteKind::GuardianConsent,
        WriteKind::DocumentUpload,
        WriteKind::VerificationRecorded,
        WriteKind::ProximityListDeclared,
        WriteKind::ReviewerDeclaration,
        WriteKind::PartnerStaffDeclared,
    ];

    /// The ticket spelling of the kind.
    pub const fn label(self) -> &'static str {
        match self {
            WriteKind::CountryStated => "country_stated",
            WriteKind::AffiliationDeclared => "affiliation_declared",
            WriteKind::AdultAttestation => "adult_attestation",
            WriteKind::GuardianConsent => "guardian_consent",
            WriteKind::DocumentUpload => "document_upload",
            WriteKind::VerificationRecorded => "verification_recorded",
            WriteKind::ProximityListDeclared => "proximity_list_declared",
            WriteKind::ReviewerDeclaration => "reviewer_declaration",
            WriteKind::PartnerStaffDeclared => "partner_staff_declared",
        }
    }

    /// The code this lane proposes for `fstp_cell_core::release::ReleaseCommand::IssueWriteTicket`
    /// and `fstp_vault_core::FactWrite::kind` (see [`wire`]).
    pub const fn code(self) -> u16 {
        match self {
            WriteKind::CountryStated => 1,
            WriteKind::AffiliationDeclared => 2,
            WriteKind::AdultAttestation => 3,
            WriteKind::GuardianConsent => 4,
            WriteKind::DocumentUpload => 5,
            WriteKind::VerificationRecorded => 6,
            WriteKind::ProximityListDeclared => 7,
            WriteKind::ReviewerDeclaration => 8,
            WriteKind::PartnerStaffDeclared => 9,
        }
    }
}

/// What a write ticket must carry to admit one origin write (ADR-009
/// "Tickets" and "Write kinds"): its kind, its writer, and the proposal or
/// scope the write names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginBinding {
    /// The ticket kind.
    pub kind: WriteKind,
    /// The writer, which the ticket's `account` must name.
    pub writer: AccountId,
    /// The proposal the ticket must name, if the write names one.
    pub proposal: Option<ProposalId>,
    /// The scope the ticket must carry, if the write needs one.
    pub scope: Option<String>,
}

impl OriginBinding {
    /// Whether ticket `t` admits the write this binding is for.
    pub fn admits(&self, t: &RefTicket) -> bool {
        t.kind == TicketKind::Write(self.kind)
            && t.account == self.writer
            && self.proposal.is_none_or(|p| t.proposal == Some(p))
            && self.scope.as_ref().is_none_or(|s| *s == t.scope)
    }
}

/// The scope a `CountryStated` ticket carries for `programme`.
///
/// Reading: the ticket format has no programme member, and the vault does
/// not know the programme of a proposal. So a country ticket names its
/// programme in the scope as `programme:<id>`. This spelling is a proposal
/// of lane W1c for `fstp_vault_proto::Ticket`, reported to Daniel.
pub fn country_scope(programme: ProgrammeId) -> String {
    format!("programme:{}", programme.raw())
}

/// The binding a write ticket needs for `w` over `facts`, the vault's
/// newest facts, or none when no ticket admits `w`.
///
/// Readings, reported to Daniel:
///
/// - The writer is the person ADR-009 "Write kinds" names. The guardian
///   writes a consent, and the ticket names its proposal, since the vault
///   cannot see `AddGuardian`.
/// - A withdrawal or an ended affiliation travels under the kind of the
///   fact it ends. Its writer is the writer of that fact, read from
///   `facts`. A consent is withdrawn by the guardian who gave it, under a
///   guardian consent ticket for the same proposal. A partner staff
///   affiliation (one with a class) ends only under a partner staff ticket.
///   With no such fact in `facts` there is nothing to end, so no ticket
///   admits the write.
/// - Any declaration that rewrites a partner staff affiliation needs a
///   partner staff ticket, with or without a class. An ordinary ticket
///   would otherwise clear the class by re-declaring the row (I-04).
/// - A country names its programme through [`country_scope`].
/// - A proximity list and a verification are written by a programme
///   manager or a recorder, who is not the fact's subject. So none is
///   returned for both until a later lane adds a rule for their writers.
///   `RecordRelationship` is not a browser write.
pub fn origin_binding(facts: &Facts, w: &RefWrite) -> Option<OriginBinding> {
    let plain = |kind: WriteKind, writer: AccountId| OriginBinding {
        kind,
        writer,
        proposal: None,
        scope: None,
    };
    match w {
        RefWrite::AdultAttestation { account, .. } | RefWrite::AttestationWithdrawn { account } => {
            Some(plain(WriteKind::AdultAttestation, *account))
        }
        RefWrite::GuardianConsent { proposal, guardian } => Some(OriginBinding {
            proposal: Some(*proposal),
            ..plain(WriteKind::GuardianConsent, *guardian)
        }),
        RefWrite::ConsentWithdrawn { proposal } => {
            facts.consent.get(proposal).map(|guardian| OriginBinding {
                proposal: Some(*proposal),
                ..plain(WriteKind::GuardianConsent, *guardian)
            })
        }
        RefWrite::AffiliationDeclared {
            account,
            org,
            class,
        } => {
            // A row that holds a class changes only under the partner staff
            // kind, so an unclassed re-declaration cannot clear it (I-04).
            let stored = facts.affiliations.get(&(*account, *org)).copied().flatten();
            Some(if class.is_some() || stored.is_some() {
                plain(WriteKind::PartnerStaffDeclared, *account)
            } else {
                plain(WriteKind::AffiliationDeclared, *account)
            })
        }
        RefWrite::AffiliationEnded { account, org } => facts
            .affiliations
            .get(&(*account, *org))
            .map(|class| match class {
                Some(_) => plain(WriteKind::PartnerStaffDeclared, *account),
                None => plain(WriteKind::AffiliationDeclared, *account),
            }),
        RefWrite::ReviewerDeclaration { reviewer, .. } => {
            Some(plain(WriteKind::ReviewerDeclaration, *reviewer))
        }
        RefWrite::CountryStated {
            account, programme, ..
        } => Some(OriginBinding {
            scope: Some(country_scope(*programme)),
            ..plain(WriteKind::CountryStated, *account)
        }),
        RefWrite::VerificationRecorded { .. }
        | RefWrite::ProximityListDeclared { .. }
        | RefWrite::Relationship { .. } => None,
    }
}

/// What a ticket admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TicketKind {
    /// A release of identity attributes (`POST /r`).
    Release,
    /// One write of one kind (`POST /w`).
    Write(WriteKind),
}

impl TicketKind {
    fn label(self) -> String {
        match self {
            TicketKind::Release => "release".to_owned(),
            TicketKind::Write(k) => format!("write:{}", k.label()),
        }
    }

    fn from_label(s: &str) -> Option<TicketKind> {
        if s == "release" {
            return Some(TicketKind::Release);
        }
        let k = s.strip_prefix("write:")?;
        WriteKind::ALL
            .iter()
            .find(|w| w.label() == k)
            .map(|w| TicketKind::Write(*w))
    }
}

/// A ticket of the vault origin: canonical JSON `{kind, cell, account,
/// proposal, scope, issued_at, expires_at, nonce}` (ADR-009).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefTicket {
    /// What it admits.
    pub kind: TicketKind,
    /// The cell, 16 bytes.
    pub cell: [u8; 16],
    /// The account: the writer of a write, the subject of a release.
    pub account: AccountId,
    /// The proposal, if the kind names one.
    pub proposal: Option<ProposalId>,
    /// The scope, a short label.
    pub scope: String,
    /// When it was issued.
    pub issued_at: Timestamp,
    /// When it expires. It is valid strictly before this instant.
    pub expires_at: Timestamp,
    /// The ticket id, 16 random bytes. A second use is refused.
    pub nonce: [u8; 16],
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = i.checked_mul(2)?;
        let end = start.checked_add(2)?;
        *slot = u8::from_str_radix(s.get(start..end)?, 16).ok()?;
    }
    Some(out)
}

impl RefTicket {
    /// The canonical JSON body, with members in RFC 8785 order. Ids are
    /// decimal strings, instants are integers of microseconds.
    pub fn canonical(&self) -> Vec<u8> {
        let proposal = match self.proposal {
            Some(p) => format!("\"{}\"", p.raw()),
            None => "null".to_owned(),
        };
        format!(
            "{{\"account\":\"{}\",\"cell\":\"{}\",\"expires_at\":{},\"issued_at\":{},\"kind\":\"{}\",\"nonce\":\"{}\",\"proposal\":{},\"scope\":\"{}\"}}",
            self.account.raw(),
            hex(&self.cell),
            self.expires_at.micros(),
            self.issued_at.micros(),
            self.kind.label(),
            hex(&self.nonce),
            proposal,
            self.scope,
        )
        .into_bytes()
    }

    /// Parses a canonical body as [`RefTicket::canonical`] writes it. Any
    /// other spelling is refused, so a forged re-encoding never passes.
    pub fn parse(body: &[u8]) -> Option<RefTicket> {
        let text = std::str::from_utf8(body).ok()?;
        let rest = text.strip_prefix("{\"account\":\"")?;
        let (account, rest) = rest.split_once("\",\"cell\":\"")?;
        let (cell, rest) = rest.split_once("\",\"expires_at\":")?;
        let (expires, rest) = rest.split_once(",\"issued_at\":")?;
        let (issued, rest) = rest.split_once(",\"kind\":\"")?;
        let (kind, rest) = rest.split_once("\",\"nonce\":\"")?;
        let (nonce, rest) = rest.split_once("\",\"proposal\":")?;
        let (proposal, rest) = rest.split_once(",\"scope\":\"")?;
        let scope = rest.strip_suffix("\"}")?;
        if scope.contains('"') || scope.contains('\\') {
            return None;
        }
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
        if !digits(account) || !digits(expires) || !digits(issued) {
            return None;
        }
        let proposal = if proposal == "null" {
            None
        } else {
            let inner = proposal.strip_prefix('"')?.strip_suffix('"')?;
            if !digits(inner) {
                return None;
            }
            Some(ProposalId::from_raw(inner.parse().ok()?))
        };
        let t = RefTicket {
            kind: TicketKind::from_label(kind)?,
            cell: unhex16(cell)?,
            account: AccountId::from_raw(account.parse().ok()?),
            proposal,
            scope: scope.to_owned(),
            issued_at: Timestamp::from_micros(issued.parse().ok()?),
            expires_at: Timestamp::from_micros(expires.parse().ok()?),
            nonce: unhex16(nonce)?,
        };
        (t.canonical() == body).then_some(t)
    }
}

/// The length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Why a signing key could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyError;

/// The Ed25519 public key of the ticket key with seed `seed`.
///
/// # Errors
///
/// [`KeyError`] when aws-lc-rs refuses the seed.
pub fn ticket_public_key(seed: &[u8; 32]) -> Result<[u8; 32], KeyError> {
    use aws_lc_rs::signature::KeyPair as _;
    let pair =
        aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError)?;
    let mut out = [0u8; 32];
    let public = pair.public_key().as_ref();
    if public.len() != out.len() {
        return Err(KeyError);
    }
    out.copy_from_slice(public);
    Ok(out)
}

/// The signed ticket: the canonical body, then the 64-byte Ed25519
/// signature over it.
///
/// Reading: ADR-009 fixes the body and the algorithm, not the framing.
/// This framing is a proposal of lane W1c for `fstp_vault_proto::Ticket`.
///
/// # Errors
///
/// [`KeyError`] when aws-lc-rs refuses the seed.
pub fn sign_ticket(t: &RefTicket, seed: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
    let pair =
        aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError)?;
    let mut out = t.canonical();
    let sig = pair.sign(&out);
    out.extend_from_slice(sig.as_ref());
    Ok(out)
}

/// Why the vault origin refused a ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TicketRefusal {
    /// The bytes do not frame a canonical body and a signature.
    Malformed,
    /// No pinned key verifies the signature.
    BadSignature,
    /// The ticket names another cell.
    ForeignCell,
    /// The ticket's kind does not match the route, or the write.
    WrongKind,
    /// The ticket is issued after now.
    NotYetValid,
    /// The ticket expired.
    Expired,
    /// The ticket lives longer than [`TICKET_LIFETIME_MAX_US`].
    TooLong,
    /// The ticket was used before.
    Replayed,
    /// No negotiation fact lists the release subject.
    NoNegotiationFact,
}

/// What the vault checks a ticket against.
#[derive(Clone, Copy, Debug)]
pub struct TicketCheck<'a> {
    /// The pinned ticket public keys of the cell: current and next.
    pub pinned: &'a [[u8; 32]],
    /// The vault's own cell.
    pub cell: [u8; 16],
    /// The route the ticket arrived on.
    pub route: RouteKind,
    /// Now.
    pub now: Timestamp,
}

/// The route group of the vault origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// `POST /w`.
    Write,
    /// `POST /r`.
    Release,
}

/// Checks a signed ticket (ADR-009 "Tickets"). The signature is checked
/// before any field is read. Then the cell, the route, the validity window,
/// the lifetime bound and single use.
///
/// # Errors
///
/// The first [`TicketRefusal`] in that order.
pub fn check_ticket(
    bytes: &[u8],
    check: &TicketCheck<'_>,
    used: &BTreeSet<[u8; 16]>,
) -> Result<RefTicket, TicketRefusal> {
    let body_len = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(TicketRefusal::Malformed)?;
    let body = bytes.get(..body_len).ok_or(TicketRefusal::Malformed)?;
    let sig = bytes.get(body_len..).ok_or(TicketRefusal::Malformed)?;
    let verified = check.pinned.iter().any(|k| {
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, k)
            .verify(body, sig)
            .is_ok()
    });
    if !verified {
        return Err(TicketRefusal::BadSignature);
    }
    let t = RefTicket::parse(body).ok_or(TicketRefusal::Malformed)?;
    if t.cell != check.cell {
        return Err(TicketRefusal::ForeignCell);
    }
    let route_ok = matches!(
        (check.route, t.kind),
        (RouteKind::Release, TicketKind::Release) | (RouteKind::Write, TicketKind::Write(_))
    );
    if !route_ok {
        return Err(TicketRefusal::WrongKind);
    }
    if check.now < t.issued_at {
        return Err(TicketRefusal::NotYetValid);
    }
    if check.now >= t.expires_at {
        return Err(TicketRefusal::Expired);
    }
    let life = t.expires_at.micros().checked_sub(t.issued_at.micros());
    if life.is_none_or(|l| l > TICKET_LIFETIME_MAX_US) {
        return Err(TicketRefusal::TooLong);
    }
    if used.contains(&t.nonce) {
        return Err(TicketRefusal::Replayed);
    }
    Ok(t)
}

// ---------------------------------------------------------------------------
// Releases (I-17).

/// The proposal states in which a release ticket may be issued:
/// NEGOTIATION and later (I-17, `overview.md`).
///
/// Reading: "later" is the states reachable only through NEGOTIATION:
/// GRANTED, IN_EXECUTION, COMPLETED and TERMINATED. DECLINED and WITHDRAWN
/// are reachable from earlier states, so they are left out.
pub const RELEASE_STATES: [StateTag; 5] = [
    StateTag::Negotiation,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// Whether the cell may issue a release ticket (design section 6.5): only
/// to an Operations role holder of the programme, for a proposal in
/// NEGOTIATION or later. A tenant admin at tenant scope holds Operations
/// in every programme (`roles-and-sod.md`, confirmed 2026-10-25).
pub fn release_ticket_allowed(holds_operations: bool, tenant_admin: bool, state: StateTag) -> bool {
    (holds_operations || tenant_admin) && RELEASE_STATES.contains(&state)
}

/// The vault side of a release (the second guard of design section 6.5):
/// the ticket is a release ticket for a proposal, and the vault's own
/// negotiation fact lists its subject.
///
/// # Errors
///
/// [`TicketRefusal::WrongKind`] or [`TicketRefusal::NoNegotiationFact`].
pub fn release_allowed(vault: &RefVault, t: &RefTicket) -> Result<(), TicketRefusal> {
    if t.kind != TicketKind::Release {
        return Err(TicketRefusal::WrongKind);
    }
    match t.proposal {
        Some(p) if vault.negotiation_lists(p, t.account) => Ok(()),
        _ => Err(TicketRefusal::NoNegotiationFact),
    }
}

// ---------------------------------------------------------------------------
// Guardian consent and the minor flag (I-18, NOTE 14, design 6.6).

/// Whether the cell may issue the guardian's write ticket for a proposal
/// (design section 6.6 step 3, state-machine NOTE 14).
///
/// `awaiting` is `fstp_domain::decision::awaiting_guardian_consent`.
/// `adult` is the vault's answer to `IsVerifiedAdultAtDeadline` for the
/// lead, asked in the same command, or `None` when the cell did not ask.
/// The ticket is issued only after the vault answered no, and only to a
/// [`GuardianRecipient::lawful`] recipient (ADR-009 "Write kinds": the
/// writer is "the guardian, a Receiving account added by `AddGuardian`").
pub fn guardian_ticket_allowed(
    awaiting: bool,
    adult: Option<bool>,
    recipient: GuardianRecipient,
) -> bool {
    awaiting && adult == Some(false) && recipient.lawful()
}

/// What the cell knows of the account a guardian consent ticket would go
/// to, for [`guardian_ticket_allowed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuardianRecipient {
    /// The account holds an active Guardian binding on the proposal, made
    /// by `AddGuardian`.
    pub guardian_binding: bool,
    /// The account is the proposal's lead.
    pub is_lead: bool,
    /// The vault's answer to `SameIdentityAsAny` for the account and the
    /// lead, if the cell asked it in the same command.
    pub same_identity_as_lead: Option<bool>,
}

impl GuardianRecipient {
    /// Whether the ticket may go to this account: it is a current guardian
    /// of the proposal, it is not the lead, and the vault did not say it
    /// shares the lead's identity.
    ///
    /// Reading, open and reported to Daniel: the sources ask no identity
    /// query at ticket issuance, and before NEGOTIATION the lead is not yet
    /// verified (R-NG-01), so a no proves little. A yes, when the cell
    /// asks, refuses the ticket, so a lead never consents through a second
    /// account the vault has already tied to it.
    pub const fn lawful(self) -> bool {
        self.guardian_binding && !self.is_lead && !matches!(self.same_identity_as_lead, Some(true))
    }
}

/// One event of a cell trace, for [`guardian_ticket_order`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CellEvent {
    /// The cell asked the vault and got this bit.
    Asked {
        /// The query.
        query: Query,
        /// The answer bit.
        holds: bool,
    },
    /// The cell issued a write ticket.
    WriteTicketIssued {
        /// The kind.
        kind: WriteKind,
        /// The proposal the ticket names.
        proposal: ProposalId,
        /// The lead of that proposal.
        lead: AccountId,
        /// The deadline the gate uses for it (ADR-008, "Which deadline").
        deadline: Timestamp,
    },
    /// A batch was shown to an actor. `vault_outcomes` counts the
    /// `VaultOutcome` records in what the actor saw.
    Shown {
        /// Whether the actor holds a Judging role.
        judging: bool,
        /// The vault outcome records the actor saw.
        vault_outcomes: usize,
    },
    /// The command ended.
    CommandEnd,
}

/// Checks a cell trace for the guardian order of design 6.6 step 3.
///
/// - Every guardian consent ticket for proposal `p` is preceded, within the
///   same command, by `IsVerifiedAdultAtDeadline` for `p`'s lead at its
///   deadline, answered no.
/// - No Judging actor is shown a vault outcome record (R-NG-01, NOTE 7).
///
/// # Errors
///
/// A message that names I-18 and the event that broke the order.
pub fn guardian_ticket_order(trace: &[CellEvent]) -> Result<(), String> {
    let mut asked: Vec<(&Query, bool)> = Vec::new();
    for (i, e) in trace.iter().enumerate() {
        match e {
            CellEvent::Asked { query, holds } => asked.push((query, *holds)),
            CellEvent::CommandEnd => asked.clear(),
            CellEvent::WriteTicketIssued {
                kind: WriteKind::GuardianConsent,
                lead,
                deadline,
                proposal,
            } => {
                let ok = asked.iter().any(|(q, holds)| {
                    !*holds
                        && matches!(q, Query::IsVerifiedAdultAtDeadline { account, deadline: d }
                            if account == lead && d == deadline)
                });
                if !ok {
                    return Err(format!(
                        "I-18: event {i} issued the guardian ticket for {proposal:?} without asking IsVerifiedAdultAtDeadline for its lead first, answered no"
                    ));
                }
            }
            CellEvent::WriteTicketIssued { .. } => {}
            CellEvent::Shown {
                judging: true,
                vault_outcomes,
            } if *vault_outcomes > 0 => {
                return Err(format!(
                    "I-18: event {i} showed {vault_outcomes} vault outcome records to a Judging actor (R-NG-01)"
                ));
            }
            CellEvent::Shown { .. } => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encodings for the production vault core.

/// The encodings that carry reference facts and queries to
/// `fstp_vault_core`, and its answers back.
///
/// Seam: the W0 stubs fix no encoding. `FactWrite` is `{kind, body}` and
/// `WireQuery` is `{kind, args}`, both opaque. Design section 6.2 asks for
/// a mirror of the query kinds, converted in `fstp-cell`, which has no
/// conversion yet. So this module is a proposal of lane W1c. Lane W2d
/// adopts it or replaces it here, and the tests follow.
///
/// - Fact kinds are [`WriteKind::code`], plus 10 for `RecordRelationship`
///   and 11 to 13 for the withdrawals. Bodies are canonical JSON with ids
///   as decimal strings, instants as integers and sets as sorted arrays.
/// - Query kinds are the index in `fstp_domain::oracle::QueryKind::ALL`.
///   Arguments are canonical JSON. Amounts are ADR-006 strings with the
///   currency code.
pub mod wire {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    use fstp_domain::id::AccountId;
    use fstp_domain::oracle::{Query, QueryKind};
    use fstp_vault_core::FactWrite;
    use fstp_vault_proto::{WireAccount, WireQuery};

    use super::{RefWrite, WriteKind};

    /// The fact kind of `RecordRelationship`.
    pub const KIND_RELATIONSHIP: u16 = 10;
    /// The fact kind of a consent withdrawal.
    pub const KIND_CONSENT_WITHDRAWN: u16 = 11;
    /// The fact kind of an attestation withdrawal.
    pub const KIND_ATTESTATION_WITHDRAWN: u16 = 12;
    /// The fact kind of an ended affiliation.
    pub const KIND_AFFILIATION_ENDED: u16 = 13;

    fn ids<T: Copy>(set: &BTreeSet<T>, raw: impl Fn(T) -> String) -> String {
        let mut s = String::from("[");
        for (i, v) in set.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "\"{}\"", raw(*v));
        }
        s.push(']');
        s
    }

    /// The canonical decimal string of `minor` units with `digits` minor
    /// digits (ADR-006), or `None` on overflow.
    pub fn decimal(minor: i64, digits: u8) -> Option<String> {
        let unsigned = u64::try_from(minor).ok()?;
        if digits == 0 {
            return Some(unsigned.to_string());
        }
        let scale = 10u64.checked_pow(u32::from(digits))?;
        let whole = unsigned.checked_div(scale)?;
        let frac = unsigned.checked_rem(scale)?;
        Some(format!(
            "{whole}.{frac:0width$}",
            width = usize::from(digits)
        ))
    }

    fn amt(text: Option<String>, code: &str) -> String {
        match text {
            Some(t) => format!("{{\"amount\":\"{t}\",\"currency\":\"{code}\"}}"),
            None => "null".to_owned(),
        }
    }

    /// The canonical JSON of one amount value. A macro, so this crate needs
    /// no `fstp-money` dependency to name the amount type.
    macro_rules! amount_json {
        ($v:expr) => {{
            let a = $v.amount();
            amt(
                decimal(a.minor(), a.currency().minor_digits()),
                a.currency().code(),
            )
        }};
    }

    /// The canonical JSON of a map from accounts to amounts.
    macro_rules! committed_json {
        ($map:expr) => {{
            let mut s = String::from("{");
            for (i, (k, v)) in $map.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let _ = write!(s, "\"{}\":{}", k.raw(), amount_json!(v));
            }
            s.push('}');
            s
        }};
    }

    /// The fact write that carries `w`.
    pub fn fact_write(w: &RefWrite) -> FactWrite {
        let (kind, body) = match w {
            // Lane W2d replaced W1c's `{account, person}`: R-ID-02 asks the
            // record to hold the method, document type, checks, time and
            // verifier (design section 6.7). The reference write has none,
            // so a fixed synthetic record stands in, by a verifier id that
            // no synthetic account takes. `identity` is the vault's id.
            RefWrite::VerificationRecorded { account, person } => (
                WriteKind::VerificationRecorded.code(),
                format!(
                    "{{\"account\":\"{}\",\"at\":0,\"checks\":[\"document_authentic\",\"photo_match\"],\"document_type\":\"passport\",\"identity\":\"{}\",\"method\":\"manual\",\"verifier\":\"{}\"}}",
                    account.raw(),
                    person.0,
                    u128::MAX
                ),
            ),
            RefWrite::AdultAttestation {
                account,
                adult_from,
            } => (
                WriteKind::AdultAttestation.code(),
                format!(
                    "{{\"account\":\"{}\",\"adult_from\":{}}}",
                    account.raw(),
                    adult_from.micros()
                ),
            ),
            RefWrite::AttestationWithdrawn { account } => (
                KIND_ATTESTATION_WITHDRAWN,
                format!("{{\"account\":\"{}\"}}", account.raw()),
            ),
            RefWrite::GuardianConsent { proposal, guardian } => (
                WriteKind::GuardianConsent.code(),
                format!(
                    "{{\"guardian\":\"{}\",\"proposal\":\"{}\"}}",
                    guardian.raw(),
                    proposal.raw()
                ),
            ),
            RefWrite::ConsentWithdrawn { proposal } => (
                KIND_CONSENT_WITHDRAWN,
                format!("{{\"proposal\":\"{}\"}}", proposal.raw()),
            ),
            RefWrite::AffiliationDeclared {
                account,
                org,
                class,
            } => {
                let class_text = match class {
                    Some(c) => format!("\"{}\"", c.raw()),
                    None => "null".to_owned(),
                };
                let kind = match class {
                    Some(_) => WriteKind::PartnerStaffDeclared.code(),
                    None => WriteKind::AffiliationDeclared.code(),
                };
                (
                    kind,
                    format!(
                        "{{\"account\":\"{}\",\"class\":{},\"org\":\"{}\"}}",
                        account.raw(),
                        class_text,
                        org.0
                    ),
                )
            }
            RefWrite::AffiliationEnded { account, org } => (
                KIND_AFFILIATION_ENDED,
                format!(
                    "{{\"account\":\"{}\",\"org\":\"{}\"}}",
                    account.raw(),
                    org.0
                ),
            ),
            RefWrite::ProximityListDeclared { list, orgs } => (
                WriteKind::ProximityListDeclared.code(),
                format!(
                    "{{\"list\":\"{}\",\"orgs\":{}}}",
                    list.raw(),
                    ids(orgs, |o| o.0.to_string())
                ),
            ),
            RefWrite::ReviewerDeclaration {
                reviewer,
                employer,
                relatives,
            } => {
                let employer_text = match employer {
                    Some(e) => format!("\"{}\"", e.0),
                    None => "null".to_owned(),
                };
                (
                    WriteKind::ReviewerDeclaration.code(),
                    format!(
                        "{{\"employer\":{},\"relatives\":{},\"reviewer\":\"{}\"}}",
                        employer_text,
                        ids(relatives, |p| p.0.to_string()),
                        reviewer.raw()
                    ),
                )
            }
            RefWrite::Relationship { a, b } => (
                KIND_RELATIONSHIP,
                format!("{{\"a\":\"{}\",\"b\":\"{}\"}}", a.raw(), b.raw()),
            ),
            RefWrite::CountryStated {
                account,
                programme,
                country,
            } => (
                WriteKind::CountryStated.code(),
                format!(
                    "{{\"account\":\"{}\",\"country\":{},\"programme\":\"{}\"}}",
                    account.raw(),
                    country,
                    programme.raw()
                ),
            ),
        };
        FactWrite {
            kind,
            body: body.into_bytes(),
        }
    }

    /// The wire account of `a`.
    pub const fn account(a: AccountId) -> WireAccount {
        WireAccount(a.raw())
    }

    /// The domain account of `a`.
    pub const fn domain_account(a: WireAccount) -> AccountId {
        AccountId::from_raw(a.0)
    }

    /// The reference form of a wire answer.
    pub fn answer(a: &fstp_vault_proto::WireAnswer) -> super::RefAnswer {
        super::RefAnswer {
            holds: a.holds,
            accounts: a
                .accounts
                .as_ref()
                .map(|v| v.iter().map(|w| domain_account(*w)).collect()),
            epoch: a.epoch,
        }
    }

    /// The kind code of `q`: its index in `QueryKind::ALL`.
    pub fn query_kind(q: &Query) -> u16 {
        let k = q.kind();
        QueryKind::ALL
            .iter()
            .position(|x| *x == k)
            .and_then(|i| u16::try_from(i).ok())
            .unwrap_or(u16::MAX)
    }

    fn accounts(set: &BTreeSet<AccountId>) -> String {
        ids(set, |a| a.raw().to_string())
    }

    /// The wire query that carries `q`.
    pub fn query(q: &Query) -> WireQuery {
        let args = match q {
            Query::IsVerified { account } => format!("{{\"account\":\"{}\"}}", account.raw()),
            Query::SameIdentityAsAny { subject, others } => format!(
                "{{\"others\":{},\"subject\":\"{}\"}}",
                accounts(others),
                subject.raw()
            ),
            Query::HasConflict { reviewer, team } => format!(
                "{{\"reviewer\":\"{}\",\"team\":{}}}",
                reviewer.raw(),
                accounts(team)
            ),
            Query::InExcludedClass {
                account,
                programme,
                classes,
            } => format!(
                "{{\"account\":\"{}\",\"classes\":{},\"programme\":\"{}\"}}",
                account.raw(),
                ids(&classes.0, |c| c.raw().to_string()),
                programme.raw()
            ),
            Query::WithinRecipientCap {
                subject,
                amount,
                committed: c,
                cap,
            } => format!(
                "{{\"amount\":{},\"cap\":{},\"committed\":{},\"subject\":\"{}\"}}",
                amount_json!(amount),
                amount_json!(cap),
                committed_json!(c),
                subject.raw()
            ),
            Query::AllRecipientsWithinCap { committed: c, cap } => format!(
                "{{\"cap\":{},\"committed\":{}}}",
                amount_json!(cap),
                committed_json!(c)
            ),
            Query::HasGuardianConsent { proposal } => {
                format!("{{\"proposal\":\"{}\"}}", proposal.raw())
            }
            Query::IsVerifiedAdultAtDeadline { account, deadline } => format!(
                "{{\"account\":\"{}\",\"deadline\":{}}}",
                account.raw(),
                deadline.micros()
            ),
            Query::DeclaresAffiliationOnList { team, list } => format!(
                "{{\"list\":\"{}\",\"team\":{}}}",
                list.raw(),
                accounts(team)
            ),
            Query::MeetsTieBreakCountry { account, programme } => format!(
                "{{\"account\":\"{}\",\"programme\":\"{}\"}}",
                account.raw(),
                programme.raw()
            ),
            Query::ChangedSince { epoch } => format!("{{\"epoch\":{}}}", epoch.raw()),
            Query::BankReleasable { grant, at, hold } => format!(
                "{{\"at\":{},\"grant\":\"{}\",\"hold\":{}}}",
                at.micros(),
                grant.raw(),
                hold.get()
            ),
            Query::HardshipEvidenceVerified { grant, evidence } => format!(
                "{{\"evidence\":\"{}\",\"grant\":\"{}\"}}",
                evidence.raw(),
                grant.raw()
            ),
        };
        WireQuery {
            kind: query_kind(q),
            args: args.into_bytes(),
        }
    }
}
