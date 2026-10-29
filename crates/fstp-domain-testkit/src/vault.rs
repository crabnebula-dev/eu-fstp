//! Synthetic identity vault and oracle doubles: SyntheticVault, HavocOracle, DownOracle (design section 4.5).
//!
//! - [`GroundTruth`] holds the vault facts of a test. Property predicates
//!   read it directly. Domain code sees only `Query` and `Answer`.
//! - [`SyntheticVault`] answers every query truthfully from its ground truth.
//! - [`HavocOracle`] answers a fixed script, whatever the facts. The domain
//!   must obey it.
//! - [`DownOracle`] never answers (`SPEC/03-architecture/overview.md` NOTE 2).
//! - [`sybil_pair`], [`excluded_applicant`], [`repeat_applicant`] and
//!   [`minor_applicant`] build ground truths shaped like the corpus
//!   variants of `SPEC/07-test-plan/synthetic-corpus.md`.
//!
//! Every id is a synthetic number. No real personal data is used.
//!
//! Readings taken where the spec is silent:
//! - Every mutator call advances the vault epoch by exactly one.
//! - A verified identity is the identity tag of a verified account. So
//!   `SameIdentityAsAny` and the cap grouping count verified accounts only.
//!   The subject itself counts when it is in the set.
//! - Conflicts and exclusions are facts about identities. They are known for
//!   every account with an identity tag, verified or not.
//! - Two accounts with one identity are always in conflict.
//! - A pending fact counts only once its account is verified, and adding it
//!   changes no account. A later verification of the same account makes any
//!   newly pending fact count. These are the facts revealed on verification
//!   of design section 4.5, not the NOTE 4 commit protocol.
//! - The NOTE 4 commit protocol has its own mutators. A provisional
//!   verification or affiliation advances the epoch and lists its account
//!   in `ChangedSince`, but no other query counts it. `make_effective` then
//!   makes it count, as a separate change. This follows the NOTE 4 text
//!   "queries count only effective facts". The reaction to a provisional
//!   fact is the exception: the queries of the VaultChanged that processes
//!   it see the fact, or the reaction could not act on it (design 4.3).
//!   Lane L-SOD adds that reaction view for M-RACE:
//!   [`GroundTruth::reaction_view`], [`GroundTruth::reaction_changed_since`]
//!   and [`GroundTruth::answer_in_reaction`]. In the reaction view the
//!   change query also lists the accounts that the revealed facts touch.
//! - Removing a fact advances the epoch and logs the accounts it touches,
//!   as adding it does.
//! - Affiliations on proximity lists and the P-17 bit are per account.
//! - An account changes when a fact about it or its identity takes effect.
//!   `ChangedSince` lists every account changed after the given epoch.
//! - An unverified account, or one without an identity tag, forms its own
//!   cap group.
//! - A cap query whose amounts cannot be added or compared, because of
//!   overflow or mixed currencies, does not hold.
//! - Answer digests are a fixed placeholder. The M3 driver computes them
//!   with `fstp-crypto` over the canonical query encoding of lane L-CODEC.
//! - An over-18 attestation is a fact about an account, as the query names
//!   the lead (`SPEC/03-architecture/overview.md` NOTE 7, R-ID-04). The
//!   twin holds it as the instant from which the attestation shows the
//!   account 18 or older. `IsVerifiedAdultAtDeadline` holds exactly when
//!   an effective attestation shows that at the deadline the query names.
//!   The vault never releases the instant. So an attestation verified late
//!   still counts when it shows the age at the deadline (ADR-008, "Late
//!   verification", interim).
//! - A verification can show an account under 18 until an instant, its
//!   18th birthday. When an effective attestation shows the account 18 or
//!   older at a deadline and such a verification shows it under 18 there,
//!   neither wins (state-machine NOTE 14, ADR-008 "Override", decided
//!   2026-10-29). A manual identity check resolves the conflict (G9).
//!   Until it does, the twin gives no answer to `IsVerifiedAdultAtDeadline`
//!   at that deadline, neither yes nor no. [`SyntheticVault`] then fails
//!   the query with `OracleDown`, and [`GroundTruth::try_answer`] gives
//!   `None`, so every gate that asks fails closed (overview NOTE 2).
//!   [`GroundTruth::answer`] still gives the attestation's bit, for the
//!   callers that never meet a conflict.
//! - An attestation becomes effective under the NOTE 4 commit protocol,
//!   like a verification. Adding, making effective or withdrawing one
//!   lists its account in `ChangedSince`.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{
    AccountId, ClassId, ContentDigest, ProgrammeId, ProposalId, ProximityListId, VaultEpoch,
};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::time::Timestamp;
use fstp_engine::IdentityOracle;
use fstp_money::{Amount, NonNegAmount};
use fstp_prop::Gen;

/// The digest every double puts on its answers. See the module documentation.
pub const PLACEHOLDER_DIGEST: ContentDigest = ContentDigest::from_bytes([0; 32]);

/// A synthetic identity: a person known only to the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityTag(u64);

impl IdentityTag {
    /// The identity with synthetic number `n`.
    pub const fn new(n: u64) -> IdentityTag {
        IdentityTag(n)
    }

    /// The synthetic number.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A relation between two identities that makes a conflict (I-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// The two work together.
    CoWorker,
    /// The two are relatives.
    Relative,
    /// One mentors the other.
    Mentoring,
}

/// A fact that the vault reveals only when an account is verified (design
/// section 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingFact {
    /// The identity is in an excluded affiliation class.
    Excluded {
        /// The identity.
        identity: IdentityTag,
        /// The class.
        class: ClassId,
    },
    /// The two identities are related.
    Related {
        /// One identity.
        a: IdentityTag,
        /// The other identity.
        b: IdentityTag,
        /// How they are related.
        relation: Relation,
    },
}

/// The outcome of a manual identity check that resolves an age conflict
/// (G9, state-machine NOTE 14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgeCheck {
    /// The check shows the account 18 or older, as the attestation says.
    Adult,
    /// The check shows the account under 18, as the verification says.
    Minor,
}

/// The facts of a synthetic vault, with its epoch and change log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroundTruth {
    identity_of: BTreeMap<AccountId, IdentityTag>,
    verified: BTreeSet<AccountId>,
    relations: BTreeSet<(IdentityTag, IdentityTag, Relation)>,
    excluded: BTreeSet<(IdentityTag, ClassId)>,
    pending: BTreeMap<AccountId, BTreeSet<PendingFact>>,
    consents: BTreeSet<ProposalId>,
    affiliations: BTreeSet<(AccountId, ProximityListId)>,
    country: BTreeSet<(AccountId, ProgrammeId)>,
    /// Verifications marked provisional under NOTE 4, not yet effective.
    provisional_verified: BTreeSet<AccountId>,
    /// Affiliations marked provisional under NOTE 4, not yet effective.
    provisional_affiliations: BTreeSet<(AccountId, ProximityListId)>,
    /// Effective verified over-18 attestations: the instant from which each
    /// shows its account 18 or older (overview NOTE 7, R-ID-04).
    adults: BTreeMap<AccountId, Timestamp>,
    /// Over-18 attestations marked provisional under NOTE 4, not yet effective.
    provisional_adults: BTreeMap<AccountId, Timestamp>,
    /// Effective verifications that show an account under 18: the instant
    /// from which each shows it 18 or older (state-machine NOTE 14).
    under_18: BTreeMap<AccountId, Timestamp>,
    epoch: VaultEpoch,
    /// The accounts changed by the mutation that produced each epoch.
    changes: Vec<(VaultEpoch, BTreeSet<AccountId>)>,
}

impl Default for GroundTruth {
    fn default() -> GroundTruth {
        GroundTruth::new()
    }
}

impl GroundTruth {
    /// A vault with no facts, at epoch 0.
    pub fn new() -> GroundTruth {
        GroundTruth {
            identity_of: BTreeMap::new(),
            verified: BTreeSet::new(),
            relations: BTreeSet::new(),
            excluded: BTreeSet::new(),
            pending: BTreeMap::new(),
            consents: BTreeSet::new(),
            affiliations: BTreeSet::new(),
            country: BTreeSet::new(),
            provisional_verified: BTreeSet::new(),
            provisional_affiliations: BTreeSet::new(),
            adults: BTreeMap::new(),
            provisional_adults: BTreeMap::new(),
            under_18: BTreeMap::new(),
            epoch: VaultEpoch::GENESIS,
            changes: Vec::new(),
        }
    }

    /// The current epoch.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }

    // -- mutators ------------------------------------------------------------

    /// Gives `account` the identity `tag`, replacing any earlier one.
    pub fn set_identity(&mut self, account: AccountId, tag: IdentityTag) {
        self.identity_of.insert(account, tag);
        self.commit([account].into_iter().collect());
    }

    /// Verifies `account`, effective at once. Its pending facts take effect
    /// now (design section 4.5).
    pub fn verify(&mut self, account: AccountId) {
        let changed = self.verify_effective(account);
        self.commit(changed);
    }

    /// Makes `account` verified and its pending facts effective, and returns
    /// the accounts this changes. It does not commit.
    fn verify_effective(&mut self, account: AccountId) -> BTreeSet<AccountId> {
        self.verified.insert(account);
        let mut changed: BTreeSet<AccountId> = [account].into_iter().collect();
        for fact in self.pending.remove(&account).unwrap_or_default() {
            match fact {
                PendingFact::Excluded { identity, class } => {
                    self.excluded.insert((identity, class));
                    changed.extend(self.accounts_of(&[identity]));
                }
                PendingFact::Related { a, b, relation } => {
                    self.relations.insert((a, b, relation));
                    changed.extend(self.accounts_of(&[a, b]));
                }
            }
        }
        changed
    }

    /// Marks a new verification of `account` as provisional (NOTE 4). The
    /// epoch advances and `ChangedSince` lists `account`, but no other query
    /// counts the verification until [`GroundTruth::make_effective`].
    pub fn verify_provisional(&mut self, account: AccountId) {
        self.provisional_verified.insert(account);
        self.commit([account].into_iter().collect());
    }

    /// Marks a new affiliation of `account` on `list` as provisional
    /// (NOTE 4). The epoch advances and `ChangedSince` lists `account`, but
    /// `DeclaresAffiliationOnList` does not count it until
    /// [`GroundTruth::make_effective`].
    pub fn declare_affiliation_provisional(&mut self, account: AccountId, list: ProximityListId) {
        self.provisional_affiliations.insert((account, list));
        self.commit([account].into_iter().collect());
    }

    /// Makes every provisional fact of `account` effective (NOTE 4): its
    /// provisional verification, with its pending facts, its provisional
    /// affiliations and its provisional over-18 attestation. The epoch advances once, and the accounts
    /// the facts touch are logged.
    pub fn make_effective(&mut self, account: AccountId) {
        let mut changed: BTreeSet<AccountId> = BTreeSet::new();
        if self.provisional_verified.remove(&account) {
            changed.extend(self.verify_effective(account));
        }
        let lists: Vec<(AccountId, ProximityListId)> = self
            .provisional_affiliations
            .iter()
            .filter(|(a, _)| *a == account)
            .copied()
            .collect();
        for fact in lists {
            self.provisional_affiliations.remove(&fact);
            self.affiliations.insert(fact);
            changed.insert(account);
        }
        if let Some(from) = self.provisional_adults.remove(&account) {
            self.adults.insert(account, from);
            changed.insert(account);
        }
        self.commit(changed);
    }

    /// Records that identities `a` and `b` are related.
    pub fn relate(&mut self, a: IdentityTag, b: IdentityTag, relation: Relation) {
        self.relations.insert((a, b, relation));
        let changed = self.accounts_of(&[a, b]);
        self.commit(changed);
    }

    /// Records that `identity` is in the excluded class `class`.
    pub fn exclude(&mut self, identity: IdentityTag, class: ClassId) {
        self.excluded.insert((identity, class));
        let changed = self.accounts_of(&[identity]);
        self.commit(changed);
    }

    /// Adds a fact that takes effect when `account` is next verified.
    pub fn add_pending(&mut self, account: AccountId, fact: PendingFact) {
        self.pending.entry(account).or_default().insert(fact);
        self.commit(BTreeSet::new());
    }

    /// Records a verified guardian consent for `proposal` (I-18).
    pub fn consent(&mut self, proposal: ProposalId) {
        self.consents.insert(proposal);
        self.commit(BTreeSet::new());
    }

    /// Records that `account` declares an affiliation on `list` (I-35, P-38).
    pub fn declare_affiliation(&mut self, account: AccountId, list: ProximityListId) {
        self.affiliations.insert((account, list));
        self.commit([account].into_iter().collect());
    }

    /// Records that `account` meets the P-17 country condition of `programme`.
    pub fn meet_country(&mut self, account: AccountId, programme: ProgrammeId) {
        self.country.insert((account, programme));
        self.commit([account].into_iter().collect());
    }

    /// Records an effective verified over-18 attestation of `account`, which
    /// shows it 18 or older from `from` on (overview NOTE 7, R-ID-04). It
    /// replaces an earlier attestation of the account.
    pub fn attest_adult(&mut self, account: AccountId, from: Timestamp) {
        self.adults.insert(account, from);
        self.commit([account].into_iter().collect());
    }

    /// Marks a new over-18 attestation of `account` as provisional (NOTE 4,
    /// overview NOTE 7). The epoch advances and `ChangedSince` lists
    /// `account`, but `IsVerifiedAdultAtDeadline` does not count it until
    /// [`GroundTruth::make_effective`].
    pub fn attest_adult_provisional(&mut self, account: AccountId, from: Timestamp) {
        self.provisional_adults.insert(account, from);
        self.commit([account].into_iter().collect());
    }

    /// Records an effective verification whose attributes show `account`
    /// under 18 until `adult_from`, and 18 or older from then on
    /// (state-machine NOTE 14). It replaces an earlier such verification.
    /// At a deadline before `adult_from` it conflicts with an attestation
    /// that shows the account 18 or older there (ADR-008, "Override").
    pub fn verify_under_18(&mut self, account: AccountId, adult_from: Timestamp) {
        self.under_18.insert(account, adult_from);
        self.commit([account].into_iter().collect());
    }

    /// Records the outcome of the manual identity check that resolves an
    /// age conflict of `account` (G9, state-machine NOTE 14). An `Adult`
    /// outcome sets the under-18 verification aside, so the attestation
    /// counts. A `Minor` outcome withdraws the attestation, so the account
    /// is not shown 18 or older. Either way the conflict ends.
    pub fn resolve_age_conflict(&mut self, account: AccountId, outcome: AgeCheck) {
        match outcome {
            AgeCheck::Adult => {
                self.under_18.remove(&account);
            }
            AgeCheck::Minor => {
                self.adults.remove(&account);
                self.provisional_adults.remove(&account);
            }
        }
        self.commit([account].into_iter().collect());
    }

    // -- removals -------------------------------------------------------------

    /// Ends the relation `relation` between identities `a` and `b`, in
    /// either order. The two may still conflict through another relation.
    pub fn unrelate(&mut self, a: IdentityTag, b: IdentityTag, relation: Relation) {
        self.relations.remove(&(a, b, relation));
        self.relations.remove(&(b, a, relation));
        let changed = self.accounts_of(&[a, b]);
        self.commit(changed);
    }

    /// Ends the affiliation of `account` on `list`, effective or provisional.
    pub fn end_affiliation(&mut self, account: AccountId, list: ProximityListId) {
        self.affiliations.remove(&(account, list));
        self.provisional_affiliations.remove(&(account, list));
        self.commit([account].into_iter().collect());
    }

    /// Takes `identity` out of the excluded class `class`.
    pub fn unexclude(&mut self, identity: IdentityTag, class: ClassId) {
        self.excluded.remove(&(identity, class));
        let changed = self.accounts_of(&[identity]);
        self.commit(changed);
    }

    /// Withdraws the guardian consent for `proposal` (I-18).
    pub fn withdraw_consent(&mut self, proposal: ProposalId) {
        self.consents.remove(&proposal);
        self.commit(BTreeSet::new());
    }

    /// Withdraws the over-18 attestation of `account`, effective or
    /// provisional. A test uses it to give a lead no attestation, whatever
    /// its setup gave it.
    pub fn withdraw_attestation(&mut self, account: AccountId) {
        self.adults.remove(&account);
        self.provisional_adults.remove(&account);
        self.commit([account].into_iter().collect());
    }

    // -- readers for property predicates --------------------------------------

    /// The identity of `account`, verified or not.
    pub fn identity_of(&self, account: AccountId) -> Option<IdentityTag> {
        self.identity_of.get(&account).copied()
    }

    /// Whether `account` is verified.
    pub fn is_verified(&self, account: AccountId) -> bool {
        self.verified.contains(&account)
    }

    /// The verified identity of `account`: its identity, if it is verified.
    pub fn verified_identity(&self, account: AccountId) -> Option<IdentityTag> {
        if self.is_verified(account) {
            self.identity_of(account)
        } else {
            None
        }
    }

    /// Whether two identities are in conflict: the same identity, or related.
    pub fn related(&self, a: IdentityTag, b: IdentityTag) -> bool {
        a == b
            || self
                .relations
                .iter()
                .any(|(x, y, _)| (*x == a && *y == b) || (*x == b && *y == a))
    }

    /// Whether `identity` is in the excluded class `class`.
    pub fn is_excluded(&self, identity: IdentityTag, class: ClassId) -> bool {
        self.excluded.contains(&(identity, class))
    }

    /// Whether the vault holds an identity or a verification for `account`,
    /// effective or provisional.
    pub fn knows(&self, account: AccountId) -> bool {
        self.identity_of.contains_key(&account)
            || self.verified.contains(&account)
            || self.provisional_verified.contains(&account)
    }

    /// Whether `account` has a provisional verification (NOTE 4). Queries do
    /// not count it.
    pub fn is_provisionally_verified(&self, account: AccountId) -> bool {
        self.provisional_verified.contains(&account)
    }

    /// Whether `account` declares an affiliation on `list` that counts.
    pub fn declares_affiliation(&self, account: AccountId, list: ProximityListId) -> bool {
        self.affiliations.contains(&(account, list))
    }

    /// Whether `account` has a provisional affiliation on `list` (NOTE 4).
    /// Queries do not count it.
    pub fn has_provisional_affiliation(&self, account: AccountId, list: ProximityListId) -> bool {
        self.provisional_affiliations.contains(&(account, list))
    }

    /// Every account with a provisional fact (NOTE 4), in order.
    pub fn provisional_accounts(&self) -> BTreeSet<AccountId> {
        self.provisional_verified
            .iter()
            .copied()
            .chain(self.provisional_affiliations.iter().map(|(a, _)| *a))
            .chain(self.provisional_adults.keys().copied())
            .collect()
    }

    /// Whether guardian consent for `proposal` is recorded (I-18).
    pub fn has_consent(&self, proposal: ProposalId) -> bool {
        self.consents.contains(&proposal)
    }

    /// Whether an effective verified over-18 attestation shows `account` 18
    /// or older at `deadline` (overview NOTE 7, R-ID-04). A provisional
    /// attestation does not count.
    pub fn is_adult_at(&self, account: AccountId, deadline: Timestamp) -> bool {
        self.adults
            .get(&account)
            .is_some_and(|from| *from <= deadline)
    }

    /// Whether `account` has a provisional over-18 attestation (NOTE 4).
    /// Queries do not count it.
    pub fn has_provisional_attestation(&self, account: AccountId) -> bool {
        self.provisional_adults.contains_key(&account)
    }

    /// Whether an effective verification shows `account` under 18 at
    /// `deadline` (state-machine NOTE 14).
    pub fn is_under_18_at(&self, account: AccountId, deadline: Timestamp) -> bool {
        self.under_18
            .get(&account)
            .is_some_and(|adult_from| deadline < *adult_from)
    }

    /// Whether the vault holds an unresolved age conflict of `account` at
    /// `deadline`: an effective attestation shows it 18 or older there,
    /// and an effective verification shows it under 18 (state-machine
    /// NOTE 14, ADR-008 "Override", decided 2026-10-29).
    pub fn age_conflict_at(&self, account: AccountId, deadline: Timestamp) -> bool {
        self.is_adult_at(account, deadline) && self.is_under_18_at(account, deadline)
    }

    /// The vault's answer to "is `account` an effective verified adult at
    /// `deadline`?", or `None` while an age conflict there waits for its
    /// manual identity check (state-machine NOTE 14).
    pub fn adult_answer(&self, account: AccountId, deadline: Timestamp) -> Option<bool> {
        (!self.age_conflict_at(account, deadline)).then(|| self.is_adult_at(account, deadline))
    }

    /// Whether the vault answers `q` at all. It answers every query except
    /// `IsVerifiedAdultAtDeadline` at a deadline with an unresolved age
    /// conflict (state-machine NOTE 14).
    pub fn answers(&self, q: &Query) -> bool {
        match q {
            Query::IsVerifiedAdultAtDeadline { account, deadline } => {
                !self.age_conflict_at(*account, *deadline)
            }
            _ => true,
        }
    }

    /// The truthful answer to `q`, or `None` when the vault gives none
    /// ([`GroundTruth::answers`]). A world that collects answers for a
    /// command leaves such a query unanswered, so the command fails closed
    /// (overview NOTE 2).
    pub fn try_answer(&self, q: &Query) -> Option<Answer> {
        self.answers(q).then(|| self.answer(q))
    }

    /// The accounts changed after `epoch`.
    pub fn changed_since(&self, epoch: VaultEpoch) -> BTreeSet<AccountId> {
        self.changes
            .iter()
            .filter(|(e, _)| *e > epoch)
            .flat_map(|(_, c)| c.iter().copied())
            .collect()
    }

    /// The answer bit to `q` under these facts. For `ChangedSince` it is
    /// whether any account changed.
    pub fn holds(&self, q: &Query) -> bool {
        match q {
            Query::IsVerified { account } => self.is_verified(*account),
            Query::SameIdentityAsAny { subject, others } => {
                match self.verified_identity(*subject) {
                    Some(t) => others.iter().any(|o| self.verified_identity(*o) == Some(t)),
                    None => false,
                }
            }
            Query::HasConflict { reviewer, team } => match self.identity_of(*reviewer) {
                Some(r) => team
                    .iter()
                    .filter_map(|m| self.identity_of(*m))
                    .any(|m| self.related(r, m)),
                None => false,
            },
            Query::InExcludedClass {
                account, classes, ..
            } => match self.identity_of(*account) {
                Some(t) => classes.0.iter().any(|c| self.is_excluded(t, *c)),
                None => false,
            },
            Query::WithinRecipientCap {
                subject,
                amount,
                committed,
                cap,
            } => {
                let group = self.cap_group(*subject, committed);
                sum_into(amount.amount(), &group, committed)
                    .is_some_and(|total| at_most(total, *cap))
            }
            Query::AllRecipientsWithinCap { committed, cap } => committed.keys().all(|a| {
                let group = self.cap_group(*a, committed);
                sum_into(Amount::zero(cap.amount().currency()), &group, committed)
                    .is_some_and(|total| at_most(total, *cap))
            }),
            Query::HasGuardianConsent { proposal } => self.consents.contains(proposal),
            Query::IsVerifiedAdultAtDeadline { account, deadline } => {
                self.is_adult_at(*account, *deadline)
            }
            Query::DeclaresAffiliationOnList { team, list } => team
                .iter()
                .any(|m| self.affiliations.contains(&(*m, *list))),
            Query::MeetsTieBreakCountry { account, programme } => {
                self.country.contains(&(*account, *programme))
            }
            Query::ChangedSince { epoch } => !self.changed_since(*epoch).is_empty(),
        }
    }

    /// The full truthful answer to `q` at the current epoch.
    pub fn answer(&self, q: &Query) -> Answer {
        let accounts = match q {
            Query::ChangedSince { epoch } => Some(self.changed_since(*epoch)),
            _ => None,
        };
        Answer {
            holds: self.holds(q),
            accounts,
            epoch: self.epoch,
            digest: PLACEHOLDER_DIGEST,
        }
    }

    // -- the reaction view (overview NOTE 4) ----------------------------------

    /// The facts that the reaction to a provisional fact sees (overview
    /// NOTE 4, the exception). Every provisional verification and
    /// affiliation counts as effective, with the pending facts a
    /// verification reveals. The epoch and the change log stay those of
    /// `self`, so answers carry the epoch the reaction is decided at.
    ///
    /// Added by lane L-SOD in step W3b. It changes no fact of `self`.
    pub fn reaction_view(&self) -> GroundTruth {
        let mut view = self.clone();
        for account in self.provisional_accounts() {
            view.make_effective(account);
        }
        view.epoch = self.epoch;
        view.changes.clone_from(&self.changes);
        view
    }

    /// The accounts the reaction to a provisional fact learns as changed
    /// after `epoch`: those of [`GroundTruth::changed_since`], and every
    /// account that the pending facts of a provisional verification touch.
    ///
    /// This is the change query contract the reaction relies on: exclusions
    /// and relations are facts about identities, so the vault lists every
    /// account of the identities they touch, as [`GroundTruth::verify`]
    /// does. Without it, a sibling account excluded by the revealed facts
    /// would keep its Receiving binding until the fact took effect.
    pub fn reaction_changed_since(&self, epoch: VaultEpoch) -> BTreeSet<AccountId> {
        let mut out = self.changed_since(epoch);
        for account in &self.provisional_verified {
            for fact in self.pending.get(account).into_iter().flatten() {
                match fact {
                    PendingFact::Excluded { identity, .. } => {
                        out.extend(self.accounts_of(&[*identity]));
                    }
                    PendingFact::Related { a, b, .. } => out.extend(self.accounts_of(&[*a, *b])),
                }
            }
        }
        out
    }

    /// The answer to `q` that the reaction to a provisional fact gets: over
    /// [`GroundTruth::reaction_view`], at the current epoch. `ChangedSince`
    /// lists [`GroundTruth::reaction_changed_since`], since making a fact
    /// effective is a later change the reaction has not seen.
    pub fn answer_in_reaction(&self, q: &Query) -> Answer {
        match q {
            Query::ChangedSince { epoch } => {
                let accounts = self.reaction_changed_since(*epoch);
                Answer {
                    holds: !accounts.is_empty(),
                    accounts: Some(accounts),
                    epoch: self.epoch,
                    digest: PLACEHOLDER_DIGEST,
                }
            }
            _ => self.reaction_view().answer(q),
        }
    }

    // -- internals ------------------------------------------------------------

    /// The accounts whose identity is one of `tags`.
    fn accounts_of(&self, tags: &[IdentityTag]) -> BTreeSet<AccountId> {
        self.identity_of
            .iter()
            .filter(|(_, t)| tags.contains(t))
            .map(|(a, _)| *a)
            .collect()
    }

    /// The accounts of `pool` that count with `account` towards one cap,
    /// including `account` itself (NOTE 1).
    fn cap_group(
        &self,
        account: AccountId,
        pool: &BTreeMap<AccountId, NonNegAmount>,
    ) -> BTreeSet<AccountId> {
        let mut group: BTreeSet<AccountId> = [account].into_iter().collect();
        if let Some(t) = self.verified_identity(account) {
            group.extend(
                pool.keys()
                    .copied()
                    .filter(|b| self.verified_identity(*b) == Some(t)),
            );
        }
        group
    }

    /// Advances the epoch by one and logs the accounts `changed`.
    fn commit(&mut self, changed: BTreeSet<AccountId>) {
        self.epoch = VaultEpoch::from_raw(self.epoch.raw().saturating_add(1));
        self.changes.push((self.epoch, changed));
    }
}

/// `start` plus the committed amounts of `group`, or `None` when they
/// cannot be added.
fn sum_into(
    start: Amount,
    group: &BTreeSet<AccountId>,
    committed: &BTreeMap<AccountId, NonNegAmount>,
) -> Option<Amount> {
    let mut total = start;
    for a in group {
        if let Some(v) = committed.get(a) {
            total = total.checked_add(v.amount()).ok()?;
        }
    }
    Some(total)
}

/// Whether `total` is at most `cap`, in one currency.
fn at_most(total: Amount, cap: NonNegAmount) -> bool {
    total
        .cmp_same(cap.amount())
        .is_ok_and(|o| o != core::cmp::Ordering::Greater)
}

/// A vault that answers truthfully from its ground truth.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SyntheticVault {
    truth: GroundTruth,
}

impl SyntheticVault {
    /// The vault over `truth`.
    pub fn new(truth: GroundTruth) -> SyntheticVault {
        SyntheticVault { truth }
    }

    /// The facts.
    pub fn truth(&self) -> &GroundTruth {
        &self.truth
    }

    /// The facts, for a test that changes them.
    pub fn truth_mut(&mut self) -> &mut GroundTruth {
        &mut self.truth
    }

    /// The facts, giving up the vault.
    pub fn into_truth(self) -> GroundTruth {
        self.truth
    }
}

impl IdentityOracle for SyntheticVault {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        // State-machine NOTE 14: an unresolved age conflict gets no answer.
        self.truth.try_answer(q).ok_or(OracleDown)
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(self.truth.epoch())
    }
}

/// An oracle that answers a fixed script, whatever the facts.
///
/// A query outside the script fails closed with [`OracleDown`]. A scripted
/// `ChangedSince` lists the accounts given with [`HavocOracle::with_changed`],
/// or none.
///
/// It is `Hash`, and its script, epoch and changed set can be changed in
/// place, so a model state can hold the oracle and change it in one step.
/// Equality and hashing treat the script as a set of query and bit pairs.
/// So two oracles scripted with the same bits in another order are one
/// model state.
#[derive(Clone, Debug)]
pub struct HavocOracle {
    epoch: VaultEpoch,
    /// One entry per query, in the order the queries were first scripted.
    script: Vec<(Query, bool)>,
    changed: BTreeSet<AccountId>,
}

impl PartialEq for HavocOracle {
    fn eq(&self, other: &HavocOracle) -> bool {
        // The script holds one entry per query, so equal lengths and
        // inclusion one way give set equality.
        self.epoch == other.epoch
            && self.changed == other.changed
            && self.script.len() == other.script.len()
            && self
                .script
                .iter()
                .all(|(q, b)| other.scripted(q) == Some(*b))
    }
}

impl Eq for HavocOracle {}

impl core::hash::Hash for HavocOracle {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        use core::hash::Hasher as _;
        self.epoch.hash(state);
        self.changed.hash(state);
        // An order-independent sum of per-entry hashes, as for
        // `fstp_domain::oracle::Answers`.
        let mut sum: u64 = 0;
        for entry in &self.script {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            entry.hash(&mut h);
            sum = sum.wrapping_add(h.finish());
        }
        state.write_usize(self.script.len());
        state.write_u64(sum);
    }
}

impl HavocOracle {
    /// The oracle at `epoch` that answers each query of `script` with its
    /// bit. For a query listed twice, the first entry counts, and the
    /// later ones are dropped.
    pub fn new(epoch: VaultEpoch, script: Vec<(Query, bool)>) -> HavocOracle {
        let mut unique: Vec<(Query, bool)> = Vec::with_capacity(script.len());
        for (q, b) in script {
            if unique.iter().all(|(s, _)| *s != q) {
                unique.push((q, b));
            }
        }
        HavocOracle {
            epoch,
            script: unique,
            changed: BTreeSet::new(),
        }
    }

    /// The same oracle, listing `changed` in every scripted `ChangedSince` answer.
    pub fn with_changed(mut self, changed: BTreeSet<AccountId>) -> HavocOracle {
        self.changed = changed;
        self
    }

    /// The scripted bit for `q`, if any.
    pub fn scripted(&self, q: &Query) -> Option<bool> {
        self.script.iter().find(|(s, _)| s == q).map(|(_, b)| *b)
    }

    /// The script, one entry per query, in the order the queries were first
    /// scripted. Equality ignores this order.
    pub fn script(&self) -> &[(Query, bool)] {
        &self.script
    }

    /// The accounts every scripted `ChangedSince` answer lists.
    pub fn changed(&self) -> &BTreeSet<AccountId> {
        &self.changed
    }

    /// Scripts `bit` for `q`, replacing the entry that counts for `q`, or
    /// adding one. The epoch does not move. Call
    /// [`HavocOracle::advance_epoch`] as well when the change is a vault change.
    pub fn set(&mut self, q: Query, bit: bool) {
        match self.script.iter_mut().find(|(s, _)| *s == q) {
            Some(entry) => entry.1 = bit,
            None => self.script.push((q, bit)),
        }
    }

    /// Lists `changed` in every scripted `ChangedSince` answer from now on.
    pub fn set_changed(&mut self, changed: BTreeSet<AccountId>) {
        self.changed = changed;
    }

    /// Advances the epoch by one, saturating at the maximum.
    pub fn advance_epoch(&mut self) {
        self.epoch = VaultEpoch::from_raw(self.epoch.raw().saturating_add(1));
    }
}

impl IdentityOracle for HavocOracle {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        let holds = self.scripted(q).ok_or(OracleDown)?;
        let accounts = match q {
            Query::ChangedSince { .. } => Some(self.changed.clone()),
            _ => None,
        };
        Ok(Answer {
            holds,
            accounts,
            epoch: self.epoch,
            digest: PLACEHOLDER_DIGEST,
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(self.epoch)
    }
}

/// An oracle that never answers (NOTE 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DownOracle;

impl IdentityOracle for DownOracle {
    fn ask(&self, _: &Query) -> Result<Answer, OracleDown> {
        Err(OracleDown)
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Err(OracleDown)
    }
}

// ---------------------------------------------------------------------------
// Corpus-variant fixtures (synthetic-corpus.md)
// ---------------------------------------------------------------------------

/// The largest synthetic number a fixture draws for a new id. A fixture
/// steps past a drawn number that is taken, so it can return a larger one
/// when every number up to this one is taken.
pub const FIXTURE_ID_SPACE: u64 = 1_000_000;

impl GroundTruth {
    /// Every account any fact or change of the vault names: identities,
    /// verifications, pending, provisional and affiliation facts, country
    /// bits and the change log.
    fn mentioned_accounts(&self) -> BTreeSet<AccountId> {
        let mut all: BTreeSet<AccountId> = self.identity_of.keys().copied().collect();
        all.extend(self.verified.iter().copied());
        all.extend(self.pending.keys().copied());
        all.extend(self.affiliations.iter().map(|(a, _)| *a));
        all.extend(self.country.iter().map(|(a, _)| *a));
        all.extend(self.provisional_verified.iter().copied());
        all.extend(self.provisional_affiliations.iter().map(|(a, _)| *a));
        all.extend(self.changes.iter().flat_map(|(_, c)| c.iter().copied()));
        all
    }

    /// Every identity any fact of the vault names: identity tags,
    /// relations, exclusions and pending facts.
    fn mentioned_identities(&self) -> BTreeSet<IdentityTag> {
        let mut all: BTreeSet<IdentityTag> = self.identity_of.values().copied().collect();
        for (a, b, _) in &self.relations {
            all.insert(*a);
            all.insert(*b);
        }
        all.extend(self.excluded.iter().map(|(t, _)| *t));
        for fact in self.pending.values().flatten() {
            match fact {
                PendingFact::Excluded { identity, .. } => {
                    all.insert(*identity);
                }
                PendingFact::Related { a, b, .. } => {
                    all.insert(*a);
                    all.insert(*b);
                }
            }
        }
        all
    }
}

/// The first number, from a draw in `1..=FIXTURE_ID_SPACE` upwards, for
/// which `taken` is false. It skips 0.
fn fresh_number(g: &mut Gen, mut taken: impl FnMut(u64) -> bool) -> u64 {
    let mut n = g.u64_in(1..=FIXTURE_ID_SPACE);
    while taken(n) {
        n = n.wrapping_add(1).max(1);
    }
    n
}

/// A synthetic account id that no fact or change of `truth` names and
/// `avoid` does not hold.
fn fresh_account(g: &mut Gen, truth: &GroundTruth, avoid: &[AccountId]) -> AccountId {
    let known = truth.mentioned_accounts();
    let n = fresh_number(g, |n| {
        let a = AccountId::from_raw(u128::from(n));
        known.contains(&a) || avoid.contains(&a)
    });
    AccountId::from_raw(u128::from(n))
}

/// A synthetic identity that no fact of `truth` names.
fn fresh_identity(g: &mut Gen, truth: &GroundTruth) -> IdentityTag {
    let known = truth.mentioned_identities();
    IdentityTag::new(fresh_number(g, |n| known.contains(&IdentityTag::new(n))))
}

/// A synthetic proposal id without a consent in `truth`, not in `avoid`.
fn fresh_proposal(g: &mut Gen, truth: &GroundTruth, avoid: &[ProposalId]) -> ProposalId {
    let n = fresh_number(g, |n| {
        let p = ProposalId::from_raw(u128::from(n));
        truth.consents.contains(&p) || avoid.contains(&p)
    });
    ProposalId::from_raw(u128::from(n))
}

/// Corpus variant "Sybil": two verified accounts of one identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SybilFixture {
    /// The account that applies.
    pub applicant: AccountId,
    /// The account that reviews.
    pub reviewer: AccountId,
    /// The identity both accounts share.
    pub identity: IdentityTag,
}

/// Builds the "Sybil" variant in `truth`: blocked by SoD-09 and I-06.
pub fn sybil_pair(g: &mut Gen, truth: &mut GroundTruth) -> SybilFixture {
    let identity = fresh_identity(g, truth);
    let applicant = fresh_account(g, truth, &[]);
    let reviewer = fresh_account(g, truth, &[applicant]);
    truth.set_identity(applicant, identity);
    truth.set_identity(reviewer, identity);
    truth.verify(applicant);
    truth.verify(reviewer);
    SybilFixture {
        applicant,
        reviewer,
        identity,
    }
}

/// Corpus variant "Excluded affiliation": an applicant in an excluded class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExcludedFixture {
    /// The applicant's account.
    pub account: AccountId,
    /// The applicant's identity.
    pub identity: IdentityTag,
    /// The excluded class.
    pub class: ClassId,
    /// Whether the vault reveals the class only when the account is verified,
    /// as at negotiation. Otherwise it is known at once, as at binding.
    pub revealed_on_verification: bool,
}

/// Builds the "Excluded affiliation" variant in `truth` (I-04, SoD-06).
pub fn excluded_applicant(g: &mut Gen, truth: &mut GroundTruth) -> ExcludedFixture {
    let identity = fresh_identity(g, truth);
    let account = fresh_account(g, truth, &[]);
    let class = ClassId::from_raw(u128::from(g.u8_in(1..=8)));
    let revealed_on_verification = g.bool();
    truth.set_identity(account, identity);
    if revealed_on_verification {
        truth.add_pending(account, PendingFact::Excluded { identity, class });
    } else {
        truth.exclude(identity, class);
        if g.bool() {
            truth.verify(account);
        }
    }
    ExcludedFixture {
        account,
        identity,
        class,
        revealed_on_verification,
    }
}

/// Corpus variant "Repeat applicant": a new lead who is the lead of a prior grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RepeatFixture {
    /// The lead of the prior grant.
    pub prior_lead: AccountId,
    /// The lead of the new proposal, another account of the same person.
    pub new_lead: AccountId,
    /// The identity both leads share.
    pub identity: IdentityTag,
    /// The prior grant.
    pub prior_proposal: ProposalId,
    /// The new proposal.
    pub new_proposal: ProposalId,
    /// The state of the prior grant's deliverables (I-15).
    pub prior_deliverables: PriorDeliverables,
}

/// The state of a prior grant's deliverables, in the five states of the
/// I-15 test plan (design section 6.2). Under the answer to Q8 the check
/// covers the deliverables accepted so far, against the prior call's P-26.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PriorDeliverables {
    /// No deliverable has been accepted yet.
    None,
    /// Every accepted deliverable is public under a licence in the prior
    /// call's P-26.
    PublicUnderP26,
    /// An accepted deliverable is public, but under a licence outside the
    /// prior call's P-26.
    PublicUnderOtherLicence,
    /// A deliverable was recorded but not accepted.
    NotAccepted,
    /// An accepted deliverable has no public snapshot recorded.
    SnapshotMissing,
}

impl PriorDeliverables {
    /// The five states, in order.
    pub const ALL: [PriorDeliverables; 5] = [
        PriorDeliverables::None,
        PriorDeliverables::PublicUnderP26,
        PriorDeliverables::PublicUnderOtherLicence,
        PriorDeliverables::NotAccepted,
        PriorDeliverables::SnapshotMissing,
    ];
}

/// Builds the "Repeat applicant" variant in `truth` (I-15).
///
/// The prior grant's records are platform facts, not vault facts. Lane
/// L-MONEY builds them through a scenario from `prior_proposal` and
/// `prior_deliverables`. The fixture only picks the state. Whether that
/// state clears I-15 is the reference rule's to say, not the fixture's.
pub fn repeat_applicant(g: &mut Gen, truth: &mut GroundTruth) -> RepeatFixture {
    let identity = fresh_identity(g, truth);
    let prior_lead = fresh_account(g, truth, &[]);
    let new_lead = fresh_account(g, truth, &[prior_lead]);
    truth.set_identity(prior_lead, identity);
    truth.verify(prior_lead);
    truth.set_identity(new_lead, identity);
    truth.verify(new_lead);
    let prior_proposal = fresh_proposal(g, truth, &[]);
    let new_proposal = fresh_proposal(g, truth, &[prior_proposal]);
    RepeatFixture {
        prior_lead,
        new_lead,
        identity,
        prior_proposal,
        new_proposal,
        prior_deliverables: *g.pick(&PriorDeliverables::ALL),
    }
}

/// Corpus variant "Minor applicant": a minor lead with a guardian.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorFixture {
    /// The minor lead.
    pub lead: AccountId,
    /// The guardian, another account and another person.
    pub guardian: AccountId,
    /// The proposal, which carries the minor flag.
    pub proposal: ProposalId,
    /// Whether the vault holds a verified guardian consent for the proposal.
    pub consent: bool,
}

/// Builds the "Minor applicant" variant in `truth` (I-18, R-NG-02).
pub fn minor_applicant(g: &mut Gen, truth: &mut GroundTruth) -> MinorFixture {
    let lead = fresh_account(g, truth, &[]);
    let guardian = fresh_account(g, truth, &[lead]);
    let lead_identity = fresh_identity(g, truth);
    truth.set_identity(lead, lead_identity);
    let guardian_identity = fresh_identity(g, truth);
    truth.set_identity(guardian, guardian_identity);
    truth.verify(guardian);
    let proposal = fresh_proposal(g, truth, &[]);
    let consent = g.bool();
    if consent {
        truth.consent(proposal);
    }
    MinorFixture {
        lead,
        guardian,
        proposal,
        consent,
    }
}
