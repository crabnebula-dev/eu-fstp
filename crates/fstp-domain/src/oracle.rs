//! Identity vault queries and answers (design section 4.1).
//!
//! The vault answers the platform only through the queries in
//! `SPEC/03-architecture/overview.md`. Every answer is one bit, except the
//! change query, which lists changed accounts and no attributes.
//!
//! - The platform builds each candidate set from its own bindings (NOTE 1).
//! - When the vault cannot answer, the command is refused and nothing is
//!   recorded (NOTE 2).
//! - Answers carry a vault epoch, and `decide` accepts only answers at the
//!   epoch the state has processed (NOTE 3).

use std::collections::{BTreeMap, BTreeSet};

use fstp_money::NonNegAmount;

use crate::id::{AccountId, ContentDigest, ProgrammeId, ProposalId, ProximityListId, VaultEpoch};
use crate::policy::ExclusionClasses;
use crate::time::Timestamp;

/// One vault query. Amounts have no order (ADR-006), so queries have none either.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Query {
    /// Is this account verified? (SoD-09, I-06)
    IsVerified {
        /// The account.
        account: AccountId,
    },
    /// Does this account share a verified identity with any account in a given set? (SoD-09, I-06, I-15)
    SameIdentityAsAny {
        /// The account asked about.
        subject: AccountId,
        /// The candidate set, built from the platform's own bindings.
        others: BTreeSet<AccountId>,
    },
    /// Does this reviewer have a conflict with this proposal's applicant team? (I-03, I-54)
    HasConflict {
        /// The reviewer, coordinator or committee member.
        reviewer: AccountId,
        /// The lead and team accounts.
        team: BTreeSet<AccountId>,
    },
    /// Is this account in an excluded affiliation class of this programme? (I-04)
    InExcludedClass {
        /// The account.
        account: AccountId,
        /// The programme.
        programme: ProgrammeId,
        /// The classes enforced: every class of the live value and the call snapshot (P-13 NOTE 7).
        classes: ExclusionClasses,
    },
    /// Would this amount keep the recipient within the cap? (I-14)
    WithinRecipientCap {
        /// The applicant lead.
        subject: AccountId,
        /// The amount to add.
        amount: NonNegAmount,
        /// Granted plus reserved per account in the programme. The vault groups them by identity.
        committed: BTreeMap<AccountId, NonNegAmount>,
        /// The cap enforced: the lower of the live P-05 and the call snapshot.
        cap: NonNegAmount,
    },
    /// Do all recipients of the programme stay within the cap? (I-14, on P-05 edits)
    AllRecipientsWithinCap {
        /// Granted plus reserved per account in the programme.
        committed: BTreeMap<AccountId, NonNegAmount>,
        /// The proposed cap.
        cap: NonNegAmount,
    },
    /// Does this proposal have a verified guardian consent record? (I-18)
    HasGuardianConsent {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Does this proposal's lead have an effective verified over-18 attestation at the call deadline? (I-18, R-ID-04)
    ///
    /// The answer is yes only for an effective attestation that shows the
    /// lead 18 or older at `deadline` (overview NOTE 7). It releases no age
    /// and no date of birth. While a verification shows the lead under 18
    /// at `deadline` against such an attestation, the vault gives no answer
    /// until a manual identity check resolves the conflict, so every guard
    /// that asks fails closed (state-machine NOTE 14, decided 2026-10-29).
    IsVerifiedAdultAtDeadline {
        /// The proposal's lead.
        account: AccountId,
        /// The deadline of the call in which the proposal passes IRC review, the later call after a re-entry (ADR-008, "Which deadline", decided 2026-10-29).
        deadline: Timestamp,
    },
    /// Does any team member declare an affiliation on this proximity list? (I-35)
    DeclaresAffiliationOnList {
        /// The lead and team accounts.
        team: BTreeSet<AccountId>,
        /// The proximity list of the reviewer's organisation (P-38).
        list: ProximityListId,
    },
    /// Does this applicant meet the P-17 country condition of this programme? (R-EV-08, P-17)
    MeetsTieBreakCountry {
        /// The applicant lead.
        account: AccountId,
        /// The programme.
        programme: ProgrammeId,
    },
    /// Which accounts have vault facts that changed since a given vault epoch? (enforcement point 3)
    ChangedSince {
        /// The epoch the state has processed.
        epoch: VaultEpoch,
    },
}

/// The fieldless tag of a [`Query`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QueryKind {
    /// [`Query::IsVerified`].
    IsVerified,
    /// [`Query::SameIdentityAsAny`].
    SameIdentityAsAny,
    /// [`Query::HasConflict`].
    HasConflict,
    /// [`Query::InExcludedClass`].
    InExcludedClass,
    /// [`Query::WithinRecipientCap`].
    WithinRecipientCap,
    /// [`Query::AllRecipientsWithinCap`].
    AllRecipientsWithinCap,
    /// [`Query::HasGuardianConsent`].
    HasGuardianConsent,
    /// [`Query::IsVerifiedAdultAtDeadline`].
    IsVerifiedAdultAtDeadline,
    /// [`Query::DeclaresAffiliationOnList`].
    DeclaresAffiliationOnList,
    /// [`Query::MeetsTieBreakCountry`].
    MeetsTieBreakCountry,
    /// [`Query::ChangedSince`].
    ChangedSince,
}

impl QueryKind {
    /// Every kind, in the order of the query table in `SPEC/03-architecture/overview.md`.
    pub const ALL: [QueryKind; 11] = [
        QueryKind::IsVerified,
        QueryKind::SameIdentityAsAny,
        QueryKind::HasConflict,
        QueryKind::InExcludedClass,
        QueryKind::WithinRecipientCap,
        QueryKind::AllRecipientsWithinCap,
        QueryKind::HasGuardianConsent,
        QueryKind::IsVerifiedAdultAtDeadline,
        QueryKind::DeclaresAffiliationOnList,
        QueryKind::MeetsTieBreakCountry,
        QueryKind::ChangedSince,
    ];

    /// The question as the query table spells it.
    pub const fn spec_question(self) -> &'static str {
        match self {
            QueryKind::IsVerified => "Is this account verified?",
            QueryKind::SameIdentityAsAny => {
                "Does this account share a verified identity with any account in a given set?"
            }
            QueryKind::HasConflict => {
                "Does this reviewer have a conflict with this proposal's applicant team?"
            }
            QueryKind::InExcludedClass => {
                "Is this account in an excluded affiliation class of this programme?"
            }
            QueryKind::WithinRecipientCap => "Would this amount keep the recipient within the cap?",
            QueryKind::AllRecipientsWithinCap => {
                "Do all recipients of the programme stay within the cap?"
            }
            QueryKind::HasGuardianConsent => {
                "Does this proposal have a verified guardian consent record?"
            }
            QueryKind::IsVerifiedAdultAtDeadline => {
                "Does this proposal's lead have an effective verified over-18 attestation at the call deadline?"
            }
            QueryKind::DeclaresAffiliationOnList => {
                "Does any team member declare an affiliation on this proximity list?"
            }
            QueryKind::MeetsTieBreakCountry => {
                "Does this applicant meet the P-17 country condition of this programme?"
            }
            QueryKind::ChangedSince => {
                "Which accounts have vault facts that changed since a given vault epoch?"
            }
        }
    }
}

impl Query {
    /// The tag of this query.
    pub const fn kind(&self) -> QueryKind {
        match self {
            Query::IsVerified { .. } => QueryKind::IsVerified,
            Query::SameIdentityAsAny { .. } => QueryKind::SameIdentityAsAny,
            Query::HasConflict { .. } => QueryKind::HasConflict,
            Query::InExcludedClass { .. } => QueryKind::InExcludedClass,
            Query::WithinRecipientCap { .. } => QueryKind::WithinRecipientCap,
            Query::AllRecipientsWithinCap { .. } => QueryKind::AllRecipientsWithinCap,
            Query::HasGuardianConsent { .. } => QueryKind::HasGuardianConsent,
            Query::IsVerifiedAdultAtDeadline { .. } => QueryKind::IsVerifiedAdultAtDeadline,
            Query::DeclaresAffiliationOnList { .. } => QueryKind::DeclaresAffiliationOnList,
            Query::MeetsTieBreakCountry { .. } => QueryKind::MeetsTieBreakCountry,
            Query::ChangedSince { .. } => QueryKind::ChangedSince,
        }
    }
}

/// One vault answer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Answer {
    /// The answer bit.
    pub holds: bool,
    /// The changed accounts. Set only for [`Query::ChangedSince`].
    pub accounts: Option<BTreeSet<AccountId>>,
    /// The vault epoch the answer was given at.
    pub epoch: VaultEpoch,
    /// The digest of the query's canonical encoding. The driver computes it,
    /// because the domain cannot hash. `decide` copies it unchanged into
    /// `Record::VaultOutcome`, so the ledger never holds the query (overview NOTE 5).
    pub digest: ContentDigest,
}

/// The answers to a command's queries.
/// A list keyed by equality, because queries hold amounts, which have no order.
/// Equality and hashing ignore the order the answers were added in, so two
/// drivers that asked in different orders hold equal `Answers`.
#[derive(Clone, Debug)]
pub struct Answers {
    entries: Vec<(Query, Answer)>,
}

impl Answers {
    /// No answers.
    pub const fn new() -> Answers {
        Answers {
            entries: Vec::new(),
        }
    }

    /// Records `answer` for `query`, replacing an earlier answer to an equal query.
    pub fn insert(&mut self, query: Query, answer: Answer) {
        match self.entries.iter_mut().find(|(q, _)| *q == query) {
            Some(slot) => slot.1 = answer,
            None => self.entries.push((query, answer)),
        }
    }

    /// The answer to `query`, if any.
    pub fn get(&self, query: &Query) -> Option<&Answer> {
        self.entries
            .iter()
            .find(|(q, _)| q == query)
            .map(|(_, a)| a)
    }

    /// The number of answers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no answers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The answers in the order they were added. Equality ignores this order.
    pub fn iter(&self) -> impl Iterator<Item = (&Query, &Answer)> {
        self.entries.iter().map(|(q, a)| (q, a))
    }
}

impl PartialEq for Answers {
    fn eq(&self, other: &Answers) -> bool {
        // `insert` keeps one entry per query, so equal lengths and inclusion
        // one way give set equality.
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .all(|(q, a)| other.get(q).is_some_and(|b| b == a))
    }
}

impl Eq for Answers {}

impl core::hash::Hash for Answers {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        use core::hash::Hasher as _;
        // An order-independent combination of per-entry hashes, so that
        // equal sets hash equally whatever their insertion order.
        let mut sum: u64 = 0;
        for entry in &self.entries {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            core::hash::Hash::hash(entry, &mut h);
            sum = sum.wrapping_add(h.finish());
        }
        state.write_usize(self.entries.len());
        state.write_u64(sum);
    }
}

impl Default for Answers {
    fn default() -> Answers {
        Answers::new()
    }
}

/// The vault could not answer. The command fails closed (NOTE 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OracleDown;

impl core::fmt::Display for OracleDown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("identity vault unavailable")
    }
}

impl std::error::Error for OracleDown {}
