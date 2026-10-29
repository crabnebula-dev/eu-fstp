//! The typed queries of the vault (design section 6.2, `overview.md`
//! query table).
//!
//! [`Query`] mirrors the eleven `fstp_domain::oracle::Query` kinds. The
//! kind code of a [`WireQuery`] is the index of its kind in
//! `fstp_domain::oracle::QueryKind::ALL`, as lane W1c proposed. The
//! arguments are canonical JSON with W1c's member names. `fstp-cell`
//! converts between the domain queries and these, so neither pure core
//! depends on the other.

use std::collections::{BTreeMap, BTreeSet};

use fstp_json::Value;
use fstp_money::Amount;

use crate::json::{self, limits, parse_canonical};
use crate::{ProtoError, WireAccount, WireClass, WireList, WireProgramme, WireProposal, WireQuery};

/// The kind of a query. The discriminant is its wire code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QueryKind {
    /// `IsVerified`.
    IsVerified = 0,
    /// `SameIdentityAsAny`.
    SameIdentityAsAny = 1,
    /// `HasConflict`.
    HasConflict = 2,
    /// `InExcludedClass`.
    InExcludedClass = 3,
    /// `WithinRecipientCap`.
    WithinRecipientCap = 4,
    /// `AllRecipientsWithinCap`.
    AllRecipientsWithinCap = 5,
    /// `HasGuardianConsent`.
    HasGuardianConsent = 6,
    /// `IsVerifiedAdultAtDeadline` (NOTE 7, Q13 A).
    IsVerifiedAdultAtDeadline = 7,
    /// `DeclaresAffiliationOnList`.
    DeclaresAffiliationOnList = 8,
    /// `MeetsTieBreakCountry`.
    MeetsTieBreakCountry = 9,
    /// `ChangedSince`.
    ChangedSince = 10,
}

impl QueryKind {
    /// Every kind, in code order.
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

    /// The wire code.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// The kind of wire code `code`, if any.
    pub fn from_code(code: u16) -> Option<QueryKind> {
        QueryKind::ALL.get(usize::from(code)).copied()
    }
}

/// One query, typed.
///
/// Every query answers one bit, except [`Query::ChangedSince`], which also
/// lists account ids (NOTE 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// The account has an effective verification.
    IsVerified {
        /// The account.
        account: WireAccount,
    },
    /// The subject's verified identity is that of an account in the set.
    SameIdentityAsAny {
        /// The subject.
        subject: WireAccount,
        /// The other accounts.
        others: BTreeSet<WireAccount>,
    },
    /// A relationship, declaration or shared identity links the reviewer
    /// with a team member (I-03, I-54).
    HasConflict {
        /// The reviewer.
        reviewer: WireAccount,
        /// The team.
        team: BTreeSet<WireAccount>,
    },
    /// An effective affiliation of the account's identity carries a class
    /// in the set (I-04).
    InExcludedClass {
        /// The account.
        account: WireAccount,
        /// The programme.
        programme: WireProgramme,
        /// The excluded classes.
        classes: BTreeSet<WireClass>,
    },
    /// The subject's identity group stays within the cap with `amount`
    /// added (I-14, NOTE 1).
    WithinRecipientCap {
        /// The subject.
        subject: WireAccount,
        /// The amount to add.
        amount: Amount,
        /// The committed amounts per account.
        committed: BTreeMap<WireAccount, Amount>,
        /// The cap.
        cap: Amount,
    },
    /// Every identity group stays within the cap (I-14).
    AllRecipientsWithinCap {
        /// The committed amounts per account.
        committed: BTreeMap<WireAccount, Amount>,
        /// The cap.
        cap: Amount,
    },
    /// An effective consent exists whose guardian verification is
    /// effective (I-18).
    HasGuardianConsent {
        /// The proposal.
        proposal: WireProposal,
    },
    /// A verified attestation shows the account 18 or older at the
    /// deadline (NOTE 7).
    IsVerifiedAdultAtDeadline {
        /// The account, the proposal's lead.
        account: WireAccount,
        /// The deadline, in UTC microseconds.
        deadline: i64,
    },
    /// A team identity's declared affiliation is on the list (I-35, P-38).
    DeclaresAffiliationOnList {
        /// The team.
        team: BTreeSet<WireAccount>,
        /// The proximity list.
        list: WireList,
    },
    /// The stated country meets the programme's P-17 condition (NOTE 6).
    MeetsTieBreakCountry {
        /// The account, the proposal's lead.
        account: WireAccount,
        /// The programme.
        programme: WireProgramme,
    },
    /// The accounts touched by facts after the epoch (NOTE 3).
    ChangedSince {
        /// The epoch.
        epoch: u64,
    },
}

const ARGS: &str = "query arguments";

impl Query {
    /// The kind.
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

    /// The canonical JSON value of the arguments.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Shape`] when a value has no canonical spelling: a
    /// negative amount, or an integer beyond 2^53 - 1.
    pub fn args_value(&self) -> Result<Value, ProtoError> {
        use json::{amount_json, amount_map_json, id_json, id_list_json, int_json, obj, uint_json};
        let accounts = |s: &BTreeSet<WireAccount>| id_list_json(s.iter().map(|a| a.0));
        let committed = |m: &BTreeMap<WireAccount, Amount>| {
            amount_map_json(m.iter().map(|(k, v)| (k.0, *v)), ARGS)
        };
        match self {
            Query::IsVerified { account } => obj(vec![("account", id_json(account.0))]),
            Query::SameIdentityAsAny { subject, others } => obj(vec![
                ("others", accounts(others)),
                ("subject", id_json(subject.0)),
            ]),
            Query::HasConflict { reviewer, team } => obj(vec![
                ("reviewer", id_json(reviewer.0)),
                ("team", accounts(team)),
            ]),
            Query::InExcludedClass {
                account,
                programme,
                classes,
            } => obj(vec![
                ("account", id_json(account.0)),
                ("classes", id_list_json(classes.iter().map(|c| c.0))),
                ("programme", id_json(programme.0)),
            ]),
            Query::WithinRecipientCap {
                subject,
                amount,
                committed: c,
                cap,
            } => obj(vec![
                ("amount", amount_json(*amount, ARGS)?),
                ("cap", amount_json(*cap, ARGS)?),
                ("committed", committed(c)?),
                ("subject", id_json(subject.0)),
            ]),
            Query::AllRecipientsWithinCap { committed: c, cap } => obj(vec![
                ("cap", amount_json(*cap, ARGS)?),
                ("committed", committed(c)?),
            ]),
            Query::HasGuardianConsent { proposal } => obj(vec![("proposal", id_json(proposal.0))]),
            Query::IsVerifiedAdultAtDeadline { account, deadline } => obj(vec![
                ("account", id_json(account.0)),
                ("deadline", int_json(*deadline, ARGS)?),
            ]),
            Query::DeclaresAffiliationOnList { team, list } => {
                obj(vec![("list", id_json(list.0)), ("team", accounts(team))])
            }
            Query::MeetsTieBreakCountry { account, programme } => obj(vec![
                ("account", id_json(account.0)),
                ("programme", id_json(programme.0)),
            ]),
            Query::ChangedSince { epoch } => obj(vec![("epoch", uint_json(*epoch, ARGS)?)]),
        }
    }

    /// The wire query.
    ///
    /// # Errors
    ///
    /// As [`Query::args_value`].
    pub fn to_wire(&self) -> Result<WireQuery, ProtoError> {
        Ok(WireQuery {
            kind: self.kind().code(),
            args: json::to_canonical(&self.args_value()?)?,
        })
    }
}

/// Decodes the arguments value `v` of a query of kind `kind`.
///
/// # Errors
///
/// [`ProtoError::Shape`] when the members are not those of `kind`.
pub fn query_from_value(kind: QueryKind, v: &Value) -> Result<Query, ProtoError> {
    use json::{amount, amount_map, id, id_set, int, object, uint};
    let account = WireAccount;
    Ok(match kind {
        QueryKind::IsVerified => {
            let o = object(v, &["account"], ARGS)?;
            Query::IsVerified {
                account: account(id(o, "account", ARGS)?),
            }
        }
        QueryKind::SameIdentityAsAny => {
            let o = object(v, &["others", "subject"], ARGS)?;
            Query::SameIdentityAsAny {
                subject: account(id(o, "subject", ARGS)?),
                others: id_set(o, "others", ARGS, WireAccount)?,
            }
        }
        QueryKind::HasConflict => {
            let o = object(v, &["reviewer", "team"], ARGS)?;
            Query::HasConflict {
                reviewer: account(id(o, "reviewer", ARGS)?),
                team: id_set(o, "team", ARGS, WireAccount)?,
            }
        }
        QueryKind::InExcludedClass => {
            let o = object(v, &["account", "classes", "programme"], ARGS)?;
            Query::InExcludedClass {
                account: account(id(o, "account", ARGS)?),
                programme: WireProgramme(id(o, "programme", ARGS)?),
                classes: id_set(o, "classes", ARGS, WireClass)?,
            }
        }
        QueryKind::WithinRecipientCap => {
            let o = object(v, &["amount", "cap", "committed", "subject"], ARGS)?;
            Query::WithinRecipientCap {
                subject: account(id(o, "subject", ARGS)?),
                amount: amount(o, "amount", ARGS)?,
                committed: amount_map(o, "committed", ARGS, WireAccount)?,
                cap: amount(o, "cap", ARGS)?,
            }
        }
        QueryKind::AllRecipientsWithinCap => {
            let o = object(v, &["cap", "committed"], ARGS)?;
            Query::AllRecipientsWithinCap {
                committed: amount_map(o, "committed", ARGS, WireAccount)?,
                cap: amount(o, "cap", ARGS)?,
            }
        }
        QueryKind::HasGuardianConsent => {
            let o = object(v, &["proposal"], ARGS)?;
            Query::HasGuardianConsent {
                proposal: WireProposal(id(o, "proposal", ARGS)?),
            }
        }
        QueryKind::IsVerifiedAdultAtDeadline => {
            let o = object(v, &["account", "deadline"], ARGS)?;
            Query::IsVerifiedAdultAtDeadline {
                account: account(id(o, "account", ARGS)?),
                deadline: int(o, "deadline", ARGS)?,
            }
        }
        QueryKind::DeclaresAffiliationOnList => {
            let o = object(v, &["list", "team"], ARGS)?;
            Query::DeclaresAffiliationOnList {
                team: id_set(o, "team", ARGS, WireAccount)?,
                list: WireList(id(o, "list", ARGS)?),
            }
        }
        QueryKind::MeetsTieBreakCountry => {
            let o = object(v, &["account", "programme"], ARGS)?;
            Query::MeetsTieBreakCountry {
                account: account(id(o, "account", ARGS)?),
                programme: WireProgramme(id(o, "programme", ARGS)?),
            }
        }
        QueryKind::ChangedSince => {
            let o = object(v, &["epoch"], ARGS)?;
            Query::ChangedSince {
                epoch: uint(o, "epoch", ARGS)?,
            }
        }
    })
}

/// Decodes a wire query: a known kind and that kind's canonical
/// arguments.
///
/// # Errors
///
/// [`ProtoError::Shape`] for an unknown kind or arguments of another
/// kind, [`ProtoError::Json`] or [`ProtoError::NotCanonical`] for
/// arguments that are not the one canonical spelling.
pub fn decode_query(q: &WireQuery) -> Result<Query, ProtoError> {
    let kind = QueryKind::from_code(q.kind).ok_or(ProtoError::Shape("query kind"))?;
    let v = parse_canonical(&q.args, &limits())?;
    query_from_value(kind, &v)
}
