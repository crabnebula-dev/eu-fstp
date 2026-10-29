//! The reference encoding of the vault wire, written by the W2d test
//! author from design section 6.2 and the W1c proposal in
//! `fstp_celltest::reference::vault::wire`.
//!
//! The vault test suites and fuzz targets include this file with
//! `#[path]`, so one spelling serves every crate of the lane. It needs
//! only `std` and `fstp_vault_proto`.
//!
//! Every message is canonical JSON (RFC 8785). Members are in key order,
//! with no white space and no escapes, since every key and label is ASCII
//! without quotes or backslashes. Then:
//!
//! - Ids (`u128`) are decimal strings with no leading zero. Sets of ids
//!   are arrays in strictly ascending numeric order.
//! - Epochs, sequences, instants and country codes are JSON integers
//!   within plus or minus 2^53 - 1, the range RFC 8785 writes exactly. A
//!   larger value has no canonical spelling and is refused. An instant is
//!   in microseconds and may be negative.
//! - A chain link is 64 lowercase hex digits.
//! - Amounts are `{"amount":"<ADR-006 string>","currency":"EUR"}`.
//! - Each message names its variant in `type`. A query is
//!   `{"args":<canonical args>,"kind":<index in QueryKind::ALL>}`, with the
//!   W1c arguments.
//!
//! Reading: a map from accounts to amounts (`committed`) is a JSON object,
//! so RFC 8785 orders its members by key text, not by account number.
//! `"10"` comes before `"9"`. W1c's `wire::query` writes them in account
//! order, which differs when two ids have different lengths. This suite
//! follows RFC 8785, and the lane report names the W1c difference.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    reason = "a shared test module: each test binary uses part of it"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fstp_vault_proto::{
    RelationshipKind, VaultRefusal, VaultRequest, VaultResponse, WireAccount, WireAnswer, WireQuery,
};

/// The query kind codes: the index of each kind in
/// `fstp_domain::oracle::QueryKind::ALL` (W1c proposal).
pub mod kind {
    /// `IsVerified`.
    pub const IS_VERIFIED: u16 = 0;
    /// `SameIdentityAsAny`.
    pub const SAME_IDENTITY_AS_ANY: u16 = 1;
    /// `HasConflict`.
    pub const HAS_CONFLICT: u16 = 2;
    /// `InExcludedClass`.
    pub const IN_EXCLUDED_CLASS: u16 = 3;
    /// `WithinRecipientCap`.
    pub const WITHIN_RECIPIENT_CAP: u16 = 4;
    /// `AllRecipientsWithinCap`.
    pub const ALL_RECIPIENTS_WITHIN_CAP: u16 = 5;
    /// `HasGuardianConsent`.
    pub const HAS_GUARDIAN_CONSENT: u16 = 6;
    /// `IsVerifiedAdultAtDeadline`.
    pub const IS_VERIFIED_ADULT_AT_DEADLINE: u16 = 7;
    /// `DeclaresAffiliationOnList`.
    pub const DECLARES_AFFILIATION_ON_LIST: u16 = 8;
    /// `MeetsTieBreakCountry`.
    pub const MEETS_TIE_BREAK_COUNTRY: u16 = 9;
    /// `ChangedSince`.
    pub const CHANGED_SINCE: u16 = 10;
    /// The number of kinds.
    pub const COUNT: u16 = 11;
}

/// A decimal id string, quoted.
pub fn id(v: u128) -> String {
    format!("\"{v}\"")
}

/// A set of ids as a JSON array in ascending order.
pub fn id_set(set: &BTreeSet<u128>) -> String {
    let mut s = String::from("[");
    for (i, v) in set.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&id(*v));
    }
    s.push(']');
    s
}

/// The ADR-006 EUR spelling of `minor` cents, which must not be negative.
pub fn decimal(minor: i64) -> String {
    let u = minor.unsigned_abs();
    format!("{}.{:02}", u / 100, u % 100)
}

/// The canonical JSON of an EUR amount of `minor` cents.
pub fn amount(minor: i64) -> String {
    format!("{{\"amount\":\"{}\",\"currency\":\"EUR\"}}", decimal(minor))
}

/// The canonical JSON of a map from accounts to EUR amounts. Members are
/// in RFC 8785 key order, the byte order of the decimal text.
pub fn committed(map: &BTreeMap<u128, i64>) -> String {
    let mut entries: Vec<(String, i64)> = map.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut s = String::from("{");
    for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"{k}\":{}", amount(*v));
    }
    s.push('}');
    s
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// One query, as the cell builds it from `fstp_domain::oracle::Query`.
/// Ids are raw `u128` values and amounts are EUR cents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RQuery {
    /// `IsVerified`.
    IsVerified {
        /// The account.
        account: u128,
    },
    /// `SameIdentityAsAny`.
    SameIdentityAsAny {
        /// The subject.
        subject: u128,
        /// The candidates.
        others: BTreeSet<u128>,
    },
    /// `HasConflict`.
    HasConflict {
        /// The reviewer.
        reviewer: u128,
        /// The team.
        team: BTreeSet<u128>,
    },
    /// `InExcludedClass`.
    InExcludedClass {
        /// The account.
        account: u128,
        /// The programme.
        programme: u128,
        /// The classes.
        classes: BTreeSet<u128>,
    },
    /// `WithinRecipientCap`.
    WithinRecipientCap {
        /// The subject.
        subject: u128,
        /// The amount to add, in cents.
        amount: i64,
        /// Committed amounts per account, in cents.
        committed: BTreeMap<u128, i64>,
        /// The cap, in cents.
        cap: i64,
    },
    /// `AllRecipientsWithinCap`.
    AllRecipientsWithinCap {
        /// Committed amounts per account, in cents.
        committed: BTreeMap<u128, i64>,
        /// The cap, in cents.
        cap: i64,
    },
    /// `HasGuardianConsent`.
    HasGuardianConsent {
        /// The proposal.
        proposal: u128,
    },
    /// `IsVerifiedAdultAtDeadline`.
    IsVerifiedAdultAtDeadline {
        /// The lead.
        account: u128,
        /// The deadline, in microseconds.
        deadline: i64,
    },
    /// `DeclaresAffiliationOnList`.
    DeclaresAffiliationOnList {
        /// The team.
        team: BTreeSet<u128>,
        /// The list.
        list: u128,
    },
    /// `MeetsTieBreakCountry`.
    MeetsTieBreakCountry {
        /// The lead.
        account: u128,
        /// The programme.
        programme: u128,
    },
    /// `ChangedSince`.
    ChangedSince {
        /// The epoch.
        epoch: u64,
    },
}

impl RQuery {
    /// The kind code.
    pub fn kind(&self) -> u16 {
        match self {
            RQuery::IsVerified { .. } => kind::IS_VERIFIED,
            RQuery::SameIdentityAsAny { .. } => kind::SAME_IDENTITY_AS_ANY,
            RQuery::HasConflict { .. } => kind::HAS_CONFLICT,
            RQuery::InExcludedClass { .. } => kind::IN_EXCLUDED_CLASS,
            RQuery::WithinRecipientCap { .. } => kind::WITHIN_RECIPIENT_CAP,
            RQuery::AllRecipientsWithinCap { .. } => kind::ALL_RECIPIENTS_WITHIN_CAP,
            RQuery::HasGuardianConsent { .. } => kind::HAS_GUARDIAN_CONSENT,
            RQuery::IsVerifiedAdultAtDeadline { .. } => kind::IS_VERIFIED_ADULT_AT_DEADLINE,
            RQuery::DeclaresAffiliationOnList { .. } => kind::DECLARES_AFFILIATION_ON_LIST,
            RQuery::MeetsTieBreakCountry { .. } => kind::MEETS_TIE_BREAK_COUNTRY,
            RQuery::ChangedSince { .. } => kind::CHANGED_SINCE,
        }
    }

    /// The canonical arguments, as W1c's `wire::query` writes them.
    pub fn args(&self) -> String {
        match self {
            RQuery::IsVerified { account } => format!("{{\"account\":{}}}", id(*account)),
            RQuery::SameIdentityAsAny { subject, others } => format!(
                "{{\"others\":{},\"subject\":{}}}",
                id_set(others),
                id(*subject)
            ),
            RQuery::HasConflict { reviewer, team } => format!(
                "{{\"reviewer\":{},\"team\":{}}}",
                id(*reviewer),
                id_set(team)
            ),
            RQuery::InExcludedClass {
                account,
                programme,
                classes,
            } => format!(
                "{{\"account\":{},\"classes\":{},\"programme\":{}}}",
                id(*account),
                id_set(classes),
                id(*programme)
            ),
            RQuery::WithinRecipientCap {
                subject,
                amount: a,
                committed: c,
                cap,
            } => format!(
                "{{\"amount\":{},\"cap\":{},\"committed\":{},\"subject\":{}}}",
                amount(*a),
                amount(*cap),
                committed(c),
                id(*subject)
            ),
            RQuery::AllRecipientsWithinCap { committed: c, cap } => format!(
                "{{\"cap\":{},\"committed\":{}}}",
                amount(*cap),
                committed(c)
            ),
            RQuery::HasGuardianConsent { proposal } => {
                format!("{{\"proposal\":{}}}", id(*proposal))
            }
            RQuery::IsVerifiedAdultAtDeadline { account, deadline } => {
                format!("{{\"account\":{},\"deadline\":{deadline}}}", id(*account))
            }
            RQuery::DeclaresAffiliationOnList { team, list } => {
                format!("{{\"list\":{},\"team\":{}}}", id(*list), id_set(team))
            }
            RQuery::MeetsTieBreakCountry { account, programme } => format!(
                "{{\"account\":{},\"programme\":{}}}",
                id(*account),
                id(*programme)
            ),
            RQuery::ChangedSince { epoch } => format!("{{\"epoch\":{epoch}}}"),
        }
    }

    /// The wire query.
    pub fn wire(&self) -> WireQuery {
        WireQuery {
            kind: self.kind(),
            args: self.args().into_bytes(),
        }
    }
}

/// The JSON of one wire query inside an `ask` request. The arguments are
/// spliced in as they are, so they must already be canonical JSON.
pub fn query_json(q: &WireQuery) -> String {
    format!(
        "{{\"args\":{},\"kind\":{}}}",
        String::from_utf8_lossy(&q.args),
        q.kind
    )
}

/// The label of a relationship kind.
pub fn relationship_label(k: RelationshipKind) -> &'static str {
    match k {
        RelationshipKind::Conflict => "conflict",
    }
}

/// The accounts in the order given. A canonical message gives them in
/// strictly ascending order; a test that writes another order gets the
/// non-canonical spelling it asked for.
fn accounts_json(v: &[WireAccount]) -> String {
    let parts: Vec<String> = v.iter().map(|a| id(a.0)).collect();
    format!("[{}]", parts.join(","))
}

/// The canonical bytes of a request.
pub fn request(r: &VaultRequest) -> Vec<u8> {
    let s = match r {
        VaultRequest::Epoch => "{\"type\":\"epoch\"}".to_owned(),
        VaultRequest::Ask {
            at,
            reaction_for,
            queries,
        } => {
            let qs: Vec<String> = queries.iter().map(query_json).collect();
            let rf = match reaction_for {
                Some(e) => e.to_string(),
                None => "null".to_owned(),
            };
            format!(
                "{{\"at\":{at},\"queries\":[{}],\"reaction_for\":{rf},\"type\":\"ask\"}}",
                qs.join(",")
            )
        }
        VaultRequest::Ack {
            epoch,
            ledger_seq,
            link,
        } => format!(
            "{{\"epoch\":{epoch},\"ledger_seq\":{ledger_seq},\"link\":\"{}\",\"type\":\"ack\"}}",
            hex(link)
        ),
        VaultRequest::NegotiationOpened {
            proposal,
            accounts,
            ledger_seq,
        } => format!(
            "{{\"accounts\":{},\"ledger_seq\":{ledger_seq},\"proposal\":{},\"type\":\"negotiation_opened\"}}",
            accounts_json(accounts),
            id(proposal.0)
        ),
        VaultRequest::NegotiationClosed {
            proposal,
            ledger_seq,
        } => format!(
            "{{\"ledger_seq\":{ledger_seq},\"proposal\":{},\"type\":\"negotiation_closed\"}}",
            id(proposal.0)
        ),
        VaultRequest::RecordRelationship {
            a,
            b,
            kind: k,
            programme,
            ledger_seq,
        } => format!(
            "{{\"a\":{},\"b\":{},\"kind\":\"{}\",\"ledger_seq\":{ledger_seq},\"programme\":{},\"type\":\"record_relationship\"}}",
            id(a.0),
            id(b.0),
            relationship_label(*k),
            id(programme.0)
        ),
    };
    s.into_bytes()
}

/// The canonical JSON of a refusal.
pub fn refusal(r: &VaultRefusal) -> String {
    match r {
        VaultRefusal::Pending { epoch } => format!("{{\"epoch\":{epoch},\"type\":\"pending\"}}"),
        VaultRefusal::StaleEpoch { current } => {
            format!("{{\"current\":{current},\"type\":\"stale_epoch\"}}")
        }
        VaultRefusal::NotThisCell => "{\"type\":\"not_this_cell\"}".to_owned(),
        VaultRefusal::Malformed => "{\"type\":\"malformed\"}".to_owned(),
        VaultRefusal::Unavailable => "{\"type\":\"unavailable\"}".to_owned(),
    }
}

/// The canonical JSON of one answer.
pub fn answer(a: &WireAnswer) -> String {
    let accounts = match &a.accounts {
        Some(v) => accounts_json(v),
        None => "null".to_owned(),
    };
    format!(
        "{{\"accounts\":{accounts},\"epoch\":{},\"holds\":{}}}",
        a.epoch, a.holds
    )
}

/// The canonical bytes of a response.
pub fn response(r: &VaultResponse) -> Vec<u8> {
    let s = match r {
        VaultResponse::Epoch(e) => format!("{{\"epoch\":{e},\"type\":\"epoch\"}}"),
        VaultResponse::Answers(v) => {
            let parts: Vec<String> = v.iter().map(answer).collect();
            format!("{{\"answers\":[{}],\"type\":\"answers\"}}", parts.join(","))
        }
        VaultResponse::Acked => "{\"type\":\"acked\"}".to_owned(),
        VaultResponse::Refused(f) => format!("{{\"refusal\":{},\"type\":\"refused\"}}", refusal(f)),
    };
    s.into_bytes()
}

/// Whether an answer keeps the one-bit rule of design section 6.2 and
/// NOTE 5: an account set appears only on a `ChangedSince` answer, and
/// there the bit says whether the set is non-empty. An answer with a set
/// whose bit disagrees, or a set out of order, is never canonical.
pub fn answer_is_lawful(a: &WireAnswer) -> bool {
    match &a.accounts {
        None => true,
        Some(v) => {
            a.holds == !v.is_empty() && v.windows(2).all(|w| matches!(w, [x, y] if x.0 < y.0))
        }
    }
}

/// The length of the Ed25519 signature that ends a signed ticket.
pub const SIGNATURE_LEN: usize = 64;

/// The claims of a vault origin ticket (ADR-009 "Tickets"), as W1c's
/// `RefTicket` spells them: canonical JSON `{account, cell, expires_at,
/// issued_at, kind, nonce, proposal, scope}`. The signed ticket is that
/// body followed by the 64-byte Ed25519 signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RTicket {
    /// `release`, or `write:<kind label>`.
    pub kind: String,
    /// The cell, 16 bytes.
    pub cell: [u8; 16],
    /// The writer of a write, the subject of a release.
    pub account: u128,
    /// The proposal, if the kind names one.
    pub proposal: Option<u128>,
    /// A short label, such as `programme:<id>` for a country.
    pub scope: String,
    /// When it was issued, in microseconds.
    pub issued_at: i64,
    /// When it expires, in microseconds. Valid strictly before.
    pub expires_at: i64,
    /// The ticket id.
    pub nonce: [u8; 16],
}

impl RTicket {
    /// The canonical body.
    pub fn body(&self) -> Vec<u8> {
        let proposal = match self.proposal {
            Some(p) => id(p),
            None => "null".to_owned(),
        };
        format!(
            "{{\"account\":{},\"cell\":\"{}\",\"expires_at\":{},\"issued_at\":{},\"kind\":\"{}\",\"nonce\":\"{}\",\"proposal\":{},\"scope\":\"{}\"}}",
            id(self.account),
            hex(&self.cell),
            self.expires_at,
            self.issued_at,
            self.kind,
            hex(&self.nonce),
            proposal,
            self.scope,
        )
        .into_bytes()
    }

    /// The body followed by `signature`.
    pub fn framed(&self, signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
        [self.body().as_slice(), signature.as_slice()].concat()
    }
}
