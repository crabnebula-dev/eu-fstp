//! Identity vault wire types, tickets and codecs (M3 design section 6.2).
//!
//! The crate has its own id newtypes and no `fstp-domain` dependency
//! (layering rule 2).
//!
//! Every message is canonical JSON (RFC 8785) with one spelling, the
//! encoding lane W1c proposed in `fstp_celltest::reference::vault::wire`
//! and the W2d test author extended to the envelopes:
//!
//! - Each request and response names its variant in a `type` member.
//! - Ids are decimal strings. Sets of ids are arrays in strictly ascending
//!   order.
//! - Epochs, sequences and instants are JSON integers within plus or
//!   minus 2^53 - 1, the range RFC 8785 writes exactly.
//! - A chain link is 64 lowercase hex digits.
//! - Amounts are ADR-006 strings with their currency.
//! - A query is `{"args":<canonical args>,"kind":<code>}` ([`query`]).
//!
//! Every answer is one bit, except `ChangedSince`, which lists account
//! ids and nothing else (NOTE 5). A decoder cannot see which query an
//! answer belongs to, so [`decode_response`] enforces what the bytes show:
//! a set is ascending, and the bit says whether it is non-empty.
//! [`answers_for`] then pairs the answers with their queries and refuses a
//! set on any answer but a `ChangedSince` one.
//!
//! A response holds at most [`json::MAX_ANSWER_ACCOUNTS`] account ids. The
//! vault cuts a `ChangedSince` answer to stay within that bound, so the
//! cell can always decode the vault's reply.

pub mod json;
pub mod query;
pub mod ticket;

use std::fmt;

use fstp_json::{Array, Value};

pub use query::{Query, QueryKind, decode_query};
pub use ticket::{
    MAX_TICKET_LEN, SIGNATURE_LEN, TICKET_LIFETIME_MAX_US, Ticket, TicketClaims, TicketKind,
    WriteKind, country_scope, decode_ticket, scope_programme,
};

pub use json::{MAX_ANSWER_ACCOUNTS, MAX_RESPONSE_LEN};
use json::{limits, parse_canonical, response_limits};

/// An account, by its vault-side id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireAccount(pub u128);

/// A proposal, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireProposal(pub u128);

/// A programme, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireProgramme(pub u128);

/// An excluded class of P-13, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireClass(pub u128);

/// A P-38 proximity list, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireList(pub u128);

/// A query of the oracle, encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireQuery {
    /// The query kind: its [`QueryKind`] code.
    pub kind: u16,
    /// The query arguments, canonical JSON.
    pub args: Vec<u8>,
}

/// A relationship the cell records in the vault.
///
/// Reading, reported to Daniel: I-54 names a mentoring relationship. The
/// design's single kind is spelled `conflict`, since the vault reads every
/// recorded relationship as a conflict of interest (I-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationshipKind {
    /// A relationship that is a conflict of interest.
    Conflict,
}

impl RelationshipKind {
    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            RelationshipKind::Conflict => "conflict",
        }
    }
}

/// A request from the cell to its vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultRequest {
    /// Ask for the current epoch.
    Epoch,
    /// Ask queries.
    Ask {
        /// UTC microseconds.
        at: u64,
        /// The epoch of a reaction, if this asks for one.
        reaction_for: Option<u64>,
        /// The queries.
        queries: Vec<WireQuery>,
    },
    /// Acknowledge a reaction (NOTE 4).
    Ack {
        /// The epoch.
        epoch: u64,
        /// The ledger sequence of the reaction.
        ledger_seq: u64,
        /// The chain link of the reaction.
        link: [u8; 32],
    },
    /// A proposal entered negotiation.
    NegotiationOpened {
        /// The proposal.
        proposal: WireProposal,
        /// Its accounts, ascending.
        accounts: Vec<WireAccount>,
        /// The ledger sequence.
        ledger_seq: u64,
    },
    /// A proposal left negotiation.
    NegotiationClosed {
        /// The proposal.
        proposal: WireProposal,
        /// The ledger sequence.
        ledger_seq: u64,
    },
    /// Record a relationship between two accounts.
    RecordRelationship {
        /// The first account.
        a: WireAccount,
        /// The second account.
        b: WireAccount,
        /// The kind.
        kind: RelationshipKind,
        /// The programme.
        programme: WireProgramme,
        /// The ledger sequence.
        ledger_seq: u64,
    },
}

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireAnswer {
    /// Whether the queried fact holds.
    pub holds: bool,
    /// The accounts, only for the queries that return them.
    pub accounts: Option<Vec<WireAccount>>,
    /// The epoch the answer is at.
    pub epoch: u64,
}

impl WireAnswer {
    /// Whether the answer keeps the one-bit rule (NOTE 5): a set appears
    /// in ascending order, and the bit says whether it is non-empty.
    pub fn is_lawful(&self) -> bool {
        match &self.accounts {
            None => true,
            Some(v) => {
                self.holds == !v.is_empty()
                    && v.windows(2).all(|w| matches!(w, [x, y] if x.0 < y.0))
            }
        }
    }
}

/// Why the vault refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultRefusal {
    /// A provisional epoch waits for its acknowledgement.
    Pending {
        /// The provisional epoch.
        epoch: u64,
    },
    /// The request named an old epoch.
    StaleEpoch {
        /// The current epoch.
        current: u64,
    },
    /// The request is for another cell.
    NotThisCell,
    /// The request did not decode.
    Malformed,
    /// The vault is unavailable.
    Unavailable,
}

/// A response of the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultResponse {
    /// The current epoch.
    Epoch(u64),
    /// Answers, in query order.
    Answers(Vec<WireAnswer>),
    /// The acknowledgement was recorded.
    Acked,
    /// The vault refused.
    Refused(VaultRefusal),
}

/// Why a message did not decode or encode.
///
/// No variant holds input bytes (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Kept so the W0 stub checks of other lanes still name it. No
    /// operation of this crate returns it.
    NotImplemented(&'static str),
    /// The bytes are not JSON within the vault's parse limits.
    Json,
    /// The JSON is not the one RFC 8785 spelling.
    NotCanonical,
    /// The members, types or values are not those of the message. It
    /// names the part that failed.
    Shape(&'static str),
    /// A ticket has no room for a body and a signature, or is too long.
    Ticket,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::NotImplemented(op) => write!(f, "{op} is not implemented"),
            ProtoError::Json => f.write_str("not JSON within the vault limits"),
            ProtoError::NotCanonical => f.write_str("not the canonical spelling"),
            ProtoError::Shape(what) => write!(f, "malformed {what}"),
            ProtoError::Ticket => f.write_str("malformed ticket framing"),
        }
    }
}

impl std::error::Error for ProtoError {}

const REQUEST: &str = "request";
const RESPONSE: &str = "response";
const ANSWER: &str = "answer";
const REFUSAL: &str = "refusal";

fn accounts_of(v: &Value, what: &'static str) -> Result<Vec<WireAccount>, ProtoError> {
    Ok(json::id_list_value(v, what)?
        .into_iter()
        .map(WireAccount)
        .collect())
}

fn query_of(v: &Value) -> Result<WireQuery, ProtoError> {
    let o = json::object(v, &["args", "kind"], REQUEST)?;
    let kind = u16::try_from(json::uint(o, "kind", REQUEST)?)
        .map_err(|_| ProtoError::Shape("query kind"))?;
    let kind_of = QueryKind::from_code(kind).ok_or(ProtoError::Shape("query kind"))?;
    let args = json::member(o, "args", REQUEST)?;
    query::query_from_value(kind_of, args)?;
    Ok(WireQuery {
        kind,
        args: json::to_canonical(args)?,
    })
}

/// Decodes a request. Fuzzed (`vault_request_decode`).
///
/// Every query's arguments are checked against its kind, so a decoded
/// request holds only queries that [`decode_query`] accepts.
///
/// # Errors
///
/// [`ProtoError::Json`], [`ProtoError::NotCanonical`] or
/// [`ProtoError::Shape`].
pub fn decode_request(bytes: &[u8]) -> Result<VaultRequest, ProtoError> {
    let v = parse_canonical(bytes, &limits())?;
    let o = |names: &[&str]| json::object(&v, names, REQUEST);
    Ok(match json::type_of(&v, REQUEST)? {
        "epoch" => {
            o(&["type"])?;
            VaultRequest::Epoch
        }
        "ask" => {
            let m = o(&["at", "queries", "reaction_for", "type"])?;
            let qs = json::member(m, "queries", REQUEST)?
                .as_array()
                .ok_or(ProtoError::Shape(REQUEST))?;
            let mut queries = Vec::with_capacity(qs.len());
            for q in qs.iter() {
                queries.push(query_of(q)?);
            }
            VaultRequest::Ask {
                at: json::uint(m, "at", REQUEST)?,
                reaction_for: json::opt_uint(m, "reaction_for", REQUEST)?,
                queries,
            }
        }
        "ack" => {
            let m = o(&["epoch", "ledger_seq", "link", "type"])?;
            VaultRequest::Ack {
                epoch: json::uint(m, "epoch", REQUEST)?,
                ledger_seq: json::uint(m, "ledger_seq", REQUEST)?,
                link: json::hex_array(json::string(m, "link", REQUEST)?, REQUEST)?,
            }
        }
        "negotiation_opened" => {
            let m = o(&["accounts", "ledger_seq", "proposal", "type"])?;
            VaultRequest::NegotiationOpened {
                proposal: WireProposal(json::id(m, "proposal", REQUEST)?),
                accounts: accounts_of(json::member(m, "accounts", REQUEST)?, REQUEST)?,
                ledger_seq: json::uint(m, "ledger_seq", REQUEST)?,
            }
        }
        "negotiation_closed" => {
            let m = o(&["ledger_seq", "proposal", "type"])?;
            VaultRequest::NegotiationClosed {
                proposal: WireProposal(json::id(m, "proposal", REQUEST)?),
                ledger_seq: json::uint(m, "ledger_seq", REQUEST)?,
            }
        }
        "record_relationship" => {
            let m = o(&["a", "b", "kind", "ledger_seq", "programme", "type"])?;
            let kind = match json::string(m, "kind", REQUEST)? {
                "conflict" => RelationshipKind::Conflict,
                _ => return Err(ProtoError::Shape(REQUEST)),
            };
            VaultRequest::RecordRelationship {
                a: WireAccount(json::id(m, "a", REQUEST)?),
                b: WireAccount(json::id(m, "b", REQUEST)?),
                kind,
                programme: WireProgramme(json::id(m, "programme", REQUEST)?),
                ledger_seq: json::uint(m, "ledger_seq", REQUEST)?,
            }
        }
        _ => return Err(ProtoError::Shape(REQUEST)),
    })
}

fn typed(kind: &str, mut members: Vec<(&str, Value)>) -> Result<Value, ProtoError> {
    members.push(("type", Value::String(kind.to_owned())));
    json::obj(members)
}

fn ascending(v: &[WireAccount]) -> bool {
    v.windows(2).all(|w| matches!(w, [x, y] if x.0 < y.0))
}

/// Encodes a request in its one canonical spelling.
///
/// # Errors
///
/// [`ProtoError::Shape`] when a value has no canonical spelling: an
/// integer beyond 2^53 - 1, accounts out of order, or query arguments
/// that [`decode_query`] refuses.
pub fn encode_request(r: &VaultRequest) -> Result<Vec<u8>, ProtoError> {
    let n = |x: u64| json::uint_json(x, REQUEST);
    let v = match r {
        VaultRequest::Epoch => typed("epoch", Vec::new())?,
        VaultRequest::Ask {
            at,
            reaction_for,
            queries,
        } => {
            let mut qs = Array::with_capacity(queries.len());
            for q in queries {
                let kind = QueryKind::from_code(q.kind).ok_or(ProtoError::Shape("query kind"))?;
                let args = parse_canonical(&q.args, &limits())?;
                query::query_from_value(kind, &args)?;
                qs.push(json::obj(vec![
                    ("args", args),
                    ("kind", n(u64::from(q.kind))?),
                ])?);
            }
            let rf = match reaction_for {
                Some(e) => n(*e)?,
                None => Value::Null,
            };
            typed(
                "ask",
                vec![
                    ("at", n(*at)?),
                    ("queries", Value::Array(qs)),
                    ("reaction_for", rf),
                ],
            )?
        }
        VaultRequest::Ack {
            epoch,
            ledger_seq,
            link,
        } => typed(
            "ack",
            vec![
                ("epoch", n(*epoch)?),
                ("ledger_seq", n(*ledger_seq)?),
                ("link", Value::String(json::hex(link))),
            ],
        )?,
        VaultRequest::NegotiationOpened {
            proposal,
            accounts,
            ledger_seq,
        } => {
            if !ascending(accounts) {
                return Err(ProtoError::Shape(REQUEST));
            }
            typed(
                "negotiation_opened",
                vec![
                    ("accounts", json::id_list_json(accounts.iter().map(|a| a.0))),
                    ("ledger_seq", n(*ledger_seq)?),
                    ("proposal", json::id_json(proposal.0)),
                ],
            )?
        }
        VaultRequest::NegotiationClosed {
            proposal,
            ledger_seq,
        } => typed(
            "negotiation_closed",
            vec![
                ("ledger_seq", n(*ledger_seq)?),
                ("proposal", json::id_json(proposal.0)),
            ],
        )?,
        VaultRequest::RecordRelationship {
            a,
            b,
            kind,
            programme,
            ledger_seq,
        } => typed(
            "record_relationship",
            vec![
                ("a", json::id_json(a.0)),
                ("b", json::id_json(b.0)),
                ("kind", Value::String(kind.label().to_owned())),
                ("ledger_seq", n(*ledger_seq)?),
                ("programme", json::id_json(programme.0)),
            ],
        )?,
    };
    json::to_canonical(&v)
}

fn answer_of(v: &Value) -> Result<WireAnswer, ProtoError> {
    let o = json::object(v, &["accounts", "epoch", "holds"], ANSWER)?;
    let set = json::member(o, "accounts", ANSWER)?;
    let a = WireAnswer {
        holds: json::boolean(o, "holds", ANSWER)?,
        accounts: if set.is_null() {
            None
        } else {
            Some(accounts_of(set, ANSWER)?)
        },
        epoch: json::uint(o, "epoch", ANSWER)?,
    };
    if a.is_lawful() {
        Ok(a)
    } else {
        Err(ProtoError::Shape(ANSWER))
    }
}

fn refusal_of(v: &Value) -> Result<VaultRefusal, ProtoError> {
    let o = |names: &[&str]| json::object(v, names, REFUSAL);
    Ok(match json::type_of(v, REFUSAL)? {
        "pending" => VaultRefusal::Pending {
            epoch: json::uint(o(&["epoch", "type"])?, "epoch", REFUSAL)?,
        },
        "stale_epoch" => VaultRefusal::StaleEpoch {
            current: json::uint(o(&["current", "type"])?, "current", REFUSAL)?,
        },
        "not_this_cell" => {
            o(&["type"])?;
            VaultRefusal::NotThisCell
        }
        "malformed" => {
            o(&["type"])?;
            VaultRefusal::Malformed
        }
        "unavailable" => {
            o(&["type"])?;
            VaultRefusal::Unavailable
        }
        _ => return Err(ProtoError::Shape(REFUSAL)),
    })
}

/// Decodes a response. Fuzzed (`vault_response_decode`).
///
/// It parses within [`response_limits`], which admit every response
/// [`encode_response`] writes. A decoded response is not yet paired with
/// its queries: the cell passes it to [`answers_for`].
///
/// # Errors
///
/// [`ProtoError::Json`], [`ProtoError::NotCanonical`] or
/// [`ProtoError::Shape`], including for an answer that breaks the one-bit
/// rule of NOTE 5.
pub fn decode_response(bytes: &[u8]) -> Result<VaultResponse, ProtoError> {
    let v = parse_canonical(bytes, &response_limits())?;
    let o = |names: &[&str]| json::object(&v, names, RESPONSE);
    Ok(match json::type_of(&v, RESPONSE)? {
        "epoch" => VaultResponse::Epoch(json::uint(o(&["epoch", "type"])?, "epoch", RESPONSE)?),
        "answers" => {
            let m = o(&["answers", "type"])?;
            let items = json::member(m, "answers", RESPONSE)?
                .as_array()
                .ok_or(ProtoError::Shape(RESPONSE))?;
            let mut answers = Vec::with_capacity(items.len());
            for a in items.iter() {
                answers.push(answer_of(a)?);
            }
            VaultResponse::Answers(answers)
        }
        "acked" => {
            o(&["type"])?;
            VaultResponse::Acked
        }
        "refused" => {
            let m = o(&["refusal", "type"])?;
            VaultResponse::Refused(refusal_of(json::member(m, "refusal", RESPONSE)?)?)
        }
        _ => return Err(ProtoError::Shape(RESPONSE)),
    })
}

fn refusal_json(r: &VaultRefusal) -> Result<Value, ProtoError> {
    let n = |x: u64| json::uint_json(x, REFUSAL);
    match r {
        VaultRefusal::Pending { epoch } => typed("pending", vec![("epoch", n(*epoch)?)]),
        VaultRefusal::StaleEpoch { current } => {
            typed("stale_epoch", vec![("current", n(*current)?)])
        }
        VaultRefusal::NotThisCell => typed("not_this_cell", Vec::new()),
        VaultRefusal::Malformed => typed("malformed", Vec::new()),
        VaultRefusal::Unavailable => typed("unavailable", Vec::new()),
    }
}

/// Encodes a response in its one canonical spelling.
///
/// # Errors
///
/// [`ProtoError::Shape`] for an integer beyond 2^53 - 1, an answer that
/// breaks the one-bit rule of NOTE 5, or a response that
/// [`decode_response`] would refuse: more than [`MAX_ANSWERS`] answers,
/// more than [`MAX_ANSWER_ACCOUNTS`] account ids, or more than
/// [`MAX_RESPONSE_LEN`] bytes. So the cell can decode every response this
/// encodes.
pub fn encode_response(r: &VaultResponse) -> Result<Vec<u8>, ProtoError> {
    let n = |x: u64| json::uint_json(x, RESPONSE);
    let v = match r {
        VaultResponse::Epoch(e) => typed("epoch", vec![("epoch", n(*e)?)])?,
        VaultResponse::Answers(answers) => {
            let ids = answers
                .iter()
                .map(|a| a.accounts.as_ref().map_or(0, Vec::len))
                .try_fold(0usize, usize::checked_add);
            if answers.len() > MAX_ANSWERS || ids.is_none_or(|n| n > MAX_ANSWER_ACCOUNTS) {
                return Err(ProtoError::Shape(RESPONSE));
            }
            let mut items = Array::with_capacity(answers.len());
            for a in answers {
                if !a.is_lawful() {
                    return Err(ProtoError::Shape(ANSWER));
                }
                let set = match &a.accounts {
                    Some(v) => json::id_list_json(v.iter().map(|x| x.0)),
                    None => Value::Null,
                };
                items.push(json::obj(vec![
                    ("accounts", set),
                    ("epoch", n(a.epoch)?),
                    ("holds", Value::Bool(a.holds)),
                ])?);
            }
            typed("answers", vec![("answers", Value::Array(items))])?
        }
        VaultResponse::Acked => typed("acked", Vec::new())?,
        VaultResponse::Refused(f) => typed("refused", vec![("refusal", refusal_json(f)?)])?,
    };
    let bytes = json::to_canonical(&v)?;
    if bytes.len() > MAX_RESPONSE_LEN {
        return Err(ProtoError::Shape(RESPONSE));
    }
    Ok(bytes)
}

/// The most answers in one response.
pub const MAX_ANSWERS: usize = 10_000;

/// Checks `answers` against the `queries` they answer, in order (NOTE 5).
///
/// There must be one answer per query. A `ChangedSince` answer carries an
/// account set, and every other answer carries none. So no one-bit query
/// can be answered with an account set.
///
/// # Errors
///
/// [`ProtoError::Shape`] for a count mismatch, a query of unknown kind, a
/// set on a one-bit answer, a `ChangedSince` answer with no set, or an
/// answer that breaks the one-bit rule.
pub fn check_answers(queries: &[WireQuery], answers: &[WireAnswer]) -> Result<(), ProtoError> {
    if queries.len() != answers.len() {
        return Err(ProtoError::Shape(ANSWER));
    }
    for (q, a) in queries.iter().zip(answers) {
        let kind = QueryKind::from_code(q.kind).ok_or(ProtoError::Shape("query kind"))?;
        let lists = kind == QueryKind::ChangedSince;
        if lists != a.accounts.is_some() || !a.is_lawful() {
            return Err(ProtoError::Shape(ANSWER));
        }
    }
    Ok(())
}

/// The answers of `response` to `queries`, once [`check_answers`] accepts
/// them. The cell reads every vault answer through this.
///
/// # Errors
///
/// [`ProtoError::Shape`] for a response that holds no answers, and as
/// [`check_answers`].
pub fn answers_for<'a>(
    queries: &[WireQuery],
    response: &'a VaultResponse,
) -> Result<&'a [WireAnswer], ProtoError> {
    match response {
        VaultResponse::Answers(answers) => {
            check_answers(queries, answers)?;
            Ok(answers)
        }
        _ => Err(ProtoError::Shape(RESPONSE)),
    }
}
