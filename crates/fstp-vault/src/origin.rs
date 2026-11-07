//! The vault origin and the internal API, sans I/O (design sections 6.1,
//! 6.2 and 6.5, ADR-009 "Vault origin", "Tickets", "Write kinds" and
//! "Releases").
//!
//! [`Vault`] holds one cell's vault state and its used ticket ids. Its
//! routes are the closed table [`ORIGIN_ROUTES`] and [`INTERNAL_ROUTES`].
//! There is no other route, and none writes a fact around the ticket and
//! NOTE 4 rules.
//!
//! - `POST /w`: the ticket signature is checked before any other field is
//!   used, then the cell, route, window, lifetime and single use. The body
//!   limit of the ticket's kind applies before the body is read. The write
//!   must be the one the ticket admits (`origin_binding`). It then enters
//!   the NOTE 4 protocol, and the ticket is used.
//! - `POST /r`: a body over [`MAX_RELEASE_LEN`] is refused before it is
//!   read. Then the same ticket checks, and the second guard of design
//!   section 6.5: the vault's own negotiation fact must list the subject.
//!   Only the facts of the programme the ticket's scope names are shown.
//!   The released fields are rendered server-side with
//!   `Content-Security-Policy: default-src 'none'` and
//!   `Cache-Control: no-store`, in a document that runs no script.
//! - The origin sets no cookie and keeps no session.
//!
//! Reading of lane W1c, kept: a refused write or release does not use up
//! its ticket. Nothing was written or released.

use std::collections::{BTreeMap, BTreeSet};

use fstp_vault_core::fact::kind as fk;
use fstp_vault_core::ticket::fact_kinds_of;
use fstp_vault_core::{
    AckMsg, Ask, CoreError, Fact, Person, Route, TicketRefusal, VaultEvent, VaultState,
    VerificationRecord, check_ticket, decode_fact, origin_binding, origin_fact, release_guard,
};
use fstp_vault_proto::{
    TicketClaims, TicketKind, VaultRefusal, VaultRequest, VaultResponse, WireAccount,
    WireProgramme, WireProposal, WireQuery, WriteKind, country_scope, decode_request,
    encode_response, scope_programme,
};

use crate::codec::decode_origin_write;
use crate::{MATCH_KEY_LEN, VaultError};

/// Why the vault origin refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OriginRefusal {
    /// The vault holds no cell id and no pinned key yet.
    Unprovisioned,
    /// The request does not decode, or its body is not the write's.
    Malformed,
    /// The body exceeds the limit of its ticket kind.
    TooLarge,
    /// No pinned key verifies the ticket signature.
    BadSignature,
    /// The ticket names another cell.
    ForeignCell,
    /// The ticket kind does not match the route or the write.
    WrongKind,
    /// The ticket is issued after now.
    NotYetValid,
    /// The ticket expired.
    Expired,
    /// The ticket lives longer than 5 minutes.
    TooLong,
    /// The ticket was used before.
    Replayed,
    /// No negotiation fact lists the release subject.
    NoNegotiationFact,
    /// The vault cannot take the write now.
    Unavailable,
}

impl OriginRefusal {
    /// The HTTP status of the refusal. The body never says more than the
    /// status.
    pub const fn status(self) -> u16 {
        match self {
            OriginRefusal::Malformed => 400,
            OriginRefusal::TooLarge => 413,
            OriginRefusal::Replayed => 409,
            OriginRefusal::Unprovisioned | OriginRefusal::Unavailable => 503,
            OriginRefusal::BadSignature
            | OriginRefusal::ForeignCell
            | OriginRefusal::WrongKind
            | OriginRefusal::NotYetValid
            | OriginRefusal::Expired
            | OriginRefusal::TooLong
            | OriginRefusal::NoNegotiationFact => 403,
        }
    }
}

impl From<TicketRefusal> for OriginRefusal {
    fn from(r: TicketRefusal) -> Self {
        match r {
            TicketRefusal::Unprovisioned => OriginRefusal::Unprovisioned,
            TicketRefusal::Malformed => OriginRefusal::Malformed,
            TicketRefusal::BadSignature => OriginRefusal::BadSignature,
            TicketRefusal::ForeignCell => OriginRefusal::ForeignCell,
            TicketRefusal::WrongKind => OriginRefusal::WrongKind,
            TicketRefusal::NotYetValid => OriginRefusal::NotYetValid,
            TicketRefusal::Expired => OriginRefusal::Expired,
            TicketRefusal::TooLong => OriginRefusal::TooLong,
            TicketRefusal::Replayed => OriginRefusal::Replayed,
            TicketRefusal::NoNegotiationFact => OriginRefusal::NoNegotiationFact,
        }
    }
}

/// The body limit of a write ticket kind, in bytes (ADR-009 "Each route
/// has a body limit per ticket kind"). Interim constants with no P- id.
pub const fn body_limit(kind: WriteKind) -> usize {
    match kind {
        WriteKind::ProximityListDeclared | WriteKind::ReviewerDeclaration => 64 << 10,
        WriteKind::HardshipEvidence => 32 << 10,
        WriteKind::DocumentUpload
        | WriteKind::CountryStated
        | WriteKind::AffiliationDeclared
        | WriteKind::AdultAttestation
        | WriteKind::GuardianConsent
        | WriteKind::VerificationRecorded
        | WriteKind::PartnerStaffDeclared
        | WriteKind::BankDetails
        | WriteKind::BankVerification
        | WriteKind::BankDispute
        | WriteKind::HardshipVerification => 1 << 10,
    }
}

/// The body limit of `POST /r`, in bytes: the longest ticket in hex
/// (ADR-009 "Each route has a body limit per ticket kind").
pub const MAX_RELEASE_LEN: usize = 2 * fstp_vault_proto::MAX_TICKET_LEN;

/// The method and path of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    /// The HTTP method.
    pub method: &'static str,
    /// The path.
    pub path: &'static str,
}

/// The routes of the vault origin (ADR-009 "It serves three route groups
/// only"). The static loader pages for `/w` and `/r` are lane W3c's.
pub const ORIGIN_ROUTES: [RouteSpec; 2] = [
    RouteSpec {
        method: "POST",
        path: "/w",
    },
    RouteSpec {
        method: "POST",
        path: "/r",
    },
];

/// The routes of the internal mTLS listener (design section 6.1).
pub const INTERNAL_ROUTES: [RouteSpec; 4] = [
    RouteSpec {
        method: "POST",
        path: "/v1/epoch",
    },
    RouteSpec {
        method: "POST",
        path: "/v1/ask",
    },
    RouteSpec {
        method: "POST",
        path: "/v1/ack",
    },
    RouteSpec {
        method: "POST",
        path: "/v1/negotiation",
    },
];

/// What a write did: the epoch it became provisional at, or none when it
/// queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The provisional epoch, if the write opened one.
    pub epoch: Option<u64>,
    /// The ticket id the write used.
    pub nonce: [u8; 16],
    /// The reference of the hardship evidence the write submitted, if it
    /// did (R-PR-04). The lead copies it into the hardship request.
    pub evidence: Option<u128>,
}

/// One HTTP reply of the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The headers, lowercase names.
    pub headers: Vec<(&'static str, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The headers of every vault origin reply: no script, no caching, no
/// framing, no referrer, and no cookie.
pub fn origin_headers(content_type: &str) -> Vec<(&'static str, String)> {
    vec![
        ("content-type", content_type.to_owned()),
        ("content-security-policy", "default-src 'none'".to_owned()),
        ("cache-control", "no-store".to_owned()),
        ("x-content-type-options", "nosniff".to_owned()),
        ("x-frame-options", "DENY".to_owned()),
        ("referrer-policy", "no-referrer".to_owned()),
        ("cross-origin-resource-policy", "same-origin".to_owned()),
    ]
}

fn refusal_reply(r: OriginRefusal) -> Reply {
    Reply {
        status: r.status(),
        headers: origin_headers("text/plain; charset=utf-8"),
        body: Vec::new(),
    }
}

/// One change the vault database must record before the vault answers
/// (design section 4.3). Each mutating call of [`Vault`] appends its
/// entries, and the service persists them with `store::persist` in one
/// transaction. If that fails, the service restores the vault it held
/// before the call, so memory never runs ahead of the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEntry {
    /// A fact write took epoch `epoch`, provisional or queued.
    Written {
        /// The epoch the write takes. Epochs are consecutive, so a queued
        /// write's epoch is known when it queues.
        epoch: u64,
        /// The fact.
        fact: Fact,
        /// The accounts it touches, once it is provisional. A queued write
        /// records an empty set, replaced at its acknowledgement.
        affected: BTreeSet<WireAccount>,
        /// When it was written, in UTC microseconds.
        at: i64,
    },
    /// The cell acknowledged epoch `epoch` (NOTE 4 step 5).
    Acked {
        /// The epoch.
        epoch: u64,
        /// The ledger sequence of the reaction.
        seq: u64,
        /// The chain link of the reaction.
        link: Option<[u8; 32]>,
        /// The accounts the epoch touched.
        affected: BTreeSet<WireAccount>,
        /// When, in UTC microseconds.
        at: i64,
    },
    /// A ticket was used (`vault.ticket_used`).
    TicketUsed {
        /// The ticket id.
        nonce: [u8; 16],
        /// When, in UTC microseconds.
        at: i64,
    },
    /// The cell pushed a negotiation fact.
    NegotiationOpened {
        /// The proposal.
        proposal: WireProposal,
        /// Its accounts.
        accounts: BTreeSet<WireAccount>,
        /// The ledger sequence.
        seq: u64,
    },
    /// The cell closed a negotiation fact.
    NegotiationClosed {
        /// The proposal.
        proposal: WireProposal,
        /// The ledger sequence.
        seq: u64,
    },
    /// The vault answered one query (`vault.query_log`).
    Asked {
        /// When, in UTC microseconds.
        at: i64,
        /// The query, which only its keyed digest leaves memory as.
        query: WireQuery,
        /// The answer bit.
        holds: bool,
        /// The epoch of the answer.
        epoch: u64,
    },
    /// A programme's P-17 condition was set (`vault.country_condition`).
    P17Set {
        /// The programme.
        programme: WireProgramme,
        /// Its countries.
        countries: BTreeSet<u16>,
    },
    /// A new identity took the match key `match_key` (`vault.identity`).
    IdentityAssigned {
        /// The identity id.
        identity: Person,
        /// The identity match key (design section 6.4, Q17).
        match_key: [u8; MATCH_KEY_LEN],
    },
    /// A verification of `account` became effective at `epoch`
    /// (`vault.account`).
    AccountVerified {
        /// The account.
        account: WireAccount,
        /// Its identity.
        identity: Person,
        /// The epoch.
        epoch: u64,
    },
}

/// One cell's vault: its state, the ticket ids it used, the identities
/// by match key, and the journal of changes not yet persisted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vault {
    state: VaultState,
    used: BTreeSet<[u8; 16]>,
    identities: BTreeMap<[u8; MATCH_KEY_LEN], Person>,
    journal: Vec<JournalEntry>,
}

impl Vault {
    /// A vault of `cell` that pins the cell's ticket public keys `pinned`
    /// (current and next).
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] for no key or too many.
    pub fn new(cell: [u8; 16], pinned: &[[u8; 32]]) -> Result<Vault, VaultError> {
        let mut v = Vault::default();
        fstp_vault_core::provision(&mut v.state, cell, pinned)
            .map_err(|_| VaultError::Malformed("pinned ticket keys"))?;
        Ok(v)
    }

    /// The vault state.
    pub fn state(&self) -> &VaultState {
        &self.state
    }

    /// The ticket ids used so far (`vault.ticket_used`).
    pub fn used_tickets(&self) -> &BTreeSet<[u8; 16]> {
        &self.used
    }

    /// The journal entries since the last call: what the vault database
    /// must record before the vault answers.
    pub fn take_journal(&mut self) -> Vec<JournalEntry> {
        std::mem::take(&mut self.journal)
    }

    fn use_ticket(&mut self, nonce: [u8; 16], now: i64) {
        self.used.insert(nonce);
        self.journal
            .push(JournalEntry::TicketUsed { nonce, at: now });
    }

    /// Takes a fact write and journals it at the epoch it takes.
    fn write_journaled(&mut self, fact: Fact, now: i64) -> Result<Vec<VaultEvent>, CoreError> {
        let unavailable = CoreError::Refused(VaultRefusal::Unavailable);
        let queued = u64::try_from(self.state.queued()).map_err(|_| unavailable)?;
        let epoch = self
            .state
            .current()
            .checked_add(queued)
            .and_then(|e| e.checked_add(1))
            .ok_or(unavailable)?;
        let events = fstp_vault_core::write_fact(&mut self.state, fact.clone(), now)?;
        let affected = match self.state.provisional() {
            Some(p) if p.epoch() == epoch => p.affected().clone(),
            _ => BTreeSet::new(),
        };
        self.journal.push(JournalEntry::Written {
            epoch,
            fact,
            affected,
            at: now,
        });
        Ok(events)
    }

    /// Takes an acknowledgement and journals it when it made an epoch
    /// effective. A repeat changes nothing and journals nothing. An
    /// effective verification also journals its account's identity
    /// (`vault.account`).
    fn ack_journaled(&mut self, a: &AckMsg, now: i64) -> Result<Vec<VaultEvent>, CoreError> {
        let events = fstp_vault_core::ack_request(&mut self.state, a)?;
        if events.contains(&VaultEvent::Effective { epoch: a.epoch }) {
            let last = self.state.log().last();
            let affected = last.map(|e| e.affected.clone()).unwrap_or_default();
            let verified = last.and_then(|e| match &e.fact {
                Fact::VerificationRecorded {
                    account, person, ..
                } => Some((*account, *person)),
                _ => None,
            });
            self.journal.push(JournalEntry::Acked {
                epoch: a.epoch,
                seq: a.ledger_seq,
                link: Some(a.link),
                affected,
                at: now,
            });
            if let Some((account, identity)) = verified {
                self.journal.push(JournalEntry::AccountVerified {
                    account,
                    identity,
                    epoch: a.epoch,
                });
            }
        }
        Ok(events)
    }

    /// Replays one stored write at `at`, with no journal entry.
    pub(crate) fn replay_write(
        &mut self,
        fact: Fact,
        at: i64,
    ) -> Result<Vec<VaultEvent>, CoreError> {
        fstp_vault_core::write_fact(&mut self.state, fact, at)
    }

    /// Replays one stored acknowledgement, with no journal entry.
    pub(crate) fn replay_ack(
        &mut self,
        epoch: u64,
        seq: u64,
        link: Option<[u8; 32]>,
    ) -> Result<Vec<VaultEvent>, CoreError> {
        match link {
            Some(link) => fstp_vault_core::ack_request(
                &mut self.state,
                &AckMsg {
                    epoch,
                    ledger_seq: seq,
                    link,
                },
            ),
            None => fstp_vault_core::ack(&mut self.state, epoch, seq),
        }
    }

    /// Replays one stored ticket use, with no journal entry.
    pub(crate) fn replay_ticket(&mut self, nonce: [u8; 16]) {
        self.used.insert(nonce);
    }

    /// Replays one stored negotiation row, with no journal entry: its
    /// highest sequence, and its accounts while it is open.
    pub(crate) fn replay_negotiation(
        &mut self,
        proposal: WireProposal,
        accounts: &BTreeSet<WireAccount>,
        opened_seq: u64,
        closed_seq: Option<u64>,
    ) -> Result<(), CoreError> {
        // A closed row holds its close sequence, which is at least its open
        // one. A close that came first stores both as the same sequence.
        let replayed = match closed_seq {
            None => fstp_vault_core::negotiation_opened(
                &mut self.state,
                proposal,
                accounts,
                opened_seq,
            )?,
            Some(seq) if seq >= opened_seq => {
                fstp_vault_core::negotiation_closed(&mut self.state, proposal, seq)
            }
            Some(_) => false,
        };
        if replayed {
            Ok(())
        } else {
            Err(CoreError::Refused(VaultRefusal::Malformed))
        }
    }

    /// Replays one stored P-17 condition, with no journal entry.
    pub(crate) fn replay_p17(
        &mut self,
        programme: WireProgramme,
        countries: &BTreeSet<u16>,
    ) -> Result<(), CoreError> {
        if self.state.p17(programme).is_some() {
            return Err(CoreError::Refused(VaultRefusal::Malformed));
        }
        fstp_vault_core::set_p17(&mut self.state, programme, countries)
    }

    /// Replays one stored identity, with no journal entry.
    pub(crate) fn replay_identity(
        &mut self,
        identity: Person,
        match_key: [u8; MATCH_KEY_LEN],
    ) -> Result<(), VaultError> {
        let taken = self.identities.values().any(|p| *p == identity);
        if taken || self.identities.insert(match_key, identity).is_some() {
            return Err(VaultError::Malformed("a stored identity"));
        }
        Ok(())
    }

    /// Sets the P-17 countries of `programme` (NOTE 6), and journals a new
    /// condition (`vault.country_condition`), so it is fixed across restarts.
    ///
    /// Open with Daniel: which message carries the condition to the vault.
    /// No internal request or provisioning input names it yet (design
    /// sections 6.1 and 6.2), so only this call sets it.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] as `fstp_vault_core::set_p17` refuses: a
    /// different condition than the one set before, or a first condition
    /// after a country was stated for the programme.
    pub fn set_p17(
        &mut self,
        programme: WireProgramme,
        countries: &BTreeSet<u16>,
    ) -> Result<(), VaultError> {
        let new = self.state.p17(programme).is_none();
        fstp_vault_core::set_p17(&mut self.state, programme, countries)
            .map_err(|_| VaultError::Malformed("P-17 condition"))?;
        if new {
            self.journal.push(JournalEntry::P17Set {
                programme,
                countries: countries.clone(),
            });
        }
        Ok(())
    }

    /// The identity of the match key `match_key`: the one `vault.identity`
    /// holds for it, or a new one, journaled (design section 6.4, Q17).
    /// The key is `crate::match_key` over the method's attribute tuple, so
    /// two accounts share an identity only when their attributes match.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when the identity ids are exhausted.
    pub fn resolve_identity(
        &mut self,
        match_key: [u8; MATCH_KEY_LEN],
    ) -> Result<Person, VaultError> {
        if let Some(p) = self.identities.get(&match_key) {
            return Ok(*p);
        }
        let next = self
            .identities
            .values()
            .map(|p| p.0)
            .max()
            .map_or(Some(1), |m| m.checked_add(1))
            .ok_or(VaultError::Unavailable("identity ids"))?;
        let identity = Person(next);
        self.identities.insert(match_key, identity);
        self.journal.push(JournalEntry::IdentityAssigned {
            identity,
            match_key,
        });
        Ok(identity)
    }

    /// The verification fact of `account` with the R-ID-02 record
    /// `record`, recorded by `verifier`. Its identity comes from
    /// [`Vault::resolve_identity`] over `match_key`, never from a request
    /// member, so no recorder can choose whose identity an account joins.
    /// The record's verifier is set to `verifier`, whatever `record` held.
    ///
    /// Seam: no route takes a verification yet. The origin never decodes
    /// kind 6 (`fact_kinds_of`). The recorder route of ADR-008 (Q1, Q14)
    /// will take its own body: the method's attribute tuple, which gives
    /// `match_key`, and the R-ID-02 record. It passes the account of the
    /// recorder's checked ticket as `verifier`.
    ///
    /// # Errors
    ///
    /// As [`Vault::resolve_identity`].
    pub fn verification_fact(
        &mut self,
        verifier: WireAccount,
        account: WireAccount,
        record: VerificationRecord,
        match_key: [u8; MATCH_KEY_LEN],
    ) -> Result<Fact, VaultError> {
        Ok(Fact::VerificationRecorded {
            account,
            person: self.resolve_identity(match_key)?,
            record: VerificationRecord { verifier, ..record },
        })
    }

    fn checked(
        &self,
        ticket: &[u8],
        route: Route,
        now: i64,
    ) -> Result<TicketClaims, OriginRefusal> {
        let c = check_ticket(&self.state, ticket, route, now)?;
        if self.used.contains(&c.nonce) {
            return Err(OriginRefusal::Replayed);
        }
        Ok(c)
    }

    /// `POST /w` with the request `bytes` at `now`.
    ///
    /// # Errors
    ///
    /// The first [`OriginRefusal`]: the frame, then the ticket checks with
    /// the signature first, then the body limit, the body, and the
    /// binding of the ticket to the write.
    pub fn post_write(&mut self, bytes: &[u8], now: i64) -> Result<Written, OriginRefusal> {
        if bytes.len() > crate::codec::MAX_ORIGIN_WRITE_LEN {
            return Err(OriginRefusal::TooLarge);
        }
        let w = decode_origin_write(bytes).map_err(|_| OriginRefusal::Malformed)?;
        let c = self.checked(&w.ticket, Route::Write, now)?;
        let TicketKind::Write(kind) = c.kind else {
            return Err(OriginRefusal::WrongKind);
        };
        if w.body.len() > body_limit(kind) {
            return Err(OriginRefusal::TooLarge);
        }
        let fact = fact_for(kind, &w.body, now, c.nonce, self.state.latest())
            .ok_or(OriginRefusal::Malformed)?;
        let binding = origin_binding(self.state.latest(), &fact).ok_or(OriginRefusal::WrongKind)?;
        if !binding.admits(&c) {
            return Err(OriginRefusal::WrongKind);
        }
        // I-33: a verification counts for a bank detail version written
        // before its ticket was issued, so a change made while the
        // verifier checks never inherits the verification.
        if let Fact::BankVerified { grant, .. } = &fact
            && self
                .state
                .latest()
                .bank_of(*grant)
                .is_none_or(|b| b.written_at >= c.issued_at)
        {
            return Err(OriginRefusal::WrongKind);
        }
        let evidence = match &fact {
            Fact::HardshipEvidence { evidence, .. } => Some(evidence.0),
            _ => None,
        };
        let events = self.write_journaled(fact, now).map_err(|e| match e {
            CoreError::Refused(VaultRefusal::Malformed) => OriginRefusal::Malformed,
            _ => OriginRefusal::Unavailable,
        })?;
        self.use_ticket(c.nonce, now);
        Ok(Written {
            epoch: events.iter().find_map(|e| match e {
                VaultEvent::Provisional { epoch } => Some(*epoch),
                VaultEvent::Effective { .. } => None,
            }),
            nonce: c.nonce,
            evidence,
        })
    }

    /// `POST /r` with the signed ticket `ticket` at `now`. The reply
    /// renders the released fields.
    ///
    /// # Errors
    ///
    /// The first [`OriginRefusal`]: the ticket checks with the signature
    /// first, then the negotiation fact.
    pub fn post_release(&mut self, ticket: &[u8], now: i64) -> Result<Reply, OriginRefusal> {
        let c = self.checked(ticket, Route::Release, now)?;
        let body = if c.kind == TicketKind::BankView {
            // M5 design reading 6: the bank details of the grant the
            // ticket names, for a verifier or a releaser. The cell decides
            // who gets the ticket, after a step-up (I-78).
            let grant = c.proposal.ok_or(OriginRefusal::WrongKind)?;
            bank_document(&self.state, grant)
        } else {
            release_guard(&self.state, &c)?;
            release_document(&self.state, &c)
        };
        self.use_ticket(c.nonce, now);
        Ok(Reply {
            status: 200,
            headers: origin_headers("text/html; charset=utf-8"),
            body,
        })
    }

    /// Routes one vault origin request. Every route outside
    /// [`ORIGIN_ROUTES`] answers 404, and a known path with another
    /// method answers 405.
    pub fn origin(&mut self, method: &str, path: &str, body: &[u8], now: i64) -> Reply {
        let known = ORIGIN_ROUTES.iter().any(|r| r.path == path);
        match (method, path) {
            ("POST", "/w") => match self.post_write(body, now) {
                // The hardship reference is the one value a write returns.
                Ok(Written {
                    evidence: Some(e), ..
                }) => Reply {
                    status: 200,
                    headers: origin_headers("application/json"),
                    body: format!("{{\"evidence\":\"{e}\"}}").into_bytes(),
                },
                Ok(_) => Reply {
                    status: 204,
                    headers: origin_headers("text/plain; charset=utf-8"),
                    body: Vec::new(),
                },
                Err(r) => refusal_reply(r),
            },
            ("POST", "/r") => {
                // The ticket is the whole body: the loader posts it as the
                // fragment gave it, in lowercase hex. The body limit of a
                // release applies before the body is read (ADR-009).
                if body.len() > MAX_RELEASE_LEN {
                    return refusal_reply(OriginRefusal::TooLarge);
                }
                let ticket = match std::str::from_utf8(body)
                    .ok()
                    .and_then(|s| fstp_vault_proto::json::unhex(s, "ticket").ok())
                {
                    Some(t) => t,
                    None => return refusal_reply(OriginRefusal::Malformed),
                };
                match self.post_release(&ticket, now) {
                    Ok(reply) => reply,
                    Err(r) => refusal_reply(r),
                }
            }
            _ => Reply {
                status: if known { 405 } else { 404 },
                headers: origin_headers("text/plain; charset=utf-8"),
                body: Vec::new(),
            },
        }
    }

    /// Takes one internal API request of the cell (design section 6.2).
    pub fn internal(&mut self, req: &VaultRequest, now: i64) -> VaultResponse {
        let refused = |e: CoreError| match e {
            CoreError::Refused(r) => VaultResponse::Refused(r),
            CoreError::NotImplemented(_) => VaultResponse::Refused(VaultRefusal::Unavailable),
        };
        match req {
            VaultRequest::Epoch => VaultResponse::Epoch(self.state.current()),
            VaultRequest::Ask {
                reaction_for,
                queries,
                ..
            } => match fstp_vault_core::ask_request(
                &self.state,
                &Ask {
                    reaction_for: *reaction_for,
                    queries,
                },
            ) {
                Ok(answers) => {
                    for (q, a) in queries.iter().zip(&answers) {
                        self.journal.push(JournalEntry::Asked {
                            at: now,
                            query: q.clone(),
                            holds: a.holds,
                            epoch: a.epoch,
                        });
                    }
                    VaultResponse::Answers(answers)
                }
                Err(e) => refused(e),
            },
            VaultRequest::Ack {
                epoch,
                ledger_seq,
                link,
            } => {
                let a = AckMsg {
                    epoch: *epoch,
                    ledger_seq: *ledger_seq,
                    link: *link,
                };
                match self.ack_journaled(&a, now) {
                    Ok(_) => VaultResponse::Acked,
                    Err(e) => refused(e),
                }
            }
            VaultRequest::NegotiationOpened {
                proposal,
                accounts,
                ledger_seq,
            } => {
                let set: BTreeSet<WireAccount> = accounts.iter().copied().collect();
                match self.negotiation_opened(*proposal, &set, *ledger_seq) {
                    Ok(()) => VaultResponse::Acked,
                    Err(_) => VaultResponse::Refused(VaultRefusal::Malformed),
                }
            }
            VaultRequest::NegotiationClosed {
                proposal,
                ledger_seq,
            } => {
                self.negotiation_closed(*proposal, *ledger_seq);
                VaultResponse::Acked
            }
            // Interim reading, pending Daniel: W1c's relationship fact
            // (kind 10) holds no kind and no programme, so the vault reads
            // every relationship as a conflict in every programme of the
            // cell. I-54 scopes it to its programme. This over-denies in
            // other programmes and never under-denies.
            //
            // Relationships form a set that no write removes. So a
            // relationship already in the newest facts, effective,
            // provisional or queued, is a retry or a repeat. It is
            // acknowledged and writes nothing, so it opens no epoch.
            VaultRequest::RecordRelationship { a, b, .. } => {
                if self.state.latest().has_relationship(*a, *b) {
                    return VaultResponse::Acked;
                }
                match self.write_journaled(Fact::Relationship { a: *a, b: *b }, now) {
                    Ok(_) => VaultResponse::Acked,
                    Err(e) => refused(e),
                }
            }
        }
    }

    /// Takes one encoded internal API request and returns the encoded
    /// response. A request that does not decode is refused as malformed
    /// (NOTE 2).
    pub fn internal_bytes(&mut self, bytes: &[u8], now: i64) -> Vec<u8> {
        let response = match decode_request(bytes) {
            Ok(req) => self.internal(&req, now),
            Err(_) => VaultResponse::Refused(VaultRefusal::Malformed),
        };
        match encode_response(&response) {
            Ok(b) => b,
            // Only an epoch beyond 2^53 - 1 has no spelling. Refuse then.
            Err(_) => b"{\"refusal\":{\"type\":\"unavailable\"},\"type\":\"refused\"}".to_vec(),
        }
    }

    /// Records the negotiation fact of `proposal` that the cell pushed at
    /// ledger sequence `seq` (`NegotiationOpened`).
    ///
    /// A fact at or below the highest sequence the vault saw for the
    /// proposal, opened or closed, is a retry or a stale message. It is
    /// accepted and changes nothing, so it never reopens a closed
    /// negotiation. A re-entry into NEGOTIATION carries a newer sequence.
    ///
    /// # Errors
    ///
    /// [`VaultError::Malformed`] for too many accounts.
    pub fn negotiation_opened(
        &mut self,
        proposal: WireProposal,
        accounts: &BTreeSet<WireAccount>,
        seq: u64,
    ) -> Result<(), VaultError> {
        let applied = fstp_vault_core::negotiation_opened(&mut self.state, proposal, accounts, seq)
            .map_err(|_| VaultError::Malformed("negotiation fact"))?;
        if applied {
            self.journal.push(JournalEntry::NegotiationOpened {
                proposal,
                accounts: accounts.clone(),
                seq,
            });
        }
        Ok(())
    }

    /// Removes the negotiation fact of `proposal`, which the cell closed
    /// at ledger sequence `seq` (`NegotiationClosed`). A close at or below
    /// the highest sequence seen changes nothing.
    pub fn negotiation_closed(&mut self, proposal: WireProposal, seq: u64) {
        if fstp_vault_core::negotiation_closed(&mut self.state, proposal, seq) {
            self.journal
                .push(JournalEntry::NegotiationClosed { proposal, seq });
        }
    }
}

/// The fact a write ticket of `kind` carries in `body`, if the body is the
/// canonical body of one of the kind's facts. A body of another kind's
/// shape becomes that fact, so the binding refuses it as the wrong kind.
///
/// A verification body (kind 6) is never decoded here, under any ticket.
/// Its identity and verifier must not come from a browser body (design
/// section 6.4, Q17, ADR-008), so it is malformed on this route.
fn fact_for(
    kind: WriteKind,
    body: &[u8],
    now: i64,
    nonce: [u8; 16],
    latest: &fstp_vault_core::Facts,
) -> Option<Fact> {
    let own = fact_kinds_of(kind)
        .iter()
        .find_map(|code| origin_fact(*code, body, now, nonce, latest).ok());
    if own.is_some() {
        return own;
    }
    // A classed affiliation under a plain affiliation ticket, or any other
    // kind's body: decode it as its own kind, so the binding names the
    // mismatch.
    [
        fk::PARTNER_STAFF_DECLARED,
        fk::COUNTRY_STATED,
        fk::ADULT_ATTESTATION,
        fk::GUARDIAN_CONSENT,
        fk::PROXIMITY_LIST_DECLARED,
        fk::REVIEWER_DECLARATION,
        fk::RELATIONSHIP,
        fk::CONSENT_WITHDRAWN,
        fk::ATTESTATION_WITHDRAWN,
        fk::AFFILIATION_ENDED,
    ]
    .iter()
    .find_map(|code| decode_fact(*code, body).ok())
}

/// The release document: the subject's released fields, rendered
/// server-side as HTML with no script, no style and no external resource.
///
/// Readings, reported to Daniel:
///
/// - The M3 vault holds no name or document attribute yet (M4 brings
///   verification methods). The document lists what the vault holds for
///   the subject: whether it is verified, and the country it stated.
/// - A release is for one proposal, issued to an Operations role holder
///   of its programme (design section 6.5, I-17). The vault does not know
///   a proposal's programme, since `NegotiationOpened` does not carry it
///   (design section 6.2). So the cell names it in the ticket's scope as
///   `programme:<id>`, and only that programme's country is shown. A
///   ticket with any other scope shows no country at all.
fn release_document(s: &VaultState, c: &TicketClaims) -> Vec<u8> {
    let facts = s.facts();
    let account = c.account;
    let verified = facts.person_of(account).is_some();
    let mut rows = String::new();
    rows.push_str(&row("Account", &account.0.to_string()));
    if let Some(p) = c.proposal {
        rows.push_str(&row("Proposal", &p.0.to_string()));
    }
    rows.push_str(&row("Verified", if verified { "yes" } else { "no" }));
    let programme = scope_programme(&c.scope).filter(|p| country_scope(*p) == c.scope);
    if let Some(programme) = programme
        && let Some(country) = facts.country_of(account, programme)
    {
        rows.push_str(&row(
            &format!("Country stated for programme {}", programme.0),
            &country.to_string(),
        ));
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Identity release</title></head><body><h1>Identity release</h1><table>{rows}</table></body></html>"
    )
    .into_bytes()
}

/// The bank details of `grant`, rendered server-side with no script (M5
/// design reading 6, I-86). It shows the latest version, when it was
/// written, whether it is verified and whether a dispute is open.
fn bank_document(s: &VaultState, grant: WireProposal) -> Vec<u8> {
    let facts = s.latest();
    let mut rows = String::new();
    rows.push_str(&row("Grant", &grant.0.to_string()));
    match facts.bank_of(grant) {
        Some(b) => {
            rows.push_str(&row("Account holder", &b.holder));
            rows.push_str(&row("IBAN", &b.iban));
            rows.push_str(&row("Version", &b.version.to_string()));
            rows.push_str(&row(
                "Written at (UTC microseconds)",
                &b.written_at.to_string(),
            ));
            rows.push_str(&row("Verified", if b.verified { "yes" } else { "no" }));
        }
        None => rows.push_str(&row("Bank details", "none entered")),
    }
    let disputed = facts.bank_disputed(grant);
    rows.push_str(&row("Dispute open", if disputed { "yes" } else { "no" }));
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Bank details</title></head><body><h1>Bank details</h1><table>{rows}</table></body></html>"
    )
    .into_bytes()
}

fn row(label: &str, value: &str) -> String {
    format!(
        "<tr><th>{}</th><td>{}</td></tr>",
        escape(label),
        escape(value)
    )
}

/// HTML text escaping.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
