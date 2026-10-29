//! Vault facts, epochs, the commit protocol, query evaluation, and the
//! release and write rules (M3 design section 6.3, NOTE 4). Pure.
//!
//! No crate outside `fstp-vault` reaches this one, except the test-only
//! `fstp-celltest` (layering rule 2).
//!
//! The NOTE 4 commit protocol:
//!
//! 1. A new fact is stored as provisional at a new epoch. Only one
//!    provisional epoch exists at a time. Later writes queue behind it.
//! 2. `affected` lists the accounts the fact touches, plus every account
//!    that facts revealed by a verification touch (confirmed 2026-10-25).
//! 3. [`ask`] refuses as pending any query that names an affected
//!    account, unless the ask is the reaction to the provisional epoch.
//!    A reaction sees the provisional fact.
//! 4. The cell runs `VaultChanged`, appends the reaction, then sends
//!    `Ack { epoch, seq, link }`.
//! 5. [`ack`] makes the fact effective, records the cell's sequence and
//!    link, and opens the next queued write. A repeated `ack` is accepted.
//!
//! Every query counts only effective facts, apart from reaction queries,
//! so I-04 and I-06 hold at every instant.

pub mod eval;
pub mod fact;
pub mod ticket;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fstp_vault_proto::{
    Query, VaultRefusal, WireAccount, WireAnswer, WireProgramme, WireProposal, WireQuery,
    decode_query,
};

pub use eval::Facts;
pub use fact::{
    Check, DocumentType, Fact, Org, Person, VerificationMethod, VerificationRecord, decode_fact,
};
pub use ticket::{
    MAX_PINNED_KEYS, OriginBinding, Route, TicketRefusal, check_ticket, origin_binding,
    release_guard,
};

/// The longest queue of writes behind the provisional one. A write beyond
/// it is refused as unavailable, so a stalled cell cannot grow the vault's
/// memory without bound.
pub const MAX_QUEUED_WRITES: usize = 10_000;

/// The most queries in one ask.
pub const MAX_QUERIES: usize = 1_000;

/// The most accounts in one negotiation fact.
pub const MAX_NEGOTIATION_ACCOUNTS: usize = 1_000;

/// The most countries in one programme's P-17 condition.
pub const MAX_P17_COUNTRIES: usize = 300;

/// The most accounts one write may touch (NOTE 4 step 2). A write that
/// touches more is refused as unavailable. It equals the most ids in one
/// response, so one epoch always fits in a `ChangedSince` answer. An
/// interim constant with no P- id.
pub const MAX_AFFECTED_ACCOUNTS: usize = fstp_vault_proto::MAX_ANSWER_ACCOUNTS;

/// A fact write: a kind code and the canonical body of that kind
/// ([`fact`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactWrite {
    /// The fact kind.
    pub kind: u16,
    /// The canonical fact body.
    pub body: Vec<u8>,
}

/// The provisional write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provisional {
    epoch: u64,
    fact: Fact,
    affected: BTreeSet<WireAccount>,
    proposal: Option<WireProposal>,
    opened_at: i64,
}

impl Provisional {
    /// Its epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The fact.
    pub fn fact(&self) -> &Fact {
        &self.fact
    }

    /// The accounts it touches.
    pub fn affected(&self) -> &BTreeSet<WireAccount> {
        &self.affected
    }

    /// When it became provisional, in UTC microseconds.
    pub fn opened_at(&self) -> i64 {
        self.opened_at
    }
}

/// One effective epoch and what it touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveEpoch {
    /// The epoch.
    pub epoch: u64,
    /// The fact.
    pub fact: Fact,
    /// The accounts it touched.
    pub affected: BTreeSet<WireAccount>,
    /// The ledger sequence of the reaction the acknowledgement named.
    pub ack_seq: u64,
    /// The chain link of that reaction, when the acknowledgement carried
    /// one.
    pub ack_link: Option<[u8; 32]>,
    /// When it became provisional, in UTC microseconds.
    pub opened_at: i64,
}

/// A queued write, with the accounts it will touch. They are known when
/// it queues: it opens over the facts after every write ahead of it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Queued {
    fact: Fact,
    at: i64,
    affected: BTreeSet<WireAccount>,
}

/// The vault state of one cell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultState {
    cell: Option<[u8; 16]>,
    pinned: Vec<[u8; 32]>,
    p17: BTreeMap<WireProgramme, BTreeSet<u16>>,
    facts: Facts,
    log: Vec<EffectiveEpoch>,
    provisional: Option<Provisional>,
    queue: VecDeque<Queued>,
    /// The facts after the provisional write and every queued one.
    tail: Facts,
    negotiation: BTreeMap<WireProposal, BTreeSet<WireAccount>>,
    /// The highest ledger sequence of a negotiation fact per proposal,
    /// opened or closed.
    negotiation_seq: BTreeMap<WireProposal, u64>,
}

impl VaultState {
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

    /// The number of writes queued behind the provisional one.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// The effective facts.
    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// The effective epochs, in order.
    pub fn log(&self) -> &[EffectiveEpoch] {
        &self.log
    }

    /// The cell id pinned at provisioning.
    pub fn cell(&self) -> Option<[u8; 16]> {
        self.cell
    }

    /// The cell's ticket public keys pinned at provisioning.
    pub fn pinned(&self) -> &[[u8; 32]] {
        &self.pinned
    }

    /// The facts a reaction to the provisional epoch sees.
    pub fn reaction_facts(&self) -> Facts {
        match &self.provisional {
            Some(p) => self.facts.after(&p.fact),
            None => self.facts.clone(),
        }
    }

    /// The facts once the provisional write and every queued write are
    /// effective: the newest facts the vault holds. The origin binds a
    /// withdrawal against them, so a withdrawal may follow a write that is
    /// still provisional or queued.
    pub fn latest_facts(&self) -> Facts {
        self.tail.clone()
    }

    /// The newest facts, as [`VaultState::latest_facts`], by reference.
    pub fn latest(&self) -> &Facts {
        &self.tail
    }

    /// The P-17 countries of `programme`, once set.
    pub fn p17(&self, programme: WireProgramme) -> Option<&BTreeSet<u16>> {
        self.p17.get(&programme)
    }

    /// The highest ledger sequence of a negotiation fact of `proposal`,
    /// opened or closed.
    pub fn negotiation_seq(&self, proposal: WireProposal) -> Option<u64> {
        self.negotiation_seq.get(&proposal).copied()
    }

    /// Whether the vault's own negotiation fact for `proposal` lists
    /// `subject` (the second guard of design section 6.5).
    pub fn negotiation_lists(&self, proposal: WireProposal, subject: WireAccount) -> bool {
        self.negotiation
            .get(&proposal)
            .is_some_and(|s| s.contains(&subject))
    }

    fn pending_for(&self, q: &Query) -> Option<u64> {
        let p = self.provisional.as_ref()?;
        let (accounts, proposal) = eval::named(q);
        let hit = accounts.iter().any(|a| p.affected.contains(a))
            || (proposal.is_some() && proposal == p.proposal);
        hit.then_some(p.epoch)
    }

    /// The accounts touched after epoch `since`, whole epoch by whole
    /// epoch, while they fit in `budget` ids. The second value is the cut:
    /// the last epoch included, when a later one did not fit.
    fn changed_since(
        &self,
        since: u64,
        with_provisional: bool,
        budget: usize,
    ) -> (BTreeSet<WireAccount>, Option<u64>) {
        let provisional = self
            .provisional
            .as_ref()
            .filter(|_| with_provisional)
            .map(|p| (p.epoch, &p.affected));
        let epochs = self
            .log
            .iter()
            .filter(|e| e.epoch > since)
            .map(|e| (e.epoch, &e.affected))
            .chain(provisional);
        let mut out = BTreeSet::new();
        let mut last = since;
        for (epoch, affected) in epochs {
            let new = affected.iter().filter(|a| !out.contains(*a)).count();
            if out.len().saturating_add(new) > budget {
                return (out, Some(last));
            }
            out.extend(affected.iter().copied());
            last = epoch;
        }
        (out, None)
    }

    /// The answer to `q` over `facts` at `epoch`. A `ChangedSince` answer
    /// takes its ids from `budget`. When they would not fit, it lists the
    /// whole epochs that do, and its epoch is the last of them, so the
    /// cell asks again from there (NOTE 5, [`MAX_AFFECTED_ACCOUNTS`]).
    fn answer_in(
        &self,
        facts: &Facts,
        q: &Query,
        epoch: u64,
        with_provisional: bool,
        budget: &mut usize,
    ) -> WireAnswer {
        match q {
            Query::ChangedSince { epoch: since } => {
                let (set, cut) = self.changed_since(*since, with_provisional, *budget);
                *budget = budget.saturating_sub(set.len());
                let accounts: Vec<WireAccount> = set.into_iter().collect();
                WireAnswer {
                    holds: !accounts.is_empty(),
                    accounts: Some(accounts),
                    epoch: cut.unwrap_or(epoch),
                }
            }
            _ => WireAnswer {
                holds: facts.holds(q, &self.p17),
                accounts: None,
                epoch,
            },
        }
    }

    fn open(&mut self, fact: Fact, at: i64, affected: BTreeSet<WireAccount>) -> Option<u64> {
        let epoch = self.effective().checked_add(1)?;
        let proposal = eval::consent_proposal(&fact);
        self.provisional = Some(Provisional {
            epoch,
            fact,
            affected,
            proposal,
            opened_at: at,
        });
        Some(epoch)
    }
}

/// An event the vault emits after a write or an acknowledgement.
///
/// A write that queues behind the provisional one emits no event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultEvent {
    /// A provisional epoch was opened.
    Provisional {
        /// The epoch.
        epoch: u64,
    },
    /// An epoch became effective.
    Effective {
        /// The epoch.
        epoch: u64,
    },
}

/// The claims of a release ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseClaims {
    /// The signed ticket bytes, presented on `POST /r`.
    pub ticket: Vec<u8>,
}

/// An ask (design section 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask<'a> {
    /// The provisional epoch this ask reacts to, if it is a reaction.
    pub reaction_for: Option<u64>,
    /// The queries.
    pub queries: &'a [WireQuery],
}

/// The cell's acknowledgement of its reaction (NOTE 4 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckMsg {
    /// The epoch.
    pub epoch: u64,
    /// The ledger sequence of the reaction.
    pub ledger_seq: u64,
    /// The chain link of the reaction.
    pub link: [u8; 32],
}

/// Why a vault core operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreError {
    /// The vault refused.
    Refused(VaultRefusal),
    /// Kept so the W1 harness that names it still compiles. No operation
    /// of this crate returns it.
    NotImplemented(&'static str),
}

impl From<VaultRefusal> for CoreError {
    fn from(r: VaultRefusal) -> Self {
        CoreError::Refused(r)
    }
}

const fn refused(r: VaultRefusal) -> CoreError {
    CoreError::Refused(r)
}

/// Pins the vault's cell id and the cell's current and next ticket public
/// keys (provisioning, design section 6.5). A later call replaces both,
/// which is how a key rotation lands.
///
/// # Errors
///
/// [`VaultRefusal::Malformed`] for no key or more than
/// [`MAX_PINNED_KEYS`].
pub fn provision(s: &mut VaultState, cell: [u8; 16], pinned: &[[u8; 32]]) -> Result<(), CoreError> {
    if pinned.is_empty() || pinned.len() > MAX_PINNED_KEYS {
        return Err(refused(VaultRefusal::Malformed));
    }
    s.cell = Some(cell);
    s.pinned = pinned.to_vec();
    Ok(())
}

/// Sets the P-17 countries of `programme` (NOTE 6). The country never
/// leaves the vault; only the one-bit answer does.
///
/// Readings, reported to Daniel:
///
/// - The condition is fixed once set, since a change would flip
///   `MeetsTieBreakCountry` answers outside the NOTE 4 protocol. Setting
///   the same condition again is accepted and changes nothing.
/// - It can be set only while no country is stated for the programme, in
///   any epoch, provisional or queued write. Until a country is stated,
///   every answer for the programme is no with or without a condition. So
///   setting it flips no answer, and only `CountryStated` epochs do.
/// - Where the condition comes from (an internal request or a
///   provisioning input) is open. `fstp-vault` persists it.
///
/// # Errors
///
/// [`VaultRefusal::Malformed`] for a different condition, a first
/// condition after a country was stated for the programme, or more than
/// [`MAX_P17_COUNTRIES`] countries.
pub fn set_p17(
    s: &mut VaultState,
    programme: WireProgramme,
    countries: &BTreeSet<u16>,
) -> Result<(), CoreError> {
    if countries.len() > MAX_P17_COUNTRIES {
        return Err(refused(VaultRefusal::Malformed));
    }
    match s.p17.get(&programme) {
        Some(old) if old != countries => Err(refused(VaultRefusal::Malformed)),
        Some(_) => Ok(()),
        None if s.tail.has_country_for(programme) => Err(refused(VaultRefusal::Malformed)),
        None => {
            s.p17.insert(programme, countries.clone());
            Ok(())
        }
    }
}

/// Whether a negotiation fact at ledger sequence `seq` is newer than any
/// the vault holds for `proposal`.
fn newer(s: &VaultState, proposal: WireProposal, seq: u64) -> bool {
    s.negotiation_seq
        .get(&proposal)
        .is_none_or(|old| seq > *old)
}

/// Records the negotiation fact the cell pushes at ledger sequence `seq`
/// when `proposal` enters NEGOTIATION (`NegotiationOpened`, ADR-009
/// "Releases").
///
/// The vault keeps the highest sequence it saw per proposal, opened or
/// closed. A fact at that sequence or an older one is a retry or a stale
/// message. It changes nothing and returns `false`, so a stale open never
/// reopens a closed negotiation. A newer open replaces the account set.
///
/// # Errors
///
/// [`VaultRefusal::Malformed`] for more than
/// [`MAX_NEGOTIATION_ACCOUNTS`] accounts.
pub fn negotiation_opened(
    s: &mut VaultState,
    proposal: WireProposal,
    accounts: &BTreeSet<WireAccount>,
    seq: u64,
) -> Result<bool, CoreError> {
    if accounts.len() > MAX_NEGOTIATION_ACCOUNTS {
        return Err(refused(VaultRefusal::Malformed));
    }
    if !newer(s, proposal, seq) {
        return Ok(false);
    }
    s.negotiation.insert(proposal, accounts.clone());
    s.negotiation_seq.insert(proposal, seq);
    Ok(true)
}

/// Removes the negotiation fact of `proposal`, which the cell closed at
/// ledger sequence `seq` (`NegotiationClosed`). A close at the highest
/// sequence seen or an older one changes nothing and returns `false`.
pub fn negotiation_closed(s: &mut VaultState, proposal: WireProposal, seq: u64) -> bool {
    if !newer(s, proposal, seq) {
        return false;
    }
    s.negotiation.remove(&proposal);
    s.negotiation_seq.insert(proposal, seq);
    true
}

/// Takes a fact write at `now` (NOTE 4 step 1). It becomes provisional at
/// a new epoch when none is outstanding, and queues otherwise.
///
/// # Errors
///
/// [`VaultRefusal::Malformed`] for an unknown kind or a body that is not
/// the kind's canonical body. [`VaultRefusal::Unavailable`] when
/// [`MAX_QUEUED_WRITES`] writes already queue, or the epoch counter is
/// exhausted. A refused write takes no epoch.
pub fn write(s: &mut VaultState, w: FactWrite, now: i64) -> Result<Vec<VaultEvent>, CoreError> {
    let fact = decode_fact(w.kind, &w.body).map_err(|_| refused(VaultRefusal::Malformed))?;
    write_fact(s, fact, now)
}

/// Takes a typed fact write at `now`, as [`write`] does.
///
/// # Errors
///
/// As [`write`], except that the fact is already typed.
pub fn write_fact(s: &mut VaultState, fact: Fact, now: i64) -> Result<Vec<VaultEvent>, CoreError> {
    if fact.body().is_err() || self_verification(&s.tail, &fact) {
        return Err(refused(VaultRefusal::Malformed));
    }
    if s.provisional.is_some() && s.queue.len() >= MAX_QUEUED_WRITES {
        return Err(refused(VaultRefusal::Unavailable));
    }
    // The write opens over the facts after every write ahead of it, so
    // its accounts are known now (NOTE 4 step 2).
    let affected = s.tail.touched(&fact);
    if affected.len() > MAX_AFFECTED_ACCOUNTS {
        return Err(refused(VaultRefusal::Unavailable));
    }
    if s.provisional.is_some() {
        s.tail.apply(&fact);
        s.queue.push_back(Queued {
            fact,
            at: now,
            affected,
        });
        return Ok(Vec::new());
    }
    let tail = s.tail.after(&fact);
    match s.open(fact, now, affected) {
        Some(epoch) => {
            s.tail = tail;
            Ok(vec![VaultEvent::Provisional { epoch }])
        }
        None => Err(refused(VaultRefusal::Unavailable)),
    }
}

/// Whether `f` is a verification its verifier records for an account of
/// their own identity (design section 6.7, ADR-008 guard). Over `facts`,
/// the newest facts, the verifier must not be the account, nor share the
/// person the record shows or the account's current person.
fn self_verification(facts: &Facts, f: &Fact) -> bool {
    match f {
        Fact::VerificationRecorded {
            account,
            person,
            record,
        } => {
            let verifier = facts.person_of(record.verifier);
            record.verifier == *account
                || verifier == Some(*person)
                || verifier.is_some_and(|v| facts.person_of(*account) == Some(v))
        }
        _ => false,
    }
}

/// Answers queries outside a reaction (NOTE 3, NOTE 4 step 3).
///
/// # Errors
///
/// As [`ask_request`] with no reaction epoch.
pub fn ask(s: &VaultState, queries: &[WireQuery]) -> Result<Vec<WireAnswer>, CoreError> {
    ask_request(
        s,
        &Ask {
            reaction_for: None,
            queries,
        },
    )
}

/// Answers an ask (NOTE 3, NOTE 4 step 3, design section 6.3).
///
/// - A reaction ask (`reaction_for` set) must name the provisional epoch.
///   It sees the provisional fact, and its answers carry that epoch.
/// - Any other ask is refused as pending when one query names an account
///   the provisional write touches. Otherwise it is answered over the
///   effective facts at the effective epoch.
///
/// Every answer is one bit, except `ChangedSince`, which lists account
/// ids in ascending order (NOTE 5). The ids of one ask total at most
/// [`MAX_AFFECTED_ACCOUNTS`]. A `ChangedSince` answer that would pass that
/// lists only the whole epochs that fit. Its epoch is then the last epoch
/// it lists, lower than the other answers', and the cell asks again from
/// there. A single epoch always fits, since no write touches more.
///
/// # Errors
///
/// [`VaultRefusal::Malformed`] when any query does not decode, or there
/// are more than [`MAX_QUERIES`]. [`VaultRefusal::StaleEpoch`] for a
/// reaction ask that names another epoch. [`VaultRefusal::Pending`] as
/// above.
pub fn ask_request(s: &VaultState, req: &Ask<'_>) -> Result<Vec<WireAnswer>, CoreError> {
    ask_bounded(s, req, MAX_AFFECTED_ACCOUNTS)
}

/// Answers an ask as [`ask_request`] does, with at most `max_accounts`
/// ids over all answers, and never more than [`MAX_AFFECTED_ACCOUNTS`]. A
/// smaller bound shows the cut of a `ChangedSince` answer on a few epochs.
///
/// # Errors
///
/// As [`ask_request`].
pub fn ask_bounded(
    s: &VaultState,
    req: &Ask<'_>,
    max_accounts: usize,
) -> Result<Vec<WireAnswer>, CoreError> {
    if req.queries.len() > MAX_QUERIES {
        return Err(refused(VaultRefusal::Malformed));
    }
    let mut queries = Vec::with_capacity(req.queries.len());
    for q in req.queries {
        queries.push(decode_query(q).map_err(|_| refused(VaultRefusal::Malformed))?);
    }
    // The account ids of every answer share one budget, so the response
    // stays within what the cell decodes (NOTE 5).
    let mut budget = max_accounts.min(MAX_AFFECTED_ACCOUNTS);
    match req.reaction_for {
        Some(e) => match &s.provisional {
            Some(p) if p.epoch == e => {
                let facts = s.reaction_facts();
                Ok(queries
                    .iter()
                    .map(|q| s.answer_in(&facts, q, e, true, &mut budget))
                    .collect())
            }
            _ => Err(refused(VaultRefusal::StaleEpoch {
                current: s.current(),
            })),
        },
        None => {
            if let Some(epoch) = queries.iter().find_map(|q| s.pending_for(q)) {
                return Err(refused(VaultRefusal::Pending { epoch }));
            }
            let epoch = s.effective();
            Ok(queries
                .iter()
                .map(|q| s.answer_in(&s.facts, q, epoch, false, &mut budget))
                .collect())
        }
    }
}

/// Records the cell's acknowledgement of `epoch` with its reaction at
/// `ledger_seq`, with no chain link (NOTE 4 step 5).
///
/// # Errors
///
/// As [`ack_request`].
pub fn ack(s: &mut VaultState, epoch: u64, ledger_seq: u64) -> Result<Vec<VaultEvent>, CoreError> {
    ack_with(s, epoch, ledger_seq, None)
}

/// Records the cell's acknowledgement (NOTE 4 step 5). The provisional
/// fact becomes effective and the next queued write becomes provisional.
/// A repeated acknowledgement of an effective epoch is accepted and
/// changes nothing; the first sequence and link stay.
///
/// # Errors
///
/// [`VaultRefusal::StaleEpoch`] for an epoch that is neither provisional
/// nor effective.
pub fn ack_request(s: &mut VaultState, a: &AckMsg) -> Result<Vec<VaultEvent>, CoreError> {
    ack_with(s, a.epoch, a.ledger_seq, Some(a.link))
}

fn ack_with(
    s: &mut VaultState,
    epoch: u64,
    ledger_seq: u64,
    link: Option<[u8; 32]>,
) -> Result<Vec<VaultEvent>, CoreError> {
    let current = s.current();
    match s.provisional.take() {
        Some(p) if p.epoch == epoch => {
            s.facts.apply(&p.fact);
            s.log.push(EffectiveEpoch {
                epoch,
                fact: p.fact,
                affected: p.affected,
                ack_seq: ledger_seq,
                ack_link: link,
                opened_at: p.opened_at,
            });
            let mut out = vec![VaultEvent::Effective { epoch }];
            // The epoch counter cannot run out before 2^64 writes, so the
            // next queued write always opens.
            if let Some(next) = s.queue.pop_front()
                && let Some(e) = s.open(next.fact, next.at, next.affected)
            {
                out.push(VaultEvent::Provisional { epoch: e });
            }
            Ok(out)
        }
        other => {
            s.provisional = other;
            if epoch >= 1 && epoch <= s.effective() {
                Ok(Vec::new())
            } else {
                Err(refused(VaultRefusal::StaleEpoch { current }))
            }
        }
    }
}

/// Whether a release ticket may be honoured now (I-17, design section
/// 6.5): [`check_ticket`] on the release route, then [`release_guard`].
/// Single use is checked by the service, which holds `vault.ticket_used`.
///
/// # Errors
///
/// [`VaultRefusal::NotThisCell`] for a ticket of another cell,
/// [`VaultRefusal::Unavailable`] for an unprovisioned vault, and
/// [`VaultRefusal::Malformed`] for every other refusal. The service uses
/// [`check_ticket`] and [`release_guard`] for the typed reason.
pub fn release_allowed(s: &VaultState, t: &ReleaseClaims, now: i64) -> Result<(), CoreError> {
    let to_core = |r: TicketRefusal| {
        refused(match r {
            TicketRefusal::ForeignCell => VaultRefusal::NotThisCell,
            TicketRefusal::Unprovisioned => VaultRefusal::Unavailable,
            _ => VaultRefusal::Malformed,
        })
    };
    let c = check_ticket(s, &t.ticket, Route::Release, now).map_err(to_core)?;
    release_guard(s, &c).map_err(to_core)
}
