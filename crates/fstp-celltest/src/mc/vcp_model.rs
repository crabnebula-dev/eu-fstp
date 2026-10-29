//! M-VCP (design section 14.2): the vault commit protocol of NOTE 4 with
//! I-04, I-06 and I-18 over effective facts. Lane W1c owns this file.
//!
//! The universe:
//!
//! - Accounts A and B of one person, C, and the guardian G. At genesis A
//!   holds a Judging role in P1, and A, C and G are verified through the
//!   NOTE 4 protocol, each with its reaction and acknowledgement.
//! - Three facts written during the run, each once and in any order: V1,
//!   the provisional verification of B that reveals B and A as one person;
//!   F1, C's affiliation in the excluded class K1; G1, G's consent for
//!   proposal PR1 of lead C. C has no over-18 attestation, so PR1 is
//!   minor-flagged (state-machine NOTE 14).
//! - One applicant command per account: B and C each take a Receiving
//!   binding in P1, and C's PR1 asks the NEGOTIATION gate.
//! - The cell's reaction to each new epoch and its acknowledgement. One
//!   lost acknowledgement, one duplicated acknowledgement, one crash of the
//!   cell (the acknowledgement in flight is lost) and one crash of the
//!   vault (it records the acknowledgement, and the reply is lost).
//!
//! The vault runs over a [`VcpVault`] backend. [`Reference`] answers from
//! `reference::vault`. [`Production`] drives `fstp_vault_core`, through the
//! encodings of `reference::vault::wire`. [`Mutant`] seeds one vault
//! defect for the teeth tests. The cell is this model's transcription of
//! the cell's NOTE 4 duties: react in one step, append the reaction, then
//! acknowledge it, and acknowledge again at restart. [`CellDefect`] seeds
//! the cell defect of the design row. `DriverCore`'s own NOTE 4 duties
//! are checked against production in M-DRIVER (`mc::driver_model`).
//!
//! Deviation from design section 14.2, reported to Daniel: the design row
//! has M-VCP drive `fstp-vault-core`, `DriverCore` and `fstp-cell-core`.
//! Here only the vault side is production. The I-04 and I-06 voiding of
//! the reaction and the join and gate decisions are this model's own, so
//! the production reaction decide is not model checked here. A production
//! cell backend that runs the reaction, `Join` and `Gate` through
//! `DriverCore` and `fstp_cell_core::decide` follows once lane W2c lands
//! them, together with a reaction ask that names its epoch (see
//! [`REACTION_ASK_SEAM`]).
//!
//! Effective facts are the vault's own: the backend reports its effective
//! epoch, and the facts are those of the writes up to that epoch. A
//! backend that answers `NotImplemented` halts the run in a state that
//! only the `backend-answers` property reports.

use std::collections::BTreeSet;

use fstp_domain::id::{AccountId, ClassId, ProgrammeId, ProposalId, VaultEpoch};
use fstp_domain::oracle::Query;
use fstp_domain::policy::ExclusionClasses;
use fstp_domain::time::Timestamp;
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::reference::vault::{self as rv, RefAnswer, RefRefusal, RefVault, RefWrite, wire};

// ---------------------------------------------------------------------------
// The universe.

/// Account A: verified at genesis, holds a Judging role in P1.
pub const A: AccountId = AccountId::from_raw(101);
/// Account B: A's person, revealed by V1.
pub const B: AccountId = AccountId::from_raw(102);
/// Account C: verified at genesis, lead of PR1.
pub const C: AccountId = AccountId::from_raw(103);
/// Account G: the guardian of PR1, verified at genesis.
pub const G: AccountId = AccountId::from_raw(104);
/// The person of A and B.
pub const PERSON_AB: rv::Person = rv::Person(1_001);
/// The person of C.
pub const PERSON_C: rv::Person = rv::Person(1_003);
/// The person of G.
pub const PERSON_G: rv::Person = rv::Person(1_004);
/// The programme.
pub const P1: ProgrammeId = ProgrammeId::from_raw(1);
/// The excluded class of P-13 in P1.
pub const K1: ClassId = ClassId::from_raw(1);
/// The organisation of F1.
pub const ORG_F1: rv::Org = rv::Org(31);
/// C's proposal.
pub const PR1: ProposalId = ProposalId::from_raw(1);
/// The deadline of PR1's call.
pub const DEADLINE: Timestamp = Timestamp::from_micros(4_000_000_000_000);
/// The instant of every vault write.
pub const NOW: Timestamp = Timestamp::from_micros(1_000_000);
/// The number of epochs genesis makes effective.
pub const GENESIS_EPOCHS: u64 = 3;
/// The cell ledger length at genesis: A's binding and three reactions.
pub const GENESIS_LEDGER: u64 = 4;

/// A fact written during the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fact {
    /// The verification of B that reveals B and A as one person.
    V1,
    /// C's affiliation in the excluded class K1.
    F1,
    /// G's consent for PR1.
    G1,
}

impl Fact {
    /// Every fact.
    pub const ALL: [Fact; 3] = [Fact::V1, Fact::F1, Fact::G1];

    /// The write of the fact.
    pub fn write(self) -> RefWrite {
        match self {
            Fact::V1 => RefWrite::VerificationRecorded {
                account: B,
                person: PERSON_AB,
            },
            Fact::F1 => RefWrite::AffiliationDeclared {
                account: C,
                org: ORG_F1,
                class: Some(K1),
            },
            Fact::G1 => RefWrite::GuardianConsent {
                proposal: PR1,
                guardian: G,
            },
        }
    }
}

/// The vault history of genesis: three verifications, each acknowledged
/// with the sequence of its reaction.
pub fn genesis_history() -> Vec<VOp> {
    vec![
        VOp::Write(RefWrite::VerificationRecorded {
            account: A,
            person: PERSON_AB,
        }),
        VOp::Ack { epoch: 1, seq: 2 },
        VOp::Write(RefWrite::VerificationRecorded {
            account: C,
            person: PERSON_C,
        }),
        VOp::Ack { epoch: 2, seq: 3 },
        VOp::Write(RefWrite::VerificationRecorded {
            account: G,
            person: PERSON_G,
        }),
        VOp::Ack { epoch: 3, seq: 4 },
    ]
}

/// The classes the cell enforces in P1.
pub fn classes() -> ExclusionClasses {
    ExclusionClasses(BTreeSet::from([K1]))
}

/// The queries of an account's Receiving binding (NOTE 1: the candidate
/// set is the Judging holder A).
pub fn join_queries(x: AccountId) -> Vec<Query> {
    vec![
        Query::SameIdentityAsAny {
            subject: x,
            others: BTreeSet::from([A]),
        },
        Query::InExcludedClass {
            account: x,
            programme: P1,
            classes: classes(),
        },
    ]
}

/// The queries of the NEGOTIATION gate for PR1 (state-machine NOTE 14).
pub fn gate_queries() -> Vec<Query> {
    vec![
        Query::IsVerifiedAdultAtDeadline {
            account: C,
            deadline: DEADLINE,
        },
        Query::HasGuardianConsent { proposal: PR1 },
    ]
}

/// The chain link of the reaction at `seq`. The model does not hash.
pub fn link_of(seq: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (slot, b) in out.iter_mut().zip(seq.to_be_bytes().iter()) {
        *slot = *b;
    }
    out
}

// ---------------------------------------------------------------------------
// Backends.

/// One vault operation that changes the vault.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VOp {
    /// A fact write.
    Write(RefWrite),
    /// An acknowledgement.
    Ack {
        /// The epoch.
        epoch: u64,
        /// The ledger sequence of the reaction.
        seq: u64,
    },
}

/// The vault's reply to an ask.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AskReply {
    /// The answers, in query order.
    Answered(Vec<RefAnswer>),
    /// Refused: a provisional epoch touches the query (NOTE 4).
    Pending(u64),
    /// Refused: the epoch named is not the provisional one.
    Stale(u64),
    /// Any other refusal. The cell fails closed (NOTE 2).
    Fault,
}

/// What the vault reports after a history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Epochs {
    /// The effective epoch.
    pub effective: u64,
    /// The epoch the vault reports to the cell: the provisional one while
    /// one is outstanding.
    pub current: u64,
}

/// A vault under M-VCP. Each call replays `history` from an empty vault.
pub trait VcpVault {
    /// The epochs after `history`.
    fn epochs(&self, history: &[VOp]) -> Result<Epochs, NotImplemented>;

    /// The reply to an ask after `history`.
    fn ask(
        &self,
        history: &[VOp],
        reaction_for: Option<u64>,
        queries: &[Query],
    ) -> Result<AskReply, NotImplemented>;

    /// Whether the vault accepts the acknowledgement after `history`.
    fn ack(&self, history: &[VOp], epoch: u64, seq: u64) -> Result<bool, NotImplemented>;
}

fn reply(r: Result<Vec<RefAnswer>, RefRefusal>) -> AskReply {
    match r {
        Ok(a) => AskReply::Answered(a),
        Err(RefRefusal::Pending { epoch }) => AskReply::Pending(epoch),
        Err(RefRefusal::StaleEpoch { current }) => AskReply::Stale(current),
    }
}

/// The reference vault after `history`.
pub fn reference_vault(history: &[VOp]) -> RefVault {
    let mut v = RefVault::default();
    for op in history {
        match op {
            VOp::Write(w) => {
                v.write(w.clone());
            }
            VOp::Ack { epoch, seq } => {
                let _ = v.ack(*epoch, *seq, link_of(*seq));
            }
        }
    }
    v
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl VcpVault for Reference {
    fn epochs(&self, history: &[VOp]) -> Result<Epochs, NotImplemented> {
        let v = reference_vault(history);
        Ok(Epochs {
            effective: v.effective(),
            current: v.current(),
        })
    }

    fn ask(
        &self,
        history: &[VOp],
        reaction_for: Option<u64>,
        queries: &[Query],
    ) -> Result<AskReply, NotImplemented> {
        Ok(reply(reference_vault(history).ask(reaction_for, queries)))
    }

    fn ack(&self, history: &[VOp], epoch: u64, seq: u64) -> Result<bool, NotImplemented> {
        Ok(reference_vault(history)
            .ack(epoch, seq, link_of(seq))
            .is_ok())
    }
}

/// The seam of [`Production::ask`] for a reaction ask:
/// `fstp_vault_core::ask` takes no `at` and no `reaction_for` (design
/// section 6.3 names `ask(s, req: &Ask)`), so a reaction cannot see the
/// provisional fact through it (lane W2d).
///
/// API request to lane W2d: `fstp_vault_core::ask` takes the reaction
/// epoch (`reaction_for`). Once it does, [`Production::ask`] passes it
/// through and this seam goes.
pub const REACTION_ASK_SEAM: &str = "fstp_celltest::mc::vcp_model::Production::ask: fstp_vault_core::ask takes no reaction_for, so no reaction ask reaches the provisional fact (design section 6.3, lane W2d)";

/// The halt of [`production_vault`] when `fstp_vault_core::write` refuses a
/// fact write. The reference never refuses one (it queues), and the model
/// gives the k-th written fact an epoch by its place in
/// [`VcpState::written`], so a refused write would shift every later
/// epoch. The run halts, and the `backend-answers` property reports it.
pub const WRITE_REFUSED: &str = "fstp_celltest::mc::vcp_model::production_vault: fstp_vault_core::write refused an M-VCP fact write, which the reference queues (NOTE 4 step 1)";

/// The production backend: `fstp_vault_core` over the encodings of
/// `reference::vault::wire`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Production;

fn core_ni(
    e: fstp_vault_core::CoreError,
) -> Result<fstp_vault_proto::VaultRefusal, NotImplemented> {
    match e {
        fstp_vault_core::CoreError::NotImplemented(op) => Err(NotImplemented::new(op)),
        fstp_vault_core::CoreError::Refused(r) => Ok(r),
    }
}

/// The production vault state after `history`, with its reported epochs.
/// The current epoch is read from the events, since `VaultState` shows
/// only the effective one.
///
/// # Errors
///
/// The first `NotImplemented` of the vault core.
pub fn production_vault(
    history: &[VOp],
) -> Result<(fstp_vault_core::VaultState, Epochs), NotImplemented> {
    let mut s = fstp_vault_core::VaultState::default();
    let mut provisional: Option<u64> = None;
    let track = |events: &[fstp_vault_core::VaultEvent], provisional: &mut Option<u64>| {
        for e in events {
            match e {
                fstp_vault_core::VaultEvent::Provisional { epoch } => *provisional = Some(*epoch),
                fstp_vault_core::VaultEvent::Effective { epoch } => {
                    if *provisional == Some(*epoch) {
                        *provisional = None;
                    }
                }
            }
        }
    };
    for op in history {
        match op {
            VOp::Write(w) => {
                match fstp_vault_core::write(&mut s, wire::fact_write(w), NOW.micros()) {
                    Ok(events) => track(&events, &mut provisional),
                    Err(e) => {
                        core_ni(e)?;
                        return Err(NotImplemented::new(WRITE_REFUSED));
                    }
                }
            }
            VOp::Ack { epoch, seq } => match fstp_vault_core::ack(&mut s, *epoch, *seq) {
                Ok(events) => track(&events, &mut provisional),
                Err(e) => {
                    core_ni(e)?;
                }
            },
        }
    }
    let effective = s.effective();
    let current = provisional.filter(|p| *p > effective).unwrap_or(effective);
    Ok((s, Epochs { effective, current }))
}

impl VcpVault for Production {
    fn epochs(&self, history: &[VOp]) -> Result<Epochs, NotImplemented> {
        Ok(production_vault(history)?.1)
    }

    fn ask(
        &self,
        history: &[VOp],
        reaction_for: Option<u64>,
        queries: &[Query],
    ) -> Result<AskReply, NotImplemented> {
        let (s, _) = production_vault(history)?;
        if reaction_for.is_some() {
            return Err(NotImplemented::new(REACTION_ASK_SEAM));
        }
        let wq: Vec<fstp_vault_proto::WireQuery> = queries.iter().map(wire::query).collect();
        match fstp_vault_core::ask(&s, &wq) {
            Ok(answers) => Ok(AskReply::Answered(
                answers.iter().map(wire::answer).collect(),
            )),
            Err(e) => Ok(match core_ni(e)? {
                fstp_vault_proto::VaultRefusal::Pending { epoch } => AskReply::Pending(epoch),
                fstp_vault_proto::VaultRefusal::StaleEpoch { current } => AskReply::Stale(current),
                _ => AskReply::Fault,
            }),
        }
    }

    fn ack(&self, history: &[VOp], epoch: u64, seq: u64) -> Result<bool, NotImplemented> {
        let (mut s, _) = production_vault(history)?;
        match fstp_vault_core::ack(&mut s, epoch, seq) {
            Ok(_) => Ok(true),
            Err(e) => core_ni(e).map(|_| false),
        }
    }
}

/// A vault defect a teeth test seeds (design section 14.2, M-VCP row).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VaultDefect {
    /// The vault answers a non-reaction query while a provisional fact
    /// touches it, over the effective facts.
    AnswersWhileProvisional,
    /// A fact becomes effective at its write, with no acknowledgement.
    EffectiveWithoutAck,
    /// A provisional consent counts for `HasGuardianConsent` (I-18).
    ProvisionalConsentCounted,
}

/// The reference vault with one seeded defect.
#[derive(Clone, Copy, Debug)]
pub struct Mutant {
    /// The defect.
    pub defect: VaultDefect,
}

impl Mutant {
    fn vault(&self, history: &[VOp]) -> RefVault {
        if self.defect != VaultDefect::EffectiveWithoutAck {
            return reference_vault(history);
        }
        let mut v = RefVault::default();
        for op in history {
            if let VOp::Write(w) = op {
                v.write(w.clone());
                if let Some(p) = v.provisional().map(|p| p.epoch) {
                    let _ = v.ack(p, 0, [0; 32]);
                }
            }
        }
        v
    }
}

impl VcpVault for Mutant {
    fn epochs(&self, history: &[VOp]) -> Result<Epochs, NotImplemented> {
        let v = self.vault(history);
        Ok(Epochs {
            effective: v.effective(),
            current: v.current(),
        })
    }

    fn ask(
        &self,
        history: &[VOp],
        reaction_for: Option<u64>,
        queries: &[Query],
    ) -> Result<AskReply, NotImplemented> {
        let v = self.vault(history);
        if reaction_for.is_some() {
            return Ok(reply(v.ask(reaction_for, queries)));
        }
        match self.defect {
            VaultDefect::AnswersWhileProvisional => Ok(AskReply::Answered(
                queries.iter().map(|q| v.eval_effective(q)).collect(),
            )),
            VaultDefect::ProvisionalConsentCounted => {
                let rest: Vec<Query> = queries
                    .iter()
                    .filter(|q| !matches!(q, Query::HasGuardianConsent { .. }))
                    .cloned()
                    .collect();
                if let Err(e) = v.ask(None, &rest) {
                    return Ok(reply(Err(e)));
                }
                Ok(AskReply::Answered(
                    queries
                        .iter()
                        .map(|q| match q {
                            Query::HasGuardianConsent { .. } => {
                                let mut a = v.eval_with_provisional(q);
                                a.epoch = v.effective();
                                a
                            }
                            _ => v.eval_effective(q),
                        })
                        .collect(),
                ))
            }
            VaultDefect::EffectiveWithoutAck => Ok(reply(v.ask(None, queries))),
        }
    }

    fn ack(&self, history: &[VOp], epoch: u64, seq: u64) -> Result<bool, NotImplemented> {
        Ok(self.vault(history).ack(epoch, seq, link_of(seq)).is_ok())
    }
}

/// The cell defect a teeth test seeds (design section 14.2, M-VCP row).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CellDefect {
    /// The driver acknowledges a reaction before the reaction commits.
    AckBeforeReaction,
}

// ---------------------------------------------------------------------------
// The model.

/// A Receiving binding of B or C in P1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Recv {
    /// None was taken.
    None,
    /// Held.
    Active,
    /// Voided by a reaction (I-04, I-06).
    Voided,
}

/// The state of PR1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pr1 {
    /// In IRC_REVIEW, every validation recorded.
    IrcReview,
    /// In NEGOTIATION.
    Negotiation,
}

/// The faults used so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Faults {
    /// One acknowledgement was lost.
    pub lost: bool,
    /// One acknowledgement was delivered twice.
    pub duplicated: bool,
    /// The cell crashed once.
    pub cell_crash: bool,
    /// The vault crashed once.
    pub vault_crash: bool,
}

/// A reaction the defective cell has acknowledged but not appended.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Unappended {
    /// The epoch.
    pub epoch: u64,
    /// The sequence it will take.
    pub seq: u64,
    /// The bindings it voids.
    pub voids: Vec<AccountId>,
}

/// One M-VCP state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VcpState {
    /// Every vault operation that changed the vault, from genesis.
    pub history: Vec<VOp>,
    /// The facts written in the run, in order. The k-th takes epoch
    /// [`GENESIS_EPOCHS`] plus k.
    pub written: Vec<Fact>,
    /// The vault's epochs after `history`.
    pub epochs: Epochs,
    /// B's Receiving binding.
    pub b: Recv,
    /// C's Receiving binding.
    pub c: Recv,
    /// PR1.
    pub pr1: Pr1,
    /// The reactions in the cell ledger: epoch and sequence.
    pub reactions: Vec<(u64, u64)>,
    /// The cell ledger length.
    pub ledger: u64,
    /// The acknowledgement the cell has in flight: epoch and sequence.
    pub inflight: Option<(u64, u64)>,
    /// A reaction acknowledged before it was appended (cell defect only).
    pub unappended: Option<Unappended>,
    /// The faults used.
    pub faults: Faults,
    /// Set when a backend answered `NotImplemented`. The state is terminal.
    pub halted: Option<String>,
}

impl VcpState {
    /// The facts the vault holds as effective.
    pub fn effective_facts(&self) -> Vec<Fact> {
        let n = self.epochs.effective.saturating_sub(GENESIS_EPOCHS);
        self.written
            .iter()
            .take(usize::try_from(n).unwrap_or(usize::MAX))
            .copied()
            .collect()
    }

    /// Whether `f` is effective.
    pub fn is_effective(&self, f: Fact) -> bool {
        self.effective_facts().contains(&f)
    }

    /// The newest epoch the cell has reacted to.
    pub fn processed(&self) -> u64 {
        self.reactions
            .iter()
            .map(|(e, _)| *e)
            .max()
            .unwrap_or(GENESIS_EPOCHS)
    }

    /// The sequence of the reaction to `epoch`, if the ledger holds one.
    pub fn reaction_seq(&self, epoch: u64) -> Option<u64> {
        self.reactions
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, s)| *s)
    }

    fn binding(&self, x: AccountId) -> Recv {
        if x == B { self.b } else { self.c }
    }

    fn set_binding(&mut self, x: AccountId, r: Recv) {
        if x == B {
            self.b = r;
        } else {
            self.c = r;
        }
    }
}

/// One M-VCP action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VcpAction {
    /// The vault takes a fact write.
    Write(Fact),
    /// The cell reacts to the newest epoch and appends the reaction.
    React,
    /// The cell takes a Receiving binding for B or C.
    Join(AccountId),
    /// PR1 asks the NEGOTIATION gate.
    Gate,
    /// The acknowledgement in flight reaches the vault.
    Deliver,
    /// The acknowledgement in flight reaches the vault twice.
    Duplicate,
    /// The acknowledgement in flight is lost.
    Lose,
    /// The cell crashes. The acknowledgement in flight is lost.
    CellCrash,
    /// The vault records the acknowledgement in flight, then crashes. The
    /// reply is lost.
    ///
    /// It adds no behaviour beyond [`VcpAction::Deliver`] today, since the
    /// model's cell does not read the reply. A crash that loses the
    /// acknowledgement before the vault records it is [`VcpAction::Lose`].
    /// The action stays so that a cell that reads the reply is checked
    /// against it.
    ///
    /// Gap: the model loses, duplicates and reorders no reaction ask. A
    /// lost ask fails the reaction closed (NOTE 2), and
    /// [`VcpAction::React`] stays enabled, so the retry is in the model.
    VaultCrash,
    /// At restart the cell finds a committed reaction to the provisional
    /// epoch and acknowledges it again (design section 5.2).
    Reack,
    /// The defective cell appends the reaction it acknowledged.
    AppendLate,
}

/// M-VCP over a vault backend.
#[derive(Clone, Debug)]
pub struct VcpModel<V> {
    vault: V,
    cell_defect: Option<CellDefect>,
}

impl<V: VcpVault> VcpModel<V> {
    /// The model over `vault` with a correct cell.
    pub fn new(vault: V) -> VcpModel<V> {
        VcpModel {
            vault,
            cell_defect: None,
        }
    }

    /// The model over `vault` with a defective cell.
    pub fn with_cell_defect(vault: V, defect: CellDefect) -> VcpModel<V> {
        VcpModel {
            vault,
            cell_defect: Some(defect),
        }
    }

    /// The vault backend.
    pub fn vault(&self) -> &V {
        &self.vault
    }

    fn halt(s: &VcpState, e: &NotImplemented) -> VcpState {
        let mut t = s.clone();
        t.halted = Some(e.operation.to_owned());
        t
    }

    fn refresh(&self, mut t: VcpState) -> VcpState {
        match self.vault.epochs(&t.history) {
            Ok(e) => {
                t.epochs = e;
                t
            }
            Err(e) => Self::halt(&t, &e),
        }
    }

    fn ask(
        &self,
        s: &VcpState,
        reaction_for: Option<u64>,
        queries: &[Query],
    ) -> Result<AskReply, Box<VcpState>> {
        self.vault
            .ask(&s.history, reaction_for, queries)
            .map_err(|e| Box::new(Self::halt(s, &e)))
    }

    /// The reaction to the newest epoch: the bindings it voids, or `None`
    /// when the vault did not answer (the cell fails closed).
    fn reaction(
        &self,
        s: &VcpState,
        reaction_for: Option<u64>,
    ) -> Result<Option<Vec<AccountId>>, Box<VcpState>> {
        let since = Query::ChangedSince {
            epoch: VaultEpoch::from_raw(s.processed()),
        };
        let changed = match self.ask(s, reaction_for, &[since])? {
            AskReply::Answered(a) => match a.first().and_then(|x| x.accounts.clone()) {
                Some(c) => c,
                None => return Ok(None),
            },
            _ => return Ok(None),
        };
        let mut voids = Vec::new();
        for x in [B, C] {
            if s.binding(x) != Recv::Active || !changed.contains(&x) {
                continue;
            }
            match self.ask(s, reaction_for, &join_queries(x))? {
                AskReply::Answered(a) => {
                    if a.iter().any(|y| y.holds) {
                        voids.push(x);
                    }
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(voids))
    }

    fn react(&self, s: &VcpState) -> Option<VcpState> {
        if s.inflight.is_some() || s.unappended.is_some() {
            return None;
        }
        let r = s.epochs.current;
        if r <= s.processed() {
            return None;
        }
        let provisional = r > s.epochs.effective;
        if provisional && s.reaction_seq(r).is_some() {
            return None;
        }
        let reaction_for = provisional.then_some(r);
        let voids = match self.reaction(s, reaction_for) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(halted) => return Some(*halted),
        };
        let mut t = s.clone();
        let seq = t.ledger.checked_add(1)?;
        if self.cell_defect == Some(CellDefect::AckBeforeReaction) && provisional {
            match self.vault.ack(&t.history, r, seq) {
                Ok(true) => t.history.push(VOp::Ack { epoch: r, seq }),
                Ok(false) => return None,
                Err(e) => return Some(Self::halt(s, &e)),
            }
            t.unappended = Some(Unappended {
                epoch: r,
                seq,
                voids,
            });
            return Some(self.refresh(t));
        }
        t.ledger = seq;
        t.reactions.push((r, seq));
        for x in voids {
            t.set_binding(x, Recv::Voided);
        }
        if provisional {
            t.inflight = Some((r, seq));
        }
        Some(t)
    }

    fn append_late(&self, s: &VcpState) -> Option<VcpState> {
        let u = s.unappended.clone()?;
        let mut t = s.clone();
        t.unappended = None;
        t.ledger = u.seq;
        t.reactions.push((u.epoch, u.seq));
        for x in u.voids {
            t.set_binding(x, Recv::Voided);
        }
        Some(t)
    }

    /// A command of the cell. The cell read the vault's epoch before the
    /// vault took any write it has not reacted to, so a provisional fact
    /// may arrive between that read and the ask. That race is the case
    /// NOTE 4 guards. The cell accepts answers only at the epoch it has
    /// processed (NOTE 3), and fails closed on any refusal (NOTE 2).
    fn command(&self, s: &VcpState, queries: &[Query]) -> Result<Option<Vec<bool>>, Box<VcpState>> {
        let processed = s.processed();
        if s.inflight.is_some() || s.unappended.is_some() || s.epochs.effective > processed {
            return Ok(None);
        }
        match self.ask(s, None, queries)? {
            AskReply::Answered(a) => {
                if a.len() != queries.len() || a.iter().any(|x| x.epoch != processed) {
                    return Ok(None);
                }
                Ok(Some(a.iter().map(|x| x.holds).collect()))
            }
            _ => Ok(None),
        }
    }

    fn join(&self, s: &VcpState, x: AccountId) -> Option<VcpState> {
        if s.binding(x) != Recv::None {
            return None;
        }
        let bits = match self.command(s, &join_queries(x)) {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(halted) => return Some(*halted),
        };
        if bits.iter().any(|b| *b) {
            return None;
        }
        let mut t = s.clone();
        t.ledger = t.ledger.checked_add(1)?;
        t.set_binding(x, Recv::Active);
        Some(t)
    }

    fn gate(&self, s: &VcpState) -> Option<VcpState> {
        if s.c != Recv::Active || s.pr1 != Pr1::IrcReview {
            return None;
        }
        let bits = match self.command(s, &gate_queries()) {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(halted) => return Some(*halted),
        };
        if !bits.iter().any(|b| *b) {
            return None;
        }
        let mut t = s.clone();
        t.ledger = t.ledger.checked_add(1)?;
        t.pr1 = Pr1::Negotiation;
        Some(t)
    }

    fn deliver(&self, s: &VcpState, times: u8) -> Option<VcpState> {
        let (epoch, seq) = s.inflight?;
        let mut t = s.clone();
        for _ in 0..times {
            match self.vault.ack(&t.history, epoch, seq) {
                Ok(true) => t.history.push(VOp::Ack { epoch, seq }),
                Ok(false) => {}
                Err(e) => return Some(Self::halt(s, &e)),
            }
        }
        t.inflight = None;
        Some(self.refresh(t))
    }
}

/// The state at genesis.
pub fn genesis<V: VcpVault>(vault: &V) -> VcpState {
    let mut s = VcpState {
        history: genesis_history(),
        written: Vec::new(),
        epochs: Epochs {
            effective: 0,
            current: 0,
        },
        b: Recv::None,
        c: Recv::None,
        pr1: Pr1::IrcReview,
        reactions: vec![(1, 2), (2, 3), (3, 4)],
        ledger: GENESIS_LEDGER,
        inflight: None,
        unappended: None,
        faults: Faults::default(),
        halted: None,
    };
    match vault.epochs(&s.history) {
        Ok(e) => s.epochs = e,
        Err(e) => s.halted = Some(e.operation.to_owned()),
    }
    s
}

impl<V: VcpVault> Model for VcpModel<V> {
    type State = VcpState;
    type Action = VcpAction;

    fn init(&self) -> Vec<VcpState> {
        vec![genesis(&self.vault)]
    }

    fn actions(&self, s: &VcpState, out: &mut Vec<VcpAction>) {
        if s.halted.is_some() {
            return;
        }
        for f in Fact::ALL {
            out.push(VcpAction::Write(f));
        }
        out.extend([
            VcpAction::React,
            VcpAction::Join(B),
            VcpAction::Join(C),
            VcpAction::Gate,
            VcpAction::Deliver,
            VcpAction::Duplicate,
            VcpAction::Lose,
            VcpAction::CellCrash,
            VcpAction::VaultCrash,
            VcpAction::Reack,
            VcpAction::AppendLate,
        ]);
    }

    fn step(&self, s: &VcpState, a: &VcpAction) -> Option<VcpState> {
        if s.halted.is_some() {
            return None;
        }
        match a {
            VcpAction::Write(f) => {
                if s.written.contains(f) {
                    return None;
                }
                let mut t = s.clone();
                t.history.push(VOp::Write(f.write()));
                t.written.push(*f);
                Some(self.refresh(t))
            }
            VcpAction::React => self.react(s),
            VcpAction::Join(x) => self.join(s, *x),
            VcpAction::Gate => self.gate(s),
            VcpAction::Deliver => self.deliver(s, 1),
            VcpAction::Duplicate => {
                if s.faults.duplicated {
                    return None;
                }
                let mut t = self.deliver(s, 2)?;
                t.faults.duplicated = true;
                Some(t)
            }
            VcpAction::Lose | VcpAction::CellCrash => {
                s.inflight?;
                let used = match a {
                    VcpAction::Lose => s.faults.lost,
                    _ => s.faults.cell_crash,
                };
                if used {
                    return None;
                }
                let mut t = s.clone();
                t.inflight = None;
                match a {
                    VcpAction::Lose => t.faults.lost = true,
                    _ => t.faults.cell_crash = true,
                }
                Some(t)
            }
            VcpAction::VaultCrash => {
                if s.faults.vault_crash {
                    return None;
                }
                let mut t = self.deliver(s, 1)?;
                t.faults.vault_crash = true;
                Some(t)
            }
            VcpAction::Reack => {
                if s.inflight.is_some() || s.unappended.is_some() {
                    return None;
                }
                let r = s.epochs.current;
                if r <= s.epochs.effective {
                    return None;
                }
                let seq = s.reaction_seq(r)?;
                let mut t = s.clone();
                t.inflight = Some((r, seq));
                Some(t)
            }
            VcpAction::AppendLate => self.append_late(s),
        }
    }

    fn is_terminal(&self, s: &VcpState) -> bool {
        s.halted.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property and witness ids of M-VCP.
pub mod ids {
    /// Every backend call answered.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-04 over effective facts.
    pub const I04: &str = "I-04";
    /// I-06 over effective facts.
    pub const I06: &str = "I-06";
    /// I-18 over effective consents.
    pub const I18: &str = "I-18";
    /// The NOTE 4 transition property.
    pub const NOTE4: &str = "NOTE-4";
    /// Witness: a fact becomes effective after its acknowledgement.
    pub const W_EFFECTIVE_AFTER_ACK: &str = "NOTE-4-witness-effective-after-ack";
    /// Witness: the reaction voids B's Receiving binding (I-06).
    pub const W_REACTION_VOIDS_B: &str = "I-06-witness-reaction-voids-b";
    /// Witness: the reaction voids C's Receiving binding (I-04).
    pub const W_REACTION_VOIDS_C: &str = "I-04-witness-reaction-voids-c";
    /// Witness: PR1 enters NEGOTIATION on an effective consent (I-18).
    pub const W_NEGOTIATION_WITH_CONSENT: &str = "I-18-witness-negotiation-with-consent";
}

/// The NOTE 4 transition check.
///
/// - The effective epoch grows only when an acknowledgement reaches the
///   vault, and only for epochs whose reaction the ledger held before.
/// - A command never commits while the reference finds one of its queries
///   pending: the vault must refuse it and the cell must fail closed.
fn note4(s: &VcpState, a: &VcpAction, t: &VcpState) -> Result<(), String> {
    if t.halted.is_some() {
        return Ok(());
    }
    if t.epochs.effective > s.epochs.effective {
        let acked = matches!(
            a,
            VcpAction::Deliver | VcpAction::Duplicate | VcpAction::VaultCrash
        );
        if !acked {
            return Err(format!(
                "NOTE-4: epoch {} became effective on {a:?}, which delivers no acknowledgement",
                t.epochs.effective
            ));
        }
        let mut e = s.epochs.effective.saturating_add(1);
        while e <= t.epochs.effective {
            if s.reaction_seq(e).is_none() {
                return Err(format!(
                    "NOTE-4: epoch {e} became effective before the ledger held its reaction"
                ));
            }
            e = e.saturating_add(1);
        }
    }
    let queries = match a {
        VcpAction::Join(x) => Some(join_queries(*x)),
        VcpAction::Gate => Some(gate_queries()),
        _ => None,
    };
    if let Some(q) = queries
        && t.ledger > s.ledger
        && let Err(RefRefusal::Pending { epoch }) = reference_vault(&s.history).ask(None, &q)
    {
        return Err(format!(
            "NOTE-4: {a:?} committed while provisional epoch {epoch} touches its queries"
        ));
    }
    Ok(())
}

/// Every M-VCP property and witness.
pub fn properties<V: VcpVault>(_m: &VcpModel<V>) -> Vec<Property<'static, VcpModel<V>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &VcpState| match &s.halted {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op} (NotImplemented)")),
        }),
        Property::always_with(ids::I04, |s: &VcpState| {
            if s.is_effective(Fact::F1) && s.c == Recv::Active {
                Err(
                    "I-04: C holds a Receiving binding with an effective excluded affiliation"
                        .to_owned(),
                )
            } else {
                Ok(())
            }
        }),
        Property::always_with(ids::I06, |s: &VcpState| {
            if s.is_effective(Fact::V1) && s.b == Recv::Active {
                Err("I-06: B holds a Receiving binding while its effective person also holds A's Judging binding".to_owned())
            } else {
                Ok(())
            }
        }),
        Property::always_with(ids::I18, |s: &VcpState| {
            if s.pr1 == Pr1::Negotiation && !s.is_effective(Fact::G1) {
                Err("I-18: minor-flagged PR1 is in NEGOTIATION without an effective verified guardian consent".to_owned())
            } else {
                Ok(())
            }
        }),
        Property::transition_with(ids::NOTE4, note4),
        Property::reachable(ids::W_EFFECTIVE_AFTER_ACK, |s: &VcpState| {
            s.halted.is_none() && s.epochs.effective > GENESIS_EPOCHS
        }),
        Property::reachable(ids::W_REACTION_VOIDS_B, |s: &VcpState| s.b == Recv::Voided),
        Property::reachable(ids::W_REACTION_VOIDS_C, |s: &VcpState| s.c == Recv::Voided),
        Property::reachable(ids::W_NEGOTIATION_WITH_CONSENT, |s: &VcpState| {
            s.pr1 == Pr1::Negotiation
        }),
    ]
}
