//! M-PREP (M4 design section 8.5, I-85, R-MC-05). Lane W3b owns this
//! file, and its test author wrote it.
//!
//! The universe holds two accounts, the programme manager [`OWNER`] and
//! the call drafter [`OTHER`], and one agent of the owner. It has three
//! operations:
//!
//! - one high-risk operation with a prepare-only tool, the publication of
//!   call 1;
//! - one binding operation under P-77 "draft only", the edit of call 2;
//! - one plain operation, the read of open calls.
//!
//! The actions are these:
//!
//! - the agent prepares an operation;
//! - the owner steps up in the main or a second session, for the stored
//!   digest or a foreign one;
//! - either account confirms, with the stored or a wrong digest;
//! - the owner discards;
//! - the clock moves past P-71, and past the pending lifetime;
//! - the owner revokes the agent;
//! - a tenant admin ends the owner's programme manager binding.
//!
//! Properties:
//!
//! - `always("I-85")`: production agrees with the reference after every
//!   step. Production is dispatch on a [`FakeCell`], replayed from the
//!   trace for every step. The reference is [`admitted`], written from
//!   design section 3.7 and `mcp-server.md`.
//! - After each step the driver checks every execution. A high-risk or
//!   draft-only binding operation executes only by a web confirmation of
//!   the same account. It carries the stored digest and names the pending
//!   action. A high-risk one carries the step-up proof taken for its
//!   digest. So each pending action executes at most once, and the
//!   executed request is the stored one.
//! - `transition("I-85")` and `transition("R-MC-05")`: the call is
//!   published, or edited, only by the owner's confirmation with the
//!   stored digest.
//! - Witnesses: a confirmed high-risk action, a confirmed binding action,
//!   an expired action, and a direct plain operation through MCP.
//!
//! Readings, interim, pending Daniel: confirming after the agent is revoked
//! may complete or be refused (the design does not say); discarding an
//! expired action may complete or be refused. The reference admits both in
//! these two cases only.
//!
//! The state holds the reference state and the trace that reached it.
//! Equality and hashing read the reference state only. So two traces that
//! reach the same reference state are one model state, and production is
//! checked along the first trace found. This bounds the run, at the cost
//! of not checking production's history dependence beyond what the
//! reference state captures.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use fstp_api_core::meta::Scope;
use fstp_api_core::pending::PENDING_LIFETIME_MICROS;
use fstp_api_core::port::{LoginMethod, PendingId};
use fstp_api_core::{ActionDigest, OpResult, PendingStatus};
use fstp_domain::Via;
use fstp_domain::command::Actor;
use fstp_domain_testkit::r#gen::roster::{self, staff_bindings};
use fstp_engine::Command;
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::fake::cell::{Class, class};
use crate::fake::fixture::{
    self, ADMIN, AGENT, CALL_EDIT, CALL_PUBLISH, OTHER, OWNER, P1, World, sample_edit,
};
use crate::fake::step_up::P71_MICROS;
use crate::fake::{FakeCell, WebLogin, requests};

/// The state count the model's first exhaustive run records, measured on
/// the reference backend on 2026-10-29. The run bound is twice this.
pub const TRIPWIRE: usize = 5_696;

/// What decides the model steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Production dispatch on a fake cell, checked against the reference.
    Production,
    /// The reference alone.
    Reference,
}

/// A fault the teeth test injects. None in the plain model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// No fault.
    None,
    /// Confirmation without the digest check. On production, an
    /// alternative adapter replaces a wrong shown digest with the stored
    /// one, as a confirm route that skips the check would. On the
    /// reference, the reference admits the wrong digest.
    ForgeShownDigest,
}

/// An operation the agent calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentOp {
    /// The prepare-only publication of call 1 (high-risk).
    Publish,
    /// The edit of call 2 (binding, P-77 "draft only").
    Edit,
    /// The read of open calls (plain).
    Plain,
}

/// A pending action of the universe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Which {
    /// The publication of call 1.
    Publish,
    /// The edit of call 2.
    Edit,
}

impl Which {
    const fn index(self) -> usize {
        match self {
            Which::Publish => 0,
            Which::Edit => 1,
        }
    }
}

/// A web session of the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Session {
    /// The session the owner confirms in.
    Main,
    /// A second session of the owner.
    Second,
}

/// The digest a step-up is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofFor {
    /// The stored digest of the publication.
    Publish,
    /// A digest of no pending action.
    Foreign,
}

/// Who confirms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Who {
    /// The owner, in the main session.
    Owner,
    /// The other account.
    Other,
}

/// The digest a confirmation carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Shown {
    /// The stored digest.
    Stored,
    /// Another digest.
    Wrong,
}

/// How far the clock moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Advance {
    /// P-71 plus 1 µs: every proof goes stale.
    PastFreshness,
    /// The pending lifetime plus 1 µs: every open action expires.
    PastExpiry,
}

impl Advance {
    const fn micros(self) -> i64 {
        match self {
            Advance::PastFreshness => P71_MICROS.saturating_add(1),
            Advance::PastExpiry => PENDING_LIFETIME_MICROS.saturating_add(1),
        }
    }
}

/// One action of M-PREP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrepAction {
    /// The agent calls the operation through MCP.
    Prepare(AgentOp),
    /// The owner completes a step-up in a session for a digest.
    StepUp(Session, ProofFor),
    /// An account confirms a pending action through the web.
    Confirm(Who, Which, Shown),
    /// The owner discards a pending action.
    Discard(Which),
    /// The clock moves.
    Advance(Advance),
    /// The owner revokes the agent (R-MC-03).
    Revoke,
    /// A tenant admin ends the owner's programme manager binding of P1.
    EndBinding,
}

/// Every action, in a fixed order.
pub const ACTIONS: [PrepAction; 18] = [
    PrepAction::Prepare(AgentOp::Publish),
    PrepAction::Prepare(AgentOp::Edit),
    PrepAction::Prepare(AgentOp::Plain),
    PrepAction::StepUp(Session::Main, ProofFor::Publish),
    PrepAction::StepUp(Session::Second, ProofFor::Publish),
    PrepAction::StepUp(Session::Main, ProofFor::Foreign),
    PrepAction::Confirm(Who::Owner, Which::Publish, Shown::Stored),
    PrepAction::Confirm(Who::Owner, Which::Publish, Shown::Wrong),
    PrepAction::Confirm(Who::Owner, Which::Edit, Shown::Stored),
    PrepAction::Confirm(Who::Owner, Which::Edit, Shown::Wrong),
    PrepAction::Confirm(Who::Other, Which::Publish, Shown::Stored),
    PrepAction::Confirm(Who::Other, Which::Edit, Shown::Stored),
    PrepAction::Discard(Which::Publish),
    PrepAction::Discard(Which::Edit),
    PrepAction::Advance(Advance::PastFreshness),
    PrepAction::Advance(Advance::PastExpiry),
    PrepAction::Revoke,
    PrepAction::EndBinding,
];

/// The outcome class the reference compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The call completed, or a port action ran.
    Done,
    /// The call became a pending action.
    Pending,
    /// The call needs a step-up.
    StepUpRequired,
    /// The call was refused.
    Refused,
}

/// A pending action in the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefPending {
    /// Its status.
    pub status: PendingStatus,
    /// Whether the clock moved past its lifetime.
    pub expired: bool,
}

impl RefPending {
    /// Whether it can still be confirmed.
    pub fn confirmable(&self) -> bool {
        self.status == PendingStatus::Open && !self.expired
    }
}

/// The reference state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ref {
    /// The pending actions, by [`Which`]. `None` until prepared.
    pub pendings: [Option<RefPending>; 2],
    /// The fresh step-up proofs not yet taken. A stale proof can never be
    /// taken again, because the clock only moves forward, so it is dropped.
    pub proofs: BTreeSet<(Session, ProofFor)>,
    /// The clock moves made.
    pub advanced: BTreeSet<Advance>,
    /// Whether the agent is revoked.
    pub revoked: bool,
    /// Whether the owner's programme manager binding of P1 ended.
    pub ended: bool,
    /// Whether call 1 is published.
    pub published: bool,
    /// Whether call 2 is edited.
    pub edited: bool,
    /// Whether the plain operation completed through MCP.
    pub plain_done: bool,
}

impl Ref {
    fn pending(&self, w: Which) -> Option<RefPending> {
        self.pendings.get(w.index()).copied().flatten()
    }

    fn set(&mut self, w: Which, p: RefPending) {
        if let Some(slot) = self.pendings.get_mut(w.index()) {
            *slot = Some(p);
        }
    }

    /// Whether some pending action is open but past its lifetime.
    pub fn has_expired_action(&self) -> bool {
        self.pendings
            .iter()
            .flatten()
            .any(|p| p.status == PendingStatus::Open && p.expired)
    }
}

/// One outcome the reference admits, with the state after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The outcome.
    pub outcome: Outcome,
    /// The state after it.
    pub next: Ref,
}

fn only(outcome: Outcome, next: Ref) -> Vec<Admitted> {
    vec![Admitted { outcome, next }]
}

/// The outcomes the reference admits for `a` in `r`, with the state after
/// each, or `None` when the action is not enabled. The first entry is the
/// outcome the reference backend takes.
pub fn admitted(r: &Ref, a: &PrepAction, fault: Fault) -> Option<Vec<Admitted>> {
    let same = r.clone();
    match *a {
        PrepAction::Prepare(op) => {
            if r.revoked {
                return Some(only(Outcome::Refused, same));
            }
            let w = match op {
                AgentOp::Plain => {
                    let mut n = same;
                    n.plain_done = true;
                    return Some(only(Outcome::Done, n));
                }
                AgentOp::Publish => Which::Publish,
                AgentOp::Edit => Which::Edit,
            };
            if r.pending(w).is_some() {
                return None;
            }
            if r.ended {
                return Some(only(Outcome::Refused, same));
            }
            let mut n = same;
            n.set(
                w,
                RefPending {
                    status: PendingStatus::Open,
                    expired: false,
                },
            );
            Some(only(Outcome::Pending, n))
        }
        PrepAction::StepUp(session, digest) => {
            if digest == ProofFor::Publish && r.pending(Which::Publish).is_none() {
                return None;
            }
            if r.proofs.contains(&(session, digest)) {
                return None;
            }
            let mut n = same;
            n.proofs.insert((session, digest));
            Some(only(Outcome::Done, n))
        }
        PrepAction::Confirm(who, w, shown) => {
            let p = r.pending(w)?;
            let forged = fault == Fault::ForgeShownDigest;
            if who == Who::Other
                || !p.confirmable()
                || (shown == Shown::Wrong && !forged)
                || r.ended
            {
                return Some(only(Outcome::Refused, same));
            }
            let mut n = same.clone();
            let outcome = match w {
                Which::Publish => {
                    if n.proofs.remove(&(Session::Main, ProofFor::Publish)) {
                        n.published = true;
                        n.set(
                            w,
                            RefPending {
                                status: PendingStatus::Confirmed,
                                expired: false,
                            },
                        );
                        Outcome::Done
                    } else {
                        Outcome::StepUpRequired
                    }
                }
                Which::Edit => {
                    n.edited = true;
                    n.set(
                        w,
                        RefPending {
                            status: PendingStatus::Confirmed,
                            expired: false,
                        },
                    );
                    Outcome::Done
                }
            };
            let mut out = only(outcome, n);
            if r.revoked {
                out.push(Admitted {
                    outcome: Outcome::Refused,
                    next: same,
                });
            }
            Some(out)
        }
        PrepAction::Discard(w) => {
            let p = r.pending(w)?;
            if p.status != PendingStatus::Open {
                return Some(only(Outcome::Refused, same));
            }
            let mut n = same.clone();
            n.set(
                w,
                RefPending {
                    status: PendingStatus::Discarded,
                    expired: p.expired,
                },
            );
            let mut out = only(Outcome::Done, n);
            if p.expired {
                out.push(Admitted {
                    outcome: Outcome::Refused,
                    next: same,
                });
            }
            Some(out)
        }
        PrepAction::Advance(adv) => {
            if r.advanced.contains(&adv) {
                return None;
            }
            let mut n = same;
            n.advanced.insert(adv);
            n.proofs.clear();
            if adv == Advance::PastExpiry {
                for p in n.pendings.iter_mut().flatten() {
                    if p.status == PendingStatus::Open {
                        p.expired = true;
                    }
                }
            }
            Some(only(Outcome::Done, n))
        }
        PrepAction::Revoke => {
            if r.revoked {
                return None;
            }
            let mut n = same;
            n.revoked = true;
            Some(only(Outcome::Done, n))
        }
        PrepAction::EndBinding => {
            if r.ended {
                return None;
            }
            let mut n = same;
            n.ended = true;
            Some(only(Outcome::Done, n))
        }
    }
}

/// One M-PREP state: the reference state, the trace that reached it with
/// production's outcomes, and the first divergence found.
#[derive(Clone, Debug)]
pub struct PrepState {
    /// The reference state.
    pub r: Ref,
    /// The trace from the start, with the outcome of each step.
    pub trace: Vec<(PrepAction, Outcome)>,
    /// The first disagreement between production and the reference.
    pub divergence: Option<String>,
}

impl PartialEq for PrepState {
    fn eq(&self, other: &PrepState) -> bool {
        self.r == other.r && self.divergence == other.divergence
    }
}

impl Eq for PrepState {}

impl Hash for PrepState {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.r.hash(h);
        self.divergence.hash(h);
    }
}

/// A digest of no pending action.
pub const FOREIGN_DIGEST: ActionDigest = ActionDigest([0xf0; 32]);

/// `d` with its first byte flipped.
fn wrong(d: ActionDigest) -> ActionDigest {
    let mut b = d.0;
    if let Some(first) = b.first_mut() {
        *first ^= 0xff;
    }
    ActionDigest(b)
}

/// Production: one fake cell with the owner's two sessions, the other
/// account's session and the agent's token, and what the steps returned.
pub struct Driver {
    cell: FakeCell,
    main: WebLogin,
    second: WebLogin,
    other: WebLogin,
    token: Vec<u8>,
    ids: [Option<PendingId>; 2],
    digests: [Option<ActionDigest>; 2],
    environment: u128,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("ids", &self.ids)
            .finish_non_exhaustive()
    }
}

/// The class of `r` as the reference compares it, or why it has none.
fn outcome_of(r: &Result<OpResult, fstp_api_core::ApiError>) -> Result<Outcome, String> {
    match class(r) {
        Class::Done => Ok(Outcome::Done),
        Class::Pending => Ok(Outcome::Pending),
        Class::StepUpRequired => Ok(Outcome::StepUpRequired),
        Class::Refused(_) => Ok(Outcome::Refused),
        Class::StrongMethodRequired => {
            Err(format!("a passkey session got StrongMethodRequired: {r:?}"))
        }
        Class::Stub => Err(format!("a stub answered: {r:?}")),
    }
}

impl Driver {
    /// A cell over `world`, with the sessions and the token.
    pub fn start(world: &World) -> Result<Driver, String> {
        let cell = FakeCell::from_world(world).map_err(|e| e.to_string())?;
        let main = cell.login(OWNER, LoginMethod::Passkey);
        let second = cell.login(OWNER, LoginMethod::Passkey);
        let other = cell.login(OTHER, LoginMethod::Passkey);
        let token = cell.token(
            OWNER,
            AGENT,
            [Scope::CallsDraft, Scope::CallsRead],
            LoginMethod::Passkey,
        );
        Ok(Driver {
            cell,
            main,
            second,
            other,
            token,
            ids: [None, None],
            digests: [None, None],
            environment: 0,
        })
    }

    /// The cell.
    pub fn cell(&self) -> &FakeCell {
        &self.cell
    }

    fn id(&self, w: Which) -> Result<PendingId, String> {
        self.ids
            .get(w.index())
            .copied()
            .flatten()
            .ok_or_else(|| format!("production holds no pending {w:?}"))
    }

    fn digest(&self, w: Which) -> Result<ActionDigest, String> {
        self.digests
            .get(w.index())
            .copied()
            .flatten()
            .ok_or_else(|| format!("production shows no digest for {w:?}"))
    }

    /// Records the pending action of `w` from a receipt, and its digest
    /// from the owner's `pending.list`.
    fn remember(
        &mut self,
        w: Which,
        r: &Result<OpResult, fstp_api_core::ApiError>,
    ) -> Result<(), String> {
        let Ok(OpResult::Pending(receipt)) = r else {
            return Ok(());
        };
        let list = self.cell.pending(&self.main)?;
        let view = list
            .iter()
            .find(|v| v.id == receipt.id)
            .ok_or_else(|| format!("pending.list omits the new {w:?}"))?;
        if let Some(slot) = self.ids.get_mut(w.index()) {
            *slot = Some(receipt.id);
        }
        if let Some(slot) = self.digests.get_mut(w.index()) {
            *slot = Some(view.digest);
        }
        Ok(())
    }

    /// Runs `a` on production with `fault`, and returns its outcome.
    pub fn run(&mut self, a: &PrepAction, fault: Fault) -> Result<Outcome, String> {
        match *a {
            PrepAction::Prepare(op) => {
                let opr = match op {
                    AgentOp::Publish => requests::publish_mcp(CALL_PUBLISH),
                    AgentOp::Edit => requests::edit_mcp(CALL_EDIT, &sample_edit()),
                    AgentOp::Plain => requests::list_open_calls_mcp(),
                };
                let r = self.cell.mcp(&self.token, opr);
                let o = outcome_of(&r)?;
                match op {
                    AgentOp::Publish => self.remember(Which::Publish, &r)?,
                    AgentOp::Edit => self.remember(Which::Edit, &r)?,
                    AgentOp::Plain => {}
                }
                Ok(o)
            }
            PrepAction::StepUp(session, digest) => {
                let s = match session {
                    Session::Main => self.main.session,
                    Session::Second => self.second.session,
                };
                let d = match digest {
                    ProofFor::Publish => self.digest(Which::Publish)?,
                    ProofFor::Foreign => FOREIGN_DIGEST,
                };
                self.cell
                    .ports
                    .step_up
                    .approve(s, d)
                    .map_err(|e| format!("step-up ceremony: {e:?}"))?;
                Ok(Outcome::Done)
            }
            PrepAction::Confirm(who, w, shown) => {
                let id = self.id(w)?;
                let stored = self.digest(w)?;
                let sent = match (shown, fault) {
                    (Shown::Stored, _) | (Shown::Wrong, Fault::ForgeShownDigest) => stored,
                    (Shown::Wrong, Fault::None) => wrong(stored),
                };
                let login = match who {
                    Who::Owner => &self.main,
                    Who::Other => &self.other,
                };
                let r = self.cell.web(login, requests::pending_confirm(id, &sent));
                if let Ok(OpResult::StepUpRequired(ch)) = &r
                    && ch.action != stored
                {
                    return Err(format!(
                        "the step-up challenge of {w:?} is bound to another digest"
                    ));
                }
                outcome_of(&r)
            }
            PrepAction::Discard(w) => {
                let id = self.id(w)?;
                outcome_of(&self.cell.web(&self.main, requests::pending_discard(id)))
            }
            PrepAction::Advance(adv) => {
                self.cell.ports.clock.advance(adv.micros());
                Ok(Outcome::Done)
            }
            PrepAction::Revoke => {
                outcome_of(&self.cell.web(&self.main, requests::agent_revoke(AGENT)))
            }
            PrepAction::EndBinding => {
                self.environment = self.environment.saturating_add(1);
                let now = self.cell.ports.clock.read();
                let end = roster::end(staff_bindings(P1)[0], now).cmd;
                let ctx = fixture::ctx(
                    ADMIN,
                    Via::Web,
                    now,
                    50_000u128.saturating_add(self.environment),
                );
                self.cell
                    .ports
                    .engine
                    .environment(Command::Core(end), ctx)
                    .map_err(|e| format!("ending the owner's binding: {e}"))?;
                Ok(Outcome::Done)
            }
        }
    }

    /// Checks production's observable state against `r`.
    pub fn observe(&self, r: &Ref) -> Result<(), String> {
        let now = self.cell.ports.clock.read();
        let list = self.cell.pending(&self.main)?;
        for v in &list {
            if !self.ids.contains(&Some(v.id)) {
                return Err(format!(
                    "pending.list holds an action the reference has not: {v:?}"
                ));
            }
            if v.agent != AGENT {
                return Err(format!("pending action {v:?} names another agent"));
            }
        }
        for w in [Which::Publish, Which::Edit] {
            let id = self.ids.get(w.index()).copied().flatten();
            let listed = id.and_then(|id| list.iter().find(|v| v.id == id));
            let confirmable =
                listed.is_some_and(|v| v.status == PendingStatus::Open && v.expires > now);
            let expected = r.pending(w).is_some_and(|p| p.confirmable());
            if confirmable != expected {
                return Err(format!(
                    "{w:?}: production confirmable {confirmable}, reference {expected} ({listed:?})"
                ));
            }
        }
        self.check_executions(r)
    }

    /// I-85, R-MC-05: production executed exactly the confirmations the
    /// reference completed, each once, through the web, by the owner, with
    /// the stored digest, the pending action named, and for the
    /// publication the step-up proof taken for its digest.
    fn check_executions(&self, r: &Ref) -> Result<(), String> {
        let appended = self.cell.ports.engine.appended();
        let mut published = 0usize;
        let mut edited = 0usize;
        for e in &appended {
            let w = match &e.cmd {
                Command::Core(fstp_domain::Command::PublishCall { call, .. })
                    if *call == CALL_PUBLISH =>
                {
                    published = published.saturating_add(1);
                    Which::Publish
                }
                Command::Core(fstp_domain::Command::EditCall {
                    call,
                    opens,
                    deadline,
                    budget,
                    ..
                }) if *call == CALL_EDIT => {
                    let s = sample_edit();
                    if *opens != s.opens
                        || *deadline != s.deadline
                        || budget.amount().minor() != s.budget_cents
                    {
                        return Err(format!(
                            "the executed edit differs from the stored one: {e:?}"
                        ));
                    }
                    edited = edited.saturating_add(1);
                    Which::Edit
                }
                other => {
                    return Err(format!(
                        "production executed an unexpected command: {other:?}"
                    ));
                }
            };
            if e.ctx.via != Via::Web || e.meta.via != Via::Web {
                return Err(format!("{w:?} executed outside the web: {e:?}"));
            }
            if e.ctx.actor != Actor::Account(OWNER) {
                return Err(format!("{w:?} executed for another actor: {e:?}"));
            }
            if e.meta.pending != Some(self.id(w)?) {
                return Err(format!(
                    "{w:?} executed without naming its pending action: {e:?}"
                ));
            }
            if e.meta.request != self.digest(w)? {
                return Err(format!("{w:?} executed under another digest: {e:?}"));
            }
            if w == Which::Publish {
                let digest = self.digest(w)?;
                let taken = self.cell.ports.step_up.taken();
                let ok = e.meta.step_up.is_some_and(|s| {
                    taken.iter().any(|t| {
                        t.proof.step_up == s
                            && t.proof.session == self.main.session
                            && t.proof.action == digest
                    })
                });
                if !ok {
                    return Err(format!(
                        "the publication executed without its step-up proof: {e:?}"
                    ));
                }
            }
        }
        if published != usize::from(r.published) || edited != usize::from(r.edited) {
            return Err(format!(
                "production executed {published} publications and {edited} edits, the reference {} and {}",
                r.published, r.edited
            ));
        }
        Ok(())
    }
}

/// The M-PREP model.
pub struct PrepModel {
    backend: Backend,
    fault: Fault,
    world: World,
    states: usize,
}

impl std::fmt::Debug for PrepModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrepModel")
            .field("backend", &self.backend)
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl PrepModel {
    /// Builds the model over the I-85 world. On production it first starts
    /// one cell, so a cell that cannot start fails here.
    pub fn new(backend: Backend) -> Result<PrepModel, NotImplemented> {
        PrepModel::with_fault(backend, Fault::None)
    }

    /// Builds the model with `fault` injected.
    pub fn with_fault(backend: Backend, fault: Fault) -> Result<PrepModel, NotImplemented> {
        let world = fixture::pending_world().map_err(|_| {
            NotImplemented::new("fstp_api_testkit::mc::prep_model: the I-85 world did not build")
        })?;
        if backend == Backend::Production {
            crate::fake::port_seams()?;
            Driver::start(&world).map_err(|_| {
                NotImplemented::new("fstp_api_testkit::mc::prep_model: the fake cell did not start")
            })?;
        }
        Ok(PrepModel {
            backend,
            fault,
            world,
            states: 0,
        })
    }

    /// The number of states explored so far.
    pub fn states(&self) -> usize {
        self.states
    }

    fn diverged(s: &PrepState, a: PrepAction, why: String) -> PrepState {
        let mut trace = s.trace.clone();
        trace.push((a, Outcome::Refused));
        PrepState {
            r: s.r.clone(),
            trace,
            divergence: Some(format!("after {:?}, {a:?}: {why}", s.trace)),
        }
    }

    /// Production: replays the trace of `s`, runs `a`, and checks it.
    fn production_step(&self, s: &PrepState, a: PrepAction, admitted: &[Admitted]) -> PrepState {
        let mut d = match Driver::start(&self.world) {
            Ok(d) => d,
            Err(e) => return Self::diverged(s, a, format!("the cell did not start: {e}")),
        };
        for (past, seen) in &s.trace {
            match d.run(past, self.fault) {
                Ok(o) if o == *seen => {}
                other => {
                    return Self::diverged(
                        s,
                        a,
                        format!("replaying {past:?} gave {other:?}, first {seen:?}"),
                    );
                }
            }
        }
        let o = match d.run(&a, self.fault) {
            Ok(o) => o,
            Err(e) => return Self::diverged(s, a, e),
        };
        let Some(hit) = admitted.iter().find(|x| x.outcome == o) else {
            let want: Vec<Outcome> = admitted.iter().map(|x| x.outcome).collect();
            return Self::diverged(
                s,
                a,
                format!("production gave {o:?}, the reference admits {want:?}"),
            );
        };
        if let Err(e) = d.observe(&hit.next) {
            return Self::diverged(s, a, e);
        }
        let mut trace = s.trace.clone();
        trace.push((a, o));
        PrepState {
            r: hit.next.clone(),
            trace,
            divergence: None,
        }
    }
}

impl Model for PrepModel {
    type State = PrepState;
    type Action = PrepAction;

    fn init(&self) -> Vec<PrepState> {
        let s = PrepState {
            r: Ref::default(),
            trace: Vec::new(),
            divergence: None,
        };
        if self.backend == Backend::Production {
            let checked = Driver::start(&self.world).and_then(|d| d.observe(&s.r));
            if let Err(e) = checked {
                return vec![PrepState {
                    divergence: Some(format!("at the start: {e}")),
                    ..s
                }];
            }
        }
        vec![s]
    }

    fn actions(&self, s: &PrepState, out: &mut Vec<PrepAction>) {
        if s.divergence.is_none() {
            out.extend(ACTIONS);
        }
    }

    fn step(&self, s: &PrepState, a: &PrepAction) -> Option<PrepState> {
        if s.divergence.is_some() {
            return None;
        }
        let admitted = admitted(
            &s.r,
            a,
            if self.backend == Backend::Reference {
                self.fault
            } else {
                Fault::None
            },
        )?;
        match self.backend {
            Backend::Reference => {
                let first = admitted.first()?;
                let mut trace = s.trace.clone();
                trace.push((*a, first.outcome));
                Some(PrepState {
                    r: first.next.clone(),
                    trace,
                    divergence: None,
                })
            }
            Backend::Production => Some(self.production_step(s, *a, &admitted)),
        }
    }

    fn is_terminal(&self, s: &PrepState) -> bool {
        s.divergence.is_some()
    }
}

/// `always("I-85")`: no divergence.
pub fn i85(s: &PrepState) -> Result<(), String> {
    match &s.divergence {
        None => Ok(()),
        Some(d) => Err(format!("I-85: {d}")),
    }
}

/// The properties of M-PREP.
pub fn prep_properties<'a>() -> Vec<Property<'a, PrepModel>> {
    vec![
        Property::always_with("I-85", i85),
        Property::transition("I-85 publication", |s: &PrepState, a, t: &PrepState| {
            s.r.published
                || !t.r.published
                || *a == PrepAction::Confirm(Who::Owner, Which::Publish, Shown::Stored)
        }),
        Property::transition("R-MC-05 edit", |s: &PrepState, a, t: &PrepState| {
            s.r.edited
                || !t.r.edited
                || *a == PrepAction::Confirm(Who::Owner, Which::Edit, Shown::Stored)
        }),
        Property::reachable(
            "I-85 witness: confirmed high-risk action",
            |s: &PrepState| s.r.published,
        ),
        Property::reachable(
            "R-MC-05 witness: confirmed binding action",
            |s: &PrepState| s.r.edited,
        ),
        Property::reachable("I-85 witness: expired action", |s: &PrepState| {
            s.r.has_expired_action()
        }),
        Property::reachable(
            "I-85 witness: direct plain op through MCP",
            |s: &PrepState| s.r.plain_done,
        ),
    ]
}

/// The fstp-prop machine of
/// `i85_prepared_publication_completes_only_after_web_confirmation`: long
/// random sequences of the M-PREP actions on one cell, with the same
/// reference and the same production checks.
///
/// The machine needs a deterministic reference, so it leaves out the two
/// cases where the reference admits two outcomes: it never revokes the
/// agent, and it never discards an expired action.
pub struct PrepMachine {
    world: Result<World, String>,
}

impl std::fmt::Debug for PrepMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrepMachine(..)")
    }
}

impl PrepMachine {
    /// The machine over the I-85 world.
    pub fn new() -> PrepMachine {
        PrepMachine {
            world: fixture::pending_world(),
        }
    }

    fn single(model: &Ref, cmd: &PrepAction) -> Option<Admitted> {
        let mut a = admitted(model, cmd, Fault::None)?;
        if a.len() == 1 { a.pop() } else { None }
    }
}

impl Default for PrepMachine {
    fn default() -> PrepMachine {
        PrepMachine::new()
    }
}

impl fstp_prop::StateMachine for PrepMachine {
    type Model = Ref;
    type Sut = Result<Driver, String>;
    type Command = PrepAction;
    type Output = Result<Outcome, String>;

    fn init_model(&self) -> Ref {
        Ref::default()
    }

    fn init_sut(&self) -> Result<Driver, String> {
        let world = self.world.as_ref().map_err(Clone::clone)?;
        Driver::start(world).map_err(|e| format!("the fake cell did not start: {e}"))
    }

    fn command(&self, g: &mut fstp_prop::Gen, model: &Ref) -> PrepAction {
        let _ = model;
        *g.pick(&ACTIONS)
    }

    fn precondition(&self, model: &Ref, cmd: &PrepAction) -> bool {
        if *cmd == PrepAction::Revoke {
            return false;
        }
        PrepMachine::single(model, cmd).is_some()
    }

    fn run(&self, sut: &mut Result<Driver, String>, cmd: &PrepAction) -> Result<Outcome, String> {
        match sut {
            Ok(d) => d.run(cmd, Fault::None),
            Err(e) => Err(e.clone()),
        }
    }

    fn next_state(&self, model: &mut Ref, cmd: &PrepAction) {
        if let Some(a) = PrepMachine::single(model, cmd) {
            *model = a.next;
        }
    }

    fn postcondition(
        &self,
        model: &Ref,
        cmd: &PrepAction,
        output: &Result<Outcome, String>,
    ) -> Result<(), String> {
        let want = PrepMachine::single(model, cmd)
            .ok_or_else(|| format!("{cmd:?} is not enabled"))?
            .outcome;
        match output {
            Ok(o) if *o == want => Ok(()),
            Ok(o) => Err(format!(
                "I-85: production gave {o:?}, the reference {want:?}"
            )),
            Err(e) => Err(format!("I-85: {e}")),
        }
    }

    fn invariant(&self, model: &Ref, sut: &Result<Driver, String>) -> Result<(), String> {
        match sut {
            Ok(d) => d.observe(model).map_err(|e| format!("I-85: {e}")),
            Err(e) => Err(format!("I-85: {e}")),
        }
    }

    fn max_commands(&self) -> usize {
        40
    }
}
