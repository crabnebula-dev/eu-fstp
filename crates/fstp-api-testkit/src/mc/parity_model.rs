//! M-PARITY (M4 design section 8.5, I-84). Lane m4/parity wrote it.
//!
//! The universe holds two accounts, the lead of the proposal X
//! ([`Who::Lead`]) and a programme manager of P
//! ([`Who::ProgrammeManager`]). X walks from its genesis to STAGE2: the
//! open call before X exists, then DRAFT, SUBMITTED, STAGE1 and STAGE2
//! ([`PATH`]). Every policy parameter takes its SuperSAFE value, except
//! P-77, which takes both values: one chain of states per value.
//!
//! In each state, each operation with an MCP tool runs once per channel
//! for each account that exists there. The MCP call goes through the
//! `tools/call` handler of `fstp_mcp::McpServer`. Its web twin goes
//! through the HTTP routes of `fstp-web` in a passkey session, with a
//! fresh step-up where the operation is high-risk. Each runs on a clean
//! world of the matrix harness, built from genesis through production
//! commands. A pending action the MCP call stores is confirmed through
//! the web on the MCP call's world ([`crate::harness::parity`]).
//!
//! Each call runs on a world no earlier call changed. So the order of the
//! calls within a state changes no outcome, and the model fixes it. The
//! exhaustive run is then one chain per P-77 value, and its state count is
//! the tripwire.
//!
//! The exposure of an operation comes from the reference
//! (`reference::authz`), never from `fstp-access`: a high-risk operation,
//! one whose reference tool is prepare-only (`RefTool::prepare`, the ADR-013
//! amendment of 2026-11-20), and a binding one under P-77 "draft only", is
//! a pending exposure. Every other one is a direct exposure, so `Pending`
//! through MCP stays a violation for it.
//!
//! Daniel's decision of 2026-11-20 on P-75 and P-77 adds a pending
//! exposure by request: `creator.apply_start` from the SuperSAFE template
//! sets both, so it is one (`RefOp::prepares`). The model's cells stay
//! true under it. In every state of [`PATH`] the programme P is active,
//! so the creator refuses a start, and a save other than P-09 alone, in
//! the dry run on both channels, before any pending action. Such a cell
//! gives the same refusal on both channels, which either exposure admits.
//!
//! Properties:
//!
//! - `transition("I-84 direct")`: for a direct exposure, the MCP outcome
//!   equals the web outcome. The one difference the design admits is D6
//!   (TH-62): with P-75 off, a content read outside the applicant team is
//!   refused through MCP under P-75, where the reference admits it with
//!   P-75 on.
//! - `transition("I-84 pending")`: for a pending exposure, where the web
//!   completes, MCP gives `Pending` and its web confirmation completes,
//!   as the direct web outcome does. Where the web refuses, the dry run
//!   refuses the MCP call with the same refusal, before any pending
//!   action (design section 3.7, step 5).
//! - `always("I-84 harness")`: the harness ran every call.
//! - Witnesses: one pending action confirmed, and one direct MCP success
//!   of an operation that is not public.
//!
//! The reference backend replaces both channels with the reference's
//! outcomes, mapped as [`reference_outcome`] says. It checks that the
//! reference itself keeps the parity the properties state.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::harness::parity::{PairRun, ParityRunner};
use crate::matrix::{Cell, Denial, Observed};
use crate::reference::authz::{
    AuthClass, AuthzReference, Channel as Via, Expected, Login, Policy, RefOp, Session,
    StateProfile, StepUp, Who, authz_reference, feasible, target_exists,
};

/// The state count the model's first exhaustive run records, measured on
/// the reference backend on 2026-11-16. Production explores the same
/// chains. The run bound is twice this.
pub const TRIPWIRE: usize = 662;

/// The two accounts of the universe.
pub const ACCOUNTS: [Who; 2] = [Who::Lead, Who::ProgrammeManager];

/// The states of X from its genesis to STAGE2, in order.
pub const PATH: [StateProfile; 5] = [
    StateProfile::CallOpen,
    StateProfile::Proposal(StateTag::Draft),
    StateProfile::Proposal(StateTag::Submitted),
    StateProfile::Proposal(StateTag::Stage1),
    StateProfile::Proposal(StateTag::Stage2),
];

/// The operation the teeth test's alternative dispatcher shortcuts:
/// `fstp_submit_proposal`, a binding operation.
pub const SHORTCUT_OP: &str = "proposal.submit";

/// What decides the model steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// The matrix harness: production dispatch behind the MCP server and
    /// the web routes.
    Production,
    /// The reference alone.
    Reference,
}

/// A fault the teeth test injects. None in the plain model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// No fault.
    None,
    /// An alternative MCP dispatcher skips the dry run for
    /// [`SHORTCUT_OP`]. It stores a pending action for every call of that
    /// tool that channel policy prepares, so a call the dry run refuses
    /// becomes `Pending` too. Its web confirmation runs the stored request
    /// through the web, so it gives the web outcome. The fault lives in
    /// this test code only, applied to what the backend observed.
    SkipDryRun,
}

/// How an operation reaches an MCP caller, by the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exposure {
    /// The tool executes the operation.
    Direct,
    /// The tool prepares a pending action for a web confirmation (I-85).
    Pending,
}

/// The exposure of `op` under `policy`. A prepare-only tool on an operation
/// that is not high-risk is a pending exposure (ADR-013 amendment of
/// 2026-11-20), and so is a matrix request that sets P-75 or P-77 (Daniel,
/// 2026-11-20). The reference names exactly those (`RefOp::prepares`).
pub fn exposure(op: &RefOp, policy: &Policy) -> Exposure {
    if op.high_risk || op.prepares() || (op.binding && policy.p77_draft_only) {
        Exposure::Pending
    } else {
        Exposure::Direct
    }
}

/// The policy of a chain: SuperSAFE, with P-77 "draft only" or not.
pub const fn policy(p77_draft_only: bool) -> Policy {
    Policy {
        p77_draft_only,
        ..Policy::SUPERSAFE
    }
}

/// The MCP session of every MCP cell: a passkey-strength token with every
/// scope.
pub const MCP: Session = Session {
    login: Some(Login::Passkey),
    step_up: StepUp::Absent,
    channel: Via::Mcp { scope: true },
};

/// The web twin of an MCP cell: the same operation, account, state and
/// policy through the web in a passkey session, with a fresh step-up for a
/// high-risk operation.
pub fn web_twin(op: &RefOp, cell: &Cell) -> Cell {
    Cell {
        session: Session {
            login: Some(Login::Passkey),
            step_up: if op.high_risk {
                StepUp::Fresh
            } else {
                StepUp::Absent
            },
            channel: Via::Web,
        },
        ..*cell
    }
}

/// One MCP cell and what the backend observed for it and its web twin.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pair {
    /// The MCP cell.
    pub cell: Cell,
    /// Its exposure.
    pub exposure: Exposure,
    /// Whether the operation is public.
    pub public: bool,
    /// Whether D6 admits a refusal under P-75 through MCP alone: P-75 is
    /// off, and the reference admits the MCP cell with P-75 on.
    pub p75_alone: bool,
    /// The web twin's outcome.
    pub web: Observed,
    /// The MCP cell's outcome.
    pub mcp: Observed,
    /// The web confirmation of the MCP cell's pending action.
    pub confirmed: Option<Observed>,
}

/// The refusal of a content read through MCP with P-75 off (D6).
fn p75_refusal() -> Observed {
    Observed::Refused(Some("P-75".to_owned()))
}

impl Pair {
    /// `transition("I-84 direct")` on this pair.
    pub fn direct_parity(&self) -> Result<(), String> {
        if self.exposure != Exposure::Direct
            || self.mcp == self.web
            || (self.p75_alone && self.mcp == p75_refusal())
        {
            return Ok(());
        }
        Err(format!(
            "I-84: {:?} is a direct exposure; MCP gave {:?}, the web {:?}",
            self.cell, self.mcp, self.web
        ))
    }

    /// `transition("I-84 pending")` on this pair.
    pub fn pending_parity(&self) -> Result<(), String> {
        if self.exposure != Exposure::Pending {
            return Ok(());
        }
        let c = &self.cell;
        match (&self.web, &self.mcp) {
            (Observed::Completed, Observed::Pending) => {
                if self.confirmed.as_ref() == Some(&self.web) {
                    Ok(())
                } else {
                    Err(format!(
                        "I-84: {c:?}: the web confirmation gave {:?}, the direct web call {:?}",
                        self.confirmed, self.web
                    ))
                }
            }
            (Observed::Completed, m) => Err(format!(
                "I-84: {c:?} is a pending exposure the web completes; MCP gave {m:?}, not Pending"
            )),
            (w, Observed::Pending) => Err(format!(
                "I-84: {c:?}: MCP stored a pending action the web refuses ({w:?}); \
                 the dry run must refuse it first (design 3.7 step 5)"
            )),
            (w, m) if w == m || (self.p75_alone && *m == p75_refusal()) => Ok(()),
            (w, m) => Err(format!(
                "I-84: {c:?} is a pending exposure; MCP gave {m:?}, the web {w:?}"
            )),
        }
    }

    /// Whether the web confirmation of a pending action completed.
    pub fn pending_confirmed(&self) -> bool {
        self.exposure == Exposure::Pending && self.confirmed == Some(Observed::Completed)
    }

    /// Whether a direct exposure of an operation that is not public
    /// completed through MCP.
    pub fn direct_success(&self) -> bool {
        self.exposure == Exposure::Direct && !self.public && self.mcp == Observed::Completed
    }
}

/// One action of M-PARITY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParityAction {
    /// Run the MCP cell and its web twin.
    Call(Cell),
    /// X moves on to this state of [`PATH`].
    Advance(StateProfile),
}

/// One M-PARITY state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParityState {
    /// The P-77 value of the chain.
    pub p77_draft_only: bool,
    /// The index of X's state in [`PATH`].
    pub stage: usize,
    /// The index of the next cell of the state.
    pub next: usize,
    /// The pair the last call gave.
    pub last: Option<Pair>,
    /// Whether some pending action was confirmed through the web.
    pub pending_confirmed: bool,
    /// Whether some direct exposure completed through MCP.
    pub direct_success: bool,
    /// Why the harness could not run a call.
    pub fault: Option<String>,
}

/// The reference's outcome of `cell`, as an observation. `Allow` is
/// `Completed`, `Pending` is `Pending`, a channel class is the channel
/// denial, and any other class is a refusal named by the class. A
/// visibility refusal through MCP that P-75 alone causes (D6) is the
/// P-75 refusal.
pub fn reference_outcome(reference: &AuthzReference, cell: &Cell) -> Option<Observed> {
    Some(match reference.expected(cell)? {
        Expected::Allow => Observed::Completed,
        Expected::Pending => Observed::Pending,
        Expected::Deny(AuthClass::NotExposed) => Observed::ChannelDenied(Denial::NotExposed),
        Expected::Deny(AuthClass::Scope) => Observed::ChannelDenied(Denial::Scope),
        Expected::Deny(AuthClass::P74) => Observed::ChannelDenied(Denial::P74),
        Expected::Deny(AuthClass::Visibility) if p75_alone(reference, cell) => p75_refusal(),
        Expected::Deny(c) => Observed::Refused(Some(format!("{c:?}"))),
    })
}

/// Whether D6 admits a P-75 refusal of the MCP `cell` alone: P-75 is off,
/// and the reference admits the same cell with P-75 on.
fn p75_alone(reference: &AuthzReference, cell: &Cell) -> bool {
    if cell.policy.p75_on || !matches!(cell.session.channel, Via::Mcp { .. }) {
        return false;
    }
    let mut on = *cell;
    on.policy.p75_on = true;
    reference.expected(&on) == Some(Expected::Allow)
}

/// The M-PARITY model.
pub struct ParityModel {
    backend: Backend,
    fault: Fault,
    reference: AuthzReference,
    /// The MCP cells of each chain and state, in a fixed order.
    cells: BTreeMap<(bool, usize), Vec<Cell>>,
    runner: RefCell<ParityRunner>,
}

impl std::fmt::Debug for ParityModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParityModel")
            .field("backend", &self.backend)
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl ParityModel {
    /// Builds the model.
    pub fn new(backend: Backend) -> Result<ParityModel, NotImplemented> {
        ParityModel::with_fault(backend, Fault::None)
    }

    /// Builds the model with `fault` injected.
    pub fn with_fault(backend: Backend, fault: Fault) -> Result<ParityModel, NotImplemented> {
        let reference = authz_reference()?;
        let mut cells = BTreeMap::new();
        for p77 in [true, false] {
            for (stage, state) in PATH.iter().enumerate() {
                let mut out = Vec::new();
                for op in reference.ops().filter(|o| o.tool.is_some()) {
                    if !target_exists(op.target, *state) {
                        continue;
                    }
                    for who in ACCOUNTS {
                        if feasible(who, *state) {
                            out.push(Cell {
                                op: op.name,
                                who,
                                state: *state,
                                policy: policy(p77),
                                session: MCP,
                            });
                        }
                    }
                }
                cells.insert((p77, stage), out);
            }
        }
        if backend == Backend::Production {
            crate::fake::port_seams()?;
        }
        Ok(ParityModel {
            backend,
            fault,
            reference,
            cells,
            runner: RefCell::new(ParityRunner::new()),
        })
    }

    /// The MCP cells of the chain `p77` in X's state `stage`.
    pub fn cells(&self, p77: bool, stage: usize) -> &[Cell] {
        self.cells.get(&(p77, stage)).map_or(&[], Vec::as_slice)
    }

    /// Runs `cell` and its web twin on the backend, and applies the fault.
    fn pair(&self, cell: &Cell) -> Result<Pair, String> {
        let op = self
            .reference
            .op(cell.op)
            .ok_or_else(|| format!("the reference has no {}", cell.op))?;
        let twin = web_twin(op, cell);
        let run = match self.backend {
            Backend::Production => self
                .runner
                .borrow_mut()
                .run(cell, &twin)
                .map_err(|e| format!("{cell:?}: {e:?}"))?,
            Backend::Reference => {
                let web = reference_outcome(&self.reference, &twin)
                    .ok_or_else(|| format!("the reference does not judge {twin:?}"))?;
                let mcp = reference_outcome(&self.reference, cell)
                    .ok_or_else(|| format!("the reference does not judge {cell:?}"))?;
                let confirmed = (mcp == Observed::Pending).then(|| web.clone());
                PairRun {
                    web,
                    mcp,
                    confirmed,
                }
            }
        };
        let exposure = exposure(op, &cell.policy);
        let mut pair = Pair {
            cell: *cell,
            exposure,
            public: op.public,
            p75_alone: p75_alone(&self.reference, cell),
            web: run.web,
            mcp: run.mcp,
            confirmed: run.confirmed,
        };
        if self.fault == Fault::SkipDryRun
            && cell.op == SHORTCUT_OP
            && exposure == Exposure::Pending
            && matches!(pair.mcp, Observed::Refused(_) | Observed::NotFound(_))
        {
            pair.mcp = Observed::Pending;
            pair.confirmed = Some(pair.web.clone());
        }
        Ok(pair)
    }
}

impl Model for ParityModel {
    type State = ParityState;
    type Action = ParityAction;

    fn init(&self) -> Vec<ParityState> {
        [true, false]
            .into_iter()
            .map(|p77| ParityState {
                p77_draft_only: p77,
                stage: 0,
                next: 0,
                last: None,
                pending_confirmed: false,
                direct_success: false,
                fault: None,
            })
            .collect()
    }

    fn actions(&self, s: &ParityState, out: &mut Vec<ParityAction>) {
        if s.fault.is_some() {
            return;
        }
        if let Some(cell) = self.cells(s.p77_draft_only, s.stage).get(s.next) {
            out.push(ParityAction::Call(*cell));
        } else if let Some(state) = PATH.get(s.stage.saturating_add(1)) {
            out.push(ParityAction::Advance(*state));
        }
    }

    fn step(&self, s: &ParityState, a: &ParityAction) -> Option<ParityState> {
        if s.fault.is_some() {
            return None;
        }
        let cells = self.cells(s.p77_draft_only, s.stage);
        match a {
            ParityAction::Call(cell) => {
                if cells.get(s.next) != Some(cell) {
                    return None;
                }
                let mut t = ParityState {
                    next: s.next.saturating_add(1),
                    ..s.clone()
                };
                match self.pair(cell) {
                    Ok(pair) => {
                        t.pending_confirmed |= pair.pending_confirmed();
                        t.direct_success |= pair.direct_success();
                        t.last = Some(pair);
                    }
                    Err(e) => {
                        t.last = None;
                        t.fault = Some(e);
                    }
                }
                Some(t)
            }
            ParityAction::Advance(state) => {
                let stage = s.stage.saturating_add(1);
                if s.next < cells.len() || PATH.get(stage) != Some(state) {
                    return None;
                }
                Some(ParityState {
                    stage,
                    next: 0,
                    last: None,
                    ..s.clone()
                })
            }
        }
    }

    fn is_terminal(&self, s: &ParityState) -> bool {
        s.fault.is_some()
            || (s.stage.saturating_add(1) == PATH.len()
                && s.next >= self.cells(s.p77_draft_only, s.stage).len())
    }
}

/// The properties of M-PARITY.
pub fn parity_properties<'a>() -> Vec<Property<'a, ParityModel>> {
    vec![
        Property::always_with("I-84 harness", |s: &ParityState| match &s.fault {
            None => Ok(()),
            Some(e) => Err(format!("I-84: the harness could not run a call: {e}")),
        }),
        Property::transition_with(
            "I-84 direct",
            |_: &ParityState, _: &ParityAction, t: &ParityState| {
                t.last.as_ref().map_or(Ok(()), Pair::direct_parity)
            },
        ),
        Property::transition_with(
            "I-84 pending",
            |_: &ParityState, _: &ParityAction, t: &ParityState| {
                t.last.as_ref().map_or(Ok(()), Pair::pending_parity)
            },
        ),
        Property::reachable(
            "I-84 witness: pending action confirmed",
            |s: &ParityState| s.pending_confirmed,
        ),
        Property::reachable("I-84 witness: direct MCP success", |s: &ParityState| {
            s.direct_success
        }),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    fn pair(exposure: Exposure, web: Observed, mcp: Observed, confirmed: Option<Observed>) -> Pair {
        Pair {
            cell: Cell {
                op: SHORTCUT_OP,
                who: Who::Lead,
                state: PATH[1],
                policy: policy(true),
                session: MCP,
            },
            exposure,
            public: false,
            p75_alone: false,
            web,
            mcp,
            confirmed,
        }
    }

    /// I-84: the parity rules of M-PARITY themselves. A direct exposure
    /// admits the web outcome only. A pending exposure admits `Pending`
    /// with a completing confirmation where the web completes, and the
    /// web's own refusal where it refuses.
    #[test]
    fn i84_m_parity_rules_self_test() {
        let done = Observed::Completed;
        let guard = Observed::Refused(Some("I-07".to_owned()));
        let d = Exposure::Direct;
        let p = Exposure::Pending;
        assert!(
            pair(d, done.clone(), done.clone(), None)
                .direct_parity()
                .is_ok()
        );
        assert!(
            pair(d, done.clone(), Observed::Pending, None)
                .direct_parity()
                .is_err()
        );
        assert!(
            pair(d, guard.clone(), guard.clone(), None)
                .direct_parity()
                .is_ok()
        );
        let ok = pair(p, done.clone(), Observed::Pending, Some(done.clone()));
        assert!(ok.pending_parity().is_ok());
        assert!(ok.pending_confirmed());
        let refused = pair(p, done.clone(), Observed::Pending, Some(guard.clone()));
        assert!(refused.pending_parity().is_err());
        assert!(
            pair(p, done.clone(), done.clone(), None)
                .pending_parity()
                .is_err()
        );
        assert!(
            pair(p, guard.clone(), guard.clone(), None)
                .pending_parity()
                .is_ok()
        );
        let skipped = pair(p, guard.clone(), Observed::Pending, Some(guard.clone()));
        assert!(skipped.pending_parity().is_err());
    }

    /// I-84, I-85, ADR-013 amendment of 2026-11-20: exactly the seven
    /// operations that are not high-risk but whose tool only prepares are
    /// pending exposures under either P-77 value. P-75 and P-77 (Daniel,
    /// 2026-11-20): the two tools that prepare a request setting either
    /// one are those of `creator.save_fields` and `creator.apply_start`.
    /// Of their matrix requests, only the template start sets them, so it
    /// is a pending exposure too. Every other operation with a tool that is
    /// neither high-risk nor binding stays a direct exposure, so `Pending`
    /// through MCP is a violation for it.
    #[test]
    fn i84_m_parity_prepare_only_tools_are_pending_exposures() {
        let reference = authz_reference().unwrap();
        let prepared: Vec<&str> = reference
            .ops()
            .filter(|o| !o.high_risk && o.tool.is_some_and(|t| t.prepare))
            .map(|o| o.name)
            .collect();
        let mut want = vec![
            "call.approve",
            "creator.accept_narrative",
            "creator.acknowledge",
            "creator.invite",
            "creator.request_activation",
            "creator.save_as_template",
            "import.resolve",
        ];
        want.sort_unstable();
        assert_eq!(prepared, want, "the prepare-only operations");
        let agent_policy: Vec<&str> = reference
            .ops()
            .filter(|o| o.tool.is_some_and(|t| t.agent_policy))
            .map(|o| o.name)
            .collect();
        assert_eq!(
            agent_policy,
            ["creator.apply_start", "creator.save_fields"],
            "the tools that prepare a request setting P-75 or P-77"
        );
        let by_request: Vec<&str> = reference
            .ops()
            .filter(|o| o.sets_agent_policy)
            .map(|o| o.name)
            .collect();
        assert_eq!(by_request, ["creator.apply_start"], "P-75, P-77 requests");
        for op in reference.ops().filter(|o| o.tool.is_some()) {
            for p77 in [true, false] {
                let got = exposure(op, &policy(p77));
                let pending = op.high_risk
                    || prepared.contains(&op.name)
                    || by_request.contains(&op.name)
                    || (op.binding && p77);
                let want = if pending {
                    Exposure::Pending
                } else {
                    Exposure::Direct
                };
                assert_eq!(got, want, "{} under P-77 draft only {p77}", op.name);
            }
        }
    }
}
