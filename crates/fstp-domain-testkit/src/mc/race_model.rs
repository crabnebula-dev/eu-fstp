//! The M-RACE model for fstp-mc: a grant request racing a vault change (design sections 4.3 and 6.3).
//!
//! M-RACE alone splits a vault change from its reaction (design 6.1). The
//! start state from genesis has a published call, a verified account a,
//! and its unverified Sybil b holding an Applicant binding in that call.
//!
//! - The vault change verifies b. Without the protocol it is effective at
//!   once. With the verification commit protocol of overview NOTE 4 it is
//!   provisional: only the reaction's queries see it.
//! - The reaction is the platform's `VaultChanged`. With the protocol the
//!   vault makes the fact effective in the same step, once the reaction is
//!   recorded, and the next command first processes that epoch as the
//!   driver does (NOTE 3).
//! - The grant request is a `GrantRole` of committee member to a, split into
//!   asking the vault and committing the decision, as an M3 driver does over
//!   a network. The commit decides with the answers asked earlier, so it is
//!   refused as stale when the state's epoch moved in between.
//!
//! I-06 is checked over the vault's effective facts in every state.
//! Without the protocol, the grant asked before the change and committed
//! before the reaction leaves a's committee binding and b's Applicant
//! binding under one verified identity, which `i06_m_race_without_protocol_reaches_violation`
//! shows. With the protocol, no state breaks I-06.
//!
//! Reading, and an open point for Daniel: NOTE 4 says the vault makes the
//! fact effective after the reaction is recorded. If a command asked after
//! the reaction but before the switch could still commit, its answers
//! would not see the provisional fact, and the switch could then break
//! I-06. The model takes the reaction and the switch as one step, which is
//! the reading under which I-06 holds at every instant.

use fstp_domain::command::Ctx;
use fstp_domain::id::{BindingId, ProposalId, VaultEpoch};
use fstp_domain::oracle::Answers;
use fstp_domain::roles::Role;
use fstp_mc::{Model, Property};

use crate::r#gen::roster::{
    A, B, Backend, Facts, P1, SodSetup, SodWorld, Step, T0, call, draft, grant, sod_truth,
};
use crate::mc::sod_model::{SodMcState, react_with};
use crate::reference::sod::{check_granted, check_i06, check_voids, expected_binding, verdict};

/// The binding id of the racing grant.
pub const RACE_GRANT: BindingId = BindingId::from_raw(1_500);
/// The proposal and binding id of b's draft.
pub const RACE_DRAFT: u128 = 1_400;

/// The state count of M-RACE with the protocol, measured on the reference
/// backend in step W3b. Step W6 writes the production count here.
pub const M_RACE_PROTOCOL_STATES: usize = 19;
/// The state count of M-RACE without the protocol, measured likewise.
pub const M_RACE_NO_PROTOCOL_STATES: usize = 12;

/// The grant request of M-RACE.
pub fn race_grant() -> Step {
    grant(RACE_GRANT, A, P1, Role::CommitteeMember, T0)
}

/// Where the grant request is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Inflight {
    /// Not asked yet.
    Idle,
    /// Asked: the context, the answers, the epoch they were asked at and
    /// whether the reference accepts the grant on the facts asked.
    Asked {
        /// The context.
        ctx: Ctx,
        /// The answers.
        answers: Answers,
        /// The state's epoch at the asking.
        epoch: VaultEpoch,
        /// The reference verdict on the facts at the asking.
        accepts: bool,
    },
    /// Committed.
    Committed,
    /// Refused at commit. `stale` when the state's epoch moved since the asking.
    Refused {
        /// Whether the answers were older than the state at the commit.
        stale: bool,
    },
}

/// One M-RACE state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RaceState {
    /// The world and divergence, as in the other SoD models.
    pub inner: SodMcState,
    /// The grant request.
    pub grant: Inflight,
    /// Whether the vault change happened.
    pub changed: bool,
}

/// An M-RACE action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RaceAction {
    /// The vault verifies b: provisional with the protocol, effective without.
    Change,
    /// The platform reacts to the newer epoch. With the protocol the vault
    /// then makes the fact effective.
    React,
    /// The grant request asks the vault, after processing any newer epoch.
    Ask,
    /// The grant request commits with the answers it asked.
    Commit,
}

/// The M-RACE model.
pub struct RaceModel {
    /// Whether the verification commit protocol is on.
    pub protocol: bool,
    /// The start state.
    pub start: RaceState,
}

impl RaceModel {
    /// The model with its start state built from genesis.
    pub fn new(protocol: bool, backend: Backend) -> Result<RaceModel, String> {
        let mut setup = SodSetup::one(1, &[1]);
        setup.published = vec![call(1)];
        let mut world = SodWorld::from_setup(backend, sod_truth(), &setup)?;
        let step = draft(
            B,
            ProposalId::from_raw(RACE_DRAFT),
            call(1),
            BindingId::from_raw(RACE_DRAFT),
            false,
        );
        match world.exec(&step, Facts::Effective)? {
            Ok(_) => {}
            Err(r) => return Err(format!("M-RACE start: b's draft refused: {r}")),
        }
        Ok(RaceModel {
            protocol,
            start: RaceState {
                inner: SodMcState::new(world),
                grant: Inflight::Idle,
                changed: false,
            },
        })
    }

    /// The reaction, then the switch to effective under the protocol.
    fn react(&self, s: &RaceState) -> Option<RaceState> {
        if s.inner.world.truth.epoch() <= s.inner.world.epoch() {
            return None;
        }
        let provisional = !s.inner.truth().provisional_accounts().is_empty();
        let facts = if provisional {
            Facts::WithProvisional
        } else {
            Facts::Effective
        };
        let mut inner = react_with(s.inner.clone(), facts)?;
        if provisional && inner.divergence.is_none() {
            for account in inner.truth().provisional_accounts() {
                inner.world.truth.make_effective(account);
            }
        }
        Some(RaceState {
            inner,
            grant: s.grant.clone(),
            changed: s.changed,
        })
    }

    fn ask(&self, s: &RaceState) -> Option<RaceState> {
        if s.grant != Inflight::Idle {
            return None;
        }
        let mut inner = match self.react(s) {
            Some(reacted) if reacted.inner.divergence.is_some() => return Some(reacted),
            Some(reacted) => reacted.inner,
            None => s.inner.clone(),
        };
        let step = race_grant();
        let accepts = verdict(inner.view(), inner.truth(), &step.ask(T0)).accepts();
        let epoch = inner.world.epoch();
        let grant = match inner.world.backend {
            Backend::Production => match inner.world.ask(&step, Facts::Effective) {
                Ok((ctx, answers)) => Inflight::Asked {
                    ctx,
                    answers,
                    epoch,
                    accepts,
                },
                Err(r) => {
                    if accepts {
                        inner.divergence = Some(format!(
                            "M-RACE ask: over-denial, the reference accepts, production refuses with {r}"
                        ));
                    }
                    Inflight::Refused { stale: false }
                }
            },
            Backend::Reference => Inflight::Asked {
                ctx: inner.world.ctx(&step),
                answers: Answers::new(),
                epoch,
                accepts,
            },
        };
        Some(RaceState {
            inner,
            grant,
            changed: s.changed,
        })
    }

    fn commit(&self, s: &RaceState) -> Option<RaceState> {
        let Inflight::Asked {
            ctx,
            answers,
            epoch,
            accepts,
        } = &s.grant
        else {
            return None;
        };
        let step = race_grant();
        let stale = *epoch != s.inner.world.epoch();
        let reference = *accepts && !stale;
        let mut inner = s.inner.clone();
        let decided = match inner.world.backend {
            Backend::Production => fstp_domain::decide(&inner.world.state, &step.cmd, ctx, answers)
                .map_err(|r| r.to_string()),
            Backend::Reference => {
                if reference {
                    let mut records = Vec::new();
                    if let Some(e) = expected_binding(inner.view(), &step.ask(T0)) {
                        records.push(fstp_domain::record::Record::BindingGranted(
                            fstp_domain::record::BindingGranted {
                                binding: e.binding,
                                account: e.account,
                                programme: e.programme,
                                role: e.role,
                                scope: e.scope,
                                start: e.start,
                                granted_by: e.granted_by,
                                second_admin: None,
                                confidentiality: None,
                                organisation: None,
                                verified_epoch: Some(*epoch),
                            },
                        ));
                    }
                    Ok(records)
                } else {
                    Err("refused".to_owned())
                }
            }
        };
        let grant = match decided {
            Ok(records) => {
                if !reference {
                    inner.divergence = Some(
                        "M-RACE commit: over-permission, production commits a grant the reference refuses"
                            .to_owned(),
                    );
                } else {
                    let context = "M-RACE commit";
                    let checked = match expected_binding(inner.view(), &step.ask(T0)) {
                        Some(e) => check_granted(context, &e, &records),
                        None => Err(format!("{context}: no expected binding")),
                    }
                    .and_then(|()| check_voids(context, &Default::default(), &records));
                    if let Err(e) = checked {
                        inner.divergence = Some(e);
                    } else if let Err(e) = inner.world.commit(&records) {
                        inner.divergence = Some(e);
                    }
                }
                Inflight::Committed
            }
            Err(r) => {
                if reference {
                    inner.divergence = Some(format!(
                        "M-RACE commit: over-denial, the reference accepts, production refuses with {r}"
                    ));
                }
                Inflight::Refused { stale }
            }
        };
        Some(RaceState {
            inner,
            grant,
            changed: s.changed,
        })
    }
}

impl Model for RaceModel {
    type State = RaceState;
    type Action = RaceAction;

    fn init(&self) -> Vec<RaceState> {
        vec![self.start.clone()]
    }

    fn actions(&self, _: &RaceState, actions: &mut Vec<RaceAction>) {
        actions.extend([
            RaceAction::Change,
            RaceAction::React,
            RaceAction::Ask,
            RaceAction::Commit,
        ]);
    }

    fn step(&self, s: &RaceState, a: &RaceAction) -> Option<RaceState> {
        if s.inner.divergence.is_some() {
            return None;
        }
        match a {
            RaceAction::Change => {
                if s.changed {
                    return None;
                }
                let mut next = s.clone();
                if self.protocol {
                    next.inner.world.truth.verify_provisional(B);
                } else {
                    next.inner.world.truth.verify(B);
                }
                next.changed = true;
                Some(next)
            }
            RaceAction::React => self.react(s),
            RaceAction::Ask => self.ask(s),
            RaceAction::Commit => self.commit(s),
        }
    }

    fn is_terminal(&self, s: &RaceState) -> bool {
        s.inner.divergence.is_some()
    }
}

/// The M-RACE properties: `two-way`, `always("I-06")` over the effective
/// facts, and witnesses of the race.
pub fn race_properties<'a, M: Model<State = RaceState>>() -> Vec<Property<'a, M>> {
    vec![
        Property::<M>::always_with("two-way", |s: &RaceState| match &s.inner.divergence {
            None => Ok(()),
            Some(d) => Err(format!("two-way: {d}")),
        }),
        Property::<M>::always_with("I-06", |s: &RaceState| {
            check_i06(s.inner.view(), s.inner.truth())
        }),
        Property::<M>::reachable(
            "M-RACE witness: the grant committed before the reaction, which voided the Sybil",
            |s: &RaceState| {
                s.grant == Inflight::Committed
                    && s.inner
                        .view()
                        .bindings
                        .get(&BindingId::from_raw(RACE_DRAFT))
                        .is_some_and(|b| b.voided.is_some())
            },
        ),
        Property::<M>::reachable(
            "M-RACE witness: a grant asked across the reaction is refused as stale",
            |s: &RaceState| s.grant == Inflight::Refused { stale: true },
        ),
        Property::<M>::reachable(
            "M-RACE witness: b is verified and still applies when no Judging binding clashes",
            |s: &RaceState| {
                s.inner.truth().is_verified(B)
                    && s.inner
                        .view()
                        .bindings
                        .get(&BindingId::from_raw(RACE_DRAFT))
                        .is_some_and(|b| b.held())
            },
        ),
    ]
}
