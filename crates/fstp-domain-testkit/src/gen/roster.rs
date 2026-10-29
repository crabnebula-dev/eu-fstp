//! Generators, fixtures, the model driver and the fstp-prop machine for roles and SoD (design sections 4.5 and 6.1).
//!
//! Synthetic data only: numeric ids and synthetic identity numbers. No real
//! personal data. The machine draws its Sybil and excluded applicants from
//! the W2 vault fixtures [`sybil_pair`] and [`excluded_applicant`]. The
//! models, which have no generator, build the same corpus shapes by hand.
//!
//! - [`SodSetup`] lists the production commands that reach a start state
//!   from genesis: programmes with P-12 and P-13, staff bindings and calls
//!   drafted and approved, some of them published.
//! - [`SodWorld`] is the driver of the models. It runs production `queries`,
//!   `decide` and `apply` over a synthetic vault, without a store, so the
//!   model state is the history-normalised projection and interleavings
//!   merge (design 0.1). Its [`Backend::Reference`] mode runs the same
//!   steps on the reference alone, for measuring model sizes and checking
//!   that witnesses are reachable before production lands.
//! - [`SodMachine`] is the fstp-prop machine over `GrantRole`, `EndRole`,
//!   `ReinstateBinding`, `PublishCall`, `EditPolicy` (P-12 and P-13),
//!   `CreateDraft`, `AddTeamMember`, `AddGuardian` and vault changes. The
//!   vault changes are verifications, new affiliations and identity merges
//!   ([`VaultOp::Merge`]). It runs through a [`Scenario`], so every step
//!   also checks the ledger (I-23).
//!
//! Reading for the models: no SoD guard compares wall-clock times, only
//! call sequences and ledger order (P-12 NOTE 4). So model commands all run
//! at one instant, [`T0`], and the reduced clock has nothing to move. The
//! machine moves time by zero or one microsecond per step, which also
//! places an end at the same instant as a publication.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::command::{Actor, Command, Ctx, SystemCause, Via};
use fstp_domain::id::{
    AccountId, BindingId, CallId, CallSeq, ClassId, CommandId, LlmConfigId, OrganisationId,
    PolicyVersionId, ProgrammeId, ProposalId,
};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::policy::{ExclusionClasses, ModelRef, PolicyVersion};
use fstp_domain::record::{
    BindingEnded, BindingGranted, BindingReinstated, BindingSuspended, BindingVoided, Record,
};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::state::State;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_engine::{ExecError, Record as EngineRecord};
use fstp_ledger::{Entry, Seq};
use fstp_money::Currency;
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::policy::{MODEL_A, base_version, core_records, eur, next_version, text};
use crate::harness::prop::{ledger_step, two_way_exec};
use crate::reference::sod::{
    Ask, ExpectedBinding, RefGroup, Verdict, View, check_bars, check_ended, check_granted,
    check_i01, check_i02, check_i04, check_i06, check_suspensions, check_voids, expected_binding,
    expected_suspensions, expected_voids, spec_group, verdict,
};
use crate::scenario::Scenario;
use crate::vault::{GroundTruth, IdentityTag, PendingFact, excluded_applicant, sybil_pair};

// ---------------------------------------------------------------------------
// Synthetic accounts and ids
// ---------------------------------------------------------------------------

/// The tenant admin. Verified, so a self-grant of a Drafting or Judging role can pass SoD-09.
pub const ADMIN: AccountId = AccountId::from_raw(1);
/// The second tenant admin who approves self-grants (SoD-07).
pub const ADMIN_2: AccountId = AccountId::from_raw(2);
/// The staff programme manager who approves and publishes calls and edits policy.
pub const STAFF_PM: AccountId = AccountId::from_raw(3);
/// The staff call drafter who drafts calls.
pub const STAFF_DRAFTER: AccountId = AccountId::from_raw(4);

/// Model account a: shares an identity with b (corpus variant "Sybil").
pub const A: AccountId = AccountId::from_raw(101);
/// Model account b: the Sybil of a, unverified at the start.
pub const B: AccountId = AccountId::from_raw(102);
/// Model account c: a distinct identity.
pub const C: AccountId = AccountId::from_raw(103);

/// The identity behind a and b.
pub const ID_AB: IdentityTag = IdentityTag::new(1001);
/// The identity behind c.
pub const ID_C: IdentityTag = IdentityTag::new(1003);

/// The first programme.
pub const P1: ProgrammeId = ProgrammeId::from_raw(1);
/// The second programme.
pub const P2: ProgrammeId = ProgrammeId::from_raw(2);

/// Excluded affiliation class 1.
pub const K1: ClassId = ClassId::from_raw(1);
/// Excluded affiliation class 2.
pub const K2: ClassId = ClassId::from_raw(2);
/// Excluded affiliation class 3.
pub const K3: ClassId = ClassId::from_raw(3);

/// The instant every model command runs at, and the machine's first instant.
pub const T0: Timestamp = Timestamp::from_micros(1_000_000);
/// The opening of every call: before every command.
pub const CALL_OPENS: Timestamp = Timestamp::from_micros(0);
/// The deadline of every call: after every command.
pub const CALL_DEADLINE: Timestamp = Timestamp::from_micros(4_000_000_000_000);

/// The instant from which the over-18 attestation of a lead whose draft is
/// not flagged as a minor's shows the lead 18 or older: the opening of
/// every call, so before every deadline (R-ID-04, overview NOTE 7).
pub const LEAD_ADULT_FROM: Timestamp = CALL_OPENS;

/// The instant from which a lead who turns 18 after the deadline is shown
/// 18 or older: one microsecond after [`CALL_DEADLINE`] (R-ID-04).
pub const LEAD_ADULT_AFTER_DEADLINE: Timestamp = Timestamp::from_micros(4_000_000_000_001);

/// The call with synthetic number `n`.
pub const fn call(n: u128) -> CallId {
    CallId::from_raw(n)
}

/// The staff bindings of `programme`: programme manager and call drafter.
pub const fn staff_bindings(programme: ProgrammeId) -> [BindingId; 2] {
    let base = programme.raw().saturating_mul(10);
    [
        BindingId::from_raw(base.saturating_add(1)),
        BindingId::from_raw(base.saturating_add(2)),
    ]
}

/// Whether `binding` is a staff binding of the setup.
pub fn is_staff_binding(binding: BindingId) -> bool {
    binding.raw() < 100
}

/// Whether `account` is a tenant admin at tenant scope, as the shell attests.
pub fn is_tenant_admin(account: AccountId) -> bool {
    account == ADMIN || account == ADMIN_2
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// The shell's attestations for one command (`Ctx` fields beside time and actor).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flags {
    /// `Ctx::tenant_admin`.
    pub tenant_admin: bool,
    /// `Ctx::second_tenant_admin`.
    pub second_admin: Option<AccountId>,
    /// `Ctx::binds_tenant_admin`.
    pub binds_tenant_admin: bool,
}

impl Flags {
    /// No attestation.
    pub const NONE: Flags = Flags {
        tenant_admin: false,
        second_admin: None,
        binds_tenant_admin: false,
    };
    /// The actor is a tenant admin.
    pub const ADMIN: Flags = Flags {
        tenant_admin: true,
        second_admin: None,
        binds_tenant_admin: false,
    };
}

/// One command with its actor and attestations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Step {
    /// The actor.
    pub actor: Actor,
    /// The attestations.
    pub flags: Flags,
    /// The command.
    pub cmd: Command,
}

impl Step {
    /// A command by `account` with `flags`.
    pub fn by(account: AccountId, flags: Flags, cmd: Command) -> Step {
        Step {
            actor: Actor::Account(account),
            flags,
            cmd,
        }
    }

    /// The reference's view of this step at `now`.
    pub fn ask(&self, now: Timestamp) -> Ask<'_> {
        Ask {
            actor: self.actor,
            tenant_admin: self.flags.tenant_admin,
            second_tenant_admin: self.flags.second_admin,
            binds_tenant_admin: self.flags.binds_tenant_admin,
            now,
            cmd: &self.cmd,
        }
    }

    /// The context of this step at `now` with command id `command`.
    pub fn ctx(&self, now: Timestamp, command: CommandId) -> Ctx {
        Ctx {
            now,
            actor: self.actor,
            command,
            via: Via::Web,
            tenant_admin: self.flags.tenant_admin,
            second_tenant_admin: self.flags.second_admin,
            binds_tenant_admin: self.flags.binds_tenant_admin,
        }
    }
}

/// A `GrantRole` by the tenant admin, starting at `start`, with
/// confidentiality terms for Drafting and Judging roles and an
/// organisation for committee members.
pub fn grant(
    binding: BindingId,
    account: AccountId,
    programme: ProgrammeId,
    role: Role,
    start: Timestamp,
) -> Step {
    let group = spec_group(role);
    let second_admin = (account == ADMIN).then_some(ADMIN_2);
    let flags = Flags {
        tenant_admin: true,
        second_admin,
        binds_tenant_admin: is_tenant_admin(account),
    };
    Step::by(
        ADMIN,
        flags,
        Command::GrantRole {
            binding,
            account,
            programme,
            role,
            start,
            second_admin,
            confidentiality: group
                .needs_verification()
                .then(|| text(binding.raw().saturating_add(50_000))),
            organisation: (role == Role::CommitteeMember)
                .then(|| OrganisationId::from_raw(account.raw())),
            end: None,
        },
    )
}

/// An `EndRole` of `binding` at `at` by the tenant admin.
pub fn end(binding: BindingId, at: Timestamp) -> Step {
    Step::by(ADMIN, Flags::ADMIN, Command::EndRole { binding, at })
}

/// A [`grant`] that also schedules the binding's end at `end` (Cooling-off
/// NOTE, decided 2026-10-25). The `end` member is set on the JSON form of
/// the command, which the command codec then decodes. The stub interface
/// does not declare the member yet, so until it does the decode fails and
/// this returns the error.
pub fn grant_until(
    binding: BindingId,
    account: AccountId,
    programme: ProgrammeId,
    role: Role,
    start: Timestamp,
    end: Timestamp,
) -> Result<Step, String> {
    use fstp_json::ToJson;
    let mut step = grant(binding, account, programme, role, start);
    let mut v = step.cmd.to_json();
    match &mut v {
        fstp_json::Value::Object(o) => {
            o.insert(
                "end".to_owned(),
                fstp_json::Value::String(end.micros().to_string()),
            );
        }
        _ => return Err("the JSON form of GrantRole is not an object".to_owned()),
    }
    step.cmd = fstp_domain::codec::command_from_json(&v)
        .map_err(|e| format!("GrantRole carries no scheduled end yet (Cooling-off NOTE): {e:?}"))?;
    Ok(step)
}

/// A `ReinstateBinding` of `binding` by the tenant admin, with a synthetic reason.
pub fn reinstate(binding: BindingId) -> Step {
    Step::by(
        ADMIN,
        Flags::ADMIN,
        Command::ReinstateBinding {
            binding,
            reason: text(binding.raw().saturating_add(70_000)),
        },
    )
}

/// A `CreateDraft` by `lead` in `call`.
pub fn draft(
    lead: AccountId,
    proposal: ProposalId,
    call: CallId,
    binding: BindingId,
    minor: bool,
) -> Step {
    let flags = Flags {
        tenant_admin: is_tenant_admin(lead),
        second_admin: None,
        binds_tenant_admin: is_tenant_admin(lead),
    };
    Step::by(
        lead,
        flags,
        Command::CreateDraft {
            proposal,
            call,
            binding,
            minor,
        },
    )
}

/// An `AddTeamMember`, or an `AddGuardian` when `guardian`, by `lead`.
pub fn add_member(
    lead: AccountId,
    proposal: ProposalId,
    account: AccountId,
    binding: BindingId,
    guardian: bool,
) -> Step {
    let flags = Flags {
        tenant_admin: is_tenant_admin(lead),
        second_admin: None,
        binds_tenant_admin: is_tenant_admin(account),
    };
    let cmd = if guardian {
        Command::AddGuardian {
            proposal,
            account,
            binding,
        }
    } else {
        Command::AddTeamMember {
            proposal,
            account,
            binding,
        }
    };
    Step::by(lead, flags, cmd)
}

/// A `PublishCall` of `call` by the staff programme manager.
pub fn publish(call: CallId) -> Step {
    Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::PublishCall {
            call,
            config: LlmConfigId::from_raw(call.raw()),
            config_model: ModelRef(MODEL_A.to_owned()),
        },
    )
}

/// An `EditPolicy` by the staff programme manager on `head`, as version
/// `id`, with `change` applied.
pub fn edit_policy(
    head: &PolicyVersion,
    id: PolicyVersionId,
    change: impl FnOnce(&mut PolicyVersion),
) -> Step {
    let mut v = next_version(head, id);
    change(&mut v);
    Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::EditPolicy {
            base: head.id,
            version: Box::new(v),
        },
    )
}

// ---------------------------------------------------------------------------
// Setup from genesis
// ---------------------------------------------------------------------------

/// A start state from genesis: what [`SodSetup::steps`] runs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SodSetup {
    /// The programmes, each with version id equal to its number.
    pub programmes: Vec<ProgrammeId>,
    /// P-12 of every programme.
    pub p12: u8,
    /// P-13 of every programme.
    pub p13: BTreeSet<ClassId>,
    /// The calls drafted and approved, with their programme.
    pub calls: Vec<(ProgrammeId, CallId)>,
    /// The calls published during the setup, in order.
    pub published: Vec<CallId>,
}

impl SodSetup {
    /// One programme with P-12 `p12`, P-13 {K1} and `calls` drafted and approved.
    pub fn one(p12: u8, calls: &[u128]) -> SodSetup {
        SodSetup {
            programmes: vec![P1],
            p12,
            p13: [K1].into_iter().collect(),
            calls: calls.iter().map(|n| (P1, call(*n))).collect(),
            published: Vec::new(),
        }
    }

    /// The first policy version of `programme`.
    pub fn version(&self, programme: ProgrammeId) -> Result<PolicyVersion, String> {
        let mut v = base_version(PolicyVersionId::from_raw(programme.raw()), programme, None)?;
        v.live.p12 = CoolingOff(self.p12);
        v.live.p13 = ExclusionClasses(self.p13.clone());
        Ok(v)
    }

    /// The production commands of the setup, in order.
    pub fn steps(&self) -> Result<Vec<Step>, String> {
        let mut out = Vec::new();
        for p in &self.programmes {
            out.push(Step::by(
                ADMIN,
                Flags::ADMIN,
                Command::CreateProgramme {
                    policy: Box::new(self.version(*p)?),
                },
            ));
            let [pm, drafter] = staff_bindings(*p);
            out.push(grant(pm, STAFF_PM, *p, Role::ProgrammeManager, T0));
            out.push(grant(drafter, STAFF_DRAFTER, *p, Role::CallDrafter, T0));
        }
        let zone = ZoneName::new("Europe/Brussels").ok_or("zone")?;
        for (p, c) in &self.calls {
            out.push(Step::by(
                STAFF_DRAFTER,
                Flags::NONE,
                Command::DraftCall {
                    call: *c,
                    programme: *p,
                    opens: CALL_OPENS,
                    deadline: CALL_DEADLINE,
                    deadline_zone: zone.clone(),
                    budget: eur(100_000_000)?,
                    text: text(c.raw().saturating_add(10_000)),
                },
            ));
            out.push(Step::by(
                STAFF_PM,
                Flags::NONE,
                Command::ApproveCallPublication {
                    call: *c,
                    decision: fstp_domain::id::DecisionId::from_raw(c.raw()),
                },
            ));
        }
        for c in &self.published {
            out.push(publish(*c));
        }
        Ok(out)
    }
}

/// Gives each staff account and the tenant admin its own verified identity.
pub fn add_staff(truth: &mut GroundTruth) {
    for (a, t) in [
        (ADMIN, 901),
        (ADMIN_2, 902),
        (STAFF_PM, 903),
        (STAFF_DRAFTER, 904),
    ] {
        truth.set_identity(a, IdentityTag::new(t));
        truth.verify(a);
    }
}

/// The vault of M-SOD: staff, a and b sharing [`ID_AB`] with a verified and
/// b not, and c with [`ID_C`], verified. The corpus variant "Sybil" with
/// the applicant still unverified.
pub fn sod_truth() -> GroundTruth {
    let mut truth = GroundTruth::new();
    add_staff(&mut truth);
    truth.set_identity(A, ID_AB);
    truth.set_identity(B, ID_AB);
    truth.set_identity(C, ID_C);
    truth.verify(A);
    truth.verify(C);
    truth
}

// ---------------------------------------------------------------------------
// The model driver
// ---------------------------------------------------------------------------

/// Which facts a vault answer counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Facts {
    /// Effective facts only: every query except a reaction's (overview NOTE 4).
    Effective,
    /// Effective and provisional facts: the queries of the reaction to a
    /// provisional fact (overview NOTE 4, the exception).
    WithProvisional,
}

/// The facts of `truth` with every provisional fact taken as effective, for
/// the queries of a reaction: [`GroundTruth::reaction_view`] (overview NOTE 4).
pub fn reaction_truth(truth: &GroundTruth) -> GroundTruth {
    truth.reaction_view()
}

/// The answer to `q` under `facts` of `truth`, at the epoch of `truth`.
/// A reaction's answers come from [`GroundTruth::answer_in_reaction`].
pub fn answer(truth: &GroundTruth, facts: Facts, q: &Query) -> Answer {
    match facts {
        Facts::Effective => truth.answer(q),
        Facts::WithProvisional => truth.answer_in_reaction(q),
    }
}

/// The accounts a `VaultChanged` after `epoch` lists under `facts`.
pub fn changed_accounts(
    truth: &GroundTruth,
    facts: Facts,
    epoch: fstp_domain::id::VaultEpoch,
) -> BTreeSet<AccountId> {
    match facts {
        Facts::Effective => truth.changed_since(epoch),
        Facts::WithProvisional => truth.reaction_changed_since(epoch),
    }
}

/// What decides the model steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Production `queries`, `decide` and `apply`.
    Production,
    /// The reference alone: accepted steps record what the reference expects.
    Reference,
}

/// The command id every model command uses. The pure functions never read it.
const MODEL_COMMAND: CommandId = CommandId::from_bytes(*b"model:sod:steps!");

/// The model refusal of a step the reference refuses, in reference mode.
const REFERENCE_REFUSAL: Refusal = Refusal::new(RuleRef::Input, RefusalReason::GuardFailed);

/// A model world: the production projection, the vault facts and the
/// reference view, at one instant. It holds no ledger, so two histories
/// that reach the same situation give equal worlds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SodWorld {
    /// What decides.
    pub backend: Backend,
    /// The production projection. Genesis in reference mode.
    pub state: State,
    /// The vault facts.
    pub truth: GroundTruth,
    /// The reference view of every record committed.
    pub view: View,
    /// The instant of every command.
    pub now: Timestamp,
}

/// What a step did: the records it committed, or the refusal. The outer
/// error is a harness failure, such as a batch the fold refused.
pub type StepResult = Result<Result<Vec<Record>, Refusal>, String>;

impl SodWorld {
    /// A world at genesis over `truth`.
    pub fn new(backend: Backend, truth: GroundTruth) -> SodWorld {
        SodWorld {
            backend,
            state: State::genesis(),
            truth,
            view: View::new(),
            now: T0,
        }
    }

    /// A world after running `setup` from genesis. Every step must succeed.
    pub fn from_setup(
        backend: Backend,
        truth: GroundTruth,
        setup: &SodSetup,
    ) -> Result<SodWorld, String> {
        let mut w = SodWorld::new(backend, truth);
        for step in setup.steps()? {
            let kind = step.cmd.kind();
            if let Err(r) = w.sync(Facts::Effective)? {
                return Err(format!(
                    "setup: the VaultChanged processed before {kind:?} was refused: {r}"
                ));
            }
            if let Err(r) = w.exec(&step, Facts::Effective)? {
                return Err(format!("setup step {kind:?} refused: {r}"));
            }
        }
        Ok(w)
    }

    /// The context of `step` now.
    pub fn ctx(&self, step: &Step) -> Ctx {
        step.ctx(self.now, MODEL_COMMAND)
    }

    /// The vault epoch the world has processed.
    pub fn epoch(&self) -> fstp_domain::id::VaultEpoch {
        match self.backend {
            Backend::Production => self.state.epoch(),
            Backend::Reference => self.view.epoch,
        }
    }

    /// Asks the production questions of `step` and their answers under `facts`.
    pub fn ask(&self, step: &Step, facts: Facts) -> Result<(Ctx, Answers), Refusal> {
        let ctx = self.ctx(step);
        let mut answers = Answers::new();
        for q in fstp_domain::queries(&self.state, &step.cmd, &ctx)? {
            let a = answer(&self.truth, facts, &q);
            answers.insert(q, a);
        }
        Ok((ctx, answers))
    }

    /// Folds `records` into the projection and the view, as one batch.
    /// Nothing changes when either fold refuses.
    pub fn commit(&mut self, records: &[Record]) -> Result<(), String> {
        let mut view = self.view.clone();
        for r in records {
            view.fold_with(r, &self.truth)
                .map_err(|e| format!("the reference cannot follow {r:?}: {e}"))?;
        }
        if self.backend == Backend::Production {
            let mut state = self.state.clone();
            for r in records {
                fstp_domain::apply(&mut state, Seq::from_raw(1), self.now, r)
                    .map_err(|e| format!("production refused to fold its own record {r:?}: {e}"))?;
            }
            self.state = state;
        }
        self.view = view;
        Ok(())
    }

    /// Processes a newer vault epoch with `VaultChanged`, its queries
    /// answered under `reaction`. Returns the records, empty when the epoch
    /// is current, or the refusal.
    pub fn sync(&mut self, reaction: Facts) -> StepResult {
        let ours = self.epoch();
        let target = self.truth.epoch();
        if target <= ours {
            return Ok(Ok(Vec::new()));
        }
        let step = Step {
            actor: Actor::System(SystemCause::Vault),
            flags: Flags::NONE,
            cmd: Command::VaultChanged {
                epoch: target,
                changed: changed_accounts(&self.truth, reaction, ours),
            },
        };
        let records = match self.backend {
            Backend::Production => {
                let (ctx, answers) = match self.ask(&step, reaction) {
                    Ok(x) => x,
                    Err(r) => return Ok(Err(r)),
                };
                match fstp_domain::decide(&self.state, &step.cmd, &ctx, &answers) {
                    Ok(records) => records,
                    Err(r) => return Ok(Err(r)),
                }
            }
            Backend::Reference => {
                let seen = match reaction {
                    Facts::Effective => self.truth.clone(),
                    Facts::WithProvisional => reaction_truth(&self.truth),
                };
                let mut out = voids(&self.view, &seen, target);
                out.extend(suspensions(&self.view, &seen, target));
                out.push(Record::VaultEpochProcessed { epoch: target });
                out
            }
        };
        self.commit(&records)?;
        Ok(Ok(records))
    }

    /// Moves `now` to `at` and runs every System command that `due` lists
    /// then, as the M6 timeline does (design 3.6). Each runs with the
    /// actor `System(Timeline)`, after the reaction to a newer vault epoch.
    /// In reference mode the reference records the scheduled ends due at
    /// `at` instead (Cooling-off NOTE, decided 2026-10-25). Returns every
    /// record, or the first refusal.
    pub fn arrive(&mut self, at: Timestamp) -> StepResult {
        self.now = at;
        if let Err(r) = self.sync(Facts::Effective)? {
            return Ok(Err(r));
        }
        let mut all = Vec::new();
        match self.backend {
            Backend::Production => {
                for cmd in fstp_domain::due(&self.state, at) {
                    let step = Step {
                        actor: Actor::System(SystemCause::Timeline),
                        flags: Flags::NONE,
                        cmd,
                    };
                    let (ctx, answers) = match self.ask(&step, Facts::Effective) {
                        Ok(x) => x,
                        Err(r) => return Ok(Err(r)),
                    };
                    let records = match fstp_domain::decide(&self.state, &step.cmd, &ctx, &answers)
                    {
                        Ok(r) => r,
                        Err(r) => return Ok(Err(r)),
                    };
                    self.commit(&records)?;
                    all.extend(records);
                }
            }
            Backend::Reference => {
                for (binding, scheduled) in crate::reference::sod::due_ends(&self.view, at) {
                    let (bar, p12) = crate::reference::sod::expected_end(&self.view, binding)
                        .ok_or("reference mode: unknown binding")?;
                    all.push(Record::BindingEnded(BindingEnded {
                        binding,
                        at: scheduled,
                        barred_through: bar,
                        p12: CoolingOff(p12),
                    }));
                }
                self.commit(&all)?;
            }
        }
        Ok(Ok(all))
    }

    /// Runs `step`: first the reaction to a newer vault epoch, as the driver
    /// does (overview NOTE 3), then the step. Returns the step's records.
    pub fn exec(&mut self, step: &Step, reaction: Facts) -> StepResult {
        if let Err(r) = self.sync(reaction)? {
            return Ok(Err(r));
        }
        let records = match self.backend {
            Backend::Production => {
                let (ctx, answers) = match self.ask(step, Facts::Effective) {
                    Ok(x) => x,
                    Err(r) => return Ok(Err(r)),
                };
                match fstp_domain::decide(&self.state, &step.cmd, &ctx, &answers) {
                    Ok(records) => records,
                    Err(r) => return Ok(Err(r)),
                }
            }
            Backend::Reference => match synthesize(&self.view, &self.truth, step, self.now)? {
                Ok(records) => records,
                Err(r) => return Ok(Err(r)),
            },
        };
        self.commit(&records)?;
        Ok(Ok(records))
    }
}

/// The `BindingVoided` records the reference expects of a reaction at
/// `epoch`, under I-06 whenever it applies (R-CF-04).
fn voids(view: &View, truth: &GroundTruth, epoch: fstp_domain::id::VaultEpoch) -> Vec<Record> {
    expected_voids(view, truth)
        .into_iter()
        .filter_map(|(binding, rules)| {
            let rule = if rules.contains(&RuleRef::I06) {
                Some(RuleRef::I06)
            } else {
                rules.first().copied()
            };
            rule.map(|rule| {
                Record::BindingVoided(BindingVoided {
                    binding,
                    rule,
                    epoch,
                })
            })
        })
        .collect()
}

/// The `BindingSuspended` records the reference expects of a reaction at
/// `epoch`: each Judging binding in a conflict of interest, under I-06, the
/// marker (Identity discovery, decided 2026-10-25).
fn suspensions(
    view: &View,
    truth: &GroundTruth,
    epoch: fstp_domain::id::VaultEpoch,
) -> Vec<Record> {
    expected_suspensions(view, truth)
        .into_iter()
        .map(|binding| {
            Record::BindingSuspended(BindingSuspended {
                binding,
                rule: RuleRef::I06,
                epoch,
            })
        })
        .collect()
}

/// The records the reference expects of `step`, or the refusal when it
/// refuses. The refusal names the rule the reference gives, or `Input`.
/// Commands outside the reference are taken as accepted with the records a
/// correct engine emits, which the setups need.
fn synthesize(
    view: &View,
    truth: &GroundTruth,
    step: &Step,
    now: Timestamp,
) -> Result<Result<Vec<Record>, Refusal>, String> {
    let actor = match step.actor {
        Actor::Account(a) => a,
        Actor::System(_) => return Err("reference mode runs no System command".to_owned()),
    };
    let ask = step.ask(now);
    match verdict(view, truth, &ask) {
        Verdict::Refuse(why) => {
            return Ok(Err(Refusal::new(
                crate::reference::sod::rule_of(&why),
                RefusalReason::GuardFailed,
            )));
        }
        Verdict::Accept => {}
        Verdict::Unjudged => {
            if let Command::ReinstateBinding { binding, reason } = &step.cmd {
                // As production does: only an open suspended binding is reinstated.
                let open_suspended = view
                    .bindings
                    .get(binding)
                    .is_some_and(|b| b.open() && b.suspended);
                return Ok(open_suspended
                    .then(|| {
                        vec![Record::BindingReinstated(BindingReinstated {
                            binding: *binding,
                            by: actor,
                            reason: *reason,
                        })]
                    })
                    .ok_or(REFERENCE_REFUSAL));
            }
            return synthesize_unjudged(view, truth, actor, &step.cmd).map(Ok);
        }
    }
    let mut out = Vec::new();
    match &step.cmd {
        Command::EndRole { binding, at } if *at > now => {
            // A later instant schedules the end (Cooling-off NOTE).
            out.push(crate::reference::sod::scheduled_end_record(*binding, *at)?);
        }
        Command::EndRole { binding, at } => {
            let (bar, p12) = crate::reference::sod::expected_end(view, *binding)
                .ok_or("reference mode: unknown binding")?;
            out.push(Record::BindingEnded(BindingEnded {
                binding: *binding,
                at: *at,
                barred_through: bar,
                p12: CoolingOff(p12),
            }));
        }
        Command::CreateDraft {
            proposal,
            call,
            minor,
            ..
        } => {
            out.push(Record::ProposalCreated {
                proposal: *proposal,
                call: *call,
                lead: actor,
                minor: *minor,
            });
        }
        _ => {}
    }
    if let Some(e) = expected_binding(view, &ask) {
        out.push(Record::BindingGranted(granted_record(&e, &step.cmd, view)));
        if let Some(end) = crate::reference::sod::grant_end(&step.cmd) {
            out.push(crate::reference::sod::scheduled_end_record(e.binding, end)?);
        }
    }
    Ok(Ok(out))
}

/// The `BindingGranted` record of an expected binding.
fn granted_record(e: &ExpectedBinding, cmd: &Command, view: &View) -> BindingGranted {
    let (second_admin, confidentiality, organisation) = match cmd {
        Command::GrantRole {
            second_admin,
            confidentiality,
            organisation,
            ..
        } => (*second_admin, *confidentiality, *organisation),
        _ => (None, None, None),
    };
    BindingGranted {
        binding: e.binding,
        account: e.account,
        programme: e.programme,
        role: e.role,
        scope: e.scope,
        start: e.start,
        granted_by: e.granted_by,
        second_admin,
        confidentiality,
        organisation,
        verified_epoch: spec_group(e.role)
            .needs_verification()
            .then_some(view.epoch),
    }
}

/// The records of a setup or staff command, in reference mode.
fn synthesize_unjudged(
    view: &View,
    truth: &GroundTruth,
    actor: AccountId,
    cmd: &Command,
) -> Result<Vec<Record>, String> {
    Ok(match cmd {
        Command::CreateProgramme { policy } => vec![
            Record::ProgrammeCreated {
                programme: policy.programme,
                currency: Currency::Eur,
                by: actor,
            },
            Record::PolicyVersionRecorded {
                version: policy.clone(),
                author: actor,
            },
        ],
        Command::EditPolicy { version, .. } => {
            let recorded = Record::PolicyVersionRecorded {
                version: version.clone(),
                author: actor,
            };
            let mut after = view.clone();
            after.fold(&recorded)?;
            let mut out = vec![recorded];
            out.extend(voids(&after, truth, view.epoch));
            out
        }
        Command::DraftCall {
            call,
            programme,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
        } => vec![Record::CallDrafted {
            call: *call,
            programme: *programme,
            opens: *opens,
            deadline: *deadline,
            deadline_zone: deadline_zone.clone(),
            budget: *budget,
            text: *text,
            author: actor,
        }],
        Command::EditCall {
            call,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
        } => vec![Record::CallEdited {
            call: *call,
            opens: *opens,
            deadline: *deadline,
            deadline_zone: deadline_zone.clone(),
            budget: *budget,
            text: *text,
            author: actor,
        }],
        // As production does, and as `reference::policy` expects: the
        // approval is recorded, so the lifecycle reference folds its decision.
        Command::ApproveCallPublication { call, decision } => vec![Record::CallApproved {
            call: *call,
            decision: *decision,
            approver: actor,
        }],
        Command::PublishCall { call, config, .. } => {
            let c = view.calls.get(call).ok_or("reference mode: unknown call")?;
            if c.seq.is_some() {
                return Err("reference mode: call published twice".to_owned());
            }
            let policy = *view
                .heads
                .get(&c.programme)
                .ok_or("reference mode: no head")?;
            let n = view.latest(c.programme).saturating_add(1);
            let seq = core::num::NonZeroU32::new(n)
                .map(CallSeq::new)
                .ok_or("seq")?;
            vec![Record::CallPublished {
                call: *call,
                policy,
                seq,
                config: *config,
                by: actor,
            }]
        }
        other => return Err(format!("reference mode cannot run {:?}", other.kind())),
    })
}

// ---------------------------------------------------------------------------
// The fstp-prop machine
// ---------------------------------------------------------------------------

/// What a machine draws most, and how big its cases are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SodFocus {
    /// Draw weights in the order grant, end, publish, P-12 edit, P-13 edit,
    /// draft, team member, guardian, verification, new affiliation,
    /// identity merge, reinstatement.
    pub weights: [u32; 12],
    /// The roles grants draw from.
    pub roles: &'static [Role],
    /// Commands per case.
    pub max_commands: usize,
    /// Cases per run.
    pub cases: u32,
}

/// Every role, for grants that try Receiving and Operations roles too.
pub const EVERY_ROLE: [Role; 14] = Role::ALL;

/// The Judging roles.
pub const JUDGING_ROLES: [Role; 4] = [
    Role::FstpCoordinator,
    Role::CommitteeMember,
    Role::CommitteeChair,
    Role::IrcMember,
];

impl SodFocus {
    /// I-01, SoD-01 and SoD-05: grants of every role, ends, publications,
    /// P-12 edits and drafts.
    pub const I01: SodFocus = SodFocus {
        weights: [6, 4, 4, 2, 0, 4, 2, 1, 1, 0, 0, 0],
        roles: &EVERY_ROLE,
        max_commands: 40,
        cases: 128,
    };
    /// I-02 and SoD-02: grants and ends of Judging roles.
    pub const I02: SodFocus = SodFocus {
        weights: [8, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        roles: &JUDGING_ROLES,
        max_commands: 32,
        cases: 128,
    };
    /// I-04 and SoD-06: Receiving bindings, verifications, new affiliations and P-13 edits.
    pub const I04: SodFocus = SodFocus {
        weights: [1, 1, 1, 0, 3, 5, 4, 2, 3, 3, 0, 0],
        roles: &EVERY_ROLE,
        max_commands: 32,
        cases: 128,
    };
    /// I-06 and SoD-09: Sybil grants, drafts, verifications, identity
    /// merges of Drafting and Judging holders, and reinstatements of
    /// conflict-of-interest suspensions.
    pub const I06: SodFocus = SodFocus {
        weights: [6, 3, 3, 1, 0, 5, 2, 1, 4, 0, 4, 2],
        roles: &[
            Role::ProgrammeManager,
            Role::CommitteeMember,
            Role::IrcMember,
            Role::Auditor,
        ],
        max_commands: 40,
        cases: 128,
    };
}

/// A vault change of the machine, processed in the same step (design 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VaultOp {
    /// The vault verifies the account, revealing its pending facts.
    Verify(AccountId),
    /// The vault learns that the identity is in the class: a new affiliation.
    Exclude(IdentityTag, ClassId),
    /// The vault merges the account into the identity: a re-tag that lists
    /// only the account as changed. Accounts holding Drafting and Judging
    /// bindings can then share one verified identity, which SoD-09 refuses
    /// at binding time (Identity discovery, last paragraph).
    Merge(AccountId, IdentityTag),
}

impl VaultOp {
    /// Applies the change to `truth`.
    pub fn apply(self, truth: &mut GroundTruth) {
        match self {
            VaultOp::Verify(a) => truth.verify(a),
            VaultOp::Exclude(t, k) => truth.exclude(t, k),
            VaultOp::Merge(a, t) => truth.set_identity(a, t),
        }
    }
}

/// One machine command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineCmd {
    /// Builds the start state from genesis over these vault facts.
    Setup {
        /// The vault facts, with the corpus fixtures.
        truth: Box<GroundTruth>,
        /// The accounts commands bind.
        subjects: Vec<AccountId>,
    },
    /// A core command at `now`.
    Core {
        /// The instant, in microseconds.
        now: i64,
        /// The command.
        step: Box<Step>,
    },
    /// A vault change at `now`, with its reaction.
    Vault {
        /// The instant, in microseconds.
        now: i64,
        /// The change.
        op: VaultOp,
    },
    /// The System commands `due` lists at `now`, as the M6 timeline runs
    /// them: the scheduled ends due then (Cooling-off NOTE, decided
    /// 2026-10-25).
    Due {
        /// The instant, in microseconds.
        now: i64,
    },
}

/// The reference side of the machine, used to draw commands.
#[derive(Clone, Debug)]
pub struct MachineModel {
    /// Whether the setup ran.
    pub ready: bool,
    /// The view of the records production appended.
    pub view: View,
    /// The head policy version of each programme.
    pub heads: BTreeMap<ProgrammeId, PolicyVersion>,
    /// The vault facts.
    pub truth: GroundTruth,
    /// The accounts commands bind.
    pub subjects: Vec<AccountId>,
    /// The calls in publication order.
    pub calls: Vec<CallId>,
    /// The latest instant, in microseconds.
    pub now: i64,
    /// The next fresh id for bindings, proposals and versions.
    pub next_id: u128,
}

/// What the machine drives.
#[derive(Debug)]
pub enum Driver {
    /// The production engine through the reference driver over a store.
    Engine(Box<Scenario>),
    /// The reference alone, with the records it accepted, for the
    /// machine's self-check before production lands.
    Reference(Box<SodWorld>, Vec<Record>),
}

impl Driver {
    /// The vault facts.
    pub fn truth(&self) -> &GroundTruth {
        match self {
            Driver::Engine(s) => s.truth(),
            Driver::Reference(w, _) => &w.truth,
        }
    }

    /// Runs `step` at `now`.
    fn execute(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
        match self {
            Driver::Engine(s) => {
                let mut ctx = s.ctx(now, step.actor);
                ctx.tenant_admin = step.flags.tenant_admin;
                ctx.second_tenant_admin = step.flags.second_admin;
                ctx.binds_tenant_admin = step.flags.binds_tenant_admin;
                s.execute(fstp_engine::Command::Core(step.cmd.clone()), ctx)
            }
            Driver::Reference(w, records) => {
                w.now = now;
                match w.exec(step, Facts::Effective) {
                    Ok(Ok(batch)) => Ok(reference_append(records, batch)),
                    Ok(Err(r)) => Err(ExecError::Refused(r)),
                    Err(_) => Err(ExecError::Contended),
                }
            }
        }
    }

    /// Changes the vault with `op` at `now` and processes the change.
    fn change_vault(&mut self, op: VaultOp, now: Timestamp) -> Result<Seq, ExecError> {
        let processed = match self {
            Driver::Engine(s) => {
                let ctx = s.ctx(now, Actor::System(SystemCause::Vault));
                s.change_vault(|t| op.apply(t), ctx)?
            }
            Driver::Reference(w, records) => {
                w.now = now;
                op.apply(&mut w.truth);
                match w.sync(Facts::Effective) {
                    Ok(Ok(batch)) if batch.is_empty() => None,
                    Ok(Ok(batch)) => Some(reference_append(records, batch)),
                    Ok(Err(r)) => return Err(ExecError::Refused(r)),
                    Err(_) => return Err(ExecError::Contended),
                }
            }
        };
        processed.ok_or(ExecError::Refused(Refusal::new(
            RuleRef::StaleFacts,
            RefusalReason::AnswerStale,
        )))
    }

    /// Runs every System command that `due` lists at `now`, with the actor
    /// `System(Timeline)`. In reference mode the reference records the
    /// scheduled ends due then. Returns the head after the last command.
    fn run_due(&mut self, now: Timestamp) -> Result<Seq, ExecError> {
        match self {
            Driver::Engine(s) => {
                let mut head = Seq::from_raw(0);
                for cmd in fstp_domain::due(&s.state().core, now) {
                    let ctx = s.ctx(now, Actor::System(SystemCause::Timeline));
                    head = s.execute(fstp_engine::Command::Core(cmd), ctx)?;
                }
                Ok(head)
            }
            Driver::Reference(w, records) => match w.arrive(now) {
                Ok(Ok(batch)) => Ok(reference_append(records, batch)),
                Ok(Err(r)) => Err(ExecError::Refused(r)),
                Err(_) => Err(ExecError::Contended),
            },
        }
    }
}

/// Appends `batch` to the reference ledger and returns its new length as a head.
fn reference_append(records: &mut Vec<Record>, batch: Vec<Record>) -> Seq {
    records.extend(batch);
    Seq::from_raw(u64::try_from(records.len()).unwrap_or(u64::MAX))
}

/// The production side of the machine.
#[derive(Debug)]
pub struct MachineSut {
    /// The driver, once the setup ran.
    pub driver: Option<Driver>,
    /// The ledger before the latest step, under the engine driver.
    pub previous: Vec<Entry<EngineRecord>>,
    /// The ledger after the latest step, under the engine driver.
    pub current: Vec<Entry<EngineRecord>>,
    /// The core records after the latest step.
    pub records: Vec<Record>,
}

impl MachineSut {
    /// Reads the ledger after a step and returns the core records it appended.
    fn advance(&mut self) -> Vec<Record> {
        let before = self.records.len();
        match &self.driver {
            Some(Driver::Engine(s)) => {
                self.previous = core::mem::take(&mut self.current);
                self.current = s.entries().unwrap_or_default();
                self.records = core_records(&self.current);
            }
            Some(Driver::Reference(_, records)) => self.records.clone_from(records),
            None => self.records.clear(),
        }
        self.records.get(before..).unwrap_or_default().to_vec()
    }
}

/// What one machine step returned, with the reference's expectations taken
/// before the step.
#[derive(Debug)]
pub struct MachineOutput {
    /// What the step is.
    pub context: String,
    /// The reference verdict.
    pub verdict: Verdict,
    /// The driver result.
    pub result: Result<Seq, ExecError>,
    /// The core records the step appended.
    pub appended: Vec<Record>,
    /// The view before the step.
    pub before: View,
    /// The binding an accepted step must record.
    pub expected: Option<ExpectedBinding>,
    /// The voids an accepted step must record, with their allowed rules.
    pub voids: BTreeMap<BindingId, BTreeSet<RuleRef>>,
    /// The conflict-of-interest suspensions an accepted step must record.
    pub suspensions: BTreeSet<BindingId>,
}

/// The fstp-prop machine over the role, draft and vault commands (I-01,
/// I-02, I-04, I-06). Its postconditions compare accept and refuse with
/// [`verdict`] in both directions and check the records of every accepted
/// step, voids and conflict-of-interest suspensions included. Its
/// invariant checks I-01, the pinned bars, I-02, I-04, I-06 and
/// I-23 after every step, over the reference view of the ledger.
#[derive(Debug)]
pub struct SodMachine {
    /// What the machine draws most.
    pub focus: SodFocus,
    /// What decides: production, or the reference alone for the self-check.
    pub backend: Backend,
    /// The records of the latest step, for `next_state`.
    last: RefCell<Vec<Record>>,
}

/// The calls of the machine's programme, drafted and approved by the setup.
pub const MACHINE_CALLS: [u128; 5] = [1, 2, 3, 4, 5];

/// The plain subjects of the machine: two verified and two unverified accounts.
pub const MACHINE_SUBJECTS: [(u128, u64, bool); 4] = [
    (11, 2011, true),
    (12, 2012, true),
    (13, 2013, false),
    (14, 2014, false),
];

impl SodMachine {
    /// A machine with `focus` over production.
    pub fn new(focus: SodFocus) -> SodMachine {
        SodMachine::with_backend(focus, Backend::Production)
    }

    /// A machine with `focus` over `backend`. [`Backend::Reference`] checks
    /// the machine itself: generators, expectations and invariants agree
    /// with the reference's own verdicts.
    pub fn with_backend(focus: SodFocus, backend: Backend) -> SodMachine {
        SodMachine {
            focus,
            backend,
            last: RefCell::new(Vec::new()),
        }
    }

    /// The setup of every machine: one programme with P-12 = 1, P-13 {K1}
    /// and five calls drafted and approved, the first one published.
    pub fn setup() -> SodSetup {
        let mut s = SodSetup::one(1, &MACHINE_CALLS);
        s.published = vec![call(1)];
        s
    }

    /// Draws the vault facts: staff, the plain subjects, a Sybil pair, a
    /// third unverified account of the Sybil's identity, and an excluded
    /// applicant.
    fn gen_setup(&self, g: &mut Gen) -> MachineCmd {
        let mut truth = GroundTruth::new();
        add_staff(&mut truth);
        let mut subjects = Vec::new();
        for (a, t, verified) in MACHINE_SUBJECTS {
            let account = AccountId::from_raw(a);
            truth.set_identity(account, IdentityTag::new(t));
            if verified {
                truth.verify(account);
            }
            subjects.push(account);
        }
        let sybil = sybil_pair(g, &mut truth);
        subjects.push(sybil.applicant);
        subjects.push(sybil.reviewer);
        let late = AccountId::from_raw(sybil.applicant.raw().saturating_add(500_000_000));
        truth.set_identity(late, sybil.identity);
        subjects.push(late);
        let excluded = excluded_applicant(g, &mut truth);
        subjects.push(excluded.account);
        if g.weighted(&[3, 1]) == 1 {
            // Another account that the vault reveals as excluded on verification.
            let hidden = AccountId::from_raw(excluded.account.raw().saturating_add(500_000_000));
            let tag = IdentityTag::new(excluded.identity.raw().saturating_add(500_000_000));
            truth.set_identity(hidden, tag);
            truth.add_pending(
                hidden,
                PendingFact::Excluded {
                    identity: tag,
                    class: K1,
                },
            );
            subjects.push(hidden);
        }
        MachineCmd::Setup {
            truth: Box::new(truth),
            subjects,
        }
    }

    fn gen_now(&self, g: &mut Gen, model: &MachineModel) -> i64 {
        model
            .now
            .saturating_add(i64::try_from(g.weighted(&[1, 2])).unwrap_or(0))
    }

    fn pick_subject(&self, g: &mut Gen, model: &MachineModel) -> AccountId {
        let switching: Vec<AccountId> = model
            .view
            .bindings
            .values()
            .filter(|b| b.end.is_some() && !is_staff_binding(b.binding))
            .map(|b| b.account)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        match g.weighted(&[1, 8, 4]) {
            0 => *g.pick(&[ADMIN, ADMIN_2, STAFF_PM]),
            2 if !switching.is_empty() => *g.pick(&switching),
            _ if model.subjects.is_empty() => ADMIN,
            _ => *g.pick(&model.subjects),
        }
    }

    fn fresh(&self, g: &mut Gen, model: &MachineModel, existing: u128) -> u128 {
        if existing > 0 && g.weighted(&[19, 1]) == 1 {
            existing
        } else {
            model.next_id
        }
    }

    fn gen_grant(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let account = self.pick_subject(g, model);
        let role = *g.pick(self.focus.roles);
        let at = Timestamp::from_micros(now);
        let start = if g.weighted(&[12, 1]) == 1 {
            Timestamp::from_micros(now.saturating_sub(1))
        } else {
            at
        };
        let binding = BindingId::from_raw(self.fresh(g, model, model.view.max_binding()));
        let mut step = grant(binding, account, P1, role, start);
        if let Command::GrantRole {
            second_admin,
            confidentiality,
            ..
        } = &mut step.cmd
        {
            if g.weighted(&[12, 1]) == 1 {
                *confidentiality = None;
            }
            if account == ADMIN {
                match g.weighted(&[6, 1, 1, 1]) {
                    1 => {
                        *second_admin = None;
                        step.flags.second_admin = None;
                    }
                    2 => step.flags.second_admin = None,
                    3 => {
                        *second_admin = Some(ADMIN);
                        step.flags.second_admin = Some(ADMIN);
                    }
                    _ => {}
                }
            }
        }
        if g.weighted(&[15, 1]) == 1 {
            step.flags.tenant_admin = false;
        }
        MachineCmd::Core {
            now,
            step: Box::new(step),
        }
    }

    fn gen_end(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let candidates: Vec<BindingId> = model
            .view
            .bindings
            .values()
            .filter(|b| !is_staff_binding(b.binding))
            .filter(|b| (b.open() && b.group != RefGroup::Receiving) || g.weighted(&[8, 1]) == 1)
            .map(|b| b.binding)
            .collect();
        if candidates.is_empty() {
            return self.gen_grant(g, model, now);
        }
        let binding = *g.pick(&candidates);
        // Mostly now, sometimes backdated, sometimes scheduled for later.
        let at = match g.weighted(&[24, 2, 1]) {
            1 => Timestamp::from_micros(now.saturating_sub(1)),
            2 => Timestamp::from_micros(now.saturating_add(1)),
            _ => Timestamp::from_micros(now),
        };
        MachineCmd::Core {
            now,
            step: Box::new(end(binding, at)),
        }
    }

    fn gen_publish(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let next = MACHINE_CALLS
            .iter()
            .map(|n| call(*n))
            .find(|c| !model.calls.contains(c));
        match next {
            Some(c) => MachineCmd::Core {
                now,
                step: Box::new(publish(c)),
            },
            None => self.gen_grant(g, model, now),
        }
    }

    fn gen_edit(&self, g: &mut Gen, model: &MachineModel, now: i64, p13: bool) -> MachineCmd {
        let Some(head) = model.heads.get(&P1) else {
            return self.gen_grant(g, model, now);
        };
        let id = PolicyVersionId::from_raw(model.next_id);
        let p12 = g.u8_in(0..=2);
        let class = ClassId::from_raw(u128::from(g.u8_in(1..=4)));
        let step = edit_policy(head, id, |v| {
            if p13 {
                v.live.p13.0.insert(class);
            } else {
                v.live.p12 = CoolingOff(p12);
            }
        });
        MachineCmd::Core {
            now,
            step: Box::new(step),
        }
    }

    fn gen_draft(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let lead = self.pick_subject(g, model);
        let target = if model.calls.is_empty() || g.weighted(&[1, 10]) == 0 {
            call(*g.pick(&MACHINE_CALLS))
        } else {
            *g.pick(&model.calls)
        };
        let proposal = ProposalId::from_raw(self.fresh(g, model, model.view.max_proposal()));
        let binding = BindingId::from_raw(model.next_id);
        MachineCmd::Core {
            now,
            step: Box::new(draft(lead, proposal, target, binding, g.bool())),
        }
    }

    fn gen_member(
        &self,
        g: &mut Gen,
        model: &MachineModel,
        now: i64,
        guardian: bool,
    ) -> MachineCmd {
        let proposals: Vec<(ProposalId, AccountId)> = model
            .view
            .proposals
            .iter()
            .map(|(p, r)| (*p, r.lead))
            .collect();
        if proposals.is_empty() {
            return self.gen_draft(g, model, now);
        }
        let (proposal, lead) = *g.pick(&proposals);
        let actor = if g.weighted(&[10, 1]) == 1 {
            self.pick_subject(g, model)
        } else {
            lead
        };
        let account = self.pick_subject(g, model);
        let binding = BindingId::from_raw(self.fresh(g, model, model.view.max_binding()));
        MachineCmd::Core {
            now,
            step: Box::new(add_member(actor, proposal, account, binding, guardian)),
        }
    }

    fn gen_verify(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let unverified: Vec<AccountId> = model
            .subjects
            .iter()
            .copied()
            .filter(|a| !model.truth.is_verified(*a))
            .collect();
        if unverified.is_empty() {
            return self.gen_grant(g, model, now);
        }
        MachineCmd::Vault {
            now,
            op: VaultOp::Verify(*g.pick(&unverified)),
        }
    }

    fn gen_affiliation(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let account = self.pick_subject(g, model);
        let Some(t) = model.truth.identity_of(account) else {
            return self.gen_grant(g, model, now);
        };
        let class = ClassId::from_raw(u128::from(g.u8_in(1..=4)));
        MachineCmd::Vault {
            now,
            op: VaultOp::Exclude(t, class),
        }
    }

    /// An identity merge: a subject takes the identity of another subject.
    /// Mostly a holder of an open Drafting or Judging binding is merged
    /// into the identity of a holder of the other group, so that the
    /// conflict of interest of Identity discovery arises.
    fn gen_merge(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let holders = |group: RefGroup| -> Vec<AccountId> {
            model
                .view
                .bindings
                .values()
                .filter(|b| b.group == group && b.open() && !is_staff_binding(b.binding))
                .map(|b| b.account)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let drafting = holders(RefGroup::Drafting);
        let judging = holders(RefGroup::Judging);
        let (account, into) =
            if !drafting.is_empty() && !judging.is_empty() && g.weighted(&[1, 3]) == 1 {
                if g.bool() {
                    (*g.pick(&judging), *g.pick(&drafting))
                } else {
                    (*g.pick(&drafting), *g.pick(&judging))
                }
            } else {
                (self.pick_subject(g, model), self.pick_subject(g, model))
            };
        match model.truth.identity_of(into) {
            Some(t) if account != into && model.truth.identity_of(account) != Some(t) => {
                MachineCmd::Vault {
                    now,
                    op: VaultOp::Merge(account, t),
                }
            }
            _ => self.gen_grant(g, model, now),
        }
    }

    /// A `ReinstateBinding`, mostly of a suspended binding.
    fn gen_reinstate(&self, g: &mut Gen, model: &MachineModel, now: i64) -> MachineCmd {
        let suspended: Vec<BindingId> = model
            .view
            .bindings
            .values()
            .filter(|b| b.suspended || g.weighted(&[8, 1]) == 1)
            .map(|b| b.binding)
            .collect();
        if suspended.is_empty() {
            return self.gen_grant(g, model, now);
        }
        MachineCmd::Core {
            now,
            step: Box::new(reinstate(*g.pick(&suspended))),
        }
    }
}

impl StateMachine for SodMachine {
    type Model = MachineModel;
    type Sut = MachineSut;
    type Command = MachineCmd;
    type Output = MachineOutput;

    fn init_model(&self) -> MachineModel {
        MachineModel {
            ready: false,
            view: View::new(),
            heads: BTreeMap::new(),
            truth: GroundTruth::new(),
            subjects: Vec::new(),
            calls: Vec::new(),
            now: T0.micros(),
            next_id: 1_000,
        }
    }

    fn init_sut(&self) -> MachineSut {
        MachineSut {
            driver: None,
            previous: Vec::new(),
            current: Vec::new(),
            records: Vec::new(),
        }
    }

    fn command(&self, g: &mut Gen, model: &MachineModel) -> MachineCmd {
        if !model.ready {
            return self.gen_setup(g);
        }
        let now = self.gen_now(g, model);
        // A scheduled end that is due runs often, so the binding's later
        // steps see it ended (Cooling-off NOTE).
        let due =
            !crate::reference::sod::due_ends(&model.view, Timestamp::from_micros(now)).is_empty();
        if due && g.weighted(&[1, 1]) == 1 {
            return MachineCmd::Due { now };
        }
        match g.weighted(&self.focus.weights) {
            0 => self.gen_grant(g, model, now),
            1 => self.gen_end(g, model, now),
            2 => self.gen_publish(g, model, now),
            3 => self.gen_edit(g, model, now, false),
            4 => self.gen_edit(g, model, now, true),
            5 => self.gen_draft(g, model, now),
            6 => self.gen_member(g, model, now, false),
            7 => self.gen_member(g, model, now, true),
            8 => self.gen_verify(g, model, now),
            9 => self.gen_affiliation(g, model, now),
            10 => self.gen_merge(g, model, now),
            _ => self.gen_reinstate(g, model, now),
        }
    }

    fn precondition(&self, model: &MachineModel, cmd: &MachineCmd) -> bool {
        match cmd {
            MachineCmd::Setup { .. } => !model.ready,
            MachineCmd::Core { now, .. }
            | MachineCmd::Vault { now, .. }
            | MachineCmd::Due { now } => model.ready && *now >= model.now,
        }
    }

    fn run(&self, sut: &mut MachineSut, cmd: &MachineCmd) -> MachineOutput {
        self.last.borrow_mut().clear();
        let mut out = MachineOutput {
            context: String::new(),
            verdict: Verdict::Unjudged,
            result: Err(ExecError::Refused(Refusal::not_implemented())),
            appended: Vec::new(),
            before: View::new(),
            expected: None,
            voids: BTreeMap::new(),
            suspensions: BTreeSet::new(),
        };
        let before = View::of(sut.records.iter()).unwrap_or_default();
        match cmd {
            MachineCmd::Setup { truth, .. } => {
                out.context = "setup".to_owned();
                out.verdict = Verdict::Accept;
                out.result = run_setup(sut, truth, self.backend);
            }
            MachineCmd::Core { now, step } => {
                let Some(driver) = sut.driver.as_mut() else {
                    out.context = "no driver".to_owned();
                    return out;
                };
                let at = Timestamp::from_micros(*now);
                let ask = step.ask(at);
                out.context = format!("{:?} by {:?}", step.cmd, step.actor);
                out.verdict = verdict(&before, driver.truth(), &ask);
                out.expected = expected_binding(&before, &ask);
                if let Command::EditPolicy { version, .. } = &step.cmd {
                    let mut after = before.clone();
                    let recorded = Record::PolicyVersionRecorded {
                        version: version.clone(),
                        author: STAFF_PM,
                    };
                    if after.fold(&recorded).is_ok() {
                        out.voids = expected_voids(&after, driver.truth());
                    }
                }
                out.result = driver.execute(step, at);
            }
            MachineCmd::Vault { now, op } => {
                let Some(driver) = sut.driver.as_mut() else {
                    out.context = "no driver".to_owned();
                    return out;
                };
                out.context = format!("vault change {op:?}");
                out.verdict = Verdict::Accept;
                out.result = driver.change_vault(*op, Timestamp::from_micros(*now));
                out.voids = expected_voids(&before, driver.truth());
                out.suspensions = expected_suspensions(&before, driver.truth());
            }
            MachineCmd::Due { now } => {
                let Some(driver) = sut.driver.as_mut() else {
                    out.context = "no driver".to_owned();
                    return out;
                };
                out.context = format!("System commands due at {now}");
                out.verdict = Verdict::Accept;
                out.result = driver.run_due(Timestamp::from_micros(*now));
            }
        }
        out.before = before;
        out.appended = sut.advance();
        self.last.borrow_mut().clone_from(&out.appended);
        out
    }

    fn postcondition(
        &self,
        _model: &MachineModel,
        cmd: &MachineCmd,
        out: &MachineOutput,
    ) -> Result<(), String> {
        let context = &out.context;
        if let MachineCmd::Setup { .. } = cmd {
            return match &out.result {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("the setup from genesis failed: {e:?}")),
            };
        }
        match &out.verdict {
            Verdict::Accept => two_way_exec(context, true, &out.result)?,
            Verdict::Refuse(why) => {
                two_way_exec(&format!("{context} (reference: {why})"), false, &out.result)?
            }
            Verdict::Unjudged => {}
        }
        if out.result.is_err() {
            return Ok(());
        }
        if let Some(e) = &out.expected
            && out.verdict.accepts()
        {
            check_granted(context, e, &out.appended)?;
        }
        if let MachineCmd::Core { now, step } = cmd
            && let Command::EndRole { binding, at } = &step.cmd
        {
            // A later instant schedules the end (Cooling-off NOTE).
            if at.micros() > *now {
                crate::reference::sod::check_scheduled(context, *binding, *at, &out.appended)?;
            } else {
                check_ended(context, &out.before, *binding, *at, &out.appended)?;
            }
        }
        if let MachineCmd::Due { now } = cmd {
            crate::reference::sod::check_due_ends(
                &out.before,
                Timestamp::from_micros(*now),
                &out.appended,
            )?;
        }
        check_voids(context, &out.voids, &out.appended)?;
        check_suspensions(context, &out.suspensions, &out.appended)
    }

    fn next_state(&self, model: &mut MachineModel, cmd: &MachineCmd) {
        let records = self.last.borrow().clone();
        match cmd {
            MachineCmd::Setup { truth, subjects } => {
                model.ready = true;
                model.truth = (**truth).clone();
                model.subjects.clone_from(subjects);
            }
            MachineCmd::Core { now, .. } | MachineCmd::Due { now } => model.now = *now,
            MachineCmd::Vault { now, op } => {
                model.now = *now;
                op.apply(&mut model.truth);
            }
        }
        for r in &records {
            // A record the reference cannot follow fails the invariant, which
            // re-folds the whole ledger.
            let _ = model.view.fold_with(r, &model.truth);
            match r {
                Record::PolicyVersionRecorded { version, .. } => {
                    model.heads.insert(version.programme, (**version).clone());
                }
                Record::CallPublished { call, .. } => model.calls.push(*call),
                _ => {}
            }
        }
        model.next_id = model.next_id.saturating_add(1);
    }

    fn invariant(&self, _model: &MachineModel, sut: &MachineSut) -> Result<(), String> {
        let Some(driver) = sut.driver.as_ref() else {
            return Ok(());
        };
        if let Driver::Engine(scenario) = driver {
            ledger_step(&sut.previous, &sut.current, scenario.state())?;
        }
        let view = View::of(sut.records.iter())
            .map_err(|e| format!("the reference cannot follow the ledger: {e}"))?;
        check_i01(&view)?;
        check_bars(&view)?;
        check_i02(&view)?;
        check_i04(&view, driver.truth())?;
        check_i06(&view, driver.truth())
    }

    fn max_commands(&self) -> usize {
        self.focus.max_commands
    }
}

/// Builds the driver of the machine from genesis over `truth`.
fn run_setup(
    sut: &mut MachineSut,
    truth: &GroundTruth,
    backend: Backend,
) -> Result<Seq, ExecError> {
    let failed = Err(ExecError::Refused(Refusal::not_implemented()));
    let mut driver = match backend {
        Backend::Production => match Scenario::new(truth.clone()) {
            Ok(s) => Driver::Engine(Box::new(s)),
            Err(_) => return failed,
        },
        Backend::Reference => Driver::Reference(
            Box::new(SodWorld::new(Backend::Reference, truth.clone())),
            Vec::new(),
        ),
    };
    let Ok(steps) = SodMachine::setup().steps() else {
        return failed;
    };
    let mut last = failed;
    for step in steps {
        last = driver.execute(&step, T0);
        if last.is_err() {
            break;
        }
    }
    sut.driver = Some(driver);
    last
}
