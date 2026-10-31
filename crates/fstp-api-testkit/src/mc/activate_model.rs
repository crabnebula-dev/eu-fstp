//! M-ACTIVATE, the I-66 and I-67 predicates, the activation machine and
//! the production adapter (M4 design sections 8.4 and 8.5). Lane W2a owns
//! this file.
//!
//! - [`production`] is the one place where the I-66 and I-67 suites call
//!   production code. Each function names the designed call it makes. The
//!   implementer wires it, and the test author reviews each call, as the
//!   M2 read adapters were handled. The creator has landed (lane W2a).
//!   A production draft still needs parallel lanes, so the first call of
//!   a production run reaches a W0 stub that refuses, and the run is red
//!   for that reason.
//! - [`System`] runs one draft on the reference or on production, behind
//!   the same reference vocabulary.
//! - [`check_i66`] and [`check_i67`] are the invariant predicates over the
//!   records on the draft. They recompute everything from raw records and
//!   never call [`RefSystem::decide`], so they check the reference too.
//! - [`ActivateModel`] is M-ACTIVATE for `fstp-mc`. [`ActivationMachine`]
//!   is the stateful property for `fstp-prop`.
//!
//! The universe of M-ACTIVATE follows design 8.5. It has tenant admins A1
//! and A2, programme managers M1 and M2, and one draft. The draft has one
//! failure an edit can fix (`FieldUnset`), one warning (`RosterShort`) and
//! one probe flip (channels). The budget allows two edits, one
//! acknowledgement, one request and two approval attempts. The model runs
//! with and without a Sybil pair. In the Sybil configuration A2 shares a
//! verified identity with M1 (T-SOD-SYBIL).
//!
//! Design 8.5 names no request budget, so the model allows one request. A
//! refusal that both sides agree on and that adds no witness is a
//! disabled step. Both choices keep the exhaustive run near 30,000
//! states.

use std::collections::BTreeSet;

use fstp_domain::id::AccountId;
use fstp_mc::{Model, Property};
use fstp_prop::{Gen, StateMachine};

use crate::reference::creator::{
    Attempt, AttemptOutcome, Base, CheckFeed, DraftPlan, EditKind, M1, M2, RefCheck, RefCommand,
    RefDraft, RefEdit, RefEvent, RefInputs, RefProbe, RefProbeOutcome, RefRefusal, RefReport,
    RefSeverity, RefStatic, RefSystem, RefVault, StepVerdict, TA, TB, adr006_eur, cast_vault,
    clean_plan,
};

// ---------------------------------------------------------------------------
// The production adapter
// ---------------------------------------------------------------------------

/// The one place where the I-66 and I-67 suites call production code.
///
/// Wiring status (lane m4wire): every function runs the production
/// engine, `fstp_engine::Engine` with `CreatorDecider` over the cell's
/// creator environment (`fake/shell.rs`), on a draft cell rebuilt from
/// the draft's ledger (`fake/draft_cell.rs`).
///
/// - [`ProductionSystem`] opens the plan's draft with
///   `CreatorCommand::OpenDraft` through the engine, grants its managers
///   with core `GrantRole` and sets the plan's environment. It refuses
///   with [`GAP_OPEN`] while `fstp_creator::decide_creator` refuses the
///   opening at its compile seam (lane m4creator). Seeding a content check
///   and every content edit refuse with [`GAP_SEEDS`] and [`GAP_EDITS`]:
///   which field edit seeds or fixes each check is the creator lane's
///   (lanes m4creator and m4guide).
/// - [`execute_core_activate`], [`fold_unpaired_activation`] and
///   [`preview_vault_trace`] check a guard, the fold or the recording of
///   vault answers after the opening. They open the draft with the entry
///   a correct `OpenDraft` appends (`draft_cell::forged_open`), as the
///   engine's own M4 envelope tests do, so they run before the creator
///   lane merges.
pub mod production {
    use std::collections::{BTreeMap, BTreeSet};

    use fstp_api_core::port::{ProbeKind as PortProbe, ProbeOutcome as PortOutcome};
    use fstp_creator::{
        CheckDetail, CreatorCommand, CreatorRecord, MandatoryElement, ProbeKind, ProbeOutcome,
        TextRole, Theme, ThemeMode,
    };
    use fstp_domain::command::{Actor, Ctx};
    use fstp_domain::id::{
        AccountId, BindingId, ContentDigest, DecisionId, PolicyVersionId, ProgrammeId, TextId,
        TextRef,
    };
    use fstp_domain::oracle::{Answer, Answers, Query};
    use fstp_domain::refusal::{RefusalReason, RuleRef};
    use fstp_domain::roles::{BindingStatus, Role};
    use fstp_domain::time::Timestamp;
    use fstp_domain_testkit::vault::GroundTruth;
    use fstp_engine::{Command, EngineState, Record};
    use fstp_json::{FromJson, ToJson, Value};
    use fstp_ledger::{Entry, MemStore, RecordStore};

    use crate::NotImplemented;
    use crate::fake::draft_cell::{self, DraftCell, VaultAccount};
    use crate::reference::creator::{
        Base, DraftPlan, EditKind, M1, M2, RefCheck, RefCommand, RefDetail, RefEdit, RefEvent,
        RefInputs, RefProbe, RefProbeOutcome, RefRefusal, RefReport, RefSeverity, SYBIL,
        StepVerdict, TA, TB,
    };

    /// The opening refused: `fstp_creator::decide_creator` refuses
    /// `OpenDraft` at its compile seam until lane m4creator merges.
    pub const GAP_OPEN: NotImplemented = NotImplemented::new(
        "CreatorCommand::OpenDraft through Engine::execute: fstp_creator::decide_creator refuses at its compile seam (lane m4creator)",
    );

    /// Seeding a content check of the plan needs the field edit that
    /// seeds it, which the creator lane fixes.
    pub const GAP_SEEDS: NotImplemented = NotImplemented::new(
        "seeding a content check of the plan: the field edit that seeds each check through SaveFields, ApplyStart or AcceptNarrative (lanes m4creator and m4guide)",
    );

    /// A content edit in the reference vocabulary needs the field edit that
    /// has the edit's effect on the checks.
    pub const GAP_EDITS: NotImplemented = NotImplemented::new(
        "a content edit of the reference vocabulary: the SaveFields, ApplyStart or AcceptNarrative with its effect on each check (lanes m4creator and m4guide)",
    );

    /// Retired: no step returns it. A theme fault is seeded through the
    /// cell's environment, which supplies the theme as it supplies the
    /// probes (design 3.2 `CreatorInputs::theme`, see [`theme_of`]). The
    /// constant stays so a test can check that no theme seed is refused.
    pub const GAP_THEME: NotImplemented = NotImplemented::new(
        "a theme fault: retired, theme faults are seeded through the cell environment (design 3.2 and 8.4)",
    );

    /// The theme of `plan` (design 3.2 `CreatorInputs::theme`, 8.4): the
    /// M4 default with each seeded theme fault. `ContrastFailure` gives
    /// the light body text its background's colour, which fails AA, and
    /// `MandatoryElementMissing` drops the AI disclosure.
    pub fn theme_of(plan: &DraftPlan) -> Theme {
        let mut theme = Theme::m4_default();
        for c in &plan.stat.theme_faults {
            match c {
                RefCheck::ContrastFailure => {
                    if let Some(p) = theme
                        .pairs
                        .iter_mut()
                        .find(|p| p.mode == ThemeMode::Light && p.role == TextRole::Body)
                    {
                        p.text = p.background;
                    }
                }
                RefCheck::MandatoryElementMissing => {
                    let _ = theme.elements.remove(&MandatoryElement::AiDisclosure);
                }
                _ => {}
            }
        }
        theme
    }

    /// Fewer unresolved imports needs a dismissal, which is a record on the
    /// draft. The reference changes the count as the environment only.
    pub const GAP_FEWER_IMPORTS: NotImplemented = NotImplemented::new(
        "fewer unresolved imports than recorded: a dismissal is a record on the draft, not an environment change (design 3.3)",
    );

    /// A production step that failed for a reason outside the model.
    pub const GAP_STEP: NotImplemented = NotImplemented::new(
        "a production step failed outside the model's refusals (see the adapter's mapping)",
    );

    /// The draft programme of every production run.
    pub const PLAN_P: ProgrammeId = ProgrammeId::from_raw(0x4d41_0001);

    /// The instant of the first entry of a run. Each step is one second
    /// later than the one before.
    const T0: i64 = 1_000_000;

    /// The accounts of the cast, each with its person and verification.
    fn vault_accounts(plan: &DraftPlan) -> Vec<VaultAccount> {
        [TA, TB, M1, M2, SYBIL]
            .into_iter()
            .map(|a| VaultAccount {
                account: a,
                person: plan.stat.vault.person(a).map(u64::from),
                verified: plan.stat.vault.is_verified(a),
            })
            .collect()
    }

    /// The port probe of a reference probe.
    fn port_probe(p: RefProbe) -> PortProbe {
        match p {
            RefProbe::Channel => PortProbe::Channel,
            RefProbe::SendingDomain => PortProbe::SendingDomain,
            RefProbe::Inference => PortProbe::Inference,
        }
    }

    /// The prober setting of a reference outcome: `None` for no prober.
    fn port_outcome(o: RefProbeOutcome) -> Option<PortOutcome> {
        match o {
            RefProbeOutcome::Pass => Some(PortOutcome::Pass),
            RefProbeOutcome::Fail => Some(PortOutcome::Fail),
            RefProbeOutcome::Absent => None,
        }
    }

    /// The reference probe of a creator probe.
    fn ref_probe(p: ProbeKind) -> RefProbe {
        match p {
            ProbeKind::Channel => RefProbe::Channel,
            ProbeKind::SendingDomain => RefProbe::SendingDomain,
            ProbeKind::Inference => RefProbe::Inference,
        }
    }

    /// The reference outcome of a creator outcome.
    fn ref_outcome(o: ProbeOutcome) -> RefProbeOutcome {
        match o {
            ProbeOutcome::Pass => RefProbeOutcome::Pass,
            ProbeOutcome::Fail => RefProbeOutcome::Fail,
            ProbeOutcome::Absent => RefProbeOutcome::Absent,
        }
    }

    /// The reference check of a creator check, by its catalogue name.
    fn ref_check(c: fstp_creator::CheckId) -> Option<RefCheck> {
        RefCheck::ALL.into_iter().find(|r| r.name() == c.name())
    }

    /// The default funder profile reference of a new draft (P-53).
    fn default_profile() -> Result<fstp_domain::policy::FunderProfileRef, NotImplemented> {
        let v = fstp_json::parse(br#"{"profile":"horizon-europe","version":1}"#)
            .map_err(|_| GAP_STEP)?;
        fstp_domain::policy::OpaqueValue::from_value(&v)
            .map(fstp_domain::policy::FunderProfileRef)
            .map_err(|_| GAP_STEP)
    }

    /// One draft on production: its ledger, its vault facts and its
    /// environment. Each step rebuilds the engine from the ledger, so the
    /// state compares and hashes.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct ProductionSystem {
        plan: DraftPlan,
        truth: GroundTruth,
        store: MemStore<Record>,
        state: EngineState,
        ledger: Vec<Entry<Record>>,
        probes: BTreeMap<RefProbe, RefProbeOutcome>,
        /// The number of the next command, which also sets its instant.
        n: u32,
    }

    /// What one engine run gave, in the reference vocabulary's terms.
    enum Run {
        /// The command appended.
        Appended,
        /// The engine refused it with this rule and reason.
        Refused(RuleRef, RefusalReason),
    }

    impl ProductionSystem {
        /// Opens the draft of `plan` on production (module documentation):
        /// `OpenDraft` by the opener, `GrantRole` of each manager by the
        /// opener, then the plan's environment.
        pub fn open(plan: &DraftPlan) -> Result<ProductionSystem, NotImplemented> {
            let truth = draft_cell::truth_of(&vault_accounts(plan));
            let store = MemStore::new();
            let state = EngineState::genesis();
            let mut s = ProductionSystem {
                plan: plan.clone(),
                truth,
                store,
                state,
                ledger: Vec::new(),
                probes: plan.env.probes.clone(),
                n: 1,
            };
            let open = CreatorCommand::OpenDraft {
                programme: PLAN_P,
                version: PolicyVersionId::from_raw(PLAN_P.raw()),
                profile: default_profile()?,
            };
            match s.run(Command::Creator(open), plan.opener)? {
                Run::Appended => {}
                Run::Refused(RuleRef::NotImplemented, _) => return Err(GAP_OPEN),
                Run::Refused(..) => return Err(GAP_STEP),
            }
            for m in &plan.managers {
                if !matches!(s.grant(plan.opener, *m)?, StepVerdict::Accepted) {
                    return Err(GAP_STEP);
                }
            }
            if !plan.seeds.is_empty() {
                return Err(GAP_SEEDS);
            }
            s.set_unresolved(plan.env.unresolved_imports)?;
            Ok(s)
        }

        /// The engine state.
        pub fn state(&self) -> &EngineState {
            &self.state
        }

        /// The ledger.
        pub fn ledger(&self) -> &[Entry<fstp_engine::Record>] {
            &self.ledger
        }

        /// The draft cell over the ledger now.
        fn cell(&self) -> Result<DraftCell, NotImplemented> {
            let probes = RefProbe::ALL
                .into_iter()
                .map(|p| {
                    let o = self
                        .probes
                        .get(&p)
                        .copied()
                        .unwrap_or(RefProbeOutcome::Absent);
                    (port_probe(p), port_outcome(o))
                })
                .collect();
            DraftCell::open_with_theme(
                self.store.clone(),
                self.truth.clone(),
                self.plan.stat.admins.clone(),
                &probes,
                self.plan.stat.wording_pending,
                theme_of(&self.plan),
            )
            .map_err(|_| GAP_STEP)
        }

        /// The context of the next command by `actor`.
        fn ctx(&mut self, actor: AccountId) -> Ctx {
            let n = self.n;
            self.n = n.saturating_add(1);
            let at = T0.saturating_add(i64::from(n).saturating_mul(1_000_000));
            draft_cell::ctx(actor, Timestamp::from_micros(at), n, &self.plan.stat.admins)
        }

        /// Runs `cmd` by `actor` through the engine, and keeps the ledger.
        fn run(&mut self, cmd: Command, actor: AccountId) -> Result<Run, NotImplemented> {
            let ctx = self.ctx(actor);
            self.run_ctx(cmd, ctx)
        }

        /// Runs `cmd` with `ctx` through the engine, and keeps the ledger.
        fn run_ctx(&mut self, cmd: Command, ctx: Ctx) -> Result<Run, NotImplemented> {
            let mut cell = self.cell()?;
            let out = match cell.execute(cmd, ctx) {
                Ok(_) => Run::Appended,
                Err(fstp_engine::ExecError::Refused(r)) => Run::Refused(r.rule, r.reason),
                Err(_) => return Err(GAP_STEP),
            };
            self.keep(cell)?;
            Ok(out)
        }

        /// Keeps the ledger and state of `cell`.
        fn keep(&mut self, cell: DraftCell) -> Result<(), NotImplemented> {
            self.state = cell.state().clone();
            self.store = cell.into_store();
            self.ledger = draft_cell::entries(&self.store).map_err(|_| GAP_STEP)?;
            Ok(())
        }

        /// The draft's head revision now.
        fn head(&self) -> Option<fstp_creator::DraftRevision> {
            self.state.creator.head(PLAN_P)
        }

        /// The revision a command names under `base`.
        fn named(&self, base: Base) -> Option<fstp_creator::DraftRevision> {
            let h = self.head()?;
            Some(match base {
                Base::Head => h,
                Base::Previous => {
                    fstp_creator::DraftRevision::new(h.seq().saturating_sub(1), h.entry())
                }
            })
        }

        /// `GrantRole` of programme manager on the draft to `to` by `by`.
        fn grant(&mut self, by: AccountId, to: AccountId) -> Result<StepVerdict, NotImplemented> {
            let mut ctx = self.ctx(by);
            ctx.binds_tenant_admin = self.plan.stat.admins.contains(&to);
            let binding =
                BindingId::from_raw(0x4d41_0000_0000u128.saturating_add(u128::from(self.n)));
            let cmd = fstp_domain::Command::GrantRole {
                binding,
                account: to,
                programme: PLAN_P,
                role: Role::ProgrammeManager,
                start: ctx.now,
                second_admin: None,
                confidentiality: Some(TextRef::new(
                    TextId::from_raw(binding.raw()),
                    ContentDigest::from_bytes([0x4d; 32]),
                )),
                organisation: None,
                end: None,
            };
            Ok(match self.run_ctx(Command::Core(cmd), ctx)? {
                Run::Appended => StepVerdict::Accepted,
                Run::Refused(rule, reason) => {
                    StepVerdict::Refused(self.grant_refusal(rule, reason))
                }
            })
        }

        /// The reference refusal of a refused grant.
        fn grant_refusal(&self, rule: RuleRef, reason: RefusalReason) -> RefRefusal {
            match (rule, reason) {
                (RuleRef::Actor, _) => RefRefusal::NotTenantAdmin,
                (RuleRef::Sod09, _) => RefRefusal::GranteeUnverified,
                _ if self.active() => RefRefusal::AlreadyActive,
                _ => RefRefusal::GrantNotAdmitted,
            }
        }

        /// Whether the draft is active.
        fn active(&self) -> bool {
            self.state
                .creator
                .draft(PLAN_P)
                .is_some_and(|d| d.active().is_some())
        }

        /// The reference refusal of a refused creator command (the inverse
        /// of `fstp_engine::compose::creator_refusal`).
        fn creator_refusal(
            &self,
            rule: RuleRef,
            reason: RefusalReason,
            approver: Option<AccountId>,
        ) -> Result<RefRefusal, NotImplemented> {
            use RefusalReason as Why;
            Ok(match (rule, reason) {
                (RuleRef::Input, Why::UnknownEntity) => RefRefusal::Opening,
                (RuleRef::Ledger, Why::IdReused) => RefRefusal::Opening,
                (RuleRef::Input, Why::WrongState) => RefRefusal::StaleRevision,
                (RuleRef::Actor, Why::BindingInactive) => RefRefusal::NotProgrammeManager,
                (RuleRef::Actor, _) => RefRefusal::NotTenantAdmin,
                (RuleRef::I66, Why::WrongState) if self.active() => RefRefusal::AlreadyActive,
                (RuleRef::I66, Why::WrongState) => RefRefusal::NoLiveRequest,
                (RuleRef::I66, Why::InvalidValue) => RefRefusal::NotAWarning,
                (RuleRef::I66, _) => self.uncleared()?,
                (RuleRef::I67, Why::GuardFailed) => RefRefusal::ApproverIsBuilder,
                (RuleRef::I67, _) => {
                    let unverified = approver.is_some_and(|a| !self.plan.stat.vault.is_verified(a));
                    if unverified {
                        RefRefusal::ApproverUnverified
                    } else if approver.is_some_and(|a| self.same_identity(a)) {
                        RefRefusal::SameIdentity
                    } else {
                        RefRefusal::Failed(RefCheck::BuilderUnverified)
                    }
                }
                _ => return Err(GAP_STEP),
            })
        }

        /// Whether `a` shares a verified identity with a builder.
        fn same_identity(&self, a: AccountId) -> bool {
            let builders = self
                .state
                .creator
                .draft(PLAN_P)
                .map(|d| d.builders().clone())
                .unwrap_or_default();
            self.plan.stat.vault.same_identity_as_any(a, &builders)
        }

        /// Why the report now does not clear, in the reference's order: the
        /// first failure in catalogue order, then the first warning
        /// without a live acknowledgement.
        fn uncleared(&self) -> Result<RefRefusal, NotImplemented> {
            let report = self.report()?;
            let acks = self
                .state
                .creator
                .draft(PLAN_P)
                .map(|d| d.live_acks())
                .unwrap_or_default();
            if let Some(c) = report.keys().find(|c| c.severity() == RefSeverity::Failure) {
                return Ok(RefRefusal::Failed(*c));
            }
            report
                .keys()
                .find(|c| {
                    c.severity() == RefSeverity::Warning
                        && !acks.iter().any(|k| ref_check(k.check) == Some(**c))
                })
                .map(|c| RefRefusal::Unacknowledged(*c))
                .ok_or(GAP_STEP)
        }

        /// The warning key of the report row of `warning`, or a key on the
        /// whole draft when the report shows no such row.
        fn warning_key(
            &self,
            warning: RefCheck,
        ) -> Result<fstp_creator::WarningKey, NotImplemented> {
            let report = self.production_report(None)?;
            let row = report
                .results()
                .iter()
                .find(|r| ref_check(r.check) == Some(warning));
            Ok(match row {
                Some(r) => r.key(),
                None => fstp_creator::WarningKey {
                    check: fstp_creator::CheckId::from_name(warning.name()).ok_or(GAP_STEP)?,
                    subject: fstp_creator::CheckSubject::Draft,
                },
            })
        }

        /// Raises the count of unresolved imports to `n`: one document by
        /// the first manager with `n` proposals recorded as the system.
        /// Records of the import store are no draft records.
        fn set_unresolved(&mut self, n: u32) -> Result<(), NotImplemented> {
            let now = self
                .state
                .import
                .unresolved(fstp_import::ProgrammeRef::from_raw(PLAN_P.raw()));
            if n < now {
                return Err(GAP_FEWER_IMPORTS);
            }
            let more = n.saturating_sub(now);
            if more == 0 {
                return Ok(());
            }
            let Some(manager) = self.plan.managers.first().copied() else {
                return Err(GAP_STEP);
            };
            let doc_n = u128::from(self.n);
            let document =
                fstp_import::ImportDocumentId::from_raw(0x4d41_d0c0_0000u128.saturating_add(doc_n));
            let text = "SYNTHETIC IMPORT DOCUMENT.\n";
            let doc = fstp_import::ImportDocument {
                id: document,
                programme: fstp_import::ProgrammeRef::from_raw(PLAN_P.raw()),
                blob: fstp_import::BlobAddress::from_bytes([0x4d; 32]),
                media: fstp_import::ImportMedia::TextPlain,
                digest: fstp_import::TextDigest::from_bytes([0x4e; 32]),
                text_bytes: u32::try_from(text.len()).map_err(|_| GAP_STEP)?,
                uploaded_by: fstp_import::AccountRef::from_raw(manager.raw()),
            };
            let reg = Command::Import(fstp_import::ImportCommand::RegisterDocument(doc));
            if !matches!(self.run(reg, manager)?, Run::Appended) {
                return Err(GAP_STEP);
            }
            let mut proposals = Vec::new();
            for i in 0..more {
                let k = u128::from(i).saturating_add(1);
                let value = fstp_import::UntrustedValue::new(&Value::from("SYNTHETIC"))
                    .map_err(|_| GAP_STEP)?;
                let id = document.raw().saturating_mul(256).saturating_add(k);
                proposals.push(fstp_import::ImportProposal {
                    id: fstp_import::ImportProposalId::from_raw(id),
                    document,
                    field: fstp_programme::FieldId::ActionAcronym,
                    value,
                    text: fstp_import::ValueTextRef::new(
                        fstp_import::ValueTextId::from_raw(id),
                        fstp_import::SaltedDigest::from_bytes([0x4f; 32]),
                    ),
                    evidence: vec![fstp_import::Span { start: 0, end: 9 }],
                    config: fstp_import::ImportConfigId::from_raw(1),
                    conflicts_with_profile: Vec::new(),
                });
            }
            let mut ctx = self.ctx(manager);
            ctx.actor = Actor::System(fstp_domain::command::SystemCause::Timeline);
            ctx.tenant_admin = false;
            let rec = Command::Import(fstp_import::ImportCommand::RecordProposals {
                document,
                proposals,
            });
            match self.run_ctx(rec, ctx)? {
                Run::Appended => Ok(()),
                Run::Refused(..) => Err(GAP_STEP),
            }
        }

        /// Runs `cmd` through the engine and maps the outcome. Environment
        /// commands set the recording-fake prober or the import store.
        pub fn apply(&mut self, cmd: &RefCommand) -> Result<StepVerdict, NotImplemented> {
            let verdict = |r: Run, s: &ProductionSystem, approver: Option<AccountId>| match r {
                Run::Appended => Ok(StepVerdict::Accepted),
                Run::Refused(rule, reason) => s
                    .creator_refusal(rule, reason, approver)
                    .map(StepVerdict::Refused),
            };
            match *cmd {
                RefCommand::Open { by } => {
                    let open = CreatorCommand::OpenDraft {
                        programme: PLAN_P,
                        version: PolicyVersionId::from_raw(PLAN_P.raw()),
                        profile: default_profile()?,
                    };
                    let r = self.run(Command::Creator(open), by)?;
                    verdict(r, self, None)
                }
                RefCommand::Grant { by, to } => self.grant(by, to),
                RefCommand::EndBinding { by, of } => {
                    let binding = self.state.core.roster().bindings().find_map(|(id, b)| {
                        (b.account == of
                            && b.programme == PLAN_P
                            && b.role == Role::ProgrammeManager
                            && matches!(b.status, BindingStatus::Active))
                        .then_some(id)
                    });
                    let Some(binding) = binding else {
                        return Ok(StepVerdict::Refused(RefRefusal::NoSuchBinding));
                    };
                    let ctx = self.ctx(by);
                    let end = fstp_domain::Command::EndRole {
                        binding,
                        at: ctx.now,
                    };
                    Ok(match self.run_ctx(Command::Core(end), ctx)? {
                        Run::Appended => StepVerdict::Accepted,
                        Run::Refused(RuleRef::Actor, _) => {
                            StepVerdict::Refused(RefRefusal::NotTenantAdmin)
                        }
                        Run::Refused(..) => StepVerdict::Refused(RefRefusal::NoSuchBinding),
                    })
                }
                RefCommand::Edit { .. } => Err(GAP_EDITS),
                RefCommand::Acknowledge { by, warning, base } => {
                    let Some(revision) = self.named(base) else {
                        return Ok(StepVerdict::Refused(RefRefusal::Opening));
                    };
                    let key = self.warning_key(warning)?;
                    let ack = CreatorCommand::AcknowledgeWarning {
                        programme: PLAN_P,
                        revision,
                        warning: key,
                    };
                    let r = self.run(Command::Creator(ack), by)?;
                    verdict(r, self, None)
                }
                RefCommand::Request { by, base } => {
                    let Some(revision) = self.named(base) else {
                        return Ok(StepVerdict::Refused(RefRefusal::Opening));
                    };
                    let req = CreatorCommand::RequestActivation {
                        programme: PLAN_P,
                        revision,
                    };
                    let r = self.run(Command::Creator(req), by)?;
                    verdict(r, self, None)
                }
                RefCommand::Approve { by, base } => {
                    let Some(revision) = self.named(base) else {
                        return Ok(StepVerdict::Refused(RefRefusal::Opening));
                    };
                    let decision =
                        DecisionId::from_raw(0x4d41_dec0u128.saturating_add(u128::from(self.n)));
                    let approve = CreatorCommand::ApproveActivation {
                        programme: PLAN_P,
                        revision,
                        decision,
                    };
                    let r = self.run(Command::Creator(approve), by)?;
                    verdict(r, self, Some(by))
                }
                RefCommand::SetProbe { probe, outcome } => {
                    let _ = self.probes.insert(probe, outcome);
                    Ok(StepVerdict::Accepted)
                }
                RefCommand::SetUnresolvedImports(n) => {
                    self.set_unresolved(n)?;
                    Ok(StepVerdict::Accepted)
                }
            }
        }

        /// The records on the draft, mapped from the raw ledger entries.
        ///
        /// An entry holding `DraftOpened` is `Opened`. A core
        /// `BindingGranted` of the programme manager role on the draft is
        /// `Granted`, and a `BindingEnded` of such a binding is
        /// `BindingEnded`. Each creator record is its reference record. An
        /// approval entry, with its `ProbeRecorded` records, `ActivationApproved`
        /// and `ProgrammeActivated`, is one `Activated`. A content edit maps
        /// to `Edited` with a neutral effect: the records do not say what an
        /// edit does to the checks. Import records are no draft records.
        pub fn events(&self) -> Result<Vec<RefEvent>, NotImplemented> {
            let mut out = Vec::new();
            let mut i = 0usize;
            let ledger = &self.ledger;
            let mut managers: BTreeMap<BindingId, AccountId> = BTreeMap::new();
            while let Some(first) = ledger.get(i) {
                let mut entry = Vec::new();
                let mut j = i;
                while let Some(e) = ledger.get(j) {
                    if e.command != first.command {
                        break;
                    }
                    entry.push(&e.record);
                    j = j.saturating_add(1);
                }
                let prefix = ledger.get(..i).unwrap_or_default();
                out.extend(self.entry_events(&entry, prefix, &mut managers)?);
                i = j;
            }
            Ok(out)
        }

        /// The reference records of one entry.
        fn entry_events(
            &self,
            entry: &[&Record],
            prefix: &[Entry<Record>],
            managers: &mut BTreeMap<BindingId, AccountId>,
        ) -> Result<Vec<RefEvent>, NotImplemented> {
            let mut out = Vec::new();
            let approval = entry.iter().find_map(|r| match r {
                Record::Creator(CreatorRecord::ActivationApproved(a))
                    if a.programme() == PLAN_P =>
                {
                    Some(a.clone())
                }
                _ => None,
            });
            if let Some(a) = approval {
                let mut probes = BTreeMap::new();
                for r in entry {
                    if let Record::Creator(CreatorRecord::ProbeRecorded {
                        probe, outcome, ..
                    }) = r
                    {
                        let _ = probes.insert(ref_probe(*probe), ref_outcome(*outcome));
                    }
                }
                let before = fstp_engine::replay(prefix).map_err(|_| GAP_STEP)?;
                let unresolved = before
                    .import
                    .unresolved(fstp_import::ProgrammeRef::from_raw(PLAN_P.raw()));
                out.push(RefEvent::Activated {
                    by: a.approver(),
                    revision: a.revision().seq(),
                    inputs: RefInputs {
                        probes,
                        unresolved_imports: unresolved,
                    },
                });
                return Ok(out);
            }
            for r in entry {
                match r {
                    Record::Creator(c) if c.programme() == PLAN_P => {
                        if let Some(e) = creator_event(c) {
                            out.push(e);
                        }
                    }
                    Record::Core(fstp_domain::Record::BindingGranted(g))
                        if g.programme == PLAN_P && g.role == Role::ProgrammeManager =>
                    {
                        let _ = managers.insert(g.binding, g.account);
                        out.push(RefEvent::Granted {
                            by: g.granted_by,
                            to: g.account,
                        });
                    }
                    Record::Core(fstp_domain::Record::BindingEnded(e)) => {
                        if let Some(of) = managers.get(&e.binding) {
                            out.push(RefEvent::BindingEnded { of: *of });
                        }
                    }
                    _ => {}
                }
            }
            Ok(out)
        }

        /// The validation report now, with fresh probes.
        pub fn report(&self) -> Result<RefReport, NotImplemented> {
            let report = self.production_report(None)?;
            let mut out = RefReport::new();
            for r in report.results() {
                let Some(c) = ref_check(r.check) else {
                    continue;
                };
                let detail = match &r.detail {
                    CheckDetail::Cap { p05, p58 } => RefDetail::Cap {
                        p05: p05.clone(),
                        p58: p58.clone(),
                    },
                    _ => RefDetail::None,
                };
                let _ = out.insert(c, detail);
            }
            Ok(out)
        }

        /// The production report of the draft now, as an approval by
        /// `approver` would read it.
        fn production_report(
            &self,
            approver: Option<AccountId>,
        ) -> Result<fstp_creator::ValidationReport, NotImplemented> {
            let cell = self.cell()?;
            let head = self.head().ok_or(GAP_STEP)?;
            let cmd = CreatorCommand::RequestActivation {
                programme: PLAN_P,
                revision: head,
            };
            let ctx = draft_cell::ctx(
                approver.unwrap_or(self.plan.opener),
                Timestamp::from_micros(T0),
                0,
                &self.plan.stat.admins,
            );
            let inputs = cell.inputs(&cmd, &ctx, approver);
            let profile = inputs.profile.clone().ok_or(GAP_STEP)?;
            Ok(fstp_creator::validate(
                &cell.state().core,
                &cell.state().creator,
                PLAN_P,
                &profile,
                &inputs,
            ))
        }

        /// Whether `fstp_engine::replay` of the ledger gives the state.
        pub fn replay_matches(&self) -> Result<bool, String> {
            match fstp_engine::replay(&self.ledger) {
                Ok(s) => Ok(s == self.state),
                Err(e) => Err(format!("replay refused the ledger: {e:?}")),
            }
        }

        /// Teeth: appends one entry with `ActivationApproved` and
        /// `ProgrammeActivated` by `by` at `revision`, through the public
        /// fold, as `harness::teeth::inject_entry` does in M2. Both records
        /// are forged through their codecs, past every guard, with the
        /// probe results of `inputs`.
        pub fn inject_activation(
            &mut self,
            by: AccountId,
            revision: u32,
            inputs: &RefInputs,
        ) -> Result<(), NotImplemented> {
            let d = self.state.creator.draft(PLAN_P).ok_or(GAP_STEP)?;
            let head = d.head();
            let rev = fstp_creator::DraftRevision::new(revision, head.entry());
            let builders = d.builders().clone();
            let report = self.production_report(None)?;
            let digest = report.digest();
            let decision = DecisionId::from_raw(0x4d41_7ee7);
            let mut records: Vec<Record> = ProbeKind::ALL
                .into_iter()
                .map(|p| {
                    let o = match inputs.probe(ref_probe(p)) {
                        RefProbeOutcome::Pass => ProbeOutcome::Pass,
                        RefProbeOutcome::Fail => ProbeOutcome::Fail,
                        RefProbeOutcome::Absent => ProbeOutcome::Absent,
                    };
                    Record::Creator(CreatorRecord::ProbeRecorded {
                        programme: PLAN_P,
                        probe: p,
                        outcome: o,
                        at: Timestamp::from_micros(T0),
                    })
                })
                .collect();
            // The request record's codec form carries the report digest's.
            let report_json = CreatorRecord::ActivationRequested {
                programme: PLAN_P,
                revision: rev,
                report: digest.clone(),
                by,
            }
            .to_json()
            .get("report")
            .cloned()
            .ok_or(GAP_STEP)?;
            let mut o = fstp_json::Object::new();
            let _ = o.insert("kind", Value::from("ActivationApproved"));
            let _ = o.insert("programme", Value::String(PLAN_P.raw().to_string()));
            let mut r = fstp_json::Object::new();
            let _ = r.insert("seq", Value::String(rev.seq().to_string()));
            let _ = r.insert("entry", Value::String(rev.entry().raw().to_string()));
            let _ = o.insert("revision", Value::Object(r));
            let _ = o.insert("report", report_json);
            let _ = o.insert("decision", Value::String(decision.raw().to_string()));
            let _ = o.insert("approver", Value::String(by.raw().to_string()));
            let _ = o.insert(
                "builders",
                Value::Array(
                    builders
                        .iter()
                        .map(|a| Value::String(a.raw().to_string()))
                        .collect(),
                ),
            );
            let approved = CreatorRecord::from_json(&Value::Object(o)).map_err(|_| GAP_STEP)?;
            let CreatorRecord::ActivationApproved(a) = &approved else {
                return Err(GAP_STEP);
            };
            let activated = self.forged_activation(a, &builders)?;
            records.push(Record::Creator(approved));
            records.push(Record::Core(activated));
            let ctx = self.ctx(by);
            let head = self.store.head();
            self.store
                .append(head, ctx.now.micros(), ctx.command.bytes(), records)
                .map_err(|_| GAP_STEP)?;
            let cell = self.cell()?;
            self.keep(cell)
        }

        /// A core `ProgrammeActivated` that pairs with `approved`, forged
        /// past the core guard: decided for a stand-in approver under
        /// answers that admit it, with the approver then rewritten in the
        /// record's codec form.
        fn forged_activation(
            &self,
            approved: &fstp_creator::ActivationApproved,
            builders: &BTreeSet<AccountId>,
        ) -> Result<fstp_domain::Record, NotImplemented> {
            let stand_in = AccountId::from_raw(0x4d41_57a0);
            let cmd = fstp_engine::compose::activate_command(approved);
            let cmd = match cmd {
                fstp_domain::Command::ActivateProgramme {
                    programme,
                    decision,
                    report,
                    revision,
                    ..
                } => fstp_domain::Command::ActivateProgramme {
                    programme,
                    decision,
                    report,
                    revision,
                    creator_builders: builders.clone(),
                },
                other => other,
            };
            let ctx = draft_cell::ctx(
                stand_in,
                Timestamp::from_micros(T0),
                0,
                &[stand_in].into_iter().collect(),
            );
            let mut answers = Answers::new();
            for q in fstp_domain::queries(&self.state.core, &cmd, &ctx).map_err(|_| GAP_STEP)? {
                let holds = matches!(q, Query::IsVerified { .. });
                answers.insert(
                    q,
                    Answer {
                        holds,
                        accounts: None,
                        epoch: self.state.epoch(),
                        digest: ContentDigest::from_bytes([0x7e; 32]),
                    },
                );
            }
            let records = fstp_domain::decide(&self.state.core, &cmd, &ctx, &answers)
                .map_err(|_| GAP_STEP)?;
            let activated = records
                .into_iter()
                .find(|r| matches!(r, fstp_domain::Record::ProgrammeActivated(_)))
                .ok_or(GAP_STEP)?;
            let text = activated
                .to_json()
                .to_canonical()
                .map_err(|_| GAP_STEP)?
                .replace(
                    &format!("\"{}\"", stand_in.raw()),
                    &format!("\"{}\"", approved.approver().raw()),
                );
            let v = fstp_json::parse(text.as_bytes()).map_err(|_| GAP_STEP)?;
            fstp_domain::Record::from_json(&v).map_err(|_| GAP_STEP)
        }
    }

    /// The reference record of one creator record on the draft.
    fn creator_event(c: &CreatorRecord) -> Option<RefEvent> {
        Some(match c {
            CreatorRecord::DraftOpened { by, .. } => RefEvent::Opened { by: *by },
            CreatorRecord::StartApplied { by, .. } => edited(*by, EditKind::Start),
            CreatorRecord::FieldsSaved { by, fields, .. } => {
                let import = fields
                    .iter()
                    .any(|(_, _, p)| matches!(p, fstp_creator::Provenance::Import { .. }));
                edited(
                    *by,
                    if import {
                        EditKind::ImportResolution
                    } else {
                        EditKind::Policy
                    },
                )
            }
            CreatorRecord::NarrativeAccepted { by, .. } => edited(*by, EditKind::Narrative),
            CreatorRecord::InvitationRecorded { by, .. } => edited(*by, EditKind::Invitation),
            CreatorRecord::InvitationWithdrawn { by, .. } => {
                edited(*by, EditKind::InvitationWithdrawal)
            }
            CreatorRecord::WarningAcknowledged {
                by,
                warning,
                revision,
                ..
            } => RefEvent::Acknowledged {
                by: *by,
                warning: ref_check(warning.check)?,
                revision: revision.seq(),
            },
            CreatorRecord::ActivationRequested { by, revision, .. } => RefEvent::Requested {
                by: *by,
                revision: revision.seq(),
            },
            CreatorRecord::ProbeRecorded { probe, outcome, .. } => RefEvent::ProbeRecorded {
                probe: ref_probe(*probe),
                outcome: ref_outcome(*outcome),
            },
            CreatorRecord::TemplateSaved { by, .. } => RefEvent::TemplateSaved { by: *by },
            CreatorRecord::ActivationApproved(_) => return None,
        })
    }

    /// An edit of `kind` by `by`, with the neutral effect (see
    /// [`ProductionSystem::events`]).
    fn edited(by: AccountId, kind: EditKind) -> RefEvent {
        RefEvent::Edited {
            by,
            kind,
            effect: RefEdit::Neutral,
        }
    }

    /// The production check catalogue: each check's name and severity,
    /// read from `fstp_creator::CHECKS`.
    pub fn catalogue() -> Result<Vec<(String, RefSeverity)>, NotImplemented> {
        Ok(fstp_creator::CHECKS
            .iter()
            .map(|c| {
                let severity = match c.severity {
                    fstp_creator::Severity::Failure => RefSeverity::Failure,
                    fstp_creator::Severity::Warning => RefSeverity::Warning,
                };
                (c.id.name().to_owned(), severity)
            })
            .collect())
    }

    /// What the core guard of `ActivateProgramme` decides when a mutant
    /// creator composes it for `actor` with `creator_builders`, on the
    /// draft of `plan` after its setup and `script` (D2, defence in
    /// depth). The mutant skips the creator's own approver checks and
    /// passes the core command to `fstp_domain::decide` as the engine
    /// composition would, with the vault's answers.
    pub fn core_activate(
        plan: &DraftPlan,
        script: &[RefCommand],
        actor: AccountId,
        creator_builders: &BTreeSet<AccountId>,
    ) -> Result<StepVerdict, NotImplemented> {
        let mut s = ProductionSystem::open(plan)?;
        for c in script {
            let _ = s.apply(c)?;
        }
        let head = s.head().ok_or(GAP_STEP)?;
        let cmd = fstp_domain::Command::ActivateProgramme {
            programme: PLAN_P,
            decision: DecisionId::from_raw(0x4d41_c0e0),
            report: fstp_domain::policy::activation::ReportDigest::from_bytes([0; 32]),
            revision: head.seq(),
            creator_builders: creator_builders.clone(),
        };
        let ctx = s.ctx(actor);
        let queries = fstp_domain::queries(&s.state.core, &cmd, &ctx);
        let verdict = match queries {
            Err(r) => Err(r),
            Ok(qs) => {
                let mut answers = Answers::new();
                for q in qs {
                    answers.insert(q.clone(), s.truth.answer(&q));
                }
                fstp_domain::decide(&s.state.core, &cmd, &ctx, &answers).map(|_| ())
            }
        };
        Ok(match verdict {
            Ok(()) => StepVerdict::Accepted,
            Err(r) => StepVerdict::Refused(match r.rule {
                RuleRef::Actor => RefRefusal::NotTenantAdmin,
                RuleRef::I67 if r.reason == RefusalReason::VaultRefused => RefRefusal::SameIdentity,
                RuleRef::I67 => RefRefusal::ApproverIsBuilder,
                _ => return Err(GAP_STEP),
            }),
        })
    }

    /// A draft cell for `plan` with its draft opened by the entry a correct
    /// `OpenDraft` appends (module documentation), and its managers
    /// granted.
    fn forged_cell(plan: &DraftPlan) -> Result<(DraftCell, u32), NotImplemented> {
        let mut store = MemStore::new();
        draft_cell::forged_open(&mut store, PLAN_P, plan.opener, Timestamp::from_micros(T0))
            .map_err(|_| GAP_STEP)?;
        let truth = draft_cell::truth_of(&vault_accounts(plan));
        let mut cell = DraftCell::open_with_theme(
            store,
            truth,
            plan.stat.admins.clone(),
            &BTreeMap::new(),
            plan.stat.wording_pending,
            theme_of(plan),
        )
        .map_err(|_| GAP_STEP)?;
        let mut n = 1u32;
        for m in &plan.managers {
            let at =
                Timestamp::from_micros(T0.saturating_add(i64::from(n).saturating_mul(1_000_000)));
            let mut ctx = draft_cell::ctx(plan.opener, at, n, &plan.stat.admins);
            ctx.binds_tenant_admin = plan.stat.admins.contains(m);
            let binding = BindingId::from_raw(0x4d41_b000u128.saturating_add(u128::from(n)));
            let grant = fstp_domain::Command::GrantRole {
                binding,
                account: *m,
                programme: PLAN_P,
                role: Role::ProgrammeManager,
                start: at,
                second_admin: None,
                confidentiality: Some(TextRef::new(
                    TextId::from_raw(binding.raw()),
                    ContentDigest::from_bytes([0x4d; 32]),
                )),
                organisation: None,
                end: None,
            };
            cell.execute(Command::Core(grant), ctx)
                .map_err(|_| GAP_STEP)?;
            n = n.saturating_add(1);
        }
        Ok((cell, n))
    }

    /// What the engine fold does with an entry that holds a core
    /// `ProgrammeActivated` and no `Creator(ActivationApproved)` for the
    /// same programme, revision and report digest. `Ok(Err(reason))` means
    /// the fold refused it.
    ///
    /// The record is decided by `fstp_domain::decide` for the core
    /// `ActivateProgramme` of the plan's second admin, which the domain
    /// alone admits. The entry is then folded alone into a copy of the
    /// draft's state through `fstp_engine::apply_in` and `finish`.
    pub fn fold_unpaired_activation(
        plan: &DraftPlan,
    ) -> Result<Result<(), String>, NotImplemented> {
        let (cell, n) = forged_cell(plan)?;
        let state = cell.state().clone();
        let approver = plan
            .stat
            .admins
            .iter()
            .copied()
            .find(|a| *a != plan.opener)
            .ok_or(GAP_STEP)?;
        let head = state.creator.head(PLAN_P).ok_or(GAP_STEP)?;
        let cmd = fstp_domain::Command::ActivateProgramme {
            programme: PLAN_P,
            decision: DecisionId::from_raw(0x4d41_f01d),
            report: fstp_domain::policy::activation::ReportDigest::from_bytes([0; 32]),
            revision: head.seq(),
            creator_builders: BTreeSet::new(),
        };
        let at = Timestamp::from_micros(T0.saturating_add(i64::from(n).saturating_mul(1_000_000)));
        let ctx = draft_cell::ctx(approver, at, n, &plan.stat.admins);
        let truth = cell.vault.truth();
        let mut answers = Answers::new();
        for q in fstp_domain::queries(&state.core, &cmd, &ctx).map_err(|_| GAP_STEP)? {
            answers.insert(q.clone(), truth.answer(&q));
        }
        let records =
            fstp_domain::decide(&state.core, &cmd, &ctx, &answers).map_err(|_| GAP_STEP)?;
        let activated = records
            .into_iter()
            .find(|r| matches!(r, fstp_domain::Record::ProgrammeActivated(_)))
            .ok_or(GAP_STEP)?;
        let mut copy = state;
        let seq = fstp_ledger::Seq::from_raw(u64::from(n).saturating_add(100));
        let folded = fstp_engine::apply_in(
            &mut copy,
            seq,
            at,
            Some(ctx.command.bytes()),
            &Record::Core(activated),
        )
        .and_then(|()| fstp_engine::finish(&mut copy));
        Ok(folded.map_err(|e| format!("{e:?}")))
    }

    /// What `Engine::execute` does with a core `ActivateProgramme` that
    /// arrives from outside, by `actor`. `Ok(Some(rule))` names the rule
    /// of the refusal, such as `"I66"`; `Ok(None)` means it was accepted.
    pub fn execute_core_activate(
        plan: &DraftPlan,
        actor: AccountId,
    ) -> Result<Option<String>, NotImplemented> {
        let (mut cell, n) = forged_cell(plan)?;
        let head = cell.state().creator.head(PLAN_P).ok_or(GAP_STEP)?;
        let builders = cell
            .state()
            .creator
            .draft(PLAN_P)
            .map(|d| d.builders().clone())
            .unwrap_or_default();
        let cmd = fstp_domain::Command::ActivateProgramme {
            programme: PLAN_P,
            decision: DecisionId::from_raw(0x4d41_e8ec),
            report: fstp_domain::policy::activation::ReportDigest::from_bytes([0; 32]),
            revision: head.seq(),
            creator_builders: builders,
        };
        let at = Timestamp::from_micros(T0.saturating_add(i64::from(n).saturating_mul(1_000_000)));
        let ctx = draft_cell::ctx(actor, at, n, &plan.stat.admins);
        match cell.execute(Command::Core(cmd), ctx) {
            Ok(_) => Ok(None),
            Err(fstp_engine::ExecError::Refused(r)) => Ok(Some(format!("{:?}", r.rule))),
            Err(_) => Err(GAP_STEP),
        }
    }

    /// One registry operation as the I-66 route test reads it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RegistryRow {
        /// The operation name, such as `creator.approve_activation`.
        pub op: String,
        /// The `CommandKind` the route decides directly, by its debug name.
        pub command: Option<String>,
        /// The MCP tool name, if the operation has a tool.
        pub tool: Option<&'static str>,
    }

    /// The registry as the I-66 route test reads it: every operation of
    /// `fstp_access::OPS`, and the `COMPOSED_ONLY` kinds by their debug
    /// names.
    pub fn registry() -> Result<(Vec<RegistryRow>, Vec<String>), NotImplemented> {
        if fstp_access::OPS.is_empty() {
            return Err(NotImplemented::new(
                "fstp_access::OPS (W0 stub: the registry is empty; lane W3a)",
            ));
        }
        let rows = fstp_access::OPS
            .iter()
            .map(|spec| RegistryRow {
                op: spec.name.to_owned(),
                command: match spec.kind {
                    fstp_access::OpKind::Command(k) => Some(format!("{k:?}")),
                    _ => None,
                },
                tool: spec.tool.map(|t| t.name),
            })
            .collect();
        let composed = fstp_access::COMPOSED_ONLY
            .iter()
            .map(|k| format!("{k:?}"))
            .collect();
        Ok((rows, composed))
    }

    /// One vault answer seen during a preview: the query digest and the
    /// answer bit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VaultAnswer {
        /// The query digest.
        pub digest: [u8; 32],
        /// The answer bit.
        pub bit: bool,
    }

    /// The vault answers the fake vault gave during the previews of
    /// `invitees` on the draft of `plan`, and the vault answers the audit
    /// log holds afterwards (NOTE 5).
    ///
    /// The opener invites each invitee by account to the programme
    /// manager role, through `CreatorCommand::Invite` on the engine. The
    /// cell's creator environment then previews every invitation with
    /// `fstp_domain::roles::preview_grant` for a report, recording each
    /// vault answer (`fake/shell.rs`).
    pub fn preview_vault_trace(
        plan: &DraftPlan,
        invitees: &[AccountId],
    ) -> Result<(Vec<VaultAnswer>, Vec<VaultAnswer>), NotImplemented> {
        let (mut cell, mut n) = forged_cell(plan)?;
        for (i, a) in invitees.iter().enumerate() {
            let at =
                Timestamp::from_micros(T0.saturating_add(i64::from(n).saturating_mul(1_000_000)));
            let ctx = draft_cell::ctx(plan.opener, at, n, &plan.stat.admins);
            let k = u128::try_from(i).map_err(|_| GAP_STEP)?;
            let invite = CreatorCommand::Invite {
                programme: PLAN_P,
                invitation: fstp_creator::InvitationId::from_raw(0x4d41_1000u128.saturating_add(k)),
                role: Role::ProgrammeManager,
                invitee: fstp_creator::Invitee::Account(*a),
                organisation: None,
            };
            cell.execute(Command::Creator(invite), ctx)
                .map_err(|_| GAP_STEP)?;
            n = n.saturating_add(1);
        }
        let asked_before = cell.engine.decider().0.asks().len();
        let audited_before = cell.audit.records().len();
        let head = cell.state().creator.head(PLAN_P).ok_or(GAP_STEP)?;
        let cmd = CreatorCommand::RequestActivation {
            programme: PLAN_P,
            revision: head,
        };
        let at = Timestamp::from_micros(T0.saturating_add(i64::from(n).saturating_mul(1_000_000)));
        let ctx = draft_cell::ctx(plan.opener, at, n, &plan.stat.admins);
        let _ = cell.inputs(&cmd, &ctx, None);
        let asked = cell
            .engine
            .decider()
            .0
            .asks()
            .into_iter()
            .skip(asked_before)
            .map(|(_, a)| VaultAnswer {
                digest: a.digest.bytes(),
                bit: a.holds,
            })
            .collect();
        let audited = cell
            .audit
            .records()
            .into_iter()
            .skip(audited_before)
            .map(|r| VaultAnswer {
                digest: r.query.0,
                bit: r.answer,
            })
            .collect();
        Ok((asked, audited))
    }
}

use production::ProductionSystem;

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// What decides the steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Production, through [`production`].
    Production,
    /// The reference alone.
    Reference,
}

/// One draft on one backend, in the reference vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum System {
    /// The reference system.
    Reference(Box<RefSystem>),
    /// The production system.
    Production(Box<ProductionSystem>),
}

impl System {
    /// Opens the draft of `plan` on `backend`.
    pub fn open(backend: Backend, plan: &DraftPlan) -> Result<System, String> {
        match backend {
            Backend::Reference => RefSystem::open(plan)
                .map(|r| System::Reference(Box::new(r)))
                .map_err(|(cmd, r)| {
                    format!("the plan is not realisable: {cmd:?} refused with {r:?}")
                }),
            Backend::Production => ProductionSystem::open(plan)
                .map(|p| System::Production(Box::new(p)))
                .map_err(|e| format!("production: {e}")),
        }
    }

    /// Applies `cmd`.
    pub fn apply(&mut self, cmd: &RefCommand) -> Result<StepVerdict, String> {
        match self {
            System::Reference(r) => Ok(r.apply(cmd)),
            System::Production(p) => p.apply(cmd).map_err(|e| format!("production: {e}")),
        }
    }

    /// The records on the draft.
    pub fn events(&self) -> Result<Vec<RefEvent>, String> {
        match self {
            System::Reference(r) => Ok(r.events.clone()),
            System::Production(p) => p.events().map_err(|e| format!("production: {e}")),
        }
    }

    /// The report now.
    pub fn report(&self) -> Result<RefReport, String> {
        match self {
            System::Reference(r) => Ok(r.report()),
            System::Production(p) => p.report().map_err(|e| format!("production: {e}")),
        }
    }

    /// Whether replaying the records gives the state.
    pub fn replay_matches(&self) -> Result<bool, String> {
        match self {
            System::Reference(r) => Ok(RefDraft::fold(&r.events) == r.draft),
            System::Production(p) => p.replay_matches(),
        }
    }

    /// Teeth: appends an activation record by `by` at `revision`, in the
    /// current environment, past every check.
    pub fn inject_activation(&mut self, by: AccountId, revision: u32) -> Result<(), String> {
        match self {
            System::Reference(r) => {
                let e = RefEvent::Activated {
                    by,
                    revision,
                    inputs: r.env.clone(),
                };
                r.draft.apply(&e);
                r.events.push(e);
                Ok(())
            }
            System::Production(p) => {
                let inputs = RefInputs::passing();
                p.inject_activation(by, revision, &inputs)
                    .map_err(|e| format!("production: {e}"))
            }
        }
    }
}

/// Runs `attempt` on `backend` through the same script as
/// [`crate::reference::creator::run_attempt`]: open, acknowledge every
/// warning the report shows, request, change the environment to the
/// approval environment, recompute the report, approve.
pub fn attempt(backend: Backend, attempt: &Attempt) -> Result<AttemptOutcome, String> {
    let mut s = System::open(backend, &attempt.plan)?;
    let builder = attempt
        .plan
        .managers
        .first()
        .copied()
        .unwrap_or(attempt.plan.opener);
    if attempt.acknowledge {
        let warnings: Vec<RefCheck> = s
            .report()?
            .keys()
            .copied()
            .filter(|c| c.severity() == RefSeverity::Warning)
            .collect();
        for w in warnings {
            let cmd = RefCommand::Acknowledge {
                by: builder,
                warning: w,
                base: Base::Head,
            };
            if let StepVerdict::Refused(r) = s.apply(&cmd)? {
                return Err(format!("setup: {cmd:?} refused with {r:?}"));
            }
        }
    }
    let request = RefCommand::Request {
        by: builder,
        base: Base::Head,
    };
    if let StepVerdict::Refused(r) = s.apply(&request)? {
        return Err(format!("setup: {request:?} refused with {r:?}"));
    }
    let report_at_request = s.report()?;
    for p in RefProbe::ALL {
        let outcome = attempt.approval_env.probe(p);
        if outcome != attempt.plan.env.probe(p) {
            s.apply(&RefCommand::SetProbe { probe: p, outcome })?;
        }
    }
    if attempt.approval_env.unresolved_imports != attempt.plan.env.unresolved_imports {
        s.apply(&RefCommand::SetUnresolvedImports(
            attempt.approval_env.unresolved_imports,
        ))?;
    }
    let report_at_approval = s.report()?;
    let verdict = s.apply(&RefCommand::Approve {
        by: attempt.approver,
        base: Base::Head,
    })?;
    Ok(AttemptOutcome {
        report_at_request,
        report_at_approval,
        verdict,
    })
}

// ---------------------------------------------------------------------------
// The invariant predicates
// ---------------------------------------------------------------------------

/// The builder set of `events`, recomputed from raw records (Q1 A): the
/// author of every authored record except an activation.
pub fn builders_from_raw(events: &[RefEvent]) -> BTreeSet<AccountId> {
    let mut b = BTreeSet::new();
    for e in events {
        match e {
            RefEvent::Opened { by }
            | RefEvent::Granted { by, .. }
            | RefEvent::Edited { by, .. }
            | RefEvent::Acknowledged { by, .. }
            | RefEvent::Requested { by, .. }
            | RefEvent::TemplateSaved { by } => {
                b.insert(*by);
            }
            RefEvent::ProbeRecorded { .. }
            | RefEvent::BindingEnded { .. }
            | RefEvent::Activated { .. } => {}
        }
    }
    b
}

/// The revision of the record at 0-based position `i`.
fn revision_at(i: usize) -> u32 {
    u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX)
}

/// I-66 over the records on one draft: every activation names the head
/// revision before its entry, and the report recomputed at that point,
/// over the probe results and import count recorded in the same entry,
/// shows no failure and no warning without a live acknowledgement.
///
/// It recomputes the content from raw records and never calls
/// [`RefSystem::decide`] or [`crate::reference::creator::report`].
pub fn check_i66(stat: &RefStatic, events: &[RefEvent]) -> Result<(), String> {
    for (k, e) in events.iter().enumerate() {
        let RefEvent::Activated {
            revision, inputs, ..
        } = e
        else {
            continue;
        };
        let prefix = events.get(..k).unwrap_or_default();
        let head = u32::try_from(k).unwrap_or(u32::MAX);
        if *revision != head {
            return Err(format!(
                "I-66: the activation at position {k} names revision {revision}, but the head was {head}"
            ));
        }
        let mut content = BTreeSet::new();
        let mut last_edit = 0;
        let mut acks: Vec<(RefCheck, u32)> = Vec::new();
        for (i, p) in prefix.iter().enumerate() {
            match p {
                RefEvent::Opened { .. }
                | RefEvent::Granted { .. }
                | RefEvent::BindingEnded { .. } => last_edit = revision_at(i),
                RefEvent::Edited { effect, .. } => {
                    last_edit = revision_at(i);
                    match effect {
                        RefEdit::Seed(c) => {
                            content.insert(*c);
                        }
                        RefEdit::Fix(c) => {
                            content.remove(c);
                        }
                        RefEdit::Neutral => {}
                    }
                }
                RefEvent::Acknowledged {
                    warning, revision, ..
                } => acks.push((*warning, *revision)),
                _ => {}
            }
        }
        let builders = builders_from_raw(prefix);
        let mut shown: BTreeSet<RefCheck> = content
            .into_iter()
            .filter(|c| c.feed() == CheckFeed::Content)
            .collect();
        if stat.cap.p05_minor > stat.cap.p58_minor {
            shown.insert(RefCheck::CapAboveCeiling);
        }
        for p in RefProbe::ALL {
            if inputs.probe(p) != RefProbeOutcome::Pass {
                shown.insert(p.check());
            }
        }
        if inputs.unresolved_imports != 0 {
            shown.insert(RefCheck::ImportUnresolved);
        }
        if stat.wording_pending {
            shown.insert(RefCheck::LegalWordingPending);
        }
        if stat.admins.len() < 2 {
            shown.insert(RefCheck::TooFewTenantAdmins);
        }
        if builders.iter().any(|b| !stat.vault.is_verified(*b)) {
            shown.insert(RefCheck::BuilderUnverified);
        }
        shown.extend(
            stat.theme_faults
                .iter()
                .copied()
                .filter(|c| c.feed() == CheckFeed::Theme),
        );
        for c in &shown {
            match c.severity() {
                RefSeverity::Failure => {
                    return Err(format!(
                        "I-66: the activation at revision {revision} has a report with the failure {}",
                        c.name()
                    ));
                }
                RefSeverity::Warning => {
                    let live = acks
                        .iter()
                        .any(|(w, r)| w == c && *r >= last_edit && *r <= head);
                    if !live {
                        return Err(format!(
                            "I-66: the activation at revision {revision} has the warning {} with no acknowledgement after the last edit at {last_edit}",
                            c.name()
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// I-67 over the records on one draft: every approver is a tenant admin
/// outside the builder set recomputed from raw records, the vault
/// verified the approver and every builder, and no builder shares the
/// approver's verified identity (Q1 A, Q2 B).
pub fn check_i67(stat: &RefStatic, events: &[RefEvent]) -> Result<(), String> {
    for (k, e) in events.iter().enumerate() {
        let RefEvent::Activated { by, revision, .. } = e else {
            continue;
        };
        let prefix = events.get(..k).unwrap_or_default();
        let builders = builders_from_raw(prefix);
        let v = &stat.vault;
        if !stat.admins.contains(by) {
            return Err(format!(
                "I-67: the approver {by:?} at revision {revision} is not a tenant admin"
            ));
        }
        if builders.contains(by) {
            return Err(format!(
                "I-67: the approver {by:?} at revision {revision} built the draft"
            ));
        }
        if !v.is_verified(*by) {
            return Err(format!(
                "I-67: the approver {by:?} at revision {revision} is unverified"
            ));
        }
        if let Some(b) = builders.iter().find(|b| !v.is_verified(**b)) {
            return Err(format!(
                "I-67: the builder {b:?} of the activation at revision {revision} is unverified"
            ));
        }
        let person = v.person(*by);
        if let Some(b) = builders
            .iter()
            .find(|b| person.is_some() && v.person(**b) == person)
        {
            return Err(format!(
                "I-67: the approver {by:?} at revision {revision} is the same person as the builder {b:?}"
            ));
        }
    }
    Ok(())
}

/// The number of activation records in `events`.
pub fn activations(events: &[RefEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, RefEvent::Activated { .. }))
        .count()
}

// ---------------------------------------------------------------------------
// M-ACTIVATE
// ---------------------------------------------------------------------------

/// The measured state count of the reference run of M-ACTIVATE without
/// the Sybil pair. The tripwire is twice this.
pub const REFERENCE_STATES: usize = 29_182;

/// The measured state count of the reference run with the Sybil pair.
pub const REFERENCE_SYBIL_STATES: usize = 45_482;

/// The state count the production run's first exhaustive run records.
/// Zero stops every run, so no production run passes on a placeholder.
pub const TRIPWIRE: usize = 0;

/// The configuration of M-ACTIVATE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ActivateConfig {
    /// Whether A2 shares a verified identity with M1 (T-SOD-SYBIL).
    pub sybil: bool,
}

/// The draft plan of M-ACTIVATE: A1 opens and grants M1, M1 seeds the
/// fixable failure `FieldUnset` and the warning `RosterShort`.
pub fn model_plan(config: ActivateConfig) -> DraftPlan {
    let mut plan = clean_plan();
    plan.seeds = [RefCheck::FieldUnset, RefCheck::RosterShort]
        .into_iter()
        .collect();
    if config.sybil {
        plan.stat.vault = sybil_vault();
    }
    plan
}

/// The cast vault with A2 the same verified person as M1.
pub fn sybil_vault() -> RefVault {
    let m1 = cast_vault().person(M1).unwrap_or(0);
    cast_vault().with(TB, m1, true)
}

/// How many steps of each kind remain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Budget {
    /// Grants of M2 by A2.
    pub grants: u8,
    /// Edits.
    pub edits: u8,
    /// Acknowledgements.
    pub acks: u8,
    /// Activation requests.
    pub requests: u8,
    /// Approval attempts.
    pub approvals: u8,
    /// Probe flips.
    pub flips: u8,
}

impl Budget {
    /// The budget of design section 8.5.
    pub const M_ACTIVATE: Budget = Budget {
        grants: 1,
        edits: 2,
        acks: 1,
        requests: 1,
        approvals: 2,
        flips: 1,
    };
}

/// A refusal the witnesses look for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Seen {
    /// An approval was refused for an unacknowledged warning.
    Unacknowledged,
    /// An approval was refused for a failure.
    Failed,
    /// An approval was refused while a live acknowledgement existed.
    RefusedAfterAcknowledgement,
    /// A2 was refused as a builder after acknowledging a warning.
    AdminAcknowledgerRefused,
    /// A2 was refused as a builder after granting a draft binding.
    AdminGrantorRefused,
    /// A2 was refused as the same person as a builder.
    SybilRefused,
    /// An approval was refused after a probe flipped to failing.
    RefusedAfterProbeFlip,
}

/// One state of M-ACTIVATE.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ActivateState {
    /// The reference system.
    pub reference: RefSystem,
    /// The production system, on the production backend.
    pub production: Option<System>,
    /// The steps left.
    pub budget: Budget,
    /// The refusals seen so far.
    pub seen: BTreeSet<Seen>,
    /// A disagreement between production and the reference, or an
    /// adapter failure. Set once; the state is then terminal.
    pub fault: Option<String>,
}

impl ActivateState {
    /// The records the properties read: production's on the production
    /// backend, else the reference's.
    pub fn events(&self) -> Result<Vec<RefEvent>, String> {
        match &self.production {
            Some(p) => p.events(),
            None => Ok(self.reference.events.clone()),
        }
    }

    /// The plan facts.
    pub fn stat(&self) -> &RefStatic {
        &self.reference.stat
    }

    /// Whether the draft is active.
    pub fn active(&self) -> bool {
        self.reference.draft.active.is_some()
    }
}

/// M-ACTIVATE (design 8.5).
#[derive(Clone, Debug)]
pub struct ActivateModel {
    config: ActivateConfig,
    backend: Backend,
    init: ActivateState,
}

impl ActivateModel {
    /// Builds the model. Its start state comes from genesis through the
    /// backend's own commands.
    pub fn new(config: ActivateConfig, backend: Backend) -> Result<ActivateModel, String> {
        let plan = model_plan(config);
        let reference = RefSystem::open(&plan)
            .map_err(|(cmd, r)| format!("the reference refused {cmd:?} with {r:?}"))?;
        let production = match backend {
            Backend::Reference => None,
            Backend::Production => Some(System::open(Backend::Production, &plan)?),
        };
        Ok(ActivateModel {
            config,
            backend,
            init: ActivateState {
                reference,
                production,
                budget: Budget::M_ACTIVATE,
                seen: BTreeSet::new(),
                fault: None,
            },
        })
    }

    /// The configuration.
    pub fn config(&self) -> ActivateConfig {
        self.config
    }

    /// The backend.
    pub fn backend(&self) -> Backend {
        self.backend
    }
}

/// The refusals a step adds to the witnesses.
fn seen_by(before: &ActivateState, cmd: &RefCommand, verdict: StepVerdict) -> Vec<Seen> {
    let mut out = Vec::new();
    let RefCommand::Approve { by, .. } = *cmd else {
        return out;
    };
    let StepVerdict::Refused(r) = verdict else {
        return out;
    };
    let d = &before.reference.draft;
    let events = &before.reference.events;
    match r {
        RefRefusal::Unacknowledged(_) => out.push(Seen::Unacknowledged),
        RefRefusal::Failed(c) => {
            out.push(Seen::Failed);
            if c == RefCheck::ChannelUnreachable {
                out.push(Seen::RefusedAfterProbeFlip);
            }
        }
        RefRefusal::ApproverIsBuilder if by == TB => {
            if events
                .iter()
                .any(|e| matches!(e, RefEvent::Acknowledged { by: a, .. } if *a == TB))
            {
                out.push(Seen::AdminAcknowledgerRefused);
            }
            if events
                .iter()
                .any(|e| matches!(e, RefEvent::Granted { by: a, .. } if *a == TB))
            {
                out.push(Seen::AdminGrantorRefused);
            }
        }
        RefRefusal::SameIdentity if by == TB => out.push(Seen::SybilRefused),
        _ => {}
    }
    if d.acks.keys().any(|w| d.ack_live(*w)) {
        out.push(Seen::RefusedAfterAcknowledgement);
    }
    out
}

impl Model for ActivateModel {
    type State = ActivateState;
    type Action = RefCommand;

    fn init(&self) -> Vec<ActivateState> {
        vec![self.init.clone()]
    }

    fn actions(&self, s: &ActivateState, actions: &mut Vec<RefCommand>) {
        if s.fault.is_some() || s.active() {
            return;
        }
        let b = s.budget;
        if b.grants > 0 {
            actions.push(RefCommand::Grant { by: TB, to: M2 });
        }
        if b.edits > 0 {
            actions.push(RefCommand::Edit {
                by: M1,
                kind: EditKind::Policy,
                effect: RefEdit::Fix(RefCheck::FieldUnset),
                base: Base::Head,
            });
            actions.push(RefCommand::Edit {
                by: M1,
                kind: EditKind::Artefact,
                effect: RefEdit::Neutral,
                base: Base::Head,
            });
            actions.push(RefCommand::Edit {
                by: M2,
                kind: EditKind::Policy,
                effect: RefEdit::Neutral,
                base: Base::Head,
            });
        }
        if b.acks > 0 {
            for by in [M1, TB] {
                actions.push(RefCommand::Acknowledge {
                    by,
                    warning: RefCheck::RosterShort,
                    base: Base::Head,
                });
            }
        }
        if b.requests > 0 {
            for by in [M1, TB] {
                actions.push(RefCommand::Request {
                    by,
                    base: Base::Head,
                });
            }
        }
        if b.approvals > 0 {
            actions.push(RefCommand::Approve {
                by: TB,
                base: Base::Head,
            });
            actions.push(RefCommand::Approve {
                by: TB,
                base: Base::Previous,
            });
            actions.push(RefCommand::Approve {
                by: TA,
                base: Base::Head,
            });
            actions.push(RefCommand::Approve {
                by: M2,
                base: Base::Head,
            });
        }
        if b.flips > 0 {
            actions.push(RefCommand::SetProbe {
                probe: RefProbe::Channel,
                outcome: RefProbeOutcome::Fail,
            });
        }
    }

    fn step(&self, s: &ActivateState, cmd: &RefCommand) -> Option<ActivateState> {
        let mut next = s.clone();
        let budget = &mut next.budget;
        let slot = match cmd {
            RefCommand::Grant { .. } => &mut budget.grants,
            RefCommand::Edit { .. } => &mut budget.edits,
            RefCommand::Acknowledge { .. } => &mut budget.acks,
            RefCommand::Request { .. } => &mut budget.requests,
            RefCommand::Approve { .. } => &mut budget.approvals,
            RefCommand::SetProbe { .. } => &mut budget.flips,
            RefCommand::Open { .. }
            | RefCommand::EndBinding { .. }
            | RefCommand::SetUnresolvedImports(_) => return None,
        };
        *slot = slot.checked_sub(1)?;
        let verdict = next.reference.apply(cmd);
        let before = next.seen.len();
        next.seen.extend(seen_by(s, cmd, verdict));
        let witnessed = next.seen.len() != before;
        if let Some(p) = next.production.as_mut() {
            match p.apply(cmd) {
                Ok(v) if v.accepted() == verdict.accepted() => {}
                Ok(v) => {
                    next.fault = Some(format!(
                        "two-way: {cmd:?} gave {v:?} on production and {verdict:?} on the reference"
                    ));
                }
                Err(e) => next.fault = Some(e),
            }
        }
        // A refusal both sides agree on appends nothing. Unless it is a new
        // witness, the step is disabled, which keeps the state space small.
        if next.fault.is_none() && !verdict.accepted() && !witnessed {
            return None;
        }
        Some(next)
    }

    fn is_terminal(&self, s: &ActivateState) -> bool {
        s.fault.is_some() || s.active() || self.budget_spent(s)
    }
}

impl ActivateModel {
    /// Whether the budget is spent, so the state is a legitimate end.
    fn budget_spent(&self, s: &ActivateState) -> bool {
        let mut a = Vec::new();
        self.actions(s, &mut a);
        a.is_empty()
    }
}

/// The checks every M-ACTIVATE property list holds: the adapter and
/// two-way agreement, and `replay(ledger) == state`.
fn common_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ActivateState>,
{
    vec![
        Property::<M>::always_with("two-way", |s: &ActivateState| match &s.fault {
            None => Ok(()),
            Some(f) => Err(f.clone()),
        }),
        Property::<M>::always_with("replay", |s: &ActivateState| {
            let reference = RefDraft::fold(&s.reference.events) == s.reference.draft;
            let production = match &s.production {
                Some(p) => p.replay_matches()?,
                None => true,
            };
            if reference && production {
                Ok(())
            } else {
                Err(format!(
                    "replay(ledger) differs from the state: reference {reference}, production {production}"
                ))
            }
        }),
    ]
}

/// `always("I-66")` alone, for any model over [`ActivateState`], such as
/// a teeth mutant.
pub fn i66_always<'a, M>() -> Property<'a, M>
where
    M: Model<State = ActivateState>,
{
    Property::<M>::always_with("I-66", |s: &ActivateState| {
        check_i66(s.stat(), &s.events()?)
    })
}

/// `always("I-67")` alone, for any model over [`ActivateState`], such as
/// a teeth mutant.
pub fn i67_always<'a, M>() -> Property<'a, M>
where
    M: Model<State = ActivateState>,
{
    Property::<M>::always_with("I-67", |s: &ActivateState| {
        check_i67(s.stat(), &s.events()?)
    })
}

/// The witness that some run activates, for any model over
/// [`ActivateState`].
pub fn activation_witness<'a, M>(id: &str) -> Property<'a, M>
where
    M: Model<State = ActivateState>,
{
    Property::<M>::reachable(id, |s: &ActivateState| s.active())
}

/// The I-66 properties of M-ACTIVATE: `always("I-66")`,
/// `transition("I-66")` and the witnesses of design 8.5.
pub fn i66_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ActivateState, Action = RefCommand>,
{
    let mut v = common_properties::<M>();
    v.push(i66_always::<M>());
    v.push(Property::<M>::transition_with(
        "I-66",
        |before: &ActivateState, cmd: &RefCommand, after: &ActivateState| {
            let was = activations(&before.events()?);
            let events = after.events()?;
            if activations(&events) == was {
                return Ok(());
            }
            if !cmd.is_approval() {
                return Err(format!("I-66: {cmd:?} activated the programme"));
            }
            check_i66(after.stat(), &events)
        },
    ));
    v.push(Property::<M>::reachable(
        "I-66 witness: activation",
        |s: &ActivateState| s.active(),
    ));
    v.push(Property::<M>::reachable(
        "I-66 witness: refusal for an unacknowledged warning",
        |s: &ActivateState| s.seen.contains(&Seen::Unacknowledged),
    ));
    v.push(Property::<M>::reachable(
        "I-66 witness: refusal after acknowledgement",
        |s: &ActivateState| s.seen.contains(&Seen::RefusedAfterAcknowledgement),
    ));
    v.push(Property::<M>::reachable(
        "I-66 witness: refusal after a probe flip at approval",
        |s: &ActivateState| s.seen.contains(&Seen::RefusedAfterProbeFlip),
    ));
    v
}

/// The I-67 properties of M-ACTIVATE without the Sybil pair:
/// `always("I-67")`, `transition("I-67")` and the witnesses of design
/// 8.4 and 8.5.
pub fn i67_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ActivateState, Action = RefCommand>,
{
    let mut v = i67_core::<M>();
    v.push(Property::<M>::reachable(
        "I-67 witness: activation by a non-builder admin",
        |s: &ActivateState| s.active(),
    ));
    v.push(Property::<M>::reachable(
        "I-67 witness: refusal of an admin who acknowledged a warning",
        |s: &ActivateState| s.seen.contains(&Seen::AdminAcknowledgerRefused),
    ));
    v.push(Property::<M>::reachable(
        "I-67 witness: refusal of an admin who granted a draft binding",
        |s: &ActivateState| s.seen.contains(&Seen::AdminGrantorRefused),
    ));
    v
}

/// The I-67 properties of M-ACTIVATE with the Sybil pair.
pub fn i67_sybil_properties<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ActivateState, Action = RefCommand>,
{
    let mut v = i67_core::<M>();
    v.push(Property::<M>::always(
        "I-67: no activation with a Sybil pair",
        |s: &ActivateState| !s.active(),
    ));
    v.push(Property::<M>::reachable(
        "I-67 witness: Sybil approver refused",
        |s: &ActivateState| s.seen.contains(&Seen::SybilRefused),
    ));
    v
}

fn i67_core<'a, M>() -> Vec<Property<'a, M>>
where
    M: Model<State = ActivateState, Action = RefCommand>,
{
    let mut v = common_properties::<M>();
    v.push(i67_always::<M>());
    v.push(Property::<M>::transition_with(
        "I-67",
        |before: &ActivateState, cmd: &RefCommand, after: &ActivateState| {
            let prior = before.events()?;
            let events = after.events()?;
            if activations(&events) == activations(&prior) {
                return Ok(());
            }
            let RefCommand::Approve { by, .. } = *cmd else {
                return Err(format!("I-67: {cmd:?} activated the programme"));
            };
            if builders_from_raw(&prior).contains(&by) {
                return Err(format!("I-67: the builder {by:?} approved the activation"));
            }
            check_i67(after.stat(), &events)
        },
    ));
    v
}

// ---------------------------------------------------------------------------
// Teeth faults
// ---------------------------------------------------------------------------

/// Teeth for I-66: a creator that approves on the report stored at the
/// request, without recomputing it. Where A2 would be refused for a
/// failure or an unacknowledged warning while a request exists, the fault
/// appends A2's activation at the head anyway.
pub fn fault_stale_report_accepted(s: &ActivateState) -> Option<ActivateState> {
    if s.fault.is_some() || s.active() || s.reference.draft.request.is_none() {
        return None;
    }
    let refusal = s.reference.decide(&RefCommand::Approve {
        by: TB,
        base: Base::Head,
    });
    if !matches!(
        refusal,
        Err(RefRefusal::Failed(_) | RefRefusal::Unacknowledged(_))
    ) {
        return None;
    }
    inject(s, TB)
}

/// Teeth for I-67: a creator that lets the opener A1 approve. Where A2's
/// approval would be accepted, the fault appends A1's activation instead,
/// so only I-67 can catch it.
pub fn fault_builder_approval(s: &ActivateState) -> Option<ActivateState> {
    if s.fault.is_some() || s.active() {
        return None;
    }
    let ok = s.reference.decide(&RefCommand::Approve {
        by: TB,
        base: Base::Head,
    });
    if ok.is_err() {
        return None;
    }
    inject(s, TA)
}

fn inject(s: &ActivateState, by: AccountId) -> Option<ActivateState> {
    let mut next = s.clone();
    let head = next.reference.draft.head;
    let mut reference = System::Reference(Box::new(next.reference.clone()));
    if let Err(e) = reference.inject_activation(by, head) {
        next.fault = Some(e);
        return Some(next);
    }
    if let System::Reference(r) = reference {
        next.reference = *r;
    }
    if let Some(Err(e)) = next
        .production
        .as_mut()
        .map(|p| p.inject_activation(by, head))
    {
        next.fault = Some(e);
    }
    Some(next)
}

// ---------------------------------------------------------------------------
// The activation machine
// ---------------------------------------------------------------------------

/// What a machine run concentrates on. Each test of design 8.4 that is a
/// "Machine" runs one focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Focus {
    /// Warnings, acknowledgements and approvals
    /// (`i66_unacknowledged_warning_blocks_activation`).
    Acknowledgement,
    /// Acknowledgements and requests followed by edits
    /// (`i66_edit_after_report_voids_clearance`).
    EditAfterReport,
    /// Random creator, policy, grant and acknowledgement actions by every
    /// cast member (`i67_approver_is_never_a_builder`).
    Builders,
    /// The Sybil pair (`i67_sybil_builder_and_approver_refused`).
    Sybil,
}

/// The model side of the machine: the reference system, or why it could
/// not be built.
#[derive(Clone, Debug)]
pub struct MachineModel {
    /// The reference system.
    pub reference: RefSystem,
    /// Why the start state could not be built, if it could not.
    pub setup: Option<String>,
}

/// The activation machine for `fstp_prop::check_machine`.
///
/// The model is the reference. The system under test is a [`System`] on
/// the chosen backend. Every postcondition is two-way: a command is
/// accepted exactly when the reference accepts it. A refusal for a failure
/// or an unacknowledged warning must name a check the reference report
/// shows with that severity. After every command the system's records
/// equal the reference's, and [`check_i66`] and [`check_i67`] hold over
/// them.
#[derive(Clone, Copy, Debug)]
pub struct ActivationMachine {
    /// The backend under test.
    pub backend: Backend,
    /// The focus.
    pub focus: Focus,
}

impl ActivationMachine {
    /// The start plan: the M-ACTIVATE plan without the seeded failure,
    /// so short sequences reach clean drafts. Random edits seed and fix
    /// `FieldUnset` again.
    fn plan(&self) -> DraftPlan {
        let sybil = self.focus == Focus::Sybil;
        let mut plan = model_plan(ActivateConfig { sybil });
        plan.seeds.remove(&RefCheck::FieldUnset);
        plan
    }
}

fn pick_account(g: &mut Gen, accounts: &[AccountId]) -> AccountId {
    *g.pick(accounts)
}

fn pick_base(g: &mut Gen) -> Base {
    if g.weighted(&[9, 1]) == 0 {
        Base::Head
    } else {
        Base::Previous
    }
}

impl StateMachine for ActivationMachine {
    type Model = MachineModel;
    type Sut = Result<System, String>;
    type Command = RefCommand;
    type Output = Result<StepVerdict, String>;

    fn init_model(&self) -> MachineModel {
        match RefSystem::open(&self.plan()) {
            Ok(reference) => MachineModel {
                reference,
                setup: None,
            },
            Err((cmd, r)) => {
                let plan = self.plan();
                MachineModel {
                    reference: RefSystem::empty(plan.stat, plan.env),
                    setup: Some(format!("the reference refused {cmd:?} with {r:?}")),
                }
            }
        }
    }

    fn init_sut(&self) -> Result<System, String> {
        System::open(self.backend, &self.plan())
    }

    fn command(&self, g: &mut Gen, _model: &MachineModel) -> RefCommand {
        let everyone = [TA, TB, M1, M2];
        // Builders: mostly the managers, so clean states arise, and now
        // and then an admin. The reference refuses an admin's field edit
        // and admits an admin's invitation (reading R9).
        let editors: &[AccountId] = match self.focus {
            Focus::Builders => &[M1, M1, M1, M2, TA, TB],
            _ => &[M1, M2],
        };
        // Builders: every cast member approves equally often, so builder
        // approvals of clean drafts are tried.
        let approver_weights: [u32; 2] = match self.focus {
            Focus::Builders => [1, 3],
            _ => [3, 1],
        };
        let weights: [u32; 8] = match self.focus {
            // grant, edit, ack, request, approve, probe, imports, end
            Focus::Acknowledgement => [1, 3, 4, 3, 5, 1, 1, 1],
            Focus::EditAfterReport => [0, 5, 4, 4, 5, 1, 0, 1],
            Focus::Builders => [3, 4, 3, 3, 4, 1, 0, 1],
            Focus::Sybil => [1, 3, 2, 3, 5, 0, 0, 0],
        };
        match g.weighted(&weights) {
            0 => RefCommand::Grant {
                by: pick_account(g, &[TA, TB]),
                to: pick_account(g, &[M1, M2]),
            },
            1 => {
                let effect = match g.weighted(&[3, 1, 3]) {
                    0 => RefEdit::Fix(RefCheck::FieldUnset),
                    1 => RefEdit::Seed(RefCheck::FieldUnset),
                    _ => RefEdit::Neutral,
                };
                let kind = *g.pick(&[
                    EditKind::Policy,
                    EditKind::Artefact,
                    EditKind::Start,
                    EditKind::Narrative,
                    EditKind::Invitation,
                    EditKind::InvitationWithdrawal,
                    EditKind::ImportResolution,
                ]);
                RefCommand::Edit {
                    by: pick_account(g, editors),
                    kind,
                    effect,
                    base: pick_base(g),
                }
            }
            2 => RefCommand::Acknowledge {
                by: pick_account(g, &[M1, M1, M2, TA, TB]),
                warning: *g.pick(&[
                    RefCheck::RosterShort,
                    RefCheck::RosterShort,
                    RefCheck::RosterShort,
                    RefCheck::RosterShort,
                    RefCheck::InferenceUnreachable,
                    RefCheck::FieldUnset,
                ]),
                base: pick_base(g),
            },
            3 => RefCommand::Request {
                by: pick_account(g, &everyone),
                base: pick_base(g),
            },
            4 => RefCommand::Approve {
                by: if g.weighted(&approver_weights) == 0 {
                    TB
                } else {
                    pick_account(g, &everyone)
                },
                base: pick_base(g),
            },
            5 => RefCommand::SetProbe {
                probe: *g.pick(&RefProbe::ALL),
                outcome: *g.pick(&[
                    RefProbeOutcome::Pass,
                    RefProbeOutcome::Fail,
                    RefProbeOutcome::Absent,
                ]),
            },
            6 => RefCommand::SetUnresolvedImports(g.u32_in(0..=1)),
            _ => RefCommand::EndBinding {
                by: pick_account(g, &[TA, TB, M1]),
                of: pick_account(g, &[M1, M2]),
            },
        }
    }

    fn run(
        &self,
        sut: &mut Result<System, String>,
        cmd: &RefCommand,
    ) -> Result<StepVerdict, String> {
        match sut {
            Ok(s) => s.apply(cmd),
            Err(e) => Err(e.clone()),
        }
    }

    fn next_state(&self, model: &mut MachineModel, cmd: &RefCommand) {
        model.reference.apply(cmd);
    }

    fn postcondition(
        &self,
        model: &MachineModel,
        cmd: &RefCommand,
        out: &Result<StepVerdict, String>,
    ) -> Result<(), String> {
        let got = out.clone()?;
        let want = model.reference.decide(cmd);
        if got.accepted() != want.is_ok() {
            return Err(format!(
                "two-way: {cmd:?} gave {got:?}, the reference says {want:?}"
            ));
        }
        let shown = model.reference.report();
        match (got, want) {
            (StepVerdict::Refused(RefRefusal::Failed(c)), Err(RefRefusal::Failed(_))) => {
                if !(shown.contains_key(&c) && c.severity() == RefSeverity::Failure) {
                    return Err(format!(
                        "I-66: the refusal names {}, which the reference report does not show as a failure",
                        c.name()
                    ));
                }
            }
            (
                StepVerdict::Refused(RefRefusal::Unacknowledged(c)),
                Err(RefRefusal::Unacknowledged(_)),
            ) => {
                if !(shown.contains_key(&c) && !model.reference.draft.ack_live(c)) {
                    return Err(format!(
                        "I-66: the refusal names {}, which is not an unacknowledged warning",
                        c.name()
                    ));
                }
            }
            (
                StepVerdict::Refused(r),
                Err(w @ (RefRefusal::Failed(_) | RefRefusal::Unacknowledged(_))),
            ) => {
                return Err(format!(
                    "I-66: {cmd:?} was refused with {r:?}; the refusal must name the check, as {w:?} does"
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn invariant(&self, model: &MachineModel, sut: &Result<System, String>) -> Result<(), String> {
        if let Some(e) = &model.setup {
            return Err(e.clone());
        }
        let s = sut.as_ref().map_err(Clone::clone)?;
        let events = s.events()?;
        if events != model.reference.events {
            return Err(format!(
                "two-way: the records differ\n system: {events:?}\n reference: {:?}",
                model.reference.events
            ));
        }
        check_i66(&model.reference.stat, &events)?;
        check_i67(&model.reference.stat, &events)?;
        if !s.replay_matches()? {
            return Err("replay(ledger) differs from the state".to_owned());
        }
        Ok(())
    }

    fn max_commands(&self) -> usize {
        24
    }
}

// ---------------------------------------------------------------------------
// Helpers for the property tests
// ---------------------------------------------------------------------------

/// A draft plan with the cap `p05` against the ceiling `p58`, in minor
/// units, and nothing else seeded.
pub fn cap_plan(p05_minor: u64, p58_minor: u64) -> DraftPlan {
    let mut p = clean_plan();
    p.stat.cap.p05_minor = p05_minor;
    p.stat.cap.p58_minor = p58_minor;
    p
}

/// The two ADR-006 strings the R-PG-01 report row must name.
pub fn cap_strings(p05_minor: u64, p58_minor: u64) -> (String, String) {
    (adr006_eur(p05_minor), adr006_eur(p58_minor))
}

/// The approval environment of `plan` with `probe` at `outcome`.
pub fn env_with(plan: &DraftPlan, probe: RefProbe, outcome: RefProbeOutcome) -> RefInputs {
    plan.env.clone().with_probe(probe, outcome)
}

/// Every account of the cast.
pub fn cast() -> [AccountId; 4] {
    [TA, TB, M1, M2]
}

/// Whether `stub` is a W0 refusal message, so a test can say why it is red.
pub fn is_stub_refusal(message: &str) -> bool {
    message.contains("is not implemented yet")
}
