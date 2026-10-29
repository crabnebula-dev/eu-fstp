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
/// Wiring status: lane W2a landed the creator of M4 design section 3.2,
/// and [`catalogue`](production::catalogue) reads `fstp_creator::CHECKS`.
/// A production draft still needs the W0 stubs of `fstp-programme` (W1a),
/// the testkit profiles (W2c) and fakes (W3b), the engine compositions
/// (W2e), the core activation (W1b) and the registry (W3a), which refuse.
/// Each function below states the designed call. Where a stub exists, the
/// function calls it, so the refusal comes from the stub. Where the
/// designed item is not declared in any stub, the function returns a
/// [`NotImplemented`] that names the missing item and its lane. The lane
/// report lists each such gap.
pub mod production {
    use std::collections::BTreeSet;

    use fstp_domain::id::AccountId;
    use fstp_engine::EngineState;
    use fstp_ledger::Entry;

    use crate::NotImplemented;
    use crate::reference::creator::{
        DraftPlan, RefCommand, RefEvent, RefInputs, RefReport, RefSeverity, StepVerdict,
    };

    /// Missing: the creator command path. `fstp_creator::decide_creator`
    /// exists (lane W2a). It refuses `OpenDraft` until `fstp-programme`
    /// compiles the profile-default policy (lane W1a). Designed call:
    /// `fstp_engine::Engine::execute(Command::Creator(CreatorCommand::..))`,
    /// which runs `fstp_creator::decide_creator(core, creator, cmd, ctx,
    /// &CreatorInputs)` and decides its `core` commands in the same entry
    /// (design 3.2 and 3.4 D2e; lanes W2a and W2e).
    pub const GAP_CREATOR_PATH: NotImplemented = NotImplemented::new(
        "fstp_engine::Command::Creator with fstp_creator::decide_creator (design 3.2, D2e; lanes W2a, W2e)",
    );

    /// Missing: the mapping from creator and core records on a programme
    /// to reference events. Designed reads: `fstp_engine::Record::Creator(
    /// CreatorRecord::..)` and the core `GrantRole`, `EditPolicy` and
    /// `ProgrammeActivated` records (design 3.2, D2; lanes W2a, W1b).
    pub const GAP_RECORDS: NotImplemented = NotImplemented::new(
        "fstp_engine::Record::Creator(fstp_creator::CreatorRecord) and Record::ProgrammeActivated (design 3.2, D2; lanes W2a, W1b, W2e)",
    );

    /// Missing: a production draft to report on. `fstp_creator::validate(
    /// core, creator, programme, profile, &CreatorInputs)` and
    /// `ValidationReport::results` exist (lane W2a). The report needs the
    /// draft that [`ProductionSystem::open`] builds, and a funder profile
    /// from the synthetic profile source (lanes W1a, W2c).
    pub const GAP_REPORT: NotImplemented = NotImplemented::new(
        "a production draft and a fstp_guide::FunderProfile for fstp_creator::validate (design 3.1, 3.2, 3.10; lanes W1a, W2c)",
    );

    /// Missing: the core activation command. Designed item:
    /// `fstp_domain::Command::ActivateProgramme { programme, decision,
    /// report, revision, creator_builders }` with its core guard (D2;
    /// lane W1b).
    pub const GAP_CORE_ACTIVATE: NotImplemented = NotImplemented::new(
        "fstp_domain::Command::ActivateProgramme and its I-67 core guard (design 3.4 D2; lane W1b)",
    );

    /// Missing: the engine fold pairing and the refusal of an outside
    /// core activation (D2e; lane W2e), over `Record::ProgrammeActivated`
    /// (D2; lane W1b).
    pub const GAP_ENGINE_PAIRING: NotImplemented = NotImplemented::new(
        "fstp_engine fold pairing of ProgrammeActivated with Creator(ActivationApproved), and DomainDecider refusal with RuleRef::I66 (design 3.4 D2e; lanes W2e, W1b)",
    );

    /// Missing: the registry columns that name each route's command, and
    /// the `COMPOSED_ONLY` list (design 0.2 point 17, 3.6; lane W3a).
    pub const GAP_REGISTRY: NotImplemented = NotImplemented::new(
        "fstp_access::OpSpec { name, command } and COMPOSED_ONLY holding ActivateProgramme (design 0.2 point 17, 3.6; lane W3a)",
    );

    /// Missing: the live SoD preview and the audit sink of vault answers.
    /// Designed calls: `fstp_domain::roles::preview_grant(state, grant,
    /// ctx, answers)` (D3; lane W1b) for each target of
    /// `fstp_creator::preview_targets`, which lane W2a landed with
    /// `CreatorCommand::Invite`, with each answer audited as a query digest and a bit through
    /// `fstp_api_core::port::AuditEntry` (lane W3b).
    pub const GAP_PREVIEW_AUDIT: NotImplemented = NotImplemented::new(
        "fstp_domain::roles::preview_grant (D3; W1b) over fstp_creator::preview_targets with audited vault answers (QueryDigest and bit; W3b)",
    );

    /// One draft on production: the engine state and its ledger. The fake
    /// ports, the vault ground truth and the profile join it when the
    /// implementer wires [`ProductionSystem::open`].
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct ProductionSystem {
        state: EngineState,
        ledger: Vec<Entry<fstp_engine::Record>>,
    }

    impl ProductionSystem {
        /// Opens the draft of `plan` on production: A1 opens it with
        /// `OpenDraft` and core `CreateProgramme`, grants each manager with
        /// `GrantRole`, and the first manager saves the fields that seed
        /// each planned check. The synthetic legal-wording profile and the
        /// recording-fake prober supply the plan's wording and probe facts.
        ///
        /// Designed calls: `profiles::synthetic_profiles()` (lane W2c),
        /// `fake::fake_ports()` (lane W3b), then [`GAP_CREATOR_PATH`].
        pub fn open(plan: &DraftPlan) -> Result<ProductionSystem, NotImplemented> {
            let _ = plan;
            let profiles = crate::profiles::synthetic_profiles()?;
            let ports = crate::fake::fake_ports()?;
            let _ = (profiles, ports);
            Err(GAP_CREATOR_PATH)
        }

        /// The engine state.
        pub fn state(&self) -> &EngineState {
            &self.state
        }

        /// The ledger.
        pub fn ledger(&self) -> &[Entry<fstp_engine::Record>] {
            &self.ledger
        }

        /// Runs `cmd` through the engine and maps the outcome. Environment
        /// commands set the recording-fake prober or the import store.
        pub fn apply(&mut self, cmd: &RefCommand) -> Result<StepVerdict, NotImplemented> {
            let _ = cmd;
            Err(GAP_CREATOR_PATH)
        }

        /// The records on the draft, mapped from the raw ledger entries.
        pub fn events(&self) -> Result<Vec<RefEvent>, NotImplemented> {
            Err(GAP_RECORDS)
        }

        /// The validation report now, with fresh probes.
        pub fn report(&self) -> Result<RefReport, NotImplemented> {
            Err(GAP_REPORT)
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
        /// fold, as `harness::teeth::inject_entry` does in M2.
        pub fn inject_activation(
            &mut self,
            by: AccountId,
            revision: u32,
            inputs: &RefInputs,
        ) -> Result<(), NotImplemented> {
            let _ = (by, revision, inputs);
            Err(GAP_RECORDS)
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
    /// composition would.
    pub fn core_activate(
        plan: &DraftPlan,
        script: &[RefCommand],
        actor: AccountId,
        creator_builders: &BTreeSet<AccountId>,
    ) -> Result<StepVerdict, NotImplemented> {
        let _ = (plan, script, actor, creator_builders);
        Err(GAP_CORE_ACTIVATE)
    }

    /// What the engine fold does with an entry that holds a core
    /// `ProgrammeActivated` and no `Creator(ActivationApproved)` for the
    /// same programme, revision and report digest. `Ok(Err(reason))` means
    /// the fold refused it.
    pub fn fold_unpaired_activation(
        plan: &DraftPlan,
    ) -> Result<Result<(), String>, NotImplemented> {
        let _ = plan;
        Err(GAP_ENGINE_PAIRING)
    }

    /// What `Engine::execute` does with a core `ActivateProgramme` that
    /// arrives from outside, by `actor`. `Ok(Some(rule))` names the rule
    /// of the refusal, such as `"I66"`; `Ok(None)` means it was accepted.
    pub fn execute_core_activate(
        plan: &DraftPlan,
        actor: AccountId,
    ) -> Result<Option<String>, NotImplemented> {
        let _ = (plan, actor);
        Err(GAP_ENGINE_PAIRING)
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

    /// The registry as the I-66 route test reads it: every operation, and
    /// the `COMPOSED_ONLY` kinds by their debug names.
    pub fn registry() -> Result<(Vec<RegistryRow>, Vec<String>), NotImplemented> {
        if fstp_access::OPS.is_empty() {
            return Err(NotImplemented::new(
                "fstp_access::OPS (W0 stub: the registry is empty; lane W3a)",
            ));
        }
        Err(GAP_REGISTRY)
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
    pub fn preview_vault_trace(
        plan: &DraftPlan,
        invitees: &[AccountId],
    ) -> Result<(Vec<VaultAnswer>, Vec<VaultAnswer>), NotImplemented> {
        let _ = (plan, invitees);
        Err(GAP_PREVIEW_AUDIT)
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
