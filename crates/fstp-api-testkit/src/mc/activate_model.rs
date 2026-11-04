//! M-ACTIVATE, the I-66 and I-67 predicates, the activation machine and
//! the production adapter (M4 design sections 8.4 and 8.5). Lane W2a owns
//! this file.
//!
//! - [`production`] is the one place where the I-66 and I-67 suites call
//!   production code. Each function names the designed call it makes. The
//!   implementer wires it, and the test author reviews each call, as the
//!   M2 read adapters were handled. Every call runs the production engine
//!   (lane m4glue). A step the production API cannot take refuses with a
//!   named gap, and the run is red for that reason.
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
/// Wiring status (lane m4glue): every function runs the production
/// engine, `fstp_engine::Engine` with `CreatorDecider` over the cell's
/// creator environment (`fake/shell.rs`), on a draft cell rebuilt from
/// the draft's ledger (`fake/draft_cell.rs`). Each rebuild holds the
/// saved and imported values again, as the shell does after a replay.
///
/// - [`ProductionSystem`] opens the plan's draft with
///   `CreatorCommand::OpenDraft` through the engine and grants its
///   managers with core `GrantRole`. The first manager then completes the
///   draft in setup entries: one `SaveFields` of the synthetic SuperSAFE
///   spec under the plan's cap, and `Invite`s of a roster that meets
///   P-03, P-39 and P-15, with spare invitations. The setup entries are
///   no records of the reference vocabulary, so [`ProductionSystem::events`]
///   leaves them out and numbers the revisions after them from the
///   reference's count. The first manager then seeds each content check
///   of the plan with the one edit that triggers it ([`Seed`]).
/// - A content edit of the reference vocabulary runs the production
///   command of its kind with the edit's effect on `FieldUnset`: a policy
///   or artefact save, a blank start, an invitation or withdrawal of a
///   spare, or an import resolution confirmed as the draft holds it. A
///   step the production API cannot take refuses with the gap that names
///   why. The kind and effect of every edit the adapter issued are kept by
///   command id, since no record says what an edit does to the checks.
/// - [`execute_core_activate`], [`fold_unpaired_activation`] and
///   [`preview_vault_trace`] check a guard, the fold or the recording of
///   vault answers after the opening. They open the draft with the entry
///   a correct `OpenDraft` appends (`draft_cell::forged_open`), as the
///   engine's own M4 envelope tests do.
pub mod production {
    use std::collections::{BTreeMap, BTreeSet};

    use fstp_api_core::port::{ProbeKind as PortProbe, ProbeOutcome as PortOutcome};
    use fstp_creator::{
        CheckDetail, CheckId, CreatorCommand, CreatorRecord, InvitationId, Invitee,
        MandatoryElement, PortPresence, ProbeKind, ProbeOutcome, StartingPoint, TextRole, Theme,
        ThemeMode, ValueDigest,
    };
    use fstp_domain::command::{Actor, Ctx};
    use fstp_domain::id::{
        AccountId, BindingId, ClassId, ContentDigest, DecisionId, OrganisationId, PolicyVersionId,
        ProgrammeId, TextId, TextRef,
    };
    use fstp_domain::oracle::{Answer, Answers, Query};
    use fstp_domain::refusal::{RefusalDetail, RefusalReason, RuleRef};
    use fstp_domain::roles::{BindingStatus, Role};
    use fstp_domain::time::Timestamp;
    use fstp_domain_testkit::vault::GroundTruth;
    use fstp_engine::{Command, EngineState, Record};
    use fstp_json::{FromJson, ToJson, Value};
    use fstp_ledger::{Entry, MemStore, RecordStore};
    use fstp_programme::{FIELDS, FieldId, FieldKind, FieldValue, ProgrammeSpec};

    use crate::NotImplemented;
    use crate::fake::draft_cell::{self, DraftCell, DraftShell, VaultAccount};
    use crate::fake::vault::Q35Known;
    use crate::reference::creator::{
        Base, CheckFeed, DraftPlan, EditKind, M1, M2, RefCheck, RefCommand, RefDetail, RefEdit,
        RefEvent, RefInputs, RefProbe, RefProbeOutcome, RefRefusal, RefReport, RefSeverity, SYBIL,
        StepVerdict, TA, TB,
    };

    /// Retired: no step returns it. A theme fault is seeded through the
    /// cell's environment, which supplies the theme as it supplies the
    /// probes (design 3.2 `CreatorInputs::theme`, see [`theme_of`]). The
    /// constant stays so a test can check that no theme seed is refused.
    pub const GAP_THEME: NotImplemented = NotImplemented::new(
        "a theme fault: retired, theme faults are seeded through the cell environment (design 3.2 and 8.4)",
    );

    /// Seeding `PolicyInvalid`: every policy save composes a core
    /// `EditPolicy`, which `fstp_domain::policy::validate` decides, so the
    /// head policy of a draft is never invalid.
    pub const GAP_POLICY_INVALID: NotImplemented = NotImplemented::new(
        "seeding PolicyInvalid: the core EditPolicy of every policy save refuses what fstp_domain::policy::validate refuses (design 3.2), so no draft policy is invalid",
    );

    /// Seeding `GuideSectionMissing`: the check reads the profile's Guide
    /// template (`fstp_guide::missing_sections`), which no draft edit
    /// changes.
    pub const GAP_GUIDE_SECTION: NotImplemented = NotImplemented::new(
        "seeding GuideSectionMissing: fstp_guide::missing_sections reads the funder profile's Guide template, which no draft edit changes",
    );

    /// Seeding `PrecheckUnavailable` together with `GuideBindingUnresolved`.
    /// A plan that seeds `PrecheckUnavailable` runs in a cell with no
    /// pre-check port, where the setup saves P-23 disabled and the seed
    /// enables it (Q38). The `GuideBindingUnresolved` seed disables P-23,
    /// which clears `PrecheckUnavailable`, so no draft shows both.
    pub const GAP_PRECHECK: NotImplemented = NotImplemented::new(
        "seeding PrecheckUnavailable together with GuideBindingUnresolved: the check needs P-23 enabled without a pre-check port, and the GuideBindingUnresolved seed disables P-23, so no production draft shows both",
    );

    /// P-23 disabled, the value the `GuideBindingUnresolved` seed saves,
    /// and the setup's P-23 when the plan seeds `PrecheckUnavailable`.
    const P23_DISABLED: &str = r#"{"account_cap_across_drafts_in_call":true,"enabled":false,"per_call_per_proposal":5,"per_day_per_proposal":1}"#;

    /// An edit that seeds `FieldUnset` without a start.
    pub const GAP_UNSET: NotImplemented = NotImplemented::new(
        "an edit of kind Policy, Artefact, Narrative, Invitation, InvitationWithdrawal or ImportResolution that seeds FieldUnset: no SaveFields, AcceptNarrative, Invite, WithdrawInvitation or ResolveImport removes a value; only ApplyStart does",
    );

    /// A start that leaves every field set.
    pub const GAP_START: NotImplemented = NotImplemented::new(
        "a start that leaves no field unset: every ApplyStart replaces the draft content (StartApplied clears the saved fields and narratives), so no start is neutral on a complete draft or fixes FieldUnset",
    );

    /// A narrative acceptance.
    pub const GAP_NARRATIVE: NotImplemented = NotImplemented::new(
        "an AcceptNarrative edit: only a template start leaves a narrative to accept, and the narrative is an unset field until it is accepted (TH-49), so no acceptance applies to a draft that a save completed",
    );

    /// A fix of `FieldUnset` that the edit's kind cannot make.
    pub const GAP_FIX: NotImplemented = NotImplemented::new(
        "a fix of FieldUnset by an edit that cannot set every unset field: an artefact-only save sets no policy field, an invitation or a withdrawal sets none, and one import resolution sets one importable field",
    );

    /// An effect on a content check other than `FieldUnset`.
    pub const GAP_EFFECT: NotImplemented = NotImplemented::new(
        "an edit that seeds or fixes a content check other than FieldUnset after the opening: the adapter realises those checks as opening seeds only",
    );

    /// Fewer unresolved imports needs a dismissal, which is a record on the
    /// draft. The reference changes the count as the environment only.
    pub const GAP_FEWER_IMPORTS: NotImplemented = NotImplemented::new(
        "fewer unresolved imports than recorded: a dismissal is a record on the draft, not an environment change (design 3.3)",
    );

    /// A production step that failed for a reason outside the model.
    pub const GAP_STEP: NotImplemented = NotImplemented::new(
        "a production step failed outside the model's refusals (see the adapter's mapping)",
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

    /// The draft programme of every production run.
    pub const PLAN_P: ProgrammeId = ProgrammeId::from_raw(0x4d41_0001);

    /// The instant of the first entry of a run. Each step is one second
    /// later than the one before.
    const T0: i64 = 1_000_000;

    /// The first account of the synthetic roster: committee members, IRC
    /// members, the chair, the coordinator and the spares. None of them
    /// acts. Each is a verified person of its own.
    const ROSTER: u128 = 0x4d41_e000;

    /// The number of roster accounts the vault knows.
    const ROSTER_ACCOUNTS: u128 = 128;

    /// The first invitation id of a production run.
    const INVITATIONS: u128 = 0x4d41_1100;

    /// The spare invitations of the setup, which a neutral withdrawal
    /// withdraws.
    const SPARES: u128 = 4;

    /// The first import document id of an import resolution edit.
    const DOCUMENTS: u128 = 0x4d41_d100;

    /// The P-04 range of the SuperSAFE fixture, in EUR minor units.
    const FIXTURE_P04_MAX: u64 = 10_000_000;
    const FIXTURE_P04_MIN: u64 = 500_000;

    /// A roster account.
    fn roster(i: u128) -> AccountId {
        AccountId::from_raw(ROSTER.saturating_add(i))
    }

    /// The accounts of the cast and the roster, each with its person and
    /// verification.
    fn vault_accounts(plan: &DraftPlan) -> Vec<VaultAccount> {
        let mut out: Vec<VaultAccount> = [TA, TB, M1, M2, SYBIL]
            .into_iter()
            .map(|a| VaultAccount {
                account: a,
                person: plan.stat.vault.person(a).map(u64::from),
                verified: plan.stat.vault.is_verified(a),
            })
            .collect();
        for i in 0..ROSTER_ACCOUNTS {
            let person = u64::try_from(i).unwrap_or(0).saturating_add(10_000);
            out.push(VaultAccount {
                account: roster(i),
                person: Some(person),
                verified: true,
            });
        }
        out
    }

    /// The shell facts of the plan's cell: the plan's wording status and
    /// theme, score tools, so that P-77 can seed its check, and a vault
    /// that knows the fixture's P-13 classes and no P-38 declaration. The
    /// cell has a pre-check provider unless the plan seeds
    /// `PrecheckUnavailable`, which the M4 cells without a `Precheck` port
    /// show once P-23 is enabled (design 3.10, Q38).
    fn shell_of(plan: &DraftPlan) -> DraftShell {
        DraftShell {
            shipped: plan.stat.wording_pending,
            theme: theme_of(plan),
            ports: PortPresence {
                precheck: !plan.seeds.contains(&RefCheck::PrecheckUnavailable),
                score_tools: true,
            },
            q35: Some(Q35Known {
                classes: [ClassId::from_raw(1), ClassId::from_raw(2)]
                    .into_iter()
                    .collect(),
                declared: BTreeSet::new(),
            }),
        }
    }

    /// An EUR amount in minor units as its JSON string, such as
    /// `"400000.00"`.
    fn eur(minor: u64) -> String {
        let units = minor.checked_div(100).unwrap_or(0);
        let cents = minor.checked_rem(100).unwrap_or(0);
        format!("\"{units}.{cents:02}\"")
    }

    /// The value of `field` decoded from `json` by its strict decoder.
    fn value(field: FieldId, json: &str) -> Result<FieldValue, NotImplemented> {
        fstp_programme::decode_field_value(field, json.as_bytes()).map_err(|_| GAP_STEP)
    }

    /// The clean spec of `plan`: the synthetic SuperSAFE spec with the
    /// plan's P-05 and P-58, and the P-04 range within P-05, so it shows
    /// no P-04 warning.
    fn clean_target(plan: &DraftPlan) -> Result<ProgrammeSpec, NotImplemented> {
        let mut spec = draft_cell::synthetic_spec().map_err(|_| GAP_STEP)?;
        let p05 = plan.stat.cap.p05_minor;
        spec.set(value(FieldId::P05, &eur(p05))?);
        spec.set(value(FieldId::P58, &eur(plan.stat.cap.p58_minor))?);
        let max = p05.min(FIXTURE_P04_MAX);
        let min = max.min(FIXTURE_P04_MIN);
        let p04 = format!("{{\"max\":{},\"min\":{}}}", eur(max), eur(min));
        spec.set(value(FieldId::P04, &p04)?);
        Ok(spec)
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
    fn ref_check(c: CheckId) -> Option<RefCheck> {
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

    /// What an entry the adapter appended is, for [`ProductionSystem::events`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Tag {
        /// A setup entry, which is no record of the reference vocabulary.
        Setup,
        /// An edit of the reference vocabulary, with its kind and effect.
        Edit(EditKind, RefEdit),
        /// Any other command, mapped from its records.
        Plain,
    }

    /// The production command of one content edit.
    enum Step {
        /// `SaveFields` of these values.
        Save(Vec<FieldValue>),
        /// `ApplyStart` of a blank start.
        Blank,
        /// `Invite` of a roster account, or of a contact when `None`.
        Invite {
            role: Role,
            account: Option<AccountId>,
            organisation: Option<OrganisationId>,
        },
        /// `WithdrawInvitation`.
        Withdraw(InvitationId),
        /// An import resolution that confirms this value.
        Import(FieldValue),
    }

    /// One draft on production: its ledger, its vault facts, its
    /// environment and what the adapter issued. Each step rebuilds the
    /// engine from the ledger, so the state compares and hashes. Equality
    /// and the hash leave out the store and the engine state, which are
    /// the ledger and its replay (`replay_matches` checks the replay).
    #[derive(Clone, Debug)]
    pub struct ProductionSystem {
        plan: DraftPlan,
        truth: GroundTruth,
        shell: DraftShell,
        store: MemStore<Record>,
        state: EngineState,
        ledger: Vec<Entry<Record>>,
        probes: BTreeMap<RefProbe, RefProbeOutcome>,
        /// The number of the next command, which also sets its instant.
        n: u32,
        /// The spec the draft holds when complete: the clean spec with
        /// every seed's value. A fix saves the unset fields from it.
        target: ProgrammeSpec,
        /// Every saved value, by field and digest, held again on each
        /// rebuild.
        values: BTreeMap<(FieldId, ValueDigest), FieldValue>,
        /// The value text and canonical JSON of each proposal the adapter
        /// recorded for an import resolution, held again on each rebuild.
        imports: BTreeMap<fstp_import::ValueTextRef, String>,
        /// The command ids of the setup entries.
        setup: BTreeSet<[u8; 16]>,
        /// The kind and effect of each edit the adapter issued.
        edits: BTreeMap<[u8; 16], (EditKind, RefEdit)>,
        /// The live spare invitations, latest last.
        spares: Vec<InvitationId>,
        /// The chair's invitation, which the `RosterShort` seed withdraws.
        chair: Option<InvitationId>,
        /// The number of the next invitation, roster account and document.
        next: u128,
    }

    impl ProductionSystem {
        /// What equality and the hash read (see [`ProductionSystem`]).
        #[allow(clippy::type_complexity)]
        fn key(
            &self,
        ) -> (
            &DraftPlan,
            &[Entry<Record>],
            &BTreeMap<RefProbe, RefProbeOutcome>,
            u32,
            &ProgrammeSpec,
            &BTreeMap<(FieldId, ValueDigest), FieldValue>,
            &BTreeMap<fstp_import::ValueTextRef, String>,
            &BTreeSet<[u8; 16]>,
            &BTreeMap<[u8; 16], (EditKind, RefEdit)>,
            &[InvitationId],
            (Option<InvitationId>, u128),
        ) {
            (
                &self.plan,
                &self.ledger,
                &self.probes,
                self.n,
                &self.target,
                &self.values,
                &self.imports,
                &self.setup,
                &self.edits,
                &self.spares,
                (self.chair, self.next),
            )
        }
    }

    impl PartialEq for ProductionSystem {
        fn eq(&self, other: &ProductionSystem) -> bool {
            self.key() == other.key()
        }
    }

    impl Eq for ProductionSystem {}

    impl std::hash::Hash for ProductionSystem {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.key().hash(state);
        }
    }

    /// What one engine run gave, in the reference vocabulary's terms.
    enum Run {
        /// The command appended.
        Appended,
        /// The engine refused it with this rule and reason, and the values
        /// the refusal names, if any.
        Refused(RuleRef, RefusalReason, Option<RefusalDetail>),
    }

    impl ProductionSystem {
        /// Opens the draft of `plan` on production (module documentation):
        /// `OpenDraft` by the opener, `GrantRole` of each manager by the
        /// opener, the first manager's setup, the plan's seeds and the
        /// plan's environment.
        pub fn open(plan: &DraftPlan) -> Result<ProductionSystem, NotImplemented> {
            let (mut s, builder) = ProductionSystem::begin(plan)?;
            s.complete(builder)?;
            for c in &plan.seeds {
                s.seed(builder, *c)?;
            }
            s.set_unresolved(plan.env.unresolved_imports)?;
            Ok(s)
        }

        /// The setup save of `plan`'s P-05 and P-58 (I-50 at save,
        /// Daniel's answer of 2026-10-31, M4 design section 15.0): `None`
        /// when the engine accepts it, or the two values the creator's
        /// `CapAboveCeiling` refusal names, as ADR-006 strings, when the
        /// engine refuses it with I-50 and appends nothing. The values are
        /// read from the engine's own refusal, which every caller of the
        /// engine, the API included, receives.
        pub fn cap_setup(plan: &DraftPlan) -> Result<Option<(String, String)>, NotImplemented> {
            let (mut s, builder) = ProductionSystem::begin(plan)?;
            let base = s.head().ok_or(GAP_STEP)?;
            let fields: Vec<fstp_creator::FieldEdit> = s
                .setup_values()?
                .into_iter()
                .map(draft_cell::manual_edit)
                .collect();
            let cmd = CreatorCommand::SaveFields {
                programme: PLAN_P,
                base,
                fields,
            };
            let ctx = s.ctx(builder);
            let before = s.ledger.len();
            match s.run_ctx(Command::Creator(cmd), ctx, Tag::Setup)? {
                Run::Appended => Ok(None),
                Run::Refused(
                    RuleRef::I50,
                    _,
                    Some(RefusalDetail::CapAboveCeiling { p05, p58 }),
                ) if s.ledger.len() == before => {
                    Ok(Some((p05.amount().to_string(), p58.amount().to_string())))
                }
                _ => Err(GAP_STEP),
            }
        }

        /// Opens the draft of `plan` and grants its managers: the part of
        /// [`ProductionSystem::open`] before the first manager's setup,
        /// with that manager.
        fn begin(plan: &DraftPlan) -> Result<(ProductionSystem, AccountId), NotImplemented> {
            let target = clean_target(plan)?;
            let mut s = ProductionSystem {
                plan: plan.clone(),
                truth: draft_cell::truth_of(&vault_accounts(plan)),
                shell: shell_of(plan),
                store: MemStore::new(),
                state: EngineState::genesis(),
                ledger: Vec::new(),
                probes: plan.env.probes.clone(),
                n: 1,
                target,
                values: BTreeMap::new(),
                imports: BTreeMap::new(),
                setup: BTreeSet::new(),
                edits: BTreeMap::new(),
                spares: Vec::new(),
                chair: None,
                next: 0,
            };
            let open = CreatorCommand::OpenDraft {
                programme: PLAN_P,
                version: PolicyVersionId::from_raw(PLAN_P.raw()),
                profile: default_profile()?,
            };
            if !matches!(
                s.run(Command::Creator(open), plan.opener, Tag::Plain)?,
                Run::Appended
            ) {
                return Err(GAP_STEP);
            }
            for m in &plan.managers {
                if !matches!(s.grant(plan.opener, *m)?, StepVerdict::Accepted) {
                    return Err(GAP_STEP);
                }
            }
            let builder = plan.managers.first().copied().ok_or(GAP_STEP)?;
            Ok((s, builder))
        }

        /// The setup of `builder` (module documentation): one save of the
        /// clean spec, then the roster and the spare invitations.
        fn complete(&mut self, builder: AccountId) -> Result<(), NotImplemented> {
            let all = self.setup_values()?;
            let base = self.head().ok_or(GAP_STEP)?;
            if !matches!(self.save(builder, base, all, Tag::Setup)?, Run::Appended) {
                return Err(GAP_STEP);
            }
            // P-03 and P-39 are 2 and P-15 is 2 in the fixture. Three
            // committee members of three organisations leave room for the
            // P39AboveP03 seed.
            let mut roster: Vec<(Role, Option<OrganisationId>)> = (1..=3u128)
                .map(|o| {
                    (
                        Role::CommitteeMember,
                        Some(OrganisationId::from_raw(0x4d41_0f00u128.saturating_add(o))),
                    )
                })
                .collect();
            roster.extend([
                (Role::IrcMember, None),
                (Role::IrcMember, None),
                (Role::CommitteeChair, None),
                (Role::FstpCoordinator, None),
            ]);
            for (role, organisation) in roster {
                let account = self.fresh_account();
                let step = Step::Invite {
                    role,
                    account: Some(account),
                    organisation,
                };
                let id = self.peek_invitation();
                if !matches!(
                    self.step(builder, Base::Head, step, Tag::Setup)?,
                    Run::Appended
                ) {
                    return Err(GAP_STEP);
                }
                if role == Role::CommitteeChair {
                    self.chair = Some(id);
                }
            }
            for _ in 0..SPARES {
                self.invite_spare(builder, Tag::Setup)?;
            }
            Ok(())
        }

        /// The values of the first manager's setup save: every field of
        /// the clean target but P-53, with P-23 disabled when the plan
        /// seeds `PrecheckUnavailable`.
        fn setup_values(&self) -> Result<Vec<FieldValue>, NotImplemented> {
            let mut all: Vec<FieldValue> = FIELDS
                .iter()
                .filter(|f| f.id != FieldId::P53)
                .filter_map(|f| self.target.get(f.id).as_set().cloned())
                .collect();
            // Without a pre-check port the setup saves P-23 disabled, so
            // the `PrecheckUnavailable` seed is the edit that enables it.
            if self.plan.seeds.contains(&RefCheck::PrecheckUnavailable) {
                let disabled = value(FieldId::P23, P23_DISABLED)?;
                for v in &mut all {
                    if v.field() == FieldId::P23 {
                        *v = disabled.clone();
                    }
                }
            }
            Ok(all)
        }

        /// Seeds `check` by `builder` with the one edit that triggers it,
        /// recorded as the reference's seeding edit, and checks that the
        /// report then shows it.
        fn seed(&mut self, builder: AccountId, check: RefCheck) -> Result<(), NotImplemented> {
            let save = |field: FieldId, json: &str| value(field, json).map(|v| Step::Save(vec![v]));
            let step = match check {
                RefCheck::PolicyInvalid => return Err(GAP_POLICY_INVALID),
                RefCheck::GuideSectionMissing => return Err(GAP_GUIDE_SECTION),
                // Q38: P-23 enabled in a cell without a pre-check port.
                RefCheck::PrecheckUnavailable => {
                    if self.plan.seeds.contains(&RefCheck::GuideBindingUnresolved) {
                        return Err(GAP_PRECHECK);
                    }
                    let enabled = clean_target(&self.plan)?
                        .get(FieldId::P23)
                        .as_set()
                        .cloned()
                        .ok_or(GAP_STEP)?;
                    Step::Save(vec![enabled])
                }
                RefCheck::FieldUnset => Step::Blank,
                RefCheck::P04MaxAboveP05 => {
                    let max = self.plan.stat.cap.p05_minor.saturating_add(1);
                    let p04 = format!("{{\"max\":{},\"min\":{}}}", eur(max), eur(0));
                    save(FieldId::P04, &p04)?
                }
                RefCheck::P39AboveP03 => save(FieldId::P39, "3")?,
                RefCheck::ActionDatesInconsistent => {
                    save(FieldId::P57, r#"{"end":"2025-12-31","start":"2026-01-01"}"#)?
                }
                RefCheck::CallPackageIncomplete => save(FieldId::P55, "[]")?,
                RefCheck::GuideBindingUnresolved => {
                    if self.plan.seeds.contains(&RefCheck::PrecheckUnavailable) {
                        return Err(GAP_PRECHECK);
                    }
                    save(FieldId::P23, P23_DISABLED)?
                }
                RefCheck::FlowDownMissing => {
                    save(FieldId::FlowDown, r#"["conflict_of_interests"]"#)?
                }
                // SoD-01: a programme manager on the draft never sits on its
                // committee.
                RefCheck::InviteeRefused => Step::Invite {
                    role: Role::CommitteeMember,
                    account: Some(builder),
                    organisation: Some(OrganisationId::from_raw(0x4d41_0f09)),
                },
                RefCheck::InviteeWithoutAccount => Step::Invite {
                    role: Role::IrcMember,
                    account: None,
                    organisation: None,
                },
                RefCheck::RosterShort => Step::Withdraw(self.chair.ok_or(GAP_STEP)?),
                RefCheck::ExclusionClassUnknown => save(
                    FieldId::P13,
                    r#"[{"description":"Synthetic class the vault does not know","id":"9"}]"#,
                )?,
                RefCheck::ProximityListMissing => {
                    save(FieldId::P38, r#"[{"list":"1","organisation":"5"}]"#)?
                }
                RefCheck::AiActReassessment => save(FieldId::P77, r#""allowed""#)?,
                _ => return Err(GAP_STEP),
            };
            if matches!(check, RefCheck::RosterShort) {
                self.chair = None;
            }
            let tag = Tag::Edit(EditKind::Policy, RefEdit::Seed(check));
            if !matches!(self.step(builder, Base::Head, step, tag)?, Run::Appended) {
                return Err(GAP_STEP);
            }
            if !self.report()?.contains_key(&check) {
                return Err(GAP_STEP);
            }
            Ok(())
        }

        /// The engine state.
        pub fn state(&self) -> &EngineState {
            &self.state
        }

        /// The ledger.
        pub fn ledger(&self) -> &[Entry<fstp_engine::Record>] {
            &self.ledger
        }

        /// The draft cell over the ledger now, with every saved and
        /// imported value held again.
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
            let mut cell = DraftCell::open_with_shell(
                self.store.clone(),
                self.truth.clone(),
                self.plan.stat.admins.clone(),
                &probes,
                &self.shell,
            )
            .map_err(|_| GAP_STEP)?;
            for (text, json) in &self.imports {
                let v = fstp_json::parse(json.as_bytes()).map_err(|_| GAP_STEP)?;
                let value = fstp_import::UntrustedValue::new(&v).map_err(|_| GAP_STEP)?;
                cell.engine
                    .hold_import(*text, value)
                    .map_err(|_| GAP_STEP)?;
            }
            draft_cell::hold_saved(&mut cell, PLAN_P, &self.values);
            Ok(cell)
        }

        /// The instant of the next command.
        fn now(&self) -> Timestamp {
            Timestamp::from_micros(T0.saturating_add(i64::from(self.n).saturating_mul(1_000_000)))
        }

        /// The context of the next command by `actor`.
        fn ctx(&mut self, actor: AccountId) -> Ctx {
            let n = self.n;
            let now = self.now();
            self.n = n.saturating_add(1);
            draft_cell::ctx(actor, now, n, &self.plan.stat.admins)
        }

        /// Runs `cmd` by `actor` through the engine, and keeps the ledger.
        fn run(&mut self, cmd: Command, actor: AccountId, tag: Tag) -> Result<Run, NotImplemented> {
            let ctx = self.ctx(actor);
            self.run_ctx(cmd, ctx, tag)
        }

        /// Runs `cmd` with `ctx` through the engine, and keeps the ledger
        /// and what the entry is.
        fn run_ctx(&mut self, cmd: Command, ctx: Ctx, tag: Tag) -> Result<Run, NotImplemented> {
            let mut cell = self.cell()?;
            let id = ctx.command.bytes();
            let out = match cell.execute(cmd, ctx) {
                Ok(_) => Run::Appended,
                Err(fstp_engine::ExecError::Refused(r)) => Run::Refused(r.rule, r.reason, r.detail),
                Err(_) => return Err(GAP_STEP),
            };
            if matches!(out, Run::Appended) {
                match tag {
                    Tag::Setup => {
                        let _ = self.setup.insert(id);
                    }
                    Tag::Edit(kind, effect) => {
                        let _ = self.edits.insert(id, (kind, effect));
                    }
                    Tag::Plain => {}
                }
            }
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

        /// `SaveFields` of `values` at `base` by `by`. The values of an
        /// appended save are kept for the rebuilds.
        fn save(
            &mut self,
            by: AccountId,
            base: fstp_creator::DraftRevision,
            values: Vec<FieldValue>,
            tag: Tag,
        ) -> Result<Run, NotImplemented> {
            let fields: Vec<fstp_creator::FieldEdit> =
                values.into_iter().map(draft_cell::manual_edit).collect();
            let kept: Vec<((FieldId, ValueDigest), FieldValue)> = fields
                .iter()
                .map(|e| ((e.field, e.digest), e.value.clone()))
                .collect();
            let cmd = CreatorCommand::SaveFields {
                programme: PLAN_P,
                base,
                fields,
            };
            let out = self.run(Command::Creator(cmd), by, tag)?;
            if matches!(out, Run::Appended) {
                for (k, v) in kept {
                    self.target.set(v.clone());
                    let _ = self.values.insert(k, v);
                }
            }
            Ok(out)
        }

        /// A roster account no invitation names yet.
        fn fresh_account(&mut self) -> AccountId {
            let a = roster(self.next.checked_rem(ROSTER_ACCOUNTS).unwrap_or(0));
            self.next = self.next.saturating_add(1);
            a
        }

        /// The id the next invitation takes.
        fn peek_invitation(&self) -> InvitationId {
            InvitationId::from_raw(INVITATIONS.saturating_add(u128::from(self.n)))
        }

        /// Invites a spare IRC member by `by`, and keeps it as a spare.
        fn invite_spare(&mut self, by: AccountId, tag: Tag) -> Result<Run, NotImplemented> {
            let account = self.fresh_account();
            let id = self.peek_invitation();
            let step = Step::Invite {
                role: Role::IrcMember,
                account: Some(account),
                organisation: None,
            };
            let out = self.step(by, Base::Head, step, tag)?;
            if matches!(out, Run::Appended) {
                self.spares.push(id);
            }
            Ok(out)
        }

        /// Runs the production command of `step` by `by` at `base`.
        fn step(
            &mut self,
            by: AccountId,
            base: Base,
            step: Step,
            tag: Tag,
        ) -> Result<Run, NotImplemented> {
            let Some(revision) = self.named(base) else {
                return Err(GAP_STEP);
            };
            match step {
                Step::Save(values) => self.save(by, revision, values, tag),
                Step::Blank => {
                    let profile = self
                        .state
                        .creator
                        .draft(PLAN_P)
                        .map(|d| d.profile().clone())
                        .ok_or(GAP_STEP)?;
                    let start = CreatorCommand::ApplyStart {
                        programme: PLAN_P,
                        base: revision,
                        start: StartingPoint::Blank { profile },
                    };
                    self.run(Command::Creator(start), by, tag)
                }
                Step::Invite {
                    role,
                    account,
                    organisation,
                } => {
                    let invitation = self.peek_invitation();
                    let invitee = match account {
                        Some(a) => Invitee::Account(a),
                        None => Invitee::Pending {
                            contact: TextRef::new(
                                TextId::from_raw(invitation.raw()),
                                ContentDigest::from_bytes([0x4c; 32]),
                            ),
                        },
                    };
                    let invite = CreatorCommand::Invite {
                        programme: PLAN_P,
                        invitation,
                        role,
                        invitee,
                        organisation,
                    };
                    self.run(Command::Creator(invite), by, tag)
                }
                Step::Withdraw(invitation) => {
                    let withdraw = CreatorCommand::WithdrawInvitation {
                        programme: PLAN_P,
                        invitation,
                    };
                    self.run(Command::Creator(withdraw), by, tag)
                }
                Step::Import(v) => self.resolve(by, revision, v, tag),
            }
        }

        /// An import resolution by `by` at `revision` that confirms `v`:
        /// `RegisterDocument` by `by`, `RecordProposals` of one proposal of
        /// `v` as the system, and `ResolveImport` with its shown digest.
        /// The steps run on a copy, which replaces the system only when
        /// the resolution is appended, so a refused resolution leaves no
        /// unresolved proposal behind.
        fn resolve(
            &mut self,
            by: AccountId,
            revision: fstp_creator::DraftRevision,
            v: FieldValue,
            tag: Tag,
        ) -> Result<Run, NotImplemented> {
            let mut s = self.clone();
            let field = v.field();
            let json = fstp_programme::encode_field_value(&v);
            let data = fstp_json::parse(json.as_bytes()).map_err(|_| GAP_STEP)?;
            let untrusted = fstp_import::UntrustedValue::new(&data).map_err(|_| GAP_STEP)?;
            let k = DOCUMENTS.saturating_add(s.next);
            s.next = s.next.saturating_add(1);
            let document = fstp_import::ImportDocumentId::from_raw(k);
            let text = "SYNTHETIC IMPORT DOCUMENT.\n";
            let doc = fstp_import::ImportDocument {
                id: document,
                programme: fstp_import::ProgrammeRef::from_raw(PLAN_P.raw()),
                blob: fstp_import::BlobAddress::from_bytes([0x4d; 32]),
                media: fstp_import::ImportMedia::TextPlain,
                digest: fstp_import::TextDigest::from_bytes([0x4e; 32]),
                text_bytes: u32::try_from(text.len()).map_err(|_| GAP_STEP)?,
                uploaded_by: fstp_import::AccountRef::from_raw(by.raw()),
            };
            let reg = Command::Import(fstp_import::ImportCommand::RegisterDocument(doc));
            if let Run::Refused(rule, reason, detail) = s.run(reg, by, Tag::Plain)? {
                return Ok(Run::Refused(rule, reason, detail));
            }
            let proposal = fstp_import::ImportProposalId::from_raw(k);
            let mut salt = [0x52u8; 32];
            for (slot, x) in salt.iter_mut().zip(k.to_be_bytes()) {
                *slot = x;
            }
            let shown = fstp_import::SaltedDigest::from_bytes(salt);
            let value_text =
                fstp_import::ValueTextRef::new(fstp_import::ValueTextId::from_raw(k), shown);
            let record = fstp_import::ImportCommand::RecordProposals {
                document,
                proposals: vec![fstp_import::ImportProposal {
                    id: proposal,
                    document,
                    field,
                    value: untrusted.clone(),
                    text: value_text,
                    evidence: vec![fstp_import::Span { start: 0, end: 9 }],
                    config: fstp_import::ImportConfigId::from_raw(1),
                    conflicts_with_profile: Vec::new(),
                }],
            };
            let mut ctx = s.ctx(by);
            ctx.actor = Actor::System(fstp_domain::command::SystemCause::Timeline);
            ctx.tenant_admin = false;
            if !matches!(
                s.run_ctx(Command::Import(record), ctx, Tag::Plain)?,
                Run::Appended
            ) {
                return Err(GAP_STEP);
            }
            let _ = s.imports.insert(value_text, json);
            let digest = fstp_import::ValueDigest::from_bytes(fstp_crypto::sha256(
                untrusted.as_data().as_bytes(),
            ));
            let resolve = Command::Bridge(fstp_engine::BridgeCommand::ResolveImport {
                programme: PLAN_P,
                proposal,
                shown,
                resolution: fstp_import::ClientResolution::Confirm {
                    value: untrusted,
                    digest,
                },
                conflict_acknowledged: false,
                base: revision,
            });
            let out = s.run(resolve, by, tag)?;
            if matches!(out, Run::Appended) {
                s.target.set(v);
                *self = s;
            }
            Ok(out)
        }

        /// The draft's head revision now.
        fn head(&self) -> Option<fstp_creator::DraftRevision> {
            self.state.creator.head(PLAN_P)
        }

        /// The number of setup entries, which the reference revisions do
        /// not count.
        fn offset(&self) -> u32 {
            let mut seen = BTreeSet::new();
            for e in &self.ledger {
                if self.setup.contains(&e.command) {
                    let _ = seen.insert(e.command);
                }
            }
            u32::try_from(seen.len()).unwrap_or(u32::MAX)
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

        /// The fields the draft does not set (`FieldUnset`).
        fn unset(&self) -> BTreeSet<FieldId> {
            let set = self
                .state
                .creator
                .draft(PLAN_P)
                .map(|d| d.set_fields())
                .unwrap_or_default();
            FIELDS
                .iter()
                .map(|f| f.id)
                .filter(|f| !set.contains(f))
                .collect()
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
            Ok(match self.run_ctx(Command::Core(cmd), ctx, Tag::Plain)? {
                Run::Appended => StepVerdict::Accepted,
                Run::Refused(rule, reason, _) => {
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
                (RuleRef::I65, Why::BindingInactive) => RefRefusal::NotProgrammeManager,
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
        /// whole draft when the report shows no such row. A warning on the
        /// whole draft or on a probe names its subject without the report,
        /// so only an invitation's key reads it.
        fn warning_key(
            &self,
            warning: RefCheck,
        ) -> Result<fstp_creator::WarningKey, NotImplemented> {
            let check = CheckId::from_name(warning.name()).ok_or(GAP_STEP)?;
            let subject = match warning {
                RefCheck::InviteeWithoutAccount => None,
                RefCheck::InferenceUnreachable => {
                    Some(fstp_creator::CheckSubject::Probe(ProbeKind::Inference))
                }
                _ => Some(fstp_creator::CheckSubject::Draft),
            };
            if let Some(subject) = subject {
                return Ok(fstp_creator::WarningKey { check, subject });
            }
            let report = self.production_report(None)?;
            let row = report
                .results()
                .iter()
                .find(|r| ref_check(r.check) == Some(warning));
            Ok(match row {
                Some(r) => r.key(),
                None => fstp_creator::WarningKey {
                    check,
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
            if !matches!(self.run(reg, manager, Tag::Plain)?, Run::Appended) {
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
                    field: FieldId::ActionAcronym,
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
            match self.run_ctx(rec, ctx, Tag::Plain)? {
                Run::Appended => Ok(()),
                Run::Refused(..) => Err(GAP_STEP),
            }
        }

        /// The verdict of a run of a creator command.
        fn verdict(
            &self,
            r: Run,
            approver: Option<AccountId>,
        ) -> Result<StepVerdict, NotImplemented> {
            match r {
                Run::Appended => Ok(StepVerdict::Accepted),
                Run::Refused(rule, reason, _) => self
                    .creator_refusal(rule, reason, approver)
                    .map(StepVerdict::Refused),
            }
        }

        /// The refusal production gives a content edit by `by` at `base`
        /// that it cannot take, or `gap` when production would admit the
        /// edit's actor and revision. A save of the head's P-02 value, or
        /// for an invitation an invitation of a spare, runs on a copy and
        /// is dropped, so the refusal names the actor or the revision as
        /// the edit's own command would.
        fn refused_or(
            &self,
            by: AccountId,
            kind: EditKind,
            base: Base,
            gap: NotImplemented,
        ) -> Result<StepVerdict, NotImplemented> {
            let mut probe = self.clone();
            let run = match kind {
                EditKind::Invitation | EditKind::InvitationWithdrawal => {
                    probe.invite_spare(by, Tag::Plain)?
                }
                _ => {
                    let p02 = probe
                        .target
                        .get(FieldId::P02)
                        .as_set()
                        .cloned()
                        .ok_or(GAP_STEP)?;
                    probe.step(by, base, Step::Save(vec![p02]), Tag::Plain)?
                }
            };
            match run {
                Run::Appended => Err(gap),
                refused => self.verdict(refused, None),
            }
        }

        /// A content edit of `kind` with `effect` by `by` at `base`
        /// (module documentation). The effect is read against the draft's
        /// `FieldUnset` now: a seed of a check the draft shows, or a fix of
        /// one it does not, leaves it as it is.
        fn edit(
            &mut self,
            by: AccountId,
            kind: EditKind,
            effect: RefEdit,
            base: Base,
        ) -> Result<StepVerdict, NotImplemented> {
            if let RefEdit::Seed(c) | RefEdit::Fix(c) = effect {
                if c.feed() != CheckFeed::Content {
                    return Ok(StepVerdict::Refused(RefRefusal::NotContent));
                }
                if c != RefCheck::FieldUnset {
                    return self.refused_or(by, kind, base, GAP_EFFECT);
                }
            }
            let unset = self.unset();
            let present = !unset.is_empty();
            let seed = matches!(effect, RefEdit::Seed(_)) && !present;
            let fix = matches!(effect, RefEdit::Fix(_)) && present;
            let field = |s: &ProductionSystem, f: FieldId| {
                s.target.get(f).as_set().cloned().ok_or(GAP_STEP)
            };
            let step = match kind {
                EditKind::Policy | EditKind::Artefact if seed => {
                    return self.refused_or(by, kind, base, GAP_UNSET);
                }
                EditKind::Policy if fix => {
                    let mut values: Vec<FieldValue> = unset
                        .iter()
                        .filter(|f| **f != FieldId::P53)
                        .map(|f| field(self, *f))
                        .collect::<Result<_, _>>()?;
                    let policy = unset
                        .iter()
                        .any(|f| f.spec().is_some_and(|s| s.kind == FieldKind::Policy));
                    if !policy {
                        values.push(field(self, FieldId::P02)?);
                    }
                    Step::Save(values)
                }
                EditKind::Policy => Step::Save(vec![field(self, FieldId::P02)?]),
                EditKind::Artefact if fix => {
                    let artefact_only = unset
                        .iter()
                        .all(|f| f.spec().is_some_and(|s| s.kind == FieldKind::Artefact));
                    if !artefact_only {
                        return self.refused_or(by, kind, base, GAP_FIX);
                    }
                    Step::Save(
                        unset
                            .iter()
                            .map(|f| field(self, *f))
                            .collect::<Result<_, _>>()?,
                    )
                }
                EditKind::Artefact => Step::Save(vec![field(self, FieldId::ProgrammeName)?]),
                EditKind::Start if seed || (present && !fix) => Step::Blank,
                EditKind::Start => return self.refused_or(by, kind, base, GAP_START),
                EditKind::Narrative => return self.refused_or(by, kind, base, GAP_NARRATIVE),
                EditKind::Invitation | EditKind::InvitationWithdrawal if seed => {
                    return self.refused_or(by, kind, base, GAP_UNSET);
                }
                EditKind::Invitation | EditKind::InvitationWithdrawal if fix => {
                    return self.refused_or(by, kind, base, GAP_FIX);
                }
                EditKind::Invitation => {
                    let out = self.invite_spare(by, Tag::Edit(kind, effect))?;
                    return self.verdict(out, None);
                }
                EditKind::InvitationWithdrawal => {
                    let Some(spare) = self.spares.last().copied() else {
                        return Err(GAP_STEP);
                    };
                    let out =
                        self.step(by, base, Step::Withdraw(spare), Tag::Edit(kind, effect))?;
                    if matches!(out, Run::Appended) {
                        let _ = self.spares.pop();
                    }
                    return self.verdict(out, None);
                }
                EditKind::ImportResolution if seed => {
                    return self.refused_or(by, kind, base, GAP_UNSET);
                }
                EditKind::ImportResolution if fix => {
                    let only: Vec<FieldId> = unset.iter().copied().collect();
                    match only.as_slice() {
                        [f] if f.spec().is_some_and(|s| s.importable) => {
                            Step::Import(field(self, *f)?)
                        }
                        _ => return self.refused_or(by, kind, base, GAP_FIX),
                    }
                }
                EditKind::ImportResolution => Step::Import(field(self, FieldId::ProgrammeName)?),
            };
            let out = self.step(by, base, step, Tag::Edit(kind, effect))?;
            self.verdict(out, None)
        }

        /// Runs `cmd` through the engine and maps the outcome. Environment
        /// commands set the recording-fake prober or the import store.
        pub fn apply(&mut self, cmd: &RefCommand) -> Result<StepVerdict, NotImplemented> {
            match *cmd {
                RefCommand::Open { by } => {
                    let open = CreatorCommand::OpenDraft {
                        programme: PLAN_P,
                        version: PolicyVersionId::from_raw(PLAN_P.raw()),
                        profile: default_profile()?,
                    };
                    let r = self.run(Command::Creator(open), by, Tag::Plain)?;
                    self.verdict(r, None)
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
                    Ok(match self.run_ctx(Command::Core(end), ctx, Tag::Plain)? {
                        Run::Appended => StepVerdict::Accepted,
                        Run::Refused(RuleRef::Actor, _, _) => {
                            StepVerdict::Refused(RefRefusal::NotTenantAdmin)
                        }
                        Run::Refused(..) => StepVerdict::Refused(RefRefusal::NoSuchBinding),
                    })
                }
                RefCommand::Edit {
                    by,
                    kind,
                    effect,
                    base,
                } => self.edit(by, kind, effect, base),
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
                    let r = self.run(Command::Creator(ack), by, Tag::Plain)?;
                    self.verdict(r, None)
                }
                RefCommand::Request { by, base } => {
                    let Some(revision) = self.named(base) else {
                        return Ok(StepVerdict::Refused(RefRefusal::Opening));
                    };
                    let req = CreatorCommand::RequestActivation {
                        programme: PLAN_P,
                        revision,
                    };
                    let r = self.run(Command::Creator(req), by, Tag::Plain)?;
                    self.verdict(r, None)
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
                    let r = self.run(Command::Creator(approve), by, Tag::Plain)?;
                    self.verdict(r, Some(by))
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
        /// The setup entries are left out, and each revision a record
        /// names is counted without them. An entry holding `DraftOpened`
        /// is `Opened`. A core `BindingGranted` of the programme manager
        /// role on the draft is `Granted`, and a `BindingEnded` of such a
        /// binding is `BindingEnded`. Each creator record is its reference
        /// record. An approval entry, with its `ProbeRecorded` records,
        /// `ActivationApproved` and `ProgrammeActivated`, is one
        /// `Activated`. A content edit maps to `Edited` with the kind its
        /// record names and the kind and effect the adapter issued it
        /// with, which no record holds. Import records are no draft
        /// records.
        pub fn events(&self) -> Result<Vec<RefEvent>, NotImplemented> {
            let mut out = Vec::new();
            let mut i = 0usize;
            let ledger = &self.ledger;
            let offset = self.offset();
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
                if !self.setup.contains(&first.command) {
                    let prefix = ledger.get(..i).unwrap_or_default();
                    let edit = self.edits.get(&first.command).copied();
                    out.extend(self.entry_events(&entry, prefix, edit, offset, &mut managers)?);
                }
                i = j;
            }
            Ok(out)
        }

        /// The reference records of one entry.
        fn entry_events(
            &self,
            entry: &[&Record],
            prefix: &[Entry<Record>],
            edit: Option<(EditKind, RefEdit)>,
            offset: u32,
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
                    revision: a.revision().seq().saturating_sub(offset),
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
                        if let Some(e) = creator_event(c, edit, offset) {
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
        /// `approver` would read it at the instant of the next command.
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
                self.now(),
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
            // The reference counts no setup entry.
            let rev = fstp_creator::DraftRevision::new(
                revision.saturating_add(self.offset()),
                head.entry(),
            );
            let builders = d.builders().clone();
            let report = self.production_report(None)?;
            let digest = report.digest();
            let decision = DecisionId::from_raw(0x4d41_7ee7);
            // The records take the instant of the injected entry, so the
            // fold sees no clock going backwards.
            let now = self.now();
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
                        at: now,
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
            let ctx = draft_cell::ctx(stand_in, self.now(), 0, &[stand_in].into_iter().collect());
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

    /// The reference record of one creator record on the draft, with the
    /// kind and effect the adapter issued an edit with, and each revision
    /// counted without the `offset` setup entries.
    fn creator_event(
        c: &CreatorRecord,
        edit: Option<(EditKind, RefEdit)>,
        offset: u32,
    ) -> Option<RefEvent> {
        let edited = |by: AccountId, kind: EditKind| {
            let (kind, effect) = edit.unwrap_or((kind, RefEdit::Neutral));
            RefEvent::Edited { by, kind, effect }
        };
        let revision = |r: &fstp_creator::DraftRevision| r.seq().saturating_sub(offset);
        Some(match c {
            CreatorRecord::DraftOpened { by, .. } => RefEvent::Opened { by: *by },
            CreatorRecord::StartApplied { by, .. } => edited(*by, EditKind::Start),
            CreatorRecord::FieldsSaved { by, fields, .. } => {
                let import = fields
                    .iter()
                    .any(|(_, _, p)| matches!(p, fstp_creator::Provenance::Import { .. }));
                let policy = fields
                    .iter()
                    .any(|(f, _, _)| f.spec().is_some_and(|s| s.kind == FieldKind::Policy));
                edited(
                    *by,
                    if import {
                        EditKind::ImportResolution
                    } else if policy {
                        EditKind::Policy
                    } else {
                        EditKind::Artefact
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
                revision: r,
                ..
            } => RefEvent::Acknowledged {
                by: *by,
                warning: ref_check(warning.check)?,
                revision: revision(r),
            },
            CreatorRecord::ActivationRequested {
                by, revision: r, ..
            } => RefEvent::Requested {
                by: *by,
                revision: revision(r),
            },
            CreatorRecord::ProbeRecorded { probe, outcome, .. } => RefEvent::ProbeRecorded {
                probe: ref_probe(*probe),
                outcome: ref_outcome(*outcome),
            },
            CreatorRecord::TemplateSaved { by, .. } => RefEvent::TemplateSaved { by: *by },
            CreatorRecord::ActivationApproved(_) => return None,
        })
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

/// The measured state count of the production run of M-ACTIVATE without
/// the Sybil pair (lane m4glue, 2026-10-30). Production states hold the
/// ledger, so two orders of the same steps are two states.
pub const PRODUCTION_STATES: usize = 77_375;

/// The measured state count of the production run with the Sybil pair
/// (lane m4glue, 2026-10-30).
pub const PRODUCTION_SYBIL_STATES: usize = 137_036;

/// The state count the production runs record: the larger of
/// [`PRODUCTION_STATES`] and [`PRODUCTION_SYBIL_STATES`], since the
/// production runs share one tripwire. It was zero until the first
/// exhaustive production runs, so no run passed on a placeholder.
pub const TRIPWIRE: usize = PRODUCTION_SYBIL_STATES;

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

/// What [`cap_attempt`] showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapOutcome {
    /// The setup save of the cap was refused with I-50, naming P-05 and
    /// P-58 as these strings, and nothing was appended.
    RefusedAtSave {
        /// P-05 as the refusal names it.
        p05: String,
        /// P-58 as the refusal names it.
        p58: String,
    },
    /// The setup save was accepted, and A2's attempt ran.
    Ran(AttemptOutcome),
}

/// Runs [`cap_plan`] of `p05_minor` and `p58_minor` on `backend` (I-50
/// at save, Daniel's answer of 2026-10-31, M4 design section 15.0). A cap
/// above the ceiling refuses the first manager's setup save, so no draft
/// holds it. Otherwise A2 attempts the activation as
/// [`Attempt::by_second_admin`] does.
pub fn cap_attempt(backend: Backend, p05_minor: u64, p58_minor: u64) -> Result<CapOutcome, String> {
    let plan = cap_plan(p05_minor, p58_minor);
    let refused = match backend {
        Backend::Reference => match RefSystem::open(&plan) {
            Ok(_) => None,
            Err((_, RefRefusal::CapAboveCeiling)) => Some(cap_strings(p05_minor, p58_minor)),
            Err((cmd, r)) => {
                return Err(format!(
                    "the plan is not realisable: {cmd:?} refused with {r:?}"
                ));
            }
        },
        Backend::Production => {
            ProductionSystem::cap_setup(&plan).map_err(|e| format!("production: {e}"))?
        }
    };
    match refused {
        Some((p05, p58)) => Ok(CapOutcome::RefusedAtSave { p05, p58 }),
        None => attempt(backend, &Attempt::by_second_admin(plan)).map(CapOutcome::Ran),
    }
}
