//! The independent creator reference for I-66 and I-67 (M4 design
//! sections 3.2, 8.4 and 8.5). Lane W2a owns this file.
//!
//! The lane's test author wrote it from the spec text, apart from the
//! production code it checks. It shares only id types with production
//! code. Sources:
//!
//! - `SPEC/02-domain/invariants.md` I-66 and I-67, and the same rules in
//!   `SPEC/02-domain/programme-creator.md`: "A programme cannot be
//!   activated while its validation report shows any failure. Warnings
//!   need a recorded acknowledgement." and "Activating a programme needs
//!   approval by a second person who did not build it."
//! - `SPEC/01-requirements/functional.md` R-PG-01 AC: "a programme with
//!   P-05 above P-58 cannot be activated, and the report names both
//!   values", and R-PG-03.
//! - The check catalogue of M4 design section 3.2, row by row, with its
//!   severities.
//!
//! # Readings
//!
//! Every reading below is the interim reading of M4 design section 12.3.
//! Daniel answered on 2026-10-29 that each recommendation is built as an
//! interim reading (design section 15.0). Each is marked "Interim,
//! pending Daniel" and is reversible.
//!
//! - **R1, edits (design 3.2 "Bound to a revision").** Every record on the
//!   draft bumps the revision. Only an edit changes the draft content. The
//!   edits are an opening, a field save, a start, an accepted narrative,
//!   an invitation, its withdrawal or its acceptance, and an import
//!   resolution, a dismissal included. A grant on the draft is an edit,
//!   and so is each later record of that binding: its end, suspension,
//!   void, reinstatement or scheduled end. Acknowledgements, probe
//!   records, activation requests and template saves change no content.
//!   An acknowledgement or a request at revision `r` stays live while no
//!   edit follows `r`. Interim, pending Daniel.
//! - **R2, builders (Q1 A).** The builder set holds the author of every
//!   authored record on the draft: the opener, every grantor of a draft
//!   binding, every reinstater of a draft binding, every editor (an import
//!   resolver included), every acknowledger, every requester and every
//!   template saver. The end of a binding names no author, and an
//!   acceptance builds nothing. The strict reading counts a request and a
//!   template save as creator records too. Interim, pending Daniel.
//! - **R3, approver (Q1 A).** The approver is a tenant admin outside the
//!   builder set. Interim, pending Daniel.
//! - **R4, second person (Q2 B).** The vault must answer `IsVerified` for
//!   the approver and for every builder. An unverified builder is the
//!   validation failure `BuilderUnverified`. An unverified approver is
//!   refused. A verified approver who shares a verified identity with any
//!   builder is refused. Interim, pending Daniel.
//! - **R5, acknowledgements.** An acknowledgement names the head revision
//!   and a warning that the current report shows. A programme manager on
//!   the draft or a tenant admin may acknowledge. Interim, pending
//!   Daniel.
//! - **R6, request.** Approval needs a live activation request. A
//!   programme manager on the draft or a tenant admin may request.
//!   Interim, pending Daniel.
//! - **R7, fresh probes (design 3.2 "Fresh probes").** The report at
//!   approval is recomputed over the probe results of the approval
//!   request, never over the stored request-time report. An absent
//!   prober reports a failure for channels and the sending domain (Q5 A).
//!   Interim, pending Daniel.
//! - **R8, pending wording (Q6 A)** and **unresolved imports (Q30)** are
//!   failures. Interim, pending Daniel.
//! - **R9, who edits (design 2.2 J1).** A programme manager on the draft
//!   may make every edit. A tenant admin may also invite and withdraw an
//!   invitation, since J1 has A1 invite M1 before any manager exists. A
//!   tenant admin may end a programme manager binding on the draft.
//!   Interim, pending Daniel.
//!
//! # What the reference abstracts
//!
//! A draft's content is the set of content checks it triggers. An edit
//! seeds or fixes one check, or changes nothing a check reads. The cap
//! values, the profile's wording status, the default theme, the tenant
//! admin set and the vault are plan facts. Probe results and the count
//! of unresolved import proposals are the environment at the time of a
//! report. The production adapter in `mc::activate_model::production`
//! realises each plan with real drafts.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::AccountId;

// ---------------------------------------------------------------------------
// The check catalogue
// ---------------------------------------------------------------------------

/// The severity of a check (design 3.2 `Severity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefSeverity {
    /// Blocks activation (I-66).
    Failure,
    /// Blocks activation until acknowledged at a live revision (I-66,
    /// `programme-creator.md` Validation).
    Warning,
}

/// The probes the shell runs for a report (design 3.2 `Prober`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefProbe {
    /// Every enabled channel of P-32.
    Channel,
    /// SPF, DKIM and DMARC of the sending domain.
    SendingDomain,
    /// The P-21 inference provider.
    Inference,
}

impl RefProbe {
    /// Every probe, in catalogue order.
    pub const ALL: [RefProbe; 3] = [
        RefProbe::Channel,
        RefProbe::SendingDomain,
        RefProbe::Inference,
    ];

    /// The check this probe feeds.
    pub const fn check(self) -> RefCheck {
        match self {
            RefProbe::Channel => RefCheck::ChannelUnreachable,
            RefProbe::SendingDomain => RefCheck::SendingDomainUnverified,
            RefProbe::Inference => RefCheck::InferenceUnreachable,
        }
    }
}

/// The outcome of one probe run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefProbeOutcome {
    /// The probe passed.
    Pass,
    /// The probe failed.
    Fail,
    /// No prober exists. Channels and the sending domain fail closed
    /// (Q5 A); inference gives its warning.
    Absent,
}

impl RefProbeOutcome {
    /// Whether the probe's check is in the report.
    pub const fn reports(self) -> bool {
        !matches!(self, RefProbeOutcome::Pass)
    }
}

/// What a check reads, so a plan can seed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckFeed {
    /// The draft's own data: fields, narrative, invitations. An edit seeds
    /// or fixes it.
    Content,
    /// P-05 against P-58 (I-50).
    Cap,
    /// A probe result at the time of the report.
    Probe(RefProbe),
    /// The count of unresolved import proposals (Q30).
    Imports,
    /// The profile's legal wording status (Q6).
    Wording,
    /// The tenant admin set (SoD-07).
    AdminSet,
    /// The vault's `IsVerified` answer for every builder (Q2).
    BuilderVault,
    /// The default theme tokens (I-69, I-70). Fixed in M4.
    Theme,
}

/// One check of the catalogue (design 3.2, `CHECKS`). The variant names
/// equal the design's check names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefCheck {
    /// `fstp_domain::policy::validate` refuses the compiled policy.
    PolicyInvalid,
    /// I-50, R-PG-01 AC: P-05 above P-58.
    CapAboveCeiling,
    /// M2 `ValidationWarning`: P-04 maximum above P-05.
    P04MaxAboveP05,
    /// M2 `ValidationWarning`: P-39 above P-03.
    P39AboveP03,
    /// A field with no value.
    FieldUnset,
    /// P-57 start after end.
    ActionDatesInconsistent,
    /// I-48: the call package is incomplete.
    CallPackageIncomplete,
    /// I-52: a required Guide section is missing.
    GuideSectionMissing,
    /// I-51: a parameter-bound placeholder does not resolve.
    GuideBindingUnresolved,
    /// `guide-for-applicants.md` Rules: approved wording is pending (Q6).
    LegalWordingPending,
    /// I-49: a flow-down obligation is missing.
    FlowDownMissing,
    /// SoD-01 to SoD-13 across invited people.
    InviteeRefused,
    /// An invitation not yet accepted cannot be checked yet.
    InviteeWithoutAccount,
    /// SoD-07: fewer than two tenant admins.
    TooFewTenantAdmins,
    /// I-67 strict reading: a builder is unverified (Q2).
    BuilderUnverified,
    /// Too few invited committee members, IRC members, no chair or no
    /// coordinator.
    RosterShort,
    /// P-13 class ids the vault does not know (Q35).
    ExclusionClassUnknown,
    /// P-38: a partner organisation without a declared list (Q35).
    ProximityListMissing,
    /// P-23 enabled while no pre-check provider exists (Q38).
    PrecheckUnavailable,
    /// `ai-act.md` reassessment trigger.
    AiActReassessment,
    /// An enabled channel of P-32 is unreachable (Q5).
    ChannelUnreachable,
    /// SPF, DKIM or DMARC of the sending domain fails (Q5).
    SendingDomainUnverified,
    /// P-21 inference is unreachable (R-NF-10).
    InferenceUnreachable,
    /// I-69: a mandatory element is missing.
    MandatoryElementMissing,
    /// I-70: a text colour pair fails contrast.
    ContrastFailure,
    /// A proposal neither confirmed, edited nor dismissed (Q30).
    ImportUnresolved,
}

impl RefCheck {
    /// Every check, in the order of the design table.
    pub const ALL: [RefCheck; 26] = [
        RefCheck::PolicyInvalid,
        RefCheck::CapAboveCeiling,
        RefCheck::P04MaxAboveP05,
        RefCheck::P39AboveP03,
        RefCheck::FieldUnset,
        RefCheck::ActionDatesInconsistent,
        RefCheck::CallPackageIncomplete,
        RefCheck::GuideSectionMissing,
        RefCheck::GuideBindingUnresolved,
        RefCheck::LegalWordingPending,
        RefCheck::FlowDownMissing,
        RefCheck::InviteeRefused,
        RefCheck::InviteeWithoutAccount,
        RefCheck::TooFewTenantAdmins,
        RefCheck::BuilderUnverified,
        RefCheck::RosterShort,
        RefCheck::ExclusionClassUnknown,
        RefCheck::ProximityListMissing,
        RefCheck::PrecheckUnavailable,
        RefCheck::AiActReassessment,
        RefCheck::ChannelUnreachable,
        RefCheck::SendingDomainUnverified,
        RefCheck::InferenceUnreachable,
        RefCheck::MandatoryElementMissing,
        RefCheck::ContrastFailure,
        RefCheck::ImportUnresolved,
    ];

    /// The design's name of the check.
    pub const fn name(self) -> &'static str {
        match self {
            RefCheck::PolicyInvalid => "PolicyInvalid",
            RefCheck::CapAboveCeiling => "CapAboveCeiling",
            RefCheck::P04MaxAboveP05 => "P04MaxAboveP05",
            RefCheck::P39AboveP03 => "P39AboveP03",
            RefCheck::FieldUnset => "FieldUnset",
            RefCheck::ActionDatesInconsistent => "ActionDatesInconsistent",
            RefCheck::CallPackageIncomplete => "CallPackageIncomplete",
            RefCheck::GuideSectionMissing => "GuideSectionMissing",
            RefCheck::GuideBindingUnresolved => "GuideBindingUnresolved",
            RefCheck::LegalWordingPending => "LegalWordingPending",
            RefCheck::FlowDownMissing => "FlowDownMissing",
            RefCheck::InviteeRefused => "InviteeRefused",
            RefCheck::InviteeWithoutAccount => "InviteeWithoutAccount",
            RefCheck::TooFewTenantAdmins => "TooFewTenantAdmins",
            RefCheck::BuilderUnverified => "BuilderUnverified",
            RefCheck::RosterShort => "RosterShort",
            RefCheck::ExclusionClassUnknown => "ExclusionClassUnknown",
            RefCheck::ProximityListMissing => "ProximityListMissing",
            RefCheck::PrecheckUnavailable => "PrecheckUnavailable",
            RefCheck::AiActReassessment => "AiActReassessment",
            RefCheck::ChannelUnreachable => "ChannelUnreachable",
            RefCheck::SendingDomainUnverified => "SendingDomainUnverified",
            RefCheck::InferenceUnreachable => "InferenceUnreachable",
            RefCheck::MandatoryElementMissing => "MandatoryElementMissing",
            RefCheck::ContrastFailure => "ContrastFailure",
            RefCheck::ImportUnresolved => "ImportUnresolved",
        }
    }

    /// The check with the design's name `name`.
    pub fn from_name(name: &str) -> Option<RefCheck> {
        RefCheck::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The severity the design table gives the check.
    pub const fn severity(self) -> RefSeverity {
        match self {
            RefCheck::P04MaxAboveP05
            | RefCheck::P39AboveP03
            | RefCheck::InviteeWithoutAccount
            | RefCheck::RosterShort
            | RefCheck::ProximityListMissing
            // Q38 C (Daniel, 2026-11-06): a missing pre-check provider
            // needs an acknowledgement and never blocks on its own.
            | RefCheck::PrecheckUnavailable
            | RefCheck::AiActReassessment
            | RefCheck::InferenceUnreachable => RefSeverity::Warning,
            _ => RefSeverity::Failure,
        }
    }

    /// What the check reads.
    pub const fn feed(self) -> CheckFeed {
        match self {
            RefCheck::CapAboveCeiling => CheckFeed::Cap,
            RefCheck::LegalWordingPending => CheckFeed::Wording,
            RefCheck::TooFewTenantAdmins => CheckFeed::AdminSet,
            RefCheck::BuilderUnverified => CheckFeed::BuilderVault,
            RefCheck::ChannelUnreachable => CheckFeed::Probe(RefProbe::Channel),
            RefCheck::SendingDomainUnverified => CheckFeed::Probe(RefProbe::SendingDomain),
            RefCheck::InferenceUnreachable => CheckFeed::Probe(RefProbe::Inference),
            RefCheck::MandatoryElementMissing | RefCheck::ContrastFailure => CheckFeed::Theme,
            RefCheck::ImportUnresolved => CheckFeed::Imports,
            _ => CheckFeed::Content,
        }
    }

    /// Every check of severity Failure, in catalogue order.
    pub fn failures() -> Vec<RefCheck> {
        RefCheck::ALL
            .into_iter()
            .filter(|c| c.severity() == RefSeverity::Failure)
            .collect()
    }

    /// Every check of severity Warning, in catalogue order.
    pub fn warnings() -> Vec<RefCheck> {
        RefCheck::ALL
            .into_iter()
            .filter(|c| c.severity() == RefSeverity::Warning)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Plan facts: money, vault, environment
// ---------------------------------------------------------------------------

/// P-05 and P-58 of a draft, in EUR minor units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefCap {
    /// The per-recipient cap, P-05.
    pub p05_minor: u64,
    /// The funder per-recipient ceiling, P-58.
    pub p58_minor: u64,
}

impl RefCap {
    /// The SuperSAFE cap of 400000.00 under an equal synthetic ceiling.
    pub const SUPERSAFE: RefCap = RefCap {
        p05_minor: 40_000_000,
        p58_minor: 40_000_000,
    };

    /// Whether the cap is above the ceiling (I-50).
    pub const fn above_ceiling(self) -> bool {
        self.p05_minor > self.p58_minor
    }
}

/// An EUR amount in minor units as an ADR-006 string: digits, a point and
/// exactly two decimals, such as `"400000.00"`. Written here apart from
/// `fstp-money`, so the R-PG-01 test does not trust the code it checks.
pub fn adr006_eur(minor: u64) -> String {
    let units = minor.checked_div(100).unwrap_or(0);
    let cents = minor.checked_rem(100).unwrap_or(0);
    format!("{units}.{cents:02}")
}

/// The vault facts the reference reads: who is verified, and which
/// accounts belong to one person.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefVault {
    verified: BTreeSet<AccountId>,
    person: BTreeMap<AccountId, u32>,
}

impl RefVault {
    /// A vault that knows nobody.
    pub fn new() -> RefVault {
        RefVault::default()
    }

    /// The vault with `account` belonging to `person`, verified or not.
    pub fn with(mut self, account: AccountId, person: u32, verified: bool) -> RefVault {
        self.person.insert(account, person);
        if verified {
            self.verified.insert(account);
        } else {
            self.verified.remove(&account);
        }
        self
    }

    /// The vault's `IsVerified` answer.
    pub fn is_verified(&self, account: AccountId) -> bool {
        self.verified.contains(&account)
    }

    /// The person of `account`, if the vault knows it.
    pub fn person(&self, account: AccountId) -> Option<u32> {
        self.person.get(&account).copied()
    }

    /// The vault's `SameIdentityAsAny` answer. It means something only
    /// between verified accounts (Q2), so an unverified account shares no
    /// verified identity.
    pub fn same_identity_as_any(&self, account: AccountId, others: &BTreeSet<AccountId>) -> bool {
        if !self.is_verified(account) {
            return false;
        }
        let Some(p) = self.person(account) else {
            return false;
        };
        others
            .iter()
            .any(|b| *b != account && self.is_verified(*b) && self.person(*b) == Some(p))
    }
}

/// The environment of one report: probe results and the count of
/// unresolved import proposals the engine passes in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefInputs {
    /// The result of every probe.
    pub probes: BTreeMap<RefProbe, RefProbeOutcome>,
    /// `CreatorInputs::unresolved_imports`.
    pub unresolved_imports: u32,
}

impl RefInputs {
    /// Every probe passes and no import proposal is pending.
    pub fn passing() -> RefInputs {
        RefInputs {
            probes: RefProbe::ALL
                .into_iter()
                .map(|p| (p, RefProbeOutcome::Pass))
                .collect(),
            unresolved_imports: 0,
        }
    }

    /// The outcome of `probe`. A probe with no recorded result is absent.
    pub fn probe(&self, probe: RefProbe) -> RefProbeOutcome {
        self.probes
            .get(&probe)
            .copied()
            .unwrap_or(RefProbeOutcome::Absent)
    }

    /// The same environment with `probe` at `outcome`.
    pub fn with_probe(mut self, probe: RefProbe, outcome: RefProbeOutcome) -> RefInputs {
        self.probes.insert(probe, outcome);
        self
    }
}

/// The facts of a draft that no draft record changes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefStatic {
    /// The attested tenant admin set (Q31 A).
    pub admins: BTreeSet<AccountId>,
    /// The vault.
    pub vault: RefVault,
    /// P-05 and P-58.
    pub cap: RefCap,
    /// Whether the profile's statements on grant agreement obligations
    /// still wait for approved wording (Q6).
    pub wording_pending: bool,
    /// The theme checks the default theme fails. Empty for the shipped
    /// default theme.
    pub theme_faults: BTreeSet<RefCheck>,
}

// ---------------------------------------------------------------------------
// Records and commands
// ---------------------------------------------------------------------------

/// How an edit changes the content checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefEdit {
    /// The edit makes the draft trigger the content check.
    Seed(RefCheck),
    /// The edit removes the cause of the content check.
    Fix(RefCheck),
    /// The edit changes nothing a check reads.
    Neutral,
}

/// Which record an edit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EditKind {
    /// `SaveFields` touching a policy field, with its core `EditPolicy`.
    Policy,
    /// `SaveFields` touching artefact fields only.
    Artefact,
    /// `ApplyStart`, which compiles the start into a core `EditPolicy`.
    Start,
    /// `AcceptNarrative`.
    Narrative,
    /// `Invite`.
    Invitation,
    /// `WithdrawInvitation`.
    InvitationWithdrawal,
    /// An import resolution, which saves fields with import provenance.
    ImportResolution,
}

impl EditKind {
    /// Whether the edit carries a core record (`EditPolicy`), so the core
    /// guard's `programme_builders` sees its author (D2).
    pub const fn has_core_record(self) -> bool {
        matches!(self, EditKind::Policy | EditKind::Start)
    }
}

/// One record on the draft, in the reference vocabulary. The production
/// adapter maps each production ledger entry on the programme to one of
/// these, from raw records.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefEvent {
    /// `DraftOpened` with core `CreateProgramme` (Draft status).
    Opened {
        /// The tenant admin who opened the draft.
        by: AccountId,
    },
    /// Core `GrantRole` of the programme manager role on the draft.
    Granted {
        /// The grantor.
        by: AccountId,
        /// The new programme manager.
        to: AccountId,
    },
    /// Core `BindingEnded` of a programme manager binding on the draft.
    /// The record names no author.
    BindingEnded {
        /// The former programme manager.
        of: AccountId,
    },
    /// An edit of the draft content.
    Edited {
        /// The author.
        by: AccountId,
        /// Which record.
        kind: EditKind,
        /// What it changes for the checks.
        effect: RefEdit,
    },
    /// `WarningAcknowledged`.
    Acknowledged {
        /// The acknowledger.
        by: AccountId,
        /// The warning.
        warning: RefCheck,
        /// The revision the acknowledgement names.
        revision: u32,
    },
    /// `ActivationRequested`.
    Requested {
        /// The requester.
        by: AccountId,
        /// The revision the request names.
        revision: u32,
    },
    /// `ProbeRecorded` outside an approval entry. It has no author.
    ProbeRecorded {
        /// The probe.
        probe: RefProbe,
        /// The outcome.
        outcome: RefProbeOutcome,
    },
    /// `TemplateSaved` from this draft.
    TemplateSaved {
        /// The author.
        by: AccountId,
    },
    /// One ledger entry with the approval's `ProbeRecorded` records,
    /// `ActivationApproved` and core `ProgrammeActivated`.
    Activated {
        /// The approver.
        by: AccountId,
        /// The revision the approval names.
        revision: u32,
        /// The probe results recorded in the same entry and the import
        /// count the engine passed in.
        inputs: RefInputs,
    },
}

impl RefEvent {
    /// The author of the record, if it has one.
    pub fn author(&self) -> Option<AccountId> {
        match self {
            RefEvent::Opened { by }
            | RefEvent::Granted { by, .. }
            | RefEvent::Edited { by, .. }
            | RefEvent::Acknowledged { by, .. }
            | RefEvent::Requested { by, .. }
            | RefEvent::TemplateSaved { by }
            | RefEvent::Activated { by, .. } => Some(*by),
            RefEvent::ProbeRecorded { .. } | RefEvent::BindingEnded { .. } => None,
        }
    }

    /// Whether the record changes the draft content (reading R1).
    pub fn is_edit(&self) -> bool {
        matches!(
            self,
            RefEvent::Opened { .. }
                | RefEvent::Granted { .. }
                | RefEvent::BindingEnded { .. }
                | RefEvent::Edited { .. }
        )
    }
}

/// Which revision a command names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Base {
    /// The current head revision.
    Head,
    /// The revision before the head: a stale view.
    Previous,
}

/// One step a model or a machine takes, in the reference vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefCommand {
    /// `OpenDraft`.
    Open {
        /// The actor.
        by: AccountId,
    },
    /// `GrantRole` of programme manager on the draft.
    Grant {
        /// The grantor.
        by: AccountId,
        /// The grantee.
        to: AccountId,
    },
    /// `EndRole` of a programme manager binding on the draft.
    EndBinding {
        /// The tenant admin who ends it.
        by: AccountId,
        /// The programme manager whose binding ends.
        of: AccountId,
    },
    /// An edit.
    Edit {
        /// The actor.
        by: AccountId,
        /// Which record.
        kind: EditKind,
        /// What it changes for the checks.
        effect: RefEdit,
        /// The revision named. An invitation and its withdrawal name none
        /// (design 3.2), so it is ignored for them.
        base: Base,
    },
    /// `AcknowledgeWarning`.
    Acknowledge {
        /// The actor.
        by: AccountId,
        /// The warning.
        warning: RefCheck,
        /// The revision named.
        base: Base,
    },
    /// `RequestActivation`.
    Request {
        /// The actor.
        by: AccountId,
        /// The revision named.
        base: Base,
    },
    /// `ApproveActivation`.
    Approve {
        /// The actor.
        by: AccountId,
        /// The revision named.
        base: Base,
    },
    /// The environment changes: `probe` gives `outcome` from now on.
    SetProbe {
        /// The probe.
        probe: RefProbe,
        /// Its outcome from now on.
        outcome: RefProbeOutcome,
    },
    /// The environment changes: this many import proposals are unresolved.
    SetUnresolvedImports(u32),
}

impl RefCommand {
    /// Whether the command is an approval.
    pub fn is_approval(&self) -> bool {
        matches!(self, RefCommand::Approve { .. })
    }
}

/// Why the reference refuses a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefRefusal {
    /// The draft was opened already, or is not opened yet.
    Opening,
    /// The programme is active, so the draft commands stop.
    AlreadyActive,
    /// The command names a revision other than the head.
    StaleRevision,
    /// The actor is not a tenant admin.
    NotTenantAdmin,
    /// The actor holds no programme manager binding on the draft.
    NotProgrammeManager,
    /// The grantee already holds the binding, or is the grantor (SoD-07
    /// needs a second admin for a self-grant).
    GrantNotAdmitted,
    /// The grantee is unverified (SoD-09).
    GranteeUnverified,
    /// The account holds no programme manager binding on the draft to
    /// end.
    NoSuchBinding,
    /// The acknowledged check is not a warning the report shows.
    NotAWarning,
    /// The edit seeds a check that no edit can seed.
    NotContent,
    /// I-67: the approver built the draft.
    ApproverIsBuilder,
    /// I-67 under Q2: the approver is unverified.
    ApproverUnverified,
    /// I-67 under Q2: the approver shares a verified identity with a
    /// builder.
    SameIdentity,
    /// No activation request is live (reading R6).
    NoLiveRequest,
    /// I-66: the recomputed report shows this failure.
    Failed(RefCheck),
    /// I-66: this warning has no live acknowledgement.
    Unacknowledged(RefCheck),
    /// I-50 at save (Daniel's answer of 2026-10-31, M4 design section
    /// 15.0): the save would put P-05 above P-58, so it is refused and no
    /// draft holds such a cap.
    CapAboveCeiling,
}

/// The verdict on one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepVerdict {
    /// The command was accepted and appended its records.
    Accepted,
    /// The command was refused and appended nothing.
    Refused(RefRefusal),
}

impl StepVerdict {
    /// Whether the command was accepted.
    pub fn accepted(self) -> bool {
        matches!(self, StepVerdict::Accepted)
    }
}

// ---------------------------------------------------------------------------
// The draft fold
// ---------------------------------------------------------------------------

/// The reference view of one draft, folded from its records.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefDraft {
    /// Whether the draft is open.
    pub opened: bool,
    /// The head revision: the number of records on the draft.
    pub head: u32,
    /// The revision of the latest edit (reading R1).
    pub last_edit: u32,
    /// The content checks the draft triggers.
    pub content: BTreeSet<RefCheck>,
    /// The builder set (reading R2).
    pub builders: BTreeSet<AccountId>,
    /// The authors of core records: `programme_builders` as the core
    /// guard sees it (D2).
    pub core_builders: BTreeSet<AccountId>,
    /// The accounts with a programme manager binding on the draft.
    pub managers: BTreeSet<AccountId>,
    /// The latest acknowledged revision of each warning.
    pub acks: BTreeMap<RefCheck, u32>,
    /// The revision of the latest activation request.
    pub request: Option<u32>,
    /// The revision the activation approved.
    pub active: Option<u32>,
}

impl RefDraft {
    /// The view before any record.
    pub fn genesis() -> RefDraft {
        RefDraft::default()
    }

    /// The view after `events`, folded from genesis.
    pub fn fold(events: &[RefEvent]) -> RefDraft {
        let mut d = RefDraft::genesis();
        for e in events {
            d.apply(e);
        }
        d
    }

    /// Folds one record.
    pub fn apply(&mut self, event: &RefEvent) {
        self.head = self.head.saturating_add(1);
        if event.is_edit() {
            self.last_edit = self.head;
        }
        if let (Some(by), false) = (event.author(), matches!(event, RefEvent::Activated { .. })) {
            self.builders.insert(by);
        }
        match event {
            RefEvent::Opened { by } => {
                self.opened = true;
                self.core_builders.insert(*by);
            }
            RefEvent::Granted { by, to } => {
                self.managers.insert(*to);
                self.core_builders.insert(*by);
            }
            RefEvent::BindingEnded { of } => {
                self.managers.remove(of);
            }
            RefEvent::Edited { by, kind, effect } => {
                if kind.has_core_record() {
                    self.core_builders.insert(*by);
                }
                match effect {
                    RefEdit::Seed(c) => {
                        self.content.insert(*c);
                    }
                    RefEdit::Fix(c) => {
                        self.content.remove(c);
                    }
                    RefEdit::Neutral => {}
                }
            }
            RefEvent::Acknowledged {
                warning, revision, ..
            } => {
                self.acks.insert(*warning, *revision);
            }
            RefEvent::Requested { revision, .. } => self.request = Some(*revision),
            RefEvent::ProbeRecorded { .. } | RefEvent::TemplateSaved { .. } => {}
            RefEvent::Activated { revision, .. } => self.active = Some(*revision),
        }
    }

    /// Whether the acknowledgement of `warning` is live: it names a
    /// revision that no edit follows (reading R1).
    pub fn ack_live(&self, warning: RefCheck) -> bool {
        self.acks
            .get(&warning)
            .is_some_and(|r| *r >= self.last_edit)
    }

    /// Whether an activation request is live (readings R1 and R6).
    pub fn request_live(&self) -> bool {
        self.request.is_some_and(|r| r >= self.last_edit)
    }

    /// The revision a command names under `base`.
    pub fn named(&self, base: Base) -> u32 {
        match base {
            Base::Head => self.head,
            Base::Previous => self.head.saturating_sub(1),
        }
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// What a report row says beyond its check.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefDetail {
    /// No detail the reference checks.
    None,
    /// R-PG-01 AC: both values, as ADR-006 strings.
    Cap {
        /// P-05.
        p05: String,
        /// P-58.
        p58: String,
    },
}

/// A validation report: every check it shows, with its detail.
pub type RefReport = BTreeMap<RefCheck, RefDetail>;

/// The report over `draft` with the plan facts `stat` and the environment
/// `inputs`.
pub fn report(stat: &RefStatic, draft: &RefDraft, inputs: &RefInputs) -> RefReport {
    let mut r = RefReport::new();
    for c in &draft.content {
        if c.feed() == CheckFeed::Content {
            r.insert(*c, RefDetail::None);
        }
    }
    if stat.cap.above_ceiling() {
        r.insert(
            RefCheck::CapAboveCeiling,
            RefDetail::Cap {
                p05: adr006_eur(stat.cap.p05_minor),
                p58: adr006_eur(stat.cap.p58_minor),
            },
        );
    }
    for p in RefProbe::ALL {
        if inputs.probe(p).reports() {
            r.insert(p.check(), RefDetail::None);
        }
    }
    if inputs.unresolved_imports > 0 {
        r.insert(RefCheck::ImportUnresolved, RefDetail::None);
    }
    if stat.wording_pending {
        r.insert(RefCheck::LegalWordingPending, RefDetail::None);
    }
    if stat.admins.len() < 2 {
        r.insert(RefCheck::TooFewTenantAdmins, RefDetail::None);
    }
    if draft.builders.iter().any(|b| !stat.vault.is_verified(*b)) {
        r.insert(RefCheck::BuilderUnverified, RefDetail::None);
    }
    for c in &stat.theme_faults {
        if c.feed() == CheckFeed::Theme {
            r.insert(*c, RefDetail::None);
        }
    }
    r
}

/// Why a report does not clear, or `None` when it is clean at the draft's
/// head: no failure, and every warning acknowledged at a live revision.
/// The first failure in catalogue order wins, then the first warning.
pub fn uncleared(report: &RefReport, draft: &RefDraft) -> Option<RefRefusal> {
    if let Some(c) = report.keys().find(|c| c.severity() == RefSeverity::Failure) {
        return Some(RefRefusal::Failed(*c));
    }
    report
        .keys()
        .find(|c| c.severity() == RefSeverity::Warning && !draft.ack_live(**c))
        .map(|c| RefRefusal::Unacknowledged(*c))
}

// ---------------------------------------------------------------------------
// The reference system
// ---------------------------------------------------------------------------

/// A plan for one draft: who acts, the vault, and the facts to seed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DraftPlan {
    /// The tenant admin who opens the draft.
    pub opener: AccountId,
    /// The facts no record changes.
    pub stat: RefStatic,
    /// The programme managers the opener grants on the draft, in order.
    /// The first one makes the seeding edits.
    pub managers: Vec<AccountId>,
    /// The content checks the first manager seeds, one edit each.
    pub seeds: BTreeSet<RefCheck>,
    /// The environment after opening.
    pub env: RefInputs,
}

/// The reference system: the plan facts, the environment, the records on
/// the draft and their fold.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefSystem {
    /// The facts no record changes.
    pub stat: RefStatic,
    /// The environment now.
    pub env: RefInputs,
    /// Every record on the draft, in ledger order.
    pub events: Vec<RefEvent>,
    /// The fold of `events`, kept step by step.
    pub draft: RefDraft,
}

impl RefSystem {
    /// The system before the draft is opened.
    pub fn empty(stat: RefStatic, env: RefInputs) -> RefSystem {
        RefSystem {
            stat,
            env,
            events: Vec::new(),
            draft: RefDraft::genesis(),
        }
    }

    /// Opens the draft of `plan`, grants its managers and seeds its
    /// content checks. Fails with the first refusal, which means the plan
    /// is not realisable.
    ///
    /// The first manager's setup save, which carries the plan's P-05 and
    /// P-58, runs after the grants and before the seeds. It is no record of
    /// this vocabulary. A cap above the ceiling refuses it with
    /// [`RefRefusal::CapAboveCeiling`] (I-50 at save, Daniel's answer of
    /// 2026-10-31, M4 design section 15.0), named as [`cap_save`].
    pub fn open(plan: &DraftPlan) -> Result<RefSystem, (RefCommand, RefRefusal)> {
        let mut s = RefSystem::empty(plan.stat.clone(), plan.env.clone());
        let mut script = vec![RefCommand::Open { by: plan.opener }];
        for m in &plan.managers {
            script.push(RefCommand::Grant {
                by: plan.opener,
                to: *m,
            });
        }
        for cmd in script {
            if let StepVerdict::Refused(r) = s.apply(&cmd) {
                return Err((cmd, r));
            }
        }
        if plan.stat.cap.above_ceiling() {
            return Err((cap_save(plan), RefRefusal::CapAboveCeiling));
        }
        if let Some(first) = plan.managers.first() {
            for c in &plan.seeds {
                let cmd = RefCommand::Edit {
                    by: *first,
                    kind: EditKind::Policy,
                    effect: RefEdit::Seed(*c),
                    base: Base::Head,
                };
                if let StepVerdict::Refused(r) = s.apply(&cmd) {
                    return Err((cmd, r));
                }
            }
        }
        Ok(s)
    }

    /// The report now, over the current environment.
    pub fn report(&self) -> RefReport {
        report(&self.stat, &self.draft, &self.env)
    }

    /// Decides `cmd`: the records it appends, or why it is refused.
    /// Environment commands append nothing and are never refused.
    pub fn decide(&self, cmd: &RefCommand) -> Result<Vec<RefEvent>, RefRefusal> {
        let d = &self.draft;
        let s = &self.stat;
        let draft_open = |r: &RefDraft| -> Result<(), RefRefusal> {
            if !r.opened {
                Err(RefRefusal::Opening)
            } else if r.active.is_some() {
                Err(RefRefusal::AlreadyActive)
            } else {
                Ok(())
            }
        };
        let at_head = |base: Base| -> Result<u32, RefRefusal> {
            if d.named(base) == d.head {
                Ok(d.head)
            } else {
                Err(RefRefusal::StaleRevision)
            }
        };
        match *cmd {
            RefCommand::Open { by } => {
                if d.opened {
                    return Err(RefRefusal::Opening);
                }
                if !s.admins.contains(&by) {
                    return Err(RefRefusal::NotTenantAdmin);
                }
                Ok(vec![RefEvent::Opened { by }])
            }
            RefCommand::Grant { by, to } => {
                draft_open(d)?;
                if !s.admins.contains(&by) {
                    return Err(RefRefusal::NotTenantAdmin);
                }
                if by == to || d.managers.contains(&to) {
                    return Err(RefRefusal::GrantNotAdmitted);
                }
                if !s.vault.is_verified(to) {
                    return Err(RefRefusal::GranteeUnverified);
                }
                Ok(vec![RefEvent::Granted { by, to }])
            }
            RefCommand::EndBinding { by, of } => {
                draft_open(d)?;
                if !s.admins.contains(&by) {
                    return Err(RefRefusal::NotTenantAdmin);
                }
                if !d.managers.contains(&of) {
                    return Err(RefRefusal::NoSuchBinding);
                }
                Ok(vec![RefEvent::BindingEnded { of }])
            }
            RefCommand::Edit {
                by,
                kind,
                effect,
                base,
            } => {
                draft_open(d)?;
                // `Invite` and `WithdrawInvitation` name no revision
                // (design 3.2), so only the other edits can be stale.
                let invitation =
                    matches!(kind, EditKind::Invitation | EditKind::InvitationWithdrawal);
                if !invitation {
                    at_head(base)?;
                }
                // Reading R9: a tenant admin may invite and withdraw.
                let admin_may = invitation && s.admins.contains(&by);
                if !(d.managers.contains(&by) || admin_may) {
                    return Err(RefRefusal::NotProgrammeManager);
                }
                if let RefEdit::Seed(c) | RefEdit::Fix(c) = effect
                    && c.feed() != CheckFeed::Content
                {
                    return Err(RefRefusal::NotContent);
                }
                Ok(vec![RefEvent::Edited { by, kind, effect }])
            }
            RefCommand::Acknowledge { by, warning, base } => {
                draft_open(d)?;
                let revision = at_head(base)?;
                if !(d.managers.contains(&by) || s.admins.contains(&by)) {
                    return Err(RefRefusal::NotProgrammeManager);
                }
                if warning.severity() != RefSeverity::Warning
                    || !self.report().contains_key(&warning)
                {
                    return Err(RefRefusal::NotAWarning);
                }
                Ok(vec![RefEvent::Acknowledged {
                    by,
                    warning,
                    revision,
                }])
            }
            RefCommand::Request { by, base } => {
                draft_open(d)?;
                let revision = at_head(base)?;
                if !(d.managers.contains(&by) || s.admins.contains(&by)) {
                    return Err(RefRefusal::NotProgrammeManager);
                }
                Ok(vec![RefEvent::Requested { by, revision }])
            }
            RefCommand::Approve { by, base } => {
                draft_open(d)?;
                let revision = at_head(base)?;
                if !s.admins.contains(&by) {
                    return Err(RefRefusal::NotTenantAdmin);
                }
                if d.builders.contains(&by) {
                    return Err(RefRefusal::ApproverIsBuilder);
                }
                if !s.vault.is_verified(by) {
                    return Err(RefRefusal::ApproverUnverified);
                }
                if s.vault.same_identity_as_any(by, &d.builders) {
                    return Err(RefRefusal::SameIdentity);
                }
                if !d.request_live() {
                    return Err(RefRefusal::NoLiveRequest);
                }
                if let Some(r) = uncleared(&self.report(), d) {
                    return Err(r);
                }
                Ok(vec![RefEvent::Activated {
                    by,
                    revision,
                    inputs: self.env.clone(),
                }])
            }
            RefCommand::SetProbe { .. } | RefCommand::SetUnresolvedImports(_) => Ok(Vec::new()),
        }
    }

    /// Applies `cmd`: environment changes, or the records `decide` gives.
    pub fn apply(&mut self, cmd: &RefCommand) -> StepVerdict {
        match self.decide(cmd) {
            Err(r) => StepVerdict::Refused(r),
            Ok(events) => {
                match *cmd {
                    RefCommand::SetProbe { probe, outcome } => {
                        self.env.probes.insert(probe, outcome);
                    }
                    RefCommand::SetUnresolvedImports(n) => self.env.unresolved_imports = n,
                    _ => {}
                }
                for e in events {
                    self.draft.apply(&e);
                    self.events.push(e);
                }
                StepVerdict::Accepted
            }
        }
    }
}

/// The core guard of `ActivateProgramme` (D2), as the reference reads it:
/// the actor is a tenant admin, outside `programme_builders(state)` and
/// the creator's builder set, and shares no verified identity with
/// either. It runs whatever the creator decided (defence in depth).
pub fn core_guard(
    stat: &RefStatic,
    core_builders: &BTreeSet<AccountId>,
    creator_builders: &BTreeSet<AccountId>,
    actor: AccountId,
) -> Result<(), RefRefusal> {
    if !stat.admins.contains(&actor) {
        return Err(RefRefusal::NotTenantAdmin);
    }
    let all: BTreeSet<AccountId> = core_builders.union(creator_builders).copied().collect();
    if all.contains(&actor) {
        return Err(RefRefusal::ApproverIsBuilder);
    }
    if stat.vault.same_identity_as_any(actor, &all) {
        return Err(RefRefusal::SameIdentity);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The synthetic cast and plans
// ---------------------------------------------------------------------------

/// Tenant admin A1 of design section 2.1. Opens the draft.
pub const TA: AccountId = AccountId::from_raw(0xA1);
/// Tenant admin A2 of design section 2.1. Approves activation.
pub const TB: AccountId = AccountId::from_raw(0xA2);
/// Programme manager M1 on the draft. Builds it.
pub const M1: AccountId = AccountId::from_raw(0xB1);
/// A second programme manager, granted during the build or never.
pub const M2: AccountId = AccountId::from_raw(0xB2);
/// A second account of M1's person (T-SOD-SYBIL shape). It is a tenant
/// admin in the plans that use it.
pub const SYBIL: AccountId = AccountId::from_raw(0xC1);

/// The person labels of the cast.
const PERSON_TA: u32 = 1;
const PERSON_TB: u32 = 2;
const PERSON_M1: u32 = 3;
const PERSON_M2: u32 = 4;

/// Every cast member verified, each a separate person, SYBIL unknown.
pub fn cast_vault() -> RefVault {
    RefVault::new()
        .with(TA, PERSON_TA, true)
        .with(TB, PERSON_TB, true)
        .with(M1, PERSON_M1, true)
        .with(M2, PERSON_M2, true)
}

/// A clean plan: A1 opens, the admins are A1 and A2, M1 builds, the cap
/// equals the ceiling, wording is approved, the default theme passes and
/// every probe passes. A2's approval after M1's request clears it.
pub fn clean_plan() -> DraftPlan {
    DraftPlan {
        opener: TA,
        stat: RefStatic {
            admins: [TA, TB].into_iter().collect(),
            vault: cast_vault(),
            cap: RefCap::SUPERSAFE,
            wording_pending: false,
            theme_faults: BTreeSet::new(),
        },
        managers: vec![M1],
        seeds: BTreeSet::new(),
        env: RefInputs::passing(),
    }
}

/// The clean plan with `check` seeded through the facts it reads.
///
/// For `TooFewTenantAdmins` the opener is the only admin, so no eligible
/// approver exists. For `BuilderUnverified` the opener A1 is unverified.
/// A grant needs only the grantee verified (SoD-09), so A1 still grants
/// M1.
pub fn seeded_plan(check: RefCheck) -> DraftPlan {
    let mut p = clean_plan();
    match check.feed() {
        CheckFeed::Content => {
            p.seeds.insert(check);
        }
        CheckFeed::Cap => {
            p.stat.cap = RefCap {
                p05_minor: 40_000_000,
                p58_minor: 30_000_000,
            };
        }
        CheckFeed::Probe(probe) => {
            p.env = p.env.with_probe(probe, RefProbeOutcome::Fail);
        }
        CheckFeed::Imports => p.env.unresolved_imports = 1,
        CheckFeed::Wording => p.stat.wording_pending = true,
        CheckFeed::AdminSet => {
            p.stat.admins = [TA].into_iter().collect();
        }
        CheckFeed::BuilderVault => {
            p.stat.vault = p.stat.vault.clone().with(TA, PERSON_TA, false);
        }
        CheckFeed::Theme => {
            p.stat.theme_faults.insert(check);
        }
    }
    p
}

/// The setup save of `plan`'s P-05 and P-58 by its first manager, or by
/// its opener without one, in this vocabulary: a policy edit at the head
/// that changes no content check. [`RefSystem::open`] names it when I-50
/// refuses it at save.
pub fn cap_save(plan: &DraftPlan) -> RefCommand {
    RefCommand::Edit {
        by: plan.managers.first().copied().unwrap_or(plan.opener),
        kind: EditKind::Policy,
        effect: RefEdit::Neutral,
        base: Base::Head,
    }
}

/// One activation attempt: the plan, whether the first manager
/// acknowledges every warning the report shows before the request, the
/// environment at approval, and the approver.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attempt {
    /// The draft plan.
    pub plan: DraftPlan,
    /// Whether the first manager acknowledges every warning before the
    /// request.
    pub acknowledge: bool,
    /// The environment the approval request runs its probes in.
    pub approval_env: RefInputs,
    /// The approver.
    pub approver: AccountId,
}

impl Attempt {
    /// A2 approves `plan` after M1 acknowledges every warning and
    /// requests, in the plan's own environment.
    pub fn by_second_admin(plan: DraftPlan) -> Attempt {
        let env = plan.env.clone();
        Attempt {
            plan,
            acknowledge: true,
            approval_env: env,
            approver: TB,
        }
    }
}

/// What one attempt showed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptOutcome {
    /// The report at the request, in the plan's environment.
    pub report_at_request: RefReport,
    /// The report recomputed in the approval environment.
    pub report_at_approval: RefReport,
    /// The approval's verdict.
    pub verdict: StepVerdict,
}

/// Why an attempt could not run: a setup command was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupRefused {
    /// The refused command.
    pub command: RefCommand,
    /// The reason.
    pub refusal: RefRefusal,
}

/// Runs `attempt` on the reference: open, grant and seed, acknowledge,
/// request, switch to the approval environment, approve.
pub fn run_attempt(attempt: &Attempt) -> Result<AttemptOutcome, SetupRefused> {
    let mut s = RefSystem::open(&attempt.plan)
        .map_err(|(command, refusal)| SetupRefused { command, refusal })?;
    let builder = attempt
        .plan
        .managers
        .first()
        .copied()
        .unwrap_or(attempt.plan.opener);
    if attempt.acknowledge {
        let warnings: Vec<RefCheck> = s
            .report()
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
            if let StepVerdict::Refused(refusal) = s.apply(&cmd) {
                return Err(SetupRefused {
                    command: cmd,
                    refusal,
                });
            }
        }
    }
    let request = RefCommand::Request {
        by: builder,
        base: Base::Head,
    };
    if let StepVerdict::Refused(refusal) = s.apply(&request) {
        return Err(SetupRefused {
            command: request,
            refusal,
        });
    }
    let report_at_request = s.report();
    s.env = attempt.approval_env.clone();
    let report_at_approval = s.report();
    let verdict = s.apply(&RefCommand::Approve {
        by: attempt.approver,
        base: Base::Head,
    });
    Ok(AttemptOutcome {
        report_at_request,
        report_at_approval,
        verdict,
    })
}

// ---------------------------------------------------------------------------
// The contrast tables, recomputed with floats
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contrast_tables {
    /// The sRGB transfer function of WCAG 2.2, from an 8-bit channel value
    /// to its linear value.
    #[allow(clippy::float_arithmetic)]
    fn linear(c: u8) -> f64 {
        let s = f64::from(c) / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }

    /// I-70, M4 design 3.2 "Contrast without floats" and 8.8: both tables
    /// of `fstp-creator`, recomputed with `f64`, enclose each channel's
    /// linear value with a margin of at least 10^-9 on each side.
    #[test]
    #[allow(clippy::float_arithmetic, clippy::cast_precision_loss)]
    fn i70_contrast_bounds_enclose_f64_values() {
        const SCALE: f64 = 1e12;
        const MARGIN: f64 = 1e-9;
        for c in 0..=u8::MAX {
            let v = linear(c);
            let (lower, upper) = fstp_creator::linear_bounds(c);
            // Both bounds are below 2^53, so the casts are exact.
            let lower = lower as f64 / SCALE;
            let upper = upper as f64 / SCALE;
            assert!(
                lower <= v - MARGIN,
                "channel {c}: the lower bound {lower} is not 10^-9 below {v}"
            );
            assert!(
                upper >= v + MARGIN,
                "channel {c}: the upper bound {upper} is not 10^-9 above {v}"
            );
        }
    }
}
