//! The operation registry (M4 design section 3.6, I-84, I-85).
//!
//! [`OPS`] holds every operation of the M4 journeys J0 to J10 up to
//! NEGOTIATION. It is the only tool table: each [`ToolDef`] sits on the
//! operation it performs, and `fstp-api-core::meta::tools()` serves them.
//! Every operation has one web route, so no tool exists that the user's
//! roles could not perform in the interface.
//!
//! Routes are relative to `/api/v1`, except the public pages, whose paths
//! start with `/p/` and are served without the API prefix.
//!
//! Interim, pending Daniel (design section 15.0): the tool table follows
//! the capability table of `mcp-server.md` only (Q8), the one prepare-only
//! tool is `fstp_prepare_call_publication` (Q32), and every tenant setting
//! is high-risk (Q10).
//!
//! Lane m4reg added the operations the M4 demo pages call that the
//! journey tables leave out or that waited for change D5:
//!
//! - the committee ballots `committee.open_round`, `committee.cast` and
//!   `committee.delegate`, with the names and routes of journey J7;
//! - the reads `tenant.list_admins`, `me.get_verification`,
//!   `creator.list_programmes`, `creator.list_templates`,
//!   `people.get_invitation` and `review.assignments`.
//!
//! Interim, pending Daniel: the design names none of these six reads.
//! Each takes the name its page calls, and its route sits beside the
//! write of the same screen.
//!
//! The interim home page of design section 15.0 (2026-10-31) added the
//! read `me.roles`: the caller's own active roles, web only (I-86).
//!
//! SoD-09: the invitation landing, its acceptance and its verification
//! address the invitation by the token of its link, `{invitation_token}`,
//! never by its decimal id. The landing admits a caller with no account,
//! so a guessable id would let anyone enumerate invitations.

use fstp_domain::CommandKind;
use fstp_domain::roles::Role;

/// An OAuth scope issued in M4 (design section 3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// `calls:read`.
    CallsRead,
    /// `proposals:read`.
    ProposalsRead,
    /// `proposals:draft`.
    ProposalsDraft,
    /// `proposals:binding`.
    ProposalsBinding,
    /// `stage2:draft`.
    Stage2Draft,
    /// `review:read`.
    ReviewRead,
    /// `review:draft`.
    ReviewDraft,
    /// `ranking:read`.
    RankingRead,
    /// `findings:read`.
    FindingsRead,
    /// `creator:draft`.
    CreatorDraft,
    /// `calls:draft`.
    CallsDraft,
    /// `audit:read`.
    AuditRead,
}

impl Scope {
    /// Every scope, in declaration order.
    pub const ALL: [Scope; 12] = [
        Scope::CallsRead,
        Scope::ProposalsRead,
        Scope::ProposalsDraft,
        Scope::ProposalsBinding,
        Scope::Stage2Draft,
        Scope::ReviewRead,
        Scope::ReviewDraft,
        Scope::RankingRead,
        Scope::FindingsRead,
        Scope::CreatorDraft,
        Scope::CallsDraft,
        Scope::AuditRead,
    ];

    /// The scope as the OAuth server spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::CallsRead => "calls:read",
            Scope::ProposalsRead => "proposals:read",
            Scope::ProposalsDraft => "proposals:draft",
            Scope::ProposalsBinding => "proposals:binding",
            Scope::Stage2Draft => "stage2:draft",
            Scope::ReviewRead => "review:read",
            Scope::ReviewDraft => "review:draft",
            Scope::RankingRead => "ranking:read",
            Scope::FindingsRead => "findings:read",
            Scope::CreatorDraft => "creator:draft",
            Scope::CallsDraft => "calls:draft",
            Scope::AuditRead => "audit:read",
        }
    }
}

/// How an MCP response classifies its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    /// Public data.
    Public,
    /// Confidential data.
    Confidential,
    /// Personal data.
    Personal,
}

impl Classification {
    /// The classification as responses spell it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Classification::Public => "public",
            Classification::Confidential => "confidential",
            Classification::Personal => "personal",
        }
    }
}

/// An HTTP method of a web route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// The method as HTTP spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

/// The session strength an operation needs (I-77).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionNeed {
    /// Any session, magic links and OPAQUE included. An account that I-77
    /// covers still needs a phishing-resistant one (`session_admits`).
    Any,
    /// A passkey or EUDI Wallet session only.
    PhishingResistant,
}

impl SessionNeed {
    /// The need as the generated table spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionNeed::Any => "any",
            SessionNeed::PhishingResistant => "phishing_resistant",
        }
    }
}

/// A role through which an operation can be performed (P-74).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleOrApplicant {
    /// A role of `Role::ALL`.
    Role(Role),
    /// An account acting with no binding yet, such as a new applicant.
    Applicant,
}

/// A later milestone, for kinds whose operations arrive after M4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Milestone {
    /// M5: amounts, grants, contracts and payments.
    M5,
    /// M6: the timeline engine and notification dispatch.
    M6,
    /// M7: the assessor and document extraction.
    M7,
    /// M8: the Matrix and WhatsApp channels.
    M8,
    /// M9: exports, white labelling and the directory.
    M9,
}

/// A creator operation kind (design section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CreatorKind {
    /// `CreatorCommand::OpenDraft`, which carries the core `CreateProgramme`.
    OpenDraft,
    /// `CreatorCommand::ApplyStart`.
    ApplyStart,
    /// `CreatorCommand::SaveFields`, which compiles to one core `EditPolicy`.
    SaveFields,
    /// `CreatorCommand::AcceptNarrative`.
    AcceptNarrative,
    /// `CreatorCommand::Invite`.
    Invite,
    /// `CreatorCommand::WithdrawInvitation`.
    WithdrawInvitation,
    /// `CreatorCommand::AcknowledgeWarning`.
    AcknowledgeWarning,
    /// `CreatorCommand::RequestActivation`.
    RequestActivation,
    /// `CreatorCommand::ApproveActivation`. It composes the core activation.
    ApproveActivation,
    /// `CreatorCommand::SaveAsTenantTemplate`.
    SaveAsTenantTemplate,
}

/// An engine bridge operation kind (design section 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BridgeKind {
    /// `BridgeCommand::ResolveImport` (I-65).
    ResolveImport,
}

/// A tenant-level parameter that M4 can set (design section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantParam {
    /// P-20, payment mode.
    P20,
    /// P-69, template licence.
    P69,
    /// P-70, login methods.
    P70,
    /// P-71, step-up freshness.
    P71,
    /// P-72, session lifetimes.
    P72,
    /// P-74, the MCP server and its roles.
    P74,
}

/// A tenant operation kind (design section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantKind {
    /// `TenantCommand::SaveStep`.
    SaveStep,
    /// Finishing onboarding.
    Complete,
    /// `TenantCommand::InviteAdmin`.
    InviteAdmin,
    /// `TenantCommand::ApproveSelfGrant` (SoD-07).
    ApproveSelfGrant,
    /// `TenantCommand::SetSetting`, one operation per parameter.
    SetSetting(TenantParam),
    /// `TenantCommand::RecordInferenceConfig`, saved with the Inference
    /// onboarding step.
    RecordInferenceConfig,
    /// `TenantCommand::GrantSignatory` (NOTE 5).
    GrantSignatory,
    /// `TenantCommand::EndSignatory` (SoD-17).
    EndSignatory,
    /// `TenantCommand::RequestActivation` (SoD-14, SoD-15).
    RequestActivation,
    /// `TenantCommand::ApproveActivation` (SoD-18).
    ApproveActivation,
}

/// A finding operation kind, one per `FindingCommand` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    /// `FindingCommand::Record`, by the assessor only.
    Record,
    /// `FindingCommand::Mark`, by an assigned reviewer.
    Mark,
    /// `FindingCommand::Regenerate`, by the assessor only.
    Regenerate,
}

/// An import operation kind, one per `ImportCommand` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportKind {
    /// `ImportCommand::RegisterDocument`.
    RegisterDocument,
    /// `ImportCommand::RecordProposals`, by the proposer only.
    RecordProposals,
}

/// An agent operation kind (R-MC-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentKind {
    /// The OAuth consent, which links a device.
    Consent,
    /// Revoking an agent client.
    Revoke,
}

/// A pending action operation kind (I-85).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingKind {
    /// Confirming a pending action in the platform.
    Confirm,
    /// Discarding a pending action.
    Discard,
}

/// A public page, feed or public tool kind (I-87).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicKind {
    /// The programme page.
    Programme,
    /// The open calls of a programme.
    ListOpenCalls,
    /// One call page.
    Call,
    /// The Guide for Applicants of a call.
    Guide,
    /// The deadlines of the open calls.
    Deadlines,
    /// The eligibility rules of the open calls.
    Eligibility,
    /// Funded grants.
    Funded,
    /// Finished grants.
    Finished,
    /// The public feed (P-52).
    Feed,
}

/// An operation served by an M3 port (design section 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortKind {
    /// Identity verification of the caller through the vault.
    BeginVerification,
    /// Accepting an invitation and its confidentiality terms.
    AcceptInvitation,
    /// Identity verification of an invitee for SoD-09.
    BeginInvitationVerification,
    /// Guardian consent through the vault (I-18).
    BeginGuardianConsent,
    /// The country statement, to the vault only.
    StateCountry,
    /// The declared affiliations, to the vault only.
    DeclareAffiliations,
    /// The lead's date of birth, to the vault only (Q23 B).
    StateBirthDate,
    /// An autosave to the private workspace (I-21).
    SaveWorkspace,
    /// A request for a copy of the application (R-SB-04).
    RequestCopy,
    /// The acknowledgement of the negotiation notice (R-NG-06).
    AcknowledgeNegotiationNotice,
    /// Ending one of the caller's sessions (R-LG-04).
    EndSession,
    /// Adding a passkey.
    AddPasskey,
    /// Approving an account recovery (I-79).
    ApproveRecovery,
    /// Approving a break-glass request (SoD-08).
    ApproveBreakGlass,
}

/// The kind of an operation (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpKind {
    /// A core domain command.
    Command(CommandKind),
    /// A creator command.
    Creator(CreatorKind),
    /// An engine bridge command.
    Bridge(BridgeKind),
    /// A tenant command.
    Tenant(TenantKind),
    /// A finding command.
    Finding(FindingKind),
    /// An import command.
    Import(ImportKind),
    /// A read.
    Read(crate::reads::ReadKind),
    /// An agent operation.
    Agent(AgentKind),
    /// A pending action operation.
    Pending(PendingKind),
    /// A public page, feed or tool.
    Public(PublicKind),
    /// An operation served by an M3 port.
    M3Port(PortKind),
}

/// The input schema of a tool. Interim, pending ADR-013: it states the
/// route's path parameters, each a string, and whether the call carries a
/// request object. The operation's strict decoder in `fstp-api-core`
/// owns the members of that object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema {
    /// The path parameters, in route order.
    pub params: &'static [&'static str],
    /// Whether the call carries a request object.
    pub body: bool,
}

/// An MCP tool definition: fixed name, description and input schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolDef {
    /// The tool name.
    pub name: &'static str,
    /// The fixed description. It never holds tenant text (TH-63).
    pub description: &'static str,
    /// The input schema.
    pub input: &'static Schema,
    /// The scope the tool needs. Public tools need no token, so the MCP
    /// channel never checks it for them.
    pub scope: Scope,
    /// Whether the tool only prepares a pending action (I-85). Only
    /// high-risk operations have one.
    pub prepare_only: bool,
}

/// One operation of the registry (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpSpec {
    /// The operation name the journeys use, such as `call.publish`. The
    /// generated TypeScript table keys on it.
    pub name: &'static str,
    /// The kind.
    pub kind: OpKind,
    /// The web route. Every human operation has one.
    pub route: Option<(Method, &'static str)>,
    /// The MCP tool, if the operation has one. The only tool table.
    pub tool: Option<ToolDef>,
    /// Whether the operation is high-risk (I-78). It equals
    /// `CommandKind::high_risk` for command operations.
    pub high_risk: bool,
    /// Whether the operation is binding under P-77 (R-MC-05). It equals
    /// `CommandKind::binding_action` for command operations.
    pub binding: bool,
    /// The session strength it needs (I-77).
    pub session: SessionNeed,
    /// The OAuth scope it needs through MCP. Public operations need none.
    pub scope: Option<Scope>,
    /// The roles through which it can be performed (P-74).
    pub acting: &'static [RoleOrApplicant],
    /// How MCP responses classify its data.
    pub classification: Classification,
}

use RoleOrApplicant::{Applicant as NoBinding, Role as R};

/// Every role, and an account with no binding.
const EVERY: &[RoleOrApplicant] = &[
    NoBinding,
    R(Role::ProgrammeManager),
    R(Role::CallDrafter),
    R(Role::FstpCoordinator),
    R(Role::CommitteeMember),
    R(Role::CommitteeChair),
    R(Role::IrcMember),
    R(Role::Applicant),
    R(Role::ApplicantTeamMember),
    R(Role::Guardian),
    R(Role::TenantAdmin),
    R(Role::FinanceApprover),
    R(Role::PaymentReleaser),
    R(Role::ContractSignatory),
    R(Role::FinancialSignatory),
    R(Role::LegalSignatory),
    R(Role::Auditor),
];
const ADMIN: &[RoleOrApplicant] = &[R(Role::TenantAdmin)];
const MANAGER: &[RoleOrApplicant] = &[R(Role::ProgrammeManager)];
const MANAGER_OR_ADMIN: &[RoleOrApplicant] = &[R(Role::ProgrammeManager), R(Role::TenantAdmin)];
const CALL_AUTHOR: &[RoleOrApplicant] = &[R(Role::ProgrammeManager), R(Role::CallDrafter)];
const CALL_STAFF: &[RoleOrApplicant] = &[
    R(Role::ProgrammeManager),
    R(Role::CallDrafter),
    R(Role::FstpCoordinator),
];
const COORDINATOR: &[RoleOrApplicant] = &[R(Role::FstpCoordinator)];
const NEW_APPLICANT: &[RoleOrApplicant] = &[
    NoBinding,
    R(Role::Applicant),
    R(Role::ApplicantTeamMember),
    R(Role::Guardian),
];
const LEAD: &[RoleOrApplicant] = &[R(Role::Applicant)];
const TEAM: &[RoleOrApplicant] = &[
    R(Role::Applicant),
    R(Role::ApplicantTeamMember),
    R(Role::Guardian),
];
const GUARDIAN: &[RoleOrApplicant] = &[R(Role::Guardian)];
const REVIEWER: &[RoleOrApplicant] = &[R(Role::CommitteeMember)];
const CONTENT: &[RoleOrApplicant] = &[
    R(Role::Applicant),
    R(Role::ApplicantTeamMember),
    R(Role::Guardian),
    R(Role::FstpCoordinator),
    R(Role::CommitteeMember),
    R(Role::IrcMember),
];
const DECLARANT: &[RoleOrApplicant] = &[
    R(Role::FstpCoordinator),
    R(Role::CommitteeMember),
    R(Role::IrcMember),
];
const COMMITTEE: &[RoleOrApplicant] = &[R(Role::CommitteeMember), R(Role::CommitteeChair)];
const IRC: &[RoleOrApplicant] = &[R(Role::IrcMember)];
const AUDITOR: &[RoleOrApplicant] = &[R(Role::Auditor)];
/// The roles of the section 7.2 matrix: every role but call drafter and
/// tenant admin (lane j2).
const JOURNEY: &[RoleOrApplicant] = &[
    R(Role::Applicant),
    R(Role::ApplicantTeamMember),
    R(Role::Guardian),
    R(Role::FstpCoordinator),
    R(Role::ProgrammeManager),
    R(Role::CommitteeMember),
    R(Role::CommitteeChair),
    R(Role::IrcMember),
    R(Role::FinanceApprover),
    R(Role::PaymentReleaser),
    R(Role::ContractSignatory),
    R(Role::Auditor),
];

const IN_NONE: Schema = Schema {
    params: &[],
    body: false,
};
const IN_PROGRAMME: Schema = Schema {
    params: &["programme"],
    body: false,
};
const IN_PROGRAMME_BODY: Schema = Schema {
    params: &["programme"],
    body: true,
};
const IN_CALL: Schema = Schema {
    params: &["call"],
    body: false,
};
const IN_CALL_BODY: Schema = Schema {
    params: &["call"],
    body: true,
};
const IN_SLUG: Schema = Schema {
    params: &["slug"],
    body: false,
};
const IN_SLUG_CALL: Schema = Schema {
    params: &["slug", "call"],
    body: false,
};
const IN_PROPOSAL: Schema = Schema {
    params: &["proposal"],
    body: false,
};
const IN_PROPOSAL_BODY: Schema = Schema {
    params: &["proposal"],
    body: true,
};
const IN_ASSIGNMENT: Schema = Schema {
    params: &["assignment"],
    body: false,
};
const IN_ASSIGNMENT_BODY: Schema = Schema {
    params: &["assignment"],
    body: true,
};
const IN_ASSIGNMENT_SCORE_BODY: Schema = Schema {
    params: &["assignment", "score"],
    body: true,
};

impl OpSpec {
    /// A plain operation: no tool, not high-risk, not binding, any session,
    /// open to every role, confidential.
    const fn new(name: &'static str, kind: OpKind, method: Method, path: &'static str) -> OpSpec {
        OpSpec {
            name,
            kind,
            route: Some((method, path)),
            tool: None,
            high_risk: false,
            binding: false,
            session: SessionNeed::Any,
            scope: None,
            acting: EVERY,
            classification: Classification::Confidential,
        }
    }

    /// A core command operation. `high_risk` and `binding` follow the
    /// domain's functions, and a high-risk command needs a
    /// phishing-resistant session.
    const fn command(
        name: &'static str,
        kind: CommandKind,
        method: Method,
        path: &'static str,
    ) -> OpSpec {
        let op = OpSpec::new(name, OpKind::Command(kind), method, path);
        let op = if kind.high_risk() { op.hr() } else { op };
        OpSpec {
            binding: kind.binding_action(),
            ..op
        }
    }

    /// A read operation.
    const fn read(name: &'static str, kind: crate::reads::ReadKind, path: &'static str) -> OpSpec {
        OpSpec::new(name, OpKind::Read(kind), Method::Get, path)
    }

    /// A public page or feed: public data for anyone, with no session rule.
    const fn public(name: &'static str, kind: PublicKind, path: &'static str) -> OpSpec {
        OpSpec {
            classification: Classification::Public,
            ..OpSpec::new(name, OpKind::Public(kind), Method::Get, path)
        }
    }

    /// High-risk (I-78), so a phishing-resistant session only.
    const fn hr(self) -> OpSpec {
        OpSpec {
            high_risk: true,
            session: SessionNeed::PhishingResistant,
            ..self
        }
    }

    /// Binding under P-77, for an operation that is not a core command.
    const fn binding(self) -> OpSpec {
        OpSpec {
            binding: true,
            ..self
        }
    }

    /// The roles through which the operation acts.
    const fn acting(self, acting: &'static [RoleOrApplicant]) -> OpSpec {
        OpSpec { acting, ..self }
    }

    /// The classification of its data.
    const fn class(self, classification: Classification) -> OpSpec {
        OpSpec {
            classification,
            ..self
        }
    }

    /// The operation's tool. A tool on a high-risk operation is
    /// prepare-only (I-85), so call this after `hr`. A public operation
    /// keeps no scope, since public tools need no token.
    const fn tool(
        self,
        name: &'static str,
        description: &'static str,
        input: &'static Schema,
        scope: Scope,
    ) -> OpSpec {
        let public = matches!(self.kind, OpKind::Public(_));
        OpSpec {
            tool: Some(ToolDef {
                name,
                description,
                input,
                scope,
                prepare_only: self.high_risk,
            }),
            scope: if public { None } else { Some(scope) },
            ..self
        }
    }
}

use crate::reads::ReadKind as RK;
use Classification::{Personal, Public};
use CommandKind as CK;
use Method::{Delete, Post, Put};

/// Every operation of M4 (design section 2.2, journeys J0 to J10).
pub const OPS: &[OpSpec] = &[
    // J0 and J10: tenant onboarding, settings and admin approvals.
    OpSpec::new(
        "me.begin_verification",
        OpKind::M3Port(PortKind::BeginVerification),
        Post,
        "/me/verification",
    )
    .class(Personal),
    OpSpec::read(
        "tenant.get_step",
        RK::GetOnboarding,
        "/admin/onboarding/{step}",
    )
    .acting(ADMIN),
    OpSpec::new(
        "tenant.save_step",
        OpKind::Tenant(TenantKind::SaveStep),
        Put,
        "/admin/onboarding/{step}",
    )
    .acting(ADMIN),
    OpSpec::new(
        "tenant.complete",
        OpKind::Tenant(TenantKind::Complete),
        Post,
        "/admin/onboarding/complete",
    )
    .acting(ADMIN),
    OpSpec::read("tenant.settings", RK::GetTenantSettings, "/admin/settings").acting(ADMIN),
    OpSpec::new(
        "tenant.invite_admin",
        OpKind::Tenant(TenantKind::InviteAdmin),
        Post,
        "/admin/admins",
    )
    .hr()
    .acting(ADMIN),
    // SoD-07: onboarding finishes only with two verified admins, so the
    // Administrators step lists them.
    OpSpec::read("tenant.list_admins", RK::ListTenantAdmins, "/admin/admins")
        .acting(ADMIN)
        .class(Personal),
    // NOTE 5, SoD-14 to SoD-17: the tenant-wide signatory roles. Granting or
    // ending one changes an Operations role, so each is high-risk (I-78).
    OpSpec::read(
        "tenant.list_signatories",
        RK::ListSignatories,
        "/admin/signatories",
    )
    .acting(ADMIN)
    .class(Personal),
    OpSpec::new(
        "tenant.grant_signatory",
        OpKind::Tenant(TenantKind::GrantSignatory),
        Post,
        "/admin/signatories",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "tenant.end_signatory",
        OpKind::Tenant(TenantKind::EndSignatory),
        Delete,
        "/admin/signatories/{role}/{account}",
    )
    .hr()
    .acting(ADMIN),
    // SoD-18: one tenant admin requests activation and another approves
    // it, by analogy with I-67. The high-risk table of `authentication.md`
    // names programme activation but not the organisation's, so neither
    // is high-risk (interim, pending Daniel).
    OpSpec::read("tenant.get_activation", RK::GetActivation, "/admin/activation")
        .acting(ADMIN),
    OpSpec::new(
        "tenant.request_activation",
        OpKind::Tenant(TenantKind::RequestActivation),
        Post,
        "/admin/activation",
    )
    .acting(ADMIN),
    OpSpec::new(
        "tenant.approve_activation",
        OpKind::Tenant(TenantKind::ApproveActivation),
        Post,
        "/admin/activation/approval",
    )
    .acting(ADMIN),
    // I-86: the caller's own verification state, never through MCP.
    OpSpec::read(
        "me.get_verification",
        RK::GetMyVerification,
        "/me/verification",
    )
    .class(Personal),
    OpSpec::new(
        "tenant.set_login_methods",
        OpKind::Tenant(TenantKind::SetSetting(TenantParam::P70)),
        Put,
        "/admin/settings/login-methods",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "tenant.set_step_up_freshness",
        OpKind::Tenant(TenantKind::SetSetting(TenantParam::P71)),
        Put,
        "/admin/settings/step-up-freshness",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "tenant.set_session_lifetimes",
        OpKind::Tenant(TenantKind::SetSetting(TenantParam::P72)),
        Put,
        "/admin/settings/session-lifetimes",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "tenant.set_mcp",
        OpKind::Tenant(TenantKind::SetSetting(TenantParam::P74)),
        Put,
        "/admin/settings/mcp",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "tenant.set_payment_mode",
        OpKind::Tenant(TenantKind::SetSetting(TenantParam::P20)),
        Put,
        "/admin/settings/payment-mode",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "tenant.set_template_licence",
        OpKind::Tenant(TenantKind::SetSetting(TenantParam::P69)),
        Put,
        "/admin/settings/template-licence",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::read("admin.approvals", RK::ListApprovals, "/admin/approvals").acting(ADMIN),
    OpSpec::new(
        "admin.approve_self_grant",
        OpKind::Tenant(TenantKind::ApproveSelfGrant),
        Post,
        "/admin/approvals/{approval}",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "admin.approve_recovery",
        OpKind::M3Port(PortKind::ApproveRecovery),
        Post,
        "/admin/recoveries/{recovery}/approval",
    )
    .hr()
    .acting(ADMIN),
    OpSpec::new(
        "admin.approve_break_glass",
        OpKind::M3Port(PortKind::ApproveBreakGlass),
        Post,
        "/admin/break-glass/{break_glass}/approval",
    )
    .hr()
    .acting(ADMIN),
    // J1: the creator and import.
    OpSpec::new(
        "creator.open_draft",
        OpKind::Creator(CreatorKind::OpenDraft),
        Post,
        "/programmes",
    )
    .hr()
    .acting(ADMIN),
    // R-PG-02: the clone sources and the template catalogue of the
    // creator start page.
    OpSpec::read(
        "creator.list_programmes",
        RK::ListProgrammes,
        "/programmes",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::read("creator.list_templates", RK::ListTemplates, "/templates")
        .acting(MANAGER_OR_ADMIN),
    OpSpec::new(
        "creator.invite",
        OpKind::Creator(CreatorKind::Invite),
        Post,
        "/programmes/{programme}/invitations",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::new(
        "creator.withdraw_invitation",
        OpKind::Creator(CreatorKind::WithdrawInvitation),
        Delete,
        "/programmes/{programme}/invitations/{invitation}",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::read(
        "creator.invitations",
        RK::ListInvitations,
        "/programmes/{programme}/invitations",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::new(
        "creator.apply_start",
        OpKind::Creator(CreatorKind::ApplyStart),
        Post,
        "/programmes/{programme}/draft/start",
    )
    .acting(MANAGER),
    OpSpec::new(
        "creator.save_fields",
        OpKind::Creator(CreatorKind::SaveFields),
        Put,
        "/programmes/{programme}/draft/fields",
    )
    .acting(MANAGER)
    .tool(
        "fstp_creator_save_fields",
        "Save field values of a draft programme. The values stay a draft until a person requests activation in the platform.",
        &IN_PROGRAMME_BODY,
        Scope::CreatorDraft,
    ),
    // TH-49: template text applies only once the manager accepts it.
    OpSpec::new(
        "creator.accept_narrative",
        OpKind::Creator(CreatorKind::AcceptNarrative),
        Post,
        "/programmes/{programme}/draft/narratives/{field}/acceptance",
    )
    .acting(MANAGER),
    OpSpec::read(
        "creator.get_draft",
        RK::GetDraft,
        "/programmes/{programme}/draft",
    )
    .acting(MANAGER_OR_ADMIN)
    .tool(
        "fstp_creator_get_draft",
        "Read the fields of a draft programme.",
        &IN_PROGRAMME,
        Scope::CreatorDraft,
    ),
    OpSpec::read(
        "creator.get_report",
        RK::GetReport,
        "/programmes/{programme}/draft/report",
    )
    .acting(MANAGER_OR_ADMIN)
    .tool(
        "fstp_creator_get_report",
        "Read the validation report of a draft programme.",
        &IN_PROGRAMME,
        Scope::CreatorDraft,
    ),
    OpSpec::new(
        "creator.acknowledge",
        OpKind::Creator(CreatorKind::AcknowledgeWarning),
        Post,
        "/programmes/{programme}/draft/acknowledgements",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::read(
        "creator.preview",
        RK::GetPreview,
        "/programmes/{programme}/draft/previews/{preview}",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::read(
        "creator.impact",
        RK::GetImpact,
        "/programmes/{programme}/draft/impact",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::new(
        "creator.request_activation",
        OpKind::Creator(CreatorKind::RequestActivation),
        Post,
        "/programmes/{programme}/activation-request",
    )
    .acting(MANAGER),
    OpSpec::new(
        "creator.approve_activation",
        OpKind::Creator(CreatorKind::ApproveActivation),
        Post,
        "/programmes/{programme}/activation",
    )
    .hr()
    .acting(ADMIN),
    // R-PG-05: a tenant-private template only (Q17 interim).
    OpSpec::new(
        "creator.save_as_template",
        OpKind::Creator(CreatorKind::SaveAsTenantTemplate),
        Post,
        "/programmes/{programme}/templates",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::new(
        "import.upload",
        OpKind::Import(ImportKind::RegisterDocument),
        Post,
        "/programmes/{programme}/imports",
    )
    .acting(MANAGER),
    OpSpec::read(
        "import.list",
        RK::ListImportProposals,
        "/programmes/{programme}/imports/proposals",
    )
    .acting(MANAGER_OR_ADMIN),
    OpSpec::new(
        "import.resolve",
        OpKind::Bridge(BridgeKind::ResolveImport),
        Post,
        "/programmes/{programme}/imports/proposals/{import_proposal}/resolution",
    )
    .acting(MANAGER),
    // J1 and J2: people and roles. SoD-09: the invitation landing, read
    // before the invitee enrols. The link token is its only capability.
    OpSpec::read(
        "people.get_invitation",
        RK::GetInvitation,
        "/invitations/{invitation_token}",
    )
    .class(Personal),
    OpSpec::new(
        "people.accept_invitation",
        OpKind::M3Port(PortKind::AcceptInvitation),
        Post,
        "/invitations/{invitation_token}/accept",
    )
    .class(Personal),
    OpSpec::new(
        "people.begin_verification",
        OpKind::M3Port(PortKind::BeginInvitationVerification),
        Post,
        "/invitations/{invitation_token}/verification",
    )
    .class(Personal),
    OpSpec::read(
        "roles.list",
        RK::ListBindings,
        "/programmes/{programme}/roles",
    )
    .acting(ADMIN),
    OpSpec::command(
        "roles.grant",
        CK::GrantRole,
        Post,
        "/programmes/{programme}/roles",
    )
    .acting(ADMIN),
    OpSpec::command(
        "roles.end",
        CK::EndRole,
        Post,
        "/programmes/{programme}/roles/{binding}/end",
    )
    .acting(ADMIN),
    OpSpec::command(
        "roles.reinstate",
        CK::ReinstateBinding,
        Post,
        "/programmes/{programme}/roles/{binding}/reinstatement",
    )
    .acting(ADMIN),
    // J3: calls.
    OpSpec::command(
        "call.draft",
        CK::DraftCall,
        Post,
        "/programmes/{programme}/calls",
    )
    .acting(CALL_AUTHOR)
    .tool(
        "fstp_draft_call",
        "Draft a call of an active programme.",
        &IN_PROGRAMME_BODY,
        Scope::CallsDraft,
    ),
    OpSpec::command("call.edit", CK::EditCall, Put, "/calls/{call}")
        .acting(CALL_AUTHOR)
        .tool(
            "fstp_edit_call",
            "Edit the text, dates or budget of a call that is not yet published.",
            &IN_CALL_BODY,
            Scope::CallsDraft,
        ),
    OpSpec::command(
        "call.approve",
        CK::ApproveCallPublication,
        Post,
        "/calls/{call}/approval",
    )
    .acting(MANAGER),
    OpSpec::command(
        "call.publish",
        CK::PublishCall,
        Post,
        "/calls/{call}/publication",
    )
    .acting(MANAGER)
    .tool(
        "fstp_prepare_call_publication",
        "Prepare the publication of an approved call. The user confirms it in the platform with a step-up.",
        &IN_CALL_BODY,
        Scope::CallsDraft,
    ),
    OpSpec::read("call.board", RK::GetCallBoard, "/calls/{call}/board")
        .acting(CALL_STAFF)
        .tool(
            "fstp_get_call_board",
            "Read the board of a call: its state, dates and proposal counts.",
            &IN_CALL,
            Scope::CallsRead,
        ),
    // J4: public pages, open calls and applicants.
    OpSpec::public("public.programme", PublicKind::Programme, "/p/{slug}").tool(
        "fstp_public_get_programme",
        "Read the public page of a programme.",
        &IN_SLUG,
        Scope::CallsRead,
    ),
    OpSpec::public(
        "public.list_open_calls",
        PublicKind::ListOpenCalls,
        "/p/{slug}/calls",
    )
    .tool(
        "fstp_public_list_open_calls",
        "List the open calls of a programme, as its public pages show them.",
        &IN_SLUG,
        Scope::CallsRead,
    ),
    OpSpec::public("public.call", PublicKind::Call, "/p/{slug}/calls/{call}").tool(
        "fstp_public_get_call",
        "Read the public page of a call.",
        &IN_SLUG_CALL,
        Scope::CallsRead,
    ),
    OpSpec::public(
        "public.guide",
        PublicKind::Guide,
        "/p/{slug}/calls/{call}/guide",
    )
    .tool(
        "fstp_public_get_guide",
        "Read the Guide for Applicants of a call.",
        &IN_SLUG_CALL,
        Scope::CallsRead,
    ),
    OpSpec::public("public.deadlines", PublicKind::Deadlines, "/p/{slug}/deadlines").tool(
        "fstp_public_get_deadlines",
        "Read the deadlines of the open calls of a programme.",
        &IN_SLUG,
        Scope::CallsRead,
    ),
    OpSpec::public(
        "public.eligibility",
        PublicKind::Eligibility,
        "/p/{slug}/eligibility",
    )
    .tool(
        "fstp_public_get_eligibility",
        "Read the eligibility rules of the open calls of a programme.",
        &IN_SLUG,
        Scope::CallsRead,
    ),
    OpSpec::public("public.funded", PublicKind::Funded, "/p/{slug}/funded").tool(
        "fstp_public_list_funded",
        "List the funded grants of a programme, as its public pages show them.",
        &IN_SLUG,
        Scope::CallsRead,
    ),
    OpSpec::public("public.finished", PublicKind::Finished, "/p/{slug}/finished").tool(
        "fstp_public_list_finished",
        "List the finished grants of a programme, as its public pages show them.",
        &IN_SLUG,
        Scope::CallsRead,
    ),
    OpSpec::public("public.feed", PublicKind::Feed, "/p/{slug}/feed"),
    OpSpec::read("calls.list_open", RK::ListOpenCalls, "/calls")
        .class(Public)
        .tool(
            "fstp_list_open_calls",
            "List the open calls of the tenant.",
            &IN_NONE,
            Scope::CallsRead,
        ),
    OpSpec::read("calls.get", RK::GetPublicCall, "/calls/{call}").class(Public),
    OpSpec::read("calls.guide", RK::GetGuide, "/calls/{call}/guide")
        .class(Public)
        .tool(
            "fstp_get_guide",
            "Read the Guide for Applicants of a call.",
            &IN_CALL,
            Scope::CallsRead,
        ),
    OpSpec::command(
        "proposal.create",
        CK::CreateDraft,
        Post,
        "/calls/{call}/proposals",
    )
    .acting(NEW_APPLICANT),
    OpSpec::read("proposal.list_own", RK::ListOwnProposals, "/me/proposals").tool(
        "fstp_list_my_proposals",
        "List the caller's own proposals.",
        &IN_NONE,
        Scope::ProposalsRead,
    ),
    OpSpec::read("proposal.view", RK::GetOwnProposal, "/proposals/{proposal}")
        .acting(TEAM)
        .tool(
            "fstp_get_my_proposal",
            "Read one of the caller's own proposals. Each read is recorded.",
            &IN_PROPOSAL,
            Scope::ProposalsRead,
        ),
    OpSpec::read(
        "proposal.get_workspace",
        RK::GetOwnWorkspace,
        "/proposals/{proposal}/workspace",
    )
    .acting(TEAM),
    OpSpec::new(
        "proposal.save_workspace",
        OpKind::M3Port(PortKind::SaveWorkspace),
        Put,
        "/proposals/{proposal}/workspace",
    )
    .acting(TEAM)
    .tool(
        "fstp_save_workspace",
        "Save a draft of the proposal form to the team's private workspace.",
        &IN_PROPOSAL_BODY,
        Scope::ProposalsDraft,
    ),
    OpSpec::command(
        "proposal.record_plan",
        CK::RecordPlanVersion,
        Put,
        "/proposals/{proposal}/plan",
    )
    .acting(LEAD)
    .tool(
        "fstp_record_plan_version",
        "Save a version of the proposal's work plan.",
        &IN_PROPOSAL_BODY,
        Scope::ProposalsDraft,
    ),
    OpSpec::command(
        "proposal.add_member",
        CK::AddTeamMember,
        Post,
        "/proposals/{proposal}/team",
    )
    .acting(LEAD),
    OpSpec::command(
        "proposal.add_guardian",
        CK::AddGuardian,
        Post,
        "/proposals/{proposal}/guardian",
    )
    .acting(LEAD),
    OpSpec::new(
        "proposal.state_country",
        OpKind::M3Port(PortKind::StateCountry),
        Put,
        "/proposals/{proposal}/vault/country",
    )
    .acting(LEAD)
    .class(Personal),
    OpSpec::new(
        "proposal.declare_affiliations",
        OpKind::M3Port(PortKind::DeclareAffiliations),
        Put,
        "/proposals/{proposal}/vault/affiliations",
    )
    .acting(LEAD)
    .class(Personal),
    // Q23 B (design section 15.0, 2026-11-06): the lead states a date of
    // birth at submission, to the vault only. No tool (I-86).
    OpSpec::new(
        "proposal.state_birth_date",
        OpKind::M3Port(PortKind::StateBirthDate),
        Put,
        "/proposals/{proposal}/vault/birth_date",
    )
    .acting(LEAD)
    .class(Personal),
    OpSpec::command(
        "proposal.submit",
        CK::Submit,
        Post,
        "/proposals/{proposal}/submission",
    )
    .acting(LEAD)
    .tool(
        "fstp_submit_proposal",
        "Submit a proposal. This is a binding action.",
        &IN_PROPOSAL_BODY,
        Scope::ProposalsBinding,
    ),
    OpSpec::new(
        "proposal.request_copy",
        OpKind::M3Port(PortKind::RequestCopy),
        Post,
        "/proposals/{proposal}/copy",
    )
    .acting(LEAD),
    OpSpec::read("me.notices", RK::GetOwnNotices, "/me/notices")
        .class(Personal)
        .tool(
            "fstp_list_notices",
            "List the caller's own notices, such as proposal outcomes.",
            &IN_NONE,
            Scope::ProposalsRead,
        ),
    OpSpec::read(
        "stage2.view",
        RK::GetOwnStage2Thread,
        "/proposals/{proposal}/stage2",
    )
    .acting(TEAM)
    .tool(
        "fstp_get_stage2_questions",
        "Read the stage 2 questions on one of the caller's own proposals.",
        &IN_PROPOSAL,
        Scope::ProposalsRead,
    ),
    OpSpec::command(
        "stage2.answer",
        CK::AnswerQuestions,
        Post,
        "/proposals/{proposal}/stage2/answers",
    )
    .acting(LEAD)
    .tool(
        "fstp_answer_stage2",
        "Answer the stage 2 questions on a proposal. This is a binding action.",
        &IN_PROPOSAL_BODY,
        Scope::Stage2Draft,
    ),
    OpSpec::command(
        "stage2.revise",
        CK::SubmitRevision,
        Post,
        "/proposals/{proposal}/stage2/revision",
    )
    .acting(LEAD)
    .tool(
        "fstp_submit_revision",
        "Submit the stage 2 revision of a proposal. This is a binding action.",
        &IN_PROPOSAL_BODY,
        Scope::ProposalsBinding,
    ),
    OpSpec::command(
        "proposal.withdraw",
        CK::Withdraw,
        Post,
        "/proposals/{proposal}/withdrawal",
    )
    .acting(LEAD),
    // Lane j2, `SPEC/12-journey-ui.md` section 10: the route position and
    // the diary of one proposal, for its team and permitted staff. Web
    // only until the journey MCP tools land (section 10 "MCP").
    OpSpec::read(
        "proposal.journey",
        RK::GetJourney,
        "/proposals/{proposal}/journey",
    )
    .acting(JOURNEY),
    OpSpec::read(
        "proposal.diary",
        RK::GetDiary,
        "/proposals/{proposal}/diary",
    )
    .acting(JOURNEY),
    OpSpec::new(
        "guardian.begin_consent",
        OpKind::M3Port(PortKind::BeginGuardianConsent),
        Post,
        "/proposals/{proposal}/guardian/consent",
    )
    .acting(GUARDIAN)
    .class(Personal),
    OpSpec::read(
        "negotiation.view",
        RK::GetNegotiationLanding,
        "/proposals/{proposal}/negotiation",
    )
    .acting(TEAM),
    OpSpec::new(
        "negotiation.acknowledge_notice",
        OpKind::M3Port(PortKind::AcknowledgeNegotiationNotice),
        Post,
        "/proposals/{proposal}/negotiation/notice",
    )
    .acting(LEAD),
    // J5: the FSTP coordinator.
    OpSpec::read("intake.queue", RK::GetIntakeQueue, "/calls/{call}/intake").acting(COORDINATOR),
    OpSpec::read(
        "review.declaration_view",
        RK::GetDeclarationView,
        "/proposals/{proposal}/declaration-view",
    )
    .acting(DECLARANT),
    OpSpec::command(
        "review.declare_proposal",
        CK::DeclareConflict,
        Post,
        "/proposals/{proposal}/coordinator-declaration",
    )
    .acting(COORDINATOR),
    OpSpec::read(
        "review.read_content",
        RK::GetContent,
        "/proposals/{proposal}/content",
    )
    .acting(CONTENT)
    .tool(
        "fstp_get_proposal_content",
        "Read the full content of a proposal. Each read is recorded, and P-75 decides whether a reviewer's agent may read it.",
        &IN_PROPOSAL,
        Scope::ReviewRead,
    ),
    OpSpec::command(
        "review.knock_out",
        CK::RecordKnockOut,
        Post,
        "/proposals/{proposal}/knock-out",
    )
    .acting(COORDINATOR),
    // R-AC-01: one proposal's assignments, for the assignment screen.
    OpSpec::read(
        "review.assignments",
        RK::ListProposalAssignments,
        "/proposals/{proposal}/assignments",
    )
    .acting(COORDINATOR),
    OpSpec::command(
        "review.assign",
        CK::Assign,
        Post,
        "/proposals/{proposal}/assignments",
    )
    .acting(COORDINATOR),
    OpSpec::command(
        "review.unassign",
        CK::Unassign,
        Delete,
        "/assignments/{assignment}",
    )
    .acting(COORDINATOR),
    OpSpec::command(
        "review.admit",
        CK::AdmitToStage1,
        Post,
        "/proposals/{proposal}/admission",
    )
    .acting(COORDINATOR),
    OpSpec::command(
        "review.close_stage1",
        CK::CloseStage1,
        Post,
        "/proposals/{proposal}/stage1-close",
    )
    .acting(COORDINATOR),
    OpSpec::read(
        "review.notifiable_conflicts",
        RK::ListNotifiableConflicts,
        "/calls/{call}/notifiable-conflicts",
    )
    .acting(COORDINATOR),
    // J6: assigned reviewers.
    OpSpec::read("me.assignments", RK::ListMyAssignments, "/me/assignments").tool(
        "fstp_list_assignments",
        "List the caller's own reviewer assignments.",
        &IN_NONE,
        Scope::ReviewRead,
    ),
    OpSpec::command(
        "review.declare_assignment",
        CK::DeclareConflict,
        Post,
        "/assignments/{assignment}/declaration",
    )
    .acting(REVIEWER),
    OpSpec::read(
        "review.score_sheet",
        RK::GetScoreSheet,
        "/assignments/{assignment}/score-sheet",
    )
    .acting(REVIEWER)
    .tool(
        "fstp_get_score_sheet",
        "Read the score sheet of one of the caller's own assignments.",
        &IN_ASSIGNMENT,
        Scope::ReviewRead,
    ),
    OpSpec::command(
        "review.score",
        CK::RecordScore,
        Post,
        "/assignments/{assignment}/scores",
    )
    .acting(REVIEWER)
    .tool(
        "fstp_record_score",
        "Record a score on one of the caller's own assignments. This is a binding action.",
        &IN_ASSIGNMENT_BODY,
        Scope::ReviewDraft,
    ),
    OpSpec::command(
        "review.correct_score",
        CK::CorrectScore,
        Put,
        "/assignments/{assignment}/scores/{score}",
    )
    .acting(REVIEWER)
    .tool(
        "fstp_correct_score",
        "Correct a score on one of the caller's own assignments. This is a binding action.",
        &IN_ASSIGNMENT_SCORE_BODY,
        Scope::ReviewDraft,
    ),
    OpSpec::command(
        "review.ranking_summary",
        CK::RecordRankingSummary,
        Post,
        "/assignments/{assignment}/ranking-summary",
    )
    .acting(REVIEWER)
    .tool(
        "fstp_record_ranking_summary",
        "Record the ranking summary and rationale of an assignment. This is a binding action.",
        &IN_ASSIGNMENT_BODY,
        Scope::ReviewDraft,
    ),
    OpSpec::read(
        "review.stage2_thread",
        RK::GetStage2Thread,
        "/assignments/{assignment}/stage2",
    )
    .acting(REVIEWER),
    OpSpec::command(
        "stage2.ask",
        CK::AskQuestion,
        Post,
        "/assignments/{assignment}/questions",
    )
    .acting(REVIEWER),
    OpSpec::command(
        "stage2.no_questions",
        CK::RecordNoQuestions,
        Post,
        "/assignments/{assignment}/no-questions",
    )
    .acting(REVIEWER),
    OpSpec::command(
        "review.rank",
        CK::RankAfterStage2,
        Post,
        "/assignments/{assignment}/ranking",
    )
    .acting(REVIEWER),
    OpSpec::read(
        "review.findings",
        RK::GetFindings,
        "/assignments/{assignment}/findings",
    )
    .acting(REVIEWER)
    .tool(
        "fstp_get_findings",
        "Read the findings on the proposal of one of the caller's own assignments.",
        &IN_ASSIGNMENT,
        Scope::FindingsRead,
    ),
    OpSpec::new(
        "review.mark_finding",
        OpKind::Finding(FindingKind::Mark),
        Post,
        "/findings/{finding}/mark",
    )
    .binding()
    .acting(REVIEWER),
    // J7: the committee and the cut-off rounds of change D5.
    OpSpec::read("committee.ranking", RK::GetRankingView, "/calls/{call}/ranking")
        .acting(COMMITTEE)
        .tool(
            "fstp_get_ranking_view",
            "Read the committee ranking view of a call.",
            &IN_CALL,
            Scope::RankingRead,
        ),
    OpSpec::command(
        "committee.open_round",
        CK::OpenCutOffRound,
        Post,
        "/calls/{call}/cut-off-rounds",
    )
    .acting(COMMITTEE),
    OpSpec::read("committee.round", RK::GetCutOffRound, "/cut-off-rounds/{round}")
        .acting(COMMITTEE),
    OpSpec::command(
        "committee.cast",
        CK::CastBallot,
        Post,
        "/cut-off-rounds/{round}/ballot",
    )
    .acting(COMMITTEE),
    OpSpec::command(
        "committee.delegate",
        CK::DelegateVote,
        Post,
        "/cut-off-rounds/{round}/delegation",
    )
    .acting(COMMITTEE),
    OpSpec::command(
        "committee.record_cutoff",
        CK::RecordCutOff,
        Post,
        "/cut-off-rounds/{round}/record",
    )
    .acting(COMMITTEE),
    // J8: IRC and the decline rows.
    OpSpec::read("me.irc_cases", RK::ListMyIrcCases, "/me/irc-cases"),
    OpSpec::command(
        "irc.declare",
        CK::DeclareConflict,
        Post,
        "/irc-assignments/{irc_assignment}/declaration",
    )
    .acting(IRC),
    OpSpec::read(
        "irc.case",
        RK::GetIrcCase,
        "/irc-assignments/{irc_assignment}/case",
    )
    .acting(IRC),
    OpSpec::command(
        "irc.review",
        CK::RecordIrcReview,
        Post,
        "/irc-assignments/{irc_assignment}/review",
    )
    .acting(IRC),
    OpSpec::command(
        "decision.decline_after_concern",
        CK::DeclineAfterConcern,
        Post,
        "/proposals/{proposal}/decline-after-concern",
    )
    .acting(MANAGER),
    OpSpec::command(
        "decision.decline_negotiation",
        CK::DeclineNegotiation,
        Post,
        "/proposals/{proposal}/decline-negotiation",
    )
    .acting(MANAGER),
    // J9: agents, sessions, pending actions and audit.
    OpSpec::new(
        "agents.consent",
        OpKind::Agent(AgentKind::Consent),
        Post,
        "/oauth/consent",
    )
    .hr()
    .class(Personal),
    OpSpec::read("agents.list", RK::ListMyAgents, "/me/agents").class(Personal),
    OpSpec::read(
        "agents.activity",
        RK::ListMyAgentActivity,
        "/me/agents/{client}/activity",
    )
    .class(Personal),
    OpSpec::new(
        "agents.revoke",
        OpKind::Agent(AgentKind::Revoke),
        Post,
        "/me/agents/{client}/revocation",
    )
    .class(Personal),
    OpSpec::read("me.sessions", RK::ListMySessions, "/me/sessions").class(Personal),
    // I-86: the caller's own active roles, for the interim home page of
    // design section 15.0 (2026-10-31). Web only: no tool.
    OpSpec::read("me.roles", RK::ListMyRoles, "/me/roles").class(Personal),
    OpSpec::new(
        "me.end_session",
        OpKind::M3Port(PortKind::EndSession),
        Post,
        "/me/sessions/{session}/end",
    )
    .class(Personal),
    OpSpec::new(
        "me.add_passkey",
        OpKind::M3Port(PortKind::AddPasskey),
        Post,
        "/me/passkeys",
    )
    .hr()
    .class(Personal),
    OpSpec::read(
        "pending.list",
        RK::ListMyPendingActions,
        "/me/pending-actions",
    )
    .class(Personal),
    OpSpec::new(
        "pending.confirm",
        OpKind::Pending(PendingKind::Confirm),
        Post,
        "/pending-actions/{pending}/confirmation",
    ),
    OpSpec::new(
        "pending.discard",
        OpKind::Pending(PendingKind::Discard),
        Post,
        "/pending-actions/{pending}/discard",
    ),
    OpSpec::read(
        "audit.entries",
        RK::GetAuditLog,
        "/programmes/{programme}/audit",
    )
    .acting(AUDITOR)
    .tool(
        "fstp_audit_list_entries",
        "List the audit entries of a programme.",
        &IN_PROGRAMME,
        Scope::AuditRead,
    ),
    OpSpec::read(
        "audit.vault_outcomes",
        RK::GetVaultOutcomes,
        "/programmes/{programme}/audit/vault-outcomes",
    )
    .acting(AUDITOR),
];

/// High-risk by the strict reading, beyond the `authentication.md` table:
/// the tenant settings other than P-70 (design section 3.5, Q10 interim).
pub const STRICT_EXTRA_HIGH_RISK: &[OpKind] = &[
    OpKind::Tenant(TenantKind::SetSetting(TenantParam::P71)),
    OpKind::Tenant(TenantKind::SetSetting(TenantParam::P72)),
    OpKind::Tenant(TenantKind::SetSetting(TenantParam::P74)),
    OpKind::Tenant(TenantKind::SetSetting(TenantParam::P20)),
    OpKind::Tenant(TenantKind::SetSetting(TenantParam::P69)),
];

/// Kinds that never arrive from a person. In M4 cells, the D13 sweep
/// issues `ExpireStage2` and `ReEnter`, and M3 issues `VaultChanged`. The
/// System records `EndScheduledRole` at a binding's scheduled end
/// (`roles-and-sod.md` Cooling-off NOTE). The rest arrive with M5.
pub const SYSTEM_ONLY: &[CommandKind] = &[
    CK::VaultChanged,
    CK::ExpireStage2,
    CK::ReEnter,
    CK::ContractFact,
    CK::StartExecution,
    CK::Complete,
    CK::RecordDeliverable,
    CK::ActivateAmendment,
    CK::EndScheduledRole,
];

/// Finding and import kinds that never arrive from a person:
/// `FindingCommand::Record` and `Regenerate` (the assessor, M7), and
/// `ImportCommand::RecordProposals` (the proposer, run by the shell).
pub const SYSTEM_ONLY_OTHER: &[OpKind] = &[
    OpKind::Finding(FindingKind::Record),
    OpKind::Finding(FindingKind::Regenerate),
    OpKind::Import(ImportKind::RecordProposals),
];

/// Kinds only the engine composes from a creator decision: the core
/// `ActivateProgramme` of change D2. No operation has it as its kind, so
/// only `creator.approve_activation` reaches an activation (I-66).
pub const COMPOSED_ONLY: &[CommandKind] = &[CK::ActivateProgramme];

/// Kinds whose operations arrive in a later milestone: the grant,
/// contract, payment and amendment kinds of M5.
pub const LATER: &[(CommandKind, Milestone)] = &[
    (CK::DetermineAmount, Milestone::M5),
    (CK::AcceptGrant, Milestone::M5),
    (CK::ApproveGrant, Milestone::M5),
    (CK::Terminate, Milestone::M5),
    (CK::RequestPayment, Milestone::M5),
    (CK::AcceptLine, Milestone::M5),
    (CK::ApprovePayment, Milestone::M5),
    (CK::ReleasePayment, Milestone::M5),
    (CK::ConfirmPaid, Milestone::M5),
    (CK::WithdrawPaymentRequest, Milestone::M5),
    (CK::RequestPaymentChanges, Milestone::M5),
    (CK::ProposeAmendment, Milestone::M5),
    (CK::RouteAmendment, Milestone::M5),
    (CK::CloseMilestone, Milestone::M5),
    (CK::ClosePaymentRequest, Milestone::M5),
];

/// The operation named `name`.
pub fn op(name: &str) -> Option<&'static OpSpec> {
    OPS.iter().find(|o| o.name == name)
}

/// The path parameters of a route, in order: each `{name}` segment.
pub fn route_params(path: &str) -> impl Iterator<Item = &str> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
}
