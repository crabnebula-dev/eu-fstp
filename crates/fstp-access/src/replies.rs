//! The reply shapes of the operations (M4 design sections 3.7 and 3.9,
//! ADR-014, ADR-006, TH-26).
//!
//! [`REPLIES`] states, for each operation whose `data` the API core
//! serves, the structure of that JSON value. `tools/gen-ts` writes it
//! into `web/src/gen/api.ts` as `SCHEMAS`, with one structural validator
//! per entry in `VALIDATORS`. The read models of `fstp-api-core` are
//! tested against these shapes, so the two cannot drift apart.
//!
//! Objects are closed: a member the shape does not name is refused, as
//! the server's decoders refuse one. Ids and instants travel as decimal
//! strings and amounts as ADR-006 strings, never as JSON numbers.
//!
//! Interim, pending Daniel: an entry is keyed by the name of the
//! operation whose reply it describes. Command operations answer
//! `{"accepted": true}` today and have no entry. Four commands answer
//! with data a page reads next, and each has an entry:
//!
//! - `proposal.create` names the drawn proposal (J4).
//! - `proposal.record_plan` carries the total the cell summed (ADR-006)
//!   and the drawn plan, which a stage 2 revision names (R-EV-05).
//! - `committee.open_round` names the drawn round, which the ballot and
//!   the delegation address. Its entry fixes that reply, `{"round": id}`.
//! - `creator.open_draft` names the drawn programme, which the creator
//!   pages open next (lane m4wire).
//!
//! Dispatch serves `committee.open_round` as
//! `fstp_api_core::model::RoundOpened`, with the drawn id.
//!
//! Optional members are the ones a read model leaves out when it has no
//! value, such as a call's title. A member that is present but empty is
//! `null`, and its shape says `Nullable`.

use fstp_domain::roles::{Group, Role};

/// The structure of one JSON value. The kinds are those of the `Schema`
/// type that the web side checks against (`web/test/support/contract.ts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Any string.
    String,
    /// An id: a canonical decimal string.
    Id,
    /// An ADR-006 EUR amount string.
    Amount,
    /// `true` or `false`.
    Bool,
    /// A safe integer, as a JSON number.
    Int,
    /// `null`.
    Null,
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// An array of values of one shape.
    Array(&'static Shape),
    /// `null`, or a value of the inner shape.
    Nullable(&'static Shape),
    /// A closed object with these members.
    Object(&'static [Member]),
}

impl Shape {
    /// The kind as the web side spells it.
    pub const fn kind(self) -> &'static str {
        match self {
            Shape::String => "string",
            Shape::Id => "id",
            Shape::Amount => "amount",
            Shape::Bool => "bool",
            Shape::Int => "int",
            Shape::Null => "null",
            Shape::Enum(_) => "enum",
            Shape::Array(_) => "array",
            Shape::Nullable(_) => "nullable",
            Shape::Object(_) => "object",
        }
    }
}

/// One member of an object shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    /// The member name.
    pub name: &'static str,
    /// Its shape.
    pub shape: Shape,
    /// Whether the member may be absent.
    pub optional: bool,
}

/// A member that is always present.
const fn m(name: &'static str, shape: Shape) -> Member {
    Member {
        name,
        shape,
        optional: false,
    }
}

/// A member the reply may leave out.
const fn opt(name: &'static str, shape: Shape) -> Member {
    Member {
        name,
        shape,
        optional: true,
    }
}

/// Which assessor produced a finding or a pre-check run (M7 design
/// section 7): the in-memory synthetic model of a demo cell, or a model.
const ASSESSOR_NAMES: &[&str] = &["synthetic", "model"];

/// The stages a client assessment answers (ADR-033): every stage but
/// verification, which needs the retrieval proxy.
const CLIENT_STAGE_NAMES: &[&str] = &["completeness", "quality", "claims", "integrity"];

/// The prompt set a client assessment names (ADR-033): its version and
/// digest.
/// ADR-035: the reason codes of the injection scan, as
/// `fstp_injscan::Reason::code` spells them. A test of `fstp-api-core`
/// keeps the two lists equal.
pub const INTEGRITY_REASONS: &[&str] = &[
    "zero_width",
    "bidi",
    "tag",
    "variation_run",
    "format",
    "hidden_markup",
    "role_marker",
    "override",
    "addressed",
    "score_request",
    "tool_call",
    "schema_payload",
    "exfil_link",
    "encoded_blob",
    "confusable",
    "truncated",
];

/// ADR-035, TH-60: the flagged spans of a served text, as closed reason
/// codes and scalar offsets. No member can hold text.
const FLAGS: Shape = Shape::Array(&Shape::Object(&[
    m("reason", Shape::Enum(INTEGRITY_REASONS)),
    m("start", Shape::Int),
    m("end", Shape::Int),
]));

const PROMPT_SET: Shape = Shape::Object(&[m("version", Shape::String), m("digest", Shape::String)]);

/// The stage names a refused-stage notice may carry, as
/// `fstp_assess::Stage::as_str` spells them (issue 6 M3, I-10, H-03).
pub const REFUSED_STAGE_NAMES: &[&str] =
    &["completeness", "quality", "claims", "verify", "integrity"];

/// The refusal codes a refused-stage notice may carry, as
/// `fstp_assess::OutputError::code` spells them (issue 6 M3, I-10, H-03).
pub const REFUSED_STAGE_CODES: &[&str] = &[
    "json",
    "unknown_member",
    "shape",
    "score_like",
    "criterion",
    "element",
    "kind",
    "too_long",
];

/// The rubric v1 element tags (M7 design section 2, reading 1).
const RUBRIC_ELEMENTS: &[&str] = &[
    "problem",
    "approach",
    "ois_relevance",
    "team_experience",
    "deliverables_licence",
    "milestones",
    "budget_justification",
];

/// One recorded plan version as the team reads it back (`proposal.get_plan`,
/// R-SB-01, ADR-006, lane m4/author-reads): its id, its origin, its tasks
/// with each milestone's amount and days, the total the cell summed when
/// the sum fits, and the work plan text when the cell holds it.
const PLAN_VIEW: Shape = Shape::Object(&[
    m("plan", Shape::Id),
    m(
        "origin",
        Shape::Enum(&["submitted", "stage2_revision", "negotiated", "amendment"]),
    ),
    m(
        "tasks",
        Shape::Array(&Shape::Object(&[m(
            "milestones",
            Shape::Array(&Shape::Object(&[
                m("amount", Shape::Amount),
                m("start", Shape::String),
                m("due", Shape::String),
            ])),
        )])),
    ),
    opt("total", Shape::Amount),
    opt("text", Shape::String),
    // ADR-007 (Daniel, 2026-11-16): the day the erasure of the work plan
    // text was requested, in place of the text once it is erased.
    opt("text_erased", Shape::String),
]);

/// The finding kinds, as the pre-check reply spells them.
const KIND_NAMES: &[&str] = &["completeness", "quality", "accuracy", "integrity"];

/// The pre-check reply (M7 design section 4, reading 4): kind, criterion,
/// severity, statement and quoted evidence per finding, and the
/// remaining P-23 checks. It carries no confidence and no score (TH-02).
const PRECHECK_VIEW: Shape = Shape::Object(&[
    m("assessor", Shape::Enum(ASSESSOR_NAMES)),
    m(
        "remaining",
        Shape::Object(&[
            m("proposal_today", Shape::Int),
            m("proposal_call", Shape::Int),
            m("account_call", Shape::Int),
            m("next", Shape::Nullable(&Shape::Id)),
        ]),
    ),
    m(
        "runs",
        Shape::Array(&Shape::Object(&[
            m("run", Shape::Id),
            m("requested", Shape::Id),
            m("state", Shape::Enum(&["pending", "done", "unavailable"])),
            m(
                "findings",
                Shape::Array(&Shape::Object(&[
                    m("kind", Shape::Enum(KIND_NAMES)),
                    m("criterion", Shape::Nullable(&Shape::Id)),
                    m("element", Shape::Nullable(&Shape::Enum(RUBRIC_ELEMENTS))),
                    m("severity", Shape::Enum(&["info", "minor", "major"])),
                    m("statement", Shape::String),
                    m(
                        "evidence",
                        Shape::Array(&Shape::Object(&[
                            m("section", Shape::Enum(&["title", "summary", "narrative"])),
                            m("quote", Shape::String),
                        ])),
                    ),
                ])),
            ),
        ])),
    ),
    // ADR-035, TH-02: the platform's injection check of the draft as it
    // stands: closed reason codes, spans and short quotes of the
    // applicant's own text. No detector internals.
    m(
        "scan",
        Shape::Array(&Shape::Object(&[
            m("section", Shape::Enum(&["title", "summary", "narrative"])),
            m("reason", Shape::Enum(INTEGRITY_REASONS)),
            m("start", Shape::Int),
            m("end", Shape::Int),
            m("quote", Shape::String),
        ])),
    ),
]);

/// The kinds of a mailbox message (lane m6/mailbox, `docs/handoff/mailbox-design.md`
/// section 2), as `me.mailbox` spells them.
pub const MAILBOX_KINDS: &[&str] = &[
    "pending.confirm",
    "proposal.submit",
    "stage2.respond",
    "negotiation.acknowledge",
    "review.declare",
    "review.score",
    "irc.declare",
    "irc.review",
    "intake.knock_out",
    "round.vote",
    "admin.approve_activation",
    // ADR-022 decision 2 (2026-11-15): the override a building tenant
    // admin may use.
    "admin.override_activation",
    "contract.sign",
    "payment.review",
    "payment.approve",
    "payment.release",
    "payment.confirm",
    "notice.outcome",
    "notice.irc_concern",
    // MB-Q3 (2026-11-13): invitations and role grants of an existing
    // account.
    "invitation.open",
    "role.granted",
    // P-41 (Daniel, 2026-11-15 late): a grant's funder retention ended.
    "admin.retention_ended",
    // P-57 (Daniel, 2026-11-15 late): a reporting period ended and its
    // report is due.
    "report.period_ended",
    // ADR-008 (Daniel, 2026-11-19): a passkey was disabled. The holder's
    // notice, and the tenant admins' notice when no relay sends the email.
    "notice.passkey_disabled",
    "admin.passkey_disabled",
];

/// The erasure causes of ADR-007, as the wire names them (lane
/// m5/retention): retention expiry (P-41), an erasure request, a cell
/// erasure, and a completed identity verification (R-ID-03).
pub const ERASURE_CAUSES: &[&str] = &[
    "retention_expiry",
    "erasure_request",
    "cell_erasure",
    "verification_completed",
];

/// What an erased text held (ADR-007 section "Built by lane L33").
pub const ERASURE_KINDS: &[&str] = &["text", "display_name", "document"];

/// Who authorised an erasure (ADR-007, Daniel 2026-11-23, question 3; lane
/// L39): the system, or an account the page never names (R-CF-03).
pub const ERASURE_AUTHORISERS: &[&str] = &["system", "account"];

/// The media types of an import document (`fstp_import::ImportMedia`).
pub const IMPORT_MEDIA: &[&str] = &["text/plain", "text/markdown"];

/// How one part of the host runs, in the host status file (ADR-028 record
/// of lane L20).
pub const PART_STATES: &[&str] = &["running", "unhealthy", "stopped"];

/// The one next thing on the host, as `fstp-admin status` names it
/// (ADR-028 "Status", record of lane L20).
pub const HOST_NEXT: &[&str] = &[
    "run_setup",
    "start_service",
    "renew_route",
    "renew",
    "public_certificate",
    "configure_backups",
    "backup",
    "keystore_snapshot",
    "web_admins",
    "verify_admins",
    "copy_keys",
    "nothing",
];

/// Every proposal state, as the state machine names it.
pub const STATE_NAMES: &[&str] = &[
    "DRAFT",
    "SUBMITTED",
    "INELIGIBLE",
    "STAGE1",
    "NOT_SELECTED",
    "STAGE2",
    "RANKED",
    "IRC_REVIEW",
    "DEFERRED",
    "DECLINED",
    "NEGOTIATION",
    "WITHDRAWN",
    "GRANTED",
    "IN_EXECUTION",
    "COMPLETED",
    "TERMINATED",
];

/// The proposal states, and `UNKNOWN` for a proposal the projection does
/// not hold.
const OWN_STATE_NAMES: &[&str] = &[
    "DRAFT",
    "SUBMITTED",
    "INELIGIBLE",
    "STAGE1",
    "NOT_SELECTED",
    "STAGE2",
    "RANKED",
    "IRC_REVIEW",
    "DEFERRED",
    "DECLINED",
    "NEGOTIATION",
    "WITHDRAWN",
    "GRANTED",
    "IN_EXECUTION",
    "COMPLETED",
    "TERMINATED",
    "UNKNOWN",
];

/// Whether creator step 9 can invite to `role`: every role outside the
/// Receiving group, except tenant admin and the two tenant-wide
/// signatory roles (NOTE 5) (`programme-creator.md` step 9,
/// SoD-09). This is the rule `fstp_creator::decide_creator` applies to
/// `Invite`, so the landing exists for every invitation it records.
pub const fn invitable(role: Role) -> bool {
    !matches!(role.group(), Group::Receiving)
        && !matches!(role, Role::TenantAdmin)
        && !role.tenant_wide_signatory()
}

/// The role as the wire spells it: the role in snake case.
pub const fn role_wire_name(role: Role) -> &'static str {
    match role {
        Role::ProgrammeManager => "programme_manager",
        Role::CallDrafter => "call_drafter",
        Role::FstpCoordinator => "fstp_coordinator",
        Role::CommitteeMember => "committee_member",
        Role::CommitteeChair => "committee_chair",
        Role::IrcMember => "irc_member",
        Role::Applicant => "applicant",
        Role::ApplicantTeamMember => "applicant_team_member",
        Role::Guardian => "guardian",
        Role::TenantAdmin => "tenant_admin",
        Role::FinanceApprover => "finance_approver",
        Role::PaymentReleaser => "payment_releaser",
        Role::ContractSignatory => "contract_signatory",
        Role::FinancialSignatory => "financial_signatory",
        Role::LegalSignatory => "legal_signatory",
        Role::Auditor => "auditor",
    }
}

/// Every role as the wire spells it, in the order of [`Role::ALL`]
/// ([`role_wire_name`]).
const ROLE_NAMES: &[&str] = &[
    "programme_manager",
    "call_drafter",
    "fstp_coordinator",
    "committee_member",
    "committee_chair",
    "irc_member",
    "applicant",
    "applicant_team_member",
    "guardian",
    "tenant_admin",
    "finance_approver",
    "payment_releaser",
    "contract_signatory",
    "financial_signatory",
    "legal_signatory",
    "auditor",
];

/// Every MCP scope as the OAuth server spells it, in the order of
/// [`crate::Scope::ALL`] ([`crate::Scope::as_str`]).
const SCOPE_NAMES: &[&str] = &[
    "calls:read",
    "proposals:read",
    "proposals:draft",
    "proposals:binding",
    "stage2:draft",
    "review:read",
    "review:draft",
    "ranking:read",
    "findings:read",
    "creator:draft",
    "calls:draft",
    "audit:read",
    "tenant:draft",
    "assess:run",
];

/// The party kinds of an unmask (ADR-023), as
/// `fstp_domain::unmask::PartyKind::wire` spells them.
const PARTY_KINDS: &[&str] = &[
    "applicant",
    "team_member",
    "guardian",
    "reviewer",
    "irc",
    "staff",
];

/// How an unmask names its subject (ADR-023).
const SUBJECT_TYPES: &[&str] = &["binding", "assignment"];

/// The sides of a ledger entry, as `fstp_engine::EnvelopeKind::member`
/// spells them.
const LEDGER_SIDES: &[&str] = &[
    "core",
    "finding",
    "creator",
    "import",
    "onboarding",
    "contract",
    "report",
];

/// The role an audit row names for its actor: a role of
/// [`ROLE_NAMES`], `system` for a record no account made, and `account`
/// for an account with no role in the programme.
const ACTOR_ROLES: &[&str] = &[
    "programme_manager",
    "call_drafter",
    "fstp_coordinator",
    "committee_member",
    "committee_chair",
    "irc_member",
    "applicant",
    "applicant_team_member",
    "guardian",
    "tenant_admin",
    "finance_approver",
    "payment_releaser",
    "contract_signatory",
    "financial_signatory",
    "legal_signatory",
    "auditor",
    "system",
    "account",
];

/// What an audit row acts on, in the order a row picks it.
const OBJECT_TYPES: &[&str] = &[
    "proposal",
    "call",
    "assignment",
    "binding",
    "request",
    "decision",
    "programme",
];

/// The roles an invitation of creator step 9 names, as the wire spells
/// them: the [`invitable`] roles in the order of [`Role::ALL`]. These are
/// the Drafting and Judging roles and every Operations role but tenant
/// admin, so the finance roles of step 9 among them.
pub const INVITED_ROLES: &[&str] = &[
    "programme_manager",
    "call_drafter",
    "fstp_coordinator",
    "committee_member",
    "committee_chair",
    "irc_member",
    "finance_approver",
    "payment_releaser",
    "contract_signatory",
    "auditor",
];

/// The roles a team or member page lists (SA-11), as the wire spells
/// them: every role outside the Receiving group, in the order of
/// [`Role::ALL`]. No applicant, team member or guardian is ever listed.
pub const TEAM_ROLES: &[&str] = &[
    "programme_manager",
    "call_drafter",
    "fstp_coordinator",
    "committee_member",
    "committee_chair",
    "irc_member",
    "tenant_admin",
    "finance_approver",
    "payment_releaser",
    "contract_signatory",
    "financial_signatory",
    "legal_signatory",
    "auditor",
];

/// The status of one role on the team and member pages (SA-11): an open
/// invitation is invited, accepted or verified, and a binding is active,
/// suspended or ended.
const TEAM_STATUSES: &[&str] = &[
    "invited",
    "accepted",
    "verified",
    "active",
    "suspended",
    "ended",
];

/// The actions the team and member pages may offer the viewer (SA-11).
/// The server decides each again when it is taken.
const TEAM_ACTIONS: &[&str] = &["grant", "end", "reinstate", "invite"];

/// One role of a member account on the member page (SA-11): the
/// programme (null for a tenant-wide role), the binding or the open
/// invitation it comes from, the role, its status, the rule of a
/// suspension or a voiding, and its dates in microseconds.
const MEMBER_ROLE: Shape = Shape::Object(&[
    m("programme", Shape::Nullable(&Shape::Id)),
    m("binding", Shape::Nullable(&Shape::Id)),
    m("invitation", Shape::Nullable(&Shape::Id)),
    m("role", Shape::Enum(TEAM_ROLES)),
    m("status", Shape::Enum(TEAM_STATUSES)),
    opt("rule", Shape::String),
    m("start", Shape::Nullable(&Shape::String)),
    m("end", Shape::Nullable(&Shape::String)),
]);

/// A pass or fail outcome, with no reason and no account (R-CF-03).
const OUTCOME: Shape = Shape::Enum(&["pass", "fail"]);

/// One call, without its authors or approver (I-17).
const CALL: Shape = Shape::Object(&[
    m("call", Shape::Id),
    m("programme", Shape::Id),
    m("status", Shape::Enum(&["draft", "approved", "published"])),
    m("opens", Shape::String),
    m("deadline", Shape::String),
    m("deadline_zone", Shape::String),
    m("budget", Shape::Amount),
    m("currency", Shape::Enum(&["EUR"])),
    m("open", Shape::Bool),
    // R-PB-01: the published call text, left out when the text store
    // cannot give it.
    opt("title", Shape::String),
    // P-04, once the call's values are frozen. The two travel together.
    opt("grant_min", Shape::Amount),
    opt("grant_max", Shape::Amount),
    // P-05, from the programme's head policy, when it has one.
    opt("recipient_max", Shape::Amount),
]);

/// One of the caller's proposals: "Proposal" plus its id, never a name
/// (I-17). The title is the submitted one, else the team's draft title,
/// and is left out for a proposal this core holds no text of.
const OWN_PROPOSAL: Shape = Shape::Object(&[
    m("proposal", Shape::Id),
    m("call", Shape::Id),
    m("state", Shape::Enum(OWN_STATE_NAMES)),
    m("role", Shape::Enum(&["lead", "member", "guardian"])),
    opt("title", Shape::String),
    // O-54: an INELIGIBLE proposal shows the recorded knock-out reason.
    opt("knock_out_reason", Shape::String),
]);

/// One of the caller's assignments, with no applicant identity (I-17).
const OWN_ASSIGNMENTS: Shape = Shape::Array(&Shape::Object(&[
    m("assignment", Shape::Id),
    m("proposal", Shape::Id),
    m("call", Shape::Id),
    m("kind", Shape::Enum(&["reviewer", "irc", "amendment"])),
    m("awaiting_declaration", Shape::Bool),
    m("active", Shape::Bool),
    // Review finding U5: whether the stage 2 thread opens, so the list
    // links it only then. Always false for an IRC row (O-58).
    m("stage2", Shape::Bool),
]));

/// One proposal of a call for its staff: "Proposal" plus its id, its
/// state and its submitted title (`intake.queue`, `call.board`).
const PROPOSAL_ROW: Shape = Shape::Object(&[
    m("proposal", Shape::Id),
    m("state", Shape::Enum(STATE_NAMES)),
    m("title", Shape::String),
]);

/// One logo slot of `tenant.branding.logos` (ADR-030): `null`, or the
/// logo's same-origin path, format, size, whether PDFs and emails show
/// it, and its contrast advice (I-70, never a refusal).
const LOGO: Shape = Shape::Nullable(&Shape::Object(&[
    m("path", Shape::String),
    m("format", Shape::Enum(&["png", "webp"])),
    m("width", Shape::String),
    m("height", Shape::String),
    m("pdf", Shape::Bool),
    m("email", Shape::Bool),
    m("contrast", Shape::Nullable(&Shape::String)),
    m("advice", Shape::Bool),
]));

/// The reply of `tenant.branding.logos` and `programme.logos` (ADR-030).
const LOGOS: Shape = Shape::Object(&[
    m(
        "tenant",
        Shape::Object(&[m("light", LOGO), m("dark", LOGO)]),
    ),
    m(
        "programmes",
        Shape::Array(&Shape::Object(&[
            m("programme", Shape::Id),
            m("name", Shape::String),
            m("light", LOGO),
            m("dark", LOGO),
        ])),
    ),
]);

/// One onboarding step as `tenant.get_step` answers it and a step save
/// replies (R-TN-01, lane m4tenant). `values` holds the members of
/// whichever step was saved, so each member is optional. `accepted` holds
/// the agreement versions the control plane recorded.
const ONBOARDING_STEP: Shape = Shape::Object(&[
    m(
        "step",
        Shape::Enum(&[
            "organisation",
            "agreements",
            "branding",
            "domains_and_email",
            "identity",
            "inference",
            "payments",
            "channels",
            "administrators",
        ]),
    ),
    m(
        "status",
        Shape::Enum(&[
            "locked",
            "open",
            "saved",
            "validated",
            "skipped",
            "unavailable",
        ]),
    ),
    m("revision", Shape::Id),
    m(
        "values",
        Shape::Nullable(&Shape::Object(&[
            opt("data_protection_contact", Shape::String),
            opt("signatories", Shape::Array(&Shape::Id)),
            opt("dpa", Shape::Id),
            opt("saas_terms", Shape::Id),
            opt("sub_processors", Shape::Id),
            opt("package", Shape::Enum(&["default", "white_label"])),
            opt("sending_domain", Shape::String),
            opt(
                "p18",
                Shape::Array(&Shape::Enum(&["document_upload", "eudi_wallet"])),
            ),
            opt(
                "p45",
                Shape::Enum(&["crabnebula_intermediary", "tenant_registration"]),
            ),
            opt("fallbacks", Shape::Array(&Shape::String)),
            opt("primary", Shape::String),
            opt("provider", Shape::String),
            opt("bank_interface", Shape::Enum(&["connect", "not_connected"])),
            opt("matrix_homeserver", Shape::Nullable(&Shape::String)),
            opt("whatsapp", Shape::Bool),
            opt("admins", Shape::Array(&Shape::Id)),
        ])),
    ),
    m(
        "outcome",
        Shape::Nullable(&Shape::Enum(&[
            "validated",
            "invalid_values",
            "probe_failed",
            "prober_absent",
            "too_few_admins",
            "no_financial_signatory",
            "no_legal_signatory",
            "agreements_not_recorded",
            "payment_mode_unset",
            "unavailable_m5",
            "unavailable_m6",
            "unavailable_m8",
            "unavailable_m9",
        ])),
    ),
    m(
        "accepted",
        Shape::Nullable(&Shape::Object(&[
            m("dpa", Shape::Id),
            m("saas_terms", Shape::Id),
            m("sub_processors", Shape::Id),
        ])),
    ),
]);

/// The detail of a validation report row: string values only (lane
/// m4wire). Each member names a subject or a detail of the creator's
/// `CheckResult`.
const REPORT_DETAIL: Shape = Shape::Object(&[
    opt("invitation", Shape::Id),
    opt("probe", Shape::String),
    opt("colour", Shape::String),
    opt("element", Shape::String),
    opt("section", Shape::String),
    opt("placeholder", Shape::String),
    opt("obligation", Shape::String),
    opt("p05", Shape::Amount),
    opt("p58", Shape::Amount),
    opt("rule", Shape::String),
    opt("status", Shape::Enum(&["not_checked"])),
    opt("unavailable", Shape::String),
    opt("outcome", Shape::String),
]);

/// The funder outputs of the Horizon Europe profile (R-RP-04).
const REPORT_KINDS: &[&str] = &[
    "call_publication_record",
    "open_call_package",
    "periodic_reporting_data",
    "audit_file",
    "deliverable_draft",
];

/// The status of a payment request (`payment-requests.md` States).
const REQUEST_STATES: &[&str] = &[
    "SUBMITTED",
    "CHECKS_FAILED",
    "UNDER_REVIEW",
    "CHANGES_REQUESTED",
    "ACCEPTED",
    "PAYMENT_APPROVED",
    "RELEASED",
    "PAID",
    "REJECTED",
    "WITHDRAWN",
    "CLOSED",
];

/// One payment request with its lines (M5 lane L-API).
const PAYMENT_REQUEST: Shape = Shape::Object(&[
    m("request", Shape::Id),
    m("proposal", Shape::Id),
    m("status", Shape::Enum(REQUEST_STATES)),
    m("kind", Shape::Enum(&["milestone", "hardship"])),
    m("submission_checks", Shape::Bool),
    m("acceptance_checks", Shape::Bool),
    m(
        "lines",
        Shape::Array(&Shape::Object(&[
            m("line", Shape::Id),
            m("milestone", Shape::Id),
            m("requested", Shape::Amount),
            m("approved", Shape::Nullable(&Shape::Amount)),
        ])),
    ),
]);

/// The state of a contract or of one version (`contracts.md` States).
const CONTRACT_STATES: &[&str] = &[
    "drafted",
    "sent",
    "signed_by_grantee",
    "effective",
    "amendment_pending",
    "superseded",
    "terminated",
];

/// The contract status of one grant (M5 lane L-API).
const CONTRACT_VIEW: Shape = Shape::Object(&[
    m("proposal", Shape::Id),
    m("contract", Shape::Nullable(&Shape::Id)),
    m("status", Shape::Nullable(&Shape::Enum(CONTRACT_STATES))),
    m(
        "versions",
        Shape::Array(&Shape::Object(&[
            m("version", Shape::Int),
            m("state", Shape::Enum(CONTRACT_STATES)),
            m(
                "parties",
                Shape::Array(&Shape::Object(&[
                    m("field", Shape::String),
                    m(
                        "role",
                        Shape::Enum(&["lead", "team_member", "guardian", "signatory"]),
                    ),
                    m("signed", Shape::Bool),
                    m("mine", Shape::Bool),
                ])),
            ),
            m("revisions", Shape::Int),
            m("digest", Shape::Nullable(&Shape::String)),
            m("open_changes", Shape::Array(&Shape::Int)),
        ])),
    ),
]);

/// One milestone of a grant with its money (M5 reads follow-up, R-PR-07,
/// I-58). `due` is a UTC day, `YYYY-MM-DD`.
const MILESTONE_FUNDS: Shape = Shape::Object(&[
    m("milestone", Shape::Id),
    m("amount", Shape::Amount),
    m("due", Shape::String),
    m("paid", Shape::Amount),
    m("pending", Shape::Amount),
    m("available", Shape::Amount),
    m("closed", Shape::Bool),
]);

/// Why a grant is in the caller's list: the rule of `grant.overview` that
/// admitted the caller (M5 reads follow-up).
const GRANT_VIA: &[&str] = &[
    "team",
    "former_team",
    "programme_manager",
    "finance_approver",
    "payment_releaser",
    "contract_signatory",
    "auditor",
    "assigned_reviewer",
];

/// The public visibility levels, lowest first (`public-transparency.md`).
const PUBLIC_LEVELS: &[&str] = &["hidden", "project", "project_and_grantee", "full"];

/// One phase of `grant.publicity.view` (M9 lane P1): whether a choice can
/// be set now (I-41), and the current choice with its effective level.
const PUBLICITY_PHASE: Shape = Shape::Object(&[
    m("open", Shape::Bool),
    m(
        "choice",
        Shape::Nullable(&Shape::Object(&[
            m("level", Shape::Enum(PUBLIC_LEVELS)),
            m("effective", Shape::Enum(PUBLIC_LEVELS)),
            m("title", Shape::String),
            m("summary", Shape::String),
            m("grantee", Shape::String),
            m("deliverables", Shape::Array(&Shape::Id)),
        ])),
    ),
]);

/// The reply shape of each operation whose `data` the API core serves,
/// by operation name.
pub const REPLIES: &[(&str, Shape)] = &[
    // M9 lane P1 (R-PB-02, R-PB-03, I-41, I-42, I-43): the grantee lead's
    // public choices, the programme maxima P-50 and P-51, the minor flag
    // that disables every level but hidden (D4), and the accepted
    // deliverables a finished choice may include. Texts are the lead's own
    // public texts. No account, amount or proposal text.
    (
        "grant.publicity.view",
        Shape::Object(&[
            m("proposal", Shape::Id),
            m("state", Shape::Enum(STATE_NAMES)),
            m("minor", Shape::Bool),
            m("max_funded", Shape::Enum(PUBLIC_LEVELS)),
            m("max_finished", Shape::Enum(PUBLIC_LEVELS)),
            m("funded", PUBLICITY_PHASE),
            m("finished", PUBLICITY_PHASE),
            m(
                "deliverables",
                Shape::Array(&Shape::Object(&[
                    m("id", Shape::Id),
                    m("licence", Shape::String),
                    m("snapshot", Shape::String),
                ])),
            ),
        ]),
    ),
    // M5 lane L-API (M5 design section 5). I-86: no bank detail, identity
    // attribute or vault value; parties by field and role only.
    (
        "grant.overview",
        Shape::Object(&[
            m("proposal", Shape::Id),
            m("state", Shape::Enum(STATE_NAMES)),
            m("determination", Shape::Nullable(&Shape::Id)),
            m("amount", Shape::Nullable(&Shape::Amount)),
            m("paid", Shape::Amount),
            m("contract", Shape::Nullable(&Shape::Id)),
            m("requests", Shape::Int),
            // M5 reads follow-up: the plan and its milestones, every sum
            // the cell's (R-PR-07, I-58, ADR-006).
            m("plan", Shape::Nullable(&Shape::Id)),
            m("milestones", Shape::Array(&MILESTONE_FUNDS)),
        ]),
    ),
    ("contract.view", CONTRACT_VIEW),
    // M5 reads follow-up: the caller's grants, and the contract versions
    // awaiting the caller's signature. I-86: parties by field and role.
    (
        "grant.list_mine",
        Shape::Array(&Shape::Object(&[
            m("proposal", Shape::Id),
            m("call", Shape::Nullable(&Shape::Id)),
            m("state", Shape::Enum(STATE_NAMES)),
            m("amount", Shape::Nullable(&Shape::Amount)),
            m("paid", Shape::Amount),
            m("contract", Shape::Nullable(&Shape::Id)),
            m("via", Shape::Enum(GRANT_VIA)),
        ])),
    ),
    // Lead, 2026-11-12: what an amount determination needs, for the
    // assigned reviewer (R-NG-03). No paid sum, contract or request.
    (
        "grant.determination_view",
        Shape::Object(&[
            m("proposal", Shape::Id),
            m("state", Shape::Enum(STATE_NAMES)),
            m("determination", Shape::Nullable(&Shape::Id)),
            m("plan", Shape::Nullable(&Shape::Id)),
            m("plan_total", Shape::Nullable(&Shape::Amount)),
            m("granted", Shape::Nullable(&Shape::Amount)),
        ]),
    ),
    (
        "contract.awaiting_me",
        Shape::Array(&Shape::Object(&[
            m("proposal", Shape::Id),
            m("contract", Shape::Id),
            m("version", Shape::Int),
            m("field", Shape::String),
            m(
                "role",
                Shape::Enum(&["lead", "team_member", "guardian", "signatory"]),
            ),
            m("state", Shape::Enum(&["sent", "signed_by_grantee"])),
            m("digest", Shape::Nullable(&Shape::String)),
        ])),
    ),
    ("payment.status", Shape::Array(&PAYMENT_REQUEST)),
    // Lane m5/polish-access (2026-11-12): what a line review needs, for
    // the assigned reviewer (R-PR-08, R-PR-01, I-32). The evidence the
    // lead gave per line, and no bank detail, account or paid sum (I-86).
    (
        "payment.line_review_view",
        Shape::Object(&[
            m("request", Shape::Id),
            m("proposal", Shape::Id),
            m("status", Shape::Enum(REQUEST_STATES)),
            m("kind", Shape::Enum(&["milestone", "hardship"])),
            m("submission_checks", Shape::Bool),
            m("acceptance_checks", Shape::Bool),
            m(
                "lines",
                Shape::Array(&Shape::Object(&[
                    m("line", Shape::Id),
                    m("milestone", Shape::Id),
                    m("requested", Shape::Amount),
                    m("approved", Shape::Nullable(&Shape::Amount)),
                    m("location", Shape::Nullable(&Shape::String)),
                    m("release", Shape::Nullable(&Shape::String)),
                    m("licence", Shape::Nullable(&Shape::String)),
                    m("report", Shape::Nullable(&Shape::String)),
                ])),
            ),
        ]),
    ),
    (
        "payment.queue",
        Shape::Array(&Shape::Object(&[
            m(
                "task",
                Shape::Enum(&["review", "approve", "release", "confirm"]),
            ),
            m("request", PAYMENT_REQUEST),
        ])),
    ),
    (
        "report.list",
        Shape::Array(&Shape::Object(&[
            m("report", Shape::Id),
            m("kind", Shape::Enum(REPORT_KINDS)),
            m("call", Shape::Nullable(&Shape::Id)),
            m("programme", Shape::Nullable(&Shape::Id)),
            m("document", Shape::String),
            m("template", Shape::String),
            m("generated_by_me", Shape::Bool),
            m("approved", Shape::Bool),
        ])),
    ),
    // Lane m5/report-programmes (R-RP-03, I-86): ids and names only.
    (
        "report.programmes",
        Shape::Array(&Shape::Object(&[
            m("id", Shape::Id),
            m("name", Shape::String),
        ])),
    ),
    // M9 finish (R-RP-01, I-86): the pinned funder profile, or `null` when
    // P-53 names no shipped profile. The digest is the SHA-256 of the
    // profile file, and the outputs are the kinds the profile defines.
    (
        "programme.funder_profile.view",
        Shape::Object(&[
            m("programme", Shape::Id),
            m(
                "profile",
                Shape::Nullable(&Shape::Object(&[
                    m("id", Shape::String),
                    m("version", Shape::Id),
                    m("digest", Shape::String),
                    m("outputs", Shape::Array(&Shape::Enum(REPORT_KINDS))),
                    m("visibility_elements", Shape::Array(&Shape::String)),
                ])),
            ),
            // P-57 (Daniel, 2026-11-15 late): the reporting periods, each
            // by number with its first instant, the instant after its last
            // day and the instant after its report deadline.
            m(
                "reporting_periods",
                Shape::Array(&Shape::Object(&[
                    m("period", Shape::Id),
                    m("start", Shape::Id),
                    m("end", Shape::Id),
                    m("deadline", Shape::Id),
                ])),
            ),
        ]),
    ),
    (
        "payment.submit",
        Shape::Object(&[m("accepted", Shape::Bool), m("request", Shape::Id)]),
    ),
    (
        "payment.resubmit",
        Shape::Object(&[m("accepted", Shape::Bool), m("request", Shape::Id)]),
    ),
    (
        "amendment.propose",
        Shape::Object(&[m("accepted", Shape::Bool), m("amendment", Shape::Id)]),
    ),
    (
        "contract.draft",
        Shape::Object(&[m("accepted", Shape::Bool), m("contract", Shape::Id)]),
    ),
    (
        "report.generate",
        Shape::Object(&[m("accepted", Shape::Bool), m("report", Shape::Id)]),
    ),
    // SoD-07 (Daniel, 2026-11-15): a grant to the admin's own account
    // awaits a second admin and names the id the approval takes. Every
    // other grant answers `accepted` alone.
    (
        "roles.grant",
        Shape::Object(&[m("accepted", Shape::Bool), opt("approval", Shape::Id)]),
    ),
    // ADR-013: the client's redirect URI with the code, `state` and `iss`.
    (
        "agents.consent",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // The vault origin page that opens with a ticket (I-86).
    (
        "vault.bank.set",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    (
        "vault.bank.verify",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    (
        "vault.bank.dispute",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    (
        "vault.bank.view_for_release",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    (
        "vault.hardship.submit",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    (
        "vault.hardship.verify",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // ADR-023 (I-17): the coordinator unmask opens the vault origin's
    // release page. No identity attribute passes through the API.
    (
        "identity.unmask",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // ADR-023: the parties of one proposal and the staff of its
    // programme, by id, party kind and role. The label is the display
    // handle of a reviewer or IRC assignee, and empty otherwise. No
    // account and no identity attribute (I-17, I-86).
    (
        "identity.parties",
        Shape::Object(&[
            m("programme", Shape::Id),
            m("proposal", Shape::Id),
            m(
                "parties",
                Shape::Array(&Shape::Object(&[
                    m("party", Shape::Enum(PARTY_KINDS)),
                    m("subject_type", Shape::Enum(SUBJECT_TYPES)),
                    m("subject", Shape::Id),
                    m("role", Shape::Enum(ROLE_NAMES)),
                    m("label", Shape::String),
                ])),
            ),
        ]),
    ),
    // ADR-023 reading 11 (R-AU-01): the unmask records of a programme,
    // oldest first. `by` is the coordinator's account id, `at` the
    // instant in UTC microseconds. `conflict` says the coordinator held a
    // conflict fact on the subject's proposal (ADR-023 decision 2). No
    // identity attribute.
    (
        "audit.unmasks",
        Shape::Object(&[m(
            "unmasks",
            Shape::Array(&Shape::Object(&[
                m("party", Shape::Enum(PARTY_KINDS)),
                m("subject_type", Shape::Enum(SUBJECT_TYPES)),
                m("subject", Shape::Id),
                m("by", Shape::Id),
                m("purpose", Shape::String),
                m("conflict", Shape::Bool),
                m("at", Shape::Id),
            ])),
        )]),
    ),
    // R-AU-01, I-24: the ledger entries of a programme, newest first, for
    // its auditor, the tenant admins and its FSTP coordinator (SA-08). Each row names its side, its record kind, the acting
    // account and that account's role in the programme, the object it
    // acts on and the ids of the texts it references. ADR-007: a text is
    // named by its id, never shown. The hash is the SHA-256 of the
    // entry's stored RFC 8785 text, so a row can be checked against the
    // ledger (I-24).
    (
        "audit.entries",
        Shape::Object(&[
            m("programme", Shape::Id),
            m(
                "entries",
                Shape::Array(&Shape::Object(&[
                    m("seq", Shape::Id),
                    m("at", Shape::Id),
                    m("side", Shape::Enum(LEDGER_SIDES)),
                    m("kind", Shape::String),
                    m("actor", Shape::Nullable(&Shape::Id)),
                    m("actor_role", Shape::Enum(ACTOR_ROLES)),
                    m("object_type", Shape::Nullable(&Shape::Enum(OBJECT_TYPES))),
                    m("object", Shape::Nullable(&Shape::Id)),
                    m("texts", Shape::Array(&Shape::Id)),
                    m("hash", Shape::String),
                ])),
            ),
        ]),
    ),
    // `overview.md` NOTE 5, design section 3.6: the vault answers the
    // decisions of a programme used, as the ledger records them: the
    // query kind, its digest, the answer bit and the vault epoch. No
    // query, candidate set or attribute. Web only (I-86).
    (
        "audit.vault_outcomes",
        Shape::Object(&[
            m("programme", Shape::Id),
            m(
                "outcomes",
                Shape::Array(&Shape::Object(&[
                    m("seq", Shape::Id),
                    m("at", Shape::Id),
                    m("query", Shape::String),
                    m("digest", Shape::String),
                    m("holds", Shape::Bool),
                    m("epoch", Shape::Id),
                ])),
            ),
        ]),
    ),
    // I-85: the caller's own pending actions.
    (
        "pending.list",
        Shape::Array(&Shape::Object(&[
            m("id", Shape::Id),
            m("agent", Shape::Id),
            m("op", Shape::String),
            m("request", Shape::String),
            m("digest", Shape::String),
            m("created", Shape::String),
            m("expires", Shape::String),
            m(
                "status",
                Shape::Enum(&["open", "confirmed", "expired", "discarded"]),
            ),
            m("confirm_path", Shape::String),
        ])),
    ),
    ("calls.list_open", Shape::Array(&CALL)),
    // Lane mcreator: the drafted call the Studio opens next.
    (
        "call.draft",
        Shape::Object(&[m("accepted", Shape::Bool), m("call", Shape::Id)]),
    ),
    // Lane mcreator, R-PC-03: each call of the programme, its state, and
    // whether the caller may approve it now.
    (
        "call.list",
        Shape::Array(&Shape::Object(&[
            m("call", Shape::Id),
            m("status", Shape::Enum(&["draft", "approved", "published"])),
            m("may_approve", Shape::Bool),
        ])),
    ),
    ("calls.get", CALL),
    // R-GA-01, I-53: the Guide the publication stored, with its
    // corrigenda, its version and the hex SHA-256 of its canonical form.
    (
        "calls.guide",
        Shape::Object(&[
            m("call", Shape::Id),
            m("version", Shape::Int),
            m("digest", Shape::String),
            m("html", Shape::String),
        ]),
    ),
    // I-17: "Proposal" plus its id, never a name.
    ("proposal.list_own", Shape::Array(&OWN_PROPOSAL)),
    ("proposal.view", OWN_PROPOSAL),
    // I-17: no applicant identity.
    ("me.assignments", OWN_ASSIGNMENTS),
    // R-IR-01: the caller's IRC assignments, the same rows.
    ("me.irc_cases", OWN_ASSIGNMENTS),
    // J4: the drawn proposal the workspace opens next. Of the other drawn
    // ids, only a recorded plan and an opened round leave the server.
    (
        "proposal.create",
        Shape::Object(&[m("accepted", Shape::Bool), m("proposal", Shape::Id)]),
    ),
    // I-21: the team's private draft.
    (
        "proposal.get_workspace",
        Shape::Object(&[
            m("title", Shape::String),
            m("summary", Shape::String),
            m("narrative", Shape::String),
        ]),
    ),
    // M7 design section 4, R-LA-06, R-LA-08, TH-02, T-LLM-ORACLE: the
    // runs of a draft and the remaining P-23 checks. No score, band,
    // weight or confidence member exists, so none is derivable. The
    // remaining counts and the next instant are the only numbers.
    ("proposal.precheck", PRECHECK_VIEW),
    ("proposal.precheck_runs", PRECHECK_VIEW),
    // ADR-006, design section 3.9: the total the cell summed, and the id
    // the server drew for the plan, which a stage 2 revision names when
    // it is submitted (R-EV-05). The two travel together. A plan with no
    // milestone has neither, and the reply is `{"accepted": true}`.
    (
        "proposal.record_plan",
        Shape::Object(&[
            m("accepted", Shape::Bool),
            opt("plan", Shape::Id),
            opt("total", Shape::Amount),
        ]),
    ),
    // R-EV-05 (lane mapp): the page form of a stage 2 revision records
    // the plan and submits it in one entry, and answers as a recorded
    // plan does. The form that names a recorded plan answers
    // `{"accepted": true}`.
    (
        "stage2.revise",
        Shape::Object(&[
            m("accepted", Shape::Bool),
            opt("plan", Shape::Id),
            opt("total", Shape::Amount),
        ]),
    ),
    // TH-08: each question under its P-11 handle, with its day only.
    // Lane m4/author-reads (Daniel, 2026-11-15, night): the team reads back
    // its own answers, oldest first, each with its day and `after`, the
    // number of questions asked before it. An answer names no reviewer.
    (
        "stage2.view",
        Shape::Object(&[
            m(
                "questions",
                Shape::Array(&Shape::Object(&[
                    m("handle", Shape::String),
                    m("asked", Shape::String),
                    m("text", Shape::String),
                ])),
            ),
            m(
                "answers",
                Shape::Array(&Shape::Object(&[
                    m("after", Shape::Int),
                    m("answered", Shape::String),
                    m("text", Shape::String),
                ])),
            ),
        ]),
    ),
    // R-SB-01, ADR-006 (lane m4/author-reads): the head of the plan chain
    // the team recorded, or `null` before the first plan. Each milestone
    // has its amount and its start and due days. The total is the cell's
    // sum. The work plan text is left out when the plan names none, and
    // `text_erased` takes its place once it is erased (ADR-007).
    (
        "proposal.get_plan",
        Shape::Object(&[m("plan", Shape::Nullable(&PLAN_VIEW))]),
    ),
    // R-EV-04, R-IR-02: the kind and the proposal, and the day once known.
    (
        "me.notices",
        Shape::Array(&Shape::Object(&[
            m("kind", Shape::Enum(&["ProposalOutcome", "IrcConcern"])),
            m("proposal", Shape::Id),
            opt("day", Shape::String),
        ])),
    ),
    // R-NG-06.
    (
        "negotiation.view",
        Shape::Object(&[m("acknowledged", Shape::Bool)]),
    ),
    // R-EV-01: the P-09 criteria and the proposals of the intake.
    (
        "intake.queue",
        Shape::Object(&[
            m(
                "knock_out",
                Shape::Array(&Shape::Object(&[
                    m("id", Shape::Id),
                    m("text", Shape::String),
                ])),
            ),
            m("proposals", Shape::Array(&PROPOSAL_ROW)),
        ]),
    ),
    ("call.board", Shape::Array(&PROPOSAL_ROW)),
    // Q9, R-CF-02: the title and the neutral summary, and nothing else.
    (
        "review.declaration_view",
        Shape::Object(&[
            m("title", Shape::String),
            m("neutral_summary", Shape::String),
        ]),
    ),
    // R-AC-01, I-03: the submitted proposal in its current call.
    (
        "review.read_content",
        Shape::Object(&[
            m("proposal", Shape::Id),
            m("state", Shape::Enum(OWN_STATE_NAMES)),
            m("title", Shape::String),
            m("text", Shape::String),
            m("title_flags", FLAGS),
            m("text_flags", FLAGS),
            m("call", Shape::Id),
        ]),
    ),
    // R-IR-03: the proposal and the outcome that brought it to the IRC,
    // and no call, score, ballot or rationale.
    (
        "irc.case",
        Shape::Object(&[
            m("proposal", Shape::Id),
            m("state", Shape::Enum(OWN_STATE_NAMES)),
            m("title", Shape::String),
            m("text", Shape::String),
            m("title_flags", FLAGS),
            m("text_flags", FLAGS),
            m("outcome", Shape::Enum(&["nominated"])),
        ]),
    ),
    // R-CF-04: one draft per notifiable conflict, by proposal.
    (
        "review.notifiable_conflicts",
        Shape::Array(&Shape::Object(&[m("proposal", Shape::Id)])),
    ),
    // P-01: the integer scale 0 to N per criterion, and the reviewer's
    // current score of the plan the stage scores.
    (
        "review.score_sheet",
        Shape::Object(&[
            m("stage", Shape::Enum(&["One", "Two"])),
            m("plan", Shape::Id),
            m(
                "criteria",
                Shape::Array(&Shape::Object(&[
                    m("id", Shape::Id),
                    m("text", Shape::String),
                    m("max", Shape::Int),
                ])),
            ),
            m(
                "current",
                Shape::Nullable(&Shape::Object(&[
                    m("score", Shape::Id),
                    m("values", Shape::Array(&Shape::Int)),
                ])),
            ),
        ]),
    ),
    // I-10, I-17, TH-01: the assessor's findings on the reviewer's
    // proposal, each with the reader's own mark. The statement is
    // untrusted data, shown as text only. No member names an account.
    (
        "review.findings",
        Shape::Array(&Shape::Object(&[
            m("finding", Shape::Id),
            m(
                "kind",
                Shape::Enum(&["Completeness", "Quality", "Accuracy", "Integrity"]),
            ),
            m("severity", Shape::Enum(&["Info", "Minor", "Major"])),
            m("confidence", Shape::Int),
            m("statement", Shape::String),
            m(
                "mark",
                Shape::Nullable(&Shape::Enum(&["Agreed", "Disputed"])),
            ),
            // M7 design section 7, R-LA-08: which assessor produced it, so
            // the panel discloses a synthetic demo run as such.
            m("assessor", Shape::Enum(ASSESSOR_NAMES)),
        ])),
    ),
    // Issue 6 M3, I-10, H-03: the stages the output validator dropped from
    // the assessment of the reviewer's proposal. Closed enums of stage
    // names and refusal codes, so no model or submission text can fit.
    (
        "review.findings_refusals",
        Shape::Array(&Shape::Object(&[
            m("stage", Shape::Enum(REFUSED_STAGE_NAMES)),
            m("code", Shape::Enum(REFUSED_STAGE_CODES)),
        ])),
    ),
    // M7 design section 7: per submitted proposal, pending or ready and
    // a count. No statement, kind or severity (I-10).
    (
        "assess.findings_status",
        Shape::Array(&Shape::Object(&[
            m("proposal", Shape::Id),
            m("status", Shape::Enum(&["pending", "ready"])),
            m("findings", Shape::Int),
            // Issue 6 M3: how many stages the validator dropped, and
            // whether the coordinator may run the assessment again.
            m("refused", Shape::Int),
            m("rerun", Shape::Enum(&["available", "in_flight", "used_up"])),
            // ADR-035: the integrity hold and the scan's reason codes.
            m("integrity", Shape::Enum(&["clear", "held", "released"])),
            m("reasons", Shape::Array(&Shape::Enum(INTEGRITY_REASONS))),
        ])),
    ),
    // ADR-033: the queue names proposals by id and state, never a title.
    (
        "assess.client_queue",
        Shape::Object(&[
            m("call", Shape::Id),
            m("open", Shape::Bool),
            m("model", Shape::Nullable(&Shape::String)),
            m("prompt_set", PROMPT_SET),
            m(
                "proposals",
                Shape::Array(&Shape::Object(&[
                    m("proposal", Shape::Id),
                    m("state", Shape::Enum(OWN_STATE_NAMES)),
                    m(
                        "status",
                        Shape::Enum(&["awaiting", "assessed", "rerun", "held"]),
                    ),
                    m("declared", Shape::Bool),
                ])),
            ),
        ]),
    ),
    // ADR-033: the stripped submission under closed labels, and the tasks
    // as closed values. The texts are data (TH-60).
    (
        "assess.client_input",
        Shape::Object(&[
            m("proposal", Shape::Id),
            m("call", Shape::Id),
            m("input_digest", Shape::String),
            m("model", Shape::String),
            m("prompt_set", PROMPT_SET),
            m(
                "tasks",
                Shape::Array(&Shape::Object(&[
                    m("stage", Shape::Enum(CLIENT_STAGE_NAMES)),
                    m("criterion", Shape::Nullable(&Shape::String)),
                    m("elements", Shape::Array(&Shape::String)),
                ])),
            ),
            m(
                "parts",
                Shape::Array(&Shape::Object(&[
                    m("label", Shape::Enum(&["title", "summary", "narrative"])),
                    m("text", Shape::String),
                    m("flags", FLAGS),
                ])),
            ),
        ]),
    ),
    // ADR-033, I-10: a count and the dropped replies as closed names.
    (
        "assess.client_submit",
        Shape::Object(&[
            m("recorded", Shape::Int),
            m(
                "refused",
                Shape::Array(&Shape::Object(&[
                    m("stage", Shape::Enum(REFUSED_STAGE_NAMES)),
                    m("code", Shape::Enum(REFUSED_STAGE_CODES)),
                ])),
            ),
        ]),
    ),
    // R-EV-05, R-AN-01: a question names its asker by P-11 handle only.
    (
        "review.stage2_thread",
        Shape::Object(&[
            m("state", Shape::Enum(OWN_STATE_NAMES)),
            m("open", Shape::Bool),
            m("own_no_questions", Shape::Bool),
            m(
                "entries",
                Shape::Array(&Shape::Object(&[
                    m("kind", Shape::Enum(&["question", "answer"])),
                    m("author", Shape::Nullable(&Shape::String)),
                    m("text", Shape::String),
                ])),
            ),
        ]),
    ),
    // R-EV-08, Q16, D9, D10. A row the viewer is recused from carries
    // `proposal` and `recused` only. The shape kinds have no union, so
    // the members of a readable row are optional here, and the read
    // model's tests fix which row carries which. The remaining budget is
    // signed, since a call can be over-nominated, and an amount carries
    // no sign (ADR-006). Below zero, a readable row serves a zero
    // `remaining_budget` and a positive `shortfall`, as the domain codec
    // spells a signed amount. At zero and above it has no `shortfall`.
    (
        "committee.ranking",
        Shape::Array(&Shape::Object(&[
            m("proposal", Shape::Id),
            m("recused", Shape::Bool),
            opt("title", Shape::Nullable(&Shape::String)),
            opt("neutral_summary", Shape::Nullable(&Shape::String)),
            opt("rationale", Shape::Nullable(&Shape::String)),
            opt("effective", Shape::String),
            opt(
                "criterion_scores",
                Shape::Array(&Shape::Object(&[
                    m("criterion", Shape::Id),
                    m("weighted", Shape::String),
                ])),
            ),
            opt("requested", Shape::Amount),
            opt("remaining_budget", Shape::Amount),
            opt("shortfall", Shape::Amount),
        ])),
    ),
    // R-LG-04.
    (
        "me.sessions",
        Shape::Array(&Shape::Object(&[
            m("session", Shape::Id),
            m(
                "method",
                Shape::Enum(&["passkey", "magic_link", "opaque", "eudi_wallet"]),
            ),
            m("started", Shape::String),
        ])),
    ),
    // R-MC-03 (lane m4/ops-roles-agents): the caller's live agent
    // clients, the scopes of their tokens and how the consenting session
    // logged in. A client name is the client's own untrusted text.
    (
        "agents.list",
        Shape::Array(&Shape::Object(&[
            m("client", Shape::Id),
            opt("name", Shape::String),
            m("scopes", Shape::Array(&Shape::Enum(SCOPE_NAMES))),
            m(
                "method",
                Shape::Enum(&["passkey", "magic_link", "opaque", "eudi_wallet"]),
            ),
            opt("since", Shape::String),
            opt("until", Shape::String),
        ])),
    ),
    // Lane L2 (ADR-013 amendment of 2026-11-20): the pending consent the
    // consent page shows. The client name is the client's own untrusted
    // text. No account, handle or digest (I-86).
    (
        "agents.consent_request",
        Shape::Object(&[
            m("client", Shape::Id),
            opt("name", Shape::String),
            m("redirect_host", Shape::String),
            m("loopback", Shape::Bool),
            m("scopes", Shape::Array(&Shape::Enum(SCOPE_NAMES))),
            m("expires", Shape::String),
        ]),
    ),
    // R-MC-03: the caller's own calls through one agent client, newest
    // first. No request content.
    (
        "agents.activity",
        Shape::Array(&Shape::Object(&[
            m("op", Shape::String),
            m("outcome", Shape::Enum(&["accepted", "pending", "refused"])),
            opt("rule", Shape::String),
            m("at", Shape::String),
        ])),
    ),
    // J1 (lane m4/ops-roles-agents): the Drafting, Judging and Operations
    // bindings of a programme, held or voided, by account id only.
    (
        "roles.list",
        Shape::Array(&Shape::Object(&[
            m("binding", Shape::Id),
            m("account", Shape::Id),
            m("role", Shape::Enum(ROLE_NAMES)),
            m("start", Shape::String),
            opt("end", Shape::String),
            m("state", Shape::Enum(&["active", "suspended", "voided"])),
            opt("rule", Shape::String),
        ])),
    ),
    (
        "me.begin_verification",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // I-18 (lane mapp): the vault's write page, where the guardian gives
    // consent.
    (
        "guardian.begin_consent",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // I-86, design section 15.0 (2026-10-31): the caller's own active
    // bindings by role, programme, proposal and published call, the
    // title of each call they name, and the open cut-off rounds of the
    // caller's committee calls, and the caller's programme manager
    // programmes that hold a creator draft. No name, no email and no
    // other account. NOTE 5 (design section 15.0, 2026-11-06): the
    // tenant-wide signatory roles the caller holds, Financial first.
    // A call title is the published call text, which anyone may read.
    (
        "me.roles",
        Shape::Object(&[
            m("tenant_admin", Shape::Bool),
            m(
                "roles",
                Shape::Array(&Shape::Object(&[
                    m("role", Shape::Enum(ROLE_NAMES)),
                    m("programme", Shape::Id),
                    opt("proposal", Shape::Id),
                    m("calls", Shape::Array(&Shape::Id)),
                ])),
            ),
            m(
                "calls",
                Shape::Array(&Shape::Object(&[
                    m("call", Shape::Id),
                    opt("title", Shape::String),
                ])),
            ),
            m(
                "rounds",
                Shape::Array(&Shape::Object(&[
                    m("round", Shape::Id),
                    m("call", Shape::Id),
                ])),
            ),
            m("drafts", Shape::Array(&Shape::Id)),
            m(
                "signatories",
                Shape::Array(&Shape::Enum(&["financial_signatory", "legal_signatory"])),
            ),
        ]),
    ),
    // Lane m6/mailbox (`docs/handoff/mailbox-design.md` section 1, I-27,
    // I-86): ids, kinds, instants, a flag and a path under `/app/`. No
    // title, text, score, name or email.
    (
        "me.mailbox",
        Shape::Object(&[
            m("open", Shape::Int),
            m(
                "messages",
                Shape::Array(&Shape::Object(&[
                    m("id", Shape::String),
                    m("kind", Shape::Enum(MAILBOX_KINDS)),
                    m("action", Shape::Bool),
                    m("href", Shape::String),
                    // MB-Q1, ADR-020: a notice's per-account read mark.
                    opt("read", Shape::Bool),
                    // MB-Q2: the ordinal of an unanswered stage 2 question.
                    opt("question", Shape::Id),
                    // MB-Q3: the role binding and the invitation.
                    opt("binding", Shape::Id),
                    opt("invitation", Shape::Id),
                    // ADR-008: the ordinal of a disabled passkey's flagging event.
                    opt("passkey", Shape::Id),
                    opt("since", Shape::Id),
                    opt("due", Shape::Id),
                    opt("proposal", Shape::Id),
                    opt("call", Shape::Id),
                    opt("assignment", Shape::Id),
                    opt("round", Shape::Id),
                    opt("contract", Shape::Id),
                    opt("request", Shape::Id),
                    opt("pending", Shape::Id),
                    opt("programme", Shape::Id),
                ])),
            ),
        ]),
    ),
    // Lane m4reg. SoD-07: each admin by account and pseudonymous handle,
    // never an email.
    (
        "tenant.list_admins",
        Shape::Object(&[m(
            "admins",
            Shape::Array(&Shape::Object(&[
                m("account", Shape::Id),
                m("handle", Shape::String),
                m("verified", Shape::Bool),
            ])),
        )]),
    ),
    // Lane m4/roles. NOTE 5: each signatory binding by account, role and
    // pseudonymous handle. A binding is tenant-wide, so no row names a
    // programme.
    (
        "tenant.list_signatories",
        Shape::Object(&[m(
            "signatories",
            Shape::Array(&Shape::Object(&[
                m("account", Shape::Id),
                m(
                    "role",
                    Shape::Enum(&["financial_signatory", "legal_signatory"]),
                ),
                m("handle", Shape::String),
            ])),
        )]),
    ),
    // SoD-18: the activation state, its open or approved request, and the
    // requesting and approving admins by account.
    (
        "tenant.get_activation",
        Shape::Object(&[
            m(
                "state",
                Shape::Enum(&["not_requested", "requested", "active"]),
            ),
            m("request", Shape::Nullable(&Shape::Id)),
            m("requested_by", Shape::Nullable(&Shape::Id)),
            m("approved_by", Shape::Nullable(&Shape::Id)),
        ]),
    ),
    // M9 lane B1, I-70: whether the tokens pass, and the failing pairs of
    // the table by name (`fstp_brand::Pair::name`), never a colour.
    (
        "tenant.branding.check",
        Shape::Object(&[
            m("accepted", Shape::Bool),
            m("failing", Shape::Array(&Shape::Enum(BRAND_PAIR_NAMES))),
        ]),
    ),
    // ADR-030: the tenant's logos in light and dark, and each
    // programme's. A path names a digest only, never tenant text.
    ("tenant.branding.logos", LOGOS),
    // ADR-030 (lead reading of 2026-11-22): the same reply for one
    // programme, to its programme managers.
    ("programme.logos", LOGOS),
    // Lane m4tenant. R-TN-01: one onboarding step, and the reply of its
    // save. The values are those of `fstp-tenant`'s codec, with the data
    // protection contact as its text.
    ("tenant.get_step", ONBOARDING_STEP),
    ("tenant.save_step", ONBOARDING_STEP),
    // R-LG-03: each tenant setting in the codec form of its parameter.
    (
        "tenant.settings",
        Shape::Object(&[
            m(
                "p20",
                Shape::Nullable(&Shape::Enum(&["execution", "record_only"])),
            ),
            m("p69", Shape::String),
            m(
                "p70",
                Shape::Array(&Shape::Enum(&[
                    "eudi_wallet",
                    "magic_link",
                    "opaque",
                    "passkey",
                ])),
            ),
            m("p71", Shape::String),
            m(
                "p72",
                Shape::Object(&[m("absolute_us", Shape::String), m("idle_us", Shape::String)]),
            ),
            m(
                "p74",
                Shape::Object(&[
                    m("enabled", Shape::Bool),
                    m("public_tools", Shape::Bool),
                    m("roles", Shape::Nullable(&Shape::Array(&Shape::String))),
                ]),
            ),
        ]),
    ),
    // M6 lane L6-API (ADR-018): the relay host and whether a CA is pinned.
    // The credential's secret name is never shown.
    (
        "tenant.get_mail_relay",
        Shape::Object(&[m(
            "relay",
            Shape::Nullable(&Shape::Object(&[
                m("host", Shape::String),
                m("ca_pinned", Shape::Bool),
            ])),
        )]),
    ),
    // Daniel, 2026-11-15 (late): every shipped and tenant-owned funder
    // profile version, with its owner, file hash, the version a copy was
    // made from, and its profile text, which the admin edits.
    (
        "tenant.funder_profiles",
        Shape::Object(&[m(
            "profiles",
            Shape::Array(&Shape::Object(&[
                m("id", Shape::String),
                m("version", Shape::Id),
                m("owner", Shape::Enum(&["shipped", "tenant"])),
                m("digest", Shape::String),
                m(
                    "source",
                    Shape::Nullable(&Shape::Object(&[
                        m("profile", Shape::String),
                        m("version", Shape::Id),
                    ])),
                ),
                m("text", Shape::String),
            ])),
        )]),
    ),
    // M6 lane L6-API, M6 design section 6, I-27: per message its template,
    // event, version, phase, attempts and reply code. No body, no address.
    (
        "tenant.deliveries",
        Shape::Array(&Shape::Object(&[
            m("outbox", Shape::String),
            m("template", Shape::String),
            m("event", Shape::String),
            m("template_version", Shape::Id),
            m(
                "phase",
                Shape::Enum(&[
                    "claimed",
                    "committing",
                    "sent",
                    "transient",
                    "permanent",
                    "in_doubt",
                ]),
            ),
            m("attempts", Shape::Int),
            m("reply_code", Shape::Nullable(&Shape::Int)),
        ])),
    ),
    // P-41, ADR-007 (lane m5/retention): the erasure log, entry by entry,
    // with its cause and times and the grant it served, and the grants
    // whose funder retention ended. Ids, causes and instants only (I-27).
    (
        "admin.erasures",
        Shape::Object(&[
            m(
                "erasures",
                Shape::Array(&Shape::Object(&[
                    m("text", Shape::Id),
                    m("cause", Shape::Enum(ERASURE_CAUSES)),
                    m("grant", Shape::Nullable(&Shape::Id)),
                    m("requested_at", Shape::Id),
                    m("completed_at", Shape::Nullable(&Shape::Id)),
                    // Lane L33: what the text held, and the destroyed root
                    // epoch once known (I-81).
                    m("kind", Shape::Enum(ERASURE_KINDS)),
                    m("destroyed_epoch", Shape::Nullable(&Shape::Id)),
                    // Lane L39 (ADR-007, Daniel 2026-11-23): whether the
                    // system or an account authorised it, never which
                    // account (R-CF-03), and the stated reason, resolved
                    // for the reader (I-97).
                    m("authoriser", Shape::Enum(ERASURE_AUTHORISERS)),
                    m("reason", Shape::Nullable(&Shape::String)),
                ])),
            ),
            m(
                "retention_ended",
                Shape::Array(&Shape::Object(&[
                    m("grant", Shape::Id),
                    m("programme", Shape::Id),
                    m("start", Shape::Id),
                    m("end", Shape::Id),
                ])),
            ),
            // Lane L39: the import documents a tenant admin may erase.
            m(
                "documents",
                Shape::Array(&Shape::Object(&[
                    m("document", Shape::Id),
                    m("programme", Shape::Id),
                    m("media", Shape::Enum(IMPORT_MEDIA)),
                    m("erased", Shape::Bool),
                ])),
            ),
        ]),
    ),
    // ADR-028 record of lane L20: the facts of the System page. Instants,
    // counts, flags and closed words only (R-NF-02).
    (
        "tenant.system",
        Shape::Object(&[
            m("now", Shape::Id),
            m("vault", Shape::Enum(&["answers", "silent"])),
            m("mail", Shape::Enum(&["works", "fails", "not_configured"])),
            m("last_cell_erasure", Shape::Nullable(&Shape::Id)),
            m(
                "host_file",
                Shape::Enum(&["present", "not_configured", "missing", "unreadable"]),
            ),
            m(
                "host",
                Shape::Nullable(&Shape::Object(&[
                    m("written_at", Shape::Id),
                    m("setup_done", Shape::Bool),
                    m(
                        "parts",
                        Shape::Object(&[
                            m("cell", Shape::Enum(PART_STATES)),
                            m("vault", Shape::Enum(PART_STATES)),
                            m("witness", Shape::Enum(PART_STATES)),
                            m("edge", Shape::Enum(PART_STATES)),
                            m("databases", Shape::Enum(PART_STATES)),
                            m("keys", Shape::Enum(PART_STATES)),
                        ]),
                    ),
                    m("backups_configured", Shape::Bool),
                    m("last_backup", Shape::Nullable(&Shape::Id)),
                    m("last_key_copy", Shape::Nullable(&Shape::Id)),
                    m("last_vault_erasure", Shape::Nullable(&Shape::Id)),
                    // ADR-028 record of lane L26: the keystore snapshots of L27.
                    m("last_app_snapshot", Shape::Nullable(&Shape::Id)),
                    m("app_snapshot_failed", Shape::Bool),
                    m("last_vault_snapshot", Shape::Nullable(&Shape::Id)),
                    m("vault_snapshot_failed", Shape::Bool),
                    m("certificate_days", Shape::Nullable(&Shape::Int)),
                    m("self_signed", Shape::Bool),
                    m("route", Shape::Enum(&["current", "mismatch", "unknown"])),
                    m("next", Shape::Enum(HOST_NEXT)),
                ])),
            ),
        ]),
    ),
    // M6 lane L6-API, M6 design section 6, R-NT-01: the events of a
    // programme, with their due instant and where each stands.
    (
        "programme.timeline",
        Shape::Array(&Shape::Object(&[
            m("event", Shape::String),
            m(
                "kind",
                Shape::Enum(&[
                    "immediate",
                    "stage2_expiry",
                    "re_enter",
                    "start_execution",
                    "complete",
                    "milestone_reminder",
                    "milestone_overdue",
                    "corrigendum",
                    "notice_issued",
                    "copy_requested",
                    "retention_end",
                    "reporting_period_end",
                    "report_deadline",
                    "signer_rotation_due",
                    "passkey_disabled",
                    "role_invitation",
                ]),
            ),
            m("due", Shape::Id),
            m("status", Shape::Enum(&["scheduled", "cancelled", "fired"])),
        ])),
    ),
    // I-86: the state only, and no other vault fact.
    (
        "me.get_verification",
        Shape::Object(&[m(
            "status",
            Shape::Enum(&["unverified", "pending", "verified"]),
        )]),
    ),
    // R-PG-02: the clone sources.
    (
        "creator.list_programmes",
        Shape::Object(&[m(
            "programmes",
            Shape::Array(&Shape::Object(&[
                m("id", Shape::Id),
                m("name", Shape::String),
            ])),
        )]),
    ),
    // R-PG-02, R-PG-05: the template catalogue.
    (
        "creator.list_templates",
        Shape::Object(&[m(
            "templates",
            Shape::Array(&Shape::Object(&[
                m("id", Shape::Id),
                m("version", Shape::Int),
                m("name", Shape::String),
            ])),
        )]),
    ),
    // Lane m4wire, R-PG-01: the draft the server drew, which the creator
    // pages open next.
    (
        "creator.open_draft",
        Shape::Object(&[m("accepted", Shape::Bool), m("programme", Shape::Id)]),
    ),
    // Lane m4wire, I-66, R-PG-01 AC: each row names its check, its
    // severity, whether a live acknowledgement holds and the key an
    // acknowledgement names. The detail holds string values only, never
    // an account (R-CF-03).
    (
        "creator.get_report",
        Shape::Object(&[
            m("revision", Shape::String),
            m(
                "results",
                Shape::Array(&Shape::Object(&[
                    m("check", Shape::String),
                    m("severity", Shape::Enum(&["failure", "warning"])),
                    m("acknowledged", Shape::Bool),
                    m("key", Shape::String),
                    m("field", Shape::Nullable(&Shape::String)),
                    opt("detail", REPORT_DETAIL),
                ])),
            ),
        ]),
    ),
    // SA-11 (Daniel, 2026-11-15, night): the team of a programme. Each
    // row is a Drafting, Judging or Operations role, or an open
    // invitation, with the display name and the invitation or login
    // email. `actions` names what the viewer may offer. Web only (I-86).
    (
        "team.list",
        Shape::Object(&[
            m("actions", Shape::Array(&Shape::Enum(TEAM_ACTIONS))),
            m(
                "rows",
                Shape::Array(&Shape::Object(&[
                    m("account", Shape::Nullable(&Shape::Id)),
                    m("display_name", Shape::Nullable(&Shape::String)),
                    m("email", Shape::Nullable(&Shape::String)),
                    m("binding", Shape::Nullable(&Shape::Id)),
                    m("invitation", Shape::Nullable(&Shape::Id)),
                    m("role", Shape::Enum(TEAM_ROLES)),
                    m("status", Shape::Enum(TEAM_STATUSES)),
                    opt("rule", Shape::String),
                    m("start", Shape::Nullable(&Shape::String)),
                    m("end", Shape::Nullable(&Shape::String)),
                ])),
            ),
        ]),
    ),
    // SA-11: every member account of the organisation, with its display
    // name, its login email, whether it is a tenant admin, and its roles
    // across programmes. Web only (I-86).
    (
        "admin.members",
        Shape::Object(&[
            m("actions", Shape::Array(&Shape::Enum(TEAM_ACTIONS))),
            m(
                "members",
                Shape::Array(&Shape::Object(&[
                    m("account", Shape::Id),
                    m("display_name", Shape::Nullable(&Shape::String)),
                    m("email", Shape::Nullable(&Shape::String)),
                    m("tenant_admin", Shape::Bool),
                    m("roles", Shape::Array(&MEMBER_ROLE)),
                ])),
            ),
        ]),
    ),
    // SA-11: the caller's own display name, or null when none is set.
    (
        "me.display_name",
        Shape::Object(&[m("display_name", Shape::Nullable(&Shape::String))]),
    ),
    // Lane m4wire, SoD-09, D3: each invitation with its live SoD check,
    // which names a rule only, never an account (R-CF-03).
    (
        "creator.invitations",
        Shape::Object(&[m(
            "invitations",
            Shape::Array(&Shape::Object(&[
                m("id", Shape::Id),
                m("email", Shape::String),
                m("role", Shape::Enum(INVITED_ROLES)),
                m(
                    "state",
                    Shape::Enum(&["invited", "accepted", "verified", "granted"]),
                ),
                m("sod", Shape::Enum(&["pass", "fail", "unchecked"])),
                opt("rule", Shape::String),
                // Design doc 11, Q3: the role dates the grant reuses, in
                // microseconds as canonical decimal strings.
                m("start", Shape::String),
                m("end", Shape::Nullable(&Shape::String)),
            ])),
        )]),
    ),
    // Lane m4wire, I-67, SoD-07: the approval inbox. An activation row
    // says whether the viewer may approve it. A self-grant row names its
    // approval, the role, the grantee's handle and the dates.
    // `unlisted` names each kind of approval the server cannot list yet,
    // so the inbox never reads as complete when it is not.
    (
        "admin.approvals",
        Shape::Object(&[
            m(
                "approvals",
                Shape::Array(&Shape::Object(&[
                    m("kind", Shape::Enum(&["activation", "self_grant"])),
                    m("programme", Shape::Id),
                    opt("revision", Shape::String),
                    m("approvable", Shape::Bool),
                    // ADR-022: an activation row says whether the viewer,
                    // a builder admin, may approve it as an override.
                    opt("overridable", Shape::Bool),
                    opt("name", Shape::Nullable(&Shape::String)),
                    opt("approval", Shape::Id),
                    opt("role", Shape::String),
                    opt("grantee", Shape::String),
                    // SoD-07: the dates of a self-grant awaiting approval,
                    // in microseconds.
                    opt("start", Shape::String),
                    opt("end", Shape::Nullable(&Shape::String)),
                ])),
            ),
            opt("unlisted", Shape::Array(&Shape::Enum(&["self_grant"]))),
        ]),
    ),
    // Lane m4wire, R-PG-04: the calls an edit of the draft affects.
    (
        "creator.impact",
        Shape::Object(&[m(
            "calls",
            Shape::Array(&Shape::Object(&[m("call", Shape::Id)])),
        )]),
    ),
    // SoD-09, J2 (lane inv): where the acceptor goes to verify identity,
    // as for `me.begin_verification`.
    (
        "people.begin_verification",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // SoD-09, J2: the role, the terms version, the programme's P-75 and
    // P-77 choices for the terms of a Judging role, and the state.
    (
        "people.get_invitation",
        Shape::Object(&[
            m("role", Shape::Enum(INVITED_ROLES)),
            m("terms_version", Shape::Int),
            m("p75", Shape::Nullable(&Shape::Bool)),
            m(
                "p77",
                Shape::Nullable(&Shape::Enum(&["draft_only", "allowed"])),
            ),
            m(
                "state",
                Shape::Enum(&["invited", "accepted", "verified", "granted"]),
            ),
        ]),
    ),
    // R-AC-01, R-CF-03, I-17: assignees and candidates by label only, and
    // the SoD-10 and SoD-11 checks as pass or fail.
    (
        "review.assignments",
        Shape::Object(&[
            m("state", Shape::Enum(STATE_NAMES)),
            m(
                "assigned",
                Shape::Array(&Shape::Object(&[
                    m("assignment", Shape::Id),
                    m("label", Shape::String),
                ])),
            ),
            m(
                "candidates",
                Shape::Array(&Shape::Object(&[
                    m("account", Shape::Id),
                    m("label", Shape::String),
                ])),
            ),
            m(
                "checks",
                Shape::Object(&[m("p39", OUTCOME), m("proximity", OUTCOME)]),
            ),
        ]),
    ),
    // R-EV-08, change D5: the round the server drew, which the ballot,
    // the delegation and the round read address. It names no voter.
    (
        "committee.open_round",
        Shape::Object(&[m("round", Shape::Id)]),
    ),
    // R-EV-08, R-EV-09, P-16 NOTE 8, change D5: one round. It counts the
    // ballots and names no voter. Its status is open, recorded or
    // superseded, and only an open round takes ballots, delegations and
    // the record. The viewer reads their own vote or delegation only.
    // Recusal is judged on an open round only and is null otherwise. The
    // delegates are labels of members who are not recused. The order
    // lists proposals by id with their state now.
    (
        "committee.round",
        Shape::Object(&[
            m("round", Shape::Id),
            m("call", Shape::Id),
            m("status", Shape::Enum(&["open", "recorded", "superseded"])),
            m(
                "order",
                Shape::Array(&Shape::Object(&[
                    m("proposal", Shape::Id),
                    m("state", Shape::Enum(STATE_NAMES)),
                ])),
            ),
            m("nominated", Shape::Int),
            m("rationale", Shape::String),
            m("tie_break", Shape::Nullable(&Shape::String)),
            m("ballots_cast", Shape::Int),
            m(
                "viewer",
                Shape::Object(&[
                    m("recused", Shape::Nullable(&Shape::Bool)),
                    m(
                        "own_vote",
                        Shape::Nullable(&Shape::Enum(&["For", "Against", "Abstain"])),
                    ),
                    m("delegated_to", Shape::Nullable(&Shape::Id)),
                ]),
            ),
            m(
                "delegates",
                Shape::Array(&Shape::Object(&[
                    m("account", Shape::Id),
                    m("label", Shape::String),
                ])),
            ),
        ]),
    ),
    // Lane j2, `SPEC/12-journey-ui.md` section 10, R-JV-01, R-JV-07: the
    // current node with its formal state name, the completed legs, whether
    // the caller's role gets the route strip (O-58), whether the caller gets
    // the full map (the team, section 8.1) and the withdrawal control (the
    // lead, NOTE 10; lane j4), and the overlay of the proposal's original
    // call, null before that call is published.
    // I-97: ids, states, times and codes only, never text.
    ("proposal.journey", JOURNEY_REPLY),
    // Lane j2, section 10, I-93, I-97: the diary entries the visibility
    // function lets the caller see, in ledger order. A sentence is its
    // catalogue key and typed parameters, and a text is its reference or
    // the erasure placeholder of section 7.3.
    ("proposal.diary", DIARY_REPLY),
];

/// The entry kinds of `SPEC/12-journey-ui.md` section 7.2, and the
/// guardian step of O-60, as the wire spells them.
pub const ENTRY_KIND_NAMES: &[&str] = &[
    "state_transition",
    "deadline_set",
    "notice_sent",
    "clarification",
    "reviewer_score",
    "conflict",
    "vault_outcome",
    "contract",
    "milestone_payment",
    "complaint",
    "agent_action",
    "guardian_step",
];

/// The parameters of section 5.5 that show as a wording choice, by id.
const WORDING_PARAM_NAMES: &[&str] = &["P-08", "P-20", "P-50", "P-51", "P-60", "P-65", "P-66"];

/// One completed leg of a route.
const LEG: Shape = Shape::Object(&[
    m("from", Shape::Enum(STATE_NAMES)),
    m("to", Shape::Enum(STATE_NAMES)),
    m("at", Shape::String),
    m("seq", Shape::Id),
]);

/// The programme overlay of section 5.5 (R-JV-07). Opaque parameters
/// appear by id only (I-97).
const OVERLAY: Shape = Shape::Object(&[
    m("policy", Shape::Id),
    m("stage2_window_days", Shape::Int),
    m("anonymity", Shape::Enum(&["anonymous", "named"])),
    m("irc_concern", Shape::Enum(&["deferred", "declined"])),
    m("agent_actions", Shape::Enum(&["draft_only", "allowed"])),
    m("wording", Shape::Array(&Shape::Enum(WORDING_PARAM_NAMES))),
]);

/// The `proposal.journey` reply.
const JOURNEY_REPLY: Shape = Shape::Object(&[
    m("proposal", Shape::Id),
    m("state", Shape::Enum(STATE_NAMES)),
    m("since", Shape::String),
    m("seq", Shape::Id),
    m("legs", Shape::Array(&LEG)),
    m("strip", Shape::Bool),
    m("map", Shape::Bool),
    m("withdraw", Shape::Bool),
    m("overlay", Shape::Nullable(&OVERLAY)),
]);

/// One sentence parameter of a diary entry: exactly one member is set.
const DIARY_PARAM: Shape = Shape::Object(&[
    opt("state", Shape::Enum(STATE_NAMES)),
    opt("amount", Shape::Amount),
    opt("seq", Shape::Id),
    opt("score", Shape::Array(&Shape::Int)),
    opt("outcome", Shape::Bool),
    opt("time", Shape::String),
]);

/// One text slot of a diary entry: a live reference (`text` and
/// `digest`), or the erasure placeholder (`erased_on` and `cause`).
const DIARY_TEXT: Shape = Shape::Object(&[
    opt("text", Shape::Id),
    opt("digest", Shape::String),
    opt("erased_on", Shape::String),
    opt("cause", Shape::Int),
]);

/// One diary entry. `entry` and `supersedes` are 32 lowercase hex digits.
const DIARY_ENTRY: Shape = Shape::Object(&[
    m("entry", Shape::String),
    m("seq", Shape::Id),
    m("kind", Shape::Enum(ENTRY_KIND_NAMES)),
    m(
        "subject",
        Shape::Enum(&["proposal", "call", "payment_request"]),
    ),
    m("subject_id", Shape::Id),
    m("key", Shape::String),
    m("at", Shape::String),
    opt("zone", Shape::String),
    opt("supersedes", Shape::String),
    m("params", Shape::Array(&DIARY_PARAM)),
    m("texts", Shape::Array(&DIARY_TEXT)),
]);

/// The `proposal.diary` reply.
const DIARY_REPLY: Shape = Shape::Object(&[
    m("proposal", Shape::Id),
    m("entries", Shape::Array(&DIARY_ENTRY)),
]);

/// The pair names of the I-70 table of `fstp_brand`, in table order
/// (M9 lane B1). The API core tests them against `fstp_brand::Pair`.
pub const BRAND_PAIR_NAMES: &[&str] = &[
    "light.brand-text/surface-0",
    "light.brand-text/surface-1",
    "light.on-brand/brand",
    "light.on-brand/brand-hover",
    "light.focus/surface-0",
    "dark.brand-text/surface-0",
    "dark.brand-text/surface-1",
    "dark.on-brand/brand",
    "dark.on-brand/brand-hover",
    "dark.focus/surface-0",
];

/// The reply shape of the operation named `name`.
pub fn reply(name: &str) -> Option<&'static Shape> {
    REPLIES.iter().find(|(n, _)| *n == name).map(|(_, s)| s)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeSet;

    use fstp_domain::StateTag;

    use super::*;

    /// TH-26: every entry names an operation of the registry, once.
    #[test]
    fn th26_replies_name_registry_operations_once() {
        let mut seen = BTreeSet::new();
        for (name, _) in REPLIES {
            assert!(crate::op(name).is_some(), "{name} is not in OPS");
            assert!(seen.insert(*name), "{name} is listed twice");
        }
    }

    /// SoD-09, `programme-creator.md` step 9: the invited roles are the
    /// invitable roles in the order of the roles table, the finance roles
    /// among them, and no Receiving role or tenant admin.
    #[test]
    fn sod09_invited_roles_are_the_invitable_roles() {
        let want: Vec<&str> = Role::ALL
            .iter()
            .filter(|r| invitable(**r))
            .map(|r| role_wire_name(*r))
            .collect();
        assert_eq!(INVITED_ROLES, want.as_slice());
        for r in [
            Role::FinanceApprover,
            Role::PaymentReleaser,
            Role::ContractSignatory,
            Role::Auditor,
        ] {
            assert!(INVITED_ROLES.contains(&role_wire_name(r)), "{r:?}");
        }
        for r in [
            Role::Applicant,
            Role::ApplicantTeamMember,
            Role::Guardian,
            Role::TenantAdmin,
        ] {
            assert!(!invitable(r), "{r:?}");
        }
    }

    /// I-86: the roles of `me.roles` are every role by its wire name, in
    /// the order of the roles table, so the home page names each binding
    /// as the other replies do (design section 15.0, 2026-10-31).
    #[test]
    fn i86_me_roles_role_names_are_the_wire_names() {
        let want: Vec<&str> = Role::ALL.iter().map(|r| role_wire_name(*r)).collect();
        assert_eq!(ROLE_NAMES, want.as_slice());
    }

    /// R-MC-03: the scopes of `agents.list` are every scope as the OAuth
    /// server spells it, in declaration order.
    #[test]
    fn r_mc_03_agent_scope_names_are_the_oauth_names() {
        let want: Vec<&str> = crate::Scope::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(SCOPE_NAMES, want.as_slice());
    }

    /// SoD-09: each role has its own wire name, in snake case.
    #[test]
    fn sod09_role_wire_names_are_distinct_snake_case() {
        let names: BTreeSet<&str> = Role::ALL.iter().map(|r| role_wire_name(*r)).collect();
        assert_eq!(names.len(), Role::ALL.len());
        for n in names {
            assert!(
                n.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'),
                "{n}"
            );
        }
    }

    /// TH-26: the state names are the state machine's, in its order.
    #[test]
    fn th26_state_names_are_the_state_machine_names() {
        let want: Vec<&str> = StateTag::ALL.iter().map(|s| s.spec_name()).collect();
        assert_eq!(STATE_NAMES, want.as_slice());
        let own = OWN_STATE_NAMES.split_last().map(|(l, rest)| (*l, rest));
        assert_eq!(own, Some(("UNKNOWN", want.as_slice())));
    }

    /// TH-26: no object shape names a member twice, and no enum repeats a
    /// value, so each shape has one reading.
    #[test]
    fn th26_shapes_have_unique_members_and_values() {
        fn walk(s: &Shape) {
            match s {
                Shape::Enum(values) => {
                    let set: BTreeSet<&str> = values.iter().copied().collect();
                    assert_eq!(set.len(), values.len(), "{values:?}");
                    assert!(!values.is_empty());
                }
                Shape::Array(inner) | Shape::Nullable(inner) => walk(inner),
                Shape::Object(members) => {
                    let set: BTreeSet<&str> = members.iter().map(|x| x.name).collect();
                    assert_eq!(set.len(), members.len(), "{members:?}");
                    for x in *members {
                        walk(&x.shape);
                    }
                }
                _ => {}
            }
        }
        for (_, s) in REPLIES {
            walk(s);
        }
    }
}
