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

/// The reply shape of each operation whose `data` the API core serves,
/// by operation name.
pub const REPLIES: &[(&str, Shape)] = &[
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
    // TH-08: each question under its P-11 handle, with its day only.
    (
        "stage2.view",
        Shape::Object(&[m(
            "questions",
            Shape::Array(&Shape::Object(&[
                m("handle", Shape::String),
                m("asked", Shape::String),
                m("text", Shape::String),
            ])),
        )]),
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
    (
        "me.begin_verification",
        Shape::Object(&[m("redirect", Shape::String)]),
    ),
    // I-86, design section 15.0 (2026-10-31): the caller's own active
    // bindings by role, programme, proposal and published call, the
    // title of each call they name, and the open cut-off rounds of the
    // caller's committee calls, and the caller's programme manager
    // programmes that hold a creator draft. No name, no email and no
    // other account.
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
            ])),
        )]),
    ),
    // Lane m4wire, I-67, SoD-07: the approval inbox. An activation row
    // says whether the viewer may approve it. A self-grant row (the
    // tenant lane) names its approval, the role and the grantee's handle.
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
                    opt("name", Shape::Nullable(&Shape::String)),
                    opt("approval", Shape::Id),
                    opt("role", Shape::String),
                    opt("grantee", Shape::String),
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
    // the caller's role gets the route strip (O-58), and the overlay of the
    // proposal's original call, null before that call is published.
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
