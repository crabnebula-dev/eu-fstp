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
//! `{"accepted": true}` today and have no entry yet. The one exception is
//! `committee.open_round`: the server draws the round id, and the
//! committee page needs it to address the round. Its entry fixes that
//! reply, `{"round": id}`.
//!
//! Seam for lane m4int-b: dispatch still answers `committee.open_round`
//! with `{"accepted": true}`. It must serve
//! `fstp_api_core::model::RoundOpened` with the drawn id instead.

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
/// Receiving group, except tenant admin (`programme-creator.md` step 9,
/// SoD-09). This is the rule `fstp_creator::decide_creator` applies to
/// `Invite`, so the landing exists for every invitation it records.
pub const fn invitable(role: Role) -> bool {
    !matches!(role.group(), Group::Receiving) && !matches!(role, Role::TenantAdmin)
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
        Role::Auditor => "auditor",
    }
}

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
    ("calls.get", CALL),
    // I-17: "Proposal" plus its id, never a name.
    (
        "proposal.list_own",
        Shape::Array(&Shape::Object(&[
            m("proposal", Shape::Id),
            m("call", Shape::Id),
            m("state", Shape::Enum(OWN_STATE_NAMES)),
            m("role", Shape::Enum(&["lead", "member", "guardian"])),
        ])),
    ),
    // I-17: no applicant identity.
    (
        "me.assignments",
        Shape::Array(&Shape::Object(&[
            m("assignment", Shape::Id),
            m("proposal", Shape::Id),
            m("call", Shape::Id),
            m("kind", Shape::Enum(&["reviewer", "irc", "amendment"])),
            m("awaiting_declaration", Shape::Bool),
            m("active", Shape::Bool),
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
