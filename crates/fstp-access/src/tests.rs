//! Unit tests of the principal, the channel rules and the read rules
//! (M4 design section 3.6), over states that need no binding. The
//! registry tests of the test author live in `tests/registry.rs`. The
//! read rules over states built from genesis with bindings live beside
//! the matrix, in `fstp-api-testkit/src/matrix.rs`, since this crate
//! takes no dependency on the domain testkit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::Via;
use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::policy::McpBindingActions;
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;

use crate::*;

const DRAFT_ONLY: McpBindingActions = McpBindingActions::DraftOnly;
const ALLOWED: McpBindingActions = McpBindingActions::Allowed;
const T0: Timestamp = Timestamp::from_micros(1_000_000);
const L1: AccountId = AccountId::from_raw(301);
const ADMIN: AccountId = AccountId::from_raw(1);

fn spec(name: &str) -> &'static OpSpec {
    op(name).unwrap_or_else(|| panic!("no operation {name}"))
}

fn admins(set: &[AccountId]) -> BTreeSet<AccountId> {
    set.iter().copied().collect()
}

fn web(account: AccountId, method: LoginMethod, admin: &[AccountId], s: &EngineState) -> Principal {
    let facts = SessionFacts {
        account,
        session: SessionId::from_raw(1),
        method,
    };
    Principal::web(&facts, &admins(admin), s, T0)
}

fn mcp(account: AccountId, scopes: &[Scope], s: &EngineState) -> Principal {
    let grant = GrantFacts {
        account,
        agent: AgentClientId::from_raw(9),
        scopes: scopes.iter().copied().collect(),
        consent_method: LoginMethod::Passkey,
    };
    Principal::mcp(&grant, &admins(&[]), s, T0).unwrap_or_else(|e| panic!("{e}"))
}

fn read(
    kind: ReadKind,
    target: ReadTarget,
    p: &Principal,
    s: &EngineState,
) -> Result<(), DenyRule> {
    authorize_read(&ReadOp { kind, target }, p, s, T0)
        .map(|_| ())
        .map_err(|d| d.rule())
}

/// I-84, design section 3.6: each tool's input schema states the route's
/// path parameters in order, and a request object for every method but
/// GET.
#[test]
fn i84_tool_input_schema_matches_its_route() {
    let mut tools = 0usize;
    for o in OPS {
        let (Some(t), Some((m, path))) = (o.tool, o.route) else {
            continue;
        };
        let params: Vec<&str> = route_params(path).collect();
        assert_eq!(t.input.params, params.as_slice(), "{}", o.name);
        assert_eq!(t.input.body, m != Method::Get, "{}", o.name);
        tools += 1;
    }
    // M5 design 12.1: the read-only contract, payment status and
    // payment queue tools, and the signing list tool (2026-11-13). The
    // ADR-013 amendment of 2026-11-20 adds 28 setup tools.
    assert_eq!(tools, 67);
}

/// I-84: no two operations share a method and a route.
#[test]
fn i84_routes_are_unique() {
    let mut seen = BTreeSet::new();
    for o in OPS {
        let route = o.route.unwrap_or_else(|| panic!("{} has no route", o.name));
        assert!(seen.insert(route), "{} repeats {route:?}", o.name);
    }
}

/// TH-63, design section 3.8: tool names are fixed ASCII identifiers with
/// the `fstp_` prefix, and descriptions are plain sentences.
#[test]
fn th63_tool_names_and_descriptions_are_fixed_text() {
    for t in OPS.iter().filter_map(|o| o.tool) {
        assert!(t.name.starts_with("fstp_"), "{}", t.name);
        assert!(
            t.name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{}",
            t.name
        );
        assert!(t.description.ends_with('.'), "{}", t.name);
        assert!(t.description.is_ascii(), "{}", t.name);
    }
}

/// I-84, design section 3.6: the web channel executes every operation,
/// so it adds no rule of its own.
#[test]
fn i84_channel_policy_executes_every_web_call() {
    let s = EngineState::genesis();
    let p = web(L1, LoginMethod::Passkey, &[], &s);
    for o in OPS {
        assert_eq!(
            channel_policy(o, &p, DRAFT_ONLY, &McpSettings::disabled()),
            ChannelVerdict::Execute,
            "{}",
            o.name
        );
    }
}

/// I-85, R-MC-05, P-77: through MCP, a high-risk operation and a binding
/// one under "draft only" become pending actions. A binding one under
/// "allowed" and a draft execute.
#[test]
fn i85_channel_policy_prepares_high_risk_and_draft_only_binding_calls() {
    let s = EngineState::genesis();
    let p = mcp(L1, &Scope::ALL, &s);
    let all = McpSettings::all_roles();
    let verdict = |name: &str, p77| channel_policy(spec(name), &p, p77, &all);
    assert_eq!(verdict("call.publish", ALLOWED), ChannelVerdict::Prepare);
    assert_eq!(
        verdict("proposal.submit", DRAFT_ONLY),
        ChannelVerdict::Prepare
    );
    assert_eq!(verdict("proposal.submit", ALLOWED), ChannelVerdict::Execute);
    assert_eq!(
        verdict("proposal.record_plan", DRAFT_ONLY),
        ChannelVerdict::Execute
    );
    assert_eq!(
        verdict("proposal.save_workspace", DRAFT_ONLY),
        ChannelVerdict::Execute
    );
    assert_eq!(
        verdict("creator.save_fields", DRAFT_ONLY),
        ChannelVerdict::Execute
    );
}

/// I-85: no prepare-only tool ever executes, whatever P-77 and P-74 say.
#[test]
fn i85_prepare_only_tools_never_execute() {
    let s = EngineState::genesis();
    let p = mcp(L1, &Scope::ALL, &s);
    for o in OPS
        .iter()
        .filter(|o| o.tool.is_some_and(|t| t.prepare_only))
    {
        for p77 in [DRAFT_ONLY, ALLOWED] {
            assert_ne!(
                channel_policy(o, &p, p77, &McpSettings::all_roles()),
                ChannelVerdict::Execute,
                "{}",
                o.name
            );
        }
    }
}

/// I-84, P-74, Q42: through MCP, an operation with no tool is not
/// exposed, a token without the scope is refused, and a disabled server
/// or a role outside the P-74 roles refuses.
#[test]
fn i84_channel_policy_denies_without_tool_scope_or_p74() {
    let s = EngineState::genesis();
    let all = McpSettings::all_roles();
    let full = mcp(L1, &Scope::ALL, &s);
    let none = mcp(L1, &[], &s);
    assert_eq!(
        channel_policy(spec("creator.approve_activation"), &full, ALLOWED, &all),
        ChannelVerdict::Deny(ChannelDenial::NotExposed)
    );
    assert_eq!(
        channel_policy(spec("review.score"), &none, ALLOWED, &all),
        ChannelVerdict::Deny(ChannelDenial::Scope)
    );
    assert_eq!(
        channel_policy(
            spec("review.score"),
            &full,
            ALLOWED,
            &McpSettings::disabled()
        ),
        ChannelVerdict::Deny(ChannelDenial::P74)
    );
    let managers_only = McpSettings::limited_to([RoleOrApplicant::Role(Role::ProgrammeManager)]);
    assert_eq!(
        channel_policy(spec("calls.list_open"), &full, ALLOWED, &managers_only),
        ChannelVerdict::Deny(ChannelDenial::P74),
        "an account with no binding acts outside the allowed roles"
    );
    let receiving = McpSettings::limited_to([RoleOrApplicant::Applicant]);
    assert_eq!(
        channel_policy(spec("calls.list_open"), &full, ALLOWED, &receiving),
        ChannelVerdict::Execute
    );
}

/// R-MC-04, I-87: public tools need no token and no scope, only an
/// enabled server. A role limit leaves them open, and the feed has no
/// tool.
#[test]
fn r_mc_04_public_tools_need_only_an_enabled_server() {
    let p = Principal::anonymous_mcp();
    assert_eq!(p.via(), Via::Mcp);
    let call = spec("public.call");
    assert_eq!(
        channel_policy(call, &p, DRAFT_ONLY, &McpSettings::all_roles()),
        ChannelVerdict::Execute
    );
    assert_eq!(
        channel_policy(call, &p, DRAFT_ONLY, &McpSettings::limited_to([])),
        ChannelVerdict::Execute
    );
    assert_eq!(
        channel_policy(call, &p, DRAFT_ONLY, &McpSettings::disabled()),
        ChannelVerdict::Deny(ChannelDenial::P74)
    );
    assert_eq!(
        channel_policy(
            spec("public.feed"),
            &p,
            DRAFT_ONLY,
            &McpSettings::all_roles()
        ),
        ChannelVerdict::Deny(ChannelDenial::NotExposed)
    );
}

/// I-77, I-78: a weak session is refused for a high-risk operation, and
/// for every operation of a tenant admin. An account with no binding may
/// use it for a plain operation, and public pages have no session rule.
#[test]
fn i77_weak_sessions_are_refused_for_high_risk_ops_and_admins() {
    let s = EngineState::genesis();
    let applicant = web(L1, LoginMethod::MagicLink, &[], &s);
    assert!(session_admits(spec("proposal.submit"), &applicant));
    assert!(!session_admits(spec("agents.consent"), &applicant));
    let admin = web(ADMIN, LoginMethod::Opaque, &[ADMIN], &s);
    assert!(!session_admits(spec("tenant.settings"), &admin));
    let strong = web(ADMIN, LoginMethod::EudiWallet, &[ADMIN], &s);
    assert!(session_admits(spec("tenant.settings"), &strong));
    assert!(session_admits(spec("public.call"), &Principal::anonymous()));
}

/// I-78: an agent grant whose consent came from a weak session cannot
/// become a principal, since consenting links a device.
#[test]
fn i78_mcp_grant_from_a_weak_consent_is_refused() {
    let grant = GrantFacts {
        account: L1,
        agent: AgentClientId::from_raw(9),
        scopes: ScopeSet::empty(),
        consent_method: LoginMethod::MagicLink,
    };
    let out = Principal::mcp(&grant, &admins(&[]), &EngineState::genesis(), T0);
    assert_eq!(out, Err(AccessError::WeakConsent));
}

/// I-84, design section 3.6: the admin flag comes from the attested set
/// only. An account with neither a binding nor the admin role acts as an
/// applicant with no binding, and an anonymous caller holds no role.
#[test]
fn i84_principal_roles_come_from_the_admin_set_and_bindings() {
    let s = EngineState::genesis();
    let stranger = web(L1, LoginMethod::Passkey, &[], &s);
    assert_eq!(
        stranger.roles().iter().collect::<Vec<_>>(),
        vec![RoleOrApplicant::Applicant]
    );
    assert!(!stranger.holds_management_role());
    let admin = web(ADMIN, LoginMethod::Passkey, &[ADMIN], &s);
    assert!(admin.tenant_admin());
    assert!(admin.holds_management_role());
    assert!(
        admin
            .roles()
            .contains(RoleOrApplicant::Role(Role::TenantAdmin))
    );
    assert!(!admin.roles().contains(RoleOrApplicant::Applicant));
    let not_admin = web(ADMIN, LoginMethod::Passkey, &[], &s);
    assert!(!not_admin.tenant_admin());
    assert!(Principal::anonymous().roles().is_empty());
    assert_eq!(Principal::anonymous().via(), Via::Web);
}

/// I-87, design section 3.6: without an account only the public reads
/// open, and every other read refuses as an actor.
#[test]
fn i87_anonymous_callers_read_public_data_only() {
    let s = EngineState::genesis();
    let p = Principal::anonymous();
    assert_eq!(
        read(ReadKind::ListOpenCalls, ReadTarget::None, &p, &s),
        Ok(())
    );
    assert_eq!(
        read(
            ReadKind::GetOwnProposal,
            ReadTarget::Proposal(ProposalId::from_raw(1)),
            &p,
            &s
        ),
        Err(DenyRule::Actor)
    );
    assert_eq!(
        read(ReadKind::ListOwnProposals, ReadTarget::None, &p, &s),
        Err(DenyRule::Actor)
    );
}

/// R-AC-01, design section 3.6: an unknown target refuses with the rule's
/// own refusal, as a target outside the caller's relations does, so a
/// read never reveals which ids exist. Only a caller the rule admits
/// whatever the target, here a tenant admin, gets an input refusal.
#[test]
fn r_ac_01_unknown_read_target_refuses_like_an_unrelated_one() {
    let s = EngineState::genesis();
    let lead = web(L1, LoginMethod::Passkey, &[], &s);
    let unknown = ReadTarget::Proposal(ProposalId::from_raw(9_999));
    assert_eq!(
        read(ReadKind::GetOwnProposal, unknown, &lead, &s),
        Err(DenyRule::Rac01)
    );
    assert_eq!(
        read(ReadKind::GetOwnWorkspace, unknown, &lead, &s),
        Err(DenyRule::I21)
    );
    assert_eq!(
        read(
            ReadKind::GetPublicCall,
            ReadTarget::Call(CallId::from_raw(9_999)),
            &Principal::anonymous(),
            &s
        ),
        Err(DenyRule::Rac01),
        "an unknown call refuses as an unpublished one does"
    );
    let admin = web(ADMIN, LoginMethod::Passkey, &[ADMIN], &s);
    assert_eq!(
        read(ReadKind::GetOnboarding, unknown, &admin, &s),
        Err(DenyRule::Input)
    );
}

/// D11: every read has exactly one rule row, and the rows of reads whose
/// target is not a proposal list all 16 states.
#[test]
fn d11_every_read_has_one_rule_row() {
    for k in ReadKind::ALL {
        let rows = READ_RULES.iter().filter(|(r, _, _)| *r == k).count();
        assert_eq!(rows, 1, "{k:?}");
        assert!(read_rule(k).is_some(), "{k:?}");
    }
    assert_eq!(READ_RULES.len(), ReadKind::ALL.len());
}

/// ADR-021: every operation the setup gate names exists in the registry,
/// and every tenant operation of the registry is an onboarding operation.
#[test]
fn adr021_setup_gate_names_registry_operations() {
    for name in ACCOUNT_SECURITY_OPS
        .iter()
        .chain(PERSONAL_PREFERENCE_OPS.iter())
        .chain(ONBOARDING_ADMIN_OPS.iter())
        .chain(ADMIN_OWN_OPS.iter())
    {
        assert!(op(name).is_some(), "ADR-021 names {name}, which OPS lacks");
    }
    for o in OPS.iter() {
        if matches!(o.kind, OpKind::Tenant(_)) {
            assert!(onboarding_op(o.name), "{} is a tenant command", o.name);
        }
    }
    assert!(!onboarding_op("admin.approve_break_glass"));
    assert!(!onboarding_op("roles.grant"));
    assert!(!onboarding_op("creator.invite"));
}

/// ADR-021, SoD-14, SoD-15, R-LG-04: before activation a tenant admin
/// keeps onboarding, its grants and its own roles and verification. Any
/// other caller keeps its sessions and passkeys only. Nothing else
/// passes, for anyone.
#[test]
fn adr021_setup_gate_admits_onboarding_for_admins_only() {
    let s = EngineState::genesis();
    let admin = web(ADMIN, LoginMethod::Passkey, &[ADMIN], &s);
    let other = web(L1, LoginMethod::Passkey, &[ADMIN], &s);
    let anon = Principal::anonymous();
    for name in [
        "tenant.save_step",
        "tenant.complete",
        "tenant.invite_admin",
        "tenant.grant_signatory",
        "tenant.end_signatory",
        "tenant.request_activation",
        "tenant.approve_activation",
        "admin.approve_self_grant",
        "me.roles",
        "me.begin_verification",
    ] {
        assert!(setup_admits(spec(name), &admin), "{name} for an admin");
        assert!(!setup_admits(spec(name), &other), "{name} for an account");
        assert!(!setup_admits(spec(name), &anon), "{name} for no account");
    }
    for name in ACCOUNT_SECURITY_OPS {
        for p in [&admin, &other, &anon] {
            assert!(setup_admits(spec(name), p), "R-LG-04: {name}");
        }
    }
    for name in [
        "creator.open_draft",
        "creator.invite",
        "roles.grant",
        "calls.list_open",
        "proposal.list_own",
        "me.mailbox",
        "admin.approve_break_glass",
        "agents.consent",
        "people.get_invitation",
    ] {
        for p in [&admin, &other, &anon] {
            assert!(!setup_admits(spec(name), p), "{name}");
        }
    }
    assert_eq!(SETUP_RULE, "ADR-021");
}

/// The setup tools of the ADR-013 amendment of 2026-11-20: each tool, its
/// operation, its scope, and whether MCP prepares it.
pub(crate) const SETUP_TOOLS: [(&str, &str, Scope, bool); 28] = [
    (
        "fstp_creator_list_programmes",
        "creator.list_programmes",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_list_templates",
        "creator.list_templates",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_apply_start",
        "creator.apply_start",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_edit_narrative",
        "creator.edit_narrative",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_get_preview",
        "creator.preview",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_get_impact",
        "creator.impact",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_upload_import",
        "import.upload",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_list_import_proposals",
        "import.list",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_creator_remove_import",
        "import.remove",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_prepare_narrative_acceptance",
        "creator.accept_narrative",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_prepare_warning_acknowledgement",
        "creator.acknowledge",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_prepare_import_resolution",
        "import.resolve",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_prepare_invitation",
        "creator.invite",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_prepare_activation_request",
        "creator.request_activation",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_prepare_tenant_template",
        "creator.save_as_template",
        Scope::CreatorDraft,
        true,
    ),
    ("fstp_list_calls", "call.list", Scope::CallsRead, false),
    (
        "fstp_get_programme_timeline",
        "programme.timeline",
        Scope::CallsRead,
        false,
    ),
    (
        "fstp_prepare_call_approval",
        "call.approve",
        Scope::CallsDraft,
        true,
    ),
    (
        "fstp_prepare_programme_draft",
        "creator.open_draft",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_list_programme_roles",
        "roles.list",
        Scope::CreatorDraft,
        false,
    ),
    (
        "fstp_prepare_role_grant",
        "roles.grant",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_prepare_role_end",
        "roles.end",
        Scope::CreatorDraft,
        true,
    ),
    (
        "fstp_tenant_list_funder_profiles",
        "tenant.funder_profiles",
        Scope::TenantDraft,
        false,
    ),
    (
        "fstp_prepare_funder_profile_copy",
        "tenant.funder_profile.copy",
        Scope::TenantDraft,
        true,
    ),
    (
        "fstp_prepare_funder_profile_save",
        "tenant.funder_profile.save",
        Scope::TenantDraft,
        true,
    ),
    (
        "fstp_tenant_check_branding",
        "tenant.branding.check",
        Scope::TenantDraft,
        false,
    ),
    (
        "fstp_prepare_branding",
        "tenant.branding.set",
        Scope::TenantDraft,
        true,
    ),
    (
        "fstp_prepare_terminology",
        "tenant.terminology.set",
        Scope::TenantDraft,
        true,
    ),
];

/// I-84, I-85, ADR-013 amendment of 2026-11-20: each setup tool sits on
/// its operation with its scope. Through MCP, a prepare-only one gives a
/// pending action under either P-77 value and never executes, and a draft
/// or read one executes. A token without the scope is refused, and the
/// web channel executes each operation as before.
#[test]
fn i85_adr013_setup_tools_prepare_or_execute_as_the_amendment_says() {
    let s = EngineState::genesis();
    let full = mcp(L1, &Scope::ALL, &s);
    let none = mcp(L1, &[], &s);
    let on_web = web(L1, LoginMethod::Passkey, &[], &s);
    let all = McpSettings::all_roles();
    for (tool, name, scope, prepare) in SETUP_TOOLS {
        let o = spec(name);
        let t = o.tool.unwrap_or_else(|| panic!("{name} has no tool"));
        assert_eq!(t.name, tool, "{name}");
        assert_eq!(t.scope, scope, "{name} scope");
        assert_eq!(o.scope, Some(scope), "{name} operation scope");
        assert_eq!(t.prepare_only, prepare, "{name} prepare_only");
        assert!(o.route.is_some(), "I-84: {name} has a web route");
        if o.high_risk {
            assert!(t.prepare_only, "I-85: {name} is high-risk");
        }
        let want = if prepare {
            ChannelVerdict::Prepare
        } else {
            ChannelVerdict::Execute
        };
        for p77 in [DRAFT_ONLY, ALLOWED] {
            assert_eq!(channel_policy(o, &full, p77, &all), want, "{name}");
        }
        assert_eq!(
            channel_policy(o, &none, ALLOWED, &all),
            ChannelVerdict::Deny(ChannelDenial::Scope),
            "{name} without its scope"
        );
        assert_eq!(
            channel_policy(o, &on_web, DRAFT_ONLY, &McpSettings::disabled()),
            ChannelVerdict::Execute,
            "{name} on the web"
        );
    }
}

/// I-86, ADR-013 amendment of 2026-11-20: no setup tool sits on an
/// operation whose data is personal, and the reads that name emails or
/// display names keep no tool.
#[test]
fn i86_adr013_setup_tools_return_no_personal_data() {
    for (_, name, _, _) in SETUP_TOOLS {
        assert_ne!(
            spec(name).classification,
            Classification::Personal,
            "{name}"
        );
    }
    for name in [
        "creator.invitations",
        "team.list",
        "admin.members",
        "tenant.list_admins",
        "tenant.list_signatories",
        "tenant.get_mail_relay",
        "me.get_verification",
    ] {
        assert!(spec(name).tool.is_none(), "{name} has a tool");
    }
}

/// I-66, I-67, R-PC-03, ADR-013 amendment of 2026-11-20: the second-person
/// approvals stay web only, so no agent completes or prepares an
/// activation approval or override, and the call publication keeps its
/// one prepare-only tool.
#[test]
fn i67_adr013_second_person_approvals_keep_no_executing_tool() {
    for name in ["creator.approve_activation", "creator.override_activation"] {
        assert!(spec(name).tool.is_none(), "{name} has a tool");
    }
    for name in ["call.approve", "call.publish"] {
        assert!(
            spec(name).tool.is_some_and(|t| t.prepare_only),
            "{name} lacks a prepare-only tool"
        );
    }
}

/// The creator commands of the P-75 and P-77 rule (ADR-013, Daniel's
/// decision of 2026-11-20), over draft 7 at revision 1.
mod agent_policy {
    use fstp_creator::{
        CreatorCommand, DraftRevision, FieldEdit, ImportDocumentId, Provenance, StartingPoint,
        TemplateId, ValueDigest,
    };
    use fstp_domain::id::{ContentDigest, ProgrammeId};
    use fstp_domain::policy::{FunderProfileRef, McpBindingActions};
    use fstp_programme::{FieldId, FieldValue};

    pub(super) const P: ProgrammeId = ProgrammeId::from_raw(7);

    pub(super) fn base() -> DraftRevision {
        DraftRevision::new(1, fstp_ledger::Seq::from_raw(1))
    }

    pub(super) fn edit(value: FieldValue) -> FieldEdit {
        FieldEdit {
            field: value.field(),
            value,
            digest: ValueDigest::new(ContentDigest::from_bytes([0; 32])),
            provenance: Provenance::Manual,
        }
    }

    pub(super) fn p75() -> FieldEdit {
        edit(FieldValue::P75(true))
    }

    pub(super) fn p77() -> FieldEdit {
        edit(FieldValue::P77(McpBindingActions::Allowed))
    }

    pub(super) fn p28() -> FieldEdit {
        edit(FieldValue::P28(false))
    }

    pub(super) fn save(fields: Vec<FieldEdit>, clear: Vec<FieldId>) -> CreatorCommand {
        CreatorCommand::SaveFields {
            programme: P,
            base: base(),
            fields,
            clear,
        }
    }

    pub(super) fn start(start: StartingPoint) -> CreatorCommand {
        CreatorCommand::ApplyStart {
            programme: P,
            base: base(),
            start,
        }
    }

    pub(super) fn template() -> StartingPoint {
        StartingPoint::Template {
            template: TemplateId::from_raw(1),
            version: 1,
        }
    }

    pub(super) fn clone_of(source: u128) -> StartingPoint {
        StartingPoint::Clone {
            source: ProgrammeId::from_raw(source),
        }
    }

    pub(super) fn blank() -> StartingPoint {
        StartingPoint::Blank {
            profile: FunderProfileRef(
                fstp_domain::policy::OpaqueValue::from_value(&fstp_json::Value::from("blank"))
                    .unwrap(),
            ),
        }
    }

    pub(super) fn import() -> StartingPoint {
        StartingPoint::Import {
            document: ImportDocumentId::from_raw(3),
        }
    }
}

/// P-75, P-77, ADR-013 decision of Daniel of 2026-11-20: a creator command
/// sets P-75 or P-77 exactly when a save or a clear names either field, or
/// a start applies a template or a clone. A save of other fields, a blank
/// start and an import start set neither.
#[test]
fn p75_p77_sets_agent_policy_by_the_decoded_command() {
    use agent_policy::*;
    use fstp_programme::FieldId;
    let sets = |c| sets_agent_policy(&c);
    assert!(sets(save(vec![p75()], vec![])), "P-75 save");
    assert!(sets(save(vec![p77()], vec![])), "P-77 save");
    assert!(sets(save(vec![p28(), p77()], vec![])), "mixed save");
    assert!(sets(save(vec![p28()], vec![FieldId::P75])), "P-75 clear");
    assert!(sets(save(vec![], vec![FieldId::P77])), "P-77 clear");
    assert!(!sets(save(vec![p28()], vec![])), "P-28 save");
    assert!(!sets(save(vec![], vec![FieldId::P28])), "P-28 clear");
    assert!(sets(start(template())), "template start");
    assert!(sets(start(clone_of(5))), "clone start");
    assert!(!sets(start(blank())), "blank start");
    assert!(!sets(start(import())), "import start");
}

/// I-85, I-84, P-75, P-77, ADR-013 decision of Daniel of 2026-11-20:
/// through MCP, `creator_channel_policy` turns `Execute` into `Prepare`
/// for a creator command that sets P-75 or P-77, mixed saves included. It
/// leaves every other verdict, and every web call, as `channel_policy`
/// gave it.
#[test]
fn i85_p75_p77_creator_channel_policy_prepares_only_mcp_calls_that_set_them() {
    use agent_policy::*;
    use fstp_programme::FieldId;
    let s = EngineState::genesis();
    let agent = mcp(ADMIN, &Scope::ALL, &s);
    let person = web(ADMIN, LoginMethod::Passkey, &[ADMIN], &s);
    let touching = [
        save(vec![p75()], vec![]),
        save(vec![p77()], vec![]),
        save(vec![p28(), p75()], vec![]),
        save(vec![], vec![FieldId::P77]),
        start(template()),
        start(clone_of(5)),
    ];
    let other = [save(vec![p28()], vec![]), start(blank()), start(import())];
    let denied = ChannelVerdict::Deny(ChannelDenial::Scope);
    for c in &touching {
        assert_eq!(
            creator_channel_policy(ChannelVerdict::Execute, &agent, c),
            ChannelVerdict::Prepare,
            "{c:?} through MCP"
        );
        assert_eq!(
            creator_channel_policy(ChannelVerdict::Prepare, &agent, c),
            ChannelVerdict::Prepare
        );
        assert_eq!(creator_channel_policy(denied, &agent, c), denied);
        assert_eq!(
            creator_channel_policy(ChannelVerdict::Execute, &person, c),
            ChannelVerdict::Execute,
            "{c:?} through the web"
        );
    }
    for c in &other {
        for p in [&agent, &person] {
            assert_eq!(
                creator_channel_policy(ChannelVerdict::Execute, p, c),
                ChannelVerdict::Execute,
                "{c:?}"
            );
        }
    }
}
