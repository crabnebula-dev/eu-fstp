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
    // payment queue tools.
    assert_eq!(tools, 38);
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
        channel_policy(spec("roles.grant"), &full, ALLOWED, &all),
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
