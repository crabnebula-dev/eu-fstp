//! Registry tests of the `OPS` table (M4 design sections 3.6, 8.4 and 13,
//! step W3a).
//!
//! Written by the W3a test author from the design and the spec, before
//! the production registry exists. Each test names the identifiers it
//! verifies. Each one also asks for the operations the design names, so
//! an empty registry fails every test and none passes vacuously.
//!
//! Operations are found by the names the journey tables of design section
//! 2.2 use, such as `call.publish`. The two spec tables these tests read,
//! the high-risk table of `authentication.md` and the capability table of
//! `mcp-server.md`, are read at test time, so a spec edit breaks the test
//! until the row maps below follow it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fstp_access::{
    COMPOSED_ONLY, CreatorKind, FindingKind, ImportKind, LATER, Milestone, OPS, OpKind, OpSpec,
    READ_RULES, ReadKind, STRICT_EXTRA_HIGH_RISK, SYSTEM_ONLY, SYSTEM_ONLY_OTHER, SessionNeed,
    TenantKind, TenantParam,
};
use fstp_domain::{CommandKind, StateTag};
use fstp_engine::FindingCommand;

/// The operation named `name`, if the registry has exactly one.
fn op(name: &str) -> Option<&'static OpSpec> {
    let mut found = OPS.iter().filter(|o| o.name == name);
    let first = found.next();
    if found.next().is_some() {
        return None;
    }
    first
}

/// The operations named, each of which must exist exactly once.
fn require(names: &[&str]) -> Vec<&'static OpSpec> {
    let missing: Vec<&str> = names.iter().copied().filter(|n| op(n).is_none()).collect();
    assert!(
        missing.is_empty(),
        "the registry lacks, or holds twice, the operations {missing:?} (OPS has {} entries)",
        OPS.len()
    );
    names.iter().filter_map(|n| op(n)).collect()
}

/// The name of a command kind, as its `Debug` spells it. The kinds that
/// changes D2 and D5 add are found by name, since lane W1b adds them in
/// parallel and this crate cannot name them yet.
fn kind_name(k: CommandKind) -> String {
    format!("{k:?}")
}

fn names(kinds: &[CommandKind]) -> BTreeSet<String> {
    kinds.iter().map(|k| kind_name(*k)).collect()
}

fn spec_file(rel: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "SPEC", rel]
        .iter()
        .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The first cells of the markdown table under the heading `heading`.
fn table_first_cells(text: &str, heading: &str) -> Vec<String> {
    let mut lines = text.lines().skip_while(|l| l.trim() != heading);
    assert!(lines.next().is_some(), "no heading {heading:?}");
    let rows: Vec<&str> = lines
        .skip_while(|l| !l.starts_with('|'))
        .take_while(|l| l.starts_with('|'))
        .collect();
    rows.iter()
        .skip(2)
        .filter_map(|r| r.split('|').nth(1))
        .map(|c| c.trim().to_string())
        .collect()
}

/// The command kinds the design says creator and read operations carry,
/// though their operation kind is not `OpKind::Command` (design sections
/// 3.2 and 3.6). `OpenDraft` carries the core `CreateProgramme`, a save
/// compiles to one core `EditPolicy`, and the content reads run the
/// domain `ReadContent` first.
fn carried(kind: OpKind) -> &'static [CommandKind] {
    match kind {
        OpKind::Creator(CreatorKind::OpenDraft) => &[CommandKind::CreateProgramme],
        OpKind::Creator(CreatorKind::SaveFields) | OpKind::Creator(CreatorKind::ApplyStart) => {
            &[CommandKind::EditPolicy]
        }
        OpKind::Read(ReadKind::GetContent)
        | OpKind::Read(ReadKind::GetOwnProposal)
        | OpKind::Read(ReadKind::GetOwnStage2Thread) => &[CommandKind::ReadContent],
        _ => &[],
    }
}

/// The kinds that never arrive from a person (design section 3.6). The
/// design lists eight. `EndScheduledRole` postdates that list: its actor is
/// the System, which records a scheduled end at its instant
/// (`roles-and-sod.md` Cooling-off NOTE). So it is system-only too.
const EXPECTED_SYSTEM_ONLY: [&str; 9] = [
    "VaultChanged",
    "ExpireStage2",
    "ReEnter",
    "ContractFact",
    "StartExecution",
    "Complete",
    "RecordDeliverable",
    "ActivateAmendment",
    "EndScheduledRole",
];

/// The grant, contract, payment and amendment kinds whose operations
/// arrive with M5 (design sections 0.4 and 3.6).
const EXPECTED_LATER_M5: [&str; 15] = [
    "DetermineAmount",
    "AcceptGrant",
    "ApproveGrant",
    "Terminate",
    "RequestPayment",
    "AcceptLine",
    "ApprovePayment",
    "ReleasePayment",
    "ConfirmPaid",
    "WithdrawPaymentRequest",
    "RequestPaymentChanges",
    "ProposeAmendment",
    "RouteAmendment",
    "CloseMilestone",
    "ClosePaymentRequest",
];

/// The kinds that changes D2 and D5 add to `CommandKind::ALL`.
const NEW_IN_M4: [&str; 4] = [
    "ActivateProgramme",
    "OpenCutOffRound",
    "CastBallot",
    "DelegateVote",
];

/// I-66, I-84, design section 3.6 `ops_cover_every_command_kind_once`:
/// each kind of `CommandKind::ALL` sits in exactly one of a routed
/// operation, `SYSTEM_ONLY`, `COMPOSED_ONLY` or `LATER`. Routed means an
/// operation of kind `OpKind::Command`, or one that carries the kind as
/// design sections 3.2 and 3.6 state. In M4 that gives 37 routed, 9
/// system-only, 1 composed and 15 later kinds, 62 in all.
#[test]
fn ops_cover_every_command_kind_once() {
    let all: BTreeSet<String> = names(&CommandKind::ALL);
    let missing_new: Vec<&str> = NEW_IN_M4
        .iter()
        .copied()
        .filter(|n| !all.contains(*n))
        .collect();
    assert!(
        missing_new.is_empty(),
        "CommandKind::ALL lacks the M4 kinds {missing_new:?} (changes D2 and D5)"
    );

    let mut routed: BTreeMap<String, usize> = BTreeMap::new();
    for o in OPS {
        if let OpKind::Command(k) = o.kind {
            *routed.entry(kind_name(k)).or_insert(0) += 1;
        }
        for k in carried(o.kind) {
            *routed.entry(kind_name(*k)).or_insert(0) += 1;
        }
    }
    let system = names(SYSTEM_ONLY);
    let composed = names(COMPOSED_ONLY);
    let later: BTreeSet<String> = LATER.iter().map(|(k, _)| kind_name(*k)).collect();

    let expected_system: BTreeSet<String> =
        EXPECTED_SYSTEM_ONLY.iter().map(|s| s.to_string()).collect();
    assert_eq!(system, expected_system, "SYSTEM_ONLY");
    assert_eq!(
        composed,
        BTreeSet::from(["ActivateProgramme".to_string()]),
        "COMPOSED_ONLY"
    );
    let expected_later: BTreeSet<String> =
        EXPECTED_LATER_M5.iter().map(|s| s.to_string()).collect();
    assert_eq!(later, expected_later, "LATER");
    assert!(
        LATER.iter().all(|(_, m)| *m == Milestone::M5),
        "every later kind arrives with M5: {LATER:?}"
    );
    assert_eq!(
        SYSTEM_ONLY.len(),
        system.len(),
        "SYSTEM_ONLY repeats a kind"
    );
    assert_eq!(
        COMPOSED_ONLY.len(),
        composed.len(),
        "COMPOSED_ONLY repeats a kind"
    );
    assert_eq!(LATER.len(), later.len(), "LATER repeats a kind");

    let mut placements: Vec<(String, Vec<&str>)> = Vec::new();
    for k in &all {
        let mut at = Vec::new();
        if routed.contains_key(k) {
            at.push("routed");
        }
        if system.contains(k) {
            at.push("SYSTEM_ONLY");
        }
        if composed.contains(k) {
            at.push("COMPOSED_ONLY");
        }
        if later.contains(k) {
            at.push("LATER");
        }
        if at.len() != 1 {
            placements.push((k.clone(), at));
        }
    }
    assert!(
        placements.is_empty(),
        "kinds placed other than exactly once: {placements:?}"
    );
    let stray: Vec<&String> = routed.keys().filter(|k| !all.contains(*k)).collect();
    assert!(stray.is_empty(), "routed kinds outside ALL: {stray:?}");
    assert_eq!(routed.len(), 37, "routed command kinds");
    assert_eq!(all.len(), 62, "CommandKind::ALL in M4");
}

/// The finding operation kind of a `FindingCommand`. The match has no
/// wildcard, so a new `FindingCommand` variant fails to compile here until
/// it is placed.
fn finding_kind_of(c: &FindingCommand) -> FindingKind {
    match c {
        FindingCommand::Record(_) => FindingKind::Record,
        FindingCommand::Mark { .. } => FindingKind::Mark,
        FindingCommand::Regenerate { .. } => FindingKind::Regenerate,
    }
}

/// Every finding kind. The match in `finding_kind_of` ties this list to
/// `FindingCommand`, and the one below ties it to `FindingKind`.
const FINDING_KINDS: [FindingKind; 3] = [
    FindingKind::Record,
    FindingKind::Mark,
    FindingKind::Regenerate,
];

fn finding_routed(k: FindingKind) -> bool {
    match k {
        FindingKind::Mark => true,
        FindingKind::Record | FindingKind::Regenerate => false,
    }
}

/// Every import kind. `fstp-import` has no `ImportCommand` yet (W0 stub),
/// so the exhaustive match ties this list to `fstp_access::ImportKind`
/// only. Gap: once lane W2b adds `ImportCommand`, a match over it belongs
/// here too, as `finding_kind_of` does for findings.
const IMPORT_KINDS: [ImportKind; 2] = [ImportKind::RegisterDocument, ImportKind::RecordProposals];

fn import_routed(k: ImportKind) -> bool {
    match k {
        ImportKind::RegisterDocument => true,
        ImportKind::RecordProposals => false,
    }
}

/// I-65, I-84, design section 3.6
/// `ops_cover_every_finding_and_import_kind_once`: `FindingCommand::Mark`
/// and `ImportCommand::RegisterDocument` are routed. `Record`,
/// `Regenerate` and `RecordProposals` are in `SYSTEM_ONLY_OTHER`, and no
/// operation routes them.
#[test]
fn ops_cover_every_finding_and_import_kind_once() {
    let _: fn(&FindingCommand) -> FindingKind = finding_kind_of;
    let mut kinds: Vec<OpKind> = FINDING_KINDS.iter().map(|k| OpKind::Finding(*k)).collect();
    kinds.extend(IMPORT_KINDS.iter().map(|k| OpKind::Import(*k)));
    for kind in kinds {
        let routed = OPS.iter().filter(|o| o.kind == kind).count();
        let system = SYSTEM_ONLY_OTHER.iter().filter(|k| **k == kind).count();
        let want_routed = match kind {
            OpKind::Finding(k) => finding_routed(k),
            OpKind::Import(k) => import_routed(k),
            _ => false,
        };
        if want_routed {
            assert_eq!((routed, system), (1, 0), "{kind:?} is routed exactly once");
        } else {
            assert_eq!(
                (routed, system),
                (0, 1),
                "{kind:?} is system-only exactly once"
            );
        }
    }
    assert_eq!(
        SYSTEM_ONLY_OTHER.len(),
        3,
        "SYSTEM_ONLY_OTHER: {SYSTEM_ONLY_OTHER:?}"
    );
}

/// Every creator kind, one per `CreatorCommand` variant of design section
/// 3.2.
const CREATOR_KINDS: [CreatorKind; 10] = [
    CreatorKind::OpenDraft,
    CreatorKind::ApplyStart,
    CreatorKind::SaveFields,
    CreatorKind::AcceptNarrative,
    CreatorKind::Invite,
    CreatorKind::WithdrawInvitation,
    CreatorKind::AcknowledgeWarning,
    CreatorKind::RequestActivation,
    CreatorKind::ApproveActivation,
    CreatorKind::SaveAsTenantTemplate,
];

/// The web route each creator kind has. The match has no wildcard, so a
/// new `CreatorKind` fails to compile here until it is placed. Gap: the
/// `fstp-creator` W0 stub has no `CreatorCommand` variants yet, so this
/// ties the list to `CreatorKind` only.
fn creator_route(k: CreatorKind) -> (&'static str, &'static str) {
    match k {
        CreatorKind::OpenDraft => ("POST", "/programmes"),
        CreatorKind::ApplyStart => ("POST", "/programmes/{programme}/draft/start"),
        CreatorKind::SaveFields => ("PUT", "/programmes/{programme}/draft/fields"),
        CreatorKind::AcceptNarrative => (
            "POST",
            "/programmes/{programme}/draft/narratives/{field}/acceptance",
        ),
        CreatorKind::Invite => ("POST", "/programmes/{programme}/invitations"),
        CreatorKind::WithdrawInvitation => {
            ("DELETE", "/programmes/{programme}/invitations/{invitation}")
        }
        CreatorKind::AcknowledgeWarning => {
            ("POST", "/programmes/{programme}/draft/acknowledgements")
        }
        CreatorKind::RequestActivation => ("POST", "/programmes/{programme}/activation-request"),
        CreatorKind::ApproveActivation => ("POST", "/programmes/{programme}/activation"),
        CreatorKind::SaveAsTenantTemplate => ("POST", "/programmes/{programme}/templates"),
    }
}

/// TH-49, R-PG-02, R-PG-05, I-84, design section 3.2: a person issues
/// every `CreatorCommand`, so each creator kind has exactly one operation,
/// with its web route and no tool beyond the draft save. Accepting
/// template narrative (TH-49), withdrawing an invitation and saving a
/// tenant-private template (R-PG-05) are reachable from the creator pages.
#[test]
fn th49_r_pg_05_ops_cover_every_creator_kind_once() {
    for k in CREATOR_KINDS {
        let found: Vec<&OpSpec> = OPS
            .iter()
            .filter(|o| o.kind == OpKind::Creator(k))
            .collect();
        assert_eq!(found.len(), 1, "{k:?} has exactly one operation");
        let o = found.first().copied().unwrap_or_else(|| unreachable!());
        let (method, path) = creator_route(k);
        assert_eq!(
            o.route.map(|(m, p)| (m.as_str(), p)),
            Some((method, path)),
            "{k:?} route"
        );
        assert_eq!(o.tool.is_some(), k == CreatorKind::SaveFields, "{k:?} tool");
    }
    let creator_ops = OPS
        .iter()
        .filter(|o| matches!(o.kind, OpKind::Creator(_)))
        .count();
    assert_eq!(creator_ops, CREATOR_KINDS.len(), "creator operations");
}

/// I-66, design section 3.6 `i66_no_route_or_tool_reaches_activate_programme`:
/// no operation has the core `ActivateProgramme` as its kind, it sits in
/// `COMPOSED_ONLY`, and the creator approval that composes it has a web
/// route, no tool, and is high-risk with a phishing-resistant session.
#[test]
fn i66_no_route_or_tool_reaches_activate_programme() {
    assert!(
        names(COMPOSED_ONLY).contains("ActivateProgramme"),
        "COMPOSED_ONLY lacks ActivateProgramme: {COMPOSED_ONLY:?}"
    );
    let direct: Vec<&str> = OPS
        .iter()
        .filter(|o| matches!(o.kind, OpKind::Command(k) if kind_name(k) == "ActivateProgramme"))
        .map(|o| o.name)
        .collect();
    assert!(
        direct.is_empty(),
        "operations of kind ActivateProgramme: {direct:?}"
    );

    let approve = require(&["creator.approve_activation"]);
    let approve = approve.first().copied().unwrap_or_else(|| unreachable!());
    assert_eq!(
        approve.kind,
        OpKind::Creator(CreatorKind::ApproveActivation),
        "creator.approve_activation kind"
    );
    assert!(
        approve.route.is_some(),
        "creator.approve_activation has a web route"
    );
    assert!(
        approve.tool.is_none(),
        "creator.approve_activation has no tool"
    );
    assert!(approve.high_risk, "creator.approve_activation is high-risk");
    assert_eq!(approve.session, SessionNeed::PhishingResistant);
    let composers: Vec<&str> = OPS
        .iter()
        .filter(|o| o.kind == OpKind::Creator(CreatorKind::ApproveActivation))
        .map(|o| o.name)
        .collect();
    assert_eq!(
        composers,
        vec!["creator.approve_activation"],
        "one approval op"
    );
}

/// I-78, I-85, R-MC-05, design section 3.6
/// `ops_high_risk_and_binding_follow_the_domain`: for every operation of
/// kind `OpKind::Command`, `high_risk` and `binding` equal the domain's
/// `CommandKind::high_risk` and `CommandKind::binding_action`.
#[test]
fn ops_high_risk_and_binding_follow_the_domain() {
    // Both polarities of both flags must be present, so an empty or
    // one-sided registry cannot pass.
    for (name, kind) in [
        ("call.publish", CommandKind::PublishCall),
        ("roles.grant", CommandKind::GrantRole),
        ("proposal.submit", CommandKind::Submit),
        ("proposal.create", CommandKind::CreateDraft),
        ("proposal.record_plan", CommandKind::RecordPlanVersion),
    ] {
        let found = require(&[name]);
        let found = found.first().copied().unwrap_or_else(|| unreachable!());
        assert_eq!(found.kind, OpKind::Command(kind), "{name} kind");
    }
    let mut checked = 0usize;
    let mut kinds: BTreeSet<String> = BTreeSet::new();
    for o in OPS {
        if let OpKind::Command(k) = o.kind {
            assert_eq!(o.high_risk, k.high_risk(), "{} high_risk", o.name);
            assert_eq!(o.binding, k.binding_action(), "{} binding", o.name);
            checked += 1;
            kinds.insert(kind_name(k));
        }
    }
    // Of the 37 routed kinds, `CreateProgramme`, `EditPolicy` and
    // `ReadContent` are carried by creator and read operations, so 34 are
    // the kind of a command operation. `DeclareConflict` sits on three
    // operations (coordinator, reviewer and IRC declarations), so there
    // are 36 command operations. (Lane m4reg corrected the floor here from
    // 37, which counted kinds, not operations.)
    assert_eq!(kinds.len(), 34, "command kinds of command operations");
    assert!(checked >= 36, "only {checked} command operations");
}

/// The high-risk table of `authentication.md`, row by row, mapped to the
/// M4 operations that perform each action. An empty row names the
/// milestone that brings its operations.
const HIGH_RISK_ROWS: [(&str, &[&str], &str); 10] = [
    (
        "Granting or changing a role in the Drafting, Judging or Operations groups, or tenant admin",
        &[
            "roles.grant",
            "roles.end",
            "roles.reinstate",
            "tenant.invite_admin",
            "admin.approve_self_grant",
        ],
        "",
    ),
    (
        "Tenant export, vault export, and any download containing identity attributes",
        &[],
        "M9 exports",
    ),
    (
        "Adding a passkey, linking a device, or signing in the desktop client",
        &["me.add_passkey", "agents.consent"],
        "",
    ),
    (
        "Changing the account email address or login methods",
        &["tenant.set_login_methods"],
        "",
    ),
    ("Changing bank details", &[], "M5 payments"),
    ("Approving or releasing a payment", &[], "M5 payments"),
    (
        "Activating a programme or publishing a call",
        &[
            "creator.approve_activation",
            "creator.open_draft",
            "call.publish",
        ],
        "",
    ),
    ("Publishing a template to other tenants", &[], "M9 (Q17)"),
    (
        "Approving break-glass access",
        &["admin.approve_break_glass"],
        "",
    ),
    (
        "Approving an account recovery",
        &["admin.approve_recovery"],
        "",
    ),
];

/// The tenant settings that are high-risk by the strict reading only
/// (design section 3.5, Q10 interim): every setting other than P-70.
const STRICT_EXTRA: [&str; 5] = [
    "tenant.set_step_up_freshness",
    "tenant.set_session_lifetimes",
    "tenant.set_mcp",
    "tenant.set_payment_mode",
    "tenant.set_template_licence",
];

/// R-LG-03, I-78, design section 3.6
/// `r_lg_03_high_risk_table_matches_authentication_md`: the high-risk
/// table is read at test time and checked against a hand-written row map
/// in both directions. Every high-risk operation is named by a row or by
/// `STRICT_EXTRA_HIGH_RISK`, and every named operation is high-risk.
#[test]
fn r_lg_03_high_risk_table_matches_authentication_md() {
    let text = spec_file("03-architecture/authentication.md");
    let spec_rows: BTreeSet<String> =
        table_first_cells(&text, "## High-risk actions and step-up (I-78)")
            .into_iter()
            .collect();
    let map_rows: BTreeSet<String> = HIGH_RISK_ROWS.iter().map(|r| r.0.to_string()).collect();
    assert_eq!(
        spec_rows, map_rows,
        "high-risk table rows against the row map"
    );
    assert!(
        text.contains("Creating a programme counts as activating it"),
        "the creation bullet behind creator.open_draft"
    );

    let mut named: BTreeSet<&str> = BTreeSet::new();
    for (row, ops, later) in HIGH_RISK_ROWS {
        assert!(
            !ops.is_empty() || !later.is_empty(),
            "row {row:?} names neither an operation nor a milestone"
        );
        for o in require(ops) {
            assert!(o.high_risk, "{} is high-risk ({row})", o.name);
            named.insert(o.name);
        }
    }
    let extra = require(&STRICT_EXTRA);
    let extra_kinds: BTreeSet<OpKind> = extra.iter().map(|o| o.kind).collect();
    let declared: BTreeSet<OpKind> = STRICT_EXTRA_HIGH_RISK.iter().copied().collect();
    assert_eq!(declared, extra_kinds, "STRICT_EXTRA_HIGH_RISK");
    assert_eq!(
        STRICT_EXTRA_HIGH_RISK.len(),
        declared.len(),
        "a repeated kind"
    );
    for o in &extra {
        assert!(o.high_risk, "{} is high-risk (strict reading)", o.name);
        assert!(
            matches!(o.kind, OpKind::Tenant(TenantKind::SetSetting(p)) if p != TenantParam::P70),
            "{} is a tenant setting other than P-70",
            o.name
        );
        named.insert(o.name);
    }
    let unnamed: Vec<&str> = OPS
        .iter()
        .filter(|o| o.high_risk && !named.contains(o.name))
        .map(|o| o.name)
        .collect();
    assert!(
        unnamed.is_empty(),
        "high-risk operations no row names: {unnamed:?}"
    );
}

/// I-85, I-78, design section 3.6 `i85_every_high_risk_tool_is_prepare_only`:
/// every tool whose operation is high-risk is prepare-only, and the
/// reverse. Under the Q32 interim reading the one prepare-only tool is
/// `fstp_prepare_call_publication` on `call.publish`.
#[test]
fn i85_every_high_risk_tool_is_prepare_only() {
    let publish = require(&["call.publish"]);
    let publish = publish.first().copied().unwrap_or_else(|| unreachable!());
    let tool = publish
        .tool
        .unwrap_or_else(|| panic!("call.publish has no tool"));
    assert_eq!(tool.name, "fstp_prepare_call_publication");
    assert!(
        tool.prepare_only,
        "fstp_prepare_call_publication is prepare-only"
    );

    let mut prepare_only = Vec::new();
    for o in OPS {
        if let Some(t) = o.tool {
            assert_eq!(
                t.prepare_only, o.high_risk,
                "{}: prepare_only equals high_risk for {}",
                t.name, o.name
            );
            if t.prepare_only {
                prepare_only.push(t.name);
            }
        }
    }
    assert_eq!(
        prepare_only,
        vec!["fstp_prepare_call_publication"],
        "Q32 interim"
    );
}

/// I-84, design section 3.6 `i84_every_tool_has_a_web_route`: no tool
/// exists that the user's roles could not perform in the interface, so
/// every operation with a tool has a web route. The capability table of
/// design section 3.8 holds 35 tools.
#[test]
fn i84_every_tool_has_a_web_route() {
    let tools: Vec<&OpSpec> = OPS.iter().filter(|o| o.tool.is_some()).collect();
    assert_eq!(tools.len(), 35, "operations with a tool");
    let routeless: Vec<&str> = tools
        .iter()
        .filter(|o| o.route.is_none())
        .map(|o| o.name)
        .collect();
    assert!(
        routeless.is_empty(),
        "tools without a web route: {routeless:?}"
    );
}

/// I-84, design section 8.4 `i84_every_tool_maps_to_one_op`: each tool name
/// appears on exactly one operation, and each operation carries at most
/// one tool. Outside the public tools, each tool's scope is the
/// operation's scope. Public tools need no token, so their operations may
/// carry no scope.
#[test]
fn i84_every_tool_maps_to_one_op() {
    let mut by_tool: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for o in OPS {
        if let Some(t) = o.tool {
            by_tool.entry(t.name).or_default().push(o.name);
            if !matches!(o.kind, OpKind::Public(_)) {
                assert_eq!(o.scope, Some(t.scope), "{}: scope of {}", o.name, t.name);
            }
        }
    }
    assert_eq!(by_tool.len(), 35, "distinct tool names");
    let shared: Vec<(&str, Vec<&str>)> = by_tool
        .into_iter()
        .filter(|(_, ops)| ops.len() != 1)
        .collect();
    assert!(
        shared.is_empty(),
        "tools on more than one operation: {shared:?}"
    );
}

/// I-84 support: operation names are unique, so the generated TypeScript
/// table and the journeys address one operation each.
#[test]
fn i84_op_names_are_unique() {
    assert!(!OPS.is_empty(), "the registry is empty");
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for o in OPS {
        *seen.entry(o.name).or_insert(0) += 1;
    }
    let repeated: Vec<&str> = seen
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name)
        .collect();
    assert!(
        repeated.is_empty(),
        "repeated operation names: {repeated:?}"
    );
}

/// The capability table of `mcp-server.md`, row by row, mapped to the M4
/// tools of design section 3.8. An empty row names the milestone that
/// brings its tools.
const CAPABILITY_ROWS: [(&str, &[&str], &str); 7] = [
    (
        "Applicant",
        &[
            "fstp_list_open_calls",
            "fstp_get_guide",
            "fstp_list_my_proposals",
            "fstp_get_my_proposal",
            "fstp_save_workspace",
            "fstp_record_plan_version",
            "fstp_submit_proposal",
            "fstp_get_stage2_questions",
            "fstp_answer_stage2",
            "fstp_submit_revision",
            "fstp_list_notices",
        ],
        "",
    ),
    ("Grantee", &[], "M5 grants"),
    (
        "Reviewer and committee",
        &[
            "fstp_list_assignments",
            "fstp_get_score_sheet",
            "fstp_record_score",
            "fstp_correct_score",
            "fstp_record_ranking_summary",
            "fstp_get_ranking_view",
            "fstp_get_findings",
            "fstp_get_proposal_content",
        ],
        "",
    ),
    (
        "Programme staff",
        &[
            "fstp_creator_get_draft",
            "fstp_creator_get_report",
            "fstp_creator_save_fields",
            "fstp_draft_call",
            "fstp_edit_call",
            "fstp_get_call_board",
            "fstp_prepare_call_publication",
        ],
        "",
    ),
    ("Finance roles", &[], "M5 payments"),
    ("Auditor", &["fstp_audit_list_entries"], ""),
    (
        "Anyone, without an account",
        &[
            "fstp_public_list_open_calls",
            "fstp_public_get_call",
            "fstp_public_get_guide",
            "fstp_public_get_deadlines",
            "fstp_public_get_eligibility",
            "fstp_public_list_funded",
            "fstp_public_list_finished",
            "fstp_public_get_programme",
        ],
        "",
    ),
];

/// I-84, R-MC-01, R-MC-04, design section 3.6
/// `ops_tools_match_mcp_capability_table`: the capability table of
/// `mcp-server.md` is read at test time and checked against a hand-written
/// row map in both directions. Every tool of the registry is in one row,
/// and every mapped tool is in the registry.
#[test]
fn ops_tools_match_mcp_capability_table() {
    let text = spec_file("03-architecture/mcp-server.md");
    let spec_rows: BTreeSet<String> = table_first_cells(&text, "## Capabilities by role")
        .into_iter()
        .collect();
    let map_rows: BTreeSet<String> = CAPABILITY_ROWS.iter().map(|r| r.0.to_string()).collect();
    assert_eq!(
        spec_rows, map_rows,
        "capability table rows against the row map"
    );

    let mut mapped: BTreeMap<&str, &str> = BTreeMap::new();
    for (row, tools, later) in CAPABILITY_ROWS {
        assert!(
            !tools.is_empty() || !later.is_empty(),
            "row {row:?} names neither a tool nor a milestone"
        );
        for t in tools {
            assert!(mapped.insert(t, row).is_none(), "{t} is in two rows");
        }
    }
    let registry: BTreeSet<&str> = OPS.iter().filter_map(|o| o.tool).map(|t| t.name).collect();
    let mapped_names: BTreeSet<&str> = mapped.keys().copied().collect();
    let missing: Vec<&&str> = mapped_names.difference(&registry).collect();
    let extra: Vec<&&str> = registry.difference(&mapped_names).collect();
    assert!(
        missing.is_empty(),
        "mapped tools the registry lacks: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "registry tools no capability row covers: {extra:?}"
    );
}

/// The tools the capability table of design section 3.8 marks binding.
const BINDING_TOOLS: [&str; 6] = [
    "fstp_submit_proposal",
    "fstp_answer_stage2",
    "fstp_submit_revision",
    "fstp_record_score",
    "fstp_correct_score",
    "fstp_record_ranking_summary",
];

/// R-MC-05, P-77, design section 3.8: the tools the capability table marks
/// "binding" are on binding operations. The drafting and read tools of the
/// Applicant and Reviewer rows are not binding, so P-77 "draft only" never
/// turns a draft or a read into a pending action.
#[test]
fn r_mc_05_capability_table_binding_marks_match_ops() {
    let mut binding = BTreeSet::new();
    let mut plain = BTreeSet::new();
    for (row, tools, _) in CAPABILITY_ROWS {
        if row != "Applicant" && row != "Reviewer and committee" {
            continue;
        }
        for t in tools {
            let o = OPS
                .iter()
                .find(|o| o.tool.map(|x| x.name) == Some(*t))
                .unwrap_or_else(|| panic!("no operation carries {t}"));
            if o.binding {
                binding.insert(*t);
            } else {
                plain.insert(*t);
            }
        }
    }
    let expected: BTreeSet<&str> = BINDING_TOOLS.iter().copied().collect();
    assert_eq!(
        binding, expected,
        "binding tools of the Applicant and Reviewer rows"
    );
    assert_eq!(
        plain.len(),
        13,
        "non-binding tools of those rows: {plain:?}"
    );
}

/// I-77, I-78, R-LG-02: every high-risk operation needs a phishing-resistant
/// session, so a magic-link or OPAQUE session never reaches one.
#[test]
fn i78_high_risk_ops_need_a_phishing_resistant_session() {
    let high: Vec<&OpSpec> = OPS.iter().filter(|o| o.high_risk).collect();
    assert!(
        high.len() >= 16,
        "high-risk operations: {:?}",
        high.iter().map(|o| o.name).collect::<Vec<_>>()
    );
    let weak: Vec<&str> = high
        .iter()
        .filter(|o| o.session != SessionNeed::PhishingResistant)
        .map(|o| o.name)
        .collect();
    assert!(
        weak.is_empty(),
        "high-risk operations open to weak sessions: {weak:?}"
    );
}

/// I-86, design section 3.6: the vault outcome read and the vault-bound
/// statements never have a tool, so nothing from the vault reaches MCP.
#[test]
fn i86_vault_reads_and_statements_have_no_tool() {
    for o in require(&[
        "audit.vault_outcomes",
        "proposal.state_country",
        "proposal.declare_affiliations",
    ]) {
        assert!(o.tool.is_none(), "{} has a tool", o.name);
    }
    let vault_read: Vec<&OpSpec> = OPS
        .iter()
        .filter(|o| o.kind == OpKind::Read(ReadKind::GetVaultOutcomes))
        .collect();
    assert_eq!(vault_read.len(), 1, "one GetVaultOutcomes operation");
    assert!(vault_read.iter().all(|o| o.tool.is_none()));
}

/// I-87, R-MC-04: every public operation is classified public, needs no
/// strong session and is neither high-risk nor binding.
#[test]
fn i87_public_ops_are_classified_public() {
    let public: Vec<&OpSpec> = OPS
        .iter()
        .filter(|o| matches!(o.kind, OpKind::Public(_)))
        .collect();
    assert!(public.len() >= 9, "public operations: {}", public.len());
    for o in public {
        assert_eq!(
            o.classification,
            fstp_access::Classification::Public,
            "{} classification",
            o.name
        );
        assert_eq!(
            o.session,
            SessionNeed::Any,
            "{} needs no strong session",
            o.name
        );
        assert!(!o.high_risk && !o.binding, "{} is a plain read", o.name);
    }
}

/// The rule state lists name proposal states, each at most once.
fn states_ok(states: &[StateTag]) -> bool {
    let set: BTreeSet<StateTag> = states.iter().copied().collect();
    set.len() == states.len()
}

/// Every read, by the name its `Debug` spells: the 38 reads of design
/// section 3.6, then the six reads lane m4reg adds for the demo pages
/// (`tenant.list_admins`, `me.get_verification`, `creator.list_programmes`,
/// `creator.list_templates`, `people.get_invitation` and
/// `review.assignments`). The list replaces an exhaustive match, which
/// could not name the m4reg kinds before they exist. A read missing here
/// fails `d11_read_kinds_are_the_design_reads_and_the_m4reg_reads`.
const READ_NAMES: [&str; 44] = [
    "ListOpenCalls",
    "GetPublicCall",
    "GetGuide",
    "ListOwnProposals",
    "GetOwnProposal",
    "GetOwnWorkspace",
    "GetOwnStage2Thread",
    "GetOwnNotices",
    "GetNegotiationLanding",
    "ListMyAssignments",
    "GetDeclarationView",
    "GetContent",
    "GetScoreSheet",
    "GetStage2Thread",
    "GetFindings",
    "GetRankingView",
    "GetCutOffRound",
    "ListMyIrcCases",
    "GetIrcCase",
    "GetIntakeQueue",
    "GetCallBoard",
    "GetDraft",
    "GetReport",
    "GetPreview",
    "GetImpact",
    "ListImportProposals",
    "ListInvitations",
    "ListBindings",
    "GetAuditLog",
    "GetVaultOutcomes",
    "ListMyAgents",
    "ListMyAgentActivity",
    "ListMyPendingActions",
    "ListMySessions",
    "ListNotifiableConflicts",
    "ListApprovals",
    "GetTenantSettings",
    "GetOnboarding",
    "ListTenantAdmins",
    "GetMyVerification",
    "ListProgrammes",
    "ListTemplates",
    "GetInvitation",
    "ListProposalAssignments",
];

/// The index of `k` in [`READ_NAMES`], or `usize::MAX` for a read the
/// list does not name, which no row counter holds.
fn read_index(k: ReadKind) -> usize {
    let name = format!("{k:?}");
    READ_NAMES
        .iter()
        .position(|n| *n == name)
        .unwrap_or(usize::MAX)
}

/// D11, design section 3.6, lane m4reg: `ReadKind::ALL` holds exactly the
/// reads of [`READ_NAMES`], each once, so no read escapes the row check
/// below. Red until lane m4reg adds its six reads.
#[test]
fn d11_read_kinds_are_the_design_reads_and_the_m4reg_reads() {
    let all: Vec<String> = ReadKind::ALL.iter().map(|k| format!("{k:?}")).collect();
    let set: BTreeSet<&str> = all.iter().map(String::as_str).collect();
    assert_eq!(
        set.len(),
        all.len(),
        "ReadKind::ALL repeats a read: {all:?}"
    );
    let want: BTreeSet<&str> = READ_NAMES.iter().copied().collect();
    let missing: Vec<&&str> = want.difference(&set).collect();
    let extra: Vec<&&str> = set.difference(&want).collect();
    assert!(missing.is_empty(), "ReadKind::ALL lacks {missing:?}");
    assert!(
        extra.is_empty(),
        "reads READ_NAMES does not list: {extra:?}"
    );
}

/// D11, R-AC-01, I-21, design section 3.6 ("Every state has a rule"): each
/// read has exactly one row of `READ_RULES` and at least one operation, and
/// each row names its open states once each. A state a row leaves out is
/// a judged refusal, so no read is unjudged in any of the 16 states. The
/// content read opens in no state outside DRAFT to NEGOTIATION for anyone
/// but the team, which the matrix checks per principal.
#[test]
fn d11_read_rules_judge_every_read_in_every_state() {
    let mut rows = [0usize; READ_NAMES.len()];
    for (k, _, states) in READ_RULES {
        let i = read_index(*k);
        if let Some(n) = rows.get_mut(i) {
            *n += 1;
        }
        assert!(states_ok(states), "{k:?} repeats a state: {states:?}");
    }
    let bad: Vec<(ReadKind, usize)> = ReadKind::ALL
        .iter()
        .map(|k| (*k, rows.get(read_index(*k)).copied().unwrap_or(0)))
        .filter(|(_, n)| *n != 1)
        .collect();
    assert!(
        bad.is_empty(),
        "reads without exactly one READ_RULES row: {bad:?}"
    );
    let without_op: Vec<ReadKind> = ReadKind::ALL
        .iter()
        .copied()
        .filter(|k| !OPS.iter().any(|o| o.kind == OpKind::Read(*k)))
        .collect();
    assert!(
        without_op.is_empty(),
        "reads without an operation: {without_op:?}"
    );
}

/// I-84, design section 3.6: every human operation has one web route. The
/// operations a person performs are every registered operation, since the
/// system-only kinds have none.
#[test]
fn i84_every_op_has_a_web_route() {
    assert!(
        OPS.len() >= 100,
        "the registry holds {} operations",
        OPS.len()
    );
    let routeless: Vec<&str> = OPS
        .iter()
        .filter(|o| o.route.is_none())
        .map(|o| o.name)
        .collect();
    assert!(
        routeless.is_empty(),
        "operations without a web route: {routeless:?}"
    );
    let routes: BTreeSet<(fstp_access::Method, &str)> =
        OPS.iter().filter_map(|o| o.route).collect();
    assert!(!routes.is_empty());
}
