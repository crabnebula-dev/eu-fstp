//! I-66 and I-67: no route or tool reaches `ActivateProgramme` (M4 design
//! sections 0.2 point 17, 3.6 and 8.4, "Registry").
//!
//! `COMPOSED_ONLY` holds `ActivateProgramme`. No operation of the registry
//! decides it directly. `creator.approve_activation` and, since ADR-022,
//! `creator.override_activation` are the only ways in. Each composes the
//! core command from the creator decision, and neither has an MCP tool, so
//! no agent reaches activation (I-85).
//!
//! The ADR-013 amendment of 2026-11-20 (Daniel) adds one tool that names
//! activation: `fstp_prepare_activation_request` on
//! `creator.request_activation`. It is prepare-only, and the request it
//! prepares composes no activation: the approval of a second person does.
//!
//! Red until lane W3a fills `fstp_access::OPS` with the operation names
//! and their commands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{CreatorKind, OpKind};
use fstp_api_testkit::mc::activate_model::production;

/// I-66, I-67: the registry never routes to the core activation command.
#[test]
fn i66_no_route_or_tool_reaches_activate_programme() {
    let (rows, composed_only) = production::registry().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        composed_only.iter().any(|k| k == "ActivateProgramme"),
        "COMPOSED_ONLY must hold ActivateProgramme: {composed_only:?}"
    );
    let direct: Vec<&str> = rows
        .iter()
        .filter(|r| r.command.as_deref() == Some("ActivateProgramme"))
        .map(|r| r.op.as_str())
        .collect();
    assert!(
        direct.is_empty(),
        "I-66: operations decide ActivateProgramme directly: {direct:?}"
    );
    // The operations that compose `ActivateProgramme` from a creator
    // decision. Exactly these two, by kind, and neither has a tool.
    let composers: Vec<&str> = fstp_access::OPS
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                OpKind::Creator(CreatorKind::ApproveActivation | CreatorKind::OverrideActivation)
            )
        })
        .map(|o| o.name)
        .collect();
    assert_eq!(
        composers,
        ["creator.approve_activation", "creator.override_activation"],
        "I-66: the composers of ActivateProgramme"
    );
    // No tool sits on an operation that decides or composes the
    // activation.
    let reaching: Vec<&str> = rows
        .iter()
        .filter(|r| {
            r.command.as_deref() == Some("ActivateProgramme") || composers.contains(&r.op.as_str())
        })
        .filter_map(|r| r.tool)
        .collect();
    assert!(
        reaching.is_empty(),
        "I-66: tools reach activation: {reaching:?}"
    );
    for name in composers {
        let row = rows
            .iter()
            .find(|r| r.op == name)
            .unwrap_or_else(|| panic!("the registry has no {name}"));
        assert_eq!(row.tool, None, "{name} has no tool");
    }
    // ADR-013 amendment of 2026-11-20: the one tool whose name mentions
    // activation is the prepare-only request, on the request operation.
    let named: Vec<(&str, &str, bool)> = fstp_access::OPS
        .iter()
        .filter_map(|o| o.tool.map(|t| (t, o)))
        .filter(|(t, _)| t.name.contains("activat"))
        .map(|(t, o)| (t.name, o.name, t.prepare_only))
        .collect();
    assert_eq!(
        named,
        [(
            "fstp_prepare_activation_request",
            "creator.request_activation",
            true
        )],
        "I-85: the one activation tool only prepares a request"
    );
    let request = fstp_access::op("creator.request_activation")
        .unwrap_or_else(|| panic!("the registry has no creator.request_activation"));
    assert_eq!(
        request.kind,
        OpKind::Creator(CreatorKind::RequestActivation),
        "the request composes no activation"
    );
}
