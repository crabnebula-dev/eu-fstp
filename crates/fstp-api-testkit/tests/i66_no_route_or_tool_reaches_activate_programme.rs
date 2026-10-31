//! I-66 and I-67: no route or tool reaches `ActivateProgramme` (M4 design
//! sections 0.2 point 17, 3.6 and 8.4, "Registry").
//!
//! `COMPOSED_ONLY` holds `ActivateProgramme`. No operation of the registry
//! decides it directly. `creator.approve_activation` is the only way in,
//! it composes the core command from the creator decision, and it has no
//! MCP tool, so no agent reaches activation (I-85).
//!
//! Red until lane W3a fills `fstp_access::OPS` with the operation names
//! and their commands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
    let tools: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.tool)
        .filter(|t| t.contains("activat"))
        .collect();
    assert!(tools.is_empty(), "I-66: tools reach activation: {tools:?}");
    let approve = rows
        .iter()
        .find(|r| r.op == "creator.approve_activation")
        .unwrap_or_else(|| panic!("the registry has no creator.approve_activation"));
    assert_eq!(approve.tool, None, "creator.approve_activation has no tool");
}
