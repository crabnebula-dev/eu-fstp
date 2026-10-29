//! Tool metadata for adapters (layering rule A2). It re-exports
//! `ToolDef`, `Scope` and `Classification` and nothing else.

pub use fstp_access::{Classification, Scope, ToolDef};

/// Every tool of the registry, in registry order. `fstp-mcp` serves this
/// list and defines no tool of its own (TH-63).
pub fn tools() -> impl Iterator<Item = &'static ToolDef> {
    fstp_access::OPS.iter().filter_map(|op| op.tool.as_ref())
}
