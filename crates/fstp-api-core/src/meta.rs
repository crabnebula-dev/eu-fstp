//! Tool metadata for adapters (layering rule A2). It re-exports
//! `ToolDef`, `Scope` and `Classification` and nothing else.
//!
//! Lane W3c (L-MCP) added the lookups `fstp-mcp` needs to serve the one
//! tool table without naming `fstp-access` (rule A1): a tool by name,
//! whether it is public, and the classification of its data. It also
//! added the draw and digest of an MCP session id, since rule A1 keeps
//! `fstp-crypto` out of `fstp-mcp` (interim, pending the lead).

pub use fstp_access::{Classification, Scope, ToolDef};

/// Every tool of the registry, in registry order. `fstp-mcp` serves this
/// list and defines no tool of its own (TH-63).
pub fn tools() -> impl Iterator<Item = &'static ToolDef> {
    fstp_access::OPS.iter().filter_map(|op| op.tool.as_ref())
}

/// The registry entry of the tool named exactly `name`.
fn op_of(name: &str) -> Option<&'static fstp_access::OpSpec> {
    fstp_access::OPS
        .iter()
        .find(|op| op.tool.is_some_and(|t| t.name == name))
}

/// The tool named exactly `name`, or `None` outside the registry.
pub fn tool(name: &str) -> Option<&'static ToolDef> {
    op_of(name).and_then(|op| op.tool.as_ref())
}

/// Whether `tool` is a public tool, served with no credential on
/// `/mcp/public` (I-87). A name outside the registry is not public.
pub fn is_public(tool: &ToolDef) -> bool {
    op_of(tool.name).is_some_and(|op| matches!(op.kind, fstp_access::OpKind::Public(_)))
}

/// How the results of `tool` classify their data. A name outside the
/// registry reads as personal, the strictest class.
pub fn classification(tool: &ToolDef) -> Classification {
    op_of(tool.name).map_or(Classification::Personal, |op| op.classification)
}

/// The length of an MCP session id, in bytes: 128 bits (design section
/// 3.8).
pub const SESSION_ID_LEN: usize = 16;

/// A fresh MCP session id of 128 random bits from
/// `fstp_crypto::random_bytes` (design section 3.8), or `None` when the
/// generator fails, so the caller fails closed.
pub fn draw_session_id() -> Option<[u8; SESSION_ID_LEN]> {
    fstp_crypto::random_array::<SESSION_ID_LEN>().ok()
}

/// The digest an MCP server stores for a session id or a bearer token it
/// binds a session to: SHA-256 of a fixed label and the bytes, so the
/// table never holds the value itself (design section 3.8).
pub fn session_digest(bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(bytes.len().saturating_add(SESSION_LABEL.len()));
    input.extend_from_slice(SESSION_LABEL);
    input.extend_from_slice(bytes);
    fstp_crypto::sha256(&input)
}

/// The label of [`session_digest`].
const SESSION_LABEL: &[u8] = b"fstp-mcp session v1\0";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// TH-63, I-87: every tool is found by its own name, a public tool is
    /// exactly one of a public operation, and its data is public.
    #[test]
    fn th63_tool_lookup_matches_the_registry() {
        for t in tools() {
            assert_eq!(tool(t.name).map(|x| x.name), Some(t.name));
            if is_public(t) {
                assert_eq!(classification(t), Classification::Public, "{}", t.name);
            }
        }
        assert!(tool("no_such_tool").is_none());
        assert!(tools().any(is_public));
    }

    /// Design section 3.8: two session ids differ, and the digest is
    /// labelled, so it is not the plain SHA-256 of the bytes.
    #[test]
    fn adr013_session_ids_are_fresh_and_stored_hashed() {
        let a = draw_session_id().unwrap();
        let b = draw_session_id().unwrap();
        assert_ne!(a, b);
        assert_ne!(session_digest(&a), fstp_crypto::sha256(&a));
        assert_eq!(session_digest(&a), session_digest(&a));
    }
}
