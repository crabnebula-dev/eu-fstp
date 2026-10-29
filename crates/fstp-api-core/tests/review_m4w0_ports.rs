//! Reviewer reproducers for lane W0 of M4, port lens
//! (`docs/handoff/m4-design.md` sections 6.1 and 13).
//!
//! Section 13 gives `crates/fstp-api-core/src/port.rs` to W0, and the lead
//! holds it afterwards. Section 6.1 lists the ports M4 is built against.
//! A port missing here cannot be added by the lane that needs it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const PORT: &str = include_str!("../src/port.rs");

/// The source of the `CellPorts` trait, up to the next item.
fn cell_ports() -> &'static str {
    let start = PORT.find("pub trait CellPorts").unwrap();
    let rest = &PORT[start..];
    let end = rest.find("\n}\n").unwrap();
    &rest[..end]
}

/// R-PG-02, design section 6.1: the `BlobStore` port holds uploaded
/// import documents, content-addressed and size-limited. It is a port of
/// `CellPorts`.
#[test]
fn review_r_pg_02_port_rs_has_blob_store() {
    assert!(
        PORT.contains("pub trait BlobStore"),
        "port.rs has no BlobStore trait (design section 6.1)"
    );
    assert!(
        cell_ports().contains(": BlobStore"),
        "CellPorts has no BlobStore port (design section 6.1)"
    );
}

/// R-GA-01 and Q38, design sections 3.10 and 6.1: `PrecheckUnavailable`
/// fails validation in a cell without a `Precheck` port, and the e2e cell
/// provides a fake one. So `CellPorts` carries the `Precheck` port.
#[test]
fn review_r_ga_01_port_rs_has_precheck() {
    assert!(
        PORT.contains("pub trait Precheck"),
        "port.rs has no Precheck trait (design section 6.1)"
    );
    assert!(
        cell_ports().contains("Precheck"),
        "CellPorts has no Precheck port (design section 6.1)"
    );
}
