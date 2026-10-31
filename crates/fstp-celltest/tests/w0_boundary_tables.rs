//! I-19, I-20: the boundary tables reviewed row by row against their
//! sources (`docs/handoff/m3-design.md` sections 4.4, 4.5 and 9.1,
//! ADR-009 "Metadata register", lane W0).
//!
//! - The metadata register (Q36 A) against the ADR-009 table, read at run
//!   time. The spec has no register text yet; Q28 proposes it.
//! - The `CellToCp` and `CpToCell` field declarations and the field-class
//!   allowlist against design section 9.1.
//! - The control-plane and witness column maps against design section 4.4.
//!
//! API these tests expect:
//!
//! - `fstp_cp_proto::METADATA_REGISTER: &[RegisterEntry]`, where
//!   `RegisterEntry` has the public `&'static str` fields `entry`,
//!   `destination` and `form`, each the ADR-009 cell verbatim;
//! - `fstp_cp_proto::FIELDS: &[FieldDecl]`, where `FieldDecl` has the
//!   public `&'static str` fields `message` (the enum), `variant`, `field`
//!   (the name, or `0` for a tuple variant) and `ty` (the type as written);
//! - `fstp_cp_proto::FIELD_CLASS_ALLOWLIST: &[&'static str]`, the closed
//!   types a field may use;
//! - `fstp_control::CATALOGUE` and `fstp_witness::CATALOGUE`, each a
//!   `&[fstp_migrate::catalogue::TableSpec]` with public fields `schema`,
//!   `name` and `columns`, each column a `ColumnSpec` with a public `name`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::Path;

use fstp_cp_proto::{FIELD_CLASS_ALLOWLIST, FIELDS, METADATA_REGISTER};

/// The rows of the first table after `heading` in a Markdown file under
/// the repository root, without the header and separator rows.
fn table_after(rel: &str, heading: &str) -> Vec<Vec<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut rows = Vec::new();
    let mut in_section = false;
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            if in_section {
                break;
            }
            in_section = t == heading;
            continue;
        }
        if !in_section {
            continue;
        }
        if t.starts_with('|') {
            in_table = true;
            rows.push(
                t.trim_matches('|')
                    .split('|')
                    .map(|c| c.trim().to_owned())
                    .collect(),
            );
        } else if in_table {
            break;
        }
    }
    rows.into_iter().skip(2).collect()
}

/// ADR-009 "Metadata register" as (entry, destination, form).
fn adr_009_register() -> BTreeSet<(String, String, String)> {
    table_after("docs/adr/ADR-009-cell-boundary.md", "## Metadata register")
        .into_iter()
        .map(|r| {
            let cell = |i: usize| r.get(i).cloned().unwrap_or_default();
            (cell(0), cell(1), cell(2))
        })
        .collect()
}

/// I-19, Q36 A, design section 9.1: the ADR-009 register has the six
/// entries the design names. This guards the parse below.
#[test]
fn i19_adr_009_register_has_the_six_designed_entries() {
    let entries: BTreeSet<String> = adr_009_register().into_iter().map(|(e, _, _)| e).collect();
    let expected: BTreeSet<String> = [
        "Heartbeat product version",
        "Heartbeat health",
        "Metering counters",
        "Edge connection metadata",
        "Operator metrics",
        "Anchor fields",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(entries, expected);
}

/// I-19, Q36 A: `METADATA_REGISTER` equals the ADR-009 table row for row,
/// with entry, destination and form verbatim.
#[test]
fn i19_metadata_register_matches_adr_009_rows() {
    let actual: BTreeSet<(String, String, String)> = METADATA_REGISTER
        .iter()
        .map(|e| {
            (
                e.entry.to_owned(),
                e.destination.to_owned(),
                e.form.to_owned(),
            )
        })
        .collect();
    assert_eq!(actual, adr_009_register());
    assert_eq!(METADATA_REGISTER.len(), 6, "an entry appears twice");
}

/// Design section 9.1, transcribed: enum, variant, field, type.
const DESIGN_FIELDS: [(&str, &str, &str, &str); 23] = [
    ("CellToCp", "Heartbeat", "cell", "CellId"),
    ("CellToCp", "Heartbeat", "version", "ProductVersion"),
    ("CellToCp", "Heartbeat", "health", "Health"),
    ("CellToCp", "RoleCredential", "role", "RoleName"),
    ("CellToCp", "RoleCredential", "spki", "SpkiDigest"),
    ("CellToCp", "RoleCredential", "pop", "PopSig"),
    (
        "CellToCp",
        "RoleCredential",
        "scram_verifier",
        "ScramVerifier",
    ),
    ("CellToCp", "CertRenewal", "component", "Component"),
    ("CellToCp", "CertRenewal", "spki", "SpkiDigest"),
    ("CellToCp", "CertRenewal", "pop", "PopSig"),
    ("CellToCp", "Metering", "cell", "CellId"),
    ("CellToCp", "Metering", "period", "i64"),
    (
        "CellToCp",
        "Metering",
        "counters",
        "Vec<(CounterKind, u64)>",
    ),
    ("CpToCell", "Certificate", "0", "CertDer"),
    ("CpToCell", "OperatorTicket", "case", "CaseRef"),
    ("CpToCell", "OperatorTicket", "kind", "TicketKind"),
    ("CpToCell", "OperatorTicket", "issued_at", "i64"),
    ("CpToCell", "OperatorTicket", "sig", "CompositeSig"),
    ("CpToCell", "BreakGlassRequest", "staff", "StaffRef"),
    ("CpToCell", "BreakGlassRequest", "scope", "BreakGlassScope"),
    ("CpToCell", "BreakGlassRequest", "until", "i64"),
    ("CpToCell", "EraseScheduled", "at", "i64"),
    ("Health", "Degraded", "0", "DegradedReason"),
];

/// The closed types of design section 9.1. `Vec` and tuples only wrap them.
const CLOSED_TYPES: [&str; 18] = [
    "CellId",
    "ProductVersion",
    "Health",
    "RoleName",
    "SpkiDigest",
    "PopSig",
    "ScramVerifier",
    "Component",
    "CounterKind",
    "CertDer",
    "CaseRef",
    "TicketKind",
    "CompositeSig",
    "StaffRef",
    "BreakGlassScope",
    "DegradedReason",
    "i64",
    "u64",
];

/// The type names inside a written type, without `Vec` and punctuation.
fn type_names(ty: &str) -> Vec<String> {
    ty.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty() && *t != "Vec")
        .map(str::to_owned)
        .collect()
}

/// I-19, design section 9.1: the field declarations equal the design's
/// closed protocol, field for field. M3 adds no variant that carries
/// tenant data (template publication and the directory arrive in M4 and
/// M9).
#[test]
fn i19_cp_proto_fields_match_design_section_9_1() {
    let actual: BTreeSet<(String, String, String, String)> = FIELDS
        .iter()
        .map(|f| {
            (
                f.message.to_owned(),
                f.variant.to_owned(),
                f.field.to_owned(),
                f.ty.to_owned(),
            )
        })
        .collect();
    let expected: BTreeSet<(String, String, String, String)> = DESIGN_FIELDS
        .iter()
        .map(|(m, v, f, t)| {
            (
                (*m).to_owned(),
                (*v).to_owned(),
                (*f).to_owned(),
                (*t).to_owned(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
}

/// I-19, design section 14.4: every field type is built from the
/// field-class allowlist only.
#[test]
fn i19_cp_proto_fields_are_declared() {
    let allow: BTreeSet<&str> = FIELD_CLASS_ALLOWLIST.iter().copied().collect();
    for f in FIELDS {
        for name in type_names(f.ty) {
            assert!(
                allow.contains(name.as_str()),
                "{}::{}.{} uses {name}, which is not on the allowlist",
                f.message,
                f.variant,
                f.field
            );
        }
    }
}

/// I-19, design section 9.1: the field-class allowlist is exactly the
/// reviewed set of closed types. It holds no free-text or byte-blob type.
#[test]
fn i19_field_class_allowlist_is_the_reviewed_closed_set() {
    let actual: BTreeSet<&str> = FIELD_CLASS_ALLOWLIST.iter().copied().collect();
    let expected: BTreeSet<&str> = CLOSED_TYPES.into_iter().collect();
    assert_eq!(actual, expected);
    for open in ["String", "str", "u8", "char", "Value", "Bytes"] {
        assert!(!actual.contains(open), "{open} is open-ended");
    }
}

/// Design section 4.4, transcribed: schema, table, columns.
const CP_TABLES: [(&str, &str, &[&str]); 9] = [
    (
        "cp",
        "cluster",
        &[
            "cluster_id",
            "kind",
            "region",
            "endpoint",
            "server_spki",
            "created_at",
        ],
    ),
    (
        "cp",
        "cell",
        &[
            "cell_id",
            "status",
            "mode",
            "app_cluster",
            "vault_cluster",
            "app_backend",
            "vault_backend",
            "org_ref",
            "created_at",
            "erased_at",
        ],
    ),
    ("cp", "route", &["host", "cell_id", "kind", "verified_at"]),
    (
        "cp",
        "custody_entry",
        &["cell_id", "chain", "backend", "key_ref"],
    ),
    ("cp", "metering", &["cell_id", "period", "counter", "value"]),
    ("cp", "staff", &["staff_id", "created_at"]),
    (
        "cp",
        "staff_credential",
        &["cred_id", "staff_id", "cose_key"],
    ),
    (
        "cp",
        "operator_ticket",
        &[
            "id",
            "cell_id",
            "kind",
            "case_ref",
            "approved_by",
            "issued_at",
        ],
    ),
    (
        "cp",
        "job",
        &["id", "cluster_id", "kind", "state", "approved_by", "at"],
    ),
];

/// The witness anchor table of design section 4.4.
const WITNESS_ANCHOR: [&str; 9] = [
    "cell_id",
    "chain",
    "n",
    "link",
    "at",
    "signature",
    "received_at",
    "witness_seq",
    "witness_link",
];

fn columns_of(
    catalogue: &[fstp_migrate::catalogue::TableSpec],
    schema: &str,
) -> BTreeSet<(String, String)> {
    catalogue
        .iter()
        .filter(|t| t.schema == schema)
        .flat_map(|t| {
            t.columns
                .iter()
                .map(move |c| (t.name.to_owned(), c.name.to_owned()))
        })
        .collect()
}

/// I-19, I-20, design section 4.4, ADR-005: the `cp` column map pins the
/// exact column set of the control-plane schema. A table or column outside
/// the design fails until the design and ADR-005 name it.
#[test]
fn i19_control_plane_column_map_matches_design_section_4_4() {
    let expected: BTreeSet<(String, String)> = CP_TABLES
        .iter()
        .flat_map(|(_, t, cols)| cols.iter().map(move |c| ((*t).to_owned(), (*c).to_owned())))
        .collect();
    assert_eq!(columns_of(fstp_control::CATALOGUE, "cp"), expected);
}

/// I-19, I-24, design section 4.4: the witness anchor table holds exactly
/// the designed columns.
#[test]
fn i19_witness_anchor_column_map_matches_design_section_4_4() {
    let actual: BTreeSet<String> = columns_of(fstp_witness::CATALOGUE, "witness")
        .into_iter()
        .filter(|(t, _)| t == "anchor")
        .map(|(_, c)| c)
        .collect();
    let expected: BTreeSet<String> = WITNESS_ANCHOR.iter().map(|c| (*c).to_owned()).collect();
    assert_eq!(actual, expected);
}
