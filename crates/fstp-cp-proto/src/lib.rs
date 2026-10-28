//! The closed protocol between a cell and the control plane (I-19, I-20,
//! M3 design section 9.1, ADR-009).
//!
//! Every field has a closed type. No variant has a free-text or byte-blob
//! field, so in M3 the protocol cannot carry tenant data. Template
//! publication (I-73) and the open-call directory (P-76) arrive in M4 and
//! M9, each behind its own guard.
//!
//! The crate also holds three reviewed tables as data:
//!
//! - [`FIELDS`], every field of [`CellToCp`], [`CpToCell`] and [`Health`]
//!   with its type as written in design section 9.1;
//! - [`FIELD_CLASS_ALLOWLIST`], the closed types a field may use;
//! - [`METADATA_REGISTER`], the six entries of the ADR-009 metadata register
//!   (Q36 A), each cell verbatim.
//!
//! Status: W0 stub for the codec. Lane W2h fills it. Every decoder refuses
//! with [`ProtoError::NotImplemented`].

pub mod types;

pub use types::{
    BreakGlassScope, CaseRef, CellId, CertDer, Component, CompositeSig, CounterKind,
    DegradedReason, PopSig, ProductVersion, ROLE_SUFFIX_GRAMMAR, RoleName, ScramVerifier,
    SpkiDigest, StaffRef, TicketKind,
};

/// A message from a cell to the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellToCp {
    /// Liveness, product version and health.
    Heartbeat {
        /// The cell.
        cell: CellId,
        /// The product version.
        version: ProductVersion,
        /// The health.
        health: Health,
    },
    /// A database role credential for provisioning.
    RoleCredential {
        /// The role.
        role: RoleName,
        /// The SPKI digest of the role certificate key.
        spki: SpkiDigest,
        /// The proof of possession.
        pop: PopSig,
        /// The SCRAM verifier.
        scram_verifier: ScramVerifier,
    },
    /// A certificate renewal request.
    CertRenewal {
        /// The component.
        component: Component,
        /// The SPKI digest of the new key.
        spki: SpkiDigest,
        /// The proof of possession.
        pop: PopSig,
    },
    /// Metering counters, as counts per day.
    Metering {
        /// The cell.
        cell: CellId,
        /// The period, a UTC day number.
        period: i64,
        /// The counters.
        counters: Vec<(CounterKind, u64)>,
    },
}

/// A message from the control plane to a cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpToCell {
    /// Acknowledged.
    Ack,
    /// An issued certificate.
    Certificate(CertDer),
    /// An operator ticket for a recovery or break-glass case.
    OperatorTicket {
        /// The cell's opaque case reference, never an account id (I-20).
        case: CaseRef,
        /// The ticket kind.
        kind: TicketKind,
        /// UTC microseconds.
        issued_at: i64,
        /// The composite signature.
        sig: CompositeSig,
    },
    /// A break-glass request for the tenant to approve (SoD-08).
    BreakGlassRequest {
        /// The staff member.
        staff: StaffRef,
        /// The scope.
        scope: BreakGlassScope,
        /// UTC microseconds.
        until: i64,
    },
    /// The cell's erasure is scheduled (R-SW-02).
    EraseScheduled {
        /// UTC microseconds.
        at: i64,
    },
}

/// The health of a cell. Closed, with no free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// Healthy.
    Ok,
    /// Degraded, with a closed reason.
    Degraded(DegradedReason),
    /// In maintenance.
    Maintenance,
}

/// One declared field of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldDecl {
    /// The enum: `CellToCp`, `CpToCell` or `Health`.
    pub message: &'static str,
    /// The variant.
    pub variant: &'static str,
    /// The field name, or `0` for a tuple variant.
    pub field: &'static str,
    /// The type as written.
    pub ty: &'static str,
}

const fn field(
    message: &'static str,
    variant: &'static str,
    field: &'static str,
    ty: &'static str,
) -> FieldDecl {
    FieldDecl {
        message,
        variant,
        field,
        ty,
    }
}

/// Every field of the protocol, as design section 9.1 writes it. Unit
/// variants have no entry. The test `i19_fields_name_every_variant` keeps
/// this list in step with the enums.
pub const FIELDS: &[FieldDecl] = &[
    field("CellToCp", "Heartbeat", "cell", "CellId"),
    field("CellToCp", "Heartbeat", "version", "ProductVersion"),
    field("CellToCp", "Heartbeat", "health", "Health"),
    field("CellToCp", "RoleCredential", "role", "RoleName"),
    field("CellToCp", "RoleCredential", "spki", "SpkiDigest"),
    field("CellToCp", "RoleCredential", "pop", "PopSig"),
    field(
        "CellToCp",
        "RoleCredential",
        "scram_verifier",
        "ScramVerifier",
    ),
    field("CellToCp", "CertRenewal", "component", "Component"),
    field("CellToCp", "CertRenewal", "spki", "SpkiDigest"),
    field("CellToCp", "CertRenewal", "pop", "PopSig"),
    field("CellToCp", "Metering", "cell", "CellId"),
    field("CellToCp", "Metering", "period", "i64"),
    field(
        "CellToCp",
        "Metering",
        "counters",
        "Vec<(CounterKind, u64)>",
    ),
    field("CpToCell", "Certificate", "0", "CertDer"),
    field("CpToCell", "OperatorTicket", "case", "CaseRef"),
    field("CpToCell", "OperatorTicket", "kind", "TicketKind"),
    field("CpToCell", "OperatorTicket", "issued_at", "i64"),
    field("CpToCell", "OperatorTicket", "sig", "CompositeSig"),
    field("CpToCell", "BreakGlassRequest", "staff", "StaffRef"),
    field("CpToCell", "BreakGlassRequest", "scope", "BreakGlassScope"),
    field("CpToCell", "BreakGlassRequest", "until", "i64"),
    field("CpToCell", "EraseScheduled", "at", "i64"),
    field("Health", "Degraded", "0", "DegradedReason"),
];

/// The closed types a protocol field may use (design section 9.1). `Vec`
/// and tuples only wrap them. No free-text or byte-blob type is here.
pub const FIELD_CLASS_ALLOWLIST: &[&str] = &[
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

/// One entry of the metadata register (ADR-009, Q36 A).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterEntry {
    /// The entry, as the ADR-009 table names it.
    pub entry: &'static str,
    /// Where it goes.
    pub destination: &'static str,
    /// Its coarsest useful form.
    pub form: &'static str,
}

/// The metadata register: the only fields that cross to shared
/// infrastructure without being tenant content (ADR-009 "Metadata
/// register", design section 9.1). Each cell is the ADR-009 text verbatim.
/// A new entry needs an amendment of ADR-009 first.
pub const METADATA_REGISTER: &[RegisterEntry] = &[
    RegisterEntry {
        entry: "Heartbeat product version",
        destination: "Control plane",
        form: "`ProductVersion`, a closed grammar",
    },
    RegisterEntry {
        entry: "Heartbeat health",
        destination: "Control plane",
        form: "`Health`, a closed enum with no free text",
    },
    RegisterEntry {
        entry: "Metering counters",
        destination: "Control plane",
        form: "`(CounterKind, u64)` counts per day",
    },
    RegisterEntry {
        entry: "Edge connection metadata",
        destination: "Edge logs",
        form: "Cell id and host. Byte counts and timings bucketed to powers of two",
    },
    RegisterEntry {
        entry: "Operator metrics",
        destination: "Shared metric sink",
        form: "Metric names from a closed enum, values labelled by cell id only",
    },
    RegisterEntry {
        entry: "Anchor fields",
        destination: "Witness",
        form: "`cell`, `chain`, `n`, `link`, `at` and the signature. `link` is a SHA-256 value over sealed rows",
    },
];

/// Why a message did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// The codec is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Decodes a message from a cell. Fuzzed (`cell_to_cp_decode`).
pub fn decode_cell_to_cp(bytes: &[u8]) -> Result<CellToCp, ProtoError> {
    let _ = bytes;
    Err(ProtoError::NotImplemented(
        "fstp_cp_proto::decode_cell_to_cp",
    ))
}

/// Decodes a message from the control plane. Fuzzed (`cp_to_cell_decode`).
pub fn decode_cp_to_cell(bytes: &[u8]) -> Result<CpToCell, ProtoError> {
    let _ = bytes;
    Err(ProtoError::NotImplemented(
        "fstp_cp_proto::decode_cp_to_cell",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The variant name of a `CellToCp` and the names of its fields. The
    /// match is exhaustive, so a new variant fails to compile here.
    fn cell_to_cp_fields(m: &CellToCp) -> (&'static str, &'static [&'static str]) {
        match m {
            CellToCp::Heartbeat { .. } => ("Heartbeat", &["cell", "version", "health"]),
            CellToCp::RoleCredential { .. } => {
                ("RoleCredential", &["role", "spki", "pop", "scram_verifier"])
            }
            CellToCp::CertRenewal { .. } => ("CertRenewal", &["component", "spki", "pop"]),
            CellToCp::Metering { .. } => ("Metering", &["cell", "period", "counters"]),
        }
    }

    /// The same for `CpToCell`.
    fn cp_to_cell_fields(m: &CpToCell) -> (&'static str, &'static [&'static str]) {
        match m {
            CpToCell::Ack => ("Ack", &[]),
            CpToCell::Certificate(_) => ("Certificate", &["0"]),
            CpToCell::OperatorTicket { .. } => {
                ("OperatorTicket", &["case", "kind", "issued_at", "sig"])
            }
            CpToCell::BreakGlassRequest { .. } => {
                ("BreakGlassRequest", &["staff", "scope", "until"])
            }
            CpToCell::EraseScheduled { .. } => ("EraseScheduled", &["at"]),
        }
    }

    /// The same for `Health`.
    fn health_fields(h: &Health) -> (&'static str, &'static [&'static str]) {
        match h {
            Health::Ok => ("Ok", &[]),
            Health::Degraded(_) => ("Degraded", &["0"]),
            Health::Maintenance => ("Maintenance", &[]),
        }
    }

    /// I-19, design section 9.1: `FIELDS` names exactly the fields of the
    /// three enums. The exhaustive matches above break the build when a
    /// variant is added without a review of this list.
    #[test]
    fn i19_fields_name_every_variant() {
        let cell = CellId([0; 16]);
        let version = ProductVersion::new(0, 0, 0);
        let health = Health::Ok;
        let samples_cell = [
            CellToCp::Heartbeat {
                cell,
                version,
                health,
            },
            CellToCp::RoleCredential {
                role: RoleName::Writer,
                spki: SpkiDigest([0; 32]),
                pop: PopSig::empty(),
                scram_verifier: ScramVerifier::empty(),
            },
            CellToCp::CertRenewal {
                component: Component::Cell,
                spki: SpkiDigest([0; 32]),
                pop: PopSig::empty(),
            },
            CellToCp::Metering {
                cell,
                period: 0,
                counters: vec![],
            },
        ];
        let samples_cp = [
            CpToCell::Ack,
            CpToCell::Certificate(CertDer::empty()),
            CpToCell::OperatorTicket {
                case: CaseRef([0; 16]),
                kind: TicketKind::Recovery,
                issued_at: 0,
                sig: CompositeSig::empty(),
            },
            CpToCell::BreakGlassRequest {
                staff: StaffRef([0; 16]),
                scope: BreakGlassScope::ReadContent,
                until: 0,
            },
            CpToCell::EraseScheduled { at: 0 },
        ];
        let samples_health = [
            Health::Ok,
            Health::Degraded(DegradedReason::Database),
            Health::Maintenance,
        ];
        let mut actual = BTreeSet::new();
        for m in &samples_cell {
            let (variant, fields) = cell_to_cp_fields(m);
            for f in fields {
                actual.insert(("CellToCp", variant, *f));
            }
        }
        for m in &samples_cp {
            let (variant, fields) = cp_to_cell_fields(m);
            for f in fields {
                actual.insert(("CpToCell", variant, *f));
            }
        }
        for h in &samples_health {
            let (variant, fields) = health_fields(h);
            for f in fields {
                actual.insert(("Health", variant, *f));
            }
        }
        let declared: BTreeSet<(&str, &str, &str)> = FIELDS
            .iter()
            .map(|f| (f.message, f.variant, f.field))
            .collect();
        assert_eq!(actual, declared);
    }
}
