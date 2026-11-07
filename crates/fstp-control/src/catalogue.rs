//! The `cp` schema catalogue: the column map of design section 4.4.
//!
//! W0 transcribed every table and column of design section 4.4. Daniel's
//! Q-A answer of 2026-11-07 (m4-design section 15.0) classes the columns
//! section 4.5 left open: `server_spki` and `cose_key` are
//! `PublicKeyMaterial`, `endpoint` and `host` the ADR-009
//! `Infrastructure` class, and `org_ref`, `key_ref` and `case_ref`
//! `OpaqueReference`. Migration 2 adds their checks.
//! ADR-005 and ADR-012 also place base backup records in `cp`; section 4.4
//! does not list them yet, so they are not here.

use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

const fn col(name: &'static str, class: ColumnClass) -> ColumnSpec {
    ColumnSpec {
        name,
        class: Some(class),
    }
}

use ColumnClass::{
    Count, Enum, Infrastructure, OpaqueReference, PublicKeyMaterial, RandomId, Time,
};

/// The tables of the control-plane database (design section 4.4).
pub const CATALOGUE: &[TableSpec] = &[
    TableSpec {
        schema: "cp",
        name: "cluster",
        class: TableClass::Placement,
        columns: &[
            col("cluster_id", RandomId),
            col("kind", Enum),
            col("region", Enum),
            col("endpoint", Infrastructure),
            col("server_spki", PublicKeyMaterial),
            col("created_at", Time),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "cell",
        class: TableClass::Placement,
        columns: &[
            col("cell_id", RandomId),
            col("status", Enum),
            col("mode", Enum),
            col("app_cluster", RandomId),
            col("vault_cluster", RandomId),
            col("app_backend", Enum),
            col("vault_backend", Enum),
            col("org_ref", OpaqueReference),
            col("created_at", Time),
            col("erased_at", Time),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "route",
        class: TableClass::Placement,
        columns: &[
            col("host", Infrastructure),
            col("cell_id", RandomId),
            col("kind", Enum),
            col("verified_at", Time),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "custody_entry",
        class: TableClass::Operational,
        columns: &[
            col("cell_id", RandomId),
            col("chain", Enum),
            col("backend", Enum),
            col("key_ref", OpaqueReference),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "metering",
        class: TableClass::Operational,
        columns: &[
            col("cell_id", RandomId),
            col("period", Time),
            col("counter", Enum),
            col("value", Count),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "staff",
        class: TableClass::Operational,
        columns: &[col("staff_id", RandomId), col("created_at", Time)],
    },
    TableSpec {
        schema: "cp",
        name: "staff_credential",
        class: TableClass::Operational,
        columns: &[
            col("cred_id", RandomId),
            col("staff_id", RandomId),
            col("cose_key", PublicKeyMaterial),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "operator_ticket",
        class: TableClass::Operational,
        columns: &[
            col("id", RandomId),
            col("cell_id", RandomId),
            col("kind", Enum),
            col("case_ref", OpaqueReference),
            col("approved_by", RandomId),
            col("issued_at", Time),
        ],
    },
    TableSpec {
        schema: "cp",
        name: "job",
        class: TableClass::Operational,
        columns: &[
            col("id", RandomId),
            col("cluster_id", RandomId),
            col("kind", Enum),
            col("state", Enum),
            col("approved_by", RandomId),
            col("at", Time),
        ],
    },
];
