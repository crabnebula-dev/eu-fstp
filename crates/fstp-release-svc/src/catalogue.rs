//! The tables of the licence registry database `licence` (M3 design
//! sections 4.5, 4.6 and 10, R-NF-08, I-16), next to the migrations in
//! `migrations/licence/`.
//!
//! The registry holds only the holder name, contact address and licence
//! type (`SPEC/05-compliance/gdpr.md`, ADR-005). Name and contact are
//! sealed, so no clear column holds personal data.
//!
//! Reading, interim, pending Daniel: the table shape. Design section 10
//! names what the registry stores but not its columns.

use fstp_migrate::catalogue::ColumnClass::{Enum, RandomId, Sealed, Time};
use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

const fn col(name: &'static str, class: ColumnClass) -> ColumnSpec {
    ColumnSpec {
        name,
        class: Some(class),
    }
}

/// The tables of the licence registry database.
pub const CATALOGUE: &[TableSpec] = &[TableSpec {
    schema: "licence",
    name: "registration",
    class: TableClass::SealedContent,
    columns: &[
        col("licence_id", RandomId),
        col("kind", Enum),
        col("holder_name", Sealed),
        col("contact_address", Sealed),
        col("registered_at", Time),
    ],
}];

#[cfg(test)]
mod tests {
    use super::CATALOGUE;
    use fstp_migrate::catalogue::ColumnClass;

    /// Design section 4.6, I-16: the licence set is a valid migration list.
    #[test]
    fn i16_licence_migrations_form_a_valid_set() {
        assert!(fstp_migrate::MigrationSet::new(crate::MIGRATIONS).is_ok());
    }

    /// R-NF-08, gdpr.md "Licence registration": the holder name and
    /// contact address are sealed, and every column has a class.
    #[test]
    fn r_nf_08_licence_holder_data_is_sealed() {
        for t in CATALOGUE {
            for c in t.columns {
                assert!(c.class.is_some(), "{}.{}.{}", t.schema, t.name, c.name);
                if c.name == "holder_name" || c.name == "contact_address" {
                    assert_eq!(c.class, Some(ColumnClass::Sealed), "{}", c.name);
                }
            }
        }
    }
}
