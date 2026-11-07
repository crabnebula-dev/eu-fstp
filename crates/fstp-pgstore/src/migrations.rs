//! The migrations of the application database `c_<cell>` (design
//! section 4.6). `fstp-migrate` runs them as `c_<cell>_migrator`, then
//! `fstp-pgagent` grants each row of the cell role plan through
//! `fstp_meta.apply_grant`.

use fstp_migrate::Migration;

/// The application migrations, in order:
///
/// 1. `meta`: `fstp_meta.placement` and the shared trigger function.
/// 2. `apply_grant`: `fstp_migrate::catalogue::APPLY_GRANT_SQL`, the one
///    shared text of design section 4.1, byte for byte, then
///    `APPLY_GRANT_REVOKE_SQL`, so PUBLIC never holds EXECUTE on the
///    function after the migration commits. The file exists so the set
///    is complete on disk; a test ties it to the two constants.
/// 3. `app`: the schemas, tables and triggers of design section 4.2.
/// 4. `journey`: the journey read model of ADR-015 and
///    `SPEC/12-journey-ui.md` section 11, in its own schema (I-83).
/// 5. `delivery`: the insert-only delivery log `ops.delivery` of the M6
///    dispatcher (M6 design section 3.2).
pub const MIGRATIONS: &[Migration] = &[
    Migration::new(1, "meta", include_str!("../migrations/app/0001_meta.sql")),
    Migration::new(
        2,
        "apply_grant",
        include_str!("../migrations/app/0002_apply_grant.sql"),
    ),
    Migration::new(3, "app", include_str!("../migrations/app/0003_app.sql")),
    Migration::new(
        4,
        "journey",
        include_str!("../migrations/app/0004_journey.sql"),
    ),
    Migration::new(
        5,
        "delivery",
        include_str!("../migrations/app/0005_delivery.sql"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_migrate::catalogue::{APPLY_GRANT_REVOKE_SQL, APPLY_GRANT_SQL};

    /// Design section 4.6: the set is a valid migration list.
    #[test]
    fn i82_app_migrations_form_a_valid_set() {
        assert!(fstp_migrate::MigrationSet::new(MIGRATIONS).is_ok());
    }

    /// I-82, design section 4.1: migration 2 is the shared function text
    /// and the shared revoke, each followed by one line break only.
    #[test]
    fn i82_apply_grant_file_is_the_shared_text() {
        let file = include_str!("../migrations/app/0002_apply_grant.sql");
        assert_eq!(
            file,
            format!("{APPLY_GRANT_SQL}\n{APPLY_GRANT_REVOKE_SQL}\n")
        );
    }

    /// I-82, design section 4.6: no migration installs an extension or
    /// defines a SECURITY DEFINER function.
    #[test]
    fn i82_app_migrations_name_no_extension_and_no_security_definer() {
        for m in MIGRATIONS {
            let upper = m.sql.to_ascii_uppercase();
            assert!(!upper.contains("CREATE EXTENSION"), "{}", m.name);
            assert!(!upper.contains("SECURITY DEFINER"), "{}", m.name);
        }
    }
}
