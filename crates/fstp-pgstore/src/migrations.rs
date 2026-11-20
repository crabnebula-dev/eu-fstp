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
/// 5. `doc`: write-once document storage of M5 design section 4.3
///    (I-30), sealed like `blob.text`.
/// 6. `delivery`: the insert-only delivery log `ops.delivery` of the M6
///    dispatcher (M6 design section 3.2).
/// 7. `migration_ledger`: `fstp_migrate.schema_migrations` in the runner's
///    own shape, for a set applied without the runner (I-16). Under the
///    runner it changes nothing.
/// 8. `column_classes`: the length checks of the column classes of
///    Daniel's Q-A answer (2026-11-07, design section 4.5, R-NF-08).
/// 9. `api`: the pending actions and their confirmations, and the sealed
///    workspaces of the API core (ADR-026, lane L1).
///
/// Lane L3 `prod/keystore-pg` (ADR-004, decided by Daniel on 2026-11-20):
///
/// - `keystore`: the keystore tables of the App chain, file
///   `0011_keystore.sql` as the production design fixes it. Its version
///   follows the last migration on the branch it lands on, since a set
///   has no gap: 9 on this lane alone, 10 after lane L1, 11 after L2.
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
    Migration::new(5, "doc", include_str!("../migrations/app/0005_doc.sql")),
    Migration::new(
        6,
        "delivery",
        include_str!("../migrations/app/0006_delivery.sql"),
    ),
    Migration::new(
        7,
        "migration_ledger",
        include_str!("../migrations/app/0007_migration_ledger.sql"),
    ),
    Migration::new(
        8,
        "column_classes",
        include_str!("../migrations/app/0008_column_classes.sql"),
    ),
    // Lane L1 (ADR-026): pending actions and workspaces.
    Migration::new(9, "api", include_str!("../migrations/app/0009_api.sql")),
    // Lane L3: see the list above for its version.
    Migration::new(
        10,
        "keystore",
        include_str!("../migrations/app/0011_keystore.sql"),
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

#[cfg(test)]
mod m4_tests {
    use super::*;

    /// The statements of `sql` with comments removed, upper case.
    fn statements(sql: &str) -> String {
        sql.lines()
            .map(|l| l.split("--").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
            .to_ascii_uppercase()
    }

    /// M4 design section 9, ADR-026: migration 9 is forward only. It
    /// creates the `api` and `workspace` schemas and changes nothing that
    /// an earlier migration created: no DROP, no ALTER, no UPDATE, no
    /// DELETE and no TRUNCATE. It follows migration 8 with no gap.
    #[test]
    fn t_db_m4_migrations_forward_only() {
        let api = MIGRATIONS.iter().find(|m| m.name == "api");
        let Some(api) = api else {
            panic!("ADR-026: migration api is missing");
        };
        assert_eq!(api.version, 9, "ADR-026: the api migration is number 9");
        let versions: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
        let last = u32::try_from(MIGRATIONS.len()).unwrap_or(0);
        let want: Vec<u32> = (1..=last).collect();
        assert_eq!(versions, want, "design section 4.6: no gap");
        let body = statements(api.sql);
        for word in [
            "DROP ",
            "ALTER ",
            "UPDATE ",
            "DELETE ",
            "TRUNCATE ",
            "GRANT ",
            "REVOKE ",
        ] {
            // `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE` name trigger
            // events, not statements.
            let hits = body
                .match_indices(word)
                .filter(|(i, _)| {
                    let before = body.get(..*i).unwrap_or("");
                    let word_start = !before
                        .chars()
                        .last()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                    word_start && !(before.ends_with("BEFORE ") || before.ends_with("OR "))
                })
                .count();
            assert_eq!(hits, 0, "M4 design section 9: migration 9 runs {word}");
        }
        for created in [
            "CREATE SCHEMA API;",
            "CREATE TABLE API.PENDING_ACTIONS",
            "CREATE TABLE API.PENDING_CONFIRMED",
            "CREATE SCHEMA WORKSPACE;",
            "CREATE TABLE WORKSPACE.DRAFTS",
        ] {
            assert!(body.contains(created), "ADR-026: {created}");
        }
        // Every table it creates is new: no earlier migration names it.
        for m in MIGRATIONS.iter().filter(|m| m.version < 9) {
            let earlier = statements(m.sql);
            for t in ["API.", "WORKSPACE."] {
                assert!(!earlier.contains(t), "{} names {t}", m.name);
            }
        }
    }

    /// I-85, ADR-007: a confirmation row is insert-only. Its table refuses
    /// UPDATE, DELETE and TRUNCATE through the shared trigger function.
    #[test]
    fn i85_pending_confirmed_is_insert_only() {
        let api = MIGRATIONS.iter().find(|m| m.name == "api");
        let body = statements(api.map_or("", |m| m.sql));
        assert!(body.contains(
            "BEFORE UPDATE OR DELETE ON API.PENDING_CONFIRMED\n  FOR EACH ROW EXECUTE FUNCTION FSTP_META.REFUSE_MUTATION()"
        ));
        assert!(body.contains(
            "BEFORE TRUNCATE ON API.PENDING_CONFIRMED\n  FOR EACH STATEMENT EXECUTE FUNCTION FSTP_META.REFUSE_MUTATION()"
        ));
        assert!(body.contains("ID         BYTEA  PRIMARY KEY REFERENCES API.PENDING_ACTIONS"));
    }
}
