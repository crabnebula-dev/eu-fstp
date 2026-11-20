//! I-82, ADR-004 (decided by Daniel on 2026-11-20): the keystore of the
//! App chain is written through `c_<cell>_keys` only. Lane L3.
//!
//! Every table of migration `0011_keystore.sql` is in the role plan of the
//! application database, the keys role holds full rights on it, and no
//! other role holds any right on any `keystore` table.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_control::pg::{APP_TABLES, CellDatabase, Privilege, cell_role_plan};
use fstp_cp_proto::{CellId, RoleName};

/// The tables of migration `0011_keystore.sql`.
const KEYSTORE_0011: [&str; 6] = [
    "keystore.chain",
    "keystore.text",
    "keystore.signer",
    "keystore.login_digest",
    "keystore.login_text",
    "keystore.erasure_request",
];

/// I-82, ADR-004 (2026-11-20): only the keys role holds a right on a
/// keystore table of the application database, and it holds all four.
#[test]
fn i82_keystore_written_by_keys_role_only() {
    for t in KEYSTORE_0011 {
        assert!(APP_TABLES.contains(&t), "APP_TABLES lacks {t}");
    }
    let plan = cell_role_plan(CellId([0x5a; 16])).unwrap();
    let keystore = |o: &str| o.split_once('.').is_some_and(|(s, _)| s == "keystore");
    let tables: Vec<&str> = APP_TABLES.iter().copied().filter(|t| keystore(t)).collect();
    assert!(tables.len() >= 10, "{tables:?}");
    for t in tables {
        let rows: Vec<_> = plan
            .grants
            .iter()
            .filter(|g| g.database == CellDatabase::App && g.object == t)
            .collect();
        assert_eq!(rows.len(), 1, "I-82: {t}: {rows:?}");
        let row = rows.first().unwrap();
        assert_eq!(row.role, RoleName::Keys, "I-82: {t}");
        for p in [
            Privilege::Select,
            Privilege::Insert,
            Privilege::Update,
            Privilege::Delete,
        ] {
            assert!(row.privileges.contains(&p), "I-82: {t} lacks {p:?}");
        }
    }
}
