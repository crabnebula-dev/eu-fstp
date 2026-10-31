//! The vault's start checks over its database (design section 9.2,
//! I-83).
//!
//! At start, `fstp-vault` refuses a database whose
//! `fstp_meta.placement.kind` is not vault, whose server certificate OU
//! is not `vault`, or whose server SPKI is registered for any other
//! cluster kind. [`accepts_database`] is that rule over the three
//! readings, and [`placement_marker`] reads the first one from the
//! database. `fstp-cell` makes the mirror checks
//! (`fstp_cell::engine::startup::accepts_database`).
//!
//! The vault does not depend on `fstp-cell` (design section 2.4), so this
//! module has its own view types.

use fstp_pgwire::Client;
use fstp_rt::Runtime;

use crate::VaultError;

/// The placement marker of a vault database (design section 4.1). The
/// vault migration set's CHECK allows no other value.
pub const VAULT_MARKER: u8 = 2;

/// The kind of a database cluster, as the start check reads it from the
/// server certificate OU and the registered SPKI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClusterRole {
    /// An application cluster.
    Application,
    /// A vault cluster.
    Vault,
    /// Any other cluster, or an unknown kind.
    Other,
}

/// What the vault sees of its database at start (design section 9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseView {
    /// `fstp_meta.placement.kind`: 1 application, 2 vault.
    pub marker: u8,
    /// The kind named by the server certificate's subject OU.
    pub server_ou: ClusterRole,
    /// The kind the server SPKI is registered for at the control plane.
    pub registered_spki: ClusterRole,
}

/// The I-83 start check of design section 9.2: the vault accepts its
/// database only when the placement marker, the server certificate OU
/// and the registered SPKI all name a vault cluster. It refuses an
/// application cluster, and any mix.
#[must_use]
pub fn accepts_database(db: &DatabaseView) -> bool {
    db.marker == VAULT_MARKER
        && db.server_ou == ClusterRole::Vault
        && db.registered_spki == ClusterRole::Vault
}

/// Reads the placement marker `fstp_meta.placement.kind` of the
/// connected database.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the query fails, and
/// [`VaultError::Malformed`] when the table does not hold exactly one row
/// or its kind is outside `u8`. The start then refuses.
pub async fn placement_marker<R: Runtime>(client: &mut Client<R>) -> Result<u8, VaultError> {
    let rows = client
        .query("SELECT kind FROM fstp_meta.placement", &[])
        .await
        .map_err(|_| VaultError::Unavailable("the placement marker"))?;
    let bad = VaultError::Malformed("the placement marker");
    let [row] = rows.as_slice() else {
        return Err(bad);
    };
    let kind: i16 = row.get(0).map_err(|_| bad)?;
    u8::try_from(kind).map_err(|_| bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [ClusterRole; 3] = [
        ClusterRole::Application,
        ClusterRole::Vault,
        ClusterRole::Other,
    ];

    /// I-83, design section 9.2: the vault start check accepts exactly the
    /// one view where the marker, the OU and the SPKI all name a vault
    /// cluster, over every marker byte and every role pair.
    #[test]
    fn i83_vault_start_check_accepts_only_a_vault_cluster() {
        for marker in 0..=u8::MAX {
            for server_ou in ROLES {
                for registered_spki in ROLES {
                    let db = DatabaseView {
                        marker,
                        server_ou,
                        registered_spki,
                    };
                    let want = marker == 2
                        && server_ou == ClusterRole::Vault
                        && registered_spki == ClusterRole::Vault;
                    assert_eq!(accepts_database(&db), want, "{db:?}");
                }
            }
        }
    }
}
