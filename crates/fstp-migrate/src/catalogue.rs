//! The schema catalogue types and the shared grant function (M3 design
//! sections 4.1 and 4.5, R-NF-08, I-16, I-19, I-82).
//!
//! Each migration set's owner lists its own tables next to its migrations:
//! `fstp_pgstore::CATALOGUE` (app), `fstp_vault::CATALOGUE`,
//! `fstp_control::CATALOGUE` (cp), `fstp_witness::CATALOGUE` and
//! `fstp_release_svc::CATALOGUE` (licence). A test in `fstp-celltest` takes
//! their union, so no lane edits another lane's list.
//!
//! [`APPLY_GRANT_SQL`] is the one text that defines
//! `fstp_meta.apply_grant` in every cell migration set (design section
//! 4.1). [`APPLY_GRANT_REVOKE_SQL`] follows it in the same migration, so
//! only the migrator may call it. `fstp-pgagent` calls it once per grant
//! row of `fstp_control::pg::cell_role_plan`, after the migrations.
//!
//! [`TableClass`] is closed. It has no class for a balance or a held amount
//! (I-16). A column whose class the design has not settled carries `None`
//! in [`ColumnSpec::class`]. The R-NF-08 catalogue test must refuse such a
//! column until the class is decided.

/// The SQL that defines `fstp_meta.apply_grant(privs, object, suffix)`:
/// one `CREATE FUNCTION` statement, shared by the application and vault
/// migration sets (design section 4.1, ADR-011).
///
/// It checks every argument against the closed grammars of design
/// section 4.1 before it runs anything. The role grammar is
/// `fstp_cp_proto::ROLE_SUFFIX_GRAMMAR`. Every dynamic statement is built
/// by `format` with `%I` for identifiers. The function runs with its
/// caller's rights, never as `SECURITY DEFINER` (design section 4.6).
///
/// Three checks go beyond the design text, each a stricter reading:
///
/// - The `fstp.cell` setting must name the database's own cell, so a
///   grant never reaches a role of another cell (I-82).
/// - The object's schema must be owned by the calling role, so the
///   function never grants on a catalog or a foreign schema.
/// - It also grants USAGE on the object's schema. A table privilege
///   cannot be used without it, and the grammar has no schema grant. So a
///   role holds USAGE exactly where it holds a table privilege. This
///   reading is interim, pending Daniel, since the design leaves it open.
///
/// A NULL argument is refused like one outside its grammar.
pub const APPLY_GRANT_SQL: &str = r"CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  cell text := current_setting('fstp.cell');
  schema_part text;
  table_part text;
  grantee text;
BEGIN
  IF cell IS NULL OR cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF current_database() NOT IN ('c_' || cell, 'v_' || cell) THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs IS NULL OR privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF object IS NULL OR object !~ '^[a-z_]{1,30}\.[a-z_]{1,30}$' THEN RAISE EXCEPTION 'bad object'; END IF;
  IF suffix IS NULL OR suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  schema_part := split_part(object, '.', 1);
  table_part := split_part(object, '.', 2);
  IF NOT EXISTS (SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
                 WHERE n.nspname = schema_part AND r.rolname = current_user) THEN
    RAISE EXCEPTION 'bad object';
  END IF;
  grantee := left(current_database(), 1) || '_' || cell || '_' || suffix;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_part, grantee);
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, schema_part, table_part, grantee);
END $$;";

/// The statement that every cell migration set runs right after
/// [`APPLY_GRANT_SQL`], in the same migration: only the owner, the
/// migrator, may call `fstp_meta.apply_grant` (design section 4.1, I-82).
/// A migration runs in one transaction, so PUBLIC never holds EXECUTE on
/// the function outside it.
pub const APPLY_GRANT_REVOKE_SQL: &str =
    "REVOKE EXECUTE ON FUNCTION fstp_meta.apply_grant(text, text, text) FROM PUBLIC;";

/// What a table holds. Closed: there is no class for a balance or a held
/// amount (I-16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TableClass {
    /// Sealed ledger records (ADR-007).
    LedgerRecord,
    /// Audit chain rows, anchors and receipts (I-24).
    AuditEvent,
    /// Sealed content such as texts.
    SealedContent,
    /// Wrapped keys and key records.
    KeyMaterial,
    /// Operational records that carry no tenant content.
    Operational,
    /// Migration ledger rows.
    Migration,
    /// Placement of cells on clusters (I-83).
    Placement,
}

/// What a clear column may hold (R-NF-08, design section 4.5).
///
/// The last three classes hold public values only: link hashes,
/// composite signatures and public key material. None holds personal data
/// or content (Daniel, 2026-10-30, design section 21.0). Each such column
/// is checked by type and exact length, or by a bounded length where its
/// encoding allows no exact one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnClass {
    /// Ciphertext under a cell key.
    Sealed,
    /// A random identifier.
    RandomId,
    /// A sequence number.
    Sequence,
    /// A timestamp.
    Time,
    /// A value of a closed enum.
    Enum,
    /// A hash of a random secret.
    SecretDigest,
    /// An HMAC under a key that erasure rotates.
    KeyedDigest,
    /// A count.
    Count,
    /// A public digest: a SHA-256 link hash over a chain head, which
    /// commits to stored rows but discloses none, or another unkeyed
    /// SHA-256 such as a stored-row hash, an action digest or a migration
    /// checksum (Daniel, Q-A, 2026-11-07). A `bytea` of exactly 32 bytes.
    PublicDigest,
    /// A composite signature (ADR-010 "Composite encoding"). A `bytea` of
    /// exactly the composite signature length.
    Signature,
    /// Public key material: a pinned DER certificate or a composite public
    /// key. A `bytea` of exactly the composite public key length for a
    /// key, and of a bounded length for a certificate, whose DER encoding
    /// has no fixed length.
    PublicKeyMaterial,
    /// An infrastructure field of the ADR-009 register: a host name or a
    /// cluster endpoint of the platform's own infrastructure. Interim
    /// class of ADR-009 (Daniel, Q-A, 2026-11-07). A `text` column checked
    /// by a closed grammar.
    Infrastructure,
    /// An opaque reference: bytes the platform chooses to name a record
    /// outside the table, such as a custody handle, an accounting or case
    /// reference, or an idempotency key. It is never derived from content
    /// or personal data (Daniel, Q-A, 2026-11-07). A `bytea` of 1 to
    /// [`OPAQUE_REFERENCE_MAX_LEN`] bytes, checked by length.
    OpaqueReference,
}

/// The longest opaque reference, in bytes: the longest custody handle
/// (`fstp_custody::keyd::MAX_HANDLE_LEN`).
pub const OPAQUE_REFERENCE_MAX_LEN: usize = 64;

/// One column of a catalogued table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnSpec {
    /// The column name.
    pub name: &'static str,
    /// The column class, or `None` while the design has not settled it.
    pub class: Option<ColumnClass>,
}

/// One catalogued table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSpec {
    /// The schema name.
    pub schema: &'static str,
    /// The table name.
    pub name: &'static str,
    /// What the table holds.
    pub class: TableClass,
    /// Every column, in declaration order.
    pub columns: &'static [ColumnSpec],
}
