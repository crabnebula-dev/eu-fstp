//! The closed field types of the protocol (design section 9.1).
//!
//! `CertDer`, `ScramVerifier`, `PopSig` and `CompositeSig` are closed
//! grammars, checked on decode. Their bytes are private, so code cannot
//! build one from arbitrary input without passing the grammar check. The
//! grammars live in [`crate::grammar`]. Each `empty()` placeholder fails
//! its own check, so no decoded message and no encoded frame holds one.

use crate::ProtoError;
use crate::grammar;

/// A cell identifier, 16 random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(pub [u8; 16]);

/// A product version, `major.minor.patch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProductVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl ProductVersion {
    /// The version `major.minor.patch`.
    pub const fn new(major: u16, minor: u16, patch: u16) -> ProductVersion {
        ProductVersion {
            major,
            minor,
            patch,
        }
    }

    /// The three components.
    pub fn parts(&self) -> (u16, u16, u16) {
        (self.major, self.minor, self.patch)
    }
}

/// A database role of a cell. Closed. The variants are the role suffixes
/// of design section 4.1, which the `fstp_meta.apply_grant` grammar
/// [`ROLE_SUFFIX_GRAMMAR`] also names. The database prefix (`c_` or `v_`)
/// comes from the database, not from the role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleName {
    /// `<db>_migrator`: owns every schema. Its certificate is issued only
    /// for a deploy window.
    Migrator,
    /// `c_<cell>_writer`: INSERT and SELECT only on the append-only tables.
    Writer,
    /// `c_<cell>_app`: the application role.
    App,
    /// `<db>_keys`: full rights on the keystore only.
    Keys,
    /// `c_<cell>_auditor`: SELECT on the audit tables and stored ledger
    /// rows only.
    Auditor,
    /// `v_<cell>_vault`: the vault service role.
    Vault,
}

/// The suffix grammar of `fstp_meta.apply_grant`, verbatim from design
/// section 4.1. Lane W2e writes `fstp_migrate::catalogue::APPLY_GRANT_SQL`
/// with this text, and a test then ties the two.
pub const ROLE_SUFFIX_GRAMMAR: &str = "^(migrator|writer|app|keys|auditor|vault)$";

impl RoleName {
    /// Every role, in the order of [`ROLE_SUFFIX_GRAMMAR`].
    pub const ALL: [RoleName; 6] = [
        RoleName::Migrator,
        RoleName::Writer,
        RoleName::App,
        RoleName::Keys,
        RoleName::Auditor,
        RoleName::Vault,
    ];

    /// The role name suffix, as `apply_grant` takes it.
    pub const fn suffix(self) -> &'static str {
        match self {
            RoleName::Migrator => "migrator",
            RoleName::Writer => "writer",
            RoleName::App => "app",
            RoleName::Keys => "keys",
            RoleName::Auditor => "auditor",
            RoleName::Vault => "vault",
        }
    }
}

/// A SHA-256 digest of a subject public key info.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpkiDigest(pub [u8; 32]);

/// A proof-of-possession signature, a closed grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopSig(Vec<u8>);

impl PopSig {
    /// An empty signature, which no check accepts.
    pub fn empty() -> PopSig {
        PopSig(Vec::new())
    }

    /// Checks the grammar: an ASN.1 DER `ECDSA-Sig-Value` for P-256, with
    /// `r` and `s` in 1 to n - 1, as the fstp-pki `pop` module signs.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Grammar`] for any other bytes.
    pub fn parse(bytes: &[u8]) -> Result<PopSig, ProtoError> {
        grammar::pop_signature(bytes)?;
        Ok(PopSig(bytes.to_vec()))
    }

    /// The signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A SCRAM-SHA-256 verifier, a closed grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScramVerifier(Vec<u8>);

impl ScramVerifier {
    /// An empty verifier, which no check accepts.
    pub fn empty() -> ScramVerifier {
        ScramVerifier(Vec::new())
    }

    /// Checks the grammar of ADR-011: `SCRAM-SHA-256$<iterations>:<salt>$
    /// <StoredKey>:<ServerKey>`. The iterations are decimal without a
    /// leading zero, from [`crate::grammar::MIN_SCRAM_ITERATIONS`]. The
    /// other fields are canonical padded base64: a salt of 16 to 64 bytes
    /// and two 32-byte keys. No quote or backslash can occur, so the
    /// verifier renders safely as a literal in `ALTER ROLE ... PASSWORD`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Grammar`] for any other bytes.
    pub fn parse(bytes: &[u8]) -> Result<ScramVerifier, ProtoError> {
        grammar::scram_verifier(bytes)?;
        Ok(ScramVerifier(bytes.to_vec()))
    }

    /// The verifier as text. The grammar admits ASCII only.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// The verifier bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A component of a cell. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    /// The cell.
    Cell,
    /// The vault.
    Vault,
    /// The backup agent.
    Backup,
}

/// A metering counter. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CounterKind {
    /// Active accounts.
    ActiveAccounts,
    /// Proposals.
    Proposals,
    /// Stored bytes.
    StoredBytes,
}

/// A DER certificate, a closed grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertDer(Vec<u8>);

impl CertDer {
    /// An empty certificate, which no check accepts.
    pub fn empty() -> CertDer {
        CertDer(Vec::new())
    }

    /// Checks the grammar: a DER `Certificate` of at most
    /// [`crate::grammar::MAX_CERT_LEN`] bytes, a SEQUENCE of exactly a
    /// SEQUENCE, a SEQUENCE and a BIT STRING, every value well formed and
    /// every length in its shortest form, nothing after it.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Grammar`] for any other bytes.
    pub fn parse(bytes: &[u8]) -> Result<CertDer, ProtoError> {
        grammar::certificate(bytes)?;
        Ok(CertDer(bytes.to_vec()))
    }

    /// The DER bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The cell's opaque case reference, never an account id (I-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaseRef(pub [u8; 16]);

/// An operator ticket kind. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TicketKind {
    /// A recovery of a sole tenant admin.
    Recovery,
    /// Break-glass access.
    BreakGlass,
}

/// A composite signature, a closed grammar (design section 7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositeSig(Vec<u8>);

impl CompositeSig {
    /// An empty signature, which no check accepts.
    pub fn empty() -> CompositeSig {
        CompositeSig(Vec::new())
    }

    /// Checks the layout of ADR-010: `mldsaSig || tradSig`, exactly
    /// [`crate::grammar::COMPOSITE_SIG_LEN`] bytes. Whether the signature
    /// verifies is the verifier's question, not the grammar's.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Grammar`] for any other length.
    pub fn parse(bytes: &[u8]) -> Result<CompositeSig, ProtoError> {
        grammar::composite_signature(bytes)?;
        Ok(CompositeSig(bytes.to_vec()))
    }

    /// The signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A staff member, by random id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StaffRef(pub [u8; 16]);

/// The scope of a break-glass request. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BreakGlassScope {
    /// Read content.
    ReadContent,
    /// Read the audit log.
    ReadAudit,
}

/// Why a cell is degraded. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DegradedReason {
    /// The database is unreachable or slow.
    Database,
    /// The vault is unreachable.
    Vault,
    /// The witness is unreachable.
    Witness,
    /// Custody is unreachable.
    Custody,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-82, design section 4.1: [`RoleName`] names exactly the role
    /// suffixes of the `apply_grant` grammar, in its order. The exhaustive
    /// match in [`RoleName::suffix`] breaks the build when a variant is
    /// added, and this test then fails until the grammar names it too.
    #[test]
    fn i82_role_names_match_the_apply_grant_suffix_grammar() {
        let suffixes: Vec<&str> = RoleName::ALL.iter().map(|r| r.suffix()).collect();
        let grammar = format!("^({})$", suffixes.join("|"));
        assert_eq!(grammar, ROLE_SUFFIX_GRAMMAR);
    }
}
