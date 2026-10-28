//! The reference proof-of-possession message.
//!
//! Design section 1.3 and ADR-005 say a component proves possession by
//! signing a fresh challenge, and design section 9.1 carries the SPKI as a
//! SHA-256 digest next to a role (`RoleCredential`) or a component
//! (`CertRenewal`). The tests fix the signed bytes here, independent of
//! `fstp-pki`:
//!
//! `"fstp-pki-pop-v1\0" || purpose || scope_id || len(name) || name ||
//! SHA-256(spki_der) || challenge`
//!
//! The prefix separates this signature from every other use of the key.
//! `purpose` is 1 for `RoleCredential` and 2 for `CertRenewal`. `scope_id`
//! is the 16-byte cell or cluster id. The name follows its one-byte
//! length, and every other part has a fixed length, so the layout has one
//! reading.

/// The domain separation prefix.
pub(crate) const POP_DOMAIN: &[u8; 16] = b"fstp-pki-pop-v1\0";

/// The purpose octet of a `RoleCredential` proof.
pub(crate) const PURPOSE_ROLE_CREDENTIAL: u8 = 1;

/// The purpose octet of a `CertRenewal` proof.
pub(crate) const PURPOSE_CERT_RENEWAL: u8 = 2;

/// The request context of a reference proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ctx {
    /// The purpose octet.
    pub(crate) purpose: u8,
    /// The cell or cluster id.
    pub(crate) scope_id: [u8; 16],
    /// The role or component name, 1 to 64 bytes.
    pub(crate) name: String,
}

impl Ctx {
    /// The context of a `RoleCredential` for `role` in the cell `scope_id`.
    pub(crate) fn role(scope_id: [u8; 16], role: &str) -> Ctx {
        Ctx {
            purpose: PURPOSE_ROLE_CREDENTIAL,
            scope_id,
            name: role.to_owned(),
        }
    }

    /// The same context as `fstp_pki::pop::PopContext`.
    pub(crate) fn to_pki(&self) -> fstp_pki::pop::PopContext {
        use fstp_pki::pop::{PopContext, PopPurpose};
        PopContext {
            purpose: if self.purpose == PURPOSE_CERT_RENEWAL {
                PopPurpose::CertRenewal
            } else {
                PopPurpose::RoleCredential
            },
            scope_id: self.scope_id,
            name: self.name.clone(),
        }
    }
}

/// The bytes the requester signs for `spki_der`, `ctx` and `challenge`.
pub(crate) fn pop_message(spki_der: &[u8], ctx: &Ctx, challenge: &[u8; 32]) -> Vec<u8> {
    let mut out = POP_DOMAIN.to_vec();
    out.push(ctx.purpose);
    out.extend_from_slice(&ctx.scope_id);
    out.push(ctx.name.len() as u8);
    out.extend_from_slice(ctx.name.as_bytes());
    out.extend_from_slice(&fstp_crypto::sha256(spki_der));
    out.extend_from_slice(challenge);
    out
}
