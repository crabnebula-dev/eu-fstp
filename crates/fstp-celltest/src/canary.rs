//! Canaries `CNRY-<cell>-<kind>-<32 hex>` (design section 14.1). Lane W1a.

use crate::NotImplemented;

/// What a canary stands in for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanaryKind {
    /// A name.
    Name,
    /// An email address.
    Email,
    /// A phone number.
    Phone,
    /// A country.
    Country,
    /// A document byte pattern.
    Document,
    /// An IP address.
    IpAddress,
    /// Proposal text.
    ProposalText,
    /// A root key.
    RootKey,
    /// A text salt.
    TextSalt,
    /// An account id.
    AccountId,
}

/// One synthetic personal value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canary {
    /// The cell index.
    pub cell: u8,
    /// The kind.
    pub kind: CanaryKind,
    /// The 16 random bytes behind the hex part.
    pub nonce: [u8; 16],
}

impl Canary {
    /// The canary's text.
    pub fn render(&self) -> Result<String, NotImplemented> {
        Err(NotImplemented::new("fstp_celltest::canary::Canary::render"))
    }
}
