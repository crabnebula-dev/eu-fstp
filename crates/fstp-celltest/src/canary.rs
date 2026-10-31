//! Canaries `CNRY-<cell>-<kind>-<32 hex>` (design section 14.1). Lane W1a.
//!
//! Every synthetic personal value a harness test writes is a canary. The
//! text names the cell in decimal, the kind by a short lowercase label and
//! the 16-byte nonce in lowercase hex. The text alone determines the
//! canary, so a scanner hit names one cell and one kind. Canary text uses
//! only ASCII letters, digits and dashes, so each encoding of section 14.1
//! has exactly one spelling of it.

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

/// The fixed first part of every canary text.
pub const PREFIX: &str = "CNRY-";

/// The number of nonce bytes behind the hex part.
pub const NONCE_LEN: usize = 16;

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
    /// The canary's text, `CNRY-<cell>-<kind>-<32 hex>`.
    ///
    /// # Errors
    ///
    /// Never fails. The `Result` keeps the W0 signature, which later lanes
    /// already call.
    pub fn render(&self) -> Result<String, NotImplemented> {
        Ok(self.text())
    }

    /// The canary's text, as [`Canary::render`] gives it.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(64);
        out.push_str(PREFIX);
        out.push_str(&self.cell.to_string());
        out.push('-');
        out.push_str(self.kind.label());
        out.push('-');
        out.push_str(&lower_hex(&self.nonce));
        out
    }

    /// The canary as an email address, `<text>@example.test`, for a field
    /// that only takes an address. The local part is the canary text, so
    /// [`crate::scan::scan`] finds the address, also after a component
    /// lowercases it. `example.test` is a reserved name (RFC 2606), so no
    /// mail can reach a real host.
    #[must_use]
    pub fn email_address(&self) -> String {
        format!("{}@example.test", self.text())
    }

    /// The canary's hex part as 32 ASCII bytes. Key-shaped canaries, such
    /// as [`CanaryKind::RootKey`] and [`CanaryKind::TextSalt`], use these
    /// bytes as the 32-byte secret, so a scan can look for the secret
    /// itself (the custody simulator does this).
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let hex = lower_hex(&self.nonce);
        for (dst, src) in out.iter_mut().zip(hex.bytes()) {
            *dst = src;
        }
        out
    }

    /// Reads a canary back from its text. Returns `None` for any text that
    /// [`Canary::render`] does not produce.
    #[must_use]
    pub fn parse(text: &str) -> Option<Canary> {
        let rest = text.strip_prefix(PREFIX)?;
        let mut parts = rest.split('-');
        let cell_text = parts.next()?;
        let label = parts.next()?;
        let hex = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let cell = parse_decimal_u8(cell_text)?;
        let kind = CanaryKind::ALL.into_iter().find(|k| k.label() == label)?;
        let nonce = parse_lower_hex_16(hex)?;
        Some(Canary { cell, kind, nonce })
    }
}

impl CanaryKind {
    /// Every kind, in declaration order (design section 14.1).
    pub const ALL: [CanaryKind; 10] = [
        CanaryKind::Name,
        CanaryKind::Email,
        CanaryKind::Phone,
        CanaryKind::Country,
        CanaryKind::Document,
        CanaryKind::IpAddress,
        CanaryKind::ProposalText,
        CanaryKind::RootKey,
        CanaryKind::TextSalt,
        CanaryKind::AccountId,
    ];

    /// The kind's label in canary text: lowercase ASCII, no dash.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CanaryKind::Name => "name",
            CanaryKind::Email => "email",
            CanaryKind::Phone => "phone",
            CanaryKind::Country => "country",
            CanaryKind::Document => "document",
            CanaryKind::IpAddress => "ip",
            CanaryKind::ProposalText => "proposal",
            CanaryKind::RootKey => "rootkey",
            CanaryKind::TextSalt => "textsalt",
            CanaryKind::AccountId => "account",
        }
    }
}

impl Canary {
    /// A new canary of `kind` for cell `cell`, with 16 fresh random bytes
    /// from the operating system.
    ///
    /// # Errors
    ///
    /// Refuses when the random source fails, or when it returns all zero
    /// bytes, which a fresh nonce never is.
    pub fn generate(cell: u8, kind: CanaryKind) -> Result<Canary, NotImplemented> {
        let mut nonce = [0u8; NONCE_LEN];
        fstp_crypto::random_bytes(&mut nonce)
            .map_err(|_| NotImplemented::new("fstp_celltest::canary: random source failed"))?;
        if nonce == [0u8; NONCE_LEN] {
            return Err(NotImplemented::new(
                "fstp_celltest::canary: random source returned zeros",
            ));
        }
        Ok(Canary { cell, kind, nonce })
    }
}

/// One fresh canary of every kind for cell `cell`, in the order of
/// [`CanaryKind::ALL`].
///
/// # Errors
///
/// Refuses as [`Canary::generate`] does, or when two nonces collide.
pub fn generate_set(cell: u8) -> Result<Vec<Canary>, NotImplemented> {
    let mut out: Vec<Canary> = Vec::with_capacity(CanaryKind::ALL.len());
    for kind in CanaryKind::ALL {
        let c = Canary::generate(cell, kind)?;
        if out.iter().any(|o| o.nonce == c.nonce) {
            return Err(NotImplemented::new(
                "fstp_celltest::canary: two nonces collided",
            ));
        }
        out.push(c);
    }
    Ok(out)
}

/// Lowercase hex of `bytes`.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b.wrapping_shr(4), b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*d));
            }
        }
    }
    out
}

/// A decimal `u8` without sign, leading zeros or other characters.
fn parse_decimal_u8(text: &str) -> Option<u8> {
    if text.is_empty() || text.len() > 3 || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u8>().ok()
}

/// Exactly 32 lowercase hex digits.
pub(crate) fn parse_lower_hex_16(text: &str) -> Option<[u8; NONCE_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let digit = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
            b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
            _ => None,
        }
    };
    let mut out = [0u8; NONCE_LEN];
    for (dst, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return None;
        };
        *dst = digit(*hi)?.wrapping_shl(4) | digit(*lo)?;
    }
    Some(out)
}
