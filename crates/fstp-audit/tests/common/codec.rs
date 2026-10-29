//! Format-agnostic codec properties (TH-26, design section 15).
//!
//! The design fixes no wire layout for chain rows, anchors or receipts.
//! These properties hold for any one-spelling layout: a round trip, one
//! encoding per value, no accepted truncation and no accepted trailing
//! byte. Every refusal must be real (see `common::real_refusal`).

use fstp_audit::AuditError;
use fstp_prop::Gen;

use super::real_refusal;

/// An encoder and a decoder under test.
pub(crate) struct Codec<T> {
    /// What the codec decodes, for messages.
    pub(crate) what: &'static str,
    /// The encoder.
    pub(crate) encode: fn(&T) -> Result<Vec<u8>, AuditError>,
    /// The decoder.
    pub(crate) decode: fn(&[u8]) -> Result<T, AuditError>,
}

impl<T: Clone + PartialEq + std::fmt::Debug> Codec<T> {
    fn encoded(&self, x: &T) -> Result<Vec<u8>, String> {
        (self.encode)(x).map_err(|e| format!("{}: encode refused {x:?}: {e:?}", self.what))
    }

    /// `decode(encode(x)) == x`.
    pub(crate) fn round_trip(&self, x: &T) -> Result<(), String> {
        let bytes = self.encoded(x)?;
        match (self.decode)(&bytes) {
            Ok(y) if y == *x => Ok(()),
            other => Err(format!("{}: {x:?} decoded as {other:?}", self.what)),
        }
    }

    /// Every proper prefix of `encode(x)` is refused for real.
    pub(crate) fn refuses_prefixes(&self, x: &T) -> Result<(), String> {
        let bytes = self.encoded(x)?;
        for cut in 0..bytes.len() {
            real_refusal(
                &format!("{}: prefix of {cut} of {} bytes", self.what, bytes.len()),
                &(self.decode)(&bytes[..cut]),
            )?;
        }
        Ok(())
    }

    /// `encode(x)` followed by `extra` is refused for real.
    pub(crate) fn refuses_trailing(&self, x: &T, extra: &[u8]) -> Result<(), String> {
        let mut bytes = self.encoded(x)?;
        bytes.extend_from_slice(extra);
        real_refusal(
            &format!("{}: {} trailing bytes", self.what, extra.len()),
            &(self.decode)(&bytes),
        )
    }

    /// One spelling: `encode(x)` with one byte changed never decodes to
    /// `x`, and whatever it decodes to re-encodes to the changed bytes.
    /// A refusal must be real.
    pub(crate) fn one_spelling_under_change(&self, x: &T, g: &mut Gen) -> Result<(), String> {
        let mut bytes = self.encoded(x)?;
        if bytes.is_empty() {
            return Err(format!("{}: {x:?} encodes to nothing", self.what));
        }
        let i = g.usize_in(0..=bytes.len() - 1);
        bytes[i] ^= g.u8_in(1..=255);
        match (self.decode)(&bytes) {
            Ok(y) if y == *x => Err(format!(
                "{}: a changed byte {i} still decodes to {x:?}",
                self.what
            )),
            Ok(y) => {
                let again = self.encoded(&y)?;
                if again == bytes {
                    Ok(())
                } else {
                    Err(format!("{}: {y:?} has two spellings", self.what))
                }
            }
            Err(e) => real_refusal(self.what, &Err::<T, _>(e)),
        }
    }

    /// One spelling on arbitrary input: accepted bytes re-encode byte for
    /// byte, and a refusal is real.
    pub(crate) fn one_spelling_on(&self, bytes: &[u8]) -> Result<(), String> {
        match (self.decode)(bytes) {
            Ok(y) => {
                let again = self.encoded(&y)?;
                if again == bytes {
                    Ok(())
                } else {
                    Err(format!("{}: {y:?} has two spellings", self.what))
                }
            }
            Err(e) => real_refusal(self.what, &Err::<T, _>(e)),
        }
    }
}
