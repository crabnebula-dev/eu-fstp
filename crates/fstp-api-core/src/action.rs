//! The action digest (design section 3.7) and the hexadecimal helpers.
//!
//! The digest is the SHA-256 of the RFC 8785 text of
//! `{"account", "op", "request", "target", "tenant"}`, through
//! `fstp-crypto`. A step-up proof and a pending action are bound to it, so
//! a confirmation can only execute the request the user was shown.
//!
//! Interim, pending the lead: no port names the tenant yet, so `tenant`
//! is the value of the dispatch seams, `null` until the tenant settings
//! carry the tenant id.

use fstp_domain::id::AccountId;
use fstp_json::{Object, Value};

use crate::ActionDigest;

/// Lowercase hexadecimal text of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(c) = DIGITS.get(usize::from(n)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}

/// The value of one lowercase hexadecimal digit.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// `N` bytes from exactly `2 N` lowercase hexadecimal digits.
pub(crate) fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N.saturating_mul(2) {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return None;
        };
        *slot = nibble(*hi)?.wrapping_shl(4) | nibble(*lo)?;
    }
    Some(out)
}

/// The digest of one action: `op` with its canonical `request`, `target`
/// and the acting `account`, in the cell of `tenant`. `None` when the
/// object has no canonical form, which a decoded request always has.
pub(crate) fn digest(
    op: &str,
    request: &Object,
    target: &Object,
    tenant: Option<u128>,
    account: Option<AccountId>,
) -> Option<ActionDigest> {
    let mut o = Object::new();
    let _ = o.insert("op", Value::from(op));
    let _ = o.insert("request", Value::Object(request.clone()));
    let _ = o.insert("target", Value::Object(target.clone()));
    let _ = o.insert(
        "tenant",
        tenant.map_or(Value::Null, |t| Value::String(t.to_string())),
    );
    let _ = o.insert(
        "account",
        account.map_or(Value::Null, |a| Value::String(a.raw().to_string())),
    );
    let text = fstp_json::to_canonical(&Value::Object(o)).ok()?;
    Some(ActionDigest(fstp_crypto::sha256(text.as_bytes())))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// I-85: the hexadecimal form round-trips and refuses uppercase and
    /// the wrong length.
    #[test]
    fn i85_digest_hex_round_trips_and_is_strict() {
        let d = ActionDigest([0xab; 32]);
        assert_eq!(ActionDigest::from_hex(&d.hex()), Some(d));
        assert_eq!(ActionDigest::from_hex(&d.hex().to_uppercase()), None);
        assert_eq!(ActionDigest::from_hex("ab"), None);
    }

    /// I-85, design section 3.7: the digest binds the operation, the
    /// request, the target, the tenant and the account. Changing any one
    /// changes it.
    #[test]
    fn i85_digest_binds_every_part() {
        let mut req = Object::new();
        let _ = req.insert("call", Value::from("1"));
        let target = req.clone();
        let a = Some(AccountId::from_raw(7));
        let base = digest("call.publish", &req, &target, None, a).unwrap();
        assert_ne!(
            base,
            digest("call.edit", &req, &target, None, a).unwrap(),
            "op"
        );
        let mut other = req.clone();
        let _ = other.insert("call", Value::from("2"));
        assert_ne!(
            base,
            digest("call.publish", &other, &target, None, a).unwrap()
        );
        assert_ne!(base, digest("call.publish", &req, &other, None, a).unwrap());
        assert_ne!(
            base,
            digest("call.publish", &req, &target, Some(1), a).unwrap()
        );
        assert_ne!(
            base,
            digest(
                "call.publish",
                &req,
                &target,
                None,
                Some(AccountId::from_raw(8))
            )
            .unwrap()
        );
    }
}
