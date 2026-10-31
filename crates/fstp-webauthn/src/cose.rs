//! COSE public keys of the algorithms ADR-008 admits (RFC 9052, RFC 9053,
//! RFC 8230).
//!
//! | Key | kty | alg | crv | Parameters |
//! | --- | --- | --- | --- | --- |
//! | ES256 | 2 (EC2) | -7 | 1 (P-256) | x and y, 32 bytes each, on the curve |
//! | EdDSA | 1 (OKP) | -8 | 6 (Ed25519) | x, 32 bytes |
//! | RS256 | 3 (RSA) | -257 | none | n of 2048 to 8192 bits, e |
//!
//! A key carries exactly the labels of its row. Any other label is
//! refused, including the private part `d` (-4) and `kid` (2). RSA
//! parameters use the minimum number of octets (RFC 8230 section 4).

use crate::cbor::{self, Item};
use crate::{CoseKey, WebAuthnError};

/// The COSE key type label.
const KTY: i128 = 1;
/// The COSE algorithm label.
const ALG: i128 = 3;
/// The first key type parameter: `crv` for EC2 and OKP, `n` for RSA.
const P1: i128 = -1;
/// The second key type parameter: `x` for EC2 and OKP, `e` for RSA.
const P2: i128 = -2;
/// The third key type parameter: `y` for EC2.
const P3: i128 = -3;

/// The OKP key type.
const KTY_OKP: i128 = 1;
/// The EC2 key type.
const KTY_EC2: i128 = 2;
/// The RSA key type.
const KTY_RSA: i128 = 3;
/// ES256.
const ALG_ES256: i128 = -7;
/// EdDSA.
const ALG_EDDSA: i128 = -8;
/// RS256.
const ALG_RS256: i128 = -257;
/// The P-256 curve.
const CRV_P256: i128 = 1;
/// The Ed25519 curve.
const CRV_ED25519: i128 = 6;

/// The smallest admitted RSA modulus, in bits (ADR-008).
const RSA_MIN_BITS: usize = 2048;
/// The largest RSA modulus `fstp_crypto::sig` verifies, in bytes.
const RSA_MAX_BYTES: usize = 1024;
/// The largest admitted RSA public exponent, in bytes.
const RSA_MAX_E_BYTES: usize = 4;

/// Parses a COSE key. Fuzzed (`cose_key_decode`).
pub(crate) fn parse(b: &[u8]) -> Result<CoseKey, WebAuthnError> {
    from_item(&cbor::decode(b)?)
}

/// The COSE key in a decoded CBOR item.
pub(crate) fn from_item(item: &Item) -> Result<CoseKey, WebAuthnError> {
    let Item::Map(pairs) = item else {
        return Err(WebAuthnError::CoseKey);
    };
    let mut labelled = Vec::new();
    for (k, v) in pairs {
        labelled.push((label(k)?, v));
    }
    let get = |l: i128| labelled.iter().find(|(k, _)| *k == l).map(|(_, v)| *v);
    let only = |allowed: &[i128]| {
        if labelled.iter().all(|(k, _)| allowed.contains(k)) {
            Ok(())
        } else {
            Err(WebAuthnError::CoseKey)
        }
    };
    let kty = int(get(KTY))?;
    let alg = int(get(ALG))?;
    match (kty, alg) {
        (KTY_EC2, ALG_ES256) => {
            only(&[KTY, ALG, P1, P2, P3])?;
            if int(get(P1))? != CRV_P256 {
                return Err(WebAuthnError::CoseKey);
            }
            let x = fixed::<32>(get(P2))?;
            let y = fixed::<32>(get(P3))?;
            fstp_crypto::sig::p256_point_check(&p256_point(&x, &y))
                .map_err(|_| WebAuthnError::CoseKey)?;
            Ok(CoseKey::Es256 { x, y })
        }
        (KTY_OKP, ALG_EDDSA) => {
            only(&[KTY, ALG, P1, P2])?;
            if int(get(P1))? != CRV_ED25519 {
                return Err(WebAuthnError::CoseKey);
            }
            Ok(CoseKey::Ed25519 {
                x: fixed::<32>(get(P2))?,
            })
        }
        (KTY_RSA, ALG_RS256) => {
            only(&[KTY, ALG, P1, P2])?;
            let n = bytes(get(P1))?;
            let e = bytes(get(P2))?;
            rsa_modulus(n)?;
            rsa_exponent(e)?;
            Ok(CoseKey::Rs256 {
                n: n.to_vec(),
                e: e.to_vec(),
            })
        }
        _ => Err(WebAuthnError::CoseKey),
    }
}

/// A COSE label, which WebAuthn keys write as integers.
fn label(item: &Item) -> Result<i128, WebAuthnError> {
    int(Some(item))
}

/// An integer parameter.
fn int(item: Option<&Item>) -> Result<i128, WebAuthnError> {
    match item {
        Some(Item::Unsigned(v)) => Ok(i128::from(*v)),
        Some(Item::Negative(n)) => (-1i128)
            .checked_sub(i128::from(*n))
            .ok_or(WebAuthnError::CoseKey),
        _ => Err(WebAuthnError::CoseKey),
    }
}

/// A byte string parameter.
fn bytes(item: Option<&Item>) -> Result<&[u8], WebAuthnError> {
    match item {
        Some(Item::Bytes(b)) => Ok(b),
        _ => Err(WebAuthnError::CoseKey),
    }
}

/// A byte string parameter of exactly `N` bytes.
fn fixed<const N: usize>(item: Option<&Item>) -> Result<[u8; N], WebAuthnError> {
    bytes(item)?.try_into().map_err(|_| WebAuthnError::CoseKey)
}

/// An RSA modulus: minimal octets, odd, and 2048 to 8192 bits.
fn rsa_modulus(n: &[u8]) -> Result<(), WebAuthnError> {
    let (Some(&first), Some(&last)) = (n.first(), n.last()) else {
        return Err(WebAuthnError::CoseKey);
    };
    if first == 0 || last & 1 == 0 || n.len() > RSA_MAX_BYTES {
        return Err(WebAuthnError::CoseKey);
    }
    // The bit length is 8 bits per octet less the leading zero bits.
    let leading = usize::try_from(first.leading_zeros()).map_err(|_| WebAuthnError::CoseKey)?;
    let bits = n
        .len()
        .checked_mul(8)
        .and_then(|b| b.checked_sub(leading))
        .ok_or(WebAuthnError::CoseKey)?;
    if bits < RSA_MIN_BITS {
        return Err(WebAuthnError::CoseKey);
    }
    Ok(())
}

/// An RSA public exponent: minimal octets, odd, at least 3, at most four
/// octets.
fn rsa_exponent(e: &[u8]) -> Result<(), WebAuthnError> {
    let (Some(&first), Some(&last)) = (e.first(), e.last()) else {
        return Err(WebAuthnError::CoseKey);
    };
    if first == 0 || last & 1 == 0 || e.len() > RSA_MAX_E_BYTES || e == [1] {
        return Err(WebAuthnError::CoseKey);
    }
    Ok(())
}

/// The uncompressed P-256 point `0x04 || x || y`.
pub(crate) fn p256_point(x: &[u8; 32], y: &[u8; 32]) -> [u8; fstp_crypto::sig::P256_POINT_LEN] {
    let mut point = [0x04u8; fstp_crypto::sig::P256_POINT_LEN];
    for (dst, src) in point.iter_mut().skip(1).zip(x.iter().chain(y.iter())) {
        *dst = *src;
    }
    point
}
