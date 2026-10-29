//! The strict CBOR subset: definite lengths, shortest forms, no duplicate
//! map keys, bounded depth and size (ADR-008 "WebAuthn subset").
//!
//! The decoder admits exactly the spellings that WebAuthn uses:
//!
//! - unsigned and negative integers, byte strings, UTF-8 text strings,
//!   arrays and maps;
//! - every head in its shortest form, and definite lengths only;
//! - no tags, no floats and no simple values (`false`, `true`, `null`);
//! - map keys that are integers or text, each at most once per map;
//! - container depth at most [`MAX_DEPTH`], where a scalar has depth 0;
//! - at most [`MAX_INPUT`] bytes.
//!
//! Map keys may come in any order, since ADR-008 fixes none. Every length
//! and count is checked against the bytes that remain before it is used,
//! so no claimed length drives an allocation. The recursion is bounded by
//! the depth limit, so no input can exhaust the stack.

use crate::WebAuthnError;

/// The input limit of ADR-008, 64 KiB.
pub const MAX_INPUT: usize = 64 * 1024;

/// The container depth limit of ADR-008. A scalar has depth 0, and an
/// array or map has one more than its deepest member.
pub const MAX_DEPTH: usize = 4;

/// A decoded CBOR item of the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// An unsigned integer.
    Unsigned(u64),
    /// A negative integer, as `-1 - n`.
    Negative(u64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string.
    Text(String),
    /// An array.
    Array(Vec<Item>),
    /// A map, in encoded order.
    Map(Vec<(Item, Item)>),
}

/// Why bytes are not one item of the strict CBOR subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    /// The input ends inside an item, or is empty.
    Truncated,
    /// Bytes follow the item.
    TrailingBytes,
    /// The input is longer than [`MAX_INPUT`].
    TooLarge,
    /// A container is deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A head is wider than its argument needs.
    NonShortest,
    /// An indefinite length, or a lone break.
    Indefinite,
    /// A reserved additional information value (28 to 30).
    Reserved,
    /// A tag (major type 6).
    Tag,
    /// A float or a simple value (major type 7).
    FloatOrSimple,
    /// A text string that is not well-formed UTF-8.
    InvalidUtf8,
    /// A map key that is neither an integer nor text.
    KeyType,
    /// A map key that occurs twice in one map.
    DuplicateKey,
}

/// Decodes exactly one item from `b`. Fuzzed (`cbor_decode`).
///
/// # Errors
///
/// [`WebAuthnError::Cbor`] when `b` is anything but one item of the
/// strict subset, including when bytes follow it.
pub fn decode(b: &[u8]) -> Result<Item, WebAuthnError> {
    if b.len() > MAX_INPUT {
        return Err(WebAuthnError::Cbor(CborError::TooLarge));
    }
    let (item, used) = decode_prefix(b)?;
    if used == b.len() {
        Ok(item)
    } else {
        Err(WebAuthnError::Cbor(CborError::TrailingBytes))
    }
}

/// Decodes one item from the front of `b`, and returns it with the number
/// of bytes it takes. The item itself is at most [`MAX_INPUT`] bytes.
///
/// Authenticator data uses this for the credential key and the
/// extensions, which carry no length of their own.
pub(crate) fn decode_prefix(b: &[u8]) -> Result<(Item, usize), WebAuthnError> {
    let bounded = b.get(..MAX_INPUT).unwrap_or(b);
    let mut r = Reader {
        input: bounded,
        pos: 0,
    };
    let item = r.item(0).map_err(WebAuthnError::Cbor)?;
    Ok((item, r.pos))
}

/// A cursor over the input.
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

/// The major types of RFC 8949 section 3.1.
const UNSIGNED: u8 = 0;
const NEGATIVE: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;
const TAG: u8 = 6;
/// The break stop code of RFC 8949 section 3.2.1.
const BREAK: u8 = 0xff;

impl<'a> Reader<'a> {
    /// The bytes not yet read.
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Reads `n` bytes.
    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        let out = self.input.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    /// Reads one byte.
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.input.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos = self.pos.checked_add(1).ok_or(CborError::Truncated)?;
        Ok(b)
    }

    /// Reads a big-endian argument of `N` bytes.
    fn be<const N: usize>(&mut self) -> Result<u64, CborError> {
        let bytes = self.take(N)?;
        let mut v = 0u64;
        for b in bytes {
            v = v.checked_shl(8).ok_or(CborError::Truncated)? | u64::from(*b);
        }
        Ok(v)
    }

    /// Reads a head and returns its major type and argument. Only the
    /// shortest definite form is admitted.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.byte()?;
        if initial == BREAK {
            return Err(CborError::Indefinite);
        }
        let major = initial >> 5;
        let ai = initial & 0x1f;
        if major == TAG {
            return Err(CborError::Tag);
        }
        if major > TAG {
            return Err(CborError::FloatOrSimple);
        }
        let v = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = self.be::<1>()?;
                if v < 24 {
                    return Err(CborError::NonShortest);
                }
                v
            }
            25 => {
                let v = self.be::<2>()?;
                if v <= u64::from(u8::MAX) {
                    return Err(CborError::NonShortest);
                }
                v
            }
            26 => {
                let v = self.be::<4>()?;
                if v <= u64::from(u16::MAX) {
                    return Err(CborError::NonShortest);
                }
                v
            }
            27 => {
                let v = self.be::<8>()?;
                if v <= u64::from(u32::MAX) {
                    return Err(CborError::NonShortest);
                }
                v
            }
            28..=30 => return Err(CborError::Reserved),
            _ => return Err(CborError::Indefinite),
        };
        Ok((major, v))
    }

    /// A length or count that must fit in the bytes that remain, since
    /// every byte, element or member takes at least one byte.
    fn bounded(&self, v: u64) -> Result<usize, CborError> {
        let n = usize::try_from(v).map_err(|_| CborError::Truncated)?;
        if n > self.remaining() {
            return Err(CborError::Truncated);
        }
        Ok(n)
    }

    /// Reads one item inside `level` enclosing containers.
    fn item(&mut self, level: usize) -> Result<Item, CborError> {
        let (major, v) = self.head()?;
        match major {
            UNSIGNED => Ok(Item::Unsigned(v)),
            NEGATIVE => Ok(Item::Negative(v)),
            BYTES => {
                let n = self.bounded(v)?;
                Ok(Item::Bytes(self.take(n)?.to_vec()))
            }
            TEXT => {
                let n = self.bounded(v)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Item::Text(s.to_owned()))
            }
            ARRAY => {
                let inner = Self::deeper(level)?;
                let n = self.bounded(v)?;
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.item(inner)?);
                }
                Ok(Item::Array(items))
            }
            MAP => {
                let inner = Self::deeper(level)?;
                let n = self.bounded(v)?;
                let mut pairs = Vec::new();
                let mut keys: Vec<&'a [u8]> = Vec::new();
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.item(inner)?;
                    if !matches!(k, Item::Unsigned(_) | Item::Negative(_) | Item::Text(_)) {
                        return Err(CborError::KeyType);
                    }
                    // Every head is in shortest form, so two keys are equal
                    // exactly when their encodings are.
                    keys.push(
                        self.input
                            .get(start..self.pos)
                            .ok_or(CborError::Truncated)?,
                    );
                    let val = self.item(inner)?;
                    pairs.push((k, val));
                }
                keys.sort_unstable();
                if keys.windows(2).any(|w| w.first() == w.get(1)) {
                    return Err(CborError::DuplicateKey);
                }
                Ok(Item::Map(pairs))
            }
            _ => Err(CborError::Tag),
        }
    }

    /// The level of the members of a container inside `level` containers.
    fn deeper(level: usize) -> Result<usize, CborError> {
        let inner = level.checked_add(1).ok_or(CborError::TooDeep)?;
        if inner > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        Ok(inner)
    }
}
