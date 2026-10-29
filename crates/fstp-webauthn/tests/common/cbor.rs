//! An independent CBOR writer (RFC 8949) for the test inputs.
//!
//! It writes only. [`encode`] writes the one spelling that ADR-008 admits:
//! definite lengths and the shortest head for every argument. The other
//! writers produce the spellings ADR-008 refuses, so a test can name the
//! exact bytes a strict decoder must refuse.

use fstp_webauthn::cbor::Item;

/// The major types of RFC 8949 section 3.1.
pub(crate) const UNSIGNED: u8 = 0;
pub(crate) const NEGATIVE: u8 = 1;
pub(crate) const BYTES: u8 = 2;
pub(crate) const TEXT: u8 = 3;
pub(crate) const ARRAY: u8 = 4;
pub(crate) const MAP: u8 = 5;
pub(crate) const TAG: u8 = 6;
pub(crate) const SIMPLE: u8 = 7;

/// The width of a head's argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Width {
    /// In the initial byte (values 0 to 23).
    Immediate,
    /// One following byte (additional information 24).
    One,
    /// Two following bytes (25).
    Two,
    /// Four following bytes (26).
    Four,
    /// Eight following bytes (27).
    Eight,
}

impl Width {
    /// The shortest width for `v`.
    pub(crate) fn shortest(v: u64) -> Width {
        if v < 24 {
            Width::Immediate
        } else if v <= u64::from(u8::MAX) {
            Width::One
        } else if v <= u64::from(u16::MAX) {
            Width::Two
        } else if v <= u64::from(u32::MAX) {
            Width::Four
        } else {
            Width::Eight
        }
    }

    /// The next wider form, or `None` for [`Width::Eight`].
    pub(crate) fn wider(self) -> Option<Width> {
        match self {
            Width::Immediate => Some(Width::One),
            Width::One => Some(Width::Two),
            Width::Two => Some(Width::Four),
            Width::Four => Some(Width::Eight),
            Width::Eight => None,
        }
    }
}

/// A head of major type `major` with argument `v`, written at `width`.
/// The caller makes sure `v` fits.
pub(crate) fn head_at(out: &mut Vec<u8>, major: u8, v: u64, width: Width) {
    let m = major << 5;
    match width {
        Width::Immediate => out.push(m | v as u8),
        Width::One => {
            out.push(m | 24);
            out.push(v as u8);
        }
        Width::Two => {
            out.push(m | 25);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        Width::Four => {
            out.push(m | 26);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        Width::Eight => {
            out.push(m | 27);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

/// A head in shortest form.
pub(crate) fn head(out: &mut Vec<u8>, major: u8, v: u64) {
    head_at(out, major, v, Width::shortest(v));
}

/// An integer, unsigned or negative.
pub(crate) fn int(v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    if v >= 0 {
        head(&mut out, UNSIGNED, v as u64);
    } else {
        head(&mut out, NEGATIVE, (-1 - v) as u64);
    }
    out
}

/// A byte string.
pub(crate) fn bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, BYTES, b.len() as u64);
    out.extend_from_slice(b);
    out
}

/// A text string.
pub(crate) fn text(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, TEXT, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

/// An array of already encoded items.
pub(crate) fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, ARRAY, items.len() as u64);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// A map of already encoded keys and values, in the given order.
pub(crate) fn map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, MAP, pairs.len() as u64);
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

/// The shortest definite encoding of `item`.
pub(crate) fn encode(item: &Item) -> Vec<u8> {
    let mut out = Vec::new();
    let mut heads = 0usize;
    write(&mut out, item, None, &mut heads);
    out
}

/// The encoding of `item` with its `k`-th head (in write order, from 0)
/// one width wider than the shortest form. `None` when that head already
/// uses eight bytes, or when `item` has fewer than `k + 1` heads.
pub(crate) fn encode_widened(item: &Item, k: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut heads = 0usize;
    let widened = write(&mut out, item, Some(k), &mut heads);
    widened.then_some(out)
}

/// The number of heads `encode(item)` writes.
pub(crate) fn head_count(item: &Item) -> usize {
    match item {
        Item::Array(items) => 1 + items.iter().map(head_count).sum::<usize>(),
        Item::Map(pairs) => {
            1 + pairs
                .iter()
                .map(|(k, v)| head_count(k) + head_count(v))
                .sum::<usize>()
        }
        _ => 1,
    }
}

/// The container depth of `item`: a scalar is 0, an array or map is one
/// more than its deepest member.
pub(crate) fn depth(item: &Item) -> usize {
    match item {
        Item::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Item::Map(pairs) => {
            1 + pairs
                .iter()
                .map(|(k, v)| depth(k).max(depth(v)))
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

fn write_head(
    out: &mut Vec<u8>,
    major: u8,
    v: u64,
    widen: Option<usize>,
    heads: &mut usize,
) -> bool {
    let shortest = Width::shortest(v);
    let mut widened = false;
    let width = if widen == Some(*heads) {
        match shortest.wider() {
            Some(w) => {
                widened = true;
                w
            }
            None => shortest,
        }
    } else {
        shortest
    };
    *heads += 1;
    head_at(out, major, v, width);
    widened
}

fn write(out: &mut Vec<u8>, item: &Item, widen: Option<usize>, heads: &mut usize) -> bool {
    match item {
        Item::Unsigned(v) => write_head(out, UNSIGNED, *v, widen, heads),
        Item::Negative(n) => write_head(out, NEGATIVE, *n, widen, heads),
        Item::Bytes(b) => {
            let w = write_head(out, BYTES, b.len() as u64, widen, heads);
            out.extend_from_slice(b);
            w
        }
        Item::Text(s) => {
            let w = write_head(out, TEXT, s.len() as u64, widen, heads);
            out.extend_from_slice(s.as_bytes());
            w
        }
        Item::Array(items) => {
            let mut w = write_head(out, ARRAY, items.len() as u64, widen, heads);
            for i in items {
                w |= write(out, i, widen, heads);
            }
            w
        }
        Item::Map(pairs) => {
            let mut w = write_head(out, MAP, pairs.len() as u64, widen, heads);
            for (k, v) in pairs {
                w |= write(out, k, widen, heads);
                w |= write(out, v, widen, heads);
            }
            w
        }
    }
}

/// `n` arrays nested in each other, the innermost one empty. Depth `n`.
pub(crate) fn nested_arrays(n: usize) -> Vec<u8> {
    let mut out = vec![0x81; n.saturating_sub(1)];
    if n > 0 {
        out.push(0x80);
    }
    out
}

/// `n` maps nested in each other under the key 0, the innermost one
/// empty. Depth `n`.
pub(crate) fn nested_maps(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 1..n {
        out.extend_from_slice(&[0xa1, 0x00]);
    }
    if n > 0 {
        out.push(0xa0);
    }
    out
}
