//! A strict RFC 1951 decoder and the RFC 1950 zlib wrapper (ADR-031
//! rows "Inflate" and "Inflate limits").
//!
//! Memory never exceeds the output cap the caller names: the output
//! vector is reserved exactly, never doubled past the cap. Time is linear
//! in the input and the output: every block reads input, and each table
//! it builds has a fixed size.

use std::fmt;

use crate::check::Adler;

/// Why a DEFLATE or zlib stream was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InflateError {
    /// The stream ends early.
    Truncated,
    /// Block type 3, which RFC 1951 reserves.
    BlockType,
    /// A stored block whose length and its complement disagree.
    StoredLength,
    /// A Huffman code description that is over-subscribed, incomplete,
    /// repeats with no previous length, runs past its count, has too many
    /// codes, or gives no code to the end of block.
    BadCode,
    /// A symbol no code may send: literal/length 286 or 287, distance 30
    /// or 31, or a bit pattern of an incomplete code.
    BadSymbol,
    /// A distance before the start of the output or beyond the window.
    Distance,
    /// The output would pass the cap.
    OutputLimit,
    /// A zlib header that is not DEFLATE with a window of at most 32 KiB,
    /// or whose check bits fail.
    Header,
    /// A zlib stream that asks for a preset dictionary.
    Dictionary,
    /// The Adler-32 of the output does not match.
    Checksum,
    /// Bytes follow the end of the stream.
    TrailingData,
}

impl InflateError {
    /// A stable machine code.
    pub const fn code(self) -> &'static str {
        match self {
            InflateError::Truncated => "truncated",
            InflateError::BlockType => "block_type",
            InflateError::StoredLength => "stored_length",
            InflateError::BadCode => "bad_code",
            InflateError::BadSymbol => "bad_symbol",
            InflateError::Distance => "distance",
            InflateError::OutputLimit => "output_limit",
            InflateError::Header => "zlib_header",
            InflateError::Dictionary => "zlib_dictionary",
            InflateError::Checksum => "zlib_checksum",
            InflateError::TrailingData => "trailing_data",
        }
    }
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "compressed data refused: {}", self.code())
    }
}

impl std::error::Error for InflateError {}

type R<T> = Result<T, InflateError>;

/// The largest DEFLATE window.
pub(crate) const MAX_WINDOW: usize = 32 * 1024;

/// A bit reader, least significant bit first.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

fn low_bits(n: u32) -> u64 {
    1u64.checked_shl(n).map_or(u64::MAX, |v| v.wrapping_sub(1))
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    fn refill(&mut self) {
        while self.cnt <= 56 {
            let Some(&b) = self.data.get(self.pos) else {
                break;
            };
            self.buf |= u64::from(b).checked_shl(self.cnt).unwrap_or(0);
            self.cnt = self.cnt.wrapping_add(8);
            self.pos = self.pos.wrapping_add(1);
        }
    }

    fn skip(&mut self, n: u32) {
        self.buf = self.buf.checked_shr(n).unwrap_or(0);
        self.cnt = self.cnt.saturating_sub(n);
    }

    /// The next `n` bits, `n` at most 32.
    fn take(&mut self, n: u32) -> R<u32> {
        if self.cnt < n {
            self.refill();
            if self.cnt < n {
                return Err(InflateError::Truncated);
            }
        }
        let v = self.buf & low_bits(n);
        self.skip(n);
        u32::try_from(v).map_err(|_| InflateError::Truncated)
    }

    fn take_usize(&mut self, n: u32) -> R<usize> {
        usize::try_from(self.take(n)?).map_err(|_| InflateError::Truncated)
    }

    /// Drops the bits up to the next byte boundary.
    fn align(&mut self) {
        self.skip(self.cnt & 7);
    }

    /// After [`Bits::align`]: the index of the next unread byte.
    fn byte_pos(&self) -> usize {
        self.pos
            .saturating_sub(usize::try_from(self.cnt >> 3).unwrap_or(0))
    }
}

/// The longest code.
const MAX_BITS: usize = 15;
/// The bits of the direct lookup table.
const FAST_BITS: u32 = 9;
const FAST_SIZE: usize = 1 << FAST_BITS;

/// A canonical Huffman decoder: a direct table for codes of up to
/// [`FAST_BITS`] bits, and the counting decoder of RFC 1951 for longer
/// codes and unused patterns.
struct Huffman {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u16>,
    /// `len << 12 | symbol`, or 0 for a longer or unused pattern.
    fast: Vec<u16>,
}

fn reverse(code: u32, len: u32) -> u32 {
    code.reverse_bits()
        .checked_shr(32u32.wrapping_sub(len))
        .unwrap_or(0)
}

fn at<T: Copy + Default>(s: &[T], i: usize) -> T {
    s.get(i).copied().unwrap_or_default()
}

impl Huffman {
    /// Builds the decoder of `lengths` (each at most 15). An incomplete
    /// code is refused, unless `allow_single` and the code has no symbol
    /// or one symbol of one bit, as zlib allows for literal/length and
    /// distance codes.
    fn build(lengths: &[u8], allow_single: bool) -> R<Huffman> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            let slot = count.get_mut(usize::from(l)).ok_or(InflateError::BadCode)?;
            *slot = slot.wrapping_add(1);
        }
        let mut left: i32 = 1;
        let mut used: usize = 0;
        for len in 1..=MAX_BITS {
            let c = at(&count, len);
            left = left.wrapping_mul(2).wrapping_sub(i32::from(c));
            if left < 0 {
                return Err(InflateError::BadCode);
            }
            used = used.wrapping_add(usize::from(c));
        }
        if left > 0 {
            let single = used == 0 || (used == 1 && at(&count, 1) == 1);
            if !(allow_single && single) {
                return Err(InflateError::BadCode);
            }
        }
        let mut offs = [0usize; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            let next = at(&offs, len).wrapping_add(usize::from(at(&count, len)));
            if let Some(o) = offs.get_mut(len.wrapping_add(1)) {
                *o = next;
            }
        }
        let mut symbol = vec![0u16; used];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let Some(o) = offs.get_mut(usize::from(l)) else {
                continue;
            };
            if let Some(s) = symbol.get_mut(*o) {
                *s = u16::try_from(sym).map_err(|_| InflateError::BadCode)?;
            }
            *o = o.wrapping_add(1);
        }
        let mut fast = vec![0u16; FAST_SIZE];
        let mut code: u32 = 0;
        let mut index: usize = 0;
        for len in 1..=FAST_BITS {
            let n = at(&count, usize::try_from(len).unwrap_or(0));
            for _ in 0..n {
                let sym = at(&symbol, index);
                let entry = u16::try_from(len << 12)
                    .unwrap_or(0)
                    .wrapping_add(sym & 0x0FFF);
                let step = 1usize.checked_shl(len).unwrap_or(FAST_SIZE);
                let mut k = usize::try_from(reverse(code, len)).unwrap_or(FAST_SIZE);
                while let Some(slot) = fast.get_mut(k) {
                    *slot = entry;
                    k = k.wrapping_add(step);
                }
                code = code.wrapping_add(1);
                index = index.wrapping_add(1);
            }
            code <<= 1;
        }
        Ok(Huffman {
            count,
            symbol,
            fast,
        })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> R<u16> {
        if bits.cnt < MAX_BITS as u32 {
            bits.refill();
        }
        let peek = usize::try_from(bits.buf & low_bits(FAST_BITS)).unwrap_or(0);
        let entry = at(&self.fast, peek);
        if entry != 0 {
            let len = u32::from(entry >> 12);
            if len > bits.cnt {
                return Err(InflateError::Truncated);
            }
            bits.skip(len);
            return Ok(entry & 0x0FFF);
        }
        // The counting decoder: the code is read most significant bit
        // first, and compared with the first code of each length.
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        let mut b = bits.buf;
        for len in 1..=MAX_BITS {
            if u32::try_from(len).unwrap_or(u32::MAX) > bits.cnt {
                return Err(InflateError::Truncated);
            }
            code |= i32::from(u8::from(b & 1 == 1));
            b >>= 1;
            let c = i32::from(at(&self.count, len));
            if code.wrapping_sub(c) < first {
                bits.skip(u32::try_from(len).unwrap_or(0));
                let i = index.wrapping_add(code).wrapping_sub(first);
                return usize::try_from(i)
                    .ok()
                    .and_then(|i| self.symbol.get(i).copied())
                    .ok_or(InflateError::BadSymbol);
            }
            index = index.wrapping_add(c);
            first = first.wrapping_add(c).wrapping_mul(2);
            code = code.wrapping_mul(2);
        }
        Err(InflateError::BadSymbol)
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// The order of the code length code lengths (RFC 1951 section 3.2.7).
pub(crate) const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub(crate) fn len_code(i: usize) -> Option<(u16, u8)> {
    Some((*LEN_BASE.get(i)?, *LEN_EXTRA.get(i)?))
}

pub(crate) fn dist_code(i: usize) -> Option<(u16, u8)> {
    Some((*DIST_BASE.get(i)?, *DIST_EXTRA.get(i)?))
}

/// The code lengths of the fixed literal/length code, all 288 symbols.
pub(crate) fn fixed_lit_lengths() -> [u8; 288] {
    let mut l = [8u8; 288];
    for (i, v) in l.iter_mut().enumerate() {
        *v = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    l
}

/// The output, under its cap and window.
struct Sink {
    out: Vec<u8>,
    cap: usize,
    window: usize,
}

impl Sink {
    fn room(&mut self, need: usize) -> R<()> {
        let left = self.cap.saturating_sub(self.out.len());
        if need > left {
            return Err(InflateError::OutputLimit);
        }
        let spare = self.out.capacity().saturating_sub(self.out.len());
        if spare < need {
            let grow = need.max(self.out.len()).min(left);
            self.out.reserve_exact(grow);
        }
        Ok(())
    }

    fn literal(&mut self, b: u8) -> R<()> {
        self.room(1)?;
        self.out.push(b);
        Ok(())
    }

    fn copy(&mut self, distance: usize, len: usize) -> R<()> {
        if distance == 0 || distance > self.out.len() || distance > self.window {
            return Err(InflateError::Distance);
        }
        self.room(len)?;
        let start = self.out.len().wrapping_sub(distance);
        if distance >= len {
            self.out.extend_from_within(start..start.wrapping_add(len));
        } else {
            for i in 0..len {
                let b = at(&self.out, start.wrapping_add(i));
                self.out.push(b);
            }
        }
        Ok(())
    }
}

fn stored(bits: &mut Bits<'_>, sink: &mut Sink) -> R<()> {
    bits.align();
    let len = bits.take(16)?;
    let nlen = bits.take(16)?;
    if len != (!nlen & 0xFFFF) {
        return Err(InflateError::StoredLength);
    }
    let len = usize::try_from(len).map_err(|_| InflateError::StoredLength)?;
    sink.room(len)?;
    for _ in 0..len {
        let b = bits.take(8)?;
        sink.out.push(u8::try_from(b).unwrap_or(0));
    }
    Ok(())
}

fn dynamic_tables(bits: &mut Bits<'_>) -> R<(Huffman, Huffman)> {
    let hlit = bits.take_usize(5)?.wrapping_add(257);
    let hdist = bits.take_usize(5)?.wrapping_add(1);
    let hclen = bits.take_usize(4)?.wrapping_add(4);
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::BadCode);
    }
    let mut cl = [0u8; 19];
    for &i in CL_ORDER.iter().take(hclen) {
        let v = bits.take(3)?;
        if let Some(slot) = cl.get_mut(i) {
            *slot = u8::try_from(v).unwrap_or(0);
        }
    }
    let cl_code = Huffman::build(&cl, false)?;
    let total = hlit.wrapping_add(hdist);
    let mut lens = vec![0u8; total];
    let mut i = 0usize;
    while i < total {
        let sym = cl_code.decode(bits)?;
        let (value, rep) = match sym {
            0..=15 => (u8::try_from(sym).unwrap_or(0), 1usize),
            16 => {
                let prev = i
                    .checked_sub(1)
                    .and_then(|p| lens.get(p).copied())
                    .ok_or(InflateError::BadCode)?;
                (prev, bits.take_usize(2)?.wrapping_add(3))
            }
            17 => (0, bits.take_usize(3)?.wrapping_add(3)),
            18 => (0, bits.take_usize(7)?.wrapping_add(11)),
            _ => return Err(InflateError::BadCode),
        };
        let end = i.wrapping_add(rep);
        let run = lens.get_mut(i..end).ok_or(InflateError::BadCode)?;
        run.fill(value);
        i = end;
    }
    let (lit, dist) = lens.split_at(hlit.min(lens.len()));
    if at(lit, 256) == 0 {
        return Err(InflateError::BadCode);
    }
    Ok((Huffman::build(lit, true)?, Huffman::build(dist, true)?))
}

fn fixed_tables() -> R<(Huffman, Huffman)> {
    Ok((
        Huffman::build(&fixed_lit_lengths(), false)?,
        Huffman::build(&[5u8; 32], false)?,
    ))
}

fn codes(bits: &mut Bits<'_>, sink: &mut Sink, lit: &Huffman, dist: &Huffman) -> R<()> {
    loop {
        let sym = lit.decode(bits)?;
        if let Ok(b) = u8::try_from(sym) {
            sink.literal(b)?;
            continue;
        }
        if sym == 256 {
            return Ok(());
        }
        let (base, extra) =
            len_code(usize::from(sym).wrapping_sub(257)).ok_or(InflateError::BadSymbol)?;
        let len = usize::from(base).wrapping_add(bits.take_usize(u32::from(extra))?);
        let d = dist.decode(bits)?;
        let (dbase, dextra) = dist_code(usize::from(d)).ok_or(InflateError::BadSymbol)?;
        let distance = usize::from(dbase).wrapping_add(bits.take_usize(u32::from(dextra))?);
        sink.copy(distance, len)?;
    }
}

fn blocks(bits: &mut Bits<'_>, sink: &mut Sink) -> R<()> {
    let mut fixed: Option<(Huffman, Huffman)> = None;
    loop {
        let last = bits.take(1)?;
        match bits.take(2)? {
            0 => stored(bits, sink)?,
            1 => {
                if fixed.is_none() {
                    fixed = Some(fixed_tables()?);
                }
                if let Some((lit, dist)) = &fixed {
                    codes(bits, sink, lit, dist)?;
                }
            }
            2 => {
                let (lit, dist) = dynamic_tables(bits)?;
                codes(bits, sink, &lit, &dist)?;
            }
            _ => return Err(InflateError::BlockType),
        }
        if last == 1 {
            return Ok(());
        }
    }
}

/// The first reservation of an output whose size is not known.
const FIRST_RESERVE: usize = 64 * 1024;

/// Inflates raw DEFLATE data (RFC 1951) to at most `max_output` bytes.
/// Any byte after the final block is refused.
pub fn inflate(data: &[u8], max_output: usize) -> Result<Vec<u8>, InflateError> {
    let mut bits = Bits::new(data);
    let mut sink = Sink {
        out: Vec::with_capacity(max_output.min(FIRST_RESERVE)),
        cap: max_output,
        window: MAX_WINDOW,
    };
    blocks(&mut bits, &mut sink)?;
    bits.align();
    if bits.byte_pos() != data.len() {
        return Err(InflateError::TrailingData);
    }
    Ok(sink.out)
}

/// Decompresses a zlib stream (RFC 1950) to at most `max_output` bytes.
/// The header must name DEFLATE with a window of at most 32 KiB and no
/// preset dictionary, no distance may pass that window, the Adler-32
/// must match, and nothing may follow it.
pub fn zlib_decompress(data: &[u8], max_output: usize) -> Result<Vec<u8>, InflateError> {
    zlib_with(data, max_output, max_output.min(FIRST_RESERVE))
}

/// [`zlib_decompress`] that reserves `reserve` bytes up front, for a
/// caller that knows the exact size.
pub(crate) fn zlib_with(data: &[u8], cap: usize, reserve: usize) -> R<Vec<u8>> {
    let (Some(&cmf), Some(&flg)) = (data.first(), data.get(1)) else {
        return Err(InflateError::Truncated);
    };
    let check = (u16::from(cmf) << 8) | u16::from(flg);
    let cinfo = cmf >> 4;
    if cmf & 0x0F != 8 || cinfo > 7 || check.checked_rem(31) != Some(0) {
        return Err(InflateError::Header);
    }
    if flg & 0x20 != 0 {
        return Err(InflateError::Dictionary);
    }
    let window = 1usize
        .checked_shl(u32::from(cinfo).wrapping_add(8))
        .unwrap_or(MAX_WINDOW);
    let body = data.get(2..).unwrap_or(&[]);
    let mut bits = Bits::new(body);
    let mut sink = Sink {
        out: Vec::with_capacity(reserve.min(cap)),
        cap,
        window,
    };
    blocks(&mut bits, &mut sink)?;
    bits.align();
    let mut sum = 0u32;
    for _ in 0..4 {
        sum = (sum << 8) | bits.take(8)?;
    }
    if bits.byte_pos() != body.len() {
        return Err(InflateError::TrailingData);
    }
    let mut adler = Adler::new();
    adler.update(&sink.out);
    if adler.finish() != sum {
        return Err(InflateError::Checksum);
    }
    Ok(sink.out)
}
