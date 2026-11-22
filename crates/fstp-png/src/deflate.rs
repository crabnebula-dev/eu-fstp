//! A deterministic DEFLATE encoder (ADR-031 row "Deflate").
//!
//! LZ77 over hash chains in the 32 KiB window, greedy, then for each
//! block of tokens the smallest of a stored, a fixed Huffman and a
//! dynamic Huffman block. Dynamic codes are length-limited by
//! package-merge and every code written is complete, so any conforming
//! decoder reads them. The same input always gives the same bytes.

use crate::check::Adler;
use crate::inflate::{CL_ORDER, MAX_WINDOW, dist_code, fixed_lit_lengths, len_code};

/// Which blocks the encoder writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Blocks {
    /// Stored blocks only, no compression.
    Stored,
    /// LZ77 with the fixed Huffman code.
    Fixed,
    /// LZ77 with dynamic Huffman codes.
    Dynamic,
    /// For each block, the smallest of the three.
    Best,
}

/// Bits written least significant first.
struct Writer {
    out: Vec<u8>,
    buf: u64,
    cnt: u32,
}

fn low_bits(n: u32) -> u64 {
    1u64.checked_shl(n).map_or(u64::MAX, |v| v.wrapping_sub(1))
}

fn at<T: Copy + Default>(s: &[T], i: usize) -> T {
    s.get(i).copied().unwrap_or_default()
}

impl Writer {
    /// Writes the low `n` bits of `v`, `n` at most 32.
    fn put(&mut self, v: u32, n: u32) {
        self.buf |= (u64::from(v) & low_bits(n))
            .checked_shl(self.cnt)
            .unwrap_or(0);
        self.cnt = self.cnt.wrapping_add(n);
        while self.cnt >= 8 {
            self.out.push(self.buf as u8);
            self.buf >>= 8;
            self.cnt = self.cnt.wrapping_sub(8);
        }
    }

    fn align(&mut self) {
        if self.cnt > 0 {
            self.out.push(self.buf as u8);
            self.buf = 0;
            self.cnt = 0;
        }
    }
}

/// One LZ77 token: a literal byte, or a match of `len` bytes at `dist`.
#[derive(Clone, Copy)]
enum Token {
    Literal(u8),
    Match { len: u16, dist: u16 },
}

/// The symbol index (from 257), extra bit count and extra value of a
/// match length from 3 to 258.
fn len_symbol(len: usize) -> (usize, u32, u32) {
    if len >= 258 {
        return (28, 0, 0);
    }
    let mut i = 0usize;
    while let Some((base, _)) = len_code(i.wrapping_add(1)) {
        if usize::from(base) > len || i >= 27 {
            break;
        }
        i = i.wrapping_add(1);
    }
    let (base, extra) = len_code(i).unwrap_or((3, 0));
    let value = len.saturating_sub(usize::from(base));
    (i, u32::from(extra), u32::try_from(value).unwrap_or(0))
}

/// The symbol, extra bit count and extra value of a distance from 1 to
/// 32768.
fn dist_symbol(dist: usize) -> (usize, u32, u32) {
    let mut i = 0usize;
    while let Some((base, _)) = dist_code(i.wrapping_add(1)) {
        if usize::from(base) > dist {
            break;
        }
        i = i.wrapping_add(1);
    }
    let (base, extra) = dist_code(i).unwrap_or((1, 0));
    let value = dist.saturating_sub(usize::from(base));
    (i, u32::from(extra), u32::try_from(value).unwrap_or(0))
}

const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN: usize = 32;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Positions inside a longer match are not hashed, which keeps long runs
/// fast.
const INSERT_MAX: usize = 32;
/// The positions at the end of a longer match that are hashed.
const TAIL: usize = 8;
const NONE: u32 = u32::MAX;
/// Tokens per block.
const BLOCK_TOKENS: usize = 1 << 15;

struct Matcher<'a> {
    data: &'a [u8],
    head: Vec<u32>,
    prev: Vec<u32>,
}

impl<'a> Matcher<'a> {
    fn new(data: &'a [u8]) -> Matcher<'a> {
        Matcher {
            data,
            head: vec![NONE; HASH_SIZE],
            prev: vec![NONE; MAX_WINDOW],
        }
    }

    fn hash(&self, p: usize) -> usize {
        let k = u32::from_le_bytes([
            at(self.data, p),
            at(self.data, p.wrapping_add(1)),
            at(self.data, p.wrapping_add(2)),
            0,
        ]);
        usize::try_from(k.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)).unwrap_or(0)
    }

    fn insert(&mut self, p: usize) {
        if p.saturating_add(MIN_MATCH) > self.data.len() {
            return;
        }
        let Ok(p32) = u32::try_from(p) else {
            return;
        };
        let h = self.hash(p);
        let old = at(&self.head, h);
        if let Some(slot) = self.prev.get_mut(p & (MAX_WINDOW - 1)) {
            *slot = old;
        }
        if let Some(slot) = self.head.get_mut(h) {
            *slot = p32;
        }
    }

    fn common(&self, a: usize, b: usize, max: usize) -> usize {
        match (self.data.get(a..), self.data.get(b..)) {
            (Some(x), Some(y)) => x
                .iter()
                .zip(y)
                .take(max)
                .take_while(|(p, q)| p == q)
                .count(),
            _ => 0,
        }
    }

    /// The longest match at `p` as (length, distance), or length 0.
    fn find(&self, p: usize) -> (usize, usize) {
        let max = MAX_MATCH.min(self.data.len().saturating_sub(p));
        if max < MIN_MATCH {
            return (0, 0);
        }
        let mut best = (0usize, 0usize);
        let mut cand = at(&self.head, self.hash(p));
        let mut chain = 0usize;
        while cand != NONE && chain < MAX_CHAIN {
            let c = usize::try_from(cand).unwrap_or(usize::MAX);
            if c >= p {
                break;
            }
            let d = p.wrapping_sub(c);
            if d > MAX_WINDOW {
                break;
            }
            let l = self.common(c, p, max);
            if l > best.0 {
                best = (l, d);
                if l >= max {
                    break;
                }
            }
            let next = at(&self.prev, c & (MAX_WINDOW - 1));
            if next == NONE || next >= cand {
                break;
            }
            cand = next;
            chain = chain.wrapping_add(1);
        }
        if best.0 >= MIN_MATCH { best } else { (0, 0) }
    }
}

/// Canonical codes of `lens`, bit-reversed for writing.
fn canonical(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 16];
    for &l in lens {
        if let Some(c) = count.get_mut(usize::from(l)) {
            *c = c.wrapping_add(1);
        }
    }
    let mut next = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..16usize {
        code = code
            .wrapping_add(if bits == 1 {
                0
            } else {
                at(&count, bits.wrapping_sub(1))
            })
            .wrapping_mul(2);
        if let Some(n) = next.get_mut(bits) {
            *n = code;
        }
    }
    lens.iter()
        .map(|&l| {
            if l == 0 {
                return 0;
            }
            let Some(n) = next.get_mut(usize::from(l)) else {
                return 0;
            };
            let c = *n;
            *n = n.wrapping_add(1);
            c.reverse_bits()
                .checked_shr(32u32.wrapping_sub(u32::from(l)))
                .unwrap_or(0)
        })
        .collect()
}

#[derive(Clone, Copy)]
enum Node {
    Leaf(usize),
    Pair(usize, usize),
}

fn merge(a: &[(u64, usize)], b: &[(u64, usize)]) -> Vec<(u64, usize)> {
    let mut out = Vec::with_capacity(a.len().saturating_add(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    loop {
        match (a.get(i), b.get(j)) {
            (Some(x), Some(y)) => {
                if x.0 <= y.0 {
                    out.push(*x);
                    i = i.wrapping_add(1);
                } else {
                    out.push(*y);
                    j = j.wrapping_add(1);
                }
            }
            (Some(x), None) => {
                out.push(*x);
                i = i.wrapping_add(1);
            }
            (None, Some(y)) => {
                out.push(*y);
                j = j.wrapping_add(1);
            }
            (None, None) => return out,
        }
    }
}

/// Code lengths of at most `limit` bits for `freq`, by package-merge.
/// At least two symbols get a length, so the code is complete.
fn limited_lengths(freq: &[u32], limit: u32) -> Vec<u8> {
    let mut lens = vec![0u8; freq.len()];
    let mut leaves: Vec<(u64, usize)> = freq
        .iter()
        .enumerate()
        .filter(|(_, f)| **f > 0)
        .map(|(i, f)| (u64::from(*f), i))
        .collect();
    let mut s = 0usize;
    while leaves.len() < 2 && s < freq.len() {
        if at(freq, s) == 0 {
            leaves.push((0, s));
        }
        s = s.wrapping_add(1);
    }
    if leaves.len() < 2 {
        return lens;
    }
    leaves.sort_unstable();
    let mut nodes: Vec<Node> = leaves.iter().map(|&(_, s)| Node::Leaf(s)).collect();
    let items: Vec<(u64, usize)> = leaves
        .iter()
        .enumerate()
        .map(|(i, &(w, _))| (w, i))
        .collect();
    let mut list = items.clone();
    for _ in 1..limit {
        let mut packages = Vec::with_capacity(list.len() / 2);
        for pair in list.chunks_exact(2) {
            if let [a, b] = pair {
                nodes.push(Node::Pair(a.1, b.1));
                packages.push((a.0.saturating_add(b.0), nodes.len().wrapping_sub(1)));
            }
        }
        list = merge(&items, &packages);
    }
    let take = leaves.len().saturating_mul(2).saturating_sub(2);
    let mut stack: Vec<usize> = list.iter().take(take).map(|&(_, id)| id).collect();
    while let Some(id) = stack.pop() {
        match nodes.get(id) {
            Some(Node::Leaf(s)) => {
                if let Some(l) = lens.get_mut(*s) {
                    *l = l.saturating_add(1);
                }
            }
            Some(Node::Pair(a, b)) => {
                stack.push(*a);
                stack.push(*b);
            }
            None => {}
        }
    }
    lens
}

/// Symbol frequencies of a block.
struct Freq {
    lit: [u32; 286],
    dist: [u32; 30],
}

fn bump(slot: Option<&mut u32>) {
    if let Some(f) = slot {
        *f = f.saturating_add(1);
    }
}

fn frequencies(tokens: &[Token]) -> Freq {
    let mut f = Freq {
        lit: [0; 286],
        dist: [0; 30],
    };
    for t in tokens {
        match *t {
            Token::Literal(b) => bump(f.lit.get_mut(usize::from(b))),
            Token::Match { len, dist } => {
                let (i, _, _) = len_symbol(usize::from(len));
                bump(f.lit.get_mut(i.wrapping_add(257)));
                let (d, _, _) = dist_symbol(usize::from(dist));
                bump(f.dist.get_mut(d));
            }
        }
    }
    bump(f.lit.get_mut(256));
    f
}

/// The bits of the tokens under the given code lengths.
fn data_bits(tokens: &[Token], lit: &[u8], dist: &[u8]) -> u64 {
    let mut bits = u64::from(at(lit, 256));
    for t in tokens {
        let n = match *t {
            Token::Literal(b) => u32::from(at(lit, usize::from(b))),
            Token::Match { len, dist: d } => {
                let (i, eb, _) = len_symbol(usize::from(len));
                let (j, db, _) = dist_symbol(usize::from(d));
                u32::from(at(lit, i.wrapping_add(257)))
                    .wrapping_add(eb)
                    .wrapping_add(u32::from(at(dist, j)))
                    .wrapping_add(db)
            }
        };
        bits = bits.saturating_add(u64::from(n));
    }
    bits
}

/// A dynamic block's codes and header.
struct Plan {
    lit: Vec<u8>,
    dist: Vec<u8>,
    hlit: usize,
    hdist: usize,
    cl: Vec<u8>,
    hclen: usize,
    /// Code length symbols with their extra values.
    rle: Vec<(u8, u8)>,
}

fn rle_extra_bits(sym: u8) -> u32 {
    match sym {
        16 => 2,
        17 => 3,
        18 => 7,
        _ => 0,
    }
}

fn rle(seq: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&v) = seq.get(i) {
        let run = seq
            .get(i..)
            .map_or(1, |s| s.iter().take_while(|&&x| x == v).count());
        let mut r = run;
        if v == 0 {
            while r >= 11 {
                let k = r.min(138);
                out.push((18, u8::try_from(k.wrapping_sub(11)).unwrap_or(0)));
                r = r.wrapping_sub(k);
            }
            if r >= 3 {
                out.push((17, u8::try_from(r.wrapping_sub(3)).unwrap_or(0)));
                r = 0;
            }
        } else {
            out.push((v, 0));
            r = r.wrapping_sub(1);
            while r >= 3 {
                let k = r.min(6);
                out.push((16, u8::try_from(k.wrapping_sub(3)).unwrap_or(0)));
                r = r.wrapping_sub(k);
            }
        }
        for _ in 0..r {
            out.push((v, 0));
        }
        i = i.wrapping_add(run.max(1));
    }
    out
}

fn last_used(lens: &[u8]) -> usize {
    lens.iter()
        .rposition(|&l| l != 0)
        .map_or(0, |p| p.wrapping_add(1))
}

fn plan(f: &Freq) -> Plan {
    let lit = limited_lengths(&f.lit, 15);
    let dist = limited_lengths(&f.dist, 15);
    let hlit = last_used(&lit).max(257);
    let hdist = last_used(&dist).max(1);
    let mut seq: Vec<u8> = lit.iter().take(hlit).copied().collect();
    seq.extend(dist.iter().take(hdist));
    let rle = rle(&seq);
    let mut cl_freq = [0u32; 19];
    for &(s, _) in &rle {
        bump(cl_freq.get_mut(usize::from(s)));
    }
    let cl = limited_lengths(&cl_freq, 7);
    let hclen = CL_ORDER
        .iter()
        .rposition(|&i| at(&cl, i) != 0)
        .map_or(4, |p| p.wrapping_add(1).max(4));
    Plan {
        lit,
        dist,
        hlit,
        hdist,
        cl,
        hclen,
        rle,
    }
}

fn header_bits(p: &Plan) -> u64 {
    let mut bits = 3u64 + 5 + 5 + 4;
    bits = bits.saturating_add(3u64.saturating_mul(u64::try_from(p.hclen).unwrap_or(0)));
    for &(s, _) in &p.rle {
        let n = u32::from(at(&p.cl, usize::from(s))).wrapping_add(rle_extra_bits(s));
        bits = bits.saturating_add(u64::from(n));
    }
    bits
}

fn write_tokens(w: &mut Writer, tokens: &[Token], lit: &[u8], dist: &[u8]) {
    let lc = canonical(lit);
    let dc = canonical(dist);
    for t in tokens {
        match *t {
            Token::Literal(b) => {
                let s = usize::from(b);
                w.put(at(&lc, s), u32::from(at(lit, s)));
            }
            Token::Match { len, dist: d } => {
                let (i, eb, ev) = len_symbol(usize::from(len));
                let s = i.wrapping_add(257);
                w.put(at(&lc, s), u32::from(at(lit, s)));
                w.put(ev, eb);
                let (j, db, dv) = dist_symbol(usize::from(d));
                w.put(at(&dc, j), u32::from(at(dist, j)));
                w.put(dv, db);
            }
        }
    }
    w.put(at(&lc, 256), u32::from(at(lit, 256)));
}

fn write_stored(w: &mut Writer, raw: &[u8], last: bool) {
    let n = raw.len().div_ceil(65_535).max(1);
    let mut parts = raw.chunks(65_535);
    for i in 0..n {
        let part = parts.next().unwrap_or(&[]);
        w.put(u32::from(last && i.wrapping_add(1) == n), 1);
        w.put(0, 2);
        w.align();
        let len = u32::try_from(part.len()).unwrap_or(0);
        w.put(len, 16);
        w.put(!len & 0xFFFF, 16);
        w.out.extend_from_slice(part);
    }
}

fn stored_bits(raw: &[u8]) -> u64 {
    let blocks = u64::try_from(raw.len().div_ceil(65_535).max(1)).unwrap_or(u64::MAX);
    let bytes = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    blocks
        .saturating_mul(3 + 7 + 32)
        .saturating_add(bytes.saturating_mul(8))
}

fn write_fixed(w: &mut Writer, tokens: &[Token], last: bool) {
    w.put(u32::from(last), 1);
    w.put(1, 2);
    write_tokens(w, tokens, &fixed_lit_lengths(), &[5u8; 30]);
}

fn write_dynamic(w: &mut Writer, tokens: &[Token], p: &Plan, last: bool) {
    w.put(u32::from(last), 1);
    w.put(2, 2);
    w.put(u32::try_from(p.hlit.wrapping_sub(257)).unwrap_or(0), 5);
    w.put(u32::try_from(p.hdist.wrapping_sub(1)).unwrap_or(0), 5);
    w.put(u32::try_from(p.hclen.wrapping_sub(4)).unwrap_or(0), 4);
    for &i in CL_ORDER.iter().take(p.hclen) {
        w.put(u32::from(at(&p.cl, i)), 3);
    }
    let cc = canonical(&p.cl);
    for &(s, extra) in &p.rle {
        let si = usize::from(s);
        w.put(at(&cc, si), u32::from(at(&p.cl, si)));
        w.put(u32::from(extra), rle_extra_bits(s));
    }
    let lit = p.lit.get(..p.hlit).unwrap_or(&p.lit);
    let dist = p.dist.get(..p.hdist).unwrap_or(&p.dist);
    write_tokens(w, tokens, lit, dist);
}

fn emit(w: &mut Writer, tokens: &[Token], raw: &[u8], last: bool, mode: Blocks) {
    match mode {
        Blocks::Stored => write_stored(w, raw, last),
        Blocks::Fixed => write_fixed(w, tokens, last),
        Blocks::Dynamic => write_dynamic(w, tokens, &plan(&frequencies(tokens)), last),
        Blocks::Best => {
            let f = frequencies(tokens);
            let p = plan(&f);
            let dynamic = header_bits(&p).saturating_add(data_bits(tokens, &p.lit, &p.dist));
            let fixed = 3u64.saturating_add(data_bits(tokens, &fixed_lit_lengths(), &[5u8; 30]));
            let stored = stored_bits(raw);
            if dynamic < fixed && dynamic < stored {
                write_dynamic(w, tokens, &p, last);
            } else if fixed < stored {
                write_fixed(w, tokens, last);
            } else {
                write_stored(w, raw, last);
            }
        }
    }
}

/// Compresses `data` to raw DEFLATE (RFC 1951) with the best block of
/// each kind ([`Blocks::Best`]).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    deflate_with(data, Blocks::Best)
}

/// Compresses `data` to raw DEFLATE with the blocks `mode` names.
pub fn deflate_with(data: &[u8], mode: Blocks) -> Vec<u8> {
    let mut w = Writer {
        out: Vec::new(),
        buf: 0,
        cnt: 0,
    };
    if mode == Blocks::Stored {
        write_stored(&mut w, data, true);
        w.align();
        return w.out;
    }
    let mut m = Matcher::new(data);
    let mut tokens: Vec<Token> = Vec::with_capacity(BLOCK_TOKENS.min(data.len().saturating_add(1)));
    let (mut p, mut start) = (0usize, 0usize);
    loop {
        if p >= data.len() || tokens.len() >= BLOCK_TOKENS {
            let last = p >= data.len();
            let raw = data.get(start..p).unwrap_or(&[]);
            emit(&mut w, &tokens, raw, last, mode);
            tokens.clear();
            start = p;
            if last {
                break;
            }
            continue;
        }
        let (len, dist) = m.find(p);
        match (u16::try_from(len), u16::try_from(dist)) {
            (Ok(l), Ok(d)) if len >= MIN_MATCH => {
                tokens.push(Token::Match { len: l, dist: d });
                m.insert(p);
                // A long match hashes only its last positions, so the next
                // search still finds the nearest repeat of a run.
                let from = if len <= INSERT_MAX {
                    1
                } else {
                    len.wrapping_sub(TAIL)
                };
                for q in from..len {
                    m.insert(p.wrapping_add(q));
                }
                p = p.wrapping_add(len);
            }
            _ => {
                tokens.push(Token::Literal(at(data, p)));
                m.insert(p);
                p = p.wrapping_add(1);
            }
        }
    }
    w.align();
    w.out
}

/// A zlib stream (RFC 1950) of `data`: header `78 DA`, [`deflate`], and
/// the Adler-32.
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    zlib_compress_with(data, Blocks::Best)
}

/// A zlib stream of `data` with the blocks `mode` names.
pub fn zlib_compress_with(data: &[u8], mode: Blocks) -> Vec<u8> {
    let mut out = vec![0x78, 0xDA];
    out.extend(deflate_with(data, mode));
    let mut a = Adler::new();
    a.update(data);
    out.extend(a.finish().to_be_bytes());
    out
}
