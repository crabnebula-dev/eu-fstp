//! The canary scanner of the isolation harness (M3 design sections 14.1
//! and 14.3, lane W1a). It is the instrument of the I-17, I-19, I-38 and
//! I-80 canary tests, so it gets its own controls and teeth.
//!
//! Section 14.1 lists the encodings: raw bytes, both hex cases, base64,
//! base64url, percent-encoding, JSON string escaping and UTF-16LE. Each
//! production test seeds a canary in every one of them and requires
//! `fstp_celltest::scan::scan` to find it.
//!
//! The predicates take the scanner as a parameter. A reference scanner
//! written here, one exact matcher per encoding, is the control. Each teeth
//! test drops one encoding's matcher from the reference and requires the
//! predicate to name the encoding it missed. Base64 and base64url coincide
//! on canary text, so their teeth test drops both. The production tests
//! are red until lane W1a lands the scanner and the canary renderer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{ScanReport, StoreSet};
use fstp_prop::{Config, FailureKind, Gen, check, run};

// ---------------------------------------------------------------------------
// Encodings of design section 14.1, written here independently of the
// harness.

/// An encoding the scanner must see through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enc {
    Raw,
    HexLower,
    HexUpper,
    Base64,
    Base64Url,
    Percent,
    JsonEscape,
    Utf16Le,
}

/// Every encoding of design section 14.1.
const ENCODINGS: [Enc; 8] = [
    Enc::Raw,
    Enc::HexLower,
    Enc::HexUpper,
    Enc::Base64,
    Enc::Base64Url,
    Enc::Percent,
    Enc::JsonEscape,
    Enc::Utf16Le,
];

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(digits[usize::from(b >> 4)]);
        out.push(digits[usize::from(b & 0x0f)]);
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 of `bytes` with `alphabet`, padded with `=` when `pad` holds.
fn base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]);
            } else if pad {
                out.push(b'=');
            }
        }
    }
    out
}

fn utf16le(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [*b, 0]).collect()
}

/// Escapes the bytes of `payload` for which `escape` holds, with
/// `escape_one`, and keeps the rest.
fn escape_some(
    payload: &[u8],
    escape: &[bool],
    upper: &[bool],
    escape_one: fn(u8, bool) -> Vec<u8>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, b) in payload.iter().enumerate() {
        if escape[i] {
            out.extend(escape_one(*b, upper[i]));
        } else {
            out.push(*b);
        }
    }
    out
}

fn percent_one(b: u8, upper: bool) -> Vec<u8> {
    let mut out = vec![b'%'];
    out.extend(hex(&[b], upper));
    out
}

fn json_one(b: u8, upper: bool) -> Vec<u8> {
    let mut out = b"\\u00".to_vec();
    out.extend(hex(&[b], upper));
    out
}

/// Encodes `payload` in `enc`. The canary text sits at `canary` inside it.
/// Percent-encoding and JSON escaping escape a random subset of the bytes,
/// in random hex case, with at least one escaped byte inside the canary.
/// A random filler of bytes that no encoding uses surrounds the result.
fn seed(g: &mut Gen, enc: Enc, payload: &[u8], canary: std::ops::Range<usize>) -> Vec<u8> {
    let encoded = match enc {
        Enc::Raw => payload.to_vec(),
        Enc::HexLower => hex(payload, false),
        Enc::HexUpper => hex(payload, true),
        Enc::Base64 => base64(payload, B64, true),
        Enc::Base64Url => base64(payload, B64URL, false),
        Enc::Utf16Le => utf16le(payload),
        Enc::Percent | Enc::JsonEscape => {
            let all = g.bool();
            let forced = g.usize_in(canary.start..=canary.end - 1);
            let escape: Vec<bool> = (0..payload.len())
                .map(|i| all || i == forced || g.bool())
                .collect();
            let upper: Vec<bool> = (0..payload.len()).map(|_| g.bool()).collect();
            let one = if enc == Enc::Percent {
                percent_one
            } else {
                json_one
            };
            escape_some(payload, &escape, &upper, one)
        }
    };
    let mut out = filler(g);
    out.extend(encoded);
    out.extend(filler(g));
    out
}

/// Bytes that no encoding produces and no escape sequence can start with.
fn filler(g: &mut Gen) -> Vec<u8> {
    g.vec(0..=9, |g| {
        let b = g.u8_in(0x80..=0xff);
        if b == 0x80 { b'#' } else { b }
    })
}

/// A random ASCII alphanumeric run, the text around a canary.
fn context(g: &mut Gen) -> Vec<u8> {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    g.vec(0..=7, |g| *g.pick(ALNUM))
}

// ---------------------------------------------------------------------------
// Canaries.

const KINDS: [CanaryKind; 10] = [
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

fn gen_canary(g: &mut Gen) -> Canary {
    let cell = g.u8();
    let kind = *g.pick(&KINDS);
    let mut nonce = [0u8; 16];
    for b in &mut nonce {
        *b = g.u8();
    }
    Canary { cell, kind, nonce }
}

/// A canary's text.
type Render<'a> = &'a dyn Fn(&Canary) -> Result<String, String>;
/// A scanner under test.
type Scanner<'a> = &'a dyn Fn(&StoreSet, &[Canary]) -> Result<ScanReport, String>;

/// The renderer the reference scanner uses. Exhaustive, so a new kind
/// fails to compile here.
fn reference_render(c: &Canary) -> Result<String, String> {
    let kind = match c.kind {
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
    };
    let nonce = String::from_utf8(hex(&c.nonce, false)).map_err(|e| e.to_string())?;
    Ok(format!("CNRY-{}-{kind}-{nonce}", c.cell))
}

fn production_render(c: &Canary) -> Result<String, String> {
    c.render().map_err(|e| format!("render refused: {e:?}"))
}

fn production_scan(stores: &StoreSet, canaries: &[Canary]) -> Result<ScanReport, String> {
    fstp_celltest::scan::scan(stores, canaries).map_err(|e| format!("scan refused: {e:?}"))
}

// ---------------------------------------------------------------------------
// The reference scanner: one exact matcher per encoding.

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes every escape that `parse` recognises and marks which output
/// bytes came from an escape. A match counts for the encoding only when it
/// covers at least one escaped byte, so that this matcher never stands in
/// for the raw one.
fn unescaped_match(hay: &[u8], text: &[u8], parse: fn(&[u8]) -> Option<(u8, usize)>) -> bool {
    let mut out = Vec::new();
    let mut escaped = Vec::new();
    let mut i = 0;
    while i < hay.len() {
        if let Some((b, used)) = parse(&hay[i..]) {
            out.push(b);
            escaped.push(true);
            i += used;
        } else {
            out.push(hay[i]);
            escaped.push(false);
            i += 1;
        }
    }
    (0..out.len().saturating_sub(text.len() - 1)).any(|start| {
        &out[start..start + text.len()] == text
            && escaped[start..start + text.len()].iter().any(|e| *e)
    })
}

fn parse_percent(s: &[u8]) -> Option<(u8, usize)> {
    if s.len() >= 3 && s[0] == b'%' {
        Some(((hex_value(s[1])? << 4) | hex_value(s[2])?, 3))
    } else {
        None
    }
}

fn parse_json(s: &[u8]) -> Option<(u8, usize)> {
    if s.len() >= 6 && s[0] == b'\\' && s[1] == b'u' && s[2] == b'0' && s[3] == b'0' {
        let b = (hex_value(s[4])? << 4) | hex_value(s[5])?;
        (b < 0x80).then_some((b, 6))
    } else {
        None
    }
}

/// Whether `hay` holds `text` in `enc`.
fn reference_matches(enc: Enc, hay: &[u8], text: &[u8]) -> bool {
    match enc {
        Enc::Raw => contains(hay, text),
        Enc::HexLower => contains(hay, &hex(text, false)),
        Enc::HexUpper => contains(hay, &hex(text, true)),
        Enc::Base64 | Enc::Base64Url => {
            let alphabet = if enc == Enc::Base64 { B64 } else { B64URL };
            (0..3).any(|skip| {
                let rest = &text[skip..];
                let whole = rest.len() / 3 * 3;
                contains(hay, &base64(&rest[..whole], alphabet, false))
            })
        }
        Enc::Percent => unescaped_match(hay, text, parse_percent),
        Enc::JsonEscape => unescaped_match(hay, text, parse_json),
        Enc::Utf16Le => contains(hay, &utf16le(text)),
    }
}

/// The reference scanner over the encodings in `encodings`.
fn reference_scan(
    stores: &StoreSet,
    canaries: &[Canary],
    encodings: &[Enc],
) -> Result<ScanReport, String> {
    let mut report = ScanReport::default();
    for (name, bytes) in &stores.stores {
        for c in canaries {
            let text = reference_render(c)?;
            if encodings
                .iter()
                .any(|e| reference_matches(*e, bytes, text.as_bytes()))
            {
                report.hits.push((name.clone(), text));
            }
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Predicates.

fn store_name(enc: Enc) -> String {
    format!("store-{enc:?}")
}

/// Design section 14.1: a canary seeded in each encoding, inside random
/// text, is found in the store that holds it. The failure names the first
/// encoding the scanner missed.
fn finds_every_encoding(
    g: &mut Gen,
    scanner: Scanner<'_>,
    render: Render<'_>,
) -> Result<(), String> {
    let canary = gen_canary(g);
    let text = render(&canary)?;
    let mut stores = StoreSet::default();
    for enc in ENCODINGS {
        let before = context(g);
        let after = context(g);
        let at = before.len()..before.len() + text.len();
        let mut payload = before;
        payload.extend(text.as_bytes());
        payload.extend(after);
        let bytes = seed(g, enc, &payload, at);
        stores.stores.push((store_name(enc), bytes));
    }
    let report = scanner(&stores, std::slice::from_ref(&canary))?;
    for enc in ENCODINGS {
        let name = store_name(enc);
        if !report.hits.iter().any(|(s, c)| *s == name && *c == text) {
            return Err(format!("scanner missed the canary in encoding {enc:?}"));
        }
    }
    Ok(())
}

/// Design section 14.1: a scan reports exactly the canaries a store holds.
/// One store holds the target canary raw. Every other store holds, in one
/// encoding each, a near miss whose nonce differs in one bit. The report
/// must hold the target store's hit and nothing else. Base64 leaves up to
/// two bytes at each end of a text undetermined, so the flipped bit lies in
/// one of the first 15 nonce bytes.
fn reports_exact_hits(g: &mut Gen, scanner: Scanner<'_>, render: Render<'_>) -> Result<(), String> {
    let target = gen_canary(g);
    let mut near = target.clone();
    let byte = g.usize_in(0..=14);
    let bit = g.u8_in(0..=7);
    near.nonce[byte] ^= 1 << bit;
    let text = render(&target)?;
    let near_text = render(&near)?;
    let mut stores = StoreSet::default();
    stores
        .stores
        .push(("target".to_owned(), text.clone().into_bytes()));
    for enc in ENCODINGS {
        let bytes = seed(g, enc, near_text.as_bytes(), 0..near_text.len());
        stores.stores.push((format!("near-{enc:?}"), bytes));
    }
    let report = scanner(&stores, std::slice::from_ref(&target))?;
    let got: BTreeSet<(String, String)> = report.hits.into_iter().collect();
    let want: BTreeSet<(String, String)> = [("target".to_owned(), text)].into_iter().collect();
    if got == want {
        Ok(())
    } else {
        Err(format!("scanner reported {got:?}, expected {want:?}"))
    }
}

/// Runs `prop` against a mutant and requires a counterexample whose message
/// holds `expect`.
fn expect_caught(name: &str, expect: &str, prop: impl Fn(&mut Gen) -> Result<(), String>) {
    let outcome = run(name, Config::default(), prop);
    match outcome.failure() {
        Some(f) if f.kind == FailureKind::Counterexample && f.message.contains(expect) => {}
        Some(f) => panic!(
            "teeth {name}: failed as {:?} with {:?}, not with {expect:?}",
            f.kind, f.message
        ),
        None => panic!("teeth {name}: the mutant went undetected"),
    }
}

// ---------------------------------------------------------------------------
// Production tests: red until the harness scanner and renderer land.

/// I-19, I-17, I-38, I-80 instrument, design section 14.1: the harness
/// scanner finds a seeded canary in every encoding the section lists.
#[test]
fn harness_scan_finds_a_seeded_canary_in_every_encoding() {
    check(
        "harness_scan_finds_a_seeded_canary_in_every_encoding",
        |g| finds_every_encoding(g, &production_scan, &production_render),
    );
}

/// I-19, I-17, I-38, I-80 instrument, design section 14.1: the harness
/// scanner reports the stores that hold a canary and no near miss.
#[test]
fn harness_scan_reports_exactly_the_stores_that_hold_a_canary() {
    check(
        "harness_scan_reports_exactly_the_stores_that_hold_a_canary",
        |g| reports_exact_hits(g, &production_scan, &production_render),
    );
}

/// Design section 14.1: two canaries of two cells in two stores are each
/// reported for their own store only, and a store with neither, but with
/// the canary prefix, has no hit.
#[test]
fn harness_scan_attributes_each_hit_to_its_store_and_canary() {
    let a = Canary {
        cell: 1,
        kind: CanaryKind::Email,
        nonce: [0x11; 16],
    };
    let b = Canary {
        cell: 2,
        kind: CanaryKind::Email,
        nonce: [0x22; 16],
    };
    let (ta, tb) = (a.render().unwrap(), b.render().unwrap());
    let mut stores = StoreSet::default();
    stores
        .stores
        .push(("cell-1-db".to_owned(), ta.clone().into_bytes()));
    stores
        .stores
        .push(("cell-2-log".to_owned(), base64(tb.as_bytes(), B64, true)));
    stores
        .stores
        .push(("control-plane".to_owned(), b"CNRY- heartbeat".to_vec()));
    let report = fstp_celltest::scan::scan(&stores, &[a, b]).unwrap();
    let got: BTreeSet<(String, String)> = report.hits.into_iter().collect();
    let want: BTreeSet<(String, String)> =
        [("cell-1-db".to_owned(), ta), ("cell-2-log".to_owned(), tb)]
            .into_iter()
            .collect();
    assert_eq!(got, want);
}

// ---------------------------------------------------------------------------
// Controls: the predicates hold for the reference scanner.

fn full_reference(stores: &StoreSet, canaries: &[Canary]) -> Result<ScanReport, String> {
    reference_scan(stores, canaries, &ENCODINGS)
}

/// Control for `harness_scan_finds_a_seeded_canary_in_every_encoding`.
#[test]
fn harness_scan_control_reference_finds_every_encoding() {
    check("harness_scan_control_reference_finds_every_encoding", |g| {
        finds_every_encoding(g, &full_reference, &reference_render)
    });
}

/// Control for `harness_scan_reports_exactly_the_stores_that_hold_a_canary`.
#[test]
fn harness_scan_control_reference_reports_exact_hits() {
    check("harness_scan_control_reference_reports_exact_hits", |g| {
        reports_exact_hits(g, &full_reference, &reference_render)
    });
}

// ---------------------------------------------------------------------------
// Teeth: a scanner that skips one encoding is caught, and the failure names
// that encoding.

fn skipping(skip: &'static [Enc]) -> impl Fn(&StoreSet, &[Canary]) -> Result<ScanReport, String> {
    move |stores, canaries| {
        let rest: Vec<Enc> = ENCODINGS
            .into_iter()
            .filter(|e| !skip.contains(e))
            .collect();
        reference_scan(stores, canaries, &rest)
    }
}

/// Runs the every-encoding predicate against the reference without the
/// matchers in `skip`, and requires the failure to name `expect`.
fn teeth_skip(skip: &'static [Enc], expect: &str) {
    let mutant = skipping(skip);
    expect_caught(
        &format!("harness_scan_teeth_skipping_{skip:?}"),
        expect,
        |g| finds_every_encoding(g, &mutant, &reference_render),
    );
}

/// Teeth: a scanner without the raw matcher is caught.
#[test]
fn harness_scan_teeth_skipping_raw_is_caught() {
    teeth_skip(&[Enc::Raw], "encoding Raw");
}

/// Teeth: a scanner without the lowercase hex matcher is caught.
#[test]
fn harness_scan_teeth_skipping_hex_lower_is_caught() {
    teeth_skip(&[Enc::HexLower], "encoding HexLower");
}

/// Teeth: a scanner without the uppercase hex matcher is caught.
#[test]
fn harness_scan_teeth_skipping_hex_upper_is_caught() {
    teeth_skip(&[Enc::HexUpper], "encoding HexUpper");
}

/// Teeth: a scanner without either base64 matcher is caught.
///
/// Canary text is ASCII letters, digits and dashes. A base64 group takes
/// the value 62 or 63 only from bytes such as `>`, `?`, `~` or bytes of
/// 0x80 and above, so for canary text the two alphabets give the same
/// characters. A scanner with one of the two matchers sees both encodings,
/// so only dropping both leaves it blind.
#[test]
fn harness_scan_teeth_skipping_base64_and_base64url_is_caught() {
    teeth_skip(&[Enc::Base64, Enc::Base64Url], "encoding Base64");
}

/// Teeth: a scanner that matches base64 at one byte alignment only is
/// caught, since the context before a canary has a random length.
#[test]
fn harness_scan_teeth_base64_at_one_alignment_only_is_caught() {
    let aligned_only = |stores: &StoreSet, canaries: &[Canary]| -> Result<ScanReport, String> {
        let rest: Vec<Enc> = ENCODINGS
            .into_iter()
            .filter(|e| !matches!(e, Enc::Base64 | Enc::Base64Url))
            .collect();
        let mut report = reference_scan(stores, canaries, &rest)?;
        for (name, bytes) in &stores.stores {
            for c in canaries {
                let text = reference_render(c)?;
                let whole = &text.as_bytes()[..text.len() / 3 * 3];
                let found = contains(bytes, &base64(whole, B64, false))
                    || contains(bytes, &base64(whole, B64URL, false));
                if found && !report.hits.iter().any(|(s, t)| s == name && *t == text) {
                    report.hits.push((name.clone(), text));
                }
            }
        }
        Ok(report)
    };
    expect_caught(
        "harness_scan_teeth_base64_at_one_alignment_only",
        "encoding Base64",
        |g| finds_every_encoding(g, &aligned_only, &reference_render),
    );
}

/// Teeth: a scanner without the percent-encoding matcher is caught.
#[test]
fn harness_scan_teeth_skipping_percent_is_caught() {
    teeth_skip(&[Enc::Percent], "encoding Percent");
}

/// Teeth: a scanner without the JSON escaping matcher is caught.
#[test]
fn harness_scan_teeth_skipping_json_escape_is_caught() {
    teeth_skip(&[Enc::JsonEscape], "encoding JsonEscape");
}

/// Teeth: a scanner without the UTF-16LE matcher is caught.
#[test]
fn harness_scan_teeth_skipping_utf16le_is_caught() {
    teeth_skip(&[Enc::Utf16Le], "encoding Utf16Le");
}

/// Teeth: a scanner that matches only on the canary's fixed prefix, and so
/// reports near misses, is caught by the exact-hits predicate.
#[test]
fn harness_scan_teeth_prefix_matching_scanner_is_caught() {
    let sloppy = |stores: &StoreSet, canaries: &[Canary]| -> Result<ScanReport, String> {
        let mut report = ScanReport::default();
        for (name, bytes) in &stores.stores {
            for c in canaries {
                let text = reference_render(c)?;
                let prefix = &text.as_bytes()[..text.len() - 32];
                if ENCODINGS
                    .iter()
                    .any(|e| reference_matches(*e, bytes, prefix))
                {
                    report.hits.push((name.clone(), text));
                }
            }
        }
        Ok(report)
    };
    expect_caught(
        "harness_scan_teeth_prefix_matching_scanner",
        "scanner reported",
        |g| reports_exact_hits(g, &sloppy, &reference_render),
    );
}
