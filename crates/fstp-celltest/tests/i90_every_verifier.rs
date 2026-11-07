//! I-90 sweep over every composite verifier of the platform (M9 design
//! section 3, lane C1). A composite signature verifies only when both the
//! Ed25519 and the ML-DSA-65 halves verify.
//!
//! [`VERIFIERS`] is one table of every shipped verifier entry point that
//! reaches `fstp_crypto::composite`. Each row signs an artifact the way
//! production does and checks it through the production verifier. The
//! sweep then gives each verifier a signature with a valid Ed25519 half
//! and a broken ML-DSA-65 half, and the reverse. Each half is broken by
//! bit flips and by a splice with the same key's signature over another
//! artifact, so the other half stays a genuine signature.
//!
//! [`i90_every_composite_verify_call_site_is_in_the_table`] scans the
//! shipped sources. A new `composite::verify*` call site that no row
//! names fails it, so a new verifier cannot skip the sweep. Lane C2 adds
//! the notice companion row.
//!
//! The layout is draft 19 section 4.3: `mldsaSig || tradSig`. Code outside
//! `fstp-crypto` splits it with `composite::MLDSA_SIGNATURE_LEN` (I-75).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fstp_audit::anchor::{
    RECEIPT_CONTEXT, anchor_signature_verifies, receipt_signature_verifies, sign_anchor,
};
use fstp_audit::chain::{ChainId, Link};
use fstp_audit::{Anchor, CellId, Receipt, ReceiptFields};
use fstp_auth::codec::encode_operator_ticket;
use fstp_auth::recovery::{OperatorTicket, StaffRef, TicketKind, verify_ticket_as};
use fstp_crypto::composite::{self, CompositeSigningKey, MLDSA_SIGNATURE_LEN, SIGNATURE_LEN};
use fstp_release::metadata::{
    METADATA_BODY_LEN, METADATA_CONTEXT, METADATA_MAGIC, ReleaseSigningKey, verify_metadata,
};

/// Signs artifact variant `v` with `key` the way production does, and
/// returns the composite signature bytes.
type Sign = fn(&CompositeSigningKey, u8) -> Vec<u8>;

/// Rebuilds artifact variant `v` with `sig` and runs the production
/// verifier under the composite public key `pk`.
type Verify = fn(&[u8], u8, &[u8]) -> bool;

/// A verifier the sweep runs: a row's [`Verify`] or a fake of the teeth test.
type DynVerify<'a> = dyn Fn(&[u8], u8, &[u8]) -> bool + 'a;

/// One composite verifier.
struct Verifier {
    /// What it verifies.
    name: &'static str,
    /// The shipped file that holds its `composite::verify*` call.
    site: &'static str,
    sign: Sign,
    verify: Verify,
}

/// Every composite verifier of the platform. A shipped file with a
/// `composite::verify*` call that no row names fails
/// [`i90_every_composite_verify_call_site_is_in_the_table`].
const VERIFIERS: [Verifier; 5] = [
    Verifier {
        name: "audit anchor (fstp_audit::anchor::anchor_signature_verifies)",
        site: "crates/fstp-audit/src/anchor.rs",
        sign: anchor_sign,
        verify: anchor_verify,
    },
    Verifier {
        name: "witness receipt (fstp_audit::anchor::receipt_signature_verifies)",
        site: "crates/fstp-audit/src/anchor.rs",
        sign: receipt_sign,
        verify: receipt_verify,
    },
    Verifier {
        name: "release metadata (fstp_release::metadata::verify_metadata)",
        site: "crates/fstp-release/src/metadata.rs",
        sign: metadata_sign,
        verify: metadata_verify,
    },
    Verifier {
        name: "recovery operator ticket (fstp_auth::recovery::verify_ticket_as)",
        site: "crates/fstp-auth/src/recovery.rs",
        sign: |k, v| ticket_sign(k, v, TicketKind::Recovery),
        verify: |pk, v, s| ticket_verify(pk, v, s, TicketKind::Recovery),
    },
    Verifier {
        name: "break-glass operator ticket (fstp_auth::recovery::verify_ticket_as)",
        site: "crates/fstp-auth/src/recovery.rs",
        sign: |k, v| ticket_sign(k, v, TicketKind::BreakGlass),
        verify: |pk, v, s| ticket_verify(pk, v, s, TicketKind::BreakGlass),
    },
];

// ------------------------------------------------------------- the rows

fn anchor_parts(v: u8) -> (CellId, ChainId, u64, Link, i64) {
    (
        CellId([v; 16]),
        ChainId::App,
        u64::from(v) + 1,
        Link([v ^ 0x5a; 32]),
        i64::from(v) * 1_000,
    )
}

fn anchor_sign(key: &CompositeSigningKey, v: u8) -> Vec<u8> {
    let (cell, chain, n, link, at) = anchor_parts(v);
    sign_anchor(key, cell, chain, n, &link, at)
        .unwrap()
        .signature
}

fn anchor_verify(pk: &[u8], v: u8, sig: &[u8]) -> bool {
    let (cell, chain, n, link, at) = anchor_parts(v);
    let a = Anchor {
        cell,
        chain,
        n,
        link,
        at,
        signature: sig.to_vec(),
    };
    anchor_signature_verifies(&a, &[pk.to_vec()])
}

fn receipt(v: u8, signature: Vec<u8>) -> Receipt {
    Receipt {
        cell: CellId([v; 16]),
        chain: ChainId::Vault,
        fields: ReceiptFields {
            n: u64::from(v) + 7,
            link: Link([v; 32]),
            witness_seq: u64::from(v) + 1,
            witness_link: Link([v ^ 0xa5; 32]),
            received_at: i64::from(v) * 2_000,
        },
        signature,
    }
}

fn receipt_sign(key: &CompositeSigningKey, v: u8) -> Vec<u8> {
    let message = receipt(v, Vec::new()).message();
    key.sign_with_context(&message, RECEIPT_CONTEXT)
        .unwrap()
        .to_bytes()
        .to_vec()
}

fn receipt_verify(pk: &[u8], v: u8, sig: &[u8]) -> bool {
    receipt_signature_verifies(&receipt(v, sig.to_vec()), &[pk.to_vec()])
}

/// A metadata body on the stable channel (code 1).
fn metadata_body(v: u8) -> Vec<u8> {
    let mut body = METADATA_MAGIC.to_vec();
    body.push(1);
    body.extend_from_slice(&u64::from(v).to_be_bytes());
    body.extend_from_slice(&[0, 1, 0, 2, 0, v]);
    body.extend_from_slice(&i64::MAX.to_be_bytes());
    body.extend_from_slice(&[v; 32]);
    assert_eq!(body.len(), METADATA_BODY_LEN);
    body
}

fn metadata_sign(key: &CompositeSigningKey, v: u8) -> Vec<u8> {
    key.sign_with_context(&metadata_body(v), METADATA_CONTEXT)
        .unwrap()
        .to_bytes()
        .to_vec()
}

fn metadata_verify(pk: &[u8], v: u8, sig: &[u8]) -> bool {
    let mut bytes = metadata_body(v);
    bytes.extend_from_slice(sig);
    verify_metadata(&bytes, &ReleaseSigningKey::from_bytes(pk).unwrap()).is_ok()
}

fn ticket(v: u8) -> OperatorTicket {
    OperatorTicket {
        case: [v; 16],
        staff_1: StaffRef([v ^ 1; 16]),
        staff_2: StaffRef([v ^ 2; 16]),
    }
}

fn ticket_sign(key: &CompositeSigningKey, v: u8, kind: TicketKind) -> Vec<u8> {
    key.sign_with_context(&ticket(v).message(), kind.context())
        .unwrap()
        .to_bytes()
        .to_vec()
}

fn ticket_verify(pk: &[u8], v: u8, sig: &[u8], kind: TicketKind) -> bool {
    let bytes = encode_operator_ticket(&ticket(v), sig).unwrap();
    verify_ticket_as(&bytes, pk, kind).is_ok()
}

// ------------------------------------------------------------- the sweep

/// The variant every sweep signs and checks, and the other one whose
/// signature supplies the spliced halves.
const THIS: u8 = 0x31;
const OTHER: u8 = 0x47;

/// Byte offsets flipped inside the ML-DSA-65 half: its start, the end of
/// `c~`, its middle and its last byte (the hint).
const MLDSA_FLIPS: [usize; 4] = [0, 47, MLDSA_SIGNATURE_LEN / 2, MLDSA_SIGNATURE_LEN - 1];
/// Byte offsets flipped inside the Ed25519 half: `R` and `S`, first and last.
const ED25519_FLIPS: [usize; 4] = [
    MLDSA_SIGNATURE_LEN,
    MLDSA_SIGNATURE_LEN + 31,
    MLDSA_SIGNATURE_LEN + 32,
    SIGNATURE_LEN - 1,
];

/// The signatures of the sweep for a valid signature `good` over
/// [`THIS`] and `other` over [`OTHER`], by the same key. Each one has
/// exactly one half that is not a valid signature over this artifact.
fn one_half_broken(good: &[u8], other: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (half, flips) in [("ML-DSA-65", MLDSA_FLIPS), ("Ed25519", ED25519_FLIPS)] {
        for at in flips {
            let mut s = good.to_vec();
            s[at] ^= 0x01;
            out.push((format!("{half} half with byte {at} flipped"), s));
        }
    }
    let mut s = other[..MLDSA_SIGNATURE_LEN].to_vec();
    s.extend_from_slice(&good[MLDSA_SIGNATURE_LEN..]);
    out.push((
        "ML-DSA-65 half from another artifact, valid Ed25519 half".to_string(),
        s,
    ));
    let mut s = good[..MLDSA_SIGNATURE_LEN].to_vec();
    s.extend_from_slice(&other[MLDSA_SIGNATURE_LEN..]);
    out.push((
        "valid ML-DSA-65 half, Ed25519 half from another artifact".to_string(),
        s,
    ));
    let mut s = vec![0; MLDSA_SIGNATURE_LEN];
    s.extend_from_slice(&good[MLDSA_SIGNATURE_LEN..]);
    out.push(("zero ML-DSA-65 half, valid Ed25519 half".to_string(), s));
    let mut s = good[..MLDSA_SIGNATURE_LEN].to_vec();
    s.extend_from_slice(&[0; SIGNATURE_LEN - MLDSA_SIGNATURE_LEN]);
    out.push(("valid ML-DSA-65 half, zero Ed25519 half".to_string(), s));
    out
}

/// The I-90 sweep of one row: the untouched signature verifies, and every
/// signature of [`one_half_broken`] is refused.
fn sweep(name: &str, sign: Sign, verify: &DynVerify<'_>) -> Result<(), String> {
    let key = composite::generate().unwrap();
    let pk = key.public_key().to_bytes().to_vec();
    let good = sign(&key, THIS);
    let other = sign(&key, OTHER);
    if good.len() != SIGNATURE_LEN || other.len() != SIGNATURE_LEN {
        return Err(format!("{name}: a signature of {} bytes", good.len()));
    }
    if good == other {
        return Err(format!("{name}: the two artifacts sign alike"));
    }
    if !verify(&pk, THIS, &good) {
        return Err(format!("{name}: the untouched signature was refused"));
    }
    if !verify(&pk, OTHER, &other) {
        return Err(format!(
            "{name}: the other artifact's signature was refused"
        ));
    }
    for (what, sig) in one_half_broken(&good, &other) {
        if verify(&pk, THIS, &sig) {
            return Err(format!("I-90: {name} accepted a signature with {what}"));
        }
    }
    Ok(())
}

/// I-90 (M9 design section 3): every composite verifier of the platform
/// rejects a signature with a valid Ed25519 half and a corrupted ML-DSA-65
/// half, and the reverse, and accepts the untouched signature.
#[test]
fn i90_every_verifier_rejects_one_half() {
    let mut failed = Vec::new();
    for v in &VERIFIERS {
        if let Err(e) = sweep(v.name, v.sign, &v.verify) {
            failed.push(e);
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

/// I-90, teeth: the sweep fails a verifier that checks one half only. Each
/// fake remembers the first signature it accepts for each artifact. Later
/// it checks a signature with the ignored half taken from that one, which
/// is a verifier whose check of one half was dropped.
#[test]
fn i90_teeth_sweep_fails_a_one_half_verifier() {
    use std::cell::RefCell;
    for (half, ignored) in [
        ("Ed25519 only", 0..MLDSA_SIGNATURE_LEN),
        ("ML-DSA-65 only", MLDSA_SIGNATURE_LEN..SIGNATURE_LEN),
    ] {
        let seen: RefCell<BTreeMap<u8, Vec<u8>>> = RefCell::new(BTreeMap::new());
        let verify = |pk: &[u8], v: u8, sig: &[u8]| {
            let first = seen.borrow().get(&v).cloned();
            match first {
                None => {
                    let ok = anchor_verify(pk, v, sig);
                    if ok {
                        seen.borrow_mut().insert(v, sig.to_vec());
                    }
                    ok
                }
                Some(good) => {
                    let mut mixed = sig.to_vec();
                    mixed[ignored.clone()].copy_from_slice(&good[ignored.clone()]);
                    anchor_verify(pk, v, &mixed)
                }
            }
        };
        assert!(
            sweep(half, anchor_sign, &verify).is_err(),
            "the sweep passed a verifier that checks the {half} half"
        );
    }
}

// --------------------------------------------------------- the call sites

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The crates whose sources may call `composite::verify*` without a row:
/// the primitive itself, and the test-only harness.
const NOT_SHIPPED_OR_PRIMITIVE: [&str; 2] = ["crates/fstp-crypto/", "crates/fstp-celltest/"];

/// The shipped `.rs` files below `dir`: no `tests`, `benches`, `examples`,
/// `fuzz` or `target` directory.
fn shipped_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if ![
                "tests",
                "benches",
                "examples",
                "fuzz",
                "target",
                ".git",
                "node_modules",
            ]
            .contains(&name.as_ref())
            {
                shipped_rs(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// `text` without `//` and `/* */` comments. String contents stay, which
/// can only add findings.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("//") {
            rest = r.find('\n').map_or("", |i| &r[i..]);
        } else if let Some(r) = rest.strip_prefix("/*") {
            rest = r.find("*/").map_or("", |i| &r[i + 2..]);
            out.push(' ');
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `code` with all whitespace removed, except one space between two
/// identifier characters.
fn squeeze(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut pending = false;
    for c in code.chars() {
        if c.is_whitespace() {
            pending = true;
            continue;
        }
        if pending && ident_char(c) && out.chars().next_back().is_some_and(ident_char) {
            out.push(' ');
        }
        pending = false;
        out.push(c);
    }
    out
}

/// The positions in `flat` where the whole identifier `word` starts.
fn word_at(flat: &str, word: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = flat[from..].find(word) {
        let start = from + at;
        from = start + word.len();
        let before = flat[..start].chars().next_back().is_some_and(ident_char);
        let after = flat[from..].chars().next().is_some_and(ident_char);
        if !before && !after {
            out.push(start);
        }
    }
    out
}

/// How many composite verify sites `code` holds: each `verify_with_context`
/// identifier, each `composite::verify` path, and each `verify` imported
/// through a `composite::{..}` group. A glob or a rename of `composite`
/// counts too, since the scan could not follow it.
fn verify_sites(code: &str) -> usize {
    let flat = squeeze(&strip_comments(code));
    let mut n = word_at(&flat, "verify_with_context").len();
    for at in word_at(&flat, "composite") {
        let rest = &flat[at + "composite".len()..];
        if let Some(path) = rest.strip_prefix("::verify") {
            if !path.chars().next().is_some_and(ident_char) {
                n += 1;
            }
        } else if let Some(group) = rest.strip_prefix("::{") {
            let inner = group.split('}').next().unwrap_or("");
            n += inner
                .split([',', '{'])
                .filter(|item| item.trim() == "verify" || item.trim().starts_with("verify as "))
                .count();
            if inner.split(',').any(|i| i.trim() == "*") {
                n += 1;
            }
        } else if rest.starts_with("::*") || rest.starts_with(" as ") {
            n += 1;
        }
    }
    n
}

/// The shipped files with composite verify sites, relative to the
/// repository root, with their count.
fn call_sites(root: &Path) -> BTreeMap<String, usize> {
    let mut files = Vec::new();
    shipped_rs(&root.join("crates"), &mut files);
    shipped_rs(&root.join("tools"), &mut files);
    let mut out = BTreeMap::new();
    for p in files {
        let rel = p
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if NOT_SHIPPED_OR_PRIMITIVE.iter().any(|s| rel.starts_with(s)) {
            continue;
        }
        let n = verify_sites(&fs::read_to_string(&p).unwrap());
        if n > 0 {
            out.insert(rel, n);
        }
    }
    out
}

/// I-90 (M9 design section 3): every shipped file that calls
/// `composite::verify*` is a site of [`VERIFIERS`], and each site holds
/// exactly one call. A new verifier that is not in the table fails here.
#[test]
fn i90_every_composite_verify_call_site_is_in_the_table() {
    let found = call_sites(&repo_root());
    let mut table: BTreeMap<String, usize> = BTreeMap::new();
    for v in &VERIFIERS {
        table.insert(v.site.to_string(), 1);
    }
    assert_eq!(
        found, table,
        "I-90: the composite verify call sites differ from the VERIFIERS table; \
         add a row with its sweep for each new site"
    );
}

/// I-90, teeth: the call-site scan sees a call by path, an imported
/// function, a group import, a glob and a rename, and skips comments.
#[test]
fn i90_teeth_call_site_scan_sees_each_form() {
    for code in [
        "fn f() { fstp_crypto::composite::verify_with_context(k, m, c, s).is_ok() }",
        "fn f() { composite::verify(k, m, s) }",
        "use fstp_crypto::composite::verify;",
        "use fstp_crypto::composite::{self, verify};",
        "use fstp_crypto::composite::{CompositePublicKey,\n    verify as v};",
        "use fstp_crypto::composite::*;",
        "use fstp_crypto::composite::{self, *};",
        "use fstp_crypto::composite as c;",
        "use fstp_crypto::{composite::{verify_with_context}};",
    ] {
        assert!(verify_sites(code) > 0, "{code}");
    }
    for code in [
        "// composite::verify(k, m, s)\nfn f() {}",
        "/* verify_with_context */ fn f() {}",
        "use fstp_crypto::composite::{CompositeSigningKey, SIGNATURE_LEN};",
        "fn f() { composite::verify_key_len(); }",
        "fn verify_metadata() {}",
    ] {
        assert_eq!(verify_sites(code), 0, "{code}");
    }
}

/// I-90, teeth: a planted shipped call site is found, while the same call
/// in a test directory, a fuzz target or `fstp-crypto` itself is not.
#[test]
fn i90_teeth_call_site_scan_finds_a_planted_verifier() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("i90_planted_site");
    let _ = fs::remove_dir_all(&root);
    let call = "fn f(k: &[u8], m: &[u8], s: &[u8]) -> bool {\n    \
                fstp_crypto::composite::verify(k, m, s).is_ok()\n}\n";
    for rel in [
        "crates/fstp-notice/src/companion.rs",
        "crates/fstp-notice/tests/t.rs",
        "crates/fstp-notice/fuzz/fuzz_targets/f.rs",
        "crates/fstp-crypto/src/composite.rs",
    ] {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, call).unwrap();
    }
    let mut want = BTreeMap::new();
    want.insert("crates/fstp-notice/src/companion.rs".to_string(), 1);
    assert_eq!(call_sites(&root), want);
    fs::remove_dir_all(&root).unwrap();
}
