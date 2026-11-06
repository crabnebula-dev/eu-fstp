//! Increment verifier tests (ADR-016 threat list, M5 design section 3.1
//! step 4, I-30).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::sync::OnceLock;

use common::{Ctx, PARTIES, Parts, sig_body};
use fstp_pdf::increment::{CONTENTS_MAX, Expected};
use fstp_pdf::{
    IncrementError, ParseErrorKind, PdfFile, embed_signature, prepare_increment, verify_increment,
    write,
};
use fstp_prop::{check, prop_assert, prop_assert_eq};

fn base() -> &'static Ctx {
    static BASE: OnceLock<Ctx> = OnceLock::new();
    BASE.get_or_init(|| Ctx::new(write(&common::contract(12)).unwrap()))
}

/// ADR-016: the canonical increment is accepted, and the `/ByteRange`
/// covers every byte of the revision except the `/Contents` string. The
/// digest equals SHA-256 over exactly those bytes.
#[test]
fn adr_016_byte_range_covers_everything_but_contents() {
    let ctx = base();
    for party in PARTIES {
        for inc in [
            prepare_increment(&ctx.base, party, 8192).unwrap(),
            Parts::canonical(ctx, party).build(&ctx.base),
        ] {
            let v = verify_increment(&ctx.base, &inc, party).unwrap();
            let full = [ctx.base.as_slice(), &inc].concat();
            let [a, b, c, d] = v.byte_range.map(|x| x as usize);
            assert_eq!(a, 0);
            assert_eq!(b, v.contents.start);
            assert_eq!(c, v.contents.end);
            assert_eq!(c + d, full.len());
            assert_eq!(full[b], b'<');
            assert_eq!(full[c - 1], b'>');
            assert!(full[b + 1..c - 1].iter().all(|&x| x == b'0'));
            let covered = [&full[..b], &full[c..]].concat();
            assert_eq!(v.digest, fstp_crypto::sha256(&covered));
            assert_eq!(v.signature.num, ctx.sig_num);
        }
    }
}

/// The attack classes of ADR-016 and the error each must yield.
const ATTACKS: usize = 24;

fn attack(
    ctx: &Ctx,
    which: usize,
    g: &mut fstp_prop::Gen,
) -> (Vec<u8>, &'static str, IncrementError) {
    let party = *g.pick(&PARTIES);
    let mut p = Parts::canonical(ctx, party);
    let (fr, _) = ctx.field(party);
    let err = match which {
        // Shadow attack: an extra object replaces content of the revision.
        0 => {
            let n = *g.pick(&ctx.other_objects);
            let at = g.usize_in(0..=2);
            p.objects.insert(at, (n, 0, "<< /Type /Annot >>".into()));
            IncrementError::ObjectOutsideField { number: n }
        }
        // Duplicate object number.
        1 => {
            let dup = p.objects[0].clone();
            p.objects.push(dup);
            IncrementError::DuplicateObject { number: fr.num }
        }
        // Another party's field, set while signing as `party`.
        2 => {
            let other = *g.pick(
                &PARTIES
                    .iter()
                    .filter(|o| **o != party)
                    .copied()
                    .collect::<Vec<_>>(),
            );
            let (or, _) = ctx.field(other);
            p.objects[0] = (or.num, or.generation, ctx.field_body(other, ctx.sig_ref()));
            IncrementError::ObjectOutsideField { number: or.num }
        }
        // A field change beyond /V.
        3 => {
            let body = &p.objects[0].2;
            p.objects[0].2 = match g.u8_in(0..=2) {
                0 => body.replacen("/F 4", "/F 6", 1),
                1 => body.replacen("/FT /Sig", "/FT /Tx", 1),
                _ => body.replacen(">>", "/Ff 1>>", 1),
            };
            IncrementError::FieldChanged
        }
        // /V names another object.
        4 => {
            let v = format!("/V {} 0 R", ctx.sig_num);
            p.objects[0].2 = p.objects[0]
                .2
                .replacen(&v, &format!("/V {} 0 R", ctx.root.num), 1);
            IncrementError::FieldValue
        }
        5 => {
            p.objects[1].2 =
                p.objects[1]
                    .2
                    .replacen("ETSI.CAdES.detached", "adbe.pkcs7.detached", 1);
            IncrementError::SignatureDictionary("SubFilter")
        }
        6 => {
            p.objects[1].2 =
                p.objects[1]
                    .2
                    .replacen("/Type /Sig", "/Type /Sig /Reference [<< >>]", 1);
            IncrementError::SignatureDictionary("unknown key")
        }
        // A pre-filled /Contents, not a placeholder.
        7 => {
            p.objects[1].2 = p.objects[1].2.replacen("<0000", "<3082", 1);
            IncrementError::ContentsPlaceholder
        }
        8 => {
            p.objects[1].2 = sig_body(CONTENTS_MAX + 1);
            IncrementError::ContentsPlaceholder
        }
        // /ByteRange gap before /Contents.
        9 => {
            p.byte_range = |[a, b, c, d]| [a, b - 1, c, d];
            IncrementError::ByteRangeGap
        }
        // /ByteRange overlapping /Contents.
        10 => {
            p.byte_range = |[a, b, c, d]| [a, b + 1, c, d];
            IncrementError::ByteRangeOverlap
        }
        11 => {
            p.byte_range = |[a, b, c, d]| [a, b, c - 1, d + 1];
            IncrementError::ByteRangeOverlap
        }
        // /ByteRange short of the end.
        12 => {
            p.byte_range = |[a, b, c, d]| [a, b, c, d - 1];
            IncrementError::ByteRangeGap
        }
        13 => {
            p.byte_range = |[a, b, c, d]| [a, b, c, d + 1];
            IncrementError::ByteRangeBeyondEnd
        }
        14 => {
            p.trailer = p.trailer.replacen(
                &format!("/Root {} 0 R", ctx.root.num),
                &format!("/Root {} 0 R", ctx.other_objects[1]),
                1,
            );
            IncrementError::Trailer("Root")
        }
        15 => {
            p.trailer = p
                .trailer
                .replacen(&format!("/Prev {}", ctx.prev), "/Prev 9", 1);
            IncrementError::Trailer("Prev")
        }
        16 => {
            p.trailer = p.trailer.replacen("/Size", "/Encrypt 1 0 R /Size", 1);
            IncrementError::Trailer("dictionary")
        }
        17 => {
            p.startxref_delta = g.i64_in(1..=40);
            IncrementError::StartXref
        }
        // An xref entry off its object.
        18 => {
            p.xref = Some(vec![
                (fr.num, g.i64_in(1..=9), fr.generation),
                (ctx.sig_num, 0, 0),
            ]);
            IncrementError::XrefMismatch
        }
        // A second update after %%EOF.
        19 => {
            p.after = b"1 0 obj\n<< >>\nendobj\n".to_vec();
            IncrementError::TrailingBytes
        }
        // A comment hiding bytes between objects.
        20 => {
            p.between = "%hidden\n".into();
            IncrementError::Parse(fstp_pdf::ParseError {
                offset: 0,
                kind: ParseErrorKind::Comment,
            })
        }
        // A stream, such as an object stream, in the increment.
        21 => {
            p.objects[1].2 = "<< /Type /ObjStm /Length 2 >>\nstream\nab\nendstream".into();
            IncrementError::StreamInIncrement
        }
        22 => {
            p.objects.pop();
            IncrementError::MissingObject(Expected::Signature)
        }
        _ => {
            p.objects[1].1 = 1;
            IncrementError::GenerationMismatch {
                number: ctx.sig_num,
            }
        }
    };
    g.note("party", &party);
    (p.build(&ctx.base), party, err)
}

/// Compares errors, ignoring the offset inside a parse error.
fn same_class(a: &IncrementError, b: &IncrementError) -> bool {
    match (a, b) {
        (IncrementError::Parse(x), IncrementError::Parse(y)) => x.kind == y.kind,
        _ => a == b,
    }
}

/// I-30, ADR-016: the verifier refuses each attack class with its typed
/// error: shadow objects, duplicate numbers, other fields, field changes,
/// malformed signature dictionaries, placeholders, `/ByteRange` gaps and
/// overlaps, trailer and xref faults, trailing updates, comments and
/// streams. No party name accepts the increment.
#[test]
fn i_30_adr_016_verifier_refuses_each_attack_class() {
    let ctx = base();
    check("i_30_adr_016_verifier_refuses_each_attack_class", |g| {
        let which = g.usize_in(0..=ATTACKS - 1);
        g.note("attack", &which);
        let (inc, party, want) = attack(ctx, which, g);
        let got = verify_increment(&ctx.base, &inc, party);
        g.note("got", &got);
        prop_assert!(
            matches!(&got, Err(e) if same_class(e, &want)),
            "attack {which} for {party}: want {want:?}, got {got:?}"
        );
        // Attack 2 is a valid increment for the other party it names.
        for other in PARTIES.iter().filter(|_| which != 2) {
            prop_assert!(
                verify_increment(&ctx.base, &inc, other).is_err(),
                "attack {which} accepted for {other}"
            );
        }
        Ok(())
    });
}

/// I-30: random byte changes to a valid increment are refused, or accepted
/// only with the same two objects, an exact `/ByteRange` and every other
/// object of the revision unchanged.
#[test]
fn i_30_mutated_increments_never_change_another_object() {
    let ctx = base();
    let party = "member-1";
    let good = Parts::canonical(ctx, party).build(&ctx.base);
    // The unmutated increment is accepted, so every refusal below is due
    // to a mutation.
    assert!(verify_increment(&ctx.base, &good, party).is_ok());
    let before = PdfFile::open(&ctx.base).unwrap();
    check("i_30_mutated_increments_never_change_another_object", |g| {
        let mut inc = good.clone();
        let edits = g.usize_in(1..=3);
        for _ in 0..edits {
            let at = g.usize_in(0..=inc.len() - 1);
            match g.u8_in(0..=2) {
                0 => inc[at] = g.u8(),
                1 => {
                    inc.remove(at);
                }
                _ => inc.insert(at, *g.pick(b" \n0123456789/<>[]()R%")),
            }
        }
        let Ok(v) = verify_increment(&ctx.base, &inc, party) else {
            return Ok(());
        };
        let full = [ctx.base.as_slice(), &inc].concat();
        let after = PdfFile::open(&full).map_err(|e| format!("accepted but unreadable: {e}"))?;
        prop_assert_eq!(after.size(), ctx.sig_num + 1);
        for (num, entry) in before.xref() {
            if *num == v.field.num || !entry.in_use {
                continue;
            }
            prop_assert_eq!(after.xref().get(num), Some(entry));
        }
        prop_assert_eq!(v.byte_range[0], 0);
        prop_assert_eq!(v.byte_range[1] as usize, v.contents.start);
        prop_assert_eq!((v.byte_range[2] + v.byte_range[3]) as usize, full.len());
        Ok(())
    });
}

/// I-30: each later revision has every earlier revision as exact byte
/// prefix, each party signs once, and a signed field refuses a second
/// increment.
#[test]
fn i_30_revisions_chain_by_exact_prefix() {
    let ctx = base();
    let mut revision = ctx.base.clone();
    for (i, party) in PARTIES.iter().enumerate() {
        let inc = prepare_increment(&revision, party, 4096).unwrap();
        let v = verify_increment(&revision, &inc, party).unwrap();
        // A synthetic stand-in for the CMS value; the real one comes from
        // the wallet or QTSP through fstp-pki::cms.
        let cms = vec![0x30, 0x82, 0x01, i as u8];
        let next = embed_signature(&revision, &inc, &v, &cms).unwrap();
        assert!(next.starts_with(&revision));
        let covered = [&next[..v.contents.start], &next[v.contents.end..]].concat();
        assert_eq!(fstp_crypto::sha256(&covered), v.digest);
        let again = prepare_increment(&next, party, 4096);
        assert_eq!(again, Err(IncrementError::FieldAlreadySigned));
        revision = next;
    }
    PdfFile::open(&revision).unwrap().parse_all().unwrap();
}

/// ADR-016: the CMS value must fit the verified placeholder, and only the
/// verified inputs can be filled.
#[test]
fn adr_016_embedding_is_bounded_to_the_placeholder() {
    let ctx = base();
    let inc = prepare_increment(&ctx.base, "lead", 1024).unwrap();
    let v = verify_increment(&ctx.base, &inc, "lead").unwrap();
    assert_eq!(
        embed_signature(&ctx.base, &inc, &v, &[1u8; 1025]),
        Err(IncrementError::SignatureTooLarge)
    );
    assert!(embed_signature(&ctx.base, &inc, &v, &[1u8; 1024]).is_ok());
    assert_eq!(
        embed_signature(&ctx.base, &inc[1..], &v, &[1u8; 4]),
        Err(IncrementError::PlaceholderMismatch)
    );
}

/// ADR-016: a party name without a field is refused.
#[test]
fn adr_016_unknown_party_is_refused() {
    let ctx = base();
    let inc = Parts::canonical(ctx, "lead").build(&ctx.base);
    assert_eq!(
        verify_increment(&ctx.base, &inc, "stranger"),
        Err(IncrementError::FieldNotFound)
    );
}

/// TH-26, ADR-016: the committed seeds of the `increment_verify` fuzz
/// target are the canonical increments of the synthetic fuzz base, so
/// they stay valid. With `FSTP_WRITE_FUZZ_SEEDS=1`, or when a seed is
/// missing, the test writes them.
#[test]
fn th_26_increment_fuzz_seeds_are_current() {
    let doc = fstp_pdf::Document {
        title: "Sub-grant agreement SYN-0001".into(),
        lang: "en".into(),
        blocks: vec![fstp_pdf::Block {
            kind: fstp_pdf::BlockKind::Paragraph,
            text: "Synthetic clause for the fuzz base.".into(),
        }],
        signature_fields: PARTIES
            .iter()
            .map(|p| fstp_pdf::SignatureField {
                name: (*p).into(),
                label: format!("Signature of {p}"),
            })
            .collect(),
    };
    let base = write(&doc).unwrap();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/increment_verify");
    let force = std::env::var("FSTP_WRITE_FUZZ_SEEDS").is_ok_and(|v| v == "1");
    for party in PARTIES {
        let seed = prepare_increment(&base, party, 1024).unwrap();
        assert!(verify_increment(&base, &seed, party).is_ok());
        let path = dir.join(party);
        if force || !path.exists() {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &seed).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), seed, "stale seed {party}");
    }
}
