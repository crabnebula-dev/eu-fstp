//! I-90: a composite signature verifies only when both the Ed25519 and
//! the ML-DSA-65 halves verify. I-90 is an M9 exit, and design section 7.4
//! runs it for anchors in M3. These are T-CR-COMPOSITE tests for TH-67.
//!
//! Lane W1e wrote these tests before the production code. They are red
//! until `fstp_crypto::composite` signs and verifies (lane dsa), its key
//! exposes its public key (`PUBLIC_KEY_SEAM`), and `fstp_audit::verify`
//! takes the anchor key history and the witness log (`VERIFY_SEAM`, lane
//! W2g).
//!
//! No test assumes a byte layout of the production composite signature.
//! The production sweep flips every byte and splices at every offset, so
//! whatever the draft 19 layout is, each half is covered. The anchor
//! verifier's sweep runs over signatures that the backend makes with its
//! own keys (`AuditBackend::sign_view`), never over reference ones. The
//! production keys stay inside the backend. The reference
//! sweep and its teeth use `reference::audit::test_encoding`, which is
//! the reference's own layout.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::audit_model::{
    AuditBackend, AuditDefect, Mutant, OpaqueRowSigs, OpaqueSigs, Production, Reference,
    prod_composite_public_key,
};
use fstp_celltest::reference::audit::{
    self as r, Forgery, KeyRole, Keys, Mutation, RefChain, RefChainView, RefPublicKey, RefSig,
    RefTamper, RowSpec, SigCheck, SymChain, test_encoding,
};
use fstp_crypto::composite;

const MSG: &[u8] = b"fstp i90 anchor message";
const OTHER: &[u8] = b"fstp i90 another message";

/// The halves of a signature an attacker can change without a key.
const HALF_FORGERIES: [Forgery; 6] = [
    Forgery::AnchorSigEd25519,
    Forgery::AnchorSigMlDsa,
    Forgery::AnchorEd25519FromAnotherMessage,
    Forgery::AnchorMlDsaFromAnotherMessage,
    Forgery::ReceiptSigEd25519,
    Forgery::ReceiptSigMlDsa,
];

/// The I-90 teeth twin of the anchor verifier's signature check.
struct EitherHalf;

impl SigCheck for EitherHalf {
    fn verifies(&self, pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
        r::either_half_verifies(pk, message, sig)
    }
}

fn chain(c: RefChain) -> SymChain {
    let mut s = SymChain::genesis([0x90; 16], c);
    s.append(
        &[RowSpec::Event {
            at: 1,
            body: b"login".to_vec(),
        }],
        2,
    )
    .unwrap();
    s.append(
        &[RowSpec::Ledger {
            at: 3,
            command: [3; 16],
            schema: 1,
            key_ix: 0,
            body: b"grant".to_vec(),
        }],
        4,
    )
    .unwrap();
    s
}

/// The anchor rule of I-90: the untouched chain verifies, and a chain
/// whose anchor or receipt has one half changed, or taken from a
/// signature over another message, does not.
fn rejects_half_forgeries(
    keys: &Keys,
    verify: &dyn Fn(&RefChainView) -> Result<(), String>,
) -> Result<(), String> {
    for c in RefChain::ALL {
        let s = chain(c);
        verify(&keys.materialize(&s).unwrap())
            .map_err(|t| format!("the untouched {c:?} chain was refused: {t}"))?;
        for a in 0..s.store.anchors.len() {
            for f in HALF_FORGERIES {
                let t = r::apply(&s, Mutation::Anchor(a, f)).unwrap();
                if verify(&keys.materialize(&t).unwrap()).is_ok() {
                    return Err(format!(
                        "I-90: anchor row {a} of the {c:?} chain verified with {f:?}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// One signature of an anchor row, picked out of its pair.
type Part = fn(&mut OpaqueRowSigs) -> &mut Vec<u8>;

/// Panics with the operation a stub refused.
fn stub<T>(e: fstp_celltest::NotImplemented) -> T {
    panic!("{} is NotImplemented", e.operation)
}

/// The layout-free anchor rule of I-90, through the backend's own
/// signatures. The backend signs the untouched chain, and the anchor
/// verifier accepts it. For the last anchor row, every one-byte change of
/// the anchor or receipt signature is refused. So is every splice with
/// the same key's signature over another message, at every offset. A
/// verifier that checks one half only accepts a change in the other half,
/// wherever the draft 19 layout puts it.
fn anchor_sweep<B: AuditBackend>(b: &B, keys: &Keys) -> Result<(), String> {
    for c in RefChain::ALL {
        let view = keys.materialize(&chain(c)).unwrap();
        let sigs = b.sign_view(&view, keys).unwrap_or_else(stub);
        let verifies =
            |s: &OpaqueSigs| b.verify_opaque(&view, s, keys).unwrap_or_else(stub).is_ok();
        if !verifies(&sigs) {
            return Err(format!(
                "the untouched {c:?} chain under the backend's own signatures was refused"
            ));
        }
        let last = sigs.anchors.len() - 1;
        let parts: [(&str, Part); 2] = [
            ("anchor", |s| &mut s.anchor),
            ("receipt", |s| &mut s.receipt),
        ];
        for (part, field) in parts {
            let sig = field(&mut sigs.anchors[last].clone()).clone();
            let other = field(&mut sigs.other.clone()).clone();
            let with = |bytes: Vec<u8>| {
                let mut t = sigs.clone();
                *field(&mut t.anchors[last]) = bytes;
                t
            };
            for i in 0..sig.len() {
                let mut s = sig.clone();
                s[i] ^= 0x01;
                if verifies(&with(s)) {
                    return Err(format!(
                        "I-90: the {c:?} chain verified with byte {i} of its last {part} \
                         signature changed"
                    ));
                }
            }
            for p in 0..=sig.len().min(other.len()) {
                let mut s = sig[..p].to_vec();
                s.extend_from_slice(&other[p..]);
                if s != sig && verifies(&with(s)) {
                    return Err(format!(
                        "I-90: the {c:?} chain verified with its last {part} signature \
                         spliced at offset {p} with another message's signature"
                    ));
                }
            }
        }
    }
    Ok(())
}
/// I-90, design section 7.4: the anchor verifier rejects an anchor or a
/// receipt whose Ed25519 or ML-DSA-65 half alone fails. Production
/// `fstp_audit::verify`, over production composite signatures that the
/// backend makes itself. The halves are reached by the layout-free sweep.
/// Then the reference half forgeries run through
/// `verify_by_translation`, which keeps each one invalid.
#[test]
fn i90_anchor_verifier_rejects_either_half_alone() {
    let keys = Keys::new().unwrap();
    anchor_sweep(&Production, &keys).unwrap_or_else(|e| panic!("{e}"));
    let verify = |v: &RefChainView| {
        Production
            .verify(v, &keys)
            .unwrap_or_else(|e| panic!("{} is NotImplemented", e.operation))
    };
    rejects_half_forgeries(&keys, &verify).unwrap_or_else(|e| panic!("{e}"));
}

/// I-90: the same rule over the reference verifier, which reports each
/// one as a bad signature at the anchor's row.
#[test]
fn i90_anchor_verifier_rejects_either_half_alone_on_the_reference() {
    let keys = Keys::new().unwrap();
    let verify = |v: &RefChainView| {
        Reference
            .verify(v, &keys)
            .unwrap_or_else(|e| panic!("{}", e.operation))
    };
    rejects_half_forgeries(&keys, &verify).unwrap_or_else(|e| panic!("{e}"));
    let s = chain(RefChain::Vault);
    let t = r::apply(
        &s,
        Mutation::Anchor(1, Forgery::AnchorMlDsaFromAnotherMessage),
    )
    .unwrap();
    let view = keys.materialize(&t).unwrap();
    assert_eq!(
        r::verify(&view, &keys),
        Err(RefTamper::BadSignature { n: 2 })
    );
}

/// I-90: the reference backend passes the same layout-free sweep, over
/// signatures in its own test encoding.
#[test]
fn i90_anchor_verifier_rejects_either_half_alone_by_the_sweep_on_the_reference() {
    let keys = Keys::new().unwrap();
    anchor_sweep(&Reference, &keys).unwrap_or_else(|e| panic!("{e}"));
}

/// I-90 teeth: an anchor verifier that accepts either half fails the
/// layout-free sweep.
#[test]
fn i90_teeth_anchor_verifier_accepting_one_half_fails_the_sweep() {
    let keys = Keys::new().unwrap();
    let found = anchor_sweep(&Mutant::new(Reference, AuditDefect::OneHalfAccepted), &keys);
    assert!(
        found.as_ref().is_err_and(|e| e.starts_with("I-90:")),
        "the one-half anchor verifier went undetected: {found:?}"
    );
}

/// I-90 teeth: an anchor verifier that accepts either half is caught.
#[test]
fn i90_teeth_anchor_verifier_accepting_one_half_is_caught() {
    let keys = Keys::new().unwrap();
    let verify = |v: &RefChainView| {
        r::verify(v, &EitherHalf)
            .map(|_| ())
            .map_err(|t| format!("{t:?}"))
    };
    let found = rejects_half_forgeries(&keys, &verify);
    assert!(
        found.as_ref().is_err_and(|e| e.starts_with("I-90:")),
        "the one-half verifier went undetected: {found:?}"
    );
}

/// A verifier over public key, message and signature bytes.
type VerifyFn<'a> = &'a dyn Fn(&[u8], &[u8], &[u8]) -> bool;

/// The layout-free sweep of I-90: `sig` over `MSG` verifies under `pk`.
/// Every one-byte change of the signature, every splice with `other` (a
/// signature over `OTHER` by the same key) at every offset, and every
/// one-byte change of the public key is refused. A verifier that checks
/// only one half accepts a change in the other half, wherever it lies.
fn sweep(verify: VerifyFn<'_>, pk: &[u8], sig: &[u8], other: &[u8]) -> Result<(), String> {
    if !verify(pk, MSG, sig) {
        return Err("the valid signature was refused".to_owned());
    }
    if verify(pk, MSG, other) {
        return Err("a signature over another message verified".to_owned());
    }
    for i in 0..sig.len() {
        let mut s = sig.to_vec();
        s[i] ^= 0x01;
        if verify(pk, MSG, &s) {
            return Err(format!("I-90: a signature with byte {i} changed verified"));
        }
    }
    for p in 0..=sig.len().min(other.len()) {
        let mut s = sig[..p].to_vec();
        s.extend_from_slice(&other[p..]);
        if s != sig && verify(pk, MSG, &s) {
            return Err(format!(
                "I-90: a splice at offset {p} with another message's signature verified"
            ));
        }
    }
    for i in 0..pk.len() {
        let mut k = pk.to_vec();
        k[i] ^= 0x01;
        if verify(&k, MSG, sig) {
            return Err(format!("I-90: a public key with byte {i} changed verified"));
        }
    }
    Ok(())
}

/// I-90, ADR-001: `fstp_crypto::composite::verify` accepts only when
/// both halves verify, by the layout-free sweep.
#[test]
fn i90_composite_verify_rejects_either_half_alone() {
    let k =
        composite::generate().unwrap_or_else(|e| panic!("fstp_crypto::composite::generate: {e}"));
    let pk = prod_composite_public_key(&k).unwrap_or_else(|e| panic!("{}", e.operation));
    let sig = k.sign(MSG).unwrap().to_bytes();
    let other = k.sign(OTHER).unwrap().to_bytes();
    let verify = |pk: &[u8], m: &[u8], s: &[u8]| composite::verify(pk, m, s).is_ok();
    sweep(&verify, &pk, &sig, &other).unwrap_or_else(|e| panic!("{e}"));
}

fn reference_case() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let keys = Keys::new().unwrap();
    let signer = keys.signer(KeyRole::Anchor(RefChain::App));
    let pk = test_encoding::encode_pk(signer.public());
    let sig = test_encoding::encode_sig(&signer.sign(MSG).unwrap());
    let other = test_encoding::encode_sig(&signer.sign(OTHER).unwrap());
    (pk, sig, other)
}

fn decoded(f: fn(&RefPublicKey, &[u8], &RefSig) -> bool) -> impl Fn(&[u8], &[u8], &[u8]) -> bool {
    move |pk, m, s| match (test_encoding::decode_pk(pk), test_encoding::decode_sig(s)) {
        (Some(pk), Some(s)) => f(&pk, m, &s),
        _ => false,
    }
}

/// I-90: the reference composite check passes the same sweep.
#[test]
fn i90_reference_composite_rejects_either_half_alone() {
    let (pk, sig, other) = reference_case();
    sweep(&decoded(r::composite_verifies), &pk, &sig, &other).unwrap_or_else(|e| panic!("{e}"));
}

/// I-90 teeth: a composite check that accepts either half fails the
/// sweep.
#[test]
fn i90_teeth_single_half_composite_verifier_is_caught() {
    let (pk, sig, other) = reference_case();
    let found = sweep(&decoded(r::either_half_verifies), &pk, &sig, &other);
    assert!(
        found.as_ref().is_err_and(|e| e.starts_with("I-90:")),
        "the one-half composite check went undetected: {found:?}"
    );
}
