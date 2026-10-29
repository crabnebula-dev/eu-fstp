//! The reference composite of draft-ietf-lamps-pq-composite-sigs version
//! 19 for id-MLDSA65-Ed25519-SHA512, written from the ADR-010 "Composite
//! encoding" table alone (T-CR-COMPOSITE, TH-67, I-90).
//!
//! The reference never calls `fstp_crypto::composite` or
//! `fstp_crypto::mldsa`. It builds the message representative `M'` itself
//! (draft sections 2.2 and 3.2) and the concatenations of sections 4.1
//! and 4.3. Its ML-DSA-65 half calls moduletto directly, and its Ed25519
//! half calls `fstp_crypto::sig`, which wraps aws-lc-rs. SHA-512 comes
//! from aws-lc-rs. So a production composite that frames a value
//! differently disagrees with it.
//!
//! This is test code inside `fstp-crypto`. The I-75 scans cover the
//! crate's `src` and every other crate, not these tests. Nothing here
//! ships, and nothing here signs with one half alone except to build the
//! forgeries the I-90 tests feed to the verifier.

use aws_lc_rs::digest::{SHA512, digest};
use fstp_crypto::sig::{Ed25519SigningKey, ed25519_verify};
use moduletto::dsa::ml_dsa_65;

use super::{base64, hex};

/// Section 2.2: the ASCII string "CompositeAlgorithmSignatures2025".
pub const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/// Section 2.2: the hex the draft gives for [`PREFIX`], verbatim.
pub const PREFIX_HEX: &str = "436F6D706F73697465416C676F726974686D5369676E61747572657332303235";

/// Section 6: the label of id-MLDSA65-Ed25519-SHA512.
pub const LABEL: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// Section 6: the OID of id-MLDSA65-Ed25519-SHA512.
pub const OID: &str = "1.3.6.1.5.5.7.6.48";

/// Section 4 Table 1 and FIPS 204 Table 2: ML-DSA-65 public key length.
pub const MLDSA_PK_LEN: usize = 1952;

/// Section 4 Table 1 and FIPS 204 Table 2: ML-DSA-65 signature length.
pub const MLDSA_SIG_LEN: usize = 3309;

/// Section 4 Table 1: the ML-DSA private key is its 32-byte seed.
pub const MLDSA_SEED_LEN: usize = 32;

/// Section 4 (EdDSA, RFC 8032 section 3): Ed25519 public key length.
pub const ED25519_PK_LEN: usize = 32;

/// Section 4 (EdDSA, RFC 8032 section 3): Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;

/// Appendix A Table 4: public key length of id-MLDSA65-Ed25519-SHA512.
pub const PK_LEN: usize = 1984;

/// Appendix A Table 4: private key length of id-MLDSA65-Ed25519-SHA512.
pub const SK_LEN: usize = 64;

/// Appendix A Table 4: signature length of id-MLDSA65-Ed25519-SHA512.
pub const SIG_LEN: usize = 3373;

/// Sections 2.2 and 3.2: `M' = Prefix || Label || len(ctx) || ctx ||
/// PH(M)`, with `PH` SHA-512 for this algorithm (section 6). `label` is a
/// parameter so the Appendix D example, which uses another label, checks
/// this function too.
pub fn m_prime(label: &[u8], ctx: &[u8], message: &[u8]) -> Vec<u8> {
    let len = u8::try_from(ctx.len()).expect("ctx of at most 255 bytes");
    let mut out = Vec::new();
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(label);
    out.push(len);
    out.extend_from_slice(ctx);
    out.extend_from_slice(digest(&SHA512, message).as_ref());
    out
}

/// A composite key pair rebuilt from a section 4.2 private key
/// `mldsaSeed || tradSK`.
pub struct RefKey {
    pub mldsa_pk: [u8; MLDSA_PK_LEN],
    mldsa_sk: Box<[u8; ml_dsa_65::SK_BYTES]>,
    pub ed25519: Ed25519SigningKey,
}

impl RefKey {
    /// Section 3.1 step 1 with the seed given: `ML-DSA.KeyGen_internal`
    /// of the first 32 bytes, and the Ed25519 key whose RFC 8032 private
    /// key is the last 32.
    pub fn from_private_key(sk: &[u8]) -> RefKey {
        assert_eq!(sk.len(), SK_LEN, "composite private key length");
        let (seed, ed) = sk.split_at(MLDSA_SEED_LEN);
        let seed: [u8; MLDSA_SEED_LEN] = seed.try_into().expect("32-byte seed");
        let ed: [u8; 32] = ed.try_into().expect("32-byte Ed25519 key");
        let (pk, sk) = ml_dsa_65::keygen_internal(&seed);
        RefKey {
            mldsa_pk: pk,
            mldsa_sk: Box::new(sk),
            ed25519: Ed25519SigningKey::from_seed(&ed).expect("Ed25519 seed"),
        }
    }

    /// Section 4.1: `mldsaPK || tradPK`.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = self.mldsa_pk.to_vec();
        out.extend_from_slice(&self.ed25519.public_key());
        out
    }

    /// The ML-DSA-65 half over `m_prime` with ML-DSA context `mldsa_ctx`
    /// (section 3.2 step 4 passes the label) and randomness `rnd`.
    pub fn mldsa_half(&self, m_prime: &[u8], mldsa_ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
        ml_dsa_65::sign(&self.mldsa_sk[..], m_prime, mldsa_ctx, rnd)
            .expect("moduletto signs")
            .to_vec()
    }

    /// The Ed25519 half over `m_prime` (section 3.2 step 4).
    pub fn ed25519_half(&self, m_prime: &[u8]) -> Vec<u8> {
        self.ed25519.sign(m_prime).expect("Ed25519 signs").to_vec()
    }

    /// Section 3.2: the whole composite signature `mldsaSig || tradSig`
    /// over `message` under application context `ctx`.
    pub fn sign(&self, message: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
        let mp = m_prime(LABEL, ctx, message);
        let mut out = self.mldsa_half(&mp, LABEL, rnd);
        out.extend_from_slice(&self.ed25519_half(&mp));
        out
    }
}

/// Section 3.3 step 4, half by half: whether the ML-DSA-65 half and the
/// Ed25519 half of `sig` verify over `message` and `ctx` under `pk`.
/// Lengths other than the section 4.1 and 4.3 ones give `(false, false)`.
pub fn verify_halves(pk: &[u8], message: &[u8], ctx: &[u8], sig: &[u8]) -> (bool, bool) {
    if pk.len() != PK_LEN || sig.len() != SIG_LEN {
        return (false, false);
    }
    let (mldsa_pk, ed_pk) = pk.split_at(MLDSA_PK_LEN);
    let (mldsa_sig, ed_sig) = sig.split_at(MLDSA_SIG_LEN);
    let mp = m_prime(LABEL, ctx, message);
    (
        ml_dsa_65::verify(mldsa_pk, &mp, LABEL, mldsa_sig),
        ed25519_verify(ed_pk, &mp, ed_sig).is_ok(),
    )
}

/// The Appendix E test case for id-MLDSA65-Ed25519-SHA512, decoded from
/// `tests/data/composite_mldsa65_ed25519_draft19.json`.
pub struct Vector {
    pub m: Vec<u8>,
    pub ctx: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub s: Vec<u8>,
    pub s_with_context: Vec<u8>,
}

/// The vector file, verbatim base64 from the draft.
pub const VECTOR_JSON: &str = include_str!("../data/composite_mldsa65_ed25519_draft19.json");

/// The vector file parsed with `fstp-json`.
pub fn vector_json() -> fstp_json::Value {
    fstp_json::parse_str(VECTOR_JSON).expect("the vector file parses")
}

/// One string field of the vector file.
pub fn vector_field(name: &str) -> String {
    vector_json()
        .get(name)
        .and_then(fstp_json::Value::as_str)
        .unwrap_or_else(|| panic!("field {name} missing"))
        .to_string()
}

/// The decoded Appendix E test case.
pub fn vector() -> Vector {
    let b = |name: &str| base64(&vector_field(name));
    Vector {
        m: b("m"),
        ctx: b("ctx"),
        pk: b("pk"),
        sk: b("sk"),
        s: b("s"),
        s_with_context: b("sWithContext"),
    }
}

/// The hex of the draft's Appendix D example `M'`, verbatim with its line
/// breaks.
pub fn appendix_d_hex(with_ctx: bool) -> Vec<u8> {
    if with_ctx {
        hex(
            "436f6d706f73697465416c676f726974686d5369676e6174757265733230323\
             5434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132\
             0808130612051626230f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c\
             3523a20974f9a3f202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d85\
             4c342f903533",
        )
    } else {
        hex(
            "436f6d706f73697465416c676f726974686d5369676e6174757265733230323\
             5434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132\
             000f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f2\
             02f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533",
        )
    }
}

/// Every single-bit flip of `bytes[range]`, as `(byte index, mask)`.
pub fn bit_flips(range: std::ops::Range<usize>) -> Vec<(usize, u8)> {
    range
        .flat_map(|i| (0..8).map(move |b| (i, 1u8 << b)))
        .collect()
}

/// Runs `accepts` over `flips` on every available core and returns the
/// flips it accepted. `accepts` gets the flipped copy of `base`.
pub fn accepted_flips(
    base: &[u8],
    flips: &[(usize, u8)],
    accepts: &(dyn Fn(&[u8]) -> bool + Sync),
) -> Vec<(usize, u8)> {
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    let chunk = flips.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = flips
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    let mut copy = base.to_vec();
                    let mut bad = Vec::new();
                    for &(i, mask) in part {
                        copy[i] ^= mask;
                        if accepts(&copy) {
                            bad.push((i, mask));
                        }
                        copy[i] ^= mask;
                    }
                    bad
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("flip worker"))
            .collect()
    })
}
